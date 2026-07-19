//! The chain-reading seam and the singleton lineage-authentication core (SPEC §5 & §10).
//!
//! dig-did performs NO network or chain I/O (INV-1). Yet authenticating that a coin is a genuine
//! singleton — and rooting it in a DID's identity — requires *reading* chain state (a coin's creating
//! spend, a DID singleton's lineage). [`ChainSource`] is the seam that squares that circle: the caller
//! supplies an honest READER of chain state (a full node / coinset client / `chia-query`), and dig-did
//! supplies ALL the trust logic on top. Reads are not broadcasts — this keeps the crate no-network and
//! wasm-buildable while still proving lineage.
//!
//! ## Why the walk, and why puzzle-hash equality is NOT enough (the soundness crux)
//!
//! A Chia coin's `puzzle_hash` is attacker-chosen: anyone can pay-to a coin whose puzzle hash equals a
//! singleton's outer puzzle hash for a victim launcher. Such a coin is NOT a singleton — it has no
//! genuine recreation history. To authenticate a coin as a real singleton this module WALKS the
//! parent-spend chain: for each step it parses the parent's puzzle with the SDK's [`SingletonLayer`]
//! (proving the parent is itself a singleton and reading its *curried* `launcher_id`), RUNS the parent's
//! inner puzzle to derive the exact singleton successor it creates, and requires that successor to be
//! the child under authentication (binding amount parity + the singleton curry). The walk terminates at
//! the singleton LAUNCHER coin, yielding an AUTHENTICATED `launcher_id`. A coin whose parent chain does
//! not resolve this way is [`DidError::NotASingleton`] — never trusted on a bare puzzle hash or a bare
//! `parent_coin_info`.
//!
//! ## Trust model
//!
//! The [`ChainSource`] MUST be the caller's OWN honest view of the chain, not an attacker-controlled
//! channel. dig-did assumes the source reports real chain state; it cannot defend against a source that
//! fabricates the chain itself. Its job is to ensure that, given honest chain data, no coin can launder
//! itself into a DID's authority (see the adversarial tests). Every read failure or gap fails CLOSED —
//! an error, never an "assume owned" default.

use chia_protocol::{Bytes32, Coin, CoinSpend, Program};
use chia_puzzle_types::singleton::SingletonArgs;
use chia_puzzle_types::Proof;
use chia_puzzles::SINGLETON_LAUNCHER_HASH;
use chia_sdk_utils::Address;
use chia_wallet_sdk::driver::{Did, DidInfo, Layer, Puzzle, SingletonLayer};
use chia_wallet_sdk::prelude::{Allocator, NodePtr};
use chia_wallet_sdk::types::{run_puzzle, Condition};
use clvm_traits::{FromClvm, ToClvm};
use clvm_utils::TreeHash;

use crate::error::{DidError, DidResult};

// The chain-reading seam is the ONE canonical `dig-chainsource-interface` contract (#1240), not a
// per-crate copy that could byte-drift. Re-exported here so the historical `dig_did::ChainSource` and
// `dig_did::SingletonLineage` paths are preserved for downstream consumers.
pub use dig_chainsource_interface::{ChainSource, SingletonLineage};

/// The maximum number of parent-spend hops the singleton walk will follow before failing closed with
/// [`DidError::LineageTooDeep`].
///
/// A genuine singleton's lineage grows by one coin per spend; a DID under active use might accumulate
/// thousands of states over its lifetime, so the bound is generous. Its purpose is purely a DoS guard:
/// a malicious [`ChainSource`] must not be able to make the walk loop unboundedly.
pub const MAX_LINEAGE_DEPTH: usize = 100_000;

/// The current unspent tip of a DID singleton, reconstructed from chain reads: the tip coin, its
/// [`DidInfo`], and the lineage [`Proof`] needed to spend it.
///
/// This is the output of [`walk_did_lineage_to_tip`] — a ready-to-inspect (and, with an inner spend,
/// ready-to-spend) [`Did`]-shaped view of a DID's current on-chain state.
#[derive(Debug, Clone)]
pub struct DidTip {
    /// The DID singleton's current unspent tip coin.
    pub coin: Coin,
    /// The DID's outer-puzzle fields at the tip (launcher id, recovery config, metadata, owner p2 hash).
    pub info: DidInfo,
    /// The lineage proof binding the tip to its parent — required in the tip's spend solution.
    pub proof: Proof,
}

impl DidTip {
    /// Projects this tip into the SDK's spendable [`Did`] (`Singleton<DidInfo>`).
    pub fn did(&self) -> Did {
        Did::new(self.coin, self.proof, self.info)
    }
}

/// The authenticated result of the singleton walk: the launcher a coin genuinely descends from, plus
/// the launcher coin itself (whose `parent_coin_info` is the coin that CREATED the launcher — the
/// launch-from-DID link for [`LineageModel::LaunchedFrom`]).
#[derive(Debug)]
pub(crate) struct AuthenticatedLineage {
    /// The launcher id the walked coin provably descends from (the curry commitment == the launcher).
    pub(crate) launcher_id: Bytes32,
    /// The launcher coin the walk terminated at. `launcher_coin.parent_coin_info` is the coin that
    /// created the launcher.
    pub(crate) launcher_coin: Coin,
    /// The coin ids walked, from the coin under proof up to (and including) the launcher — an audit
    /// trail carried into [`crate::lineage::AncestryProof`].
    pub(crate) trail: Vec<Bytes32>,
}

/// Authenticates `coin_id` as a genuine singleton by walking its parent-spend chain to the launcher.
///
/// See the module docs for WHY this walk (not a puzzle-hash check) is the only sound authentication.
/// Fails closed with [`DidError::NotASingleton`] on any break in the singleton structure, and
/// [`DidError::LineageTooDeep`] past [`MAX_LINEAGE_DEPTH`]. Read failures propagate as
/// [`DidError::Chain`].
pub(crate) fn authenticate_singleton<S: ChainSource>(
    coin_id: Bytes32,
    source: &S,
) -> DidResult<AuthenticatedLineage> {
    authenticate_singleton_bounded(coin_id, source, MAX_LINEAGE_DEPTH)
}

/// [`authenticate_singleton`] with an explicit depth bound — the DoS guard, factored out so the
/// [`DidError::LineageTooDeep`] behaviour can be exercised over a real (short) chain with a tiny bound.
pub(crate) fn authenticate_singleton_bounded<S: ChainSource>(
    coin_id: Bytes32,
    source: &S,
    max_depth: usize,
) -> DidResult<AuthenticatedLineage> {
    let mut allocator = Allocator::new();
    let mut trail = vec![coin_id];
    let mut current = coin_id;
    // The launcher id every singleton parent must agree on — captured from the first singleton parent
    // and re-checked at every subsequent hop and at the terminal launcher.
    let mut expected_launcher: Option<Bytes32> = None;

    for _hop in 0..max_depth {
        let spend = source
            .parent_spend(current)
            .map_err(chain_error)?
            .ok_or(DidError::NotASingleton)?;
        let parent = spend.coin;
        let (parent_puzzle, parent_solution) = parse_spend(&mut allocator, &spend)?;

        // Terminal: the parent is the singleton launcher, so `current` is the eve singleton.
        if parent.puzzle_hash == SINGLETON_LAUNCHER_HASH.into() {
            let launcher_id = parent.coin_id();
            if let Some(expected) = expected_launcher {
                require(expected == launcher_id)?;
            }
            require(launcher_creates(
                &mut allocator,
                parent,
                parent_puzzle,
                parent_solution,
                current,
            )?)?;
            return Ok(AuthenticatedLineage {
                launcher_id,
                launcher_coin: parent,
                trail,
            });
        }

        // Otherwise the parent must itself be a genuine singleton that recreates `current`.
        let layer = SingletonLayer::<Puzzle>::parse_puzzle(&allocator, parent_puzzle)
            .map_err(DidError::Driver)?
            .ok_or(DidError::NotASingleton)?;
        if let Some(expected) = expected_launcher {
            require(expected == layer.launcher_id)?;
        }
        expected_launcher = Some(layer.launcher_id);

        let successor = singleton_successor(&mut allocator, parent, &layer, parent_solution)?
            .ok_or(DidError::NotASingleton)?;
        require(successor.coin_id() == current)?;

        trail.push(parent.coin_id());
        current = parent.coin_id();
    }

    Err(DidError::LineageTooDeep)
}

/// Reconstructs the exact singleton successor coin that `parent` (a singleton for `layer.launcher_id`)
/// creates, by running its inner puzzle and re-wrapping the odd-amount successor in the singleton curry.
///
/// Returns `None` when the spend emits no odd-amount successor (a melt / no child). The returned coin's
/// puzzle hash is COMPUTED from the launcher id and the successor's inner puzzle hash — it is never read
/// from an untrusted field, which is what makes the authentication sound.
fn singleton_successor(
    allocator: &mut Allocator,
    parent: Coin,
    layer: &SingletonLayer<Puzzle>,
    parent_solution: NodePtr,
) -> DidResult<Option<Coin>> {
    let solution = SingletonLayer::<Puzzle>::parse_solution(allocator, parent_solution)
        .map_err(DidError::Driver)?;
    let output = run_puzzle(allocator, layer.inner_puzzle.ptr(), solution.inner_solution)
        .map_err(|error| DidError::Parse(error.to_string()))?;
    let conditions = Vec::<Condition>::from_clvm(allocator, output)
        .map_err(|e| DidError::Parse(e.to_string()))?;

    let Some(create_coin) = conditions
        .into_iter()
        .filter_map(Condition::into_create_coin)
        .find(|create_coin| create_coin.amount % 2 == 1)
    else {
        return Ok(None);
    };

    let inner_hash: TreeHash = create_coin.puzzle_hash.into();
    let full_puzzle_hash = SingletonArgs::curry_tree_hash(layer.launcher_id, inner_hash);
    Ok(Some(Coin::new(
        parent.coin_id(),
        full_puzzle_hash.into(),
        create_coin.amount,
    )))
}

/// Whether the launcher coin's spend creates exactly the eve coin `eve_id`.
///
/// The launcher's `CREATE_COIN` puzzle hash is already the eve's full (singleton-wrapped) puzzle hash,
/// so the eve coin is reconstructed directly and its id compared. This binds the eve to a genuine
/// launcher spend rather than a claimed parent.
fn launcher_creates(
    allocator: &mut Allocator,
    launcher: Coin,
    launcher_puzzle: Puzzle,
    launcher_solution: NodePtr,
    eve_id: Bytes32,
) -> DidResult<bool> {
    let output = run_puzzle(allocator, launcher_puzzle.ptr(), launcher_solution)
        .map_err(|error| DidError::Parse(error.to_string()))?;
    let conditions = Vec::<Condition>::from_clvm(allocator, output)
        .map_err(|e| DidError::Parse(e.to_string()))?;

    Ok(conditions
        .into_iter()
        .filter_map(Condition::into_create_coin)
        .any(|create_coin| {
            Coin::new(
                launcher.coin_id(),
                create_coin.puzzle_hash,
                create_coin.amount,
            )
            .coin_id()
                == eve_id
        }))
}

/// Walks a DID singleton forward to its current unspent tip, reconstructing it as a [`DidTip`].
///
/// Consolidates dig-identity's lineage half against this crate's [`ChainSource`]: it resolves the DID's
/// lineage tip via [`ChainSource::resolve_singleton_lineage`], reads the spend that created the tip, and
/// parses the tip DID with the SDK ([`Did::parse_child`], INV-4). Returns `None` when the DID has no
/// current on-chain coin (unlaunched or melted). Fails closed with [`DidError::NotDid`] when the tip's
/// creating spend does not parse as a DID (e.g. the tip is a bare eve whose parent is the launcher).
pub fn walk_did_lineage_to_tip<S: ChainSource>(
    source: &S,
    launcher_id: Bytes32,
) -> DidResult<Option<DidTip>> {
    let Some(lineage) = source
        .resolve_singleton_lineage(launcher_id)
        .map_err(chain_error)?
    else {
        return Ok(None);
    };
    let tip_id = lineage.tip();

    let spend = source
        .parent_spend(tip_id)
        .map_err(chain_error)?
        .ok_or(DidError::NoIdentitySingleton)?;
    let parent = spend.coin;

    let mut allocator = Allocator::new();
    let (parent_puzzle, parent_solution) = parse_spend(&mut allocator, &spend)?;

    // Reconstruct the tip coin from the parent's genuine singleton successor.
    let layer = SingletonLayer::<Puzzle>::parse_puzzle(&allocator, parent_puzzle)
        .map_err(DidError::Driver)?
        .ok_or(DidError::NotDid)?;
    let tip_coin = singleton_successor(&mut allocator, parent, &layer, parent_solution)?
        .filter(|coin| coin.coin_id() == tip_id)
        .ok_or(DidError::NotDid)?;

    let did = Did::parse_child(
        &mut allocator,
        parent,
        parent_puzzle,
        parent_solution,
        tip_coin,
    )
    .map_err(DidError::Driver)?
    .ok_or(DidError::NotDid)?;

    Ok(Some(DidTip {
        coin: did.coin,
        info: did.info,
        proof: did.proof,
    }))
}

/// Resolves a DID's CURRENT owner XCH payment address from chain — the DID→address primitive
/// (SPEC §3, U10).
///
/// Walks the DID singleton identified by `launcher_id` to its current authenticated tip and returns
/// the tip owner's payment address: the tip's `p2_puzzle_hash` (SPEC §2.1, "the current owner's
/// address") bech32m-encoded under `prefix`. `prefix` is the network HRP (`"xch"` mainnet, `"txch"`
/// testnet) — dig-did stays network-agnostic and never hard-codes an HRP. This is a ChainSource-READ
/// only: it never signs and never broadcasts (INV-1/INV-2).
///
/// # Money-critical soundness (why the extra walk)
///
/// This primitive routes payments, so a wrong answer silently pays the wrong recipient. The tip's
/// curried `launcher_id` is attacker-chosen (the `pay_to_coin_wearing_a_singleton_puzzle_hash`
/// attack class), so `tip.info.launcher_id() == launcher_id` is INSUFFICIENT. After walking to the
/// tip this function runs the `authenticate_singleton` parent-spend walk — which walks the
/// parent-spend chain to the GENUINE launcher — and requires that authenticated launcher to equal
/// `launcher_id`. Only then is
/// the address built. A dishonest [`ChainSource`] that echoes a DIFFERENT DID's tip for `launcher_id`
/// is caught here as [`DidError::LauncherMismatch`], never resolved to the attacker's address.
///
/// # Returns
///
/// `Ok(Some(address))` for a launched, authenticated DID; `Ok(None)` when the DID has no current
/// on-chain coin (unlaunched or melted). Every other failure is a typed, fail-closed [`DidError`]:
///
/// | Case | Result |
/// |---|---|
/// | unlaunched / melted | `Ok(None)` |
/// | tip creating-spend absent | `Err(NoIdentitySingleton)` |
/// | tip not a DID | `Err(NotDid)` |
/// | tip not a genuine singleton (spoofed curry) | `Err(NotASingleton)` |
/// | genuine launcher ≠ requested | `Err(LauncherMismatch)` |
/// | chain read fails | `Err(Chain)` |
/// | lineage over-deep | `Err(LineageTooDeep)` |
/// | `Address::encode` fails (bad `prefix`) | `Err(Parse)` |
pub fn resolve_xch_address<S: ChainSource>(
    launcher_id: Bytes32,
    prefix: &str,
    source: &S,
) -> DidResult<Option<Address>> {
    let Some(tip) = walk_did_lineage_to_tip(source, launcher_id)? else {
        return Ok(None);
    };

    // The money-critical guard: authenticate the tip's GENUINE launcher via the parent-spend walk,
    // never the attacker-chosen curried launcher id on the tip itself.
    let authenticated = authenticate_singleton(tip.coin.coin_id(), source)?;
    if authenticated.launcher_id != launcher_id {
        return Err(DidError::LauncherMismatch);
    }

    let address = Address::new(tip.info.p2_puzzle_hash, prefix.to_string());
    // Validate the address encodes under `prefix` before returning it — a bad HRP fails closed here
    // rather than handing back an address that cannot be rendered.
    address
        .encode()
        .map_err(|error| DidError::Parse(error.to_string()))?;
    Ok(Some(address))
}

/// Resolves a DID's current owner XCH payment address from its `did:chia:1…` string form — a
/// convenience wrapper over [`resolve_xch_address`] (SPEC §3, U10).
///
/// Decodes `did` to its launcher id (see [`crate::launcher_id_from_did_string`]) and delegates. A
/// malformed `did:chia:` string fails closed with [`DidError::InvalidDidString`] before any chain
/// read. All other semantics — including the money-critical launcher authentication — match
/// [`resolve_xch_address`].
pub fn resolve_xch_address_from_did_string<S: ChainSource>(
    did: &str,
    prefix: &str,
    source: &S,
) -> DidResult<Option<Address>> {
    let launcher_id = crate::launcher_id_from_did_string(did)?;
    resolve_xch_address(launcher_id, prefix, source)
}

/// Deserializes a [`CoinSpend`]'s puzzle reveal and solution into the allocator, returning the parsed
/// [`Puzzle`] and the solution [`NodePtr`].
fn parse_spend(allocator: &mut Allocator, spend: &CoinSpend) -> DidResult<(Puzzle, NodePtr)> {
    let puzzle_ptr = alloc_program(allocator, &spend.puzzle_reveal)?;
    let solution_ptr = alloc_program(allocator, &spend.solution)?;
    Ok((Puzzle::parse(allocator, puzzle_ptr), solution_ptr))
}

/// Deserializes a [`Program`] (a puzzle reveal or solution) into an allocated [`NodePtr`].
fn alloc_program(allocator: &mut Allocator, program: &Program) -> DidResult<NodePtr> {
    program
        .to_clvm(allocator)
        .map_err(|error| DidError::Parse(error.to_string()))
}

/// Fails closed with [`DidError::NotASingleton`] unless `condition` holds — the single-line guard the
/// singleton walk uses so every structural break maps to the same "not a singleton" verdict.
fn require(condition: bool) -> DidResult<()> {
    condition.then_some(()).ok_or(DidError::NotASingleton)
}

/// Wraps a source-specific error into [`DidError::Chain`] without requiring `S::Error: 'static`.
fn chain_error<E: core::fmt::Display>(error: E) -> DidError {
    DidError::Chain(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    use chia_puzzle_types::Memos;
    use chia_wallet_sdk::driver::{SingletonInfo, SpendContext, StandardLayer};
    use chia_wallet_sdk::test::Simulator;
    use chia_wallet_sdk::types::Conditions;
    use dig_chainsource_interface::{CoinRecord, MockChainSource};

    use crate::create::create_simple_did;
    use crate::did_string::did_string_from_launcher_id;
    use crate::types::Owner;

    /// The mainnet payment-address HRP used across the resolve tests (dig-did itself is
    /// network-agnostic — the caller passes the prefix).
    const XCH: &str = "xch";

    /// A DID freshly created and settled in the simulator, kept together with its owner so tests can
    /// spend it further.
    struct SettledDid {
        did: Did,
        launcher_id: Bytes32,
    }

    /// A chain view backed by the real in-process simulator, with a per-launcher lineage map that a
    /// test can populate HONESTLY (the DID's own lineage) or DISHONESTLY (echoing another DID's tip
    /// for a victim launcher — the money-critical attack). Everything except the lineage map is read
    /// straight from the genuine simulator, so the parent-spend authentication walk always sees real
    /// on-chain spends.
    struct SimSource<'a> {
        sim: &'a Simulator,
        lineages: HashMap<Bytes32, SingletonLineage>,
    }

    impl ChainSource for SimSource<'_> {
        type Error = String;

        fn coin_record(&self, coin_id: Bytes32) -> Result<Option<CoinRecord>, Self::Error> {
            Ok(self.sim.coin_state(coin_id).map(CoinRecord::from))
        }

        fn coin_records_by_puzzle_hash(
            &self,
            _puzzle_hash: Bytes32,
            _include_spent: bool,
        ) -> Result<Vec<CoinRecord>, Self::Error> {
            Ok(Vec::new())
        }

        fn coin_records_by_parent(
            &self,
            _parent_coin_id: Bytes32,
        ) -> Result<Vec<CoinRecord>, Self::Error> {
            Ok(Vec::new())
        }

        fn coin_spend(&self, coin_id: Bytes32) -> Result<Option<CoinSpend>, Self::Error> {
            let Some(state) = self.sim.coin_state(coin_id) else {
                return Ok(None);
            };
            let (Some(reveal), Some(solution)) =
                (self.sim.puzzle_reveal(coin_id), self.sim.solution(coin_id))
            else {
                return Ok(None);
            };
            Ok(Some(CoinSpend::new(state.coin, reveal, solution)))
        }

        fn resolve_singleton_lineage(
            &self,
            launcher_id: Bytes32,
        ) -> Result<Option<SingletonLineage>, Self::Error> {
            Ok(self.lineages.get(&launcher_id).cloned())
        }

        fn peak_height(&self) -> Result<Option<u32>, Self::Error> {
            Ok(None)
        }

        fn block_timestamp(&self, _height: u32) -> Result<Option<u64>, Self::Error> {
            Ok(None)
        }
    }

    /// Creates and settles a fresh single-owner DID in `sim`, returning it plus its launcher id.
    fn settle_did(sim: &mut Simulator, ctx: &mut SpendContext) -> anyhow::Result<SettledDid> {
        let owner = sim.bls(1);
        let spend = create_simple_did(ctx, owner.coin, Owner::Standard(owner.pk))?;
        let did = spend.child.expect("create returns a child DID");
        sim.spend_coins(spend.coin_spends, std::slice::from_ref(&owner.sk))?;
        let launcher_id = did.info.launcher_id();
        Ok(SettledDid { did, launcher_id })
    }

    /// The full lineage of a freshly-settled DID (launcher -> eve -> settled tip).
    fn did_lineage(did: &Did) -> SingletonLineage {
        SingletonLineage::new(
            did.coin.coin_id(),
            [
                did.info.launcher_id(),
                did.coin.parent_coin_info,
                did.coin.coin_id(),
            ],
        )
    }

    /// An honest source reporting `did`'s own lineage for its launcher.
    fn honest_source<'a>(sim: &'a Simulator, did: &Did) -> SimSource<'a> {
        SimSource {
            sim,
            lineages: HashMap::from([(did.info.launcher_id(), did_lineage(did))]),
        }
    }

    #[test]
    fn resolve_happy_path_matches_the_owner_address() -> anyhow::Result<()> {
        let mut sim = Simulator::new();
        let ctx = &mut SpendContext::new();
        let SettledDid { did, launcher_id } = settle_did(&mut sim, ctx)?;
        let source = honest_source(&sim, &did);

        let address = resolve_xch_address(launcher_id, XCH, &source)?
            .expect("a launched, authenticated DID resolves to an address");

        assert_eq!(address.puzzle_hash, did.info.p2_puzzle_hash);
        assert_eq!(address.prefix, XCH);
        let expected = Address::new(did.info.p2_puzzle_hash, XCH.to_string()).encode()?;
        assert_eq!(address.encode()?, expected);
        Ok(())
    }

    #[test]
    fn resolved_address_roundtrips_through_decode() -> anyhow::Result<()> {
        let mut sim = Simulator::new();
        let ctx = &mut SpendContext::new();
        let SettledDid { did, launcher_id } = settle_did(&mut sim, ctx)?;
        let source = honest_source(&sim, &did);

        let address = resolve_xch_address(launcher_id, XCH, &source)?.expect("resolves");
        let decoded = Address::decode(&address.encode()?)?;

        assert_eq!(decoded.puzzle_hash, did.info.p2_puzzle_hash);
        assert_eq!(decoded.prefix, XCH);
        Ok(())
    }

    #[test]
    fn resolve_rejects_an_echoed_different_dids_tip() -> anyhow::Result<()> {
        // THE money test. A dishonest source echoes an ATTACKER DID's real tip for the VICTIM's
        // launcher. A naive resolver would walk to the attacker's tip, trust the tip's curried
        // launcher id, and hand back the ATTACKER's payment address for the victim's DID — silently
        // routing funds to the attacker. The parent-walk `authenticate_singleton` guard must catch it.
        let mut sim = Simulator::new();
        let ctx = &mut SpendContext::new();
        let victim = settle_did(&mut sim, ctx)?;
        let attacker = settle_did(&mut sim, ctx)?;

        // The victim launcher resolves (dishonestly) to the ATTACKER's lineage tip.
        let source = SimSource {
            sim: &sim,
            lineages: HashMap::from([(victim.launcher_id, did_lineage(&attacker.did))]),
        };

        let result = resolve_xch_address(victim.launcher_id, XCH, &source);
        assert!(matches!(result, Err(DidError::LauncherMismatch)));

        // Explicitly prove the guard prevented the wrong-recipient payment: the attacker's address is
        // what a naive resolver would have returned, and resolve did NOT return it.
        let attacker_address =
            Address::new(attacker.did.info.p2_puzzle_hash, XCH.to_string()).encode()?;
        assert!(
            !matches!(result, Ok(Some(address)) if address.encode().ok() == Some(attacker_address))
        );
        Ok(())
    }

    #[test]
    fn resolve_rejects_a_spoofed_curry_singleton() -> anyhow::Result<()> {
        // A pay-to coin that merely WEARS a singleton outer puzzle hash for the launcher, minted from
        // an ordinary coin (no genuine singleton recreation parent-spend). Fed as the echoed lineage
        // tip, it must fail closed — never resolved to an address.
        let mut sim = Simulator::new();
        let ctx = &mut SpendContext::new();
        let victim = settle_did(&mut sim, ctx)?;

        let alice = sim.bls(1);
        let alice_p2 = StandardLayer::new(alice.pk);
        let fake_singleton_puzzle_hash: Bytes32 =
            SingletonArgs::curry_tree_hash(victim.launcher_id, alice.puzzle_hash.into()).into();
        alice_p2.spend(
            ctx,
            alice.coin,
            Conditions::new().create_coin(fake_singleton_puzzle_hash, 1, Memos::None),
        )?;
        sim.spend_coins(ctx.take(), std::slice::from_ref(&alice.sk))?;

        let fake_coin = Coin::new(alice.coin.coin_id(), fake_singleton_puzzle_hash, 1);
        let source = SimSource {
            sim: &sim,
            lineages: HashMap::from([(
                victim.launcher_id,
                SingletonLineage::single(fake_coin.coin_id()),
            )]),
        };

        let result = resolve_xch_address(victim.launcher_id, XCH, &source);
        // Fail-closed: the tip is not a genuine singleton state of the DID, so it never parses into a
        // resolvable owner. (The spoof is rejected at the DID/singleton gate, never as an address.)
        assert!(matches!(
            result,
            Err(DidError::NotDid | DidError::NotASingleton)
        ));
        Ok(())
    }

    #[test]
    fn resolve_returns_none_for_unlaunched_or_melted() -> anyhow::Result<()> {
        // An empty mock source reports no lineage for any launcher — the DID was never launched or has
        // been fully melted. Absence is `Ok(None)`, never an error and never an address.
        let source = MockChainSource::new();
        let launcher_id: Bytes32 =
            clvm_utils::tree_hash_atom(b"dig-did::resolve::unlaunched-launcher").into();

        let resolved = resolve_xch_address(launcher_id, XCH, &source)?;
        assert!(resolved.is_none());
        Ok(())
    }

    #[test]
    fn resolve_from_did_string_rejects_malformed() {
        // A malformed did:chia string fails closed BEFORE any chain read.
        let source = MockChainSource::new();
        let error = resolve_xch_address_from_did_string("not-a-valid-did", XCH, &source)
            .expect_err("a malformed did:chia string must fail closed");
        assert!(matches!(error, DidError::InvalidDidString(_)));
    }

    #[test]
    fn resolve_from_did_string_happy_path_matches_direct_resolution() -> anyhow::Result<()> {
        // The string convenience fn agrees with the launcher-id form for a genuine DID.
        let mut sim = Simulator::new();
        let ctx = &mut SpendContext::new();
        let SettledDid { did, launcher_id } = settle_did(&mut sim, ctx)?;
        let source = honest_source(&sim, &did);

        let did_string = did_string_from_launcher_id(launcher_id);
        let via_string = resolve_xch_address_from_did_string(&did_string, XCH, &source)?
            .expect("resolves via the did:chia string");
        let via_launcher = resolve_xch_address(launcher_id, XCH, &source)?.expect("resolves");

        assert_eq!(via_string.encode()?, via_launcher.encode()?);
        Ok(())
    }
}
