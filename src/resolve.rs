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

use std::collections::BTreeSet;

use chia_protocol::{Bytes32, Coin, CoinSpend, Program};
use chia_puzzle_types::singleton::SingletonArgs;
use chia_puzzle_types::Proof;
use chia_puzzles::SINGLETON_LAUNCHER_HASH;
use chia_wallet_sdk::driver::{Did, DidInfo, Layer, Puzzle, SingletonLayer};
use chia_wallet_sdk::prelude::{Allocator, NodePtr};
use chia_wallet_sdk::types::{run_puzzle, Condition};
use clvm_traits::{FromClvm, ToClvm};
use clvm_utils::TreeHash;

use crate::error::{DidError, DidResult};

/// The maximum number of parent-spend hops the singleton walk will follow before failing closed with
/// [`DidError::LineageTooDeep`].
///
/// A genuine singleton's lineage grows by one coin per spend; a DID under active use might accumulate
/// thousands of states over its lifetime, so the bound is generous. Its purpose is purely a DoS guard:
/// a malicious [`ChainSource`] must not be able to make the walk loop unboundedly.
pub const MAX_LINEAGE_DEPTH: usize = 100_000;

/// A caller-supplied, honest READER of Chia chain state — the seam that keeps dig-did network-free
/// (INV-1) while still authenticating on-chain lineage.
///
/// A consumer (dig-node, dig-chat, the extension, hub) implements this over its own chain backend
/// (coinset.org, a local full node, `chia-query`). dig-did supplies all the trust logic on top; the
/// source only fetches. See the module trust model — the source MUST be honest chain data and is never
/// treated as a source of authority claims.
pub trait ChainSource {
    /// The source's own fetch/transport error, surfaced verbatim through [`DidError::Chain`].
    type Error: core::fmt::Display;

    /// Walks the singleton lineage from `launcher_id` to its current unspent tip, returning EVERY coin
    /// id on that walk as a [`SingletonLineage`].
    ///
    /// Returns `None` when the launcher never existed or the singleton has been fully spent (melted).
    /// The returned lineage is trusted as the DID singleton's authentic lineage — so this MUST be a
    /// genuine forward walk from the DID launcher to its tip (each coin the singleton recreation of the
    /// previous), NEVER an echo of a caller-supplied coin. The caller implements the walk against its
    /// own chain backend.
    fn resolve_singleton_lineage(
        &self,
        launcher_id: Bytes32,
    ) -> Result<Option<SingletonLineage>, Self::Error>;

    /// Returns the coin spend that CREATED `coin_id` — i.e. the spend of `coin_id`'s parent coin —
    /// or `None` when no such spend is known (an unspent-parent / coinbase / genesis edge).
    ///
    /// This is the single primitive the singleton-authentication walk consumes: given a coin, it reads
    /// the parent's puzzle reveal + solution, proves the parent is a singleton (or the launcher), and
    /// derives the successor the parent created. The source only fetches; it performs NO authentication.
    fn parent_spend(&self, coin_id: Bytes32) -> Result<Option<CoinSpend>, Self::Error>;
}

/// The lineage of a DID identity singleton: every coin id from the launcher spend forward to the
/// current unspent tip.
///
/// Authority is MEMBERSHIP in this lineage, not equality with the tip: a coin launched from ANY genuine
/// DID coin — the launch-time coin `Cn`, later spent to `Cn+1` — is rooted in the DID, while an
/// attacker's coin (never a member, since minting any lineage coin requires the DID's key) is not. This
/// is byte-coherent with dig-identity's `SingletonLineage` so the two crates can later de-duplicate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SingletonLineage {
    /// The current unspent singleton tip coin id (the DID's current on-chain state handle).
    tip: Bytes32,
    /// Every coin id in the lineage (launcher -> tip inclusive). Always contains `tip`.
    members: BTreeSet<Bytes32>,
}

impl SingletonLineage {
    /// Builds a lineage from its full member set and current `tip`. `tip` is always treated as a
    /// member, so a caller need not include it in `members` explicitly.
    pub fn new(tip: Bytes32, members: impl IntoIterator<Item = Bytes32>) -> Self {
        let mut members: BTreeSet<Bytes32> = members.into_iter().collect();
        members.insert(tip);
        Self { tip, members }
    }

    /// A degenerate single-coin lineage (the tip is the only member) — a DID never spent since launch.
    pub fn single(tip: Bytes32) -> Self {
        Self::new(tip, [tip])
    }

    /// The current unspent singleton tip coin id.
    pub fn tip(&self) -> Bytes32 {
        self.tip
    }

    /// Whether `coin_id` is a genuine coin in this singleton's lineage — the authority membership test.
    pub fn contains(&self, coin_id: Bytes32) -> bool {
        self.members.contains(&coin_id)
    }

    /// The number of coins in the lineage (launcher -> tip inclusive).
    pub fn len(&self) -> usize {
        self.members.len()
    }

    /// Whether the lineage has no members. Always `false` for a well-formed lineage (the tip is a
    /// member), but provided so `len`/`is_empty` are consistent for lints and callers.
    pub fn is_empty(&self) -> bool {
        self.members.is_empty()
    }
}

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
    let mut allocator = Allocator::new();
    let mut trail = vec![coin_id];
    let mut current = coin_id;
    // The launcher id every singleton parent must agree on — captured from the first singleton parent
    // and re-checked at every subsequent hop and at the terminal launcher.
    let mut expected_launcher: Option<Bytes32> = None;

    for _hop in 0..MAX_LINEAGE_DEPTH {
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
    let conditions =
        Vec::<Condition>::from_clvm(allocator, output).map_err(|e| DidError::Parse(e.to_string()))?;

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
    let conditions =
        Vec::<Condition>::from_clvm(allocator, output).map_err(|e| DidError::Parse(e.to_string()))?;

    Ok(conditions
        .into_iter()
        .filter_map(Condition::into_create_coin)
        .any(|create_coin| {
            Coin::new(launcher.coin_id(), create_coin.puzzle_hash, create_coin.amount).coin_id()
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

    let did = Did::parse_child(&mut allocator, parent, parent_puzzle, parent_solution, tip_coin)
        .map_err(DidError::Driver)?
        .ok_or(DidError::NotDid)?;

    Ok(Some(DidTip {
        coin: did.coin,
        info: did.info,
        proof: did.proof,
    }))
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

    #[test]
    fn lineage_membership_includes_tip_and_ancestors() {
        let launcher = Bytes32::new([1u8; 32]);
        let cn = Bytes32::new([2u8; 32]);
        let tip = Bytes32::new([3u8; 32]);
        let lineage = SingletonLineage::new(tip, [launcher, cn]);

        assert!(lineage.contains(launcher));
        assert!(lineage.contains(cn));
        assert!(lineage.contains(tip));
        assert!(!lineage.contains(Bytes32::new([9u8; 32])));
        assert_eq!(lineage.tip(), tip);
        assert_eq!(lineage.len(), 3);
        assert!(!lineage.is_empty());
    }

    #[test]
    fn single_lineage_is_tip_only() {
        let tip = Bytes32::new([7u8; 32]);
        let lineage = SingletonLineage::single(tip);
        assert_eq!(lineage.len(), 1);
        assert!(lineage.contains(tip));
    }
}
