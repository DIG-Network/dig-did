//! Lineage proof: authenticating that a coin belongs to a DID's identity (SPEC §5).
//!
//! [`prove_lineage`] answers ONE question — "is this coin a coin the DID identity owns / is rooted
//! in?" — and answers it soundly, via exactly two accepted models, both reduced to DID-singleton
//! lineage membership:
//!
//! - **[`LineageModel::Direct`]** — the coin authenticates as a state of the DID singleton ITSELF
//!   (its authenticated launcher id equals the DID's launcher id).
//! - **[`LineageModel::LaunchedFrom`]** — the coin is a DISTINCT singleton whose launcher coin's parent
//!   is a MEMBER of the DID singleton's lineage (the DID coin created that launcher). Membership, NOT
//!   tip-equality: launching from a DID recreates the DID coin in the same spend, so the launcher's
//!   parent is a PAST DID coin `Cn` while the DID tip is already `Cn+1`.
//!
//! Everything else fails closed. In particular an ordinary payment/change coin whose `parent_coin_info`
//! merely happens to be a DID coin is REJECTED — a DID spend can pay anyone, so a pay-to coin is not
//! owned by the DID. The discriminator is SINGLETON STRUCTURE (authenticated by the walk in
//! [`crate::resolve`]): a non-singleton coin has no launcher and fails with [`DidError::NotASingleton`].

use chia_protocol::Bytes32;
use chia_wallet_sdk::driver::{Did, SingletonInfo};

use crate::error::{DidError, DidResult};
use crate::resolve::{authenticate_singleton, ChainSource};

/// How a coin is rooted in a DID's identity — the two (and only two) accepted models.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LineageModel {
    /// The coin is a state of the DID singleton itself (authenticated launcher id == the DID's).
    Direct,

    /// The coin is a distinct singleton launched from the DID: its launcher's parent is a member of the
    /// DID singleton's lineage.
    LaunchedFrom {
        /// The authenticated launcher id of the distinct (launched) singleton.
        launcher: Bytes32,
        /// The DID coin (a member of the DID lineage) that created the distinct singleton's launcher.
        did_parent: Bytes32,
    },
}

/// A chain-authenticated proof that a coin is rooted in a DID's identity.
///
/// Its fields are PRIVATE and exposed only through accessors: an `AncestryProof` cannot be forged by a
/// struct literal — the only way to obtain one is [`prove_lineage`], which authenticates every field
/// against the chain. Treat a value of this type as evidence the proof genuinely holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AncestryProof {
    coin_id: Bytes32,
    did_launcher_id: Bytes32,
    model: LineageModel,
    did_lineage_tip: Bytes32,
    authenticated_launcher: Bytes32,
    chain: Vec<Bytes32>,
}

impl AncestryProof {
    /// The coin this proof authenticates.
    pub fn coin_id(&self) -> Bytes32 {
        self.coin_id
    }

    /// The launcher id of the DID the coin is rooted in.
    pub fn did_launcher_id(&self) -> Bytes32 {
        self.did_launcher_id
    }

    /// Which of the two accepted models roots the coin in the DID.
    pub fn model(&self) -> LineageModel {
        self.model
    }

    /// The DID singleton's current unspent tip at proof time.
    pub fn did_lineage_tip(&self) -> Bytes32 {
        self.did_lineage_tip
    }

    /// The launcher id the coin itself authenticated to (equal to the DID's launcher id for
    /// [`LineageModel::Direct`]; the distinct singleton's launcher for [`LineageModel::LaunchedFrom`]).
    pub fn authenticated_launcher(&self) -> Bytes32 {
        self.authenticated_launcher
    }

    /// The audit trail of coin ids walked, from the proven coin up to (and including) its launcher.
    pub fn chain(&self) -> &[Bytes32] {
        &self.chain
    }
}

/// Proves that `coin_id` is rooted in `did`'s identity, reading chain state through `chain`.
///
/// This is the crate's lineage trust anchor. It authenticates `coin_id` as a genuine singleton (walking
/// its parent-spend chain to a launcher — see [`crate::resolve`]) and then roots it in the DID by one of
/// the two [`LineageModel`]s. Pure over the injected reads: NO keys, NO signing, NO network (INV-1/2).
///
/// # Errors
///
/// Fails closed on every gap or mismatch (SPEC §5):
///
/// - [`DidError::NoIdentitySingleton`] — the DID has no current on-chain coin (unlaunched or melted).
/// - [`DidError::NotASingleton`] — `coin_id` is not a genuine singleton (a payment/change coin, or a
///   pay-to coin wearing a singleton puzzle hash with no genuine recreation parent spend).
/// - [`DidError::NotDidRooted`] — `coin_id` authenticates as a singleton but is neither the DID nor
///   launched from a coin in the DID's lineage.
/// - [`DidError::LineageTooDeep`] — the walk exceeded [`crate::resolve::MAX_LINEAGE_DEPTH`].
/// - [`DidError::Chain`] — a `chain` read failed (never degraded to "assume owned").
pub fn prove_lineage<S: ChainSource>(
    coin_id: Bytes32,
    did: &Did,
    chain: &S,
) -> DidResult<AncestryProof> {
    let did_launcher_id = did.info.launcher_id();

    // The DID's own authentic lineage — its existence anchors the proof, and its membership set decides
    // the LaunchedFrom model. A missing lineage is fail-closed, never "assume owned".
    let did_lineage = chain
        .resolve_singleton_lineage(did_launcher_id)
        .map_err(|error| DidError::Chain(error.to_string()))?
        .ok_or(DidError::NoIdentitySingleton)?;

    // Authenticate the coin as a genuine singleton and derive the launcher it descends from.
    let authenticated = authenticate_singleton(coin_id, chain)?;

    // Model (a) Direct: the coin IS a state of the DID singleton.
    let model = if authenticated.launcher_id == did_launcher_id {
        LineageModel::Direct
    } else {
        // Model (b) LaunchedFrom: the distinct singleton's launcher must have been created by a coin in
        // the DID's lineage (membership, not tip-equality).
        let did_parent = authenticated.launcher_coin.parent_coin_info;
        if !did_lineage.contains(did_parent) {
            return Err(DidError::NotDidRooted);
        }
        LineageModel::LaunchedFrom {
            launcher: authenticated.launcher_id,
            did_parent,
        }
    };

    Ok(AncestryProof {
        coin_id,
        did_launcher_id,
        model,
        did_lineage_tip: did_lineage.tip(),
        authenticated_launcher: authenticated.launcher_id,
        chain: authenticated.trail,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    use chia_protocol::{Coin, CoinSpend};
    use chia_puzzle_types::singleton::SingletonArgs;
    use chia_puzzle_types::Memos;
    use chia_wallet_sdk::driver::{Launcher, SpendContext, StandardLayer};
    use chia_wallet_sdk::test::Simulator;
    use chia_wallet_sdk::types::Conditions;

    use crate::create::create_simple_did;
    use crate::resolve::{authenticate_singleton_bounded, SingletonLineage};
    use crate::types::Owner;

    /// An honest chain view for tests: the real in-process Simulator answers `parent_spend` (the
    /// creating spend of any coin), and a per-launcher lineage map answers `resolve_singleton_lineage`.
    struct SimSource<'a> {
        sim: &'a Simulator,
        lineages: HashMap<Bytes32, SingletonLineage>,
    }

    impl ChainSource for SimSource<'_> {
        type Error = String;

        fn resolve_singleton_lineage(
            &self,
            launcher_id: Bytes32,
        ) -> Result<Option<SingletonLineage>, Self::Error> {
            Ok(self.lineages.get(&launcher_id).cloned())
        }

        fn parent_spend(&self, coin_id: Bytes32) -> Result<Option<CoinSpend>, Self::Error> {
            let Some(state) = self.sim.coin_state(coin_id) else {
                return Ok(None);
            };
            let parent_id = state.coin.parent_coin_info;
            let Some(parent) = self.sim.coin_state(parent_id) else {
                return Ok(None);
            };
            let (Some(reveal), Some(solution)) = (
                self.sim.puzzle_reveal(parent_id),
                self.sim.solution(parent_id),
            ) else {
                return Ok(None);
            };
            Ok(Some(CoinSpend::new(parent.coin, reveal, solution)))
        }
    }

    /// A single-coin lineage source for `launcher_id` with a chosen member set.
    fn source_with<'a>(
        sim: &'a Simulator,
        launcher_id: Bytes32,
        lineage: SingletonLineage,
    ) -> SimSource<'a> {
        SimSource {
            sim,
            lineages: HashMap::from([(launcher_id, lineage)]),
        }
    }

    /// The full lineage of a freshly-created DID (launcher -> eve -> settled tip), derived from the
    /// settled `Did` alone (`did.coin.parent_coin_info` is the eve coin id).
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

    #[test]
    fn model_a_direct_proves_a_did_state() -> anyhow::Result<()> {
        let mut sim = Simulator::new();
        let ctx = &mut SpendContext::new();
        let owner = sim.bls(1);

        let spend = create_simple_did(ctx, owner.coin, Owner::Standard(owner.pk))?;
        let did = spend.child.expect("create returns a child DID");
        sim.spend_coins(spend.coin_spends, std::slice::from_ref(&owner.sk))?;

        let launcher_id = did.info.launcher_id();
        let source = source_with(&sim, launcher_id, did_lineage(&did));

        let proof = prove_lineage(did.coin.coin_id(), &did, &source)?;
        assert_eq!(proof.model(), LineageModel::Direct);
        assert_eq!(proof.authenticated_launcher(), launcher_id);
        assert_eq!(proof.did_launcher_id(), launcher_id);
        assert_eq!(proof.coin_id(), did.coin.coin_id());
        assert!(!proof.chain().is_empty());
        Ok(())
    }

    #[test]
    fn model_b_launched_from_proves_a_singleton_launched_by_the_did() -> anyhow::Result<()> {
        let mut sim = Simulator::new();
        let ctx = &mut SpendContext::new();
        // Fund the DID with 3 mojos so its spend can create a launcher (even amount 2) AND recreate the
        // DID (odd amount 1) — a singleton spend may emit only ONE odd child.
        let owner = sim.bls(3);
        let owner_p2 = StandardLayer::new(owner.pk);

        let create = create_simple_did(ctx, owner.coin, Owner::Standard(owner.pk))?;
        let did = create.child.expect("create returns a child DID");
        sim.spend_coins(create.coin_spends, std::slice::from_ref(&owner.sk))?;

        // The DID spend creates a launcher parented to the DID coin, and mints an eve singleton from it.
        let launcher = Launcher::new(did.coin.coin_id(), 2).with_singleton_amount(1);
        let launcher_id = launcher.coin().coin_id();
        let (launch_conditions, eve_coin) = launcher.spend(ctx, owner.puzzle_hash, ())?;

        let memos = ctx.hint(did.info.p2_puzzle_hash)?;
        let did_spend_conditions =
            launch_conditions.create_coin(did.info.inner_puzzle_hash().into(), 1, memos);
        did.spend_with(ctx, &owner_p2, did_spend_conditions)?;
        sim.spend_coins(ctx.take(), std::slice::from_ref(&owner.sk))?;

        let source = source_with(&sim, did.info.launcher_id(), did_lineage(&did));

        let proof = prove_lineage(eve_coin.coin_id(), &did, &source)?;
        assert_eq!(
            proof.model(),
            LineageModel::LaunchedFrom {
                launcher: launcher_id,
                did_parent: did.coin.coin_id(),
            }
        );
        assert_eq!(proof.authenticated_launcher(), launcher_id);
        assert_eq!(proof.did_launcher_id(), did.info.launcher_id());
        Ok(())
    }

    #[test]
    fn payment_coin_parented_to_a_did_is_not_a_singleton() -> anyhow::Result<()> {
        let mut sim = Simulator::new();
        let ctx = &mut SpendContext::new();
        let owner = sim.bls(3);
        let owner_p2 = StandardLayer::new(owner.pk);

        let create = create_simple_did(ctx, owner.coin, Owner::Standard(owner.pk))?;
        let did = create.child.expect("create returns a child DID");
        sim.spend_coins(create.coin_spends, std::slice::from_ref(&owner.sk))?;

        // Spend the DID(3): recreate it (odd 1) and pay a PLAIN coin (even 2) to a standard puzzle. The
        // payment's parent is a DID coin, but it is not a singleton — it must NOT prove as owned.
        let memos = ctx.hint(did.info.p2_puzzle_hash)?;
        let payment_puzzle_hash = owner.puzzle_hash;
        let conditions = Conditions::new()
            .create_coin(did.info.inner_puzzle_hash().into(), 1, memos)
            .create_coin(payment_puzzle_hash, 2, Memos::None);
        did.spend_with(ctx, &owner_p2, conditions)?;
        sim.spend_coins(ctx.take(), std::slice::from_ref(&owner.sk))?;

        let payment_coin = Coin::new(did.coin.coin_id(), payment_puzzle_hash, 2);
        let source = source_with(&sim, did.info.launcher_id(), did_lineage(&did));

        let error = prove_lineage(payment_coin.coin_id(), &did, &source).unwrap_err();
        assert!(matches!(error, DidError::NotASingleton));
        Ok(())
    }

    #[test]
    fn attacker_singleton_from_attacker_coin_is_not_did_rooted() -> anyhow::Result<()> {
        let mut sim = Simulator::new();
        let ctx = &mut SpendContext::new();

        let victim = sim.bls(1);
        let victim_spend = create_simple_did(ctx, victim.coin, Owner::Standard(victim.pk))?;
        let victim_did = victim_spend.child.expect("child DID");
        sim.spend_coins(victim_spend.coin_spends, std::slice::from_ref(&victim.sk))?;

        let attacker = sim.bls(1);
        let attacker_spend = create_simple_did(ctx, attacker.coin, Owner::Standard(attacker.pk))?;
        let attacker_did = attacker_spend.child.expect("child DID");
        sim.spend_coins(
            attacker_spend.coin_spends,
            std::slice::from_ref(&attacker.sk),
        )?;

        // The victim's honest lineage — it does NOT contain any attacker coin.
        let source = source_with(
            &sim,
            victim_did.info.launcher_id(),
            did_lineage(&victim_did),
        );

        let error = prove_lineage(attacker_did.coin.coin_id(), &victim_did, &source).unwrap_err();
        assert!(matches!(error, DidError::NotDidRooted));
        Ok(())
    }

    #[test]
    fn pay_to_coin_wearing_a_singleton_puzzle_hash_is_not_a_singleton() -> anyhow::Result<()> {
        let mut sim = Simulator::new();
        let ctx = &mut SpendContext::new();

        let victim = sim.bls(1);
        let victim_spend = create_simple_did(ctx, victim.coin, Owner::Standard(victim.pk))?;
        let victim_did = victim_spend.child.expect("child DID");
        sim.spend_coins(victim_spend.coin_spends, std::slice::from_ref(&victim.sk))?;

        // A plain coin pays TO a puzzle hash equal to a singleton outer puzzle for the victim launcher,
        // but its parent is an ordinary coin — there is NO genuine singleton recreation. This is WHY a
        // bare puzzle-hash equality is forbidden: it must fail closed.
        let alice = sim.bls(1);
        let alice_p2 = StandardLayer::new(alice.pk);
        let fake_singleton_puzzle_hash: Bytes32 =
            SingletonArgs::curry_tree_hash(victim_did.info.launcher_id(), alice.puzzle_hash.into())
                .into();
        alice_p2.spend(
            ctx,
            alice.coin,
            Conditions::new().create_coin(fake_singleton_puzzle_hash, 1, Memos::None),
        )?;
        sim.spend_coins(ctx.take(), std::slice::from_ref(&alice.sk))?;

        let fake_coin = Coin::new(alice.coin.coin_id(), fake_singleton_puzzle_hash, 1);
        let source = source_with(
            &sim,
            victim_did.info.launcher_id(),
            did_lineage(&victim_did),
        );

        let error = prove_lineage(fake_coin.coin_id(), &victim_did, &source).unwrap_err();
        assert!(matches!(error, DidError::NotASingleton));
        Ok(())
    }

    #[test]
    fn melted_did_has_no_identity_singleton() -> anyhow::Result<()> {
        let mut sim = Simulator::new();
        let ctx = &mut SpendContext::new();
        let owner = sim.bls(1);

        let spend = create_simple_did(ctx, owner.coin, Owner::Standard(owner.pk))?;
        let did = spend.child.expect("child DID");
        sim.spend_coins(spend.coin_spends, std::slice::from_ref(&owner.sk))?;

        // The source reports NO lineage for the DID launcher (unlaunched or melted).
        let source = SimSource {
            sim: &sim,
            lineages: HashMap::new(),
        };

        let error = prove_lineage(did.coin.coin_id(), &did, &source).unwrap_err();
        assert!(matches!(error, DidError::NoIdentitySingleton));
        Ok(())
    }

    #[test]
    fn an_over_deep_lineage_fails_closed() -> anyhow::Result<()> {
        let mut sim = Simulator::new();
        let ctx = &mut SpendContext::new();
        let owner = sim.bls(1);

        let spend = create_simple_did(ctx, owner.coin, Owner::Standard(owner.pk))?;
        let did = spend.child.expect("child DID");
        sim.spend_coins(spend.coin_spends, std::slice::from_ref(&owner.sk))?;

        let source = source_with(&sim, did.info.launcher_id(), did_lineage(&did));

        // The settled DID needs two hops to reach its launcher (settled -> eve -> launcher). A depth
        // bound of 1 must fail closed rather than walk further.
        let error = authenticate_singleton_bounded(did.coin.coin_id(), &source, 1).unwrap_err();
        assert!(matches!(error, DidError::LineageTooDeep));
        Ok(())
    }

    #[test]
    fn walk_did_lineage_to_tip_reconstructs_the_current_did() -> anyhow::Result<()> {
        let mut sim = Simulator::new();
        let ctx = &mut SpendContext::new();
        let owner = sim.bls(1);

        let spend = create_simple_did(ctx, owner.coin, Owner::Standard(owner.pk))?;
        let did = spend.child.expect("child DID");
        sim.spend_coins(spend.coin_spends, std::slice::from_ref(&owner.sk))?;

        let source = source_with(&sim, did.info.launcher_id(), did_lineage(&did));

        let tip = crate::resolve::walk_did_lineage_to_tip(&source, did.info.launcher_id())?
            .expect("a launched DID has a tip");
        assert_eq!(tip.coin.coin_id(), did.coin.coin_id());
        assert_eq!(tip.info.launcher_id(), did.info.launcher_id());
        assert_eq!(tip.did(), did);
        Ok(())
    }

    #[test]
    fn walk_did_lineage_to_tip_returns_none_when_absent() -> anyhow::Result<()> {
        let sim = Simulator::new();
        let source = SimSource {
            sim: &sim,
            lineages: HashMap::new(),
        };
        assert!(
            crate::resolve::walk_did_lineage_to_tip(&source, Bytes32::new([1u8; 32]))?.is_none()
        );
        Ok(())
    }
}
