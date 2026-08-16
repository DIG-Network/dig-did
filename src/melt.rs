//! DID melt / termination (SPEC §3, unit U7).
//!
//! [`melt`] spends a DID singleton with a `MELT_SINGLETON` (magic `-113`) condition instead of the
//! recreation condition every other operation emits, so the singleton is permanently retired: the
//! returned [`DidSpend`] carries `child == None` and no coin in the lineage's next generation
//! exists. Like every operation the spend is unsigned (INV-1..4); it requires exactly one
//! `AGG_SIG_ME` over the owner's synthetic key, obtained via [`crate::required_signatures`].
//!
//! This is `dig-merkle`'s `melt` for the identity half of a profile: deleting a profile ends both
//! of its singletons, and a DID left alive after its store is gone still resolves while pointing at
//! nothing.
//!
//! # The melted amount is an implicit fee, not a payout
//!
//! The singleton's amount cannot be recovered to a caller-supplied puzzle hash in this spend. The
//! singleton top layer asserts that AT MOST ONE odd-amount `CREATE_COIN` is emitted, and the melt
//! magic condition (`(51 () -113)`, itself odd) occupies it — a second odd-amount output makes the
//! puzzle fail outright, and an even-amount output cannot carry an odd singleton's whole amount.
//! The amount is therefore not paid out, and the resulting output-under-input difference is an
//! implicit fee to the farmer. For the conventional 1-mojo DID that is one mojo.

use chia_puzzle_types::standard::StandardArgs;
use chia_wallet_sdk::driver::{Did, SpendContext};
use chia_wallet_sdk::types::Conditions;

use crate::context::{drain_coin_spends, inner_spend};
use crate::error::{DidError, DidResult};
use crate::types::{DidSpend, Owner};

/// Terminally spends `did`, ending its lineage: the returned [`DidSpend`] creates no successor
/// singleton and its `child` is `None`.
///
/// The DID's inner puzzle emits a single `MELT_SINGLETON` condition, so the singleton top layer
/// recreates nothing and no coin of the next generation is ever created. The spend is returned
/// unsigned (INV-3).
///
/// # This is irreversible, and the caller must mean it
///
/// A launcher id is derived from a coin that has been spent, so a melted DID can never be
/// recreated: every `did:chia:` reference to it, anywhere, becomes permanently unresolvable. There
/// is no undo at any layer.
///
/// # Signing
///
/// The spend requires exactly one `AGG_SIG_ME`, over this DID coin, under `owner`'s key. Obtain it
/// via [`crate::required_signatures`]; dig-did never signs (INV-2).
///
/// # Errors
///
/// - [`DidError::UnsupportedOwner`] for [`Owner::Custom`]. The `MELT_SINGLETON` condition is built
///   INSIDE this call and a pre-built inner spend emits one fixed condition set, so accepting one
///   would return `Ok` for a bundle that melts nothing while reporting a melt.
/// - [`DidError::NotTheOwner`] if `owner`'s key does not curry to the DID's current
///   `p2_puzzle_hash` — i.e. the caller cannot prove it controls the singleton. Because the melt is
///   irreversible, authority is checked BEFORE any spend exists rather than left to fail at
///   mempool admission with a signature the caller cannot produce.
/// - [`DidError::Driver`] if the SDK fails to build the spend.
/// - [`DidError::Parse`] if the spend unexpectedly yields a successor DID — a melt that recreated
///   the singleton is not a melt, and is refused rather than returned as one.
pub fn melt(ctx: &mut SpendContext, did: Did, owner: Owner) -> DidResult<DidSpend> {
    if matches!(owner, Owner::Custom(_)) {
        return Err(DidError::UnsupportedOwner(
            "melt requires Owner::Standard; a pre-built custom inner spend cannot carry the \
             MELT_SINGLETON condition this call builds — the bundle would melt nothing",
        ));
    }

    gate_owner_controls_did(&did, owner)?;

    let spend = inner_spend(ctx, owner, Conditions::new().melt_singleton())?;
    let successor = did.spend(ctx, spend)?;

    if successor.is_some() {
        return Err(DidError::Parse(
            "melt produced a successor DID: the singleton was recreated, not melted".into(),
        ));
    }

    Ok(DidSpend::new(drain_coin_spends(ctx), None))
}

/// Refuses `owner` unless its key curries to the DID's current inner puzzle hash.
///
/// The check is `StandardArgs::curry_tree_hash(pk) == did.info.p2_puzzle_hash` — the same
/// commitment the DID's own puzzle enforces on chain, evaluated here so an unauthorized melt is
/// refused before a spend exists. Fail-closed by construction: only an exact match proceeds.
fn gate_owner_controls_did(did: &Did, owner: Owner) -> DidResult<()> {
    let Owner::Standard(public_key) = owner else {
        return Err(DidError::UnsupportedOwner(
            "melt requires Owner::Standard to prove control of the singleton",
        ));
    };

    let controlling_puzzle_hash = StandardArgs::curry_tree_hash(public_key);
    if controlling_puzzle_hash != did.info.p2_puzzle_hash.into() {
        return Err(DidError::NotTheOwner);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chia_protocol::Coin;
    use chia_puzzle_types::singleton::SingletonArgs;
    use chia_wallet_sdk::driver::SingletonInfo;
    use chia_wallet_sdk::prelude::MAINNET_CONSTANTS;
    use chia_wallet_sdk::signer::{AggSigConstants, RequiredSignature};
    use chia_wallet_sdk::test::Simulator;

    use crate::create::create_simple_did;
    use crate::required_signatures;
    use crate::test_support::all_emitted_conditions;

    /// Creates and settles a DID on the simulator, returning the owner keypair and the settled DID.
    fn settled_did(
        sim: &mut Simulator,
    ) -> anyhow::Result<(chia_wallet_sdk::test::BlsPairWithCoin, Did)> {
        let owner = sim.bls(1);
        let ctx = &mut SpendContext::new();
        let spend = create_simple_did(ctx, owner.coin, Owner::Standard(owner.pk))?;
        let did = spend.child.expect("create returns a child DID");
        sim.spend_coins(spend.coin_spends, std::slice::from_ref(&owner.sk))?;
        Ok((owner, did))
    }

    /// The coin the DID's NEXT generation would occupy if this spend recreated the singleton: the
    /// melted coin's id as parent, wearing the DID's own (unchanged) singleton-wrapped puzzle hash.
    fn would_be_successor(did: &Did) -> Coin {
        let wrapped =
            SingletonArgs::curry_tree_hash(did.info.launcher_id(), did.info.inner_puzzle_hash());
        Coin::new(did.coin.coin_id(), wrapped.into(), did.coin.amount)
    }

    /// THE acceptance property (#3043): after a melt confirms, the lineage TERMINATES — walking
    /// forward from the melted coin finds no successor singleton on chain.
    ///
    /// Asserting only that the spend validated cannot see this: a spend that quietly recreated the
    /// singleton validates identically and leaves the identity alive. So the successor coin the
    /// next generation WOULD occupy is reconstructed independently of the builder — from the DID's
    /// own launcher id and inner puzzle hash, the way `resolve`'s walk reconstructs a tip — and the
    /// simulator is asked whether it exists. The melted coin is confirmed spent in the same breath,
    /// so "no successor" cannot be a vacuous "nothing happened".
    #[test]
    fn a_melted_did_has_no_next_generation_on_chain() -> anyhow::Result<()> {
        let mut sim = Simulator::new();
        let (owner, did) = settled_did(&mut sim)?;
        let successor = would_be_successor(&did);

        // Control: before the melt the DID coin is a live, unspent singleton and its successor
        // does not yet exist. Without this the assertions below could pass on a DID that was never
        // created at all.
        assert!(
            sim.coin_state(did.coin.coin_id())
                .is_some_and(|state| state.spent_height.is_none()),
            "the DID must be live before it is melted"
        );

        let ctx = &mut SpendContext::new();
        let built = melt(ctx, did, Owner::Standard(owner.pk))?;
        assert!(built.child.is_none(), "a melt reports no successor DID");
        sim.spend_coins(built.coin_spends, std::slice::from_ref(&owner.sk))?;

        assert!(
            sim.coin_state(did.coin.coin_id())
                .is_some_and(|state| state.spent_height.is_some()),
            "the melt must actually have spent the DID coin"
        );
        assert!(
            sim.coin_state(successor.coin_id()).is_none(),
            "the lineage must terminate: no next-generation singleton may exist"
        );
        Ok(())
    }

    /// A CONTROL for the test above: an ordinary DID-preserving spend of the same DID, on the same
    /// harness, DOES create exactly that successor coin.
    ///
    /// Without it, "the successor coin does not exist" proves nothing about melting — a wrong
    /// reconstruction of the successor id would report termination for every spend, including one
    /// that kept the singleton alive.
    #[test]
    fn a_non_melting_spend_does_create_the_next_generation() -> anyhow::Result<()> {
        let mut sim = Simulator::new();
        let (owner, did) = settled_did(&mut sim)?;
        let successor = would_be_successor(&did);

        let ctx = &mut SpendContext::new();
        let _recreated = crate::spend_did_with_conditions(
            ctx,
            did,
            Owner::Standard(owner.pk),
            Conditions::new(),
        )?;
        let coin_spends = ctx.take();
        sim.spend_coins(coin_spends, std::slice::from_ref(&owner.sk))?;

        assert!(
            sim.coin_state(successor.coin_id()).is_some(),
            "the reconstructed successor id must be the one a live spend really creates"
        );
        Ok(())
    }

    /// The executed melt spend emits NO `CREATE_COIN` at all — no successor, and no payout.
    ///
    /// This asserts what the CHAIN sees: the conditions the full coin spend actually produces. The
    /// `MELT_SINGLETON` magic condition itself is deliberately absent from that output — the
    /// singleton top layer consumes it and does not prepend it — so its presence is proven instead
    /// by the spend confirming at all (without it the layer's `has_odd_output_been_found` assert
    /// raises). What remains observable, and is the whole point, is an empty output set: the
    /// singleton's amount is not paid out, and becomes an implicit fee.
    #[test]
    fn the_executed_melt_creates_no_coin_at_all() -> anyhow::Result<()> {
        let mut sim = Simulator::new();
        let (owner, did) = settled_did(&mut sim)?;

        let ctx = &mut SpendContext::new();
        let built = melt(ctx, did, Owner::Standard(owner.pk))?;

        let inspector = &mut SpendContext::new();
        let conditions = all_emitted_conditions(inspector, &built.coin_spends)?;
        let created: Vec<_> = conditions
            .iter()
            .filter_map(|condition| condition.clone().into_create_coin())
            .collect();
        assert!(
            created.is_empty(),
            "a melt creates no coin: no successor, and the amount becomes an implicit fee, got: {created:?}"
        );
        Ok(())
    }

    /// Fail-closed authority: a key that does not control the DID is refused BEFORE a spend exists.
    ///
    /// A melt is irreversible, so the refusal must not be left to the signature check at mempool
    /// admission — and it must not leave a half-built spend in the context either.
    #[test]
    fn a_key_that_does_not_control_the_did_is_refused() -> anyhow::Result<()> {
        let mut sim = Simulator::new();
        let (_owner, did) = settled_did(&mut sim)?;
        let stranger = sim.bls(1);

        let ctx = &mut SpendContext::new();
        let result = melt(ctx, did, Owner::Standard(stranger.pk));

        assert!(
            matches!(result, Err(DidError::NotTheOwner)),
            "a stranger's melt must be refused, got: {result:?}"
        );
        assert!(
            ctx.take().is_empty(),
            "the refusal must happen before any spend is built"
        );
        Ok(())
    }

    /// REGRESSION (mirrors dig-merkle #2418): a melt MUST refuse [`Owner::Custom`] rather than
    /// return a bundle carrying no `MELT_SINGLETON` condition.
    ///
    /// `context::inner_spend` DROPS the conditions for a custom owner, so accepting one would
    /// return `Ok` for a spend that melts nothing — and, worse here, one that also recreates
    /// nothing, which the singleton layer rejects outright at admission.
    #[test]
    fn a_custom_owner_melt_is_refused() -> anyhow::Result<()> {
        use chia_wallet_sdk::driver::{SpendWithConditions, StandardLayer};

        let mut sim = Simulator::new();
        let (owner, did) = settled_did(&mut sim)?;

        let ctx = &mut SpendContext::new();
        let prebuilt =
            StandardLayer::new(owner.pk).spend_with_conditions(ctx, Conditions::new())?;
        let result = melt(ctx, did, Owner::Custom(prebuilt));

        assert!(
            matches!(result, Err(DidError::UnsupportedOwner(_))),
            "a custom-owner melt must refuse, got: {result:?}"
        );
        Ok(())
    }

    /// The unsigned melt requires exactly one `AGG_SIG_ME`, over the owner's key.
    #[test]
    fn the_melt_requires_a_single_agg_sig_me() -> anyhow::Result<()> {
        let mut sim = Simulator::new();
        let (owner, did) = settled_did(&mut sim)?;

        let ctx = &mut SpendContext::new();
        let built = melt(ctx, did, Owner::Standard(owner.pk))?;

        let constants = AggSigConstants::from(&*MAINNET_CONSTANTS);
        let required = required_signatures(&built.coin_spends, &constants)?;
        assert_eq!(required.len(), 1, "one AGG_SIG_ME expected");
        match &required[0] {
            RequiredSignature::Bls(bls) => assert_eq!(bls.public_key, owner.pk),
            RequiredSignature::Secp(_) => panic!("a standard owner signs with a BLS key"),
        }
        Ok(())
    }
}
