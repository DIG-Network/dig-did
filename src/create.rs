//! DID creation (SPEC §3 "Create").
//!
//! Minting a DID from a funding coin is three coin spends bundled together (SPEC §3 notes): the
//! **funding coin** spend (which creates the launcher and, per [`Owner`], requires the owner's
//! signature), the **launcher** spend (which creates the eve DID), and an **owner update/settle**
//! spend that confirms the DID's metadata so wallets can parse it. All three land in one
//! [`DidSpend`] — dig-did never splits a create across multiple return values.
//!
//! Every builder here is generic over [`Owner`] (§2.4): a [`Owner::Standard`] key or a
//! [`Owner::Custom`] pre-built inner spend both work, because the settle step is built from the raw
//! [`chia_wallet_sdk::driver::Spend`] primitive (`Did::spend`) rather than a typed inner layer.

use chia_protocol::{Bytes32, Coin};
use chia_puzzle_types::standard::StandardArgs;
use chia_wallet_sdk::driver::{Did, HashedPtr, Launcher, SingletonInfo, SpendContext};
use chia_wallet_sdk::types::Conditions;
use clvm_utils::tree_hash;

use crate::context::{drain_coin_spends, inner_spend};
use crate::error::DidResult;
use crate::types::{DidSpend, Owner};

/// Mints a brand-new DID, fully settled and wallet-parseable, from a funding coin.
///
/// Spends `funding_coin` (owned by `owner`) to create the launcher, launches the eve DID with the
/// given recovery configuration and metadata, then performs the owner-update ("settle") spend that
/// confirms the DID for wallets. Returns a [`DidSpend`] whose `child` is the fully-created,
/// spendable [`Did`].
///
/// # Signature
///
/// Two `AGG_SIG_ME` signatures are required, both under whichever key/spend `owner` names
/// (SPEC §3): one over the funding-coin spend (which creates the launcher) and one over the settle
/// spend (which confirms the DID for wallets). Both are coin-bound `AGG_SIG_ME`, never `AGG_SIG_UNSAFE`.
///
/// # Errors
///
/// Propagates any chia-wallet-sdk driver failure (currying, spend construction) as
/// [`crate::DidError::Driver`].
///
/// # Owner::Custom
///
/// When using `Owner::Custom(spend)`, the ONE caller-supplied inner spend is used for BOTH the
/// funding-coin spend and the settle spend. The caller is responsible for ensuring the custom spend
/// emits all conditions needed to satisfy both steps; conditions are not added by dig-did for a
/// custom spend. A custom create-spend that omits required conditions will fail closed with a parse
/// error, never a custody leak.
pub fn create_did(
    ctx: &mut SpendContext,
    funding_coin: Coin,
    owner: Owner,
    recovery_list_hash: Option<Bytes32>,
    num_verifications_required: u64,
    metadata: HashedPtr,
) -> DidResult<DidSpend> {
    let owner_puzzle_hash = owner_puzzle_hash(ctx, owner)?;

    let launcher = Launcher::new(funding_coin.coin_id(), funding_coin.amount);
    let (launch_conditions, eve) = launcher.create_eve_did(
        ctx,
        owner_puzzle_hash,
        recovery_list_hash,
        num_verifications_required,
        metadata,
    )?;

    let settled = settle(ctx, eve, owner)?;
    spend_funding_coin(ctx, funding_coin, owner, launch_conditions)?;

    Ok(DidSpend::new(drain_coin_spends(ctx), Some(settled)))
}

/// [`create_did`] with the common defaults: no recovery list, a single required verification, and
/// nil metadata. The usual entry point for a DID that does not need a recovery configuration.
///
/// # Errors
///
/// See [`create_did`].
pub fn create_simple_did(
    ctx: &mut SpendContext,
    funding_coin: Coin,
    owner: Owner,
) -> DidResult<DidSpend> {
    create_did(ctx, funding_coin, owner, None, 1, HashedPtr::NIL)
}

/// Launches the eve DID WITHOUT the owner-update settle step.
///
/// The eve DID this returns is real and spendable on-chain, but most wallets expect the additional
/// settle spend ([`create_did`] performs it) before they will recognize the DID. Use this lower-level
/// primitive when the caller intends to perform its own follow-up spend on the eve DID (e.g. to fold
/// the settle into a larger spend bundle).
///
/// # Signature
///
/// Exactly one `AGG_SIG_ME` is required, over the funding-coin spend, under `owner`'s key/spend.
///
/// # Errors
///
/// See [`create_did`].
pub fn create_eve_did_only(
    ctx: &mut SpendContext,
    funding_coin: Coin,
    owner: Owner,
    recovery_list_hash: Option<Bytes32>,
    num_verifications_required: u64,
    metadata: HashedPtr,
) -> DidResult<DidSpend> {
    let owner_puzzle_hash = owner_puzzle_hash(ctx, owner)?;

    let launcher = Launcher::new(funding_coin.coin_id(), funding_coin.amount);
    let (launch_conditions, eve) = launcher.create_eve_did(
        ctx,
        owner_puzzle_hash,
        recovery_list_hash,
        num_verifications_required,
        metadata,
    )?;

    spend_funding_coin(ctx, funding_coin, owner, launch_conditions)?;

    Ok(DidSpend::new(drain_coin_spends(ctx), Some(eve)))
}

/// The puzzle hash of the p2 puzzle `owner` names — the DID's `p2_puzzle_hash` at creation.
///
/// [`Owner::Standard`] curries the standard-puzzle tree hash directly (no CLVM run needed);
/// [`Owner::Custom`] hashes the caller's already-built inner puzzle.
fn owner_puzzle_hash(ctx: &SpendContext, owner: Owner) -> DidResult<Bytes32> {
    Ok(match owner {
        Owner::Standard(public_key) => StandardArgs::curry_tree_hash(public_key).into(),
        Owner::Custom(spend) => tree_hash(ctx, spend.puzzle).into(),
    })
}

/// Performs the owner-update ("settle") spend that leaves the DID's metadata/p2 puzzle unchanged but
/// makes it wallet-parseable — the same effect as [`Did::update`], generalized over [`Owner`] (which
/// `Did::update` cannot be, since it requires a typed `SpendWithConditions` inner layer).
fn settle(ctx: &mut SpendContext, did: Did, owner: Owner) -> DidResult<Did> {
    let unchanged_inner_puzzle_hash: Bytes32 = did.info.inner_puzzle_hash().into();
    let memos = ctx.hint(did.info.p2_puzzle_hash)?;
    let settle_conditions =
        Conditions::new().create_coin(unchanged_inner_puzzle_hash, did.coin.amount, memos);

    let spend = inner_spend(ctx, owner, settle_conditions)?;
    did.spend(ctx, spend)?.ok_or_else(|| {
        crate::error::DidError::Parse("settle spend produced no successor DID".into())
    })
}

/// Spends the funding coin under `owner`, emitting the launcher's create/announcement conditions —
/// the step that actually creates the launcher coin and requires the owner's `AGG_SIG_ME`.
fn spend_funding_coin(
    ctx: &mut SpendContext,
    funding_coin: Coin,
    owner: Owner,
    launch_conditions: Conditions,
) -> DidResult<()> {
    let spend = inner_spend(ctx, owner, launch_conditions)?;
    ctx.spend(funding_coin, spend)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chia_wallet_sdk::prelude::MAINNET_CONSTANTS;
    use chia_wallet_sdk::signer::{AggSigConstants, RequiredSignature};
    use chia_wallet_sdk::test::Simulator;

    /// Creating a simple DID produces exactly the funding+launcher+settle spends, and the resulting
    /// child DID is real: it can be broadcast against a simulator and parsed back byte-identically.
    #[test]
    fn create_simple_did_produces_a_spendable_settled_did() -> anyhow::Result<()> {
        let mut sim = Simulator::new();
        let ctx = &mut SpendContext::new();

        let owner = sim.bls(1);
        let spend = create_simple_did(ctx, owner.coin, Owner::Standard(owner.pk))?;

        let child = spend.child.expect("create always returns a child DID");
        assert_eq!(child.info.recovery_list_hash, None);
        assert_eq!(child.info.num_verifications_required, 1);
        assert_eq!(child.info.p2_puzzle_hash, owner.puzzle_hash);

        sim.spend_coins(spend.coin_spends, &[owner.sk])?;
        Ok(())
    }

    /// `create_did` requires two `AGG_SIG_ME`s — one over the funding-coin spend (which creates the
    /// launcher) and one over the settle spend (which confirms the DID for wallets) — both under the
    /// owner's key, never an `AGG_SIG_UNSAFE` (SPEC §3/§4; corrects the earlier single-signature
    /// estimate now that the settle step is known to require its own spend of the owner's p2 puzzle).
    #[test]
    fn create_did_requires_two_agg_sig_mes_over_the_owner_key() -> anyhow::Result<()> {
        let mut sim = Simulator::new();
        let ctx = &mut SpendContext::new();

        let owner = sim.bls(1);
        let spend = create_simple_did(ctx, owner.coin, Owner::Standard(owner.pk))?;

        let constants = AggSigConstants::from(&*MAINNET_CONSTANTS);
        let required = crate::sign::required_signatures(&spend.coin_spends, &constants)
            .expect("signature calculation must succeed for a well-formed create spend");

        assert_eq!(
            required.len(),
            2,
            "the funding-coin spend AND the settle spend each require one AGG_SIG_ME"
        );
        for signature in &required {
            match signature {
                RequiredSignature::Bls(bls) => assert_eq!(bls.public_key, owner.pk),
                RequiredSignature::Secp(_) => panic!("a standard owner signs with BLS, not secp"),
            }
        }
        Ok(())
    }

    /// A full recovery configuration round-trips through creation untouched.
    #[test]
    fn create_did_preserves_a_custom_recovery_configuration() -> anyhow::Result<()> {
        let mut sim = Simulator::new();
        let ctx = &mut SpendContext::new();

        let owner = sim.bls(1);
        let recovery_list_hash =
            Some(clvm_utils::tree_hash_atom(b"dig-did::create::recovery-list").into());

        let spend = create_did(
            ctx,
            owner.coin,
            Owner::Standard(owner.pk),
            recovery_list_hash,
            2,
            HashedPtr::NIL,
        )?;
        let child = spend.child.expect("create always returns a child DID");

        assert_eq!(child.info.recovery_list_hash, recovery_list_hash);
        assert_eq!(child.info.num_verifications_required, 2);

        sim.spend_coins(spend.coin_spends, &[owner.sk])?;
        Ok(())
    }

    /// The lower-level eve-only primitive skips the settle spend, returning just the eve DID — the
    /// caller is expected to perform its own follow-up spend.
    #[test]
    fn create_eve_did_only_skips_the_settle_spend() -> anyhow::Result<()> {
        let mut sim = Simulator::new();
        let ctx = &mut SpendContext::new();

        let owner = sim.bls(1);
        let spend = create_eve_did_only(
            ctx,
            owner.coin,
            Owner::Standard(owner.pk),
            None,
            1,
            HashedPtr::NIL,
        )?;

        // Two spends: funding coin + launcher — no separate settle spend.
        assert_eq!(spend.coin_spends.len(), 2);

        let eve = spend.child.expect("create always returns a child DID");
        assert_eq!(eve.info.p2_puzzle_hash, owner.puzzle_hash);

        sim.spend_coins(spend.coin_spends, &[owner.sk])?;
        Ok(())
    }
}
