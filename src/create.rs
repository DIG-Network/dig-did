//! DID creation (SPEC §3 "Create").
//!
//! Minting a DID from a funding coin is three coin spends bundled together (SPEC §3 notes): the
//! **funding coin** spend (which creates the launcher and, per [`Owner`], requires the owner's
//! signature), the **launcher** spend (which creates the eve DID), and an **owner update/settle**
//! spend that confirms the DID's metadata so wallets can parse it. All three land in one
//! [`DidSpend`] — dig-did never splits a create across multiple return values.
//!
//! Creation requires [`Owner::Standard`] (§2.4). [`Owner::Custom`] is REFUSED with
//! [`crate::DidError::UnsupportedOwner`]: both spends in a create emit conditions that are only
//! computable inside this call, and a pre-built inner spend cannot carry them. See the
//! `# Owner::Custom` section on [`create_did`] for the three independent reasons.

use chia_protocol::{Bytes32, Coin};
use chia_puzzle_types::standard::StandardArgs;
use chia_wallet_sdk::driver::{Did, HashedPtr, Launcher, SpendContext};
use chia_wallet_sdk::types::Conditions;

use crate::amount::SingletonAmount;
use crate::context::{drain_coin_spends, inner_spend};
use crate::error::{DidError, DidResult};
use crate::types::{DidSpend, Owner};

/// Mints a brand-new DID, fully settled and wallet-parseable, from a funding coin.
///
/// Spends `funding_coin` (owned by `owner`) to create the launcher, launches the eve DID with the
/// given recovery configuration and metadata, then performs the owner-update ("settle") spend that
/// confirms the DID for wallets. Returns a [`DidSpend`] whose `child` is the fully-created,
/// spendable [`Did`].
///
/// # The funding coin becomes the DID, in full
///
/// The singleton's amount IS `funding_coin.amount` — the whole coin, because this crate builds
/// spends and emits no change output (choosing where change goes is caller policy). Two
/// consequences the caller owns:
///
/// - The amount MUST be ODD, or no singleton is created at all and the coin is spent for nothing.
///   Refused here with [`crate::DidError::EvenSingletonAmount`].
/// - Any excess is locked in the identity coin forever. Pass a coin pre-split to EXACTLY the amount
///   the DID should carry — `dig-account` splits an exact 1-mojo coin off its source coin and calls
///   in with that, which is the reference pattern.
///
/// # Signature
///
/// Two `AGG_SIG_ME` signatures are required, both under whichever key/spend `owner` names
/// (SPEC §3): one over the funding-coin spend (which creates the launcher) and one over the settle
/// spend (which confirms the DID for wallets). Both are coin-bound `AGG_SIG_ME`, never `AGG_SIG_UNSAFE`.
///
/// # Errors
///
/// - [`crate::DidError::UnsupportedOwner`] if `owner` is [`Owner::Custom`] — see below.
/// - [`crate::DidError::EvenSingletonAmount`] if `funding_coin.amount` is even — see above.
/// - Any chia-wallet-sdk driver failure (currying, spend construction) as
///   [`crate::DidError::Driver`].
///
/// # Owner::Custom
///
/// Refused. A create is two spends of two different coins, and a pre-built inner spend is one fixed
/// `(puzzle, solution)` pair emitting one fixed condition set, so it cannot serve both. Three
/// independent reasons, each sufficient on its own:
///
/// 1. **Different coins, one condition set.** The funding coin must emit the launcher's
///    create/announcement conditions; the DID coin must emit its own recreation. One spend cannot
///    emit both.
/// 2. **Circular.** The recreation condition needs `did.info.inner_puzzle_hash()`, which does not
///    exist until `create_eve_did` has run *inside* this call. No caller can precompute it.
/// 3. **Actively wrong, not merely insufficient.** With a custom owner the DID's p2 puzzle IS the
///    caller's puzzle, so replaying that solution on the DID coin re-emits the FUNDING conditions —
///    a second launcher `CREATE_COIN` from the DID coin, not a settle.
///
/// Additionally, any `AGG_SIG_ME` baked into a custom spend is coin-bound and therefore valid for at
/// most one of the two coins.
///
/// A caller that genuinely needs a custom DID p2 puzzle wants a launch-conditions builder it can
/// compose into its own parent spend (mirroring `dig_merkle`'s `mint_datastore_launch_with_kind`),
/// not this end-to-end builder.
pub fn create_did(
    ctx: &mut SpendContext,
    funding_coin: Coin,
    owner: Owner,
    recovery_list_hash: Option<Bytes32>,
    num_verifications_required: u64,
    metadata: HashedPtr,
) -> DidResult<DidSpend> {
    let owner_puzzle_hash = standard_owner_puzzle_hash(owner, "create_did")?;

    let (launch_conditions, eve) = singleton_launcher(funding_coin)?.create_eve_did(
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
/// # The funding coin becomes the DID, in full
///
/// This delegates to [`create_did`], so its funding-coin contract applies unchanged: the singleton's
/// amount is the coin's ENTIRE amount, it MUST be odd, and any excess is locked in the DID forever.
/// Pass a coin pre-split to exactly the intended amount.
///
/// # Errors
///
/// See [`create_did`] — including [`crate::DidError::EvenSingletonAmount`].
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
/// # The funding coin becomes the DID, in full
///
/// Identical to [`create_did`]: the eve DID's amount is `funding_coin.amount` in full, it MUST be
/// odd (else the coin is spent and no singleton exists), and any excess is locked in the identity
/// coin. Pass a coin pre-split to exactly the intended amount — `dig-account`'s 1-mojo split is the
/// reference pattern.
///
/// # Signature
///
/// Exactly one `AGG_SIG_ME` is required, over the funding-coin spend, under `owner`'s key/spend.
///
/// # Errors
///
/// See [`create_did`] — including [`crate::DidError::EvenSingletonAmount`] and the
/// [`Owner::Custom`] refusal, which applies here for reason 1
/// (the launcher conditions are produced inside this call and a pre-built spend cannot carry them).
pub fn create_eve_did_only(
    ctx: &mut SpendContext,
    funding_coin: Coin,
    owner: Owner,
    recovery_list_hash: Option<Bytes32>,
    num_verifications_required: u64,
    metadata: HashedPtr,
) -> DidResult<DidSpend> {
    let owner_puzzle_hash = standard_owner_puzzle_hash(owner, "create_eve_did_only")?;

    let (launch_conditions, eve) = singleton_launcher(funding_coin)?.create_eve_did(
        ctx,
        owner_puzzle_hash,
        recovery_list_hash,
        num_verifications_required,
        metadata,
    )?;

    spend_funding_coin(ctx, funding_coin, owner, launch_conditions)?;

    Ok(DidSpend::new(drain_coin_spends(ctx), Some(eve)))
}

/// The single place this crate builds a [`Launcher`] — the chokepoint that keeps an even funding
/// amount out of every launch path.
///
/// The SDK's `Launcher::new(parent_coin_id, amount)` uses `amount` as BOTH the launcher solution's
/// amount and the launched singleton's amount, and accepts any `u64`. Routing every launch through
/// [`SingletonAmount`] means the odd-amount proof is carried in the type rather than repeated as a
/// guard each launch site must remember; a new launch site cannot obtain a launcher without it.
fn singleton_launcher(funding_coin: Coin) -> DidResult<Launcher> {
    let amount = SingletonAmount::from_funding_coin(&funding_coin)?;
    Ok(Launcher::new(funding_coin.coin_id(), amount.get()))
}

/// The DID's `p2_puzzle_hash` at creation — the gate that keeps [`Owner::Custom`] out of the create
/// path (see [`create_did`]'s `# Owner::Custom` section for why it cannot work here).
///
/// `operation` names the caller so the refusal message points at the function the user actually
/// called.
fn standard_owner_puzzle_hash(owner: Owner, operation: &'static str) -> DidResult<Bytes32> {
    match owner {
        Owner::Standard(public_key) => Ok(StandardArgs::curry_tree_hash(public_key).into()),
        Owner::Custom(_) => Err(DidError::UnsupportedOwner(match operation {
            "create_eve_did_only" => {
                "create_eve_did_only requires Owner::Standard; a pre-built custom inner spend \
                 cannot emit the launcher conditions, which are only computable inside this call — \
                 build the launch yourself with Launcher::create_eve_did"
            }
            _ => {
                "create_did requires Owner::Standard; a pre-built custom inner spend cannot emit \
                 both the launcher conditions and the DID's recreation — build the launch yourself \
                 with Launcher::create_eve_did"
            }
        })),
    }
}

/// Performs the owner-update ("settle") spend that leaves the DID's metadata/p2 puzzle unchanged but
/// makes it wallet-parseable — the no-condition case of [`crate::spend_did_with_conditions`], which
/// owns the recreation logic so there is exactly one code path for it.
fn settle(ctx: &mut SpendContext, did: Did, owner: Owner) -> DidResult<Did> {
    crate::update::spend_did_with_conditions(ctx, did, owner, Conditions::new())
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

    /// A pre-built inner spend cannot emit the launcher conditions, so creation refuses it outright.
    ///
    /// Before this refusal, `create_eve_did_only` returned `Ok` with an eve DID while the bundle
    /// contained no `CREATE_COIN` to `SINGLETON_LAUNCHER_HASH` at all — a DID that could never
    /// exist. That silent-drop reproduction is preserved as the control below.
    #[test]
    fn create_did_refuses_a_custom_owner() -> anyhow::Result<()> {
        let mut sim = Simulator::new();
        let ctx = &mut SpendContext::new();

        let owner = sim.bls(1);
        let prebuilt = prebuilt_inner_spend(ctx, owner.pk)?;

        assert!(matches!(
            create_simple_did(ctx, owner.coin, Owner::Custom(prebuilt)),
            Err(DidError::UnsupportedOwner(_))
        ));
        assert!(matches!(
            create_eve_did_only(
                ctx,
                owner.coin,
                Owner::Custom(prebuilt),
                None,
                1,
                HashedPtr::NIL
            ),
            Err(DidError::UnsupportedOwner(_))
        ));
        Ok(())
    }

    /// The control that makes the refusal load-bearing: the same custom spend, routed through the
    /// underlying SDK launcher the way the old code did, produces a bundle with NO launcher
    /// `CREATE_COIN`. This is the outcome the refusal now prevents; if it ever stops holding, the
    /// refusal above is guarding a defect that no longer exists and should be re-derived.
    #[test]
    fn a_custom_inner_spend_would_silently_drop_the_launcher_conditions() -> anyhow::Result<()> {
        let mut sim = Simulator::new();
        let ctx = &mut SpendContext::new();

        let owner = sim.bls(1);
        let prebuilt = prebuilt_inner_spend(ctx, owner.pk)?;

        let launcher = Launcher::new(owner.coin.coin_id(), owner.coin.amount);
        let (_dropped_launch_conditions, _eve) =
            launcher.create_eve_did(ctx, owner.puzzle_hash, None, 1, HashedPtr::NIL)?;
        // Exactly what the old `spend_funding_coin` did with an `Owner::Custom`: the conditions go
        // nowhere, because a pre-built spend is used verbatim.
        ctx.spend(owner.coin, prebuilt)?;

        let coin_spends = drain_coin_spends(ctx);
        assert!(
            !crate::test_support::creates_coin_to(
                ctx,
                &coin_spends,
                chia_puzzles::SINGLETON_LAUNCHER_HASH.into(),
            )?,
            "nothing in the bundle creates the launcher the eve DID was supposedly launched from"
        );
        Ok(())
    }

    /// A syntactically valid inner spend that emits a condition of its own — the most favourable
    /// custom spend a caller could plausibly supply.
    fn prebuilt_inner_spend(
        ctx: &mut SpendContext,
        public_key: chia_wallet_sdk::prelude::PublicKey,
    ) -> DidResult<chia_wallet_sdk::driver::Spend> {
        inner_spend(
            ctx,
            Owner::Standard(public_key),
            Conditions::new().reserve_fee(0),
        )
    }

    /// An even-amount funding coin is refused by EVERY creation entry point, naming the amount.
    ///
    /// Without the refusal all three assemble happily: the singleton's amount is the funding coin's
    /// amount, an even-amount coin is not a singleton, so the bundle spends the coin and creates no
    /// DID — a total loss with a success return. `sim.bls(2)` is a real, ordinary even coin, the
    /// shape roughly half of arbitrary wallet coins have.
    #[test]
    fn every_creation_entry_point_refuses_an_even_funding_coin() -> anyhow::Result<()> {
        let mut sim = Simulator::new();
        let ctx = &mut SpendContext::new();

        let owner = sim.bls(2);
        assert_eq!(owner.coin.amount, 2, "the fixture must be genuinely even");

        assert!(matches!(
            create_simple_did(ctx, owner.coin, Owner::Standard(owner.pk)),
            Err(DidError::EvenSingletonAmount(2))
        ));
        assert!(matches!(
            create_did(
                ctx,
                owner.coin,
                Owner::Standard(owner.pk),
                None,
                1,
                HashedPtr::NIL
            ),
            Err(DidError::EvenSingletonAmount(2))
        ));
        assert!(matches!(
            create_eve_did_only(
                ctx,
                owner.coin,
                Owner::Standard(owner.pk),
                None,
                1,
                HashedPtr::NIL
            ),
            Err(DidError::EvenSingletonAmount(2))
        ));
        Ok(())
    }

    /// The positive control for the refusal above: the SAME three entry points, given an odd
    /// funding coin one mojo away from the refused fixture, each produce a bundle the simulator
    /// accepts. Without this, a refusal that rejected every amount would look identical.
    #[test]
    fn every_creation_entry_point_accepts_an_odd_funding_coin() -> anyhow::Result<()> {
        for build in [
            (|ctx: &mut SpendContext, coin, owner| create_simple_did(ctx, coin, owner))
                as fn(&mut SpendContext, Coin, Owner) -> DidResult<DidSpend>,
            |ctx, coin, owner| create_did(ctx, coin, owner, None, 1, HashedPtr::NIL),
            |ctx, coin, owner| create_eve_did_only(ctx, coin, owner, None, 1, HashedPtr::NIL),
        ] {
            let mut sim = Simulator::new();
            let ctx = &mut SpendContext::new();

            let owner = sim.bls(3);
            assert_eq!(owner.coin.amount, 3, "the fixture must be genuinely odd");

            let spend = build(ctx, owner.coin, Owner::Standard(owner.pk))?;
            let child = spend.child.expect("create always returns a child DID");
            assert_eq!(
                child.coin.amount, 3,
                "the singleton carries the funding coin's ENTIRE amount"
            );

            sim.spend_coins(spend.coin_spends, &[owner.sk])?;
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
