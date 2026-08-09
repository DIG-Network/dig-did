//! DID owner spends that leave the DID itself unchanged (SPEC §3, unit U3).
//!
//! The DID's inner puzzle is spent, the DID recreates itself byte-identically, and any conditions the
//! caller supplies ride along in that same spend. This is how a caller binds another operation — a
//! dig-merkle store launch, an NFT assignment, an attestation — to an authenticated act of the DID
//! it controls, in one atomic bundle.
//!
//! The DID's own spend requires exactly one `AGG_SIG_ME` under the owner's key. The caller's
//! conditions may add signature requirements of their own on top of that, but only the kinds bound
//! to a coin id or parent id: the caller's conditions are judged by an ALLOWLIST over their
//! re-parsed CLVM form, so `AGG_SIG_UNSAFE` and every other unbound or lifetime-constant signature
//! kind is refused. See [`permit_only_conditions_a_did_may_carry`] for why only an allowlist can
//! fail closed here.
//!
//! # One odd-amount output
//!
//! A singleton's inner puzzle may emit exactly ONE odd-amount `CREATE_COIN`, and the DID's own
//! recreation occupies it. A singleton launcher is an odd-amount coin, so a foreign singleton CANNOT
//! be parented to the DID coin. [`spend_did_with_conditions`] therefore refuses a caller's
//! odd-amount `CREATE_COIN` outright: left to run, the bundle would assemble and report a child DID,
//! then be dropped at mempool admission — never entering a block, so costing no fee, but telling the
//! caller nothing about why. A DID-rooted launch parents its launcher to an ordinary coin and binds
//! it to the DID by other means (an announcement this spend asserts, or the launched singleton's
//! owner puzzle hash). See
//! `a_foreign_singleton_launcher_cannot_be_parented_to_the_did_coin` in this module's tests.

use chia_protocol::Bytes32;
use chia_wallet_sdk::driver::{Did, SingletonInfo, SpendContext};
use chia_wallet_sdk::types::{Condition, Conditions};

use crate::context::inner_spend;
use crate::error::{DidError, DidResult};
use crate::types::Owner;

/// Spends `did`, emitting `conditions` **in addition to** the recreation condition that preserves the
/// DID unchanged. Returns the recreated child DID.
///
/// The recreation `CREATE_COIN` — same inner puzzle hash, same amount, same owner hint — is emitted
/// FIRST and the caller's conditions follow it; it is never substituted for them, and they never
/// replace it. A DID that fails to recreate itself is a burned identity, so that condition is not
/// the caller's to omit. (The ordering is load-bearing, not cosmetic — see the comment in the body.)
///
/// A caller may emit at most one odd-amount `CREATE_COIN`'s worth of singleton output, and the
/// recreation already uses it; see this module's docs before attempting a DID-parented launcher.
///
/// The spend is staged into `ctx` (drain it with `SpendContext::take` once the whole bundle is
/// assembled). `conditions` MUST have been built in that SAME context: [`Conditions`] holds
/// `NodePtr`s that address `ctx`'s allocator and are meaningless — silently, not as a compile error —
/// in any other.
///
/// # Signature
///
/// The DID's own spend requires exactly one `AGG_SIG_ME`, over this DID coin, under `owner`'s key
/// (SPEC §3). The caller's `conditions` MAY add further signature requirements of their own — a
/// permitted `AGG_SIG_*` among them appears in `required_signatures` too — so the total is one PLUS
/// whatever the caller supplied, not always one. Only the coin-bound kinds are permitted
/// (`AGG_SIG_ME` and the `PARENT`-bearing kinds); `AGG_SIG_UNSAFE` and the kinds bound only to
/// attributes a self-recreating DID never varies are refused, because the signatures they induce
/// are replayable against other spends. See [`permit_only_conditions_a_did_may_carry`].
///
/// # Errors
///
/// - [`DidError::AggSigUnsafeInConditions`] if any caller condition is an `AGG_SIG_UNSAFE`.
/// - [`DidError::DisallowedCondition`] if any caller condition falls outside the allowlist of
///   shapes a DID-preserving spend may carry — the guard refuses everything it does not explicitly
///   permit, judged on the re-parsed conditions, so it fails closed against a condition disguised
///   as one the SDK cannot name.
/// - [`DidError::UnsupportedOwner`] if `owner` is [`Owner::Custom`]. A pre-built inner spend emits
///   one fixed condition set, so it cannot carry the recreation condition this function must add —
///   the caller would receive a child DID the bundle never creates. Build the spend yourself and
///   call `Did::spend` directly instead.
/// - [`DidError::OddAmountCreateCoin`] if any caller condition is an odd-amount `CREATE_COIN`. The
///   singleton's single odd-amount output is already the DID's recreation, so such a spend could
///   never be valid on chain; it is refused here rather than at mempool admission.
/// - [`DidError::Parse`] if the spend produces no parseable successor DID.
/// - [`DidError::Driver`] for any underlying chia-wallet-sdk failure.
pub fn spend_did_with_conditions(
    ctx: &mut SpendContext,
    did: Did,
    owner: Owner,
    conditions: Conditions,
) -> DidResult<Did> {
    if matches!(owner, Owner::Custom(_)) {
        return Err(DidError::UnsupportedOwner(
            "spend_did_with_conditions requires Owner::Standard; a pre-built custom inner spend \
             cannot carry the DID's recreation condition — build the spend yourself and call \
             Did::spend",
        ));
    }

    permit_only_conditions_a_did_may_carry(ctx, &conditions)?;

    let unchanged_inner_puzzle_hash: Bytes32 = did.info.inner_puzzle_hash().into();
    let memos = ctx.hint(did.info.p2_puzzle_hash)?;

    // The recreation is emitted FIRST, and that order is load-bearing, not cosmetic. `Did::spend`
    // identifies the successor by scanning for the first odd-amount `CREATE_COIN`, and BAILS with
    // `Ok(None)` — not `continue` — the moment it meets one carrying no memos. A singleton launcher
    // is exactly that condition (amount 1, `Memos::None`), so a caller launching a foreign singleton
    // would otherwise get "no successor DID" for a spend that is in fact perfectly valid.
    let with_recreation = Conditions::new()
        .create_coin(unchanged_inner_puzzle_hash, did.coin.amount, memos)
        .extend(conditions);

    let spend = inner_spend(ctx, owner, with_recreation)?;
    did.spend(ctx, spend)?
        .ok_or_else(|| DidError::Parse("DID spend produced no successor DID".into()))
}

/// Permits ONLY the condition shapes a DID-preserving spend legitimately carries, refusing
/// everything else — including anything the SDK cannot name.
///
/// # Why an allowlist, and why it judges the RE-PARSED conditions
///
/// [`Condition`] is `#[non_exhaustive]` and its final variant is a catch-all, [`Condition::Other`],
/// which holds a raw CLVM node and serializes to the wire **verbatim**. `Other` is a public variant
/// of a public enum, so ANY caller may build the exact bytes of a forbidden condition and hand them
/// over under that name. A guard that matches the caller's typing therefore judges what the caller
/// chose to CALL the condition, not what the chain will EXECUTE — and its compiler-mandated `_` arm
/// waves the disguise through. This was not theoretical: an `AGG_SIG_UNSAFE` smuggled as `Other`
/// reached `required_signatures` intact, an arbitrary-message signing oracle under the DID owner's
/// identity key.
///
/// Two properties close that, and both are required:
///
/// 1. **Re-parse before judging.** The caller's conditions are allocated to CLVM and read back as
///    `Vec<Condition>`, so an `Other`-wrapped `AGG_SIG_UNSAFE` resolves into the typed variant it
///    actually is. The guard then sees what the chain sees.
/// 2. **Refuse anything not explicitly permitted.** A denylist over a `#[non_exhaustive]` enum with
///    a verbatim catch-all is structurally unable to fail closed: every SDK release may add a
///    variant it silently admits. An allowlist fails closed by construction, and `Other` itself is
///    refused — a DID-preserving spend has no legitimate need for a condition the SDK cannot name.
///
/// # What is permitted, and why
///
/// Announcements and assertions (including timelocks and `ASSERT_MY_*`) only constrain when and
/// alongside what this spend may run; even-amount `CREATE_COIN`s and `RESERVE_FEE` are ordinary
/// payments; `REMARK` is inert; messages are the announcement mechanism's successor.
///
/// Of the `AGG_SIG_*` family only the kinds bound to something UNIQUE to this coin are permitted —
/// `AGG_SIG_ME` and the `PARENT`-bearing kinds, all of which commit to a coin id or parent id that
/// never recurs. `AGG_SIG_PUZZLE`, `AGG_SIG_AMOUNT` and `AGG_SIG_PUZZLE_AMOUNT` are refused because
/// a self-recreating DID keeps those attributes IDENTICAL for its entire lifetime (same puzzle
/// hash, amount 1, every generation), so such a signature is replayable in any later spend emitting
/// the same kind and message. `AGG_SIG_UNSAFE` is refused with its own error, being bound to
/// nothing at all.
///
/// Refused by omission, and deliberately: `MELT_SINGLETON` (it would burn the DID), the `RUN_CAT_TAIL`
/// and NFT/data-store magic `CREATE_COIN` forms, `SOFTFORK`, and `Other`.
fn permit_only_conditions_a_did_may_carry(
    ctx: &mut SpendContext,
    conditions: &Conditions,
) -> DidResult<()> {
    let allocated = ctx.alloc(conditions)?;
    let as_the_chain_sees_them: Vec<Condition> = ctx.extract(allocated)?;

    for condition in &as_the_chain_sees_them {
        match condition {
            // A singleton permits exactly ONE odd-amount `CREATE_COIN` and the recreation claims it.
            // `spend_did_with_conditions` never melts, so a caller's odd-amount output is ALWAYS
            // chain-invalid here — there is no legitimate case this rejects.
            Condition::CreateCoin(create) if create.amount % 2 == 1 => {
                return Err(DidError::OddAmountCreateCoin);
            }
            // `AGG_SIG_UNSAFE` carries no coin binding and no domain separation, so signing it yields
            // a replayable assertion under the DID owner's key over attacker-chosen bytes. It keeps
            // its own error because that is the failure a caller most needs named precisely.
            Condition::AggSigUnsafe(_) => return Err(DidError::AggSigUnsafeInConditions),

            Condition::Remark(_)
            | Condition::CreateCoin(_)
            | Condition::ReserveFee(_)
            | Condition::CreateCoinAnnouncement(_)
            | Condition::AssertCoinAnnouncement(_)
            | Condition::CreatePuzzleAnnouncement(_)
            | Condition::AssertPuzzleAnnouncement(_)
            | Condition::AssertConcurrentSpend(_)
            | Condition::AssertConcurrentPuzzle(_)
            | Condition::SendMessage(_)
            | Condition::ReceiveMessage(_)
            | Condition::AssertMyCoinId(_)
            | Condition::AssertMyParentId(_)
            | Condition::AssertMyPuzzleHash(_)
            | Condition::AssertMyAmount(_)
            | Condition::AssertMyBirthSeconds(_)
            | Condition::AssertMyBirthHeight(_)
            | Condition::AssertEphemeral(_)
            | Condition::AssertSecondsRelative(_)
            | Condition::AssertSecondsAbsolute(_)
            | Condition::AssertHeightRelative(_)
            | Condition::AssertHeightAbsolute(_)
            | Condition::AssertBeforeSecondsRelative(_)
            | Condition::AssertBeforeSecondsAbsolute(_)
            | Condition::AssertBeforeHeightRelative(_)
            | Condition::AssertBeforeHeightAbsolute(_)
            | Condition::AggSigMe(_)
            | Condition::AggSigParent(_)
            | Condition::AggSigParentAmount(_)
            | Condition::AggSigParentPuzzle(_) => {}

            // The arm that makes this fail closed. It is reached by `Other`, by the magic
            // `CREATE_COIN` forms, by `SOFTFORK`, by the replayable `AGG_SIG_*` kinds — and by every
            // variant a future SDK release adds. Widening the allowlist must be a deliberate act
            // with a stated reason, never the default.
            other => return Err(DidError::DisallowedCondition(format!("{other:?}"))),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::create::create_simple_did;
    use crate::test_support::{all_emitted_conditions, creates_coin_to};
    use chia_bls::SecretKey;
    use chia_protocol::Bytes;
    use chia_puzzle_types::singleton::SingletonArgs;
    use chia_puzzle_types::Memos;
    use chia_wallet_sdk::clvm_traits::ToClvm;
    use chia_wallet_sdk::clvmr::{self, Allocator};
    use chia_wallet_sdk::driver::Launcher;
    use chia_wallet_sdk::prelude::{PublicKey, MAINNET_CONSTANTS};
    use chia_wallet_sdk::signer::{AggSigConstants, RequiredSignature};
    use chia_wallet_sdk::test::Simulator;
    use chia_wallet_sdk::types::conditions::{AggSig, AggSigKind, CreateCoin};

    /// A DID minted and confirmed on the simulator, with the owner key material needed to spend it
    /// again. Every test here starts from a DID that genuinely exists on chain.
    struct MintedDid {
        did: Did,
        pk: PublicKey,
        sk: SecretKey,
        puzzle_hash: Bytes32,
    }

    /// The puzzle hash the DID's recreation `CREATE_COIN` must carry: the singleton-wrapped inner
    /// puzzle hash. Derived from the SDK's own currying rather than read back off the returned
    /// child, so the assertion is independent of the value under test.
    fn singleton_puzzle_hash(did: &Did) -> Bytes32 {
        SingletonArgs::curry_tree_hash(did.info.launcher_id, did.info.inner_puzzle_hash()).into()
    }

    fn mint(sim: &mut Simulator, ctx: &mut SpendContext) -> anyhow::Result<MintedDid> {
        let owner = sim.bls(1);
        let spend = create_simple_did(ctx, owner.coin, Owner::Standard(owner.pk))?;
        let did = spend.child.expect("create always returns a child DID");
        sim.spend_coins(spend.coin_spends, std::slice::from_ref(&owner.sk))?;
        Ok(MintedDid {
            did,
            pk: owner.pk,
            sk: owner.sk,
            puzzle_hash: owner.puzzle_hash,
        })
    }

    /// The load-bearing property, in BOTH halves: the DID recreates itself into a parseable child the
    /// simulator accepts, AND the caller's conditions actually reach the wire. A test asserting only
    /// the child would stay green while the conditions were silently dropped — precisely the defect
    /// class this crate is fixing.
    #[test]
    fn spend_did_with_conditions_recreates_the_did_and_emits_the_callers_conditions(
    ) -> anyhow::Result<()> {
        let mut sim = Simulator::new();
        let ctx = &mut SpendContext::new();
        let owner = mint(&mut sim, ctx)?;

        // A distinctive, caller-chosen condition dig-did would never emit on its own.
        let marker = Bytes::from(b"dig-did::update::marker".to_vec());
        let child = spend_did_with_conditions(
            ctx,
            owner.did,
            Owner::Standard(owner.pk),
            Conditions::new().create_puzzle_announcement(marker.clone()),
        )?;

        let coin_spends = ctx.take();
        let emitted = all_emitted_conditions(ctx, &coin_spends)?;
        assert!(
            emitted.iter().any(|condition| matches!(
                condition.as_create_puzzle_announcement(),
                Some(announcement) if announcement.message == marker
            )),
            "the caller's condition must reach the wire"
        );

        assert_eq!(child.info.launcher_id, owner.did.info.launcher_id);
        assert_eq!(child.info.p2_puzzle_hash, owner.did.info.p2_puzzle_hash);
        assert_eq!(child.coin.amount, owner.did.coin.amount);

        sim.spend_coins(coin_spends, &[owner.sk])?;
        Ok(())
    }

    /// The caller's conditions ride ALONGSIDE the recreation, never in place of it — a DID that fails
    /// to recreate itself is a burned identity.
    #[test]
    fn callers_conditions_do_not_displace_the_recreation() -> anyhow::Result<()> {
        let mut sim = Simulator::new();
        let ctx = &mut SpendContext::new();
        let owner = mint(&mut sim, ctx)?;

        let recreated_puzzle_hash = singleton_puzzle_hash(&owner.did);
        let child = spend_did_with_conditions(
            ctx,
            owner.did,
            Owner::Standard(owner.pk),
            Conditions::new()
                .create_puzzle_announcement(Bytes::from(b"noise".to_vec()))
                .create_puzzle_announcement(Bytes::from(b"more noise".to_vec())),
        )?;
        assert_eq!(child.coin.puzzle_hash, recreated_puzzle_hash);

        let coin_spends = ctx.take();
        assert!(
            creates_coin_to(ctx, &coin_spends, recreated_puzzle_hash)?,
            "the recreation CREATE_COIN must survive the caller's conditions"
        );
        sim.spend_coins(coin_spends, &[owner.sk])?;
        Ok(())
    }

    /// Whether `condition` is a `CREATE_COIN` paying `puzzle_hash`.
    fn creates_coin_with_puzzle_hash(condition: &Condition, puzzle_hash: Bytes32) -> bool {
        condition
            .as_create_coin()
            .is_some_and(|create| create.puzzle_hash == puzzle_hash)
    }

    /// Whether `condition` is a `CREATE_PUZZLE_ANNOUNCEMENT` carrying exactly `message`.
    fn announces(condition: &Condition, message: &Bytes) -> bool {
        condition
            .as_create_puzzle_announcement()
            .is_some_and(|announcement| announcement.message == *message)
    }

    /// The recreation `CREATE_COIN` is emitted FIRST, ahead of every caller condition — pinned
    /// structurally, on the conditions the spend actually emits.
    ///
    /// **Do not delete this as redundant with
    /// `a_foreign_singleton_launcher_cannot_be_parented_to_the_did_coin`.** That test no longer
    /// pins the ordering: it was the only fixture supplying the odd-amount, memo-less `CREATE_COIN`
    /// that `Did::spend`'s successor scan aborts on, and `reject_conditions_a_did_must_never_carry`
    /// now refuses exactly that input at build time. Every condition that reaches the emit is
    /// therefore even-amount, and the successor scan finds the recreation wherever it sits — so the
    /// ordering is no longer observable through this crate's public API by outcome alone. This test
    /// is the only thing standing between a refactor to `Conditions::new().extend(conditions)
    /// .create_coin(..)` and a silent break of a property `SPEC.md` states normatively.
    ///
    /// It asserts POSITION, not outcome, precisely because outcome cannot distinguish the two
    /// orderings.
    ///
    /// Position is measured relative to the caller's own conditions rather than as an absolute
    /// index: the puzzle layers contribute a fixed prefix of their own ahead of anything this
    /// function composes (the singleton top layer's `ASSERT_MY_AMOUNT`/`ASSERT_MY_PARENT_ID`, and
    /// the p2 puzzle's `AGG_SIG_ME`), so the recreation is never at absolute index 0. What IS
    /// load-bearing, and what this pins, is that the recreation opens the composed list and the
    /// caller's conditions follow it IMMEDIATELY and in order — the shape `Did::spend`'s successor
    /// scan depends on. Two caller conditions, so a reversal is visible as more than an off-by-one.
    #[test]
    fn the_recreation_is_emitted_before_the_callers_conditions() -> anyhow::Result<()> {
        let mut sim = Simulator::new();
        let ctx = &mut SpendContext::new();
        let owner = mint(&mut sim, ctx)?;

        let recreated_puzzle_hash = singleton_puzzle_hash(&owner.did);
        let first = Bytes::from(b"dig-did::ordering::first".to_vec());
        let second = Bytes::from(b"dig-did::ordering::second".to_vec());
        let _child = spend_did_with_conditions(
            ctx,
            owner.did,
            Owner::Standard(owner.pk),
            Conditions::new()
                .create_puzzle_announcement(first.clone())
                .create_puzzle_announcement(second.clone()),
        )?;

        let coin_spends = ctx.take();
        let emitted = all_emitted_conditions(ctx, &coin_spends)?;

        let index_of = |what: &str, predicate: &dyn Fn(&Condition) -> bool| {
            emitted
                .iter()
                .position(predicate)
                .unwrap_or_else(|| panic!("{what} must reach the wire, got {emitted:?}"))
        };

        let recreation = index_of("the DID's recreation", &|condition| {
            creates_coin_with_puzzle_hash(condition, recreated_puzzle_hash)
        });
        let first = index_of("the caller's first condition", &|condition| {
            announces(condition, &first)
        });
        let second = index_of("the caller's second condition", &|condition| {
            announces(condition, &second)
        });

        assert_eq!(
            (first, second),
            (recreation + 1, recreation + 2),
            "the recreation must open the composed list, with the caller's conditions following it \
             in order, got {emitted:?}"
        );

        sim.spend_coins(coin_spends, &[owner.sk])?;
        Ok(())
    }

    /// Exactly one `AGG_SIG_ME` under the owner's key — the key accounting the consuming crate's
    /// signing gate depends on.
    ///
    /// The fixture deliberately carries a NON-empty condition list. An earlier version passed
    /// `Conditions::new()`, which could not distinguish "the caller's conditions add no signature
    /// requirement" from "the caller supplied nothing at all" — the assertion held for a reason the
    /// test never exercised. A benign announcement is the honest control: conditions ARE present,
    /// and the count is still one.
    #[test]
    fn spend_did_with_conditions_requires_exactly_one_agg_sig_me_under_the_owner(
    ) -> anyhow::Result<()> {
        let mut sim = Simulator::new();
        let ctx = &mut SpendContext::new();
        let owner = mint(&mut sim, ctx)?;

        let _child = spend_did_with_conditions(
            ctx,
            owner.did,
            Owner::Standard(owner.pk),
            Conditions::new().create_puzzle_announcement(Bytes::from(b"benign".to_vec())),
        )?;
        let coin_spends = ctx.take();

        let constants = AggSigConstants::from(&*MAINNET_CONSTANTS);
        let required = crate::sign::required_signatures(&coin_spends, &constants)
            .expect("signature calculation must succeed for a well-formed DID spend");

        assert_eq!(required.len(), 1, "one owner spend, one AGG_SIG_ME");
        match &required[0] {
            RequiredSignature::Bls(bls) => assert_eq!(bls.public_key, owner.pk),
            RequiredSignature::Secp(_) => panic!("a standard owner signs with BLS, not secp"),
        }
        Ok(())
    }

    /// A custom inner spend cannot carry the recreation condition, so it is refused rather than
    /// silently producing a child DID the bundle never creates.
    #[test]
    fn spend_did_with_conditions_refuses_a_custom_owner() -> anyhow::Result<()> {
        let mut sim = Simulator::new();
        let ctx = &mut SpendContext::new();
        let owner = mint(&mut sim, ctx)?;

        let prebuilt = inner_spend(ctx, Owner::Standard(owner.pk), Conditions::new())?;
        let result =
            spend_did_with_conditions(ctx, owner.did, Owner::Custom(prebuilt), Conditions::new());

        assert!(matches!(result, Err(DidError::UnsupportedOwner(_))));
        Ok(())
    }

    /// General composition, proven on the simulator: the caller's conditions create a real extra
    /// coin alongside the DID's own recreation, and the whole bundle is accepted. A bundle whose
    /// conditions merely *look* right on inspection is exactly what a dead-allocator `NodePtr`
    /// produces, so the assertion that matters is that the chain takes it.
    #[test]
    fn composes_with_caller_conditions_that_create_a_coin() -> anyhow::Result<()> {
        let mut sim = Simulator::new();
        let ctx = &mut SpendContext::new();
        let owner = mint(&mut sim, ctx)?;

        // The DID coin holds 1 mojo and must recreate itself with all of it, so the extra coin is
        // balanced by a second coin spent in the same bundle (Chia checks additions against removals
        // across the whole bundle, not per coin).
        let funder = sim.bls(2);
        let funder_spend = inner_spend(ctx, Owner::Standard(funder.pk), Conditions::new())?;
        ctx.spend(funder.coin, funder_spend)?;

        let recreated_puzzle_hash = singleton_puzzle_hash(&owner.did);
        let child = spend_did_with_conditions(
            ctx,
            owner.did,
            Owner::Standard(owner.pk),
            Conditions::new().create_coin(owner.puzzle_hash, 2, Memos::None),
        )?;
        assert_eq!(child.coin.puzzle_hash, recreated_puzzle_hash);

        let coin_spends = ctx.take();
        assert!(
            creates_coin_to(ctx, &coin_spends, recreated_puzzle_hash)?,
            "the DID must still recreate itself"
        );
        assert!(
            creates_coin_to(ctx, &coin_spends, owner.puzzle_hash)?,
            "and the caller's coin must actually be created"
        );
        sim.spend_coins(coin_spends, &[owner.sk, funder.sk])?;
        Ok(())
    }

    /// A CONSTRAINT, pinned so nobody re-derives it the expensive way: a singleton's inner puzzle may
    /// emit exactly ONE odd-amount `CREATE_COIN`, and the DID's own recreation occupies it. A
    /// singleton launcher is an odd-amount coin, so a foreign singleton CANNOT be parented to the DID
    /// coin itself — `spend_did_with_conditions` builds a bundle the singleton top layer then
    /// rejects. A DID-rooted launch must parent its launcher to an ordinary coin and bind it to the
    /// DID some other way (an announcement asserted by this spend, an owner puzzle hash).
    ///
    /// This is a chia singleton rule, not a dig-did choice; the test exists so the failure is a
    /// documented boundary rather than a surprise at the point of use.
    ///
    /// This test is ALSO the guard that pins the recreation-first ordering — it is the only test
    /// whose fixture supplies an odd-amount, memo-less `CREATE_COIN`, the exact condition
    /// `Did::spend`'s successor scan aborts on. Deleting it as "a redundant documentation test"
    /// silently unpins a load-bearing property of `spend_did_with_conditions`.
    #[test]
    fn a_foreign_singleton_launcher_cannot_be_parented_to_the_did_coin() -> anyhow::Result<()> {
        let mut sim = Simulator::new();
        let ctx = &mut SpendContext::new();
        let owner = mint(&mut sim, ctx)?;

        let launcher = Launcher::new(owner.did.coin.coin_id(), 1);
        let (launch_conditions, _eve_coin) = launcher.spend(ctx, owner.puzzle_hash, ())?;

        // The launcher's amount-1 `CREATE_COIN` is the singleton's second odd-amount output, so the
        // bundle could never confirm. It is refused here rather than assembled and dropped at
        // mempool admission, which would report a child DID that no block ever creates.
        let result =
            spend_did_with_conditions(ctx, owner.did, Owner::Standard(owner.pk), launch_conditions);
        assert!(
            matches!(result, Err(DidError::OddAmountCreateCoin)),
            "an odd-amount CREATE_COIN must be refused at build time, got {result:?}"
        );
        Ok(())
    }

    /// `AGG_SIG_UNSAFE` is signed with no coin binding and no domain separation, so a DID owner
    /// induced to sign one produces a replayable assertion over attacker-chosen bytes under their
    /// identity key. The fixture supplies a message that is NOT derived from any coin in this spend,
    /// which is precisely what makes the resulting signature reusable elsewhere.
    #[test]
    fn spend_did_with_conditions_refuses_an_agg_sig_unsafe_condition() -> anyhow::Result<()> {
        let mut sim = Simulator::new();
        let ctx = &mut SpendContext::new();
        let owner = mint(&mut sim, ctx)?;

        let result = spend_did_with_conditions(
            ctx,
            owner.did,
            Owner::Standard(owner.pk),
            Conditions::new()
                .agg_sig_unsafe(owner.pk, Bytes::from(b"ATTACKER-CHOSEN-MESSAGE".to_vec())),
        );
        assert!(
            matches!(result, Err(DidError::AggSigUnsafeInConditions)),
            "an AGG_SIG_UNSAFE must be refused at build time, got {result:?}"
        );
        Ok(())
    }

    /// Wraps `value`'s raw CLVM as [`Condition::Other`] — the catch-all variant the SDK's
    /// `conditions!` macro appends, which serializes to the wire VERBATIM.
    ///
    /// This is the attacker's move, reproduced exactly: build the bytes of a condition the guard
    /// refuses, then hand them over under a name the guard does not recognise. Any check that
    /// matches on the caller's own typing sees `Other` and waves it through, while the chain sees
    /// the condition itself.
    fn smuggled(
        ctx: &mut SpendContext,
        value: &impl ToClvm<Allocator>,
    ) -> anyhow::Result<Condition> {
        Ok(Condition::Other(ctx.alloc(value)?))
    }

    /// The executed bypass, pinned permanently: an `AGG_SIG_UNSAFE` handed over as
    /// [`Condition::Other`] reached the wire under the old denylist and was reported for signing
    /// with no coin binding and no domain separation — an arbitrary-message signing oracle under the
    /// DID owner's identity key. The message here is the attacker's own sentence, not a value
    /// derived from this spend, which is exactly what makes such a signature reusable elsewhere.
    #[test]
    fn refuses_an_agg_sig_unsafe_smuggled_as_an_unrecognized_condition() -> anyhow::Result<()> {
        let mut sim = Simulator::new();
        let ctx = &mut SpendContext::new();
        let owner = mint(&mut sim, ctx)?;

        let unsafe_sig = AggSig::new(
            AggSigKind::Unsafe,
            owner.pk,
            Bytes::from(b"I, the DID owner, authorize the transfer of everything".to_vec()),
        );
        let disguised = smuggled(ctx, &unsafe_sig)?;

        let result = spend_did_with_conditions(
            ctx,
            owner.did,
            Owner::Standard(owner.pk),
            Conditions::new().with(disguised),
        );
        assert!(
            matches!(result, Err(DidError::AggSigUnsafeInConditions)),
            "an AGG_SIG_UNSAFE must be refused however the caller types it, got {result:?}"
        );
        Ok(())
    }

    /// The same bypass against the odd-`CREATE_COIN` half: judging the caller's typing rather than
    /// the wire lets the singleton's single odd-amount output be claimed twice.
    #[test]
    fn refuses_an_odd_amount_create_coin_smuggled_as_an_unrecognized_condition(
    ) -> anyhow::Result<()> {
        let mut sim = Simulator::new();
        let ctx = &mut SpendContext::new();
        let owner = mint(&mut sim, ctx)?;

        let odd: CreateCoin<clvmr::NodePtr> = CreateCoin::new(owner.puzzle_hash, 1, Memos::None);
        let disguised = smuggled(ctx, &odd)?;

        let result = spend_did_with_conditions(
            ctx,
            owner.did,
            Owner::Standard(owner.pk),
            Conditions::new().with(disguised),
        );
        assert!(
            matches!(result, Err(DidError::OddAmountCreateCoin)),
            "an odd-amount CREATE_COIN must be refused however the caller types it, got {result:?}"
        );
        Ok(())
    }

    /// A condition the SDK genuinely cannot name survives re-parsing as [`Condition::Other`], and
    /// the allowlist refuses it. This is the arm that makes the guard fail CLOSED: whatever the next
    /// SDK release, or a bare-CLVM caller, invents, it does not ride into a DID spend unexamined.
    #[test]
    fn refuses_a_condition_the_sdk_cannot_name() -> anyhow::Result<()> {
        let mut sim = Simulator::new();
        let ctx = &mut SpendContext::new();
        let owner = mint(&mut sim, ctx)?;

        // Opcode 12345 is not a condition the SDK knows, so it re-parses as `Other`, unchanged.
        let unknown = smuggled(ctx, &(12345_u32, (Bytes::from(b"payload".to_vec()), ())))?;

        let result = spend_did_with_conditions(
            ctx,
            owner.did,
            Owner::Standard(owner.pk),
            Conditions::new().with(unknown),
        );
        assert!(
            matches!(result, Err(DidError::DisallowedCondition(_))),
            "a condition outside the allowlist must be refused, got {result:?}"
        );
        Ok(())
    }

    /// `AGG_SIG_PUZZLE` binds to the DID's puzzle hash, which a self-recreating DID keeps IDENTICAL
    /// in every generation — so such a signature is replayable in any later spend of the same DID
    /// that emits the same kind and message. `AGG_SIG_AMOUNT` (always 1) and `AGG_SIG_PUZZLE_AMOUNT`
    /// are the same class. The allowlist removes the class rather than waiting for a p2 layer that
    /// authorizes on one of them.
    #[test]
    fn refuses_agg_sig_kinds_bound_only_to_lifetime_constant_attributes() -> anyhow::Result<()> {
        let mut sim = Simulator::new();
        let ctx = &mut SpendContext::new();
        let owner = mint(&mut sim, ctx)?;

        for kind in [
            AggSigKind::Puzzle,
            AggSigKind::Amount,
            AggSigKind::PuzzleAmount,
        ] {
            let mut replay_ctx = SpendContext::new();
            let sig = AggSig::new(kind, owner.pk, Bytes::from(b"replayable".to_vec()));
            let condition = smuggled(&mut replay_ctx, &sig)?;
            let result = spend_did_with_conditions(
                &mut replay_ctx,
                owner.did,
                Owner::Standard(owner.pk),
                Conditions::new().with(condition),
            );
            assert!(
                matches!(result, Err(DidError::DisallowedCondition(_))),
                "{kind:?} binds only to attributes constant across the DID's lifetime and must be \
                 refused, got {result:?}"
            );
        }
        Ok(())
    }

    /// The control the rejection tests cannot supply on their own: an allowlist that refused
    /// EVERYTHING would satisfy every test above while breaking the function entirely. A realistic
    /// mix — an announcement, a timelock, a self-assertion, and a coin-bound signature requirement —
    /// must still build, reach the chain, and add its signature requirement to the DID's own.
    #[test]
    fn permits_the_conditions_a_did_spend_legitimately_carries() -> anyhow::Result<()> {
        let mut sim = Simulator::new();
        let ctx = &mut SpendContext::new();
        let owner = mint(&mut sim, ctx)?;

        let _child = spend_did_with_conditions(
            ctx,
            owner.did,
            Owner::Standard(owner.pk),
            Conditions::new()
                .create_puzzle_announcement(Bytes::from(b"bind-me".to_vec()))
                .assert_my_amount(owner.did.coin.amount)
                .assert_height_relative(0)
                .agg_sig_me(owner.pk, Bytes::from(b"coin-bound".to_vec())),
        )?;

        let coin_spends = ctx.take();
        let constants = AggSigConstants::from(&*MAINNET_CONSTANTS);
        let required = crate::sign::required_signatures(&coin_spends, &constants)
            .expect("signature calculation must succeed for a well-formed DID spend");
        assert_eq!(
            required.len(),
            2,
            "the DID's own AGG_SIG_ME plus the caller's coin-bound one"
        );

        sim.spend_coins(coin_spends, &[owner.sk])?;
        Ok(())
    }
}
