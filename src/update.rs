//! DID owner spends that leave the DID itself unchanged (SPEC §3, unit U3).
//!
//! The DID's inner puzzle is spent, the DID recreates itself byte-identically, and any conditions the
//! caller supplies ride along in that same spend. This is how a caller binds another operation — a
//! dig-merkle store launch, an NFT assignment, an attestation — to an authenticated act of the DID
//! it controls, in one atomic bundle.
//!
//! The DID's own spend requires exactly one `AGG_SIG_ME` under the owner's key. The caller's
//! conditions may add signature requirements of their own on top of that; `AGG_SIG_UNSAFE` is
//! refused, since it is unbound to any coin and its signature is replayable elsewhere.
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
/// (SPEC §3). The caller's `conditions` MAY add further signature requirements of their own — any
/// `AGG_SIG_*` among them appears in `required_signatures` too — so the total is one PLUS whatever
/// the caller supplied, not always one. `AGG_SIG_UNSAFE` is the sole exception: it is refused
/// outright, because it is signed with no coin binding and no domain separation and so yields a
/// signature replayable against any other spend.
///
/// # Errors
///
/// - [`DidError::AggSigUnsafeInConditions`] if any caller condition is an `AGG_SIG_UNSAFE`.
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

    reject_conditions_a_did_must_never_carry(&conditions)?;

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

/// Rejects the two condition shapes a DID-preserving spend can never legitimately carry.
///
/// Both are refused at build time rather than left to fail later, because both later failures are
/// silent or misleading: the odd `CREATE_COIN` is dropped at mempool admission with no explanation,
/// and the `AGG_SIG_UNSAFE` does not fail at all — it succeeds, which is the problem.
fn reject_conditions_a_did_must_never_carry(conditions: &Conditions) -> DidResult<()> {
    for condition in conditions.iter() {
        match condition {
            // A singleton permits exactly ONE odd-amount `CREATE_COIN` and the recreation claims it.
            // `spend_did_with_conditions` never melts, so a caller's odd-amount output is ALWAYS
            // chain-invalid here — there is no legitimate case this rejects.
            Condition::CreateCoin(create) if create.amount % 2 == 1 => {
                return Err(DidError::OddAmountCreateCoin);
            }
            // `AGG_SIG_UNSAFE` carries no coin binding and no domain separation, so signing it yields
            // a replayable assertion under the DID owner's key over attacker-chosen bytes.
            Condition::AggSigUnsafe(_) => return Err(DidError::AggSigUnsafeInConditions),
            _ => {}
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
    use chia_wallet_sdk::driver::Launcher;
    use chia_wallet_sdk::prelude::{PublicKey, MAINNET_CONSTANTS};
    use chia_wallet_sdk::signer::{AggSigConstants, RequiredSignature};
    use chia_wallet_sdk::test::Simulator;

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
}
