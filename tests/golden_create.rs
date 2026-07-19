//! Golden `CoinSpend` fixture for DID creation (SPEC §8 "Backwards compatibility").
//!
//! Given fixed inputs, [`dig_did::create_simple_did`] MUST always produce byte-identical
//! `CoinSpend`s — that is the guarantee downstream custody + signing code depends on. This is the
//! FIRST entry in the crate's golden-fixture suite; later units add their own operation's fixture
//! alongside it. A future dig-did that changes this byte shape without updating (and proving it can
//! still decode) this fixture violates SPEC §8.

use chia_bls::SecretKey;
use chia_protocol::Coin;
use chia_puzzle_types::standard::StandardArgs;
use chia_traits::chia_error::Result as StreamResult;
use chia_traits::Streamable;
use chia_wallet_sdk::driver::SpendContext;
use dig_did::{create_simple_did, parse_did_coin_spend, Owner};

/// The exact hex-encoded `CoinSpend` bytes `create_simple_did` produces for [`funding_coin`] +
/// [`owner_key`] today. Regenerate ONLY as a deliberate, documented protocol event (SPEC §8) — never
/// silently, and never without also proving older fixtures still decode.
// `create_simple_did`'s internal spend order is [launcher, settle, funding] — the launcher and
// settle spends are recorded as `create_eve_did`/`Did::spend` build them, and the funding-coin spend
// (which requires the owner's signature) is appended last (SPEC §3 "Create").
const GOLDEN_LAUNCHER_SPEND_HEX: &str =
    include_str!("fixtures/create_simple_did.launcher_spend.hex");
const GOLDEN_SETTLE_SPEND_HEX: &str = include_str!("fixtures/create_simple_did.settle_spend.hex");
const GOLDEN_FUNDING_SPEND_HEX: &str = include_str!("fixtures/create_simple_did.funding_spend.hex");

/// A deterministic (never a hard-coded integer/byte literal — CodeQL flags those) BLS keypair, so
/// the fixture is reproducible without embedding raw key material in the test source.
fn owner_key() -> chia_bls::PublicKey {
    SecretKey::from_seed(b"dig-did::golden::create_simple_did::v1").public_key()
}

/// A deterministic funding coin owned by [`owner_key`], sized to fund a 1-mojo DID launch.
fn funding_coin() -> Coin {
    let parent_coin_info =
        clvm_utils::tree_hash_atom(b"dig-did::golden::funding-coin-parent").into();
    let puzzle_hash = StandardArgs::curry_tree_hash(owner_key()).into();
    Coin::new(parent_coin_info, puzzle_hash, 1)
}

#[test]
fn create_simple_did_reproduces_the_golden_fixture_byte_identically() -> anyhow::Result<()> {
    let ctx = &mut SpendContext::new();
    let spend = create_simple_did(ctx, funding_coin(), Owner::Standard(owner_key()))?;

    assert_eq!(spend.coin_spends.len(), 3, "funding + launcher + settle");
    let actual_hex: Vec<String> = spend
        .coin_spends
        .iter()
        .map(stream_to_hex)
        .collect::<StreamResult<_>>()?;

    assert_eq!(
        actual_hex[0],
        GOLDEN_LAUNCHER_SPEND_HEX.trim(),
        "launcher spend bytes changed"
    );
    assert_eq!(
        actual_hex[1],
        GOLDEN_SETTLE_SPEND_HEX.trim(),
        "settle spend bytes changed"
    );
    assert_eq!(
        actual_hex[2],
        GOLDEN_FUNDING_SPEND_HEX.trim(),
        "funding-coin spend bytes changed"
    );
    Ok(())
}

/// The current reader decodes the golden fixture's settle spend back into the same DID this crate
/// just built — proving `parse_did_coin_spend` (SPEC §5/§9) stays byte-agreeing with the builder.
#[test]
fn the_current_reader_decodes_the_golden_settle_spend() -> anyhow::Result<()> {
    let ctx = &mut SpendContext::new();
    let spend = create_simple_did(ctx, funding_coin(), Owner::Standard(owner_key()))?;
    let settle_spend = &spend.coin_spends[1];

    let parsed = parse_did_coin_spend(
        settle_spend.coin,
        &settle_spend.puzzle_reveal,
        &settle_spend.solution,
    )?
    .expect("the golden settle spend is a real DID spend");

    let (parsed_did, _p2_spend) = parsed;
    assert_eq!(
        parsed_did.info,
        spend.child.expect("create always returns a child DID").info,
        "the reader must reconstruct the exact DidInfo the builder produced"
    );
    Ok(())
}

fn stream_to_hex<T: Streamable>(value: &T) -> StreamResult<String> {
    Ok(hex::encode(value.to_bytes()?))
}
