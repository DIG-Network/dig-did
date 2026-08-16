//! The `dig-did` error taxonomy (SPEC §6).
//!
//! Every fallible operation in this crate returns [`DidError`]. It wraps the underlying
//! chia-wallet-sdk driver error (the byte-source-of-truth for puzzle construction, INV-4) and adds
//! the DID-domain failure modes this crate raises directly — parse failures, fail-closed hydration
//! guards, and the `did:chia:` address-codec errors.

use chia_wallet_sdk::driver::DriverError;
use thiserror::Error;

/// The result type returned by every fallible `dig-did` operation.
pub type DidResult<T> = Result<T, DidError>;

/// Everything that can go wrong while building or parsing a DID spend.
///
/// The variants split into two families: errors *delegated* to the chia-wallet-sdk driver/signer
/// (wrapped verbatim so the underlying cause is never lost), and DID-domain errors this crate
/// raises itself (parse/hydration/codec guards, all fail-closed per SPEC §5).
///
/// Marked `#[non_exhaustive]`: this taxonomy grows whenever a new fail-closed guard is added, and
/// every such addition would otherwise be a breaking change for any downstream exhaustive `match`.
/// Downstream code must carry a `_` arm. `dig-account`'s `AccountError` is `#[non_exhaustive]` for
/// the same reason; the two now agree.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum DidError {
    /// A chia-wallet-sdk driver operation failed (puzzle currying, spend construction, CLVM
    /// evaluation). The wrapped [`DriverError`] carries the precise cause.
    #[error("chia driver error: {0}")]
    Driver(#[from] DriverError),

    /// The signing calculator failed to derive the required signatures from the coin spends
    /// (invalid puzzle/solution, an infinity public key in an `AGG_SIG` condition). The message is
    /// the underlying signer error rendered as a string, so this crate does not leak the signer's
    /// error type into its public surface.
    #[error("signature calculation failed: {0}")]
    Signer(String),

    /// A coin/puzzle/solution could not be parsed as the expected shape.
    #[error("failed to parse DID: {0}")]
    Parse(String),

    /// The supplied puzzle parsed successfully but is not a DID singleton.
    #[error("coin is not a DID singleton")]
    NotDid,

    /// The caller could not prove it controls the DID: the supplied [`crate::Owner`] key does not
    /// curry to the DID's current `p2_puzzle_hash`.
    ///
    /// Raised by irreversible operations — [`crate::melt`] — before any spend is built. Such a
    /// spend could never confirm (the caller cannot produce its `AGG_SIG_ME`), but a melt is
    /// unrecoverable, so authority is refused up front rather than discovered at signing time
    /// (SPEC §5, fail-closed).
    #[error(
        "the supplied owner key does not control this DID: it does not match the DID's current          inner puzzle hash"
    )]
    NotTheOwner,

    /// A `did:chia:1…` string was malformed or failed bech32m decoding.
    #[error("invalid did:chia string: {0}")]
    InvalidDidString(String),

    /// The operation cannot honour the [`crate::Owner`] variant it was given, because it must add
    /// conditions of its own and a caller-supplied pre-built inner spend emits one fixed condition
    /// set. Rather than silently dropping those conditions — which yields a well-formed bundle that
    /// creates none of the coins it reports — the operation refuses. The message names the
    /// alternative the caller should use instead (SPEC §5, fail-closed).
    #[error("unsupported owner for this operation: {0}")]
    UnsupportedOwner(&'static str),

    /// A funding coin with an EVEN amount was supplied to a DID launch. The `u64` is that amount.
    ///
    /// Chia's singleton top layer recognises only the launcher's ODD-amount output as the
    /// singleton, and this crate's launch gives the singleton the funding coin's entire amount. An
    /// even-amount funding coin therefore produces a bundle that spends the money and creates no
    /// DID at all — a total, silent loss of the funding coin, not a rejected spend. Arbitrary
    /// wallet coins are even about half the time.
    ///
    /// Split the funding coin down to exactly the odd amount the singleton should carry first
    /// (`dig-account` splits to 1 mojo) and pass that coin (SPEC §3, fail-closed).
    #[error(
        "funding coin amount {0} is even: a singleton is the odd-amount output of its launcher, so \
         this launch would spend the coin and create no DID — split the funding coin to an exact \
         odd amount (1 mojo is conventional) first"
    )]
    EvenSingletonAmount(u64),

    /// A caller supplied an odd-amount `CREATE_COIN` to a DID-preserving spend. A singleton's inner
    /// puzzle may emit exactly ONE odd-amount `CREATE_COIN`, and the DID's own recreation occupies
    /// it, so a caller's odd-amount `CREATE_COIN` can never be valid here — most often an attempt to
    /// parent a foreign singleton launcher (an amount-1 coin) to the DID coin.
    ///
    /// Refused at build time because the alternative is opaque: the bundle would assemble and report
    /// a child DID, then be rejected at mempool admission. It never enters a block, so no fee is
    /// paid — but the caller pays a wasted round-trip and gets no explanation. Parent the launcher to
    /// an ordinary coin instead and bind it to the DID by an announcement this spend asserts, or by
    /// the launched singleton's owner puzzle hash (SPEC §5, fail-closed).
    #[error(
        "caller supplied an odd-amount CREATE_COIN: a singleton may emit exactly one odd-amount \
         output and the DID's recreation occupies it, so this spend could never be valid on chain \
         — parent any singleton launcher to an ordinary coin and bind it to the DID by announcement"
    )]
    OddAmountCreateCoin,

    /// A caller supplied an `AGG_SIG_UNSAFE` requirement in the conditions of a DID spend.
    ///
    /// Unlike every other `AGG_SIG_*` condition, `AGG_SIG_UNSAFE` is signed with **no coin binding
    /// and no domain separation** — the signed message is the caller's bytes verbatim. A DID owner
    /// induced to sign one produces a permanent, replayable assertion under their identity key,
    /// reusable in any spend or challenge-response the attacker later constructs. Since this crate's
    /// contract is that the caller signs every message `required_signatures` reports, such a
    /// requirement is never legitimate in a DID spend and is refused (SPEC §5, fail-closed).
    ///
    /// This refusal removes the UNBOUNDED shape, not every shape whose damage outlives the bundle.
    /// A permitted `AGG_SIG_PARENT` also outlives it: that signature is bound to the DID coin's
    /// PARENT id, so it stays satisfiable by any future spend of any coin sharing that parent — the
    /// other outputs of the DID's PREVIOUS spend, not anything this spend creates. That set was
    /// fixed before this spend was built and MAY include a coin an earlier caller paid to a third
    /// party, under a puzzle that third party chose. What the refusal buys is a BOUND, not an end
    /// to persistence: unlike `AGG_SIG_UNSAFE`, a permitted signature can never reach a later
    /// generation of the DID and can never become an off-domain assertion.
    ///
    /// Nor does it make a hostile condition set safe. The permitted shapes still move the caller's
    /// own bundled funds to caller-chosen puzzle hashes and still emit announcements under the
    /// DID's authority. A caller composing conditions from an untrusted source MUST review the
    /// bundle before signing — and, where an `AGG_SIG_PARENT` is present, MUST also account for
    /// what the DID's PREVIOUS spend created, which this bundle does not show.
    #[error(
        "caller supplied an AGG_SIG_UNSAFE condition: it is signed with no coin binding and no \
         domain separation, so the resulting signature is replayable against any other spend — a \
         DID spend must never carry one"
    )]
    AggSigUnsafeInConditions,

    /// A caller supplied a `CREATE_COIN` whose amount atom is not chia's canonical integer encoding.
    ///
    /// CLVM integers are SIGNED and chia additionally requires a canonical encoding, but the typed
    /// `CreateCoin::amount` this crate's allowlist reads is a `u64` decoded from the atom UNSIGNED.
    /// The two disagree on exactly the encodings chia refuses: a leading byte with the sign bit set
    /// (`0x80` reads as 128, chain says `CoinAmountNegative`), a redundant leading zero (`0x000002`
    /// reads as 2, chain says `InvalidCoinAmount`), and an atom with more bytes than the value needs
    /// (chain says the amount overflows). Such a spend assembles here, reports a child DID, and is
    /// then dropped at mempool admission telling the caller nothing — the opaque failure this guard
    /// exists to prevent.
    ///
    /// The rule mirrors chia's `sanitize_uint` exactly, so it can refuse nothing the chain would
    /// accept (SPEC §5, fail-closed).
    #[error(
        "caller supplied a CREATE_COIN whose amount is not canonically encoded: {0} — CLVM \
         integers are signed and chia requires a canonical encoding, so this amount would be \
         rejected at mempool admission"
    )]
    NonCanonicalCreateCoinAmount(String),

    /// A caller supplied a condition that is not on the allowlist of shapes a DID-preserving spend
    /// may carry. The string renders the offending condition.
    ///
    /// The guard is an allowlist rather than a list of refusals for a structural reason:
    /// `chia_sdk_types::Condition` is `#[non_exhaustive]` and carries a catch-all `Other` variant
    /// that serializes to CLVM **verbatim**, so any caller can hand a refused condition over under a
    /// name a denylist does not recognise while the chain still sees the condition itself. Only a
    /// guard that refuses everything it does not explicitly permit can fail closed — and it stays
    /// closed when a future SDK release adds a variant nobody here has considered (SPEC §5).
    #[error(
        "caller supplied a condition a DID spend may not carry: {0} — a DID-preserving spend \
         permits only announcements, assertions, even-amount CREATE_COINs, fees, and coin-bound \
         signature requirements"
    )]
    DisallowedCondition(String),

    /// A recovery operation supplied an inconsistent recovery configuration (list hash / required
    /// verifications mismatch).
    #[error("invalid recovery configuration: {0}")]
    InvalidRecovery(String),

    /// Hydration could not establish the lineage proof required to spend the DID (SPEC §5,
    /// fail-closed).
    #[error("missing lineage proof for DID")]
    MissingLineage,

    /// A parsed DID coin was missing the owner hint memo required to recreate its child (SPEC §5,
    /// fail-closed).
    #[error("missing owner hint on DID coin")]
    MissingHint,

    /// A chain-level precondition was violated (e.g. a supplied coin does not match the expected
    /// launcher). The string states the specific violation. Also carries a [`crate::resolve::ChainSource`]
    /// read error verbatim — a failed read NEVER degrades to "assume owned" (SPEC §5, fail-closed).
    #[error("chain precondition failed: {0}")]
    Chain(String),

    /// The DID's identity singleton has no current on-chain coin — it was never launched, or has been
    /// melted, so there is no lineage to root a coin against (SPEC §5, fail-closed).
    #[error("DID singleton has no current on-chain coin (unlaunched or melted)")]
    NoIdentitySingleton,

    /// The coin under proof could not be authenticated as a genuine singleton: its parent-spend chain
    /// does not resolve to a singleton launcher (an ordinary payment/change coin, or a pay-to coin that
    /// merely wears a singleton puzzle hash without a genuine recreation parent spend). SPEC §5.
    #[error("coin is not a genuine singleton")]
    NotASingleton,

    /// The coin authenticates as a genuine singleton, but neither IS the DID singleton nor was launched
    /// from a coin in the DID singleton's lineage — it is not rooted in the DID's identity (SPEC §5).
    #[error("coin is not rooted in the DID's singleton lineage")]
    NotDidRooted,

    /// The DID's current tip authenticated as a genuine singleton, but its GENUINE launcher (walked
    /// from the parent-spend chain) is not the launcher that was requested. This is the money-critical
    /// guard for [`crate::resolve_xch_address`]: a dishonest [`crate::ChainSource`] can echo an
    /// attacker DID's tip for a victim launcher, and the curried `launcher_id` on that tip is
    /// attacker-chosen, so only the parent-walk-authenticated launcher may be trusted. Resolving an
    /// address from a mismatched launcher would pay the wrong recipient, so this fails closed (SPEC §5).
    #[error("the DID tip's authenticated launcher does not match the requested launcher")]
    LauncherMismatch,

    /// The parent-spend walk exceeded [`crate::resolve::MAX_LINEAGE_DEPTH`] — a DoS guard against an
    /// unbounded (possibly adversarial) lineage. The proof fails closed rather than walk forever.
    #[error("singleton lineage exceeds the maximum authenticated depth")]
    LineageTooDeep,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_messages_are_descriptive() {
        assert_eq!(DidError::NotDid.to_string(), "coin is not a DID singleton");
        assert_eq!(
            DidError::MissingLineage.to_string(),
            "missing lineage proof for DID"
        );
        assert_eq!(
            DidError::MissingHint.to_string(),
            "missing owner hint on DID coin"
        );
        assert_eq!(
            DidError::Parse("bad".into()).to_string(),
            "failed to parse DID: bad"
        );
        assert_eq!(
            DidError::InvalidDidString("nope".into()).to_string(),
            "invalid did:chia string: nope"
        );
        assert_eq!(
            DidError::InvalidRecovery("mismatch".into()).to_string(),
            "invalid recovery configuration: mismatch"
        );
        assert_eq!(
            DidError::Signer("boom".into()).to_string(),
            "signature calculation failed: boom"
        );
        assert_eq!(
            DidError::Chain("wrong launcher".into()).to_string(),
            "chain precondition failed: wrong launcher"
        );
    }

    #[test]
    fn wraps_driver_errors_via_from() {
        let driver = DriverError::InvalidSingletonStruct;
        let err: DidError = driver.into();
        assert!(matches!(err, DidError::Driver(_)));
        assert!(err.to_string().starts_with("chia driver error:"));
    }
}
