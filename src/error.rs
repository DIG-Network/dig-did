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
#[derive(Debug, Error)]
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

    /// A `did:chia:1…` string was malformed or failed bech32m decoding.
    #[error("invalid did:chia string: {0}")]
    InvalidDidString(String),

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
    /// launcher). The string states the specific violation.
    #[error("chain precondition failed: {0}")]
    Chain(String),
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
