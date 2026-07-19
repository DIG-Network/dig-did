//! The `did:chia:1…` string codec (SPEC §2.3 & §9).
//!
//! A DID's canonical string form is `did:chia:` followed by the **bech32m** encoding of its
//! `launcher_id`. This codec delegates to `chia-sdk-utils`' [`Address`] — the same codec
//! `dig-identity` and chip35 use — so a `did:chia:` string byte-agrees across the ecosystem
//! (INV-4, SPEC §9). It never hand-rolls bech32m.

use chia_protocol::Bytes32;
use chia_sdk_utils::Address;

use crate::error::{DidError, DidResult};

/// The bech32m human-readable prefix of a v1 Chia DID (`did:chia:1...`).
pub const DID_CHIA_PREFIX: &str = "did:chia:";

/// Encodes a DID singleton's launcher id as its canonical `did:chia:1…` string.
///
/// Bech32m-encoding a fixed 32-byte payload under the fixed [`DID_CHIA_PREFIX`] cannot fail, so this
/// function is infallible.
pub fn did_string_from_launcher_id(launcher_id: Bytes32) -> String {
    Address::new(launcher_id, DID_CHIA_PREFIX.to_string())
        .encode()
        .expect("encoding a 32-byte launcher id under a fixed valid prefix never fails")
}

/// Decodes a `did:chia:1…` string back to the DID singleton's launcher id.
///
/// The input is trimmed of surrounding whitespace before decoding, matching `dig-identity`'s
/// discovery contract that a description field IS the DID string verbatim (modulo whitespace).
///
/// # Errors
///
/// Returns [`DidError::InvalidDidString`] when the string fails bech32m decoding or decodes under a
/// human-readable prefix other than [`DID_CHIA_PREFIX`] — never a silently-wrong launcher id.
pub fn launcher_id_from_did_string(did: &str) -> DidResult<Bytes32> {
    let candidate = did.trim();
    let address = Address::decode(candidate)
        .map_err(|error| DidError::InvalidDidString(error.to_string()))?;

    if address.prefix != DID_CHIA_PREFIX {
        return Err(DidError::InvalidDidString(format!(
            "expected the '{DID_CHIA_PREFIX}' prefix, got '{}'",
            address.prefix
        )));
    }

    Ok(address.puzzle_hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A deterministic, non-literal 32-byte test launcher id, derived by hashing a seed string
    /// (never a bare integer literal — CodeQL flags those as hard-coded cryptographic values).
    fn sample_launcher_id() -> Bytes32 {
        clvm_utils::tree_hash_atom(b"dig-did::did_string::sample-launcher-id").into()
    }

    #[test]
    fn roundtrips_through_the_canonical_string_form() {
        let launcher_id = sample_launcher_id();

        let did = did_string_from_launcher_id(launcher_id);
        assert!(did.starts_with(DID_CHIA_PREFIX));

        let decoded = launcher_id_from_did_string(&did).expect("a freshly-encoded DID must decode");
        assert_eq!(decoded, launcher_id);
    }

    #[test]
    fn trims_surrounding_whitespace_before_decoding() {
        let launcher_id = sample_launcher_id();
        let did = did_string_from_launcher_id(launcher_id);
        let padded = format!("  {did}\n");

        let decoded =
            launcher_id_from_did_string(&padded).expect("padding must not break decoding");
        assert_eq!(decoded, launcher_id);
    }

    #[test]
    fn rejects_malformed_bech32m() {
        let error = launcher_id_from_did_string("not-a-valid-bech32m-string")
            .expect_err("garbage input must fail closed");
        assert!(matches!(error, DidError::InvalidDidString(_)));
    }

    #[test]
    fn rejects_a_wrong_human_readable_prefix() {
        // Encode under a DIFFERENT (but well-formed) prefix — a valid bech32m string, just not a DID.
        let not_a_did = Address::new(sample_launcher_id(), "xch".to_string())
            .encode()
            .expect("a 32-byte payload under the 'xch' prefix encodes fine");

        let error = launcher_id_from_did_string(&not_a_did)
            .expect_err("a non-did:chia prefix must be rejected, never silently accepted");
        assert!(matches!(error, DidError::InvalidDidString(_)));
    }

    #[test]
    fn byte_agrees_with_the_chia_sdk_utils_address_codec() {
        // The codec IS chia-sdk-utils' Address under the hood; prove the string this crate builds
        // agrees with one built directly via `Address::encode` — the same path dig-identity/chip35
        // ultimately rely on.
        let launcher_id = sample_launcher_id();
        let via_address = Address::new(launcher_id, DID_CHIA_PREFIX.to_string())
            .encode()
            .expect("encoding must succeed for a well-formed 32-byte payload");
        let via_dig_did = did_string_from_launcher_id(launcher_id);
        assert_eq!(via_address, via_dig_did);
    }
}
