//! The `did:chia:1…` string codec (SPEC §2 & §9, unit U11).
//!
//! Will own encoding a DID launcher id to, and decoding it from, the canonical `did:chia:1…` bech32m
//! string. The codec byte-agrees with `chia-sdk-utils`' `Address` (SPEC §9 conformance) — never a
//! hand-rolled bech32m. Malformed input yields [`crate::DidError::InvalidDidString`].
