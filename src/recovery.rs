//! DID recovery configuration & recovery spends (SPEC §3, unit U4).
//!
//! Will own setting the recovery list hash / number of required verifications and executing a
//! recovery that rotates the DID to a new owner via the configured recoverers' attestations.
