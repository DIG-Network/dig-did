//! # dig-did — the DIG Network canonical Chia DID expert crate
//!
//! `dig-did` is a **pure, key-free, network-free** SpendBundle-builder for Chia Decentralized
//! Identifiers (DIDs). It constructs the exact [`CoinSpend`]s for every DID
//! lifecycle operation and reports — via [`required_signatures`] — the exact signatures a caller
//! must produce. It never holds a secret key, never signs, and never touches the network. The
//! consumer signs the reported messages, assembles the `SpendBundle`, and broadcasts.
//!
//! ## Invariants
//!
//! These four invariants hold across the entire crate and are the contract every unit is built to
//! (SPEC §1):
//!
//! - **INV-1 — No network.** dig-did performs NO network or chain I/O. Every function is a pure
//!   transform of its inputs; the caller fetches coins and broadcasts bundles.
//! - **INV-2 — No keys.** dig-did never accepts, holds, derives, or logs a secret key. It computes
//!   what must be signed ([`required_signatures`]); the caller's signer produces the signatures.
//! - **INV-3 — Unsigned output.** Every operation returns an unsigned [`DidSpend`] — coin spends
//!   plus the recreated child DID. Signatures are always the caller's responsibility.
//! - **INV-4 — SDK byte-source-of-truth.** Every puzzle, layer, and coin-spend byte is produced by
//!   `chia-wallet-sdk` (pinned to the 0.30 / chia-protocol 0.26 family). dig-did adds DID-workflow
//!   ergonomics on top; it never re-implements a puzzle or hand-rolls a spend bundle.
//!
//! ## Consumer pattern
//!
//! ```text
//! build an unsigned DidSpend  ->  required_signatures(&spend.coin_spends, &constants)
//!   ->  caller signs each reported message  ->  assemble SpendBundle  ->  broadcast
//! ```
//!
//! ## Status
//!
//! The foundation (type surface, error taxonomy, inner-spend helpers, signing boundary) ships
//! alongside **create** ([`create_did`], [`create_simple_did`], [`create_eve_did_only`]),
//! **hydrate** ([`hydrate_did_from_parent_spend`], [`parse_did_coin_spend`],
//! [`did_info_from_puzzle`]), and the **did:chia:** string codec ([`did_string_from_launcher_id`],
//! [`launcher_id_from_did_string`]). The remaining DID operations (update, recovery, transfer,
//! launch, melt, attest, resolve) land in their own units against this foundation; their modules are
//! declared below as doc-only stubs so the layout is final.

// Internal helpers — not part of the public surface.
mod context;

// Public modules.
pub mod error;
pub mod sign;
pub mod types;

// DID creation, hydration, and the did:chia string codec — shipped.
pub mod create;
pub mod did_string;
pub mod hydrate;

// The remaining DID operation modules — declared now so the crate layout is final; each is filled
// in its own unit (doc-only until then, so they add no untested surface).
pub mod attest;
pub mod launch;
pub mod melt;
pub mod recovery;
pub mod transfer;
pub mod update;

// Lineage authentication (U3): the chain-reading seam + singleton walk, and the lineage proof.
pub mod lineage;
pub mod resolve;

// The curated public surface — consumers depend on these paths, not the module layout.
pub use create::{create_did, create_eve_did_only, create_simple_did};
pub use did_string::{did_string_from_launcher_id, launcher_id_from_did_string, DID_CHIA_PREFIX};
pub use error::{DidError, DidResult};
pub use hydrate::{did_info_from_puzzle, hydrate_did_from_parent_spend, parse_did_coin_spend};
pub use lineage::{prove_lineage, AncestryProof, LineageModel};
pub use resolve::{
    walk_did_lineage_to_tip, ChainSource, DidTip, SingletonLineage, MAX_LINEAGE_DEPTH,
};
pub use sign::required_signatures;
pub use types::{Bytes32, Coin, CoinSpend, Did, DidInfo, DidSpend, LineageProof, Owner, Proof};

// Re-export the signing types a consumer needs to CALL [`required_signatures`] and consume its
// result, so a downstream crate need not add a direct chia-wallet-sdk dependency for them.
pub use chia_wallet_sdk::signer::{AggSigConstants, RequiredSignature};
