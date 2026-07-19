//! DID metadata update & settle (SPEC §3, unit U3).
//!
//! Will own the metadata-update spend and the follow-up "settle" spend that confirms new metadata so
//! wallets can sync it from the parent coin, plus the no-op spend used to emit conditions (e.g.
//! assigning the DID to NFTs) without transferring it. Each owner op requires one `AGG_SIG_ME`.
