//! DID creation (SPEC §3, unit U2).
//!
//! Will own the mint of a brand-new DID from a funding coin: launcher creation, the eve spend, and
//! the first owner update that makes the DID wallet-parseable. Produces a [`crate::DidSpend`] whose
//! `child` is the newly created DID and whose owner op requires one `AGG_SIG_ME` over the owner key.
