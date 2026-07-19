//! DID melt / termination (SPEC §3, unit U7).
//!
//! Will own melting a DID (spending it with no odd-amount successor), a terminal operation whose
//! [`crate::DidSpend::child`] is `None`. Requires one `AGG_SIG_ME` over the owner key.
