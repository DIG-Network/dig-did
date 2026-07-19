//! DID hydration from chain data (SPEC §3 & §5, unit U9).
//!
//! Will own reconstructing a spendable [`crate::Did`] (coin + lineage proof + info) from a parent
//! coin spend, applying the fail-closed lineage/hint rules of SPEC §5: a missing lineage proof or
//! owner hint is an error ([`crate::DidError::MissingLineage`] / [`crate::DidError::MissingHint`]),
//! never a silently-degraded DID.
