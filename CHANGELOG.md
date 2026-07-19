# Changelog

All notable changes to this project are documented here.
This project adheres to [Semantic Versioning](https://semver.org) and
[Conventional Commits](https://www.conventionalcommits.org).

## [Unreleased]

### Features
- Resolve a DID's current XCH payment address from chain: `resolve_xch_address` +
  `resolve_xch_address_from_did_string` — walk the DID to its tip, authenticate the genuine launcher
  via the parent-spend walk (money-critical, fail-closed), then return the owner's bech32m `Address`.
  New `DidError::LauncherMismatch`; `Address` re-exported. (#1239)
- Migrate the `ChainSource` seam onto the canonical `dig-chainsource-interface` crate: drop dig-did's
  local `ChainSource` trait + `SingletonLineage`, depend on the published interface, and re-export both
  so `dig_did::ChainSource` / `dig_did::SingletonLineage` are unchanged (additive). (#1240)

## [0.3.0] - 2026-07-19

### Features
- Lineage proof (ChainSource seam, singleton auth, prove_lineage, AncestryProof) (#2)

## [0.2.0] - 2026-07-19

### Features
- DID create + hydrate + did:chia codec (#1)

## [0.1.0] - 2026-07-19

### Features
- Crate skeleton, SPEC, signing boundary, and CI gate set (U1)


