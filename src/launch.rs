//! Launching other singletons authorized BY a DID (SPEC §3, unit U6).
//!
//! Will own the DID-authorized launch of dependent singletons — a child DID, an NFT, and a
//! CHIP-0035 datastore — where the DID's update spend emits the launch conditions. The datastore
//! launch authorization byte-agrees with `chip35` (SPEC §9 conformance).
