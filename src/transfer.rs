//! DID ownership transfer (SPEC §3, unit U5).
//!
//! Will own transferring a DID to a new p2 puzzle hash (new owner), recreating the child DID under
//! the new owner and requiring one `AGG_SIG_ME` over the CURRENT owner key.
