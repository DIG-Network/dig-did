//! The public type surface of `dig-did` (SPEC §2).
//!
//! Two kinds of types live here: the DID/coin types re-exported verbatim from chia-wallet-sdk (the
//! byte-source-of-truth, INV-4 — this crate never re-defines a puzzle-carrying type), and the small
//! `dig-did`-owned types that describe an *unsigned* operation result ([`DidSpend`]) and *who* is
//! authorized to spend a DID ([`Owner`]).

use chia_wallet_sdk::driver::Spend;
use chia_wallet_sdk::prelude::PublicKey;

// Re-exported from chia-wallet-sdk so consumers of dig-did never need a direct SDK dependency to
// name the DID it produces. These are the canonical Chia types — dig-did adds no shadow copy.
pub use chia_protocol::{Bytes32, Coin, CoinSpend};
pub use chia_puzzle_types::{LineageProof, Proof};
pub use chia_wallet_sdk::driver::{Did, DidInfo};

/// The result of building a DID operation: the unsigned coin spends plus the recreated child DID.
///
/// This is the crate's output contract (INV-3). A `DidSpend` carries NO signature — the consumer
/// feeds `coin_spends` to [`crate::required_signatures`], signs the reported messages, assembles a
/// `SpendBundle`, and broadcasts. `child` is the DID as it will exist AFTER the spend confirms
/// (`None` for a terminal operation such as a melt, which leaves no DID successor).
#[derive(Debug, Clone)]
#[must_use]
pub struct DidSpend {
    /// The unsigned coin spends this operation produces, in spend order.
    pub coin_spends: Vec<CoinSpend>,

    /// The DID as it will exist after these spends confirm, or `None` for a terminal operation.
    pub child: Option<Did>,
}

impl DidSpend {
    /// Creates a [`DidSpend`] from its coin spends and (optional) recreated child DID.
    pub fn new(coin_spends: Vec<CoinSpend>, child: Option<Did>) -> Self {
        Self { coin_spends, child }
    }
}

/// Who is authorized to spend a DID — i.e. the p2 ("inner") puzzle that guards it.
///
/// Every DID operation is authorized by spending the DID's inner puzzle. `Owner` lets a caller pick
/// that inner puzzle without dig-did hard-coding one:
///
/// - [`Owner::Standard`] is the common case — the standard single-key p2 puzzle. dig-did builds the
///   `StandardLayer` for you; the resulting spend requires one `AGG_SIG_ME` over the given key.
/// - [`Owner::Custom`] is the escape hatch — the caller supplies an already-built inner [`Spend`]
///   (any p2 puzzle: a custom vault, a multisig, a delegated puzzle). dig-did passes it through
///   unchanged, so the caller owns its signature requirements.
#[derive(Debug, Clone, Copy)]
pub enum Owner {
    /// The standard single-key p2 puzzle, owned by the given (synthetic) public key.
    Standard(PublicKey),

    /// A fully pre-built inner spend for a custom p2 puzzle, passed through unchanged.
    Custom(Spend),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn did_spend_carries_its_coin_spends_and_child() {
        let spend = DidSpend::new(Vec::new(), None);
        assert!(spend.coin_spends.is_empty());
        assert!(spend.child.is_none());
    }

    #[test]
    fn owner_standard_holds_the_given_key() {
        let key = PublicKey::default();
        let owner = Owner::Standard(key);
        match owner {
            Owner::Standard(k) => assert_eq!(k, key),
            Owner::Custom(_) => panic!("expected a standard owner"),
        }
    }
}
