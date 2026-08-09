//! The singleton amount — a coin amount proven odd at construction (SPEC §3 "Create").
//!
//! Chia's singleton top layer only recognises an ODD-amount coin as the singleton. A launch built
//! from an even-amount funding coin therefore spends the funding coin and produces no singleton at
//! all: the money is gone and the identity does not exist. Arbitrary wallet coins are even roughly
//! half the time, so this is not an exotic input.
//!
//! [`SingletonAmount`] makes that state unrepresentable rather than merely refused. Its only
//! constructor validates, its field is private, and it is the only type this crate will hand to a
//! launcher — so a future launch site cannot reach the launcher without passing the check, the way
//! a bare `if amount % 2 == 0` inside one function could be walked around by the next caller.

use chia_protocol::Coin;

use crate::error::{DidError, DidResult};

/// A coin amount that has been proven ODD, and is therefore usable as a singleton's amount.
///
/// Construct with [`SingletonAmount::new`] or [`SingletonAmount::from_funding_coin`]; there is no
/// other way to obtain one, and the inner value is only readable through [`SingletonAmount::get`].
///
/// # Money note
///
/// This type proves the amount is *launchable*, not that it is the amount you meant to lock up.
/// The whole amount becomes the singleton's amount — see [`SingletonAmount::from_funding_coin`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SingletonAmount(u64);

impl SingletonAmount {
    /// The amount `dig-account` splits a funding coin down to before minting, and the smallest
    /// amount a singleton can carry. Callers with no reason to prefer another value should use it.
    pub const MINIMAL: Self = Self(1);

    /// Proves `amount` is odd, and therefore usable as a singleton's amount.
    ///
    /// # Errors
    ///
    /// [`DidError::EvenSingletonAmount`] if `amount` is even (which includes zero). A singleton is
    /// identified on chain by being the odd-amount output of its launcher, so an even amount can
    /// never produce one.
    pub const fn new(amount: u64) -> DidResult<Self> {
        if amount % 2 == 0 {
            return Err(DidError::EvenSingletonAmount(amount));
        }
        Ok(Self(amount))
    }

    /// Proves the funding coin's amount is usable as the singleton's amount.
    ///
    /// # The whole coin becomes the singleton
    ///
    /// A launch built from `coin` gives the singleton `coin.amount` — the ENTIRE amount, because
    /// this crate is a pure spend builder and emits no change output. Deciding where change goes is
    /// the caller's policy, not this crate's: `dig-account` splits an exact 1-mojo coin off its
    /// source coin first (`CREATE_COIN(puzzle_hash, 1, memos)`) and calls in with that, keeping the
    /// remainder under its own control. A caller that instead passes a whole 1,000,001-mojo wallet
    /// coin mints a 1,000,001-mojo DID and locks the excess in the identity coin.
    ///
    /// So: pass a coin pre-split to EXACTLY the amount the singleton should carry.
    ///
    /// # Errors
    ///
    /// [`DidError::EvenSingletonAmount`] if the coin's amount is even — see [`SingletonAmount::new`].
    pub const fn from_funding_coin(coin: &Coin) -> DidResult<Self> {
        Self::new(coin.amount)
    }

    /// The proven-odd amount.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chia_protocol::Bytes32;

    fn coin_of(amount: u64) -> Coin {
        Coin::new(Bytes32::default(), Bytes32::default(), amount)
    }

    #[test]
    fn odd_amounts_are_accepted_and_read_back_unchanged() {
        for amount in [1_u64, 3, 1_000_001, u64::MAX] {
            let proven = SingletonAmount::new(amount)
                .expect("an odd amount is a valid singleton amount")
                .get();
            assert_eq!(proven, amount);
        }
    }

    #[test]
    fn even_amounts_are_refused_by_value() {
        for amount in [0_u64, 2, 1_000_000, u64::MAX - 1] {
            assert!(
                matches!(
                    SingletonAmount::new(amount),
                    Err(DidError::EvenSingletonAmount(reported)) if reported == amount
                ),
                "{amount} is even and must be refused, naming itself"
            );
        }
    }

    #[test]
    fn from_funding_coin_reads_the_coins_amount() {
        assert_eq!(
            SingletonAmount::from_funding_coin(&coin_of(7))
                .expect("7 is odd")
                .get(),
            7
        );
        assert!(matches!(
            SingletonAmount::from_funding_coin(&coin_of(8)),
            Err(DidError::EvenSingletonAmount(8))
        ));
    }

    #[test]
    fn minimal_is_the_one_mojo_amount_dig_account_splits_to() {
        assert_eq!(SingletonAmount::MINIMAL.get(), 1);
    }
}
