//! The singleton amount — a coin amount proven odd at construction (SPEC §3 "Create").
//!
//! Chia's singleton top layer only recognises an ODD-amount coin as the singleton. A launch built
//! from an even-amount funding coin therefore spends the funding coin and produces no singleton at
//! all: the money is gone and the identity does not exist. Arbitrary wallet coins are even roughly
//! half the time, so this is not an exotic input.
//!
//! [`SingletonAmount`] makes that state unrepresentable rather than merely refused. Its only
//! constructor validates, its field is private, and it is the only type this crate hands to a
//! launcher — unlike a bare `if amount % 2 == 0` inside one function, which the next caller can
//! simply not write.
//!
//! The type alone does not stop a future author calling the SDK's `Launcher::new` directly, so that
//! constructor is on `disallowed-methods` in `clippy.toml` and CI runs
//! `cargo clippy --all-targets -- -D warnings`. A launch site that skips this check therefore fails
//! the build; the single production exemption is annotated at `create::singleton_launcher`.

use chia_protocol::Coin;

use crate::error::{DidError, DidResult};

/// A coin amount that has been proven ODD, and is therefore usable as a singleton's amount.
///
/// Construct with [`SingletonAmount::new`] or [`SingletonAmount::from_funding_coin`]; there is no
/// other way to obtain one, and the inner value is only readable through [`SingletonAmount::get`].
///
/// # Why this is public when no public function takes one
///
/// It is a PRE-FLIGHT VALIDATOR for callers, not a parameter type: a wallet splitting a funding coin
/// checks the amount it is about to split to — `SingletonAmount::new(amount)?` — BEFORE building the
/// spend, and gets the same answer, from the same code, that `create_did` would give it afterwards.
/// The create entry points take a `Coin` and validate internally, so the type appears in no
/// signature today. (dig_ecosystem#2479 proposes promoting it so `dig-account` and `dig-merkle`
/// share this one validated type instead of each restating the odd-amount rule; until then, keep it
/// public — a consumer restating the rule is exactly the drift it exists to prevent.)
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
    ///
    /// This const is built in-module, so it bypasses [`SingletonAmount::new`]'s check — the same is
    /// true of any const added beside it. Every such const MUST therefore carry an ODD value, and
    /// MUST be covered by a test that re-validates it through `new` (`consts_are_odd…` below) rather
    /// than asserting its literal number, so that an even one turns a test red.
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

    /// Pins the PROPERTY the in-module consts must have, not the number they happen to hold.
    ///
    /// `MINIMAL` is `Self(1)`, a construction that skips [`SingletonAmount::new`]. Asserting
    /// `MINIMAL.get() == 1` would only catch a changed *value*; it would stay green if someone
    /// added — or changed `MINIMAL` to — an EVEN const, which is the failure that actually loses a
    /// funding coin. Re-validating through `new` fails on exactly that.
    #[test]
    fn consts_are_odd_and_would_pass_the_constructor() {
        assert_const_would_pass_the_constructor("MINIMAL", SingletonAmount::MINIMAL);
    }

    /// Re-validates an in-module const through the public constructor. Call it once per const added
    /// to [`SingletonAmount`], from the test above.
    fn assert_const_would_pass_the_constructor(name: &str, amount: SingletonAmount) {
        assert!(
            SingletonAmount::new(amount.get()).is_ok(),
            "{name} = {} bypasses new(), so it must itself be odd",
            amount.get()
        );
    }
}
