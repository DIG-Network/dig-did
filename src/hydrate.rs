//! DID hydration from chain data (SPEC §3 & §5).
//!
//! These functions reconstruct dig-did's own types — a spendable [`Did`], or a raw [`DidInfo`] —
//! from puzzle reveals and solutions a caller already fetched from the chain. Every function here
//! is a pure parse: no network I/O, no keys, and **fail-closed** (SPEC §5) — an under-specified or
//! ambiguous input is an error, never a guessed or partially-populated DID.

use chia_protocol::{Coin, Program};
use chia_wallet_sdk::driver::{Did, DidInfo, DriverError, Puzzle, Spend};
use chia_wallet_sdk::prelude::{Allocator, NodePtr};
use clvm_traits::ToClvm;

use crate::error::{DidError, DidResult};

/// Reconstructs the spendable child [`Did`] created by a parent DID's coin spend.
///
/// This is the primary hydration path (SPEC §3 "Hydrate", unit U9): given the parent DID's coin,
/// its puzzle reveal and solution (as fetched from the chain), and the child coin it created, it
/// derives the child's [`Did`] — its [`DidInfo`] and lineage [`chia_puzzle_types::Proof`] — ready to
/// spend.
///
/// # Errors
///
/// Fail-closed per SPEC §5: this never fabricates a lineage proof or an owner hint.
///
/// - [`DidError::NotDid`] — the parent puzzle does not parse as a DID singleton at all.
/// - [`DidError::MissingLineage`] — the parent spend's inner puzzle emitted no odd-amount successor
///   coin, so no child DID was created to hydrate.
/// - [`DidError::MissingHint`] — a successor coin was created but is not hinted, so its owner p2
///   puzzle hash cannot be recovered.
/// - [`DidError::Parse`] — the puzzle reveal/solution bytes did not deserialize as CLVM.
/// - [`DidError::Driver`] — any other chia-wallet-sdk driver failure (currying/evaluation).
pub fn hydrate_did_from_parent_spend(
    parent_coin: Coin,
    parent_puzzle_reveal: &Program,
    parent_solution: &Program,
    child_coin: Coin,
) -> DidResult<Did> {
    let mut allocator = Allocator::new();
    let parent_puzzle_ptr = alloc_program(&mut allocator, parent_puzzle_reveal)?;
    let parent_solution_ptr = alloc_program(&mut allocator, parent_solution)?;
    let parent_puzzle = Puzzle::parse(&allocator, parent_puzzle_ptr);

    match Did::parse_child(
        &mut allocator,
        parent_coin,
        parent_puzzle,
        parent_solution_ptr,
        child_coin,
    ) {
        Ok(Some(did)) => Ok(did),
        Ok(None) => Err(DidError::NotDid),
        Err(DriverError::MissingChild) => Err(DidError::MissingLineage),
        Err(DriverError::MissingHint) => Err(DidError::MissingHint),
        Err(other) => Err(DidError::Driver(other)),
    }
}

/// Parses a DID coin's OWN spend — its puzzle reveal and solution — into the [`Did`] it spent and,
/// when the spend carried one, the p2 (owner) [`Spend`] that authorized it.
///
/// Unlike [`hydrate_did_from_parent_spend`] (which looks at the PARENT to find a child), this parses
/// a DID coin's own recorded spend. Returns `Ok(None)` when the puzzle is not a DID at all (not an
/// error — the caller may be scanning unrelated coins); returns `Ok(Some((did, None)))` when the DID
/// was spent via its recovery path (no ordinary p2 solution to report).
///
/// # Errors
///
/// [`DidError::Parse`] if the reveal/solution bytes fail to deserialize; [`DidError::Driver`] for any
/// other chia-wallet-sdk driver failure.
pub fn parse_did_coin_spend(
    coin: Coin,
    puzzle_reveal: &Program,
    solution: &Program,
) -> DidResult<Option<(Did, Option<Spend>)>> {
    let mut allocator = Allocator::new();
    let puzzle_ptr = alloc_program(&mut allocator, puzzle_reveal)?;
    let solution_ptr = alloc_program(&mut allocator, solution)?;
    let puzzle = Puzzle::parse(&allocator, puzzle_ptr);

    let parsed = Did::parse(&allocator, coin, puzzle, solution_ptr).map_err(DidError::Driver)?;

    Ok(parsed.map(|(did, p2)| {
        let p2_spend = p2.map(|(p2_puzzle, p2_solution)| Spend::new(p2_puzzle.ptr(), p2_solution));
        (did, p2_spend)
    }))
}

/// Parses a puzzle reveal into its [`DidInfo`] — the DID's outer-puzzle fields alone, without a
/// coin or lineage proof. Useful when only the DID's identity/metadata is needed (e.g. resolving a
/// `did:chia:` string to its current recovery configuration) and a full [`Did`] is unnecessary.
///
/// Returns `Ok(None)` when the puzzle is not a DID at all (not an error).
///
/// # Errors
///
/// [`DidError::Parse`] if the reveal bytes fail to deserialize; [`DidError::Driver`] for any other
/// chia-wallet-sdk driver failure.
pub fn did_info_from_puzzle(puzzle_reveal: &Program) -> DidResult<Option<DidInfo>> {
    let mut allocator = Allocator::new();
    let puzzle_ptr = alloc_program(&mut allocator, puzzle_reveal)?;
    let puzzle = Puzzle::parse(&allocator, puzzle_ptr);

    let parsed = DidInfo::parse(&allocator, puzzle).map_err(DidError::Driver)?;
    Ok(parsed.map(|(info, _p2_puzzle)| info))
}

/// Deserializes a [`Program`] (a puzzle reveal or solution as bytes) into an allocated [`NodePtr`].
fn alloc_program(allocator: &mut Allocator, program: &Program) -> DidResult<NodePtr> {
    program
        .to_clvm(allocator)
        .map_err(|error| DidError::Parse(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chia_wallet_sdk::driver::{Launcher, SpendContext, StandardLayer};
    use chia_wallet_sdk::test::Simulator;
    use chia_wallet_sdk::types::Conditions;

    /// A full create → chain-confirm → hydrate roundtrip: the hydrated child must byte-agree with
    /// the `Did` the SDK itself produced when building the spend (proves this module wraps
    /// `Did::parse_child` faithfully, per SPEC §5/§9).
    #[test]
    fn hydrates_the_exact_did_the_sdk_produced() -> anyhow::Result<()> {
        let mut sim = Simulator::new();
        let ctx = &mut SpendContext::new();

        let owner = sim.bls(1);
        let owner_p2 = StandardLayer::new(owner.pk);

        let (create_did, expected_did) =
            Launcher::new(owner.coin.coin_id(), 1).create_simple_did(ctx, &owner_p2)?;
        owner_p2.spend(ctx, owner.coin, create_did)?;
        sim.spend_coins(ctx.take(), &[owner.sk])?;

        let parent_coin = sim
            .coin_state(expected_did.coin.parent_coin_info)
            .expect("the launcher coin must be tracked by the simulator")
            .coin;
        let parent_puzzle_reveal = sim
            .puzzle_reveal(expected_did.coin.parent_coin_info)
            .expect("the launcher spend must have a recorded puzzle reveal");
        let parent_solution = sim
            .solution(expected_did.coin.parent_coin_info)
            .expect("the launcher spend must have a recorded solution");

        let hydrated = hydrate_did_from_parent_spend(
            parent_coin,
            &parent_puzzle_reveal,
            &parent_solution,
            expected_did.coin,
        )
        .expect("a real create-spend must hydrate cleanly");

        assert_eq!(
            hydrated, expected_did,
            "hydration must byte-agree with the SDK's own Did"
        );
        Ok(())
    }

    /// A parent spend that creates no odd-amount successor has no child DID to hydrate — this must
    /// fail closed, never guess or panic.
    #[test]
    fn fails_closed_when_the_parent_spend_creates_no_child() -> anyhow::Result<()> {
        let mut sim = Simulator::new();
        let ctx = &mut SpendContext::new();

        let owner = sim.bls(1);
        let owner_p2 = StandardLayer::new(owner.pk);

        let (create_did, did) =
            Launcher::new(owner.coin.coin_id(), 1).create_simple_did(ctx, &owner_p2)?;
        owner_p2.spend(ctx, owner.coin, create_did)?;
        sim.spend_coins(ctx.take(), &[owner.sk])?;

        // Build (never broadcast) a follow-up DID spend whose inner puzzle emits NO conditions at
        // all — no odd-amount successor, so there is no child to hydrate.
        did.spend_with(ctx, &owner_p2, Conditions::new())?;
        let coin_spends = ctx.take();
        let melt_spend = coin_spends
            .into_iter()
            .find(|coin_spend| coin_spend.coin == did.coin)
            .expect("the no-successor DID spend must be present");

        // No child was ever created by that spend; make up a plausible (but nonexistent) one.
        let bogus_child = chia_protocol::Coin::new(did.coin.coin_id(), owner.puzzle_hash, 1);

        let error = hydrate_did_from_parent_spend(
            did.coin,
            &melt_spend.puzzle_reveal,
            &melt_spend.solution,
            bogus_child,
        )
        .expect_err("a melt spend creates no child DID to hydrate");

        assert!(matches!(error, DidError::MissingLineage));
        Ok(())
    }

    /// `parse_did_coin_spend` on a plain (non-DID) puzzle returns `Ok(None)`, never an error.
    #[test]
    fn parse_did_coin_spend_returns_none_for_a_non_did_puzzle() -> anyhow::Result<()> {
        let mut sim = Simulator::new();
        let ctx = &mut SpendContext::new();

        let alice = sim.bls(1);
        let alice_p2 = StandardLayer::new(alice.pk);
        alice_p2.spend(
            ctx,
            alice.coin,
            Conditions::new().create_coin(alice.puzzle_hash, 1, chia_puzzle_types::Memos::None),
        )?;
        sim.spend_coins(ctx.take(), &[alice.sk])?;

        let puzzle_reveal = sim
            .puzzle_reveal(alice.coin.coin_id())
            .expect("the standard spend must have a recorded puzzle reveal");
        let solution = sim
            .solution(alice.coin.coin_id())
            .expect("the standard spend must have a recorded solution");

        let parsed = parse_did_coin_spend(alice.coin, &puzzle_reveal, &solution)
            .expect("parsing a non-DID puzzle is not an error");
        assert!(parsed.is_none());
        Ok(())
    }
}
