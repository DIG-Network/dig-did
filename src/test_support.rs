//! Test-only helpers for inspecting what a built bundle actually EMITS.
//!
//! Every defect this crate has shipped so far shared one shape: a spend that is well-formed, parses,
//! and returns `Ok`, while the conditions the caller needed were silently dropped. Asserting on the
//! returned Rust values cannot see that — only re-running each coin spend's puzzle and reading the
//! conditions it produces can. These helpers do exactly that.

use chia_protocol::{Bytes32, CoinSpend};
use chia_wallet_sdk::driver::SpendContext;
use chia_wallet_sdk::types::{run_puzzle, Condition};
use clvm_traits::FromClvm;

/// Runs `coin_spend`'s revealed puzzle against its solution and returns the conditions it emits.
pub(crate) fn emitted_conditions(
    ctx: &mut SpendContext,
    coin_spend: &CoinSpend,
) -> anyhow::Result<Vec<Condition>> {
    let puzzle = ctx.alloc(&coin_spend.puzzle_reveal)?;
    let solution = ctx.alloc(&coin_spend.solution)?;
    let output = run_puzzle(ctx, puzzle, solution)?;
    Ok(Vec::<Condition>::from_clvm(ctx, output)?)
}

/// Every condition emitted by every spend in `coin_spends`, flattened in spend order.
pub(crate) fn all_emitted_conditions(
    ctx: &mut SpendContext,
    coin_spends: &[CoinSpend],
) -> anyhow::Result<Vec<Condition>> {
    let mut conditions = Vec::new();
    for coin_spend in coin_spends {
        conditions.extend(emitted_conditions(ctx, coin_spend)?);
    }
    Ok(conditions)
}

/// Whether any spend in `coin_spends` emits a `CREATE_COIN` to `puzzle_hash`.
pub(crate) fn creates_coin_to(
    ctx: &mut SpendContext,
    coin_spends: &[CoinSpend],
    puzzle_hash: Bytes32,
) -> anyhow::Result<bool> {
    Ok(all_emitted_conditions(ctx, coin_spends)?
        .into_iter()
        .any(|condition| {
            matches!(condition.into_create_coin(), Some(create) if create.puzzle_hash == puzzle_hash)
        }))
}
