#![no_main]
//! Coverage-guided soundness fuzzing of the settlement engine + Merkle + fault verifiers.
//!
//! libFuzzer drives `check_no_false_slash`: it builds an HONEST transcript from the arbitrary input,
//! commits the real Merkle trees, and asserts that NO fault verifier (transition / input / provenance)
//! flags it — because any fault on an honest transcript is a permissionless FALSE-SLASH of an honest
//! operator. A violation `panic!`s (libFuzzer minimises + saves the crashing input). The engine's
//! no-panic property is exercised implicitly (the honest run calls `apply_step` on the fuzzed steps),
//! so an integer-overflow panic in the engine (the class the cargo-test harness already caught + fixed)
//! is also a fuzzer-reportable crash.

use arbitrary::Arbitrary;
use challenge::settlement::{fuzz_support, RuleParams, StepInput};
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct FuzzStep {
    ts: i64,
    qty_micro: i64,
    entry_price: u64,
    exit_price: u64,
}

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    starting_balance: i64,
    profit_target_bps: u16,
    max_daily_loss_bps: u16,
    max_total_drawdown_bps: u16,
    is_trailing: bool,
    min_trading_days: u8,
    steps: Vec<FuzzStep>,
}

fuzz_target!(|input: FuzzInput| {
    let rules = RuleParams {
        starting_balance: input.starting_balance as i128,
        profit_target_bps: input.profit_target_bps as i128,
        max_daily_loss_bps: input.max_daily_loss_bps as i128,
        max_total_drawdown_bps: input.max_total_drawdown_bps as i128,
        is_trailing_drawdown: input.is_trailing,
        min_trading_days: input.min_trading_days as u32,
    };
    // Cap length to keep each iteration fast; libFuzzer still explores the value space.
    let steps: Vec<StepInput> = input
        .steps
        .iter()
        .take(48)
        .map(|s| StepInput {
            ts: s.ts,
            qty_micro: s.qty_micro,
            entry_price: s.entry_price,
            exit_price: s.exit_price,
        })
        .collect();

    if let Err(reason) = fuzz_support::check_no_false_slash(&rules, &steps) {
        panic!("SETTLEMENT SOUNDNESS VIOLATION (honest transcript false-slashed): {reason}");
    }
});
