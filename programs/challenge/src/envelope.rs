//! The evaluation ENVELOPE — the legal bounds any `RulesSnapshot` must sit inside (ENVELOPE-1).
//!
//! `purchase_challenge` takes the `RulesSnapshot` as **caller-supplied instruction data** and, before
//! this module, validated only that `trader_split + stakeholder_split <= 10000`. Everything else — the
//! profit target a trader must hit, the drawdown that fails them, their share of their own profit —
//! was accepted verbatim from whoever built the transaction. The §9 grandfathering guarantee ("the
//! rules you are judged on were locked at purchase and nobody can retighten them") therefore rested on
//! the honesty of the transaction builder rather than on anything this program checked.
//!
//! That gap was not exploitable in practice — the instruction also requires `settlement_authority` to
//! co-sign, and the gateway refuses to sell an eval whose firm authority is not the platform keeper, so
//! forging rules needed the platform keeper's key. This is defense-in-depth, not a patched hole. But a
//! protocol that calls itself trustless should not rest its headline fairness guarantee on "the
//! operator is honest and their key is safe."
//!
//! # Why an envelope and not a committed hash
//!
//! Committing the exact expected snapshot hash collapses on contact with the risk engine: a snapshot is
//! a function of firm baseline × risk tier × account size × the within-band interpolation of a score
//! that moves every 15 minutes. The set of valid hashes is enormous and continuously changing, so
//! publishing them on-chain each sweep is not workable.
//!
//! So this program does not reproduce the engine's output — it enforces that the output lies inside the
//! legal envelope. That is robust to the engine changing its internal math, costs no per-sweep on-chain
//! writes, and supports a claim worth publishing: *no evaluation can be sold outside the published
//! envelope, regardless of who holds which key.*
//!
//! # Why constants and not a config account
//!
//! A mutable bounds account would reintroduce precisely the authority this removes: whoever can widen
//! the envelope can sell outside it, and we are back to trusting a key. The envelope is a protocol
//! constant in the same class as `MAX_ACCOUNT_SIZE_TIER`; changing it is a program upgrade, which is
//! public and reviewable.
//!
//! # The two rules that make this safe to enforce
//!
//! 1. **Only the trader-harming direction is bounded.** A too-hard target or a too-tight drawdown is
//!    what makes an evaluation unwinnable, so those get a ceiling and floors respectively. The opposite
//!    direction (a trivially easy evaluation) costs the firm, not the trader, and the firm is the party
//!    choosing it — so it is deliberately left unbounded here.
//! 2. **`0` means "not enforced" and is always legal.** The off-chain projection emits 0 for any rule a
//!    template omits, so a floor that rejected 0 would brick sparse, legacy and giveaway-granted
//!    challenges. Every floor below is conditional on the field being non-zero.
//!
//! Bounds carry deliberate headroom over what the engine can currently emit (each is annotated with the
//! live worst case). Headroom is the point: this is a sanity boundary on forged or corrupted input, not
//! a second copy of the engine's tuning. Hugging current output would turn every future retune into a
//! production purchase outage.
//!
//! Mirrored in TypeScript at `services/api-gateway/src/onchain/rules-envelope.ts`; the two are pinned
//! value-for-value by `services/api-gateway/src/__tests__/rules-envelope.test.ts`, which also asserts
//! the real generator's full tier × phase × score matrix lands inside these bounds.

use crate::{ChallengeError, RulesSnapshot};
use anchor_lang::prelude::*;

/// Hardest profit target sellable. Engine max today: 1200 bps (700 baseline + 500 Critical delta).
pub const MAX_PROFIT_TARGET_BPS: u16 = 2_000;
/// Tightest daily-loss cap sellable, when enforced. Engine min today: 300 bps (500 − 200 Critical).
pub const MIN_DAILY_LOSS_BPS: u16 = 100;
/// Tightest total drawdown sellable, when enforced. Engine min today: 700 bps (1000 − 300 Critical).
pub const MIN_TOTAL_DRAWDOWN_BPS: u16 = 300;
/// Longest minimum-trading-days gate sellable. Engine max today: 9 (4 baseline + 5 Critical).
pub const MAX_MIN_TRADING_DAYS: u8 = 30;
/// Harshest consistency cap sellable, when enforced. Engine today: 3000 bps, flat at every tier.
pub const MIN_CONSISTENCY_RULE_BPS: u16 = 1_000;
/// Harshest single-trade profit cap sellable, when enforced. Engine min today: 3000 bps (Critical).
pub const MIN_SINGLE_TRADE_PROFIT_BPS: u16 = 1_000;
/// Longest forced hold sellable. Engine max today: 120s (Critical).
pub const MAX_MIN_HOLD_SECONDS: u16 = 3_600;
/// Smallest trader profit share sellable. Engine min today: 6000 bps (Critical tier split).
pub const MIN_TRADER_SPLIT_BPS: u16 = 5_000;

/// Enforce the envelope on a caller-supplied snapshot. Called from `init_challenge_state`, the single
/// chokepoint both `purchase_challenge` and `grant_giveaway_challenge` construct challenges through, so
/// no path can mint a challenge whose locked rules sit outside these bounds.
pub fn validate_rules_envelope(r: &RulesSnapshot) -> Result<()> {
    // Winnability. `0` = rule not enforced for this evaluation, which is always legal.
    require!(
        r.profit_target_bps <= MAX_PROFIT_TARGET_BPS,
        ChallengeError::ProfitTargetTooHigh
    );
    require!(
        r.max_daily_loss_bps == 0 || r.max_daily_loss_bps >= MIN_DAILY_LOSS_BPS,
        ChallengeError::DailyLossTooTight
    );
    require!(
        r.max_total_drawdown_bps == 0 || r.max_total_drawdown_bps >= MIN_TOTAL_DRAWDOWN_BPS,
        ChallengeError::DrawdownTooTight
    );

    // Coherence: a daily-loss cap LOOSER than the total drawdown is incoherent — the account would
    // fail the total before the daily could ever bind, making the daily cap decorative. Only checked
    // when both are enforced.
    require!(
        r.max_daily_loss_bps == 0
            || r.max_total_drawdown_bps == 0
            || r.max_daily_loss_bps <= r.max_total_drawdown_bps,
        ChallengeError::DailyLossExceedsDrawdown
    );

    // Time and shape gates.
    require!(
        r.min_trading_days <= MAX_MIN_TRADING_DAYS,
        ChallengeError::MinTradingDaysTooHigh
    );
    require!(
        r.consistency_rule_bps == 0 || r.consistency_rule_bps >= MIN_CONSISTENCY_RULE_BPS,
        ChallengeError::ConsistencyTooTight
    );
    require!(
        r.max_single_trade_profit_bps == 0
            || r.max_single_trade_profit_bps >= MIN_SINGLE_TRADE_PROFIT_BPS,
        ChallengeError::SingleTradeCapTooTight
    );
    require!(
        r.min_hold_time_seconds <= MAX_MIN_HOLD_SECONDS,
        ChallengeError::MinHoldTooLong
    );

    // Economics. This is the field an attacker able to forge rules would actually reach for, and the
    // one `PAYOUT-SPLIT-LOCK-1` already makes load-bearing at settlement: the firm program caps a
    // payout at this locked split, so a forged low split is permanently unpayable value rather than
    // merely a bad deal.
    require!(
        r.trader_split_bps >= MIN_TRADER_SPLIT_BPS,
        ChallengeError::TraderSplitTooLow
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A snapshot at the live platform baseline (1-step: 7% target / 5% daily / 10% drawdown / 4 days,
    /// 80% split) — the exact shape the gateway sells today.
    fn legal() -> RulesSnapshot {
        RulesSnapshot {
            profit_target_bps: 700,
            max_daily_loss_bps: 500,
            max_total_drawdown_bps: 1_000,
            is_trailing_drawdown: false,
            starting_balance: 50_000_000_000,
            min_trading_days: 4,
            max_trading_days: 30,
            max_open_positions: 0,
            max_position_size_bps: 0,
            max_leverage_bps: 10_000,
            allow_weekend_holding: true,
            allow_news_trading: true,
            base_spread_bps: 0,
            dynamic_spread: false,
            simulate_slippage: false,
            min_hold_time_seconds: 15,
            max_price_age_seconds: 10,
            consistency_rule_bps: 3_000,
            max_single_trade_profit_bps: 0,
            daily_variance_gate: false,
            trader_split_bps: 8_000,
            stakeholder_split_bps: 2_000,
        }
    }

    #[test]
    fn accepts_the_live_baseline() {
        assert!(validate_rules_envelope(&legal()).is_ok());
    }

    #[test]
    fn accepts_the_harshest_tier_the_engine_can_emit() {
        // Critical, 1-step: 700+500 target, 500−200 daily, 1000−300 drawdown, 4+5 days, 3000 single-
        // trade cap, 120s hold, 6000 split. The envelope must not bind on any of these.
        let mut r = legal();
        r.profit_target_bps = 1_200;
        r.max_daily_loss_bps = 300;
        r.max_total_drawdown_bps = 700;
        r.min_trading_days = 9;
        r.max_single_trade_profit_bps = 3_000;
        r.min_hold_time_seconds = 120;
        r.trader_split_bps = 6_000;
        r.stakeholder_split_bps = 4_000;
        assert!(validate_rules_envelope(&r).is_ok());
    }

    #[test]
    fn accepts_all_zero_unenforced_rules() {
        // The sparse/legacy template: every optional rule omitted. Must stay sellable.
        let mut r = legal();
        r.profit_target_bps = 0;
        r.max_daily_loss_bps = 0;
        r.max_total_drawdown_bps = 0;
        r.min_trading_days = 0;
        r.consistency_rule_bps = 0;
        r.max_single_trade_profit_bps = 0;
        assert!(validate_rules_envelope(&r).is_ok());
    }

    #[test]
    fn rejects_an_unwinnable_target() {
        let mut r = legal();
        r.profit_target_bps = MAX_PROFIT_TARGET_BPS + 1;
        assert!(validate_rules_envelope(&r).is_err());
    }

    #[test]
    fn rejects_a_hair_trigger_daily_loss() {
        let mut r = legal();
        r.max_daily_loss_bps = MIN_DAILY_LOSS_BPS - 1;
        assert!(validate_rules_envelope(&r).is_err());
    }

    #[test]
    fn rejects_a_hair_trigger_drawdown() {
        let mut r = legal();
        r.max_total_drawdown_bps = MIN_TOTAL_DRAWDOWN_BPS - 1;
        assert!(validate_rules_envelope(&r).is_err());
    }

    #[test]
    fn rejects_a_daily_cap_looser_than_the_total() {
        let mut r = legal();
        r.max_daily_loss_bps = 1_100;
        r.max_total_drawdown_bps = 1_000;
        assert!(validate_rules_envelope(&r).is_err());
    }

    #[test]
    fn rejects_a_starved_trader_split() {
        let mut r = legal();
        r.trader_split_bps = MIN_TRADER_SPLIT_BPS - 1;
        assert!(validate_rules_envelope(&r).is_err());
    }

    #[test]
    fn rejects_an_endless_minimum_days_gate() {
        let mut r = legal();
        r.min_trading_days = MAX_MIN_TRADING_DAYS + 1;
        assert!(validate_rules_envelope(&r).is_err());
    }

    #[test]
    fn rejects_a_crushing_consistency_cap() {
        let mut r = legal();
        r.consistency_rule_bps = MIN_CONSISTENCY_RULE_BPS - 1;
        assert!(validate_rules_envelope(&r).is_err());
    }
}
