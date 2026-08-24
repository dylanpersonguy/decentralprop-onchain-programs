//! Verifiable settlement core (F5 — "did the house pass itself?" → trustless).
//!
//! The off-chain engine runs the full evaluation, but it must commit to a **deterministic,
//! replayable transcript** so that ANY observer can disprove a dishonest settlement on-chain.
//! This module is the on-chain *adjudicator*: it does NOT replay the whole evaluation (that would
//! be far too expensive), it only ever recomputes **one disputed step** during a fraud proof.
//!
//! The construction is an optimistic / interactive-fraud-proof scheme:
//!
//!   1. At settlement the operator commits, on-chain, to:
//!        - `transcript_root` — a Merkle root over the per-step state-hash chain `h_0..h_N`
//!          (`h_0` = genesis from the locked rules, `h_N` = the final state), and
//!        - `claimed_result` (passed / virtual_profit) which must equal `derive_outcome(state_N)`.
//!      The committed trades/prices already live in the `batch` program's append-only roots.
//!   2. A challenge window opens. Funds cannot move until it closes (`finalize_settlement`).
//!   3. During the window anyone may submit `prove_settlement_fault(i, state_i, step_i, …)`:
//!      the chain recomputes `apply_step(state_i, step_i, rules)` for that **single** index and,
//!      if its hash ≠ the operator's committed `h_{i+1}`, the settlement is `Faulted` and the
//!      operator is slashed. Combined with the existing input-integrity disputes (Merkle
//!      inclusion against `batch` roots, in the `dispute` program), this binds settlement to
//!      *real inputs* (dispute) **and** *correct math over them* (this module).
//!
//! ── Determinism contract (MUST match the off-chain engine byte-for-byte) ──
//! - All monetary amounts are **micro-USD** (1e-6), matching USDC's 6 decimals.
//! - `qty_micro` is signed micro-lots (1e-6); `entry_price`/`exit_price` are micro-USD per lot.
//! - A step is one **closed round-trip trade**: `pnl = qty_micro * (exit - entry) / PRICE_SCALE`.
//! - Integer division **truncates toward zero** (Rust `i128 /` and JS `BigInt /` agree).
//! - Hashing is domain-separated SHA-256 over canonical **decimal/hex strings** (i128 `Display`
//!   == JS `BigInt.toString()`), matching the `leaf:` / `node:` scheme in `@decentralprop/provably-fair`.
//! - `ts` is unix seconds and assumed ≥ 0 (day index = `ts / 86_400`).

// The numbered-list continuation above (bullet "1.", line ~19) dedents back to the parent item
// after a nested `-` sub-list, which clippy's doc_lazy_continuation lint can't disambiguate from
// CommonMark alone — doc-comment-only, no behavioral or IDL impact (this is a plain `mod`, not
// `#[program]`, so these docs never reach the IDL).
#![allow(clippy::doc_lazy_continuation)]

use anchor_lang::prelude::*;
use anchor_lang::solana_program::hash::hash as sha256;

/// Basis-point denominator.
pub const BPS_DENOM: i128 = 10_000;
/// Price scale: `qty_micro (1e-6) * price_micro (1e-6) / 1e6` → micro-USD (1e-6).
pub const PRICE_SCALE: i128 = 1_000_000;
/// Seconds per UTC day (the daily-loss reset boundary).
pub const SECONDS_PER_DAY: i64 = 86_400;

/// Breach bitflags — sticky once set (a breach can never be "un-breached" by later steps).
pub const BREACH_DAILY_LOSS: u8 = 1 << 0;
pub const BREACH_TOTAL_DD: u8 = 1 << 1;

/// The minimal rule subset settlement is a deterministic function of. Extracted from the
/// challenge's immutable `RulesSnapshot` so the verifier reads exactly the locked terms.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RuleParams {
    pub starting_balance: i128,
    pub profit_target_bps: i128,
    pub max_daily_loss_bps: i128,
    pub max_total_drawdown_bps: i128,
    pub is_trailing_drawdown: bool,
    pub min_trading_days: u32,
}

/// The full engine state at a step boundary. `Display`-stable fields only (no floats) so the
/// canonical hash is identical in Rust and TypeScript.
#[derive(Clone, Copy, PartialEq, Eq, Debug, AnchorSerialize, AnchorDeserialize)]
pub struct EngineState {
    /// Current account equity (micro-USD).
    pub equity: i128,
    /// High-water mark of equity (micro-USD) — the trailing-drawdown reference.
    pub peak_equity: i128,
    /// Equity at the start of the current UTC day (micro-USD) — the daily-loss reference.
    pub day_start_equity: i128,
    /// Current UTC day index (`ts / 86_400`).
    pub day_index: i64,
    /// Count of distinct days on which a step occurred (the min-trading-days rule).
    pub trading_days: u32,
    /// Sticky breach flags (see `BREACH_*`).
    pub breach: u8,
}

/// One closed round-trip trade the engine consumes. Bound to committed prices off-chain.
#[derive(Clone, Copy, PartialEq, Eq, Debug, AnchorSerialize, AnchorDeserialize)]
pub struct StepInput {
    /// Fill/close timestamp (unix seconds, ≥ 0).
    pub ts: i64,
    /// Signed size in micro-lots (sign encodes long/short).
    pub qty_micro: i64,
    /// Committed entry price (micro-USD per lot).
    pub entry_price: u64,
    /// Committed exit price (micro-USD per lot).
    pub exit_price: u64,
}

/// The deterministic settlement outcome derived purely from the final state + rules.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SettlementResult {
    pub passed: bool,
    /// Net virtual profit (micro-USD), `equity - starting_balance`. May be negative.
    pub virtual_profit: i128,
}

/// The genesis state at the start of an evaluation: equity == peak == day_start == starting_balance.
pub fn genesis_state(rules: &RuleParams) -> EngineState {
    EngineState {
        equity: rules.starting_balance,
        peak_equity: rules.starting_balance,
        day_start_equity: rules.starting_balance,
        day_index: 0,
        trading_days: 0,
        breach: 0,
    }
}

/// Realized pnl of one closed trade (micro-USD), truncating toward zero. Saturating throughout so the
/// engine can NEVER panic on an adversarially-crafted step (a panic in `apply_step` would make a
/// fraudulent settlement un-faultable — the watchtower's `verify_transition_fault` recomputes this). A
/// real bounded trade never reaches these extremes, and an out-of-range fabricated step is caught by the
/// input/coverage binding (it can't be a committed batch tick), so saturation is pure defense-in-depth.
pub fn step_pnl(step: &StepInput) -> i128 {
    let qty = step.qty_micro as i128;
    let spread = (step.exit_price as i128).saturating_sub(step.entry_price as i128);
    qty.saturating_mul(spread) / PRICE_SCALE
}

/// The canonical single-step transition. Pure; the ONLY thing the on-chain fault proof recomputes.
///
/// Order of operations is part of the determinism contract — do not reorder:
///   1. day rollover (resets the daily-loss reference, increments trading_days),
///   2. apply realized pnl to equity,
///   3. update the high-water mark,
///   4. evaluate the (sticky) breach flags.
pub fn apply_step(prev: &EngineState, step: &StepInput, rules: &RuleParams) -> EngineState {
    let mut s = *prev;

    // 1. Day rollover — a new UTC day re-bases the daily-loss reference and counts a trading day.
    let day = step.ts / SECONDS_PER_DAY;
    if s.trading_days == 0 || day != s.day_index {
        s.day_index = day;
        s.day_start_equity = s.equity;
        s.trading_days = s.trading_days.saturating_add(1);
    }

    // 2. Realized pnl.
    s.equity = s.equity.saturating_add(step_pnl(step));

    // 3. High-water mark.
    if s.equity > s.peak_equity {
        s.peak_equity = s.equity;
    }

    // 4. Breach evaluation (sticky — flags only ever turn ON). Saturating subtraction/multiplication so
    //    an extreme equity (driven by a crafted step) can never overflow-panic the fault recompute.
    let daily_loss = s.day_start_equity.saturating_sub(s.equity);
    let daily_threshold = rules.max_daily_loss_bps.saturating_mul(rules.starting_balance) / BPS_DENOM;
    if rules.max_daily_loss_bps > 0 && daily_loss >= daily_threshold && daily_threshold > 0 {
        s.breach |= BREACH_DAILY_LOSS;
    }

    let dd_high = if rules.is_trailing_drawdown { s.peak_equity } else { rules.starting_balance };
    let drawdown = dd_high.saturating_sub(s.equity);
    let dd_threshold = rules.max_total_drawdown_bps.saturating_mul(rules.starting_balance) / BPS_DENOM;
    if rules.max_total_drawdown_bps > 0 && drawdown >= dd_threshold && dd_threshold > 0 {
        s.breach |= BREACH_TOTAL_DD;
    }

    s
}

/// Run a whole transcript (off-chain / test helper). The on-chain program never calls this.
pub fn run_transcript(rules: &RuleParams, steps: &[StepInput]) -> Vec<EngineState> {
    run_transcript_from(&genesis_state(rules), rules, steps)
}

/// Run a transcript from an ARBITRARY genesis — the withdrawal-cycle form (DEC-62), where cycle `N`
/// starts from `rebaseline_after_withdrawal(cycle N-1 final, gross)` rather than `genesis_state(rules)`.
/// `run_transcript` is just this with the cycle-0 genesis. Off-chain / test helper; the on-chain program
/// never calls it (it only ever recomputes ONE step inside a fault proof).
pub fn run_transcript_from(
    genesis: &EngineState,
    rules: &RuleParams,
    steps: &[StepInput],
) -> Vec<EngineState> {
    let mut states = Vec::with_capacity(steps.len() + 1);
    let mut cur = *genesis;
    states.push(cur);
    for step in steps {
        cur = apply_step(&cur, step, rules);
        states.push(cur);
    }
    states
}

/// Derive the pass/fail + profit purely from the final state. A breach fails outright; otherwise
/// the trader must hit the profit target AND the minimum trading-days floor.
pub fn derive_outcome(final_state: &EngineState, rules: &RuleParams) -> SettlementResult {
    let net_profit = final_state.equity.saturating_sub(rules.starting_balance);
    let target = rules.profit_target_bps.saturating_mul(rules.starting_balance) / BPS_DENOM;
    let passed = final_state.breach == 0
        && net_profit >= target
        && final_state.trading_days >= rules.min_trading_days;
    SettlementResult { passed, virtual_profit: net_profit }
}

// ───────────────────────── Hashing (must match provably-fair byte-for-byte) ─────────────────────

fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

/// Hex-encode a committed 32-byte root for comparison against the string-based proof recomputation
/// (the on-chain commitment is stored as `[u8; 32]`, mirroring `batch::BatchRoot.merkle_root`).
pub fn root_to_hex(root: &[u8; 32]) -> String {
    to_hex(root)
}

fn sha256_hex(input: &str) -> String {
    to_hex(&sha256(input.as_bytes()).to_bytes())
}

/// Canonical hash of an engine state. Domain tag `state:`; decimal fields joined by `:` —
/// portable across Rust (`i128` Display) and JS (`BigInt.toString()`).
pub fn state_hash(s: &EngineState) -> String {
    sha256_hex(&format!(
        "state:{}:{}:{}:{}:{}:{}",
        s.equity, s.peak_equity, s.day_start_equity, s.day_index, s.trading_days, s.breach
    ))
}

/// Canonical hash of a step input. Domain tag `step:` + the step's index in the transcript.
pub fn step_hash(index: u32, step: &StepInput) -> String {
    sha256_hex(&format!(
        "step:{}:{}:{}:{}:{}",
        index, step.ts, step.qty_micro, step.entry_price, step.exit_price
    ))
}

/// Domain-separated Merkle leaf/pair hashing — identical to the `dispute` program / provably-fair.
pub fn hash_leaf(data: &str) -> String {
    sha256_hex(&format!("leaf:{data}"))
}
pub fn hash_pair(left: &str, right: &str) -> String {
    sha256_hex(&format!("node:{left}{right}"))
}

/// One step of a Merkle membership proof (sibling hex + which side it sits on).
#[derive(Clone, Debug, AnchorSerialize, AnchorDeserialize)]
pub struct ProofStep {
    pub sibling: String,
    pub sibling_on_right: bool,
}

/// Recompute a Merkle root from a leaf payload and its proof path (matches `dispute::recompute_root`).
pub fn recompute_root(leaf_data: &str, proof: &[ProofStep]) -> String {
    let mut h = hash_leaf(leaf_data);
    for step in proof {
        h = if step.sibling_on_right {
            hash_pair(&h, &step.sibling)
        } else {
            hash_pair(&step.sibling, &h)
        };
    }
    h
}

/// THE on-chain adjudication primitive. Given the operator's committed `transcript_root` (state
/// chain) + `step_root` (the inputs), and a challenger's claim that step `index` is mis-computed,
/// returns `true` iff a **fault is proven**: the pre-state `h_i`, the operator's post-state
/// `h_{i+1}`, AND the step are all committed members, yet the honestly-recomputed next-state hash
/// differs from the committed `h_{i+1}`.
///
/// Binding the STEP (via `step_root` + `step_proof`) is what makes this sound: without it a malicious
/// challenger could supply a fabricated `step`, recompute a different next-state, and false-slash an
/// HONEST operator. With it, the only step that verifies is the one the operator actually committed,
/// so a proven mismatch means the operator's own transcript is internally inconsistent → Faulted.
/// (The committed step leaf `hash_leaf(step_hash(index, step))` is byte-identical to a `batch` trade
/// tick, so the same step is also bindable to the firm's committed trade roots via the dispute path.)
#[allow(clippy::too_many_arguments)]
pub fn verify_transition_fault(
    transcript_root: &str,
    step_root: &str,
    index: u32,
    prev_state: &EngineState,
    prev_proof: &[ProofStep],
    claimed_next_state_hash: &str,
    next_proof: &[ProofStep],
    step: &StepInput,
    step_proof: &[ProofStep],
    rules: &RuleParams,
) -> bool {
    // (a) the revealed pre-state must be the committed leaf at `index`.
    let prev_hash = state_hash(prev_state);
    if recompute_root(&prev_hash, prev_proof) != *transcript_root {
        return false; // pre-state not in the committed transcript — proof is invalid, no fault.
    }
    // (b) the operator's claimed post-state must be the committed leaf at `index + 1`.
    if recompute_root(claimed_next_state_hash, next_proof) != *transcript_root {
        return false; // claimed next-state not in the transcript — invalid proof.
    }
    // (c) the step must be the one COMMITTED at `index` — binds the input, prevents false slashing.
    if recompute_root(&step_hash(index, step), step_proof) != *step_root {
        return false; // a substituted (non-committed) step proves nothing.
    }
    // (d) recompute the single honest transition and compare.
    let honest_next = apply_step(prev_state, step, rules);
    state_hash(&honest_next) != *claimed_next_state_hash
}

// ───────────────────── H-2: input authenticity (settlement ↔ batch binding) ─────────────────────
//
// The transition/result/genesis faults above prove the operator's MATH is correct over the committed
// steps. They do NOT prove the steps are REAL committed trades — a malicious settlement keeper can
// fabricate a favourable `StepInput` and the rest of the transcript stays internally consistent. H-2
// closes that by binding each committed step to a position in a pre-committed `batch` Merkle root.
//
// Scheme (the determinism contract — must match the off-chain prover + the batch-commit service):
//   • A trade's canonical, index-independent encoding is `tick:ts:qty:entry:exit`. The `batch` program
//     commits each hourly trade tick as `hash_leaf(tick_preimage)` — byte-identical to the value below.
//   • In the settlement transcript the operator commits, per step, a PROVENANCE-BOUND leaf:
//         bound_step_leaf = hash_leaf("bind:" + transcript_index + ":" + batch_epoch + ":" +
//                                     batch_leaf_index + ":" + tick_preimage(step))
//     i.e. the step is welded to the (epoch, leaf_index) batch slot it claims to come from. The
//     `step_root` committed at `propose_settlement` is the Merkle root over these bound leaves.
//
// A challenger then needs only ONE mis-bound step to fault the whole settlement: reveal the step, its
// claimed provenance, its membership in `step_root`, and the REAL batch leaf at that (epoch, index)
// with its membership in the batch root. If the operator's committed trade ≠ the real committed trade
// at the slot it pointed to, the settlement used a fabricated input → Faulted. This is a POSITIVE
// proof (a concrete mismatch), so it can never false-slash an honest operator, whose every step is the
// genuine committed tick at its slot.

/// Canonical, transcript-index-independent encoding of one trade tick. The `batch` program's committed
/// leaf for this trade is `hash_leaf(tick_preimage(step))` — the binding point between settlement and
/// the append-only trade roots.
pub fn tick_preimage(step: &StepInput) -> String {
    format!("tick:{}:{}:{}:{}", step.ts, step.qty_micro, step.entry_price, step.exit_price)
}

/// The provenance-bound transcript leaf the operator commits in `step_root` for step `transcript_index`,
/// welding the step to the batch slot `(batch_epoch, batch_leaf_index)` it is drawn from.
pub fn bound_step_leaf(transcript_index: u32, batch_epoch: u64, batch_leaf_index: u32, step: &StepInput) -> String {
    hash_leaf(&format!(
        "bind:{}:{}:{}:{}",
        transcript_index,
        batch_epoch,
        batch_leaf_index,
        tick_preimage(step)
    ))
}

/// THE on-chain input-authenticity adjudication primitive (H-2). Returns `true` iff a **fabricated-input
/// fault is proven** for `transcript_index`: the operator committed `step` at provenance
/// `(batch_epoch, batch_leaf_index)` (proven a member of `step_root`), yet the real tick committed in
/// `batch_root` at `batch_leaf_index` differs from the operator's step — so the settlement consumed a
/// trade that was never in the firm's append-only roots.
///
/// Soundness: binding the provenance into BOTH the committed step leaf and the comparison means the only
/// way this returns `true` is a genuine divergence between the operator's transcript and the firm's
/// committed trade evidence. An honest operator (every step = the committed tick at its slot) can never
/// be faulted. (The complementary "provenance points outside committed coverage" case is handled at
/// `propose_settlement` by the count/coverage binding — see VERIFIABLE_SETTLEMENT_BATCH_BINDING.md.)
#[allow(clippy::too_many_arguments)]
pub fn verify_input_fault(
    step_root: &str,
    transcript_index: u32,
    batch_epoch: u64,
    batch_leaf_index: u32,
    step: &StepInput,
    step_membership_proof: &[ProofStep],
    batch_root: &str,
    actual_batch_leaf: &str,
    batch_membership_proof: &[ProofStep],
) -> bool {
    // (a) the operator must have committed THIS step at THIS provenance in the transcript step_root.
    let bound_leaf = bound_step_leaf(transcript_index, batch_epoch, batch_leaf_index, step);
    if recompute_root_from_leaf_hash(&bound_leaf, step_membership_proof) != *step_root {
        return false; // not the committed step/provenance — proves nothing, no fault.
    }
    // (b) `actual_batch_leaf` must be the real committed leaf at `batch_leaf_index` in the batch root.
    if recompute_root_from_leaf_hash(actual_batch_leaf, batch_membership_proof) != *batch_root {
        return false; // the alleged batch leaf isn't actually in the committed root — invalid proof.
    }
    // (c) fault iff the operator's committed trade differs from the real committed trade at that slot.
    hash_leaf(&tick_preimage(step)) != *actual_batch_leaf
}

/// Recompute a Merkle root from an ALREADY-HASHED leaf (not a raw payload). `bound_step_leaf` and the
/// batch tick leaves are themselves `hash_leaf(...)` outputs, so membership is verified by folding the
/// leaf hash directly (vs `recompute_root`, which hashes a raw `leaf:` payload first).
pub fn recompute_root_from_leaf_hash(leaf_hash: &str, proof: &[ProofStep]) -> String {
    let mut h = leaf_hash.to_string();
    for step in proof {
        h = if step.sibling_on_right {
            hash_pair(&h, &step.sibling)
        } else {
            hash_pair(&step.sibling, &h)
        };
    }
    h
}

/// OUT-OF-RANGE input fault (H-2). Returns `true` iff the operator committed a step at provenance
/// `(batch_epoch, batch_leaf_index)` in `step_root` whose `batch_leaf_index` is **beyond the real number
/// of trades** committed for that epoch (`trade_count`) — i.e. the step points past the end of the
/// committed batch, so it cannot be a real trade. A POSITIVE proof (the committed provenance + the real
/// `trade_count` from the on-chain `BatchRoot`), so it can never false-slash an honest operator.
///
/// This tightens `verify_input_fault`: a fabricator pointing at a REAL epoch can no longer hide a fake
/// trade in an out-of-range slot (where no real tick exists to mismatch against). The only fabrication
/// path left is pointing at a NON-EXISTENT epoch — closed by the propose-time coverage/count binding
/// (VERIFIABLE_SETTLEMENT_BATCH_BINDING.md §3b).
pub fn verify_input_range_fault(
    step_root: &str,
    transcript_index: u32,
    batch_epoch: u64,
    batch_leaf_index: u32,
    step: &StepInput,
    step_membership_proof: &[ProofStep],
    trade_count: u32,
) -> bool {
    // (a) the operator must have committed THIS step at THIS provenance.
    let bound_leaf = bound_step_leaf(transcript_index, batch_epoch, batch_leaf_index, step);
    if recompute_root_from_leaf_hash(&bound_leaf, step_membership_proof) != *step_root {
        return false; // not the committed provenance — proves nothing.
    }
    // (b) fault iff the committed slot is past the end of the real committed batch.
    batch_leaf_index >= trade_count
}

// ─────────────────── H-2 §3b: coverage / positional-provenance binding ───────────────────
//
// `verify_input_fault` + `verify_input_range_fault` close fabrication that points at a REAL epoch. The
// only escape left is pointing a step at a NON-EXISTENT epoch (no committed `BatchRoot` to adjudicate).
// We close it by binding the settlement to a COVERAGE: the ordered set of real batch epochs the
// transcript draws from (each proven to exist when the coverage is built), with `Σ trade_count ==
// transcript_len - 1`. Step i's provenance is then POSITIONAL — fixed by i and the coverage, not chosen
// by the operator — so every step provably maps to one real committed trade.
//
// (Soundness note: this closes FABRICATION — no step maps to a non-real trade. OMISSION — a real trade
// the operator left out of the coverage/transcript — remains the `dispute` program's job: the trader
// proves inclusion against the batch root and force-resolves. The two together fully bound a settlement.)

/// BATCH-ROOT-SCOPE-1 — the canonical encoding of one challenge's **segment** within a firm-hour
/// batch root: the contiguous run `[base_offset, base_offset + trade_count)` of leaves that belong to
/// `challenge`. The producer commits one such leaf per challenge that traded the epoch, under
/// `BatchRoot.segment_root`.
///
/// Mirrors TS `segmentPreimage` byte-for-byte (a `Pubkey` renders as base58 via `Display`, matching
/// `PublicKey.toBase58()`). Domain-tagged `seg:` so a segment leaf can never be replayed as a `tick:`
/// or `bind:` leaf in another tree.
pub fn segment_preimage(challenge: &Pubkey, base_offset: u32, trade_count: u32) -> String {
    format!("seg:{challenge}:{base_offset}:{trade_count}")
}

/// The committed `segment_root` leaf for one challenge's run inside a firm-hour batch root.
pub fn segment_leaf(challenge: &Pubkey, base_offset: u32, trade_count: u32) -> String {
    hash_leaf(&segment_preimage(challenge, base_offset, trade_count))
}

/// Verify that `(challenge, base_offset, trade_count)` is the segment the producer committed for this
/// epoch — i.e. that this challenge's run really does sit at `base_offset` in the firm-hour root.
///
/// This is what makes ONE firm-hour root safely serve MANY challenges. An ASSERTED `base_offset`
/// would let an operator point its transcript at another account's contiguous run of real, profitable
/// ticks: every tick it referenced would be genuinely committed, so `prove_input_fault` would stay
/// silent and the theft would be unprovable. The offset must therefore come from a root that had to
/// land within `MAX_COMMIT_DELAY` — before the operator knew which account would withdraw.
pub fn verify_segment(
    segment_root: &str,
    challenge: &Pubkey,
    base_offset: u32,
    trade_count: u32,
    proof: &[ProofStep],
) -> bool {
    recompute_root(&segment_preimage(challenge, base_offset, trade_count), proof) == segment_root
}

/// One covered batch epoch. `prefix` is the running sum of `trade_count` over earlier covered epochs,
/// so global step index `i` maps to local trade `i - prefix` **of this challenge's run**, which sits at
/// `base_offset` inside the firm-hour root — hence slot `base_offset + (i - prefix)`.
///
/// `base_offset` exists because the root is per (firm, epoch) while a transcript is per challenge: the
/// firm's other accounts' fills share the epoch's leaf space. It is 0 only when this challenge happens
/// to sort first among those that traded the epoch.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CovEntry {
    pub epoch: u64,
    pub prefix: u64,
    pub trade_count: u32,
    /// Index of this challenge's first leaf within the firm-hour root (segment-proven at coverage time).
    pub base_offset: u32,
}

/// Map a global transcript step index to its POSITIONAL batch slot `(epoch, leaf_index)` under the
/// ordered coverage, where `leaf_index` is the slot in the FIRM-HOUR root. `None` if `i` falls outside
/// the covered range.
pub fn positional_slot(entries: &[CovEntry], i: u32) -> Option<(u64, u32)> {
    let gi = i as u64;
    for e in entries {
        if gi >= e.prefix && gi < e.prefix + e.trade_count as u64 {
            // `i - prefix` is the step's ordinal within THIS challenge's run; `base_offset` places that
            // run inside the firm-hour root. Saturating rather than wrapping: a slot past u32 is not a
            // real leaf, and returning a wrapped one would silently point a fault proof at the wrong tick.
            let local = (gi - e.prefix) as u32;
            let slot = e.base_offset.checked_add(local)?;
            return Some((e.epoch, slot));
        }
    }
    None
}

/// PROVENANCE fault (H-2 §3b). Returns `true` iff the operator committed step `i` (proven a member of
/// `step_root`) at a provenance `(committed_epoch, committed_idx)` that is NOT the positional slot the
/// bound coverage assigns to `i`. This catches a step pointed anywhere other than its real positional
/// trade — including a NON-EXISTENT epoch, the last fabrication escape — via a POSITIVE proof (the
/// committed leaf + the coverage-derived positional slot), so it can never false-slash an honest
/// operator whose every step sits at its positional slot.
pub fn verify_provenance_fault(
    step_root: &str,
    i: u32,
    committed_epoch: u64,
    committed_idx: u32,
    step: &StepInput,
    step_membership_proof: &[ProofStep],
    positional: (u64, u32),
) -> bool {
    let bound = bound_step_leaf(i, committed_epoch, committed_idx, step);
    if recompute_root_from_leaf_hash(&bound, step_membership_proof) != *step_root {
        return false; // not the committed provenance — proves nothing.
    }
    (committed_epoch, committed_idx) != positional
}

// ───────────────── DEC-62: funded withdrawals (rebaselined per-cycle transcripts) ─────────────────
//
// A funded account keeps trading across withdrawals, so its life is cut into CYCLES. Cycle N's transcript
// covers only the trades since withdrawal N-1, and its genesis is cycle N-1's final state with the
// withdrawal debited. Everything above — `apply_step`, `step_hash`, `tick_preimage`, `bound_step_leaf`,
// the H-2 coverage binding — is deliberately UNTOUCHED by this section: a cycle transcript is still pure
// trades, so `covered_trade_count == transcript_len - 1` still holds and the committed batch ticks stay
// byte-identical. (The rejected alternative — a withdrawal STEP interleaved in the transcript — would have
// broken exactly that binding, since a withdrawal maps to no committed batch trade. See DEC-62.)
//
// ── Why this exists (the two bugs it closes; both verified against the code) ──
//  1. DRAIN: `derive_outcome` measures `equity - starting_balance` and knows nothing about payouts, so a
//     SECOND withdrawal citing the same transcript is CONSISTENT with it — the chain re-derives the same
//     profit and sees nothing wrong. Repeat-withdrawing one profit was un-faultable: a keeper-signed drain.
//  2. FALSE-SLASH: off-chain, the only thing preventing (1) is `applyPayoutDebit` decrementing the DB
//     balance — which is not a trade and so leaves NO mark on the transcript. The chain replays undebited
//     profit while the keeper claims the debited figure, and `prove_result_fault` slashes the operator on
//     exactly that mismatch. Rebaselining makes both sides derive the same number.
//
// The determinism contract extends unchanged: `rebaseline_after_withdrawal` MUST match the off-chain
// `applyPayoutDebit` (peak/day-start collapse to the new equity; the breach flags are STICKY) and the TS
// mirror in `packages/provably-fair` byte-for-byte, pinned by the golden vectors in both languages.

/// The honest genesis of withdrawal cycle `N`'s transcript: cycle `N-1`'s final state with the withdrawn
/// GROSS debited. Mirrors the off-chain `applyPayoutDebit` (`payout-account-effects.ts:156-162`), which
/// sets `highWaterMark`/`peakBalance = newBalance` and clears the trailing floor — so the on-chain replay
/// and the off-chain engine agree on equity AND on the drawdown reference after a payout.
///
/// `gross_micro` is the FULL gross profit withdrawn (micro-USD), not the trader's split: the firm's share
/// leaves the account too, so the balance drops by the gross (PAYOUT-DEBIT-1). Debiting only the trader's
/// cut would leave the firm's residual in equity to be re-counted as fresh profit next cycle — the exact
/// compounding bug PAYOUT-DEBIT-1 fixed off-chain.
///
/// Saturating throughout: like `apply_step`, this is recomputed inside a permissionless fault proof, and a
/// panic here would make a fraudulent withdrawal un-faultable.
pub fn rebaseline_after_withdrawal(prev_final: &EngineState, gross_micro: i128) -> EngineState {
    let equity = prev_final.equity.saturating_sub(gross_micro);
    EngineState {
        equity,
        // Collapse the high-water mark onto the new equity — a withdrawal is not a drawdown.
        peak_equity: equity,
        // PAYOUT-REBASELINE-DAILY-1. DEBIT the daily reference by the same gross rather than collapsing
        // it onto equity, so a withdrawal is NEUTRAL for the daily-loss rule instead of resetting it.
        //
        // v1 wrote `day_start_equity: equity`, described as handing the trader "a fresh daily-loss
        // allowance from the rebaselined balance." At a day boundary that is what it does, because
        // `apply_step`'s rollover overwrites `day_start_equity` on the cycle's first trade anyway. MID-day
        // it does the opposite. The trader's gains already banked against that day are thrown away, and
        // the same UTC day continues with a full-size limit measured from a baseline lower by the whole
        // withdrawn gross — so ordinary intraday movement trips a limit they were never near.
        //
        // Observed in production: Trustless Funding account `71795c32`, 2026-08-20. The trader finished
        // the day **up $1,262**; the rebaselined replay put them $70 over a $1,250 daily limit and set
        // BREACH_DAILY_LOSS, which `propose_funded_withdrawal` below then refuses forever
        // (`WithdrawalBreached`). $2,068.99 unpayable, with nothing off-chain agreeing anything was wrong.
        //
        // This preserves `day_start - equity` exactly across the debit, so it launders nothing: the day's
        // running loss is carried, not forgiven, and `breach` stays sticky as before.
        day_start_equity: prev_final.day_start_equity.saturating_sub(gross_micro),
        // Carried, NOT reset: a withdrawal is not a new evaluation.
        day_index: prev_final.day_index,
        trading_days: prev_final.trading_days,
        // STICKY. A withdrawal must never launder a breach — otherwise a breached funded account could
        // withdraw once and come back clean.
        breach: prev_final.breach,
    }
}

/// The PRE-`PAYOUT-REBASELINE-DAILY-1` rebaseline. Kept for one reason: cycles committed before that fix
/// have their v1 genesis welded into `transcript_root` on-chain, and a fault verifier that only knows v2
/// would report a genesis fault on every one of them. That is not a drift warning, it is a live
/// false-slash path against honest history, permissionlessly callable by anyone.
///
/// **Only the fault verifiers may accept this.** `propose_funded_withdrawal` binds v2 and nothing else, so
/// no NEW cycle can ever be committed under v1 — which is what makes accepting it here safe rather than a
/// standing choice for an operator to exploit. The permissive branch can only ever excuse pre-upgrade
/// history, which is exactly its job.
pub fn rebaseline_after_withdrawal_v1(prev_final: &EngineState, gross_micro: i128) -> EngineState {
    let equity = prev_final.equity.saturating_sub(gross_micro);
    EngineState {
        equity,
        peak_equity: equity,
        day_start_equity: equity,
        day_index: prev_final.day_index,
        trading_days: prev_final.trading_days,
        breach: prev_final.breach,
    }
}

/// The profit a funded account has earned but NOT yet been paid, at the end of a rebaselined cycle
/// transcript: `final.equity - starting_balance`.
///
/// This is the entitlement measure, and the rebaseline is what makes it correct: because
/// `rebaseline_after_withdrawal` has ALREADY debited every prior withdrawal out of equity, whatever sits
/// above `starting_balance` is by construction profit the trader has not been paid — including a residual
/// they chose not to take in an earlier cycle. Withdraw everything and the next cycle's genesis is exactly
/// `starting_balance`, so this returns 0 and a repeat withdrawal has nothing to claim. **That is the whole
/// mechanism**: on an UN-rebaselined transcript the same expression re-counts withdrawn profit forever
/// (the DEC-62 drain); on a rebaselined one it is exactly right.
///
/// Do NOT measure from the cycle's own genesis (`final.equity - genesis.equity`) instead. That looks
/// natural and is wrong: after a PARTIAL withdrawal the un-withdrawn residual sits below the rebaselined
/// genesis, so a cycle-relative measure reports 0 for it and the trader can **never reach their own
/// money** again. Caught by `partial_withdrawal_leaves_the_residual_withdrawable`.
pub fn withdrawable_profit(final_state: &EngineState, rules: &RuleParams) -> i128 {
    final_state.equity.saturating_sub(rules.starting_balance)
}

/// The trader's share of a withdrawn gross, in micro-USD. Binding this on-chain leaves ONLY the
/// micro-USD → lamports conversion keeper-struck (the trust settlement already carries — `payout_sol_owed`
/// is likewise unchecked by `prove_result_fault`; see MASTER_FIXES SETTLE-SOL-PRICE-1).
pub fn trader_entitlement(gross_micro: i128, trader_split_bps: i128) -> i128 {
    gross_micro.saturating_mul(trader_split_bps) / BPS_DENOM
}

/// WITHDRAWAL-GENESIS fault (DEC-62). Returns `true` iff the operator's committed genesis for cycle `N`'s
/// transcript is NOT the honest rebaseline of cycle `N-1`'s committed final state — i.e. the keeper
/// rebaselined to an equity of its choosing (e.g. "forgot" to debit the last withdrawal, resurrecting
/// profit already paid, or laundered a sticky breach).
///
/// **Without this proof the whole scheme is theatre**: rebaselining only binds anything if a dishonest
/// rebaseline is refutable. A POSITIVE proof — the revealed `prev_final_state` must hash to the value
/// committed on `FundedWithdrawal[N-1]` (on-chain truth) and the claimed genesis must be the committed
/// leaf at index 0 — so an honest keeper, whose genesis IS the rebaseline, can never be false-slashed.
///
/// Cycle 0 has no predecessor; its honest genesis is plain `genesis_state(rules)`, adjudicated by the
/// existing `prove_genesis_fault` path instead.
pub fn verify_withdrawal_genesis_fault(
    transcript_root: &str,
    claimed_genesis: &EngineState,
    genesis_proof: &[ProofStep],
    prev_final_state: &EngineState,
    prev_final_state_hash: &str,
    prev_gross_micro: i128,
) -> bool {
    // (a) the revealed predecessor must be the final state COMMITTED for cycle N-1 — not one the
    //     challenger invented (else an honest keeper could be false-slashed against a fake predecessor).
    if state_hash(prev_final_state) != *prev_final_state_hash {
        return false;
    }
    // (b) the claimed genesis must be the committed leaf at index 0 of THIS cycle's transcript.
    let gh = state_hash(claimed_genesis);
    if recompute_root(&gh, genesis_proof) != *transcript_root {
        return false;
    }
    // (c) fault iff it is neither accepted rebaseline of the committed predecessor.
    //
    // PAYOUT-REBASELINE-DAILY-1: v1 is accepted here and ONLY here. Cycles proposed before that fix
    // committed a v1 genesis into `transcript_root`; checking v2 alone would make every one of them
    // provably "faulty" to any passing challenger, voiding honest withdrawals and slashing the operator's
    // bond on history that was correct under the rule in force when it was written.
    //
    // Safe because `propose_funded_withdrawal` binds v2 exclusively: the operator has no choice at commit
    // time, so this cannot become a menu. It is a grandfather clause, not a relaxation.
    *claimed_genesis != rebaseline_after_withdrawal(prev_final_state, prev_gross_micro)
        && *claimed_genesis != rebaseline_after_withdrawal_v1(prev_final_state, prev_gross_micro)
}

/// WITHDRAWAL-AMOUNT fault (DEC-62). Returns `true` iff the operator claimed more than the account has
/// left to be paid — a gross exceeding `withdrawable_profit(final, rules)`, or a trader cut exceeding the
/// locked `trader_split_bps` of that gross.
///
/// **This is the proof that makes a repeat withdrawal refutable.** Withdraw everything and cycle N+1's
/// rebaselined genesis is exactly `starting_balance`; with no new trades the final state still is, so
/// `withdrawable_profit == 0` and ANY claimed gross faults. The final state is revealed and proven to be
/// the committed leaf at `transcript_len - 1`, so this can never false-slash an honest keeper.
///
/// It pairs with `verify_withdrawal_genesis_fault` and needs it: this proof trusts that equity has been
/// honestly rebaselined, and THAT proof is what binds the rebaseline. Neither is sufficient alone — the
/// genesis proof without this one lets a keeper overclaim against an honest genesis; this one without the
/// genesis proof lets a keeper rebaseline to any equity it likes.
///
/// A NEGATIVE `withdrawable_profit` (the account is underwater) makes any positive gross a fault, which
/// is correct: an account below its starting balance owes nothing.
#[allow(clippy::too_many_arguments)]
pub fn verify_withdrawal_amount_fault(
    transcript_root: &str,
    final_state: &EngineState,
    final_proof: &[ProofStep],
    claimed_gross_micro: i128,
    claimed_trader_micro: i128,
    trader_split_bps: i128,
    rules: &RuleParams,
) -> bool {
    // (a) the revealed final state must be a committed leaf of this cycle's transcript.
    let fh = state_hash(final_state);
    if recompute_root(&fh, final_proof) != *transcript_root {
        return false;
    }
    // (b) fault on either overclaim: a gross beyond what is still owed, or a cut beyond the locked split.
    let owed = withdrawable_profit(final_state, rules);
    claimed_gross_micro > owed
        || claimed_trader_micro > trader_entitlement(claimed_gross_micro, trader_split_bps)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules() -> RuleParams {
        RuleParams {
            starting_balance: 100_000_000_000, // $100k in micro-USD
            profit_target_bps: 800,            // 8%
            max_daily_loss_bps: 500,           // 5%
            max_total_drawdown_bps: 1000,      // 10%
            is_trailing_drawdown: false,
            min_trading_days: 3,
        }
    }

    // A winning trade: long 1 lot, +$10 move → +$10 (micro-USD) per the scale convention.
    fn win(ts: i64, usd: i64) -> StepInput {
        // pnl = qty_micro * (exit-entry)/1e6. Use qty_micro=1e6 (1 lot), exit-entry = usd*1e6.
        StepInput { ts, qty_micro: 1_000_000, entry_price: 0, exit_price: (usd as u64) * 1_000_000 }
    }
    fn loss(ts: i64, usd: i64) -> StepInput {
        StepInput { ts, qty_micro: 1_000_000, entry_price: (usd as u64) * 1_000_000, exit_price: 0 }
    }

    #[test]
    fn pnl_scale_is_micro_usd() {
        // 1 lot, +$10 → +$10 in micro-USD = 10_000_000.
        assert_eq!(step_pnl(&win(0, 10)), 10_000_000);
        assert_eq!(step_pnl(&loss(0, 10)), -10_000_000);
    }

    #[test]
    fn passing_run_is_a_pass() {
        let r = rules();
        // Three distinct days, total +$9k > 8% of $100k = $8k, no breach.
        let steps = [win(0, 3_000), win(SECONDS_PER_DAY, 3_000), win(2 * SECONDS_PER_DAY, 3_000)];
        let states = run_transcript(&r, &steps);
        let out = derive_outcome(states.last().unwrap(), &r);
        assert!(out.passed);
        assert_eq!(out.virtual_profit, 9_000_000_000); // $9k micro-USD
        assert_eq!(states.last().unwrap().trading_days, 3);
    }

    #[test]
    fn profit_without_enough_trading_days_fails() {
        let r = rules();
        // +$9k but all on ONE day → min_trading_days (3) not met.
        let steps = [win(0, 9_000)];
        let states = run_transcript(&r, &steps);
        assert!(!derive_outcome(states.last().unwrap(), &r).passed);
    }

    #[test]
    fn daily_loss_breach_fails_even_if_later_recovered() {
        let r = rules();
        // Day 0: lose $6k (> 5% of $100k = $5k) → DAILY_LOSS breach, sticky.
        // Then recover to a big profit over more days — still fails (breach is terminal).
        let steps = [
            loss(0, 6_000),
            win(SECONDS_PER_DAY, 10_000),
            win(2 * SECONDS_PER_DAY, 10_000),
        ];
        let states = run_transcript(&r, &steps);
        assert_eq!(states[1].breach & BREACH_DAILY_LOSS, BREACH_DAILY_LOSS);
        assert!(!derive_outcome(states.last().unwrap(), &r).passed);
    }

    #[test]
    fn total_drawdown_breach_fails() {
        let r = rules();
        // Spread the loss across days so it isn't a daily-loss breach, but total dd ≥ 10%.
        let steps = [loss(0, 4_000), loss(SECONDS_PER_DAY, 4_000), loss(2 * SECONDS_PER_DAY, 4_000)];
        let states = run_transcript(&r, &steps);
        assert_eq!(states.last().unwrap().breach & BREACH_TOTAL_DD, BREACH_TOTAL_DD);
        assert!(!derive_outcome(states.last().unwrap(), &r).passed);
    }

    #[test]
    fn honest_transcript_has_no_provable_fault() {
        let r = rules();
        let steps = [win(0, 3_000), win(SECONDS_PER_DAY, 3_000), win(2 * SECONDS_PER_DAY, 3_000)];
        let states = run_transcript(&r, &steps);
        // Build a tiny 2-leaf-style proof manually for index 0→1 using the real chain:
        // sibling of h0's leaf is leaf(h1); sibling of h1's leaf is leaf(h0).
        let h0 = state_hash(&states[0]);
        let h1 = state_hash(&states[1]);
        let root = hash_pair(&hash_leaf(&h0), &hash_leaf(&h1));
        let prev_proof = [ProofStep { sibling: hash_leaf(&h1), sibling_on_right: true }];
        let next_proof = [ProofStep { sibling: hash_leaf(&h0), sibling_on_right: false }];
        // Single-leaf step commitment for index 0 (root == the leaf, empty proof).
        let step_root = hash_leaf(&step_hash(0, &steps[0]));
        let empty: [ProofStep; 0] = [];
        // Honest operator: claimed_next == real h1 → NO fault.
        let fault = verify_transition_fault(
            &root, &step_root, 0, &states[0], &prev_proof, &h1, &next_proof, &steps[0], &empty, &r,
        );
        assert!(!fault, "an honest transition must not be provable as a fault");
    }

    #[test]
    fn substituted_step_is_not_a_fault() {
        // Soundness: a challenger who supplies a step that ISN'T the committed one proves nothing,
        // even though recomputing with it yields a different next-state. Prevents false-slashing.
        let r = rules();
        let steps = [win(0, 3_000), win(SECONDS_PER_DAY, 3_000), win(2 * SECONDS_PER_DAY, 3_000)];
        let states = run_transcript(&r, &steps);
        let h0 = state_hash(&states[0]);
        let h1 = state_hash(&states[1]);
        let root = hash_pair(&hash_leaf(&h0), &hash_leaf(&h1));
        let prev_proof = [ProofStep { sibling: hash_leaf(&h1), sibling_on_right: true }];
        let next_proof = [ProofStep { sibling: hash_leaf(&h0), sibling_on_right: false }];
        // Step root commits the REAL step 0; the challenger instead submits a fabricated losing step.
        let step_root = hash_leaf(&step_hash(0, &steps[0]));
        let empty: [ProofStep; 0] = [];
        let fake_step = loss(0, 9_999);
        let fault = verify_transition_fault(
            &root, &step_root, 0, &states[0], &prev_proof, &h1, &next_proof, &fake_step, &empty, &r,
        );
        assert!(!fault, "a non-committed (substituted) step must not be provable as a fault");
    }

    #[test]
    fn tampered_next_state_is_caught_as_a_fault() {
        let r = rules();
        let steps = [win(0, 3_000), win(SECONDS_PER_DAY, 3_000), win(2 * SECONDS_PER_DAY, 3_000)];
        let states = run_transcript(&r, &steps);
        let h0 = state_hash(&states[0]);
        // Operator LIES: claims a post-state with an inflated equity (fabricated profit).
        let mut fake = states[1];
        fake.equity += 50_000_000_000; // +$50k out of thin air
        let fake_h1 = state_hash(&fake);
        // Commit the fraudulent leaf into the root.
        let root = hash_pair(&hash_leaf(&h0), &hash_leaf(&fake_h1));
        let prev_proof = [ProofStep { sibling: hash_leaf(&fake_h1), sibling_on_right: true }];
        let next_proof = [ProofStep { sibling: hash_leaf(&h0), sibling_on_right: false }];
        // The step itself is honest (the operator faked the STATE, not the input).
        let step_root = hash_leaf(&step_hash(0, &steps[0]));
        let empty: [ProofStep; 0] = [];
        let fault = verify_transition_fault(
            &root, &step_root, 0, &states[0], &prev_proof, &fake_h1, &next_proof, &steps[0], &empty, &r,
        );
        assert!(fault, "a fabricated post-state must be provable as a fault");
    }

    #[test]
    fn golden_vectors_lock_cross_language_parity() {
        // The canonical scenario shared with the off-chain TS engine
        // (`packages/provably-fair/src/__tests__/settlement.test.ts`). These hex strings are the
        // determinism contract: if EITHER side changes `apply_step` / `state_hash` / `step_hash`,
        // one of the two golden tests breaks. Do not edit without updating both.
        let r = rules();
        let steps = [win(0, 3_000), win(SECONDS_PER_DAY, 3_000), win(2 * SECONDS_PER_DAY, 3_000)];
        let states = run_transcript(&r, &steps);
        let golden_states = [
            "e7e573066f03f8e67cfbac620746968b894d07ba0c7537ae90e153f00d393880",
            "6594af0231ecaaf55c9028679c90c964b48de33c5f5cf8a93f02e1b0e0a58598",
            "424a8d133948e9588449a45820227c854fce4977e8a00ea578c66422ff7aa7e4",
            "a9ac49cd6c9ab4171377658f06004a613b4952dfbed88bb334b984feb7ae9dcd",
        ];
        for (i, s) in states.iter().enumerate() {
            assert_eq!(state_hash(s), golden_states[i], "state[{i}] hash drifted");
        }
        let golden_steps = [
            "d485997df68f11a3a6f213a6c20104618f4e937240c5f09a6a183d4e79891bca",
            "02f17e8dd82d66bc6391e502fc1d7cbf355a73118e4b6689ca2e2f891a32ba86",
            "05e2ac2fd141a7bf8b8608d0bbd668129c6daedcada85015ee70c0dc28a40027",
        ];
        for (i, st) in steps.iter().enumerate() {
            assert_eq!(step_hash(i as u32, st), golden_steps[i], "step[{i}] hash drifted");
        }
        let out = derive_outcome(states.last().unwrap(), &r);
        assert!(out.passed);
        assert_eq!(out.virtual_profit, 9_000_000_000);
    }

    #[test]
    fn invalid_proof_is_not_a_fault() {
        let r = rules();
        let steps = [win(0, 3_000)];
        let states = run_transcript(&r, &steps);
        let h1 = state_hash(&states[1]);
        // A bogus root that the pre-state is NOT a member of → must return false (not a fault).
        let bogus_root = sha256_hex("not-a-real-root");
        let empty: [ProofStep; 0] = [];
        let fault = verify_transition_fault(
            &bogus_root, &bogus_root, 0, &states[0], &empty, &h1, &empty, &steps[0], &empty, &r,
        );
        assert!(!fault, "a proof that doesn't resolve to the committed root proves nothing");
    }

    // ───────────────────── H-2: input-authenticity fault tests ─────────────────────

    const EPOCH: u64 = 100;

    /// Build a 2-leaf Merkle root + the proof for index 0 (sibling = leaf1 on the right).
    fn two_leaf(leaf0: &str, leaf1: &str) -> (String, [ProofStep; 1]) {
        let root = hash_pair(leaf0, leaf1);
        (root, [ProofStep { sibling: leaf1.to_string(), sibling_on_right: true }])
    }

    #[test]
    fn honest_input_has_no_provable_fault() {
        // The trader's two committed trades.
        let trade0 = win(0, 3_000);
        let trade1 = win(SECONDS_PER_DAY, 3_000);
        // Batch root commits the canonical ticks (what the batch-commit service published).
        let batch_leaf0 = hash_leaf(&tick_preimage(&trade0));
        let batch_leaf1 = hash_leaf(&tick_preimage(&trade1));
        let (batch_root, batch_proof0) = two_leaf(&batch_leaf0, &batch_leaf1);
        // Operator commits provenance-bound steps welded to the SAME batch slots.
        let s_leaf0 = bound_step_leaf(0, EPOCH, 0, &trade0);
        let s_leaf1 = bound_step_leaf(1, EPOCH, 1, &trade1);
        let (step_root, step_proof0) = two_leaf(&s_leaf0, &s_leaf1);
        // Honest: the operator's step 0 IS the committed tick at batch slot 0 → no fault.
        let fault = verify_input_fault(
            &step_root, 0, EPOCH, 0, &trade0, &step_proof0, &batch_root, &batch_leaf0, &batch_proof0,
        );
        assert!(!fault, "an honest, correctly-sourced step must not be provable as an input fault");
    }

    #[test]
    fn fabricated_input_is_caught_as_a_fault() {
        // Real committed trades (the truth, in the batch root).
        let real_trade0 = win(0, 100); // a modest +$100 trade actually happened
        let real_trade1 = win(SECONDS_PER_DAY, 100);
        let batch_leaf0 = hash_leaf(&tick_preimage(&real_trade0));
        let batch_leaf1 = hash_leaf(&tick_preimage(&real_trade1));
        let (batch_root, batch_proof0) = two_leaf(&batch_leaf0, &batch_leaf1);
        // Operator FABRICATES a huge winner and welds it to real batch slot 0 (claims it came from there).
        let fake_trade0 = win(0, 9_999);
        let s_leaf0 = bound_step_leaf(0, EPOCH, 0, &fake_trade0);
        let s_leaf1 = bound_step_leaf(1, EPOCH, 1, &real_trade1);
        let (step_root, step_proof0) = two_leaf(&s_leaf0, &s_leaf1);
        // The committed step at slot 0 (+$9,999) ≠ the real committed tick at slot 0 (+$100) → FAULT.
        let fault = verify_input_fault(
            &step_root, 0, EPOCH, 0, &fake_trade0, &step_proof0, &batch_root, &batch_leaf0, &batch_proof0,
        );
        assert!(fault, "a fabricated trade welded to a real batch slot must be provable as an input fault");
    }

    #[test]
    fn step_not_in_step_root_proves_nothing() {
        // Soundness: a challenger who supplies a step/provenance the operator did NOT commit proves
        // nothing (prevents false-slashing an honest operator).
        let real_trade0 = win(0, 100);
        let batch_leaf0 = hash_leaf(&tick_preimage(&real_trade0));
        let (batch_root, batch_proof0) = two_leaf(&batch_leaf0, &hash_leaf("other"));
        // The committed step_root is over DIFFERENT leaves; the challenger fabricates a provenance.
        let (step_root, _) = two_leaf(&hash_leaf("committedA"), &hash_leaf("committedB"));
        let bogus_proof = [ProofStep { sibling: hash_leaf("committedB"), sibling_on_right: true }];
        let fake_trade0 = win(0, 9_999);
        let fault = verify_input_fault(
            &step_root, 0, EPOCH, 0, &fake_trade0, &bogus_proof, &batch_root, &batch_leaf0, &batch_proof0,
        );
        assert!(!fault, "a step the operator never committed must not be provable as a fault");
    }

    #[test]
    fn h2_leaf_golden_vectors_lock_cross_language_parity() {
        // Shared with the TS test (provably-fair/src/__tests__/settlement-binding.test.ts). If EITHER
        // side changes `tick_preimage` / `bound_step_leaf`, one of these breaks. Step = win(0, 3000),
        // epoch 100, transcript index 0, batch leaf index 0.
        let step = win(0, 3_000);
        assert_eq!(
            hash_leaf(&tick_preimage(&step)),
            "78ba643e131c459b81487f2580f00501bd0d7582c9eab09a2780d4fdbe5027eb",
            "tick leaf hash drifted"
        );
        assert_eq!(
            bound_step_leaf(0, 100, 0, &step),
            "56e59457b2adc117e17fb6d648a7b82224e7345289617ea3540920d2b05df0d9",
            "bound_step_leaf hash drifted"
        );
        // BATCH-ROOT-SCOPE-1 segment leaf. A fixed, well-known pubkey (the system program) so the TS
        // side can pin the identical vector — `Pubkey`'s Display is base58, matching `toBase58()`.
        // A drift here silently breaks EVERY coverage append: the segment proof simply stops verifying
        // and no settlement or withdrawal can ever be proposed again.
        let sys = Pubkey::default();
        assert_eq!(
            segment_preimage(&sys, 2, 3),
            "seg:11111111111111111111111111111111:2:3",
            "segment_preimage drifted"
        );
        assert_eq!(
            segment_leaf(&sys, 2, 3),
            SEGMENT_LEAF_GOLDEN,
            "segment_leaf hash drifted"
        );
    }

    /// Shared with the TS test — printed by the assertion below if it ever drifts.
    const SEGMENT_LEAF_GOLDEN: &str =
        "ba1b8571815ae1aecd308551ddce0b563a6ca893a04b3b4a7b2e774ac32153d7";

    #[test]
    fn wrong_batch_leaf_proof_proves_nothing() {
        // Soundness: an `actual_batch_leaf` that isn't truly in the batch root yields no fault.
        let real_trade0 = win(0, 100);
        let s_leaf0 = bound_step_leaf(0, EPOCH, 0, &real_trade0);
        let (step_root, step_proof0) = two_leaf(&s_leaf0, &hash_leaf("s1"));
        let batch_leaf0 = hash_leaf(&tick_preimage(&real_trade0));
        let (batch_root, _) = two_leaf(&batch_leaf0, &hash_leaf("b1"));
        // Challenger lies about the batch leaf (claims a different leaf with a mismatched proof).
        let lied_leaf = hash_leaf("a-leaf-not-in-the-batch-root");
        let bad_proof = [ProofStep { sibling: hash_leaf("b1"), sibling_on_right: true }];
        let fault = verify_input_fault(
            &step_root, 0, EPOCH, 0, &real_trade0, &step_proof0, &batch_root, &lied_leaf, &bad_proof,
        );
        assert!(!fault, "an unproven batch leaf must not be provable as a fault");
    }

    #[test]
    fn out_of_range_provenance_is_caught_as_a_fault() {
        // The real batch for EPOCH has 2 trades (trade_count = 2). The operator welds a fabricated step
        // to slot index 5 — past the end of the real batch (no real tick there to hide behind).
        let fake = win(0, 9_999);
        let s_leaf0 = bound_step_leaf(0, EPOCH, 5, &fake);
        let (step_root, step_proof0) = two_leaf(&s_leaf0, &hash_leaf("s1"));
        let fault = verify_input_range_fault(&step_root, 0, EPOCH, 5, &fake, &step_proof0, 2);
        assert!(fault, "a committed step pointing past the real trade_count must be a fault");
    }

    #[test]
    fn in_range_provenance_is_not_a_range_fault() {
        // An in-range slot (index 1 < trade_count 2) is NOT a range fault — it's adjudicated by the
        // tick-mismatch path (verify_input_fault), not here.
        let step = win(0, 100);
        let s_leaf0 = bound_step_leaf(0, EPOCH, 0, &step);
        let s_leaf1 = bound_step_leaf(1, EPOCH, 1, &step);
        let step_root = hash_pair(&s_leaf0, &s_leaf1);
        // membership proof for index 1: sibling s_leaf0 sits on the LEFT.
        let proof1 = [ProofStep { sibling: s_leaf0.clone(), sibling_on_right: false }];
        assert_eq!(recompute_root_from_leaf_hash(&s_leaf1, &proof1), step_root);
        let fault = verify_input_range_fault(&step_root, 1, EPOCH, 1, &step, &proof1, 2);
        assert!(!fault, "an in-range slot must not be a range fault");
    }

    // ───────────────────── H-2 §3b: coverage / positional-provenance tests ─────────────────────

    fn coverage() -> Vec<CovEntry> {
        // Epoch 100 has 2 trades (global 0,1); epoch 102 has 3 (global 2,3,4). Total 5 trades.
        vec![
            CovEntry { epoch: 100, prefix: 0, trade_count: 2, base_offset: 0 },
            CovEntry { epoch: 102, prefix: 2, trade_count: 3, base_offset: 0 },
        ]
    }

    #[test]
    fn positional_slot_maps_indices_across_epochs() {
        let cov = coverage();
        assert_eq!(positional_slot(&cov, 0), Some((100, 0)));
        assert_eq!(positional_slot(&cov, 1), Some((100, 1)));
        assert_eq!(positional_slot(&cov, 2), Some((102, 0)));
        assert_eq!(positional_slot(&cov, 4), Some((102, 2)));
        assert_eq!(positional_slot(&cov, 5), None); // past the covered range
    }

    #[test]
    fn positional_provenance_is_not_a_fault() {
        // Operator commits step 2 at its POSITIONAL slot (epoch 102, local 0) → no provenance fault.
        let cov = coverage();
        let step = win(0, 100);
        let pos = positional_slot(&cov, 2).unwrap();
        let leaf = bound_step_leaf(2, pos.0, pos.1, &step);
        let (step_root, proof) = two_leaf(&leaf, &hash_leaf("s_other"));
        let fault = verify_provenance_fault(&step_root, 2, pos.0, pos.1, &step, &proof, pos);
        assert!(!fault, "a positionally-correct provenance must not be a fault");
    }

    #[test]
    fn non_existent_epoch_provenance_is_caught_as_a_fault() {
        // THE last escape: operator welds step 2 to a NON-EXISTENT epoch (999) instead of its
        // positional slot (epoch 102, local 0). The provenance fault catches it.
        let cov = coverage();
        let fake = win(0, 9_999);
        let committed_epoch = 999u64; // no batch root exists for this epoch
        let committed_idx = 0u32;
        let leaf = bound_step_leaf(2, committed_epoch, committed_idx, &fake);
        let (step_root, proof) = two_leaf(&leaf, &hash_leaf("s_other"));
        let pos = positional_slot(&cov, 2).unwrap(); // (102, 0) — the real slot
        let fault = verify_provenance_fault(&step_root, 2, committed_epoch, committed_idx, &fake, &proof, pos);
        assert!(fault, "a step welded to a non-existent epoch (≠ its positional slot) must be a fault");
    }

    #[test]
    fn provenance_fault_needs_the_committed_step() {
        // Soundness: a challenger asserting a provenance the operator never committed proves nothing.
        let cov = coverage();
        let step = win(0, 100);
        let pos = positional_slot(&cov, 2).unwrap();
        let (step_root, _) = two_leaf(&hash_leaf("committedA"), &hash_leaf("committedB"));
        let bogus = [ProofStep { sibling: hash_leaf("committedB"), sibling_on_right: true }];
        let fault = verify_provenance_fault(&step_root, 2, 999, 0, &step, &bogus, pos);
        assert!(!fault, "an uncommitted provenance must not be provable as a fault");
    }

    // ───────────────── DEC-62: funded withdrawal (rebaselined cycle) tests ─────────────────

    /// Build a transcript root over the given states + the membership proof for one index.
    /// (Uses the shared fuzz_support builder so the tree matches the verifiers' fold exactly.)
    fn commit_states(states: &[EngineState]) -> (String, Vec<Vec<ProofStep>>) {
        let leaves: Vec<String> = states.iter().map(|s| hash_leaf(&state_hash(s))).collect();
        fuzz_support::build_tree(&leaves)
    }

    #[test]
    fn rebaseline_collapses_peak_and_debits_the_daily_reference() {
        let r = rules();
        // Trade up to $109k equity over 3 days, peak $109k. The last day opened at $106k, so the trader
        // is +$3k on the day when they withdraw.
        let steps = [win(0, 3_000), win(SECONDS_PER_DAY, 3_000), win(2 * SECONDS_PER_DAY, 3_000)];
        let states = run_transcript(&r, &steps);
        let final_state = *states.last().unwrap();
        assert_eq!(final_state.equity, 109_000_000_000);
        assert_eq!(final_state.peak_equity, 109_000_000_000);
        assert_eq!(final_state.day_start_equity, 106_000_000_000);

        // Withdraw the whole $9k gross → equity back to the $100k starting balance.
        let g = rebaseline_after_withdrawal(&final_state, 9_000_000_000);
        assert_eq!(g.equity, 100_000_000_000);
        // The high-water mark COLLAPSES onto the new equity — a withdrawal is not a drawdown.
        assert_eq!(g.peak_equity, 100_000_000_000);
        // PAYOUT-REBASELINE-DAILY-1: the daily reference is DEBITED, not collapsed. The trader was
        // +$3k on the day before the withdrawal and is still +$3k after it, so the day's remaining
        // loss allowance is unchanged rather than silently reset to zero.
        assert_eq!(g.day_start_equity, 97_000_000_000);
        assert_eq!(g.equity - g.day_start_equity, final_state.equity - final_state.day_start_equity);
        // Carried, not reset.
        assert_eq!(g.trading_days, 3);
        assert_eq!(g.day_index, final_state.day_index);

        // v1 is the pre-fix rule, kept ONLY so the fault verifiers can grandfather history.
        let v1 = rebaseline_after_withdrawal_v1(&final_state, 9_000_000_000);
        assert_eq!(v1.day_start_equity, 100_000_000_000);
        assert_ne!(v1.day_start_equity, g.day_start_equity);
    }

    #[test]
    fn mid_day_withdrawal_no_longer_manufactures_a_daily_breach() {
        // PAYOUT-REBASELINE-DAILY-1, reproduced from production: Trustless Funding account `71795c32`,
        // 2026-08-20, payout `3cf73be7`. The trader withdrew just after the day's peak and then gave
        // some of it back, finishing the day UP. Under v1 the replay set BREACH_DAILY_LOSS and
        // `propose_funded_withdrawal` refused the next cycle forever (`WithdrawalBreached`).
        //
        // Scaled to this fixture's rules ($100k start, 5% daily = $5,000, 10% total DD = $10,000):
        // day 1 opens at $103k, the trader makes $9k (equity $112k), withdraws the $9k gross mid-day,
        // then loses $6k later the same day. They finish the day +$3k up, so nothing may breach. The
        // $6k is chosen to sit above v1's $5k daily line and below both v2's ($14k) and the total
        // drawdown's ($13k), which is what isolates the daily rule as the thing under test.
        let r = rules();
        let c0 = run_transcript(&r, &[win(0, 3_000), win(SECONDS_PER_DAY, 9_000)]);
        let c0_final = *c0.last().unwrap();
        assert_eq!(c0_final.equity, 112_000_000_000);
        assert_eq!(c0_final.day_start_equity, 103_000_000_000); // day 1 opened here
        assert_eq!(c0_final.breach, 0);

        // Withdraw the $9k banked today, then lose $4k LATER THE SAME DAY (no rollover).
        let g = rebaseline_after_withdrawal(&c0_final, 9_000_000_000);
        let after = apply_step(&g, &loss(SECONDS_PER_DAY + 60, 6_000), &r);
        assert_eq!(
            after.breach, 0,
            "a day the trader finished up must not breach after a mid-day withdrawal"
        );

        // The same sequence under v1 breaches — this is the bug, pinned so it cannot come back.
        let g_v1 = rebaseline_after_withdrawal_v1(&c0_final, 9_000_000_000);
        let after_v1 = apply_step(&g_v1, &loss(SECONDS_PER_DAY + 60, 6_000), &r);
        assert_eq!(after_v1.breach, BREACH_DAILY_LOSS, "v1 is expected to be wrong here");
    }

    #[test]
    fn fault_verifier_grandfathers_a_v1_genesis_but_still_catches_a_lie() {
        // PAYOUT-REBASELINE-DAILY-1: cycles committed before the fix hold a v1 genesis in their
        // transcript root. The verifier must not fault them — that would be a permissionless
        // false-slash against honest history — while still faulting anything that is neither rule.
        let r = rules();
        let c0_final =
            *run_transcript(&r, &[win(0, 3_000), win(SECONDS_PER_DAY, 3_000)]).last().unwrap();
        let gross = 6_000_000_000;
        let prev_hash = state_hash(&c0_final);

        for genesis in [
            rebaseline_after_withdrawal(&c0_final, gross),
            rebaseline_after_withdrawal_v1(&c0_final, gross),
        ] {
            let cycle = run_transcript_from(&genesis, &r, &[win(2 * SECONDS_PER_DAY, 500)]);
            let (root, proofs) = commit_states(&cycle);
            assert!(
                !verify_withdrawal_genesis_fault(
                    &root, &cycle[0], &proofs[0], &c0_final, &prev_hash, gross
                ),
                "an honest genesis under either rule must not be faultable"
            );
        }

        // A genesis that debited nothing is still a fault under both.
        let cheat = rebaseline_after_withdrawal(&c0_final, 0);
        let cheat_cycle = run_transcript_from(&cheat, &r, &[win(2 * SECONDS_PER_DAY, 500)]);
        let (cheat_root, cheat_proofs) = commit_states(&cheat_cycle);
        assert!(
            verify_withdrawal_genesis_fault(
                &cheat_root, &cheat_cycle[0], &cheat_proofs[0], &c0_final, &prev_hash, gross
            ),
            "an undebited genesis must still fault"
        );
    }

    #[test]
    fn rebaseline_never_launders_a_breach() {
        // A withdrawal must not wash a sticky breach — otherwise a breached funded account withdraws
        // once and comes back clean.
        let r = rules();
        let steps = [loss(0, 6_000)]; // > 5% daily loss → BREACH_DAILY_LOSS, sticky
        let states = run_transcript(&r, &steps);
        let final_state = *states.last().unwrap();
        assert_eq!(final_state.breach & BREACH_DAILY_LOSS, BREACH_DAILY_LOSS);
        let g = rebaseline_after_withdrawal(&final_state, 0);
        assert_eq!(g.breach, final_state.breach, "a withdrawal must never clear a breach flag");
    }

    #[test]
    fn withdrawing_the_same_profit_twice_earns_zero() {
        // THE DEC-62 drain, in engine terms. Cycle 0 earns $9k and withdraws it. Cycle 1 spans NO new
        // trades, so its profit is 0 — not the $9k a `derive_outcome`-based entitlement would re-count.
        let r = rules();
        let steps = [win(0, 3_000), win(SECONDS_PER_DAY, 3_000), win(2 * SECONDS_PER_DAY, 3_000)];
        let c0 = run_transcript(&r, &steps);
        let c0_final = *c0.last().unwrap();
        assert_eq!(withdrawable_profit(&c0_final, &r), 9_000_000_000); // $9k owed after cycle 0

        // Withdraw the whole gross; cycle 1 opens at the rebaselined genesis and trades nothing.
        let c1_genesis = rebaseline_after_withdrawal(&c0_final, 9_000_000_000);
        let c1 = run_transcript_from(&c1_genesis, &r, &[]);
        assert_eq!(
            withdrawable_profit(c1.last().unwrap(), &r),
            0,
            "profit already paid must not be withdrawable again"
        );
    }

    #[test]
    fn partial_withdrawal_leaves_the_residual_withdrawable() {
        // REGRESSION (caught by the TS parity test, 2026-07-15). A trader who takes only PART of their
        // profit must still be able to reach the rest. An earlier draft measured the entitlement from the
        // cycle's own genesis (`final.equity - genesis.equity`), which reports 0 for the residual and
        // would have locked traders out of their own money forever. `withdrawable_profit` measures from
        // `starting_balance` on an already-rebaselined equity, which is exactly right.
        let r = rules();
        let steps = [win(0, 3_000), win(SECONDS_PER_DAY, 3_000), win(2 * SECONDS_PER_DAY, 3_000)];
        let c0_final = *run_transcript(&r, &steps).last().unwrap();
        assert_eq!(withdrawable_profit(&c0_final, &r), 9_000_000_000); // $9k earned

        // Take only $4k of the $9k.
        let c1_genesis = rebaseline_after_withdrawal(&c0_final, 4_000_000_000);
        assert_eq!(c1_genesis.equity, 105_000_000_000);
        let c1 = run_transcript_from(&c1_genesis, &r, &[]);
        // The untaken $5k is STILL owed — not stranded.
        assert_eq!(
            withdrawable_profit(c1.last().unwrap(), &r),
            5_000_000_000,
            "the residual a trader chose not to withdraw must stay reachable"
        );

        // Earn $500 more; now $5.5k is owed (residual + new).
        let c2 = run_transcript_from(&c1_genesis, &r, &[win(3 * SECONDS_PER_DAY, 500)]);
        assert_eq!(withdrawable_profit(c2.last().unwrap(), &r), 5_500_000_000);

        // And claiming that full $5.5k must NOT fault.
        let (root, proofs) = commit_states(&c2);
        let last = c2.len() - 1;
        let fault = verify_withdrawal_amount_fault(
            &root, &c2[last], &proofs[last], 5_500_000_000, trader_entitlement(5_500_000_000, 8_000),
            8_000, &r,
        );
        assert!(!fault, "claiming the residual plus new profit must not be faultable");
    }

    #[test]
    fn honest_withdrawal_has_no_provable_amount_fault() {
        let r = rules();
        let steps = [win(0, 3_000), win(SECONDS_PER_DAY, 3_000), win(2 * SECONDS_PER_DAY, 3_000)];
        let states = run_transcript(&r, &steps);
        let (root, proofs) = commit_states(&states);
        let last = states.len() - 1;
        // Honest: claim exactly the $9k earned, and exactly the locked 80% trader split.
        let gross = 9_000_000_000i128;
        let trader = trader_entitlement(gross, 8_000);
        let fault = verify_withdrawal_amount_fault(
            &root, &states[last], &proofs[last], gross, trader, 8_000, &r,
        );
        assert!(!fault, "an honest, correctly-split withdrawal must not be faultable");
    }

    #[test]
    fn repeat_withdrawal_over_no_new_trades_is_caught_as_a_fault() {
        // THE proof the design exists for. Cycle 1 spans no trades; any positive gross must fault.
        let r = rules();
        let c0_final = *run_transcript(&r, &[win(0, 3_000), win(SECONDS_PER_DAY, 3_000), win(2 * SECONDS_PER_DAY, 3_000)])
            .last()
            .unwrap();
        let c1_genesis = rebaseline_after_withdrawal(&c0_final, 9_000_000_000);
        let c1 = run_transcript_from(&c1_genesis, &r, &[]);
        let (root, proofs) = commit_states(&c1);
        let last = c1.len() - 1;
        // The keeper tries to pay the SAME $9k a second time.
        let fault = verify_withdrawal_amount_fault(
            &root, &c1[last], &proofs[last],
            9_000_000_000, trader_entitlement(9_000_000_000, 8_000), 8_000, &r,
        );
        assert!(fault, "re-withdrawing an already-paid profit MUST be provable as a fault");
    }

    #[test]
    fn overclaiming_the_trader_split_is_caught_as_a_fault() {
        // The cycle really earned $9k, but the keeper strikes the trader's cut at 100% instead of the
        // locked 80% — the firm's share walks out of the door.
        let r = rules();
        let states = run_transcript(&r, &[win(0, 3_000), win(SECONDS_PER_DAY, 3_000), win(2 * SECONDS_PER_DAY, 3_000)]);
        let (root, proofs) = commit_states(&states);
        let last = states.len() - 1;
        let gross = 9_000_000_000i128;
        let fault = verify_withdrawal_amount_fault(
            &root, &states[last], &proofs[last], gross, gross, 8_000, &r,
        );
        assert!(fault, "a trader cut above the locked split must be provable as a fault");
    }

    #[test]
    fn a_losing_cycle_owes_nothing() {
        let r = rules();
        // Spread losses across days: negative cycle profit, no daily-loss breach needed for the point.
        let states = run_transcript(&r, &[loss(0, 1_000), loss(SECONDS_PER_DAY, 1_000)]);
        let (root, proofs) = commit_states(&states);
        let last = states.len() - 1;
        assert!(withdrawable_profit(&states[last], &r) < 0);
        let fault = verify_withdrawal_amount_fault(
            &root, &states[last], &proofs[last], 1, 1, 8_000, &r,
        );
        assert!(fault, "any positive claim on an underwater account must be a fault");
    }

    #[test]
    fn honest_rebaselined_genesis_has_no_provable_fault() {
        let r = rules();
        let c0_final = *run_transcript(&r, &[win(0, 3_000), win(SECONDS_PER_DAY, 3_000), win(2 * SECONDS_PER_DAY, 3_000)])
            .last()
            .unwrap();
        let gross = 9_000_000_000i128;
        let c1_genesis = rebaseline_after_withdrawal(&c0_final, gross);
        let c1 = run_transcript_from(&c1_genesis, &r, &[win(3 * SECONDS_PER_DAY, 500)]);
        let (root, proofs) = commit_states(&c1);
        let fault = verify_withdrawal_genesis_fault(
            &root, &c1[0], &proofs[0], &c0_final, &state_hash(&c0_final), gross,
        );
        assert!(!fault, "an honestly-rebaselined genesis must not be faultable");
    }

    #[test]
    fn undebited_rebaseline_is_caught_as_a_fault() {
        // The keeper "forgets" to debit the withdrawal — carrying the paid $9k into cycle 1's genesis so
        // it can be withdrawn all over again. This is the drain, dressed as a rebaseline.
        let r = rules();
        let c0_final = *run_transcript(&r, &[win(0, 3_000), win(SECONDS_PER_DAY, 3_000), win(2 * SECONDS_PER_DAY, 3_000)])
            .last()
            .unwrap();
        let gross = 9_000_000_000i128;
        let dishonest_genesis = rebaseline_after_withdrawal(&c0_final, 0); // debited nothing
        let c1 = run_transcript_from(&dishonest_genesis, &r, &[]);
        let (root, proofs) = commit_states(&c1);
        let fault = verify_withdrawal_genesis_fault(
            &root, &c1[0], &proofs[0], &c0_final, &state_hash(&c0_final), gross,
        );
        assert!(fault, "a genesis that didn't debit the committed withdrawal must be a fault");
    }

    #[test]
    fn breach_laundering_rebaseline_is_caught_as_a_fault() {
        // The keeper rebaselines a BREACHED account into a clean genesis.
        let r = rules();
        let c0_final = *run_transcript(&r, &[loss(0, 6_000)]).last().unwrap();
        assert_ne!(c0_final.breach, 0);
        let mut laundered = rebaseline_after_withdrawal(&c0_final, 0);
        laundered.breach = 0; // washed
        let c1 = run_transcript_from(&laundered, &r, &[]);
        let (root, proofs) = commit_states(&c1);
        let fault = verify_withdrawal_genesis_fault(
            &root, &c1[0], &proofs[0], &c0_final, &state_hash(&c0_final), 0,
        );
        assert!(fault, "washing a sticky breach through a rebaseline must be a fault");
    }

    #[test]
    fn fabricated_predecessor_proves_nothing() {
        // Soundness: a challenger who invents a predecessor state (one the chain never committed for
        // cycle N-1) proves nothing — otherwise an honest keeper could be false-slashed against a fake.
        let r = rules();
        let c0_final = *run_transcript(&r, &[win(0, 3_000), win(SECONDS_PER_DAY, 3_000), win(2 * SECONDS_PER_DAY, 3_000)])
            .last()
            .unwrap();
        let gross = 9_000_000_000i128;
        let c1_genesis = rebaseline_after_withdrawal(&c0_final, gross);
        let c1 = run_transcript_from(&c1_genesis, &r, &[]);
        let (root, proofs) = commit_states(&c1);
        // The challenger reveals a DIFFERENT predecessor (richer), against the real committed hash.
        let mut fake_prev = c0_final;
        fake_prev.equity += 50_000_000_000;
        let fault = verify_withdrawal_genesis_fault(
            &root, &c1[0], &proofs[0], &fake_prev, &state_hash(&c0_final), gross,
        );
        assert!(!fault, "a predecessor that isn't the committed one must not be provable as a fault");
    }

    #[test]
    fn uncommitted_boundary_states_prove_nothing() {
        // Soundness: boundary states that aren't the committed leaves prove nothing.
        let r = rules();
        let states = run_transcript(&r, &[win(0, 3_000)]);
        let bogus_root = sha256_hex("not-a-real-root");
        let empty: [ProofStep; 0] = [];
        let fault = verify_withdrawal_amount_fault(
            &bogus_root, &states[1], &empty, 9_000_000_000, 0, 8_000, &r,
        );
        assert!(!fault, "a final state outside the committed transcript proves nothing");
    }

    #[test]
    fn dec62_golden_vectors_lock_cross_language_parity() {
        // Shared with the TS mirror (provably-fair settlement.test.ts). If EITHER side changes
        // `rebaseline_after_withdrawal`, one of these breaks. Do not edit without updating both.
        let r = rules();
        let c0_final = *run_transcript(&r, &[win(0, 3_000), win(SECONDS_PER_DAY, 3_000), win(2 * SECONDS_PER_DAY, 3_000)])
            .last()
            .unwrap();
        let g = rebaseline_after_withdrawal(&c0_final, 9_000_000_000);
        assert_eq!(g.equity, 100_000_000_000);
        assert_eq!(g.peak_equity, 100_000_000_000);
        // PAYOUT-REBASELINE-DAILY-1 repinned this from 100_000_000_000 (v1 collapsed it onto equity).
        assert_eq!(g.day_start_equity, 97_000_000_000);
        assert_eq!(g.day_index, 2);
        assert_eq!(g.trading_days, 3);
        assert_eq!(g.breach, 0);
        assert_eq!(
            state_hash(&g),
            "2cf0989b137d369b858d8223e6745bed9636a0521edeffacf16d5c5c54d63927",
            "DEC-62 rebaselined-genesis state hash drifted"
        );
        // The pre-fix vector, kept so the grandfather path is pinned too rather than merely described.
        let v1 = rebaseline_after_withdrawal_v1(&c0_final, 9_000_000_000);
        assert_eq!(v1.day_start_equity, 100_000_000_000);
        assert_eq!(
            state_hash(&v1),
            "bd487c7478ec0244237e2b26182e088a74e51e2b1a2ed1f0ffb86462d867df0a",
            "the v1 vector is history and must never change"
        );
    }
}

// ───────────────────────── Randomized fuzz harness (security-critical) ─────────────────────────
// A `cargo test`-native, zero-dependency fuzz harness for the settlement engine + Merkle + fault
// verifiers. A bug here is a security hole: either an HONEST operator gets FALSE-SLASHED (a permissionless
// fault wrongly voids their settlement + slashes the bond), or genuine fraud is MISSED. Each property is
// hammered over thousands of seeded inputs; on failure the seed is printed for one-line reproduction.
//
// (This harness is what surfaced the `apply_step` i128 overflow-panic — a crafted extreme step could make
// a fraudulent settlement un-faultable — now fixed with saturating arithmetic and pinned by
// `fuzz_engine_never_panics_on_extreme_steps`.)

/// Shared fuzz/property support — reused by BOTH the `cargo test` randomized harness (`mod fuzz`) and the
/// coverage-guided `cargo fuzz` target (`fuzz/fuzz_targets/settlement_soundness.rs`), so the two exercise
/// the IDENTICAL Merkle construction + soundness invariants. Gated behind `test` / `fuzzing` — never
/// compiled into the deployed program.
#[cfg(any(test, feature = "fuzzing"))]
pub mod fuzz_support {
    use super::*;

    /// Merkle builder matching `recompute_root_from_leaf_hash`'s fold (hash_pair(left,right); odd node
    /// duplicates itself; sibling_on_right ⇔ this node is a left child). Input: already-hashed leaves.
    pub fn build_tree(leaves: &[String]) -> (String, Vec<Vec<ProofStep>>) {
        assert!(!leaves.is_empty());
        let mut levels: Vec<Vec<String>> = vec![leaves.to_vec()];
        while levels.last().unwrap().len() > 1 {
            let prev = levels.last().unwrap();
            let mut next = Vec::with_capacity(prev.len().div_ceil(2));
            let mut i = 0;
            while i < prev.len() {
                let right = if i + 1 < prev.len() { &prev[i + 1] } else { &prev[i] };
                next.push(hash_pair(&prev[i], right));
                i += 2;
            }
            levels.push(next);
        }
        let root = levels.last().unwrap()[0].clone();
        let mut proofs = Vec::with_capacity(leaves.len());
        for leaf_idx in 0..leaves.len() {
            let mut proof = Vec::new();
            let mut i = leaf_idx;
            for level in &levels[..levels.len() - 1] {
                let sibling_on_right = i % 2 == 0;
                let sib_idx = if sibling_on_right { i + 1 } else { i - 1 };
                let sibling = if sib_idx < level.len() { level[sib_idx].clone() } else { level[i].clone() };
                proof.push(ProofStep { sibling, sibling_on_right });
                i /= 2;
            }
            proofs.push(proof);
        }
        (root, proofs)
    }

    /// THE soundness invariant: an HONEST `(rules, steps)` transcript must NOT be faultable by ANY verifier
    /// (transition / input / provenance). A violation means an honest operator could be permissionlessly
    /// false-slashed. Returns `Err(reason)` on a violation; the cargo-fuzz target turns that into a crash
    /// libFuzzer minimises, and the cargo-test harness asserts it. (Engine no-panic is implicit — building
    /// the transcript runs `apply_step` on the input.)
    pub fn check_no_false_slash(
        rules: &RuleParams,
        steps: &[StepInput],
    ) -> std::result::Result<(), String> {
        if steps.is_empty() {
            return Ok(());
        }
        let states = run_transcript(rules, steps);
        let state_leaves: Vec<String> = states.iter().map(|s| hash_leaf(&state_hash(s))).collect();
        let (transcript_root, state_proofs) = build_tree(&state_leaves);
        let step_leaves: Vec<String> =
            steps.iter().enumerate().map(|(i, s)| hash_leaf(&step_hash(i as u32, s))).collect();
        let (step_root, step_proofs) = build_tree(&step_leaves);
        for i in 0..steps.len() {
            let claimed_next = state_hash(&states[i + 1]);
            if verify_transition_fault(
                &transcript_root, &step_root, i as u32, &states[i], &state_proofs[i],
                &claimed_next, &state_proofs[i + 1], &steps[i], &step_proofs[i], rules,
            ) {
                return Err(format!("transition false-slash at step {i}"));
            }
        }
        // Input + provenance: a single-epoch coverage covering all steps, positional bound leaves.
        let epoch = 100u64;
        let batch_leaves: Vec<String> = steps.iter().map(|s| hash_leaf(&tick_preimage(s))).collect();
        let (batch_root, batch_proofs) = build_tree(&batch_leaves);
        let bound: Vec<String> =
            steps.iter().enumerate().map(|(i, s)| bound_step_leaf(i as u32, epoch, i as u32, s)).collect();
        let (bstep_root, bstep_proofs) = build_tree(&bound);
        let entries = [CovEntry { epoch, prefix: 0, trade_count: steps.len() as u32, base_offset: 0 }];
        for i in 0..steps.len() {
            let leaf = hash_leaf(&tick_preimage(&steps[i]));
            if verify_input_fault(
                &bstep_root, i as u32, epoch, i as u32, &steps[i], &bstep_proofs[i], &batch_root, &leaf, &batch_proofs[i],
            ) {
                return Err(format!("input false-slash at step {i}"));
            }
            let pos = positional_slot(&entries, i as u32)
                .ok_or_else(|| "positional_slot None".to_string())?;
            if verify_provenance_fault(&bstep_root, i as u32, pos.0, pos.1, &steps[i], &bstep_proofs[i], pos) {
                return Err(format!("provenance false-slash at step {i}"));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod fuzz {
    use super::fuzz_support::build_tree;
    use super::*;

    /// Small dependency-free PRNG (SplitMix64-ish) for reproducible sequences.
    struct Rng(u64);
    impl Rng {
        fn new(seed: u64) -> Self { Self(seed ^ 0x9E37_79B9_7F4A_7C15) }
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }
        fn range(&mut self, n: u64) -> u64 { if n == 0 { 0 } else { self.next() % n } }
        fn boolean(&mut self) -> bool { self.next() & 1 == 1 }
    }

    // Bounded, realistic micro-USD generators (honest transcripts never hit i128 extremes — those are a
    // separate no-panic stress test below).
    fn gen_rules(r: &mut Rng) -> RuleParams {
        RuleParams {
            starting_balance: (1_000 + r.range(1_000_000)) as i128 * 1_000_000,
            profit_target_bps: r.range(2000) as i128,
            max_daily_loss_bps: r.range(1500) as i128,
            max_total_drawdown_bps: r.range(2000) as i128,
            is_trailing_drawdown: r.boolean(),
            min_trading_days: r.range(6) as u32,
        }
    }
    fn gen_step(r: &mut Rng, day: i64) -> StepInput {
        let qty = (r.range(20_000_000) as i64) - 10_000_000;
        let entry = r.range(200_000_000);
        let exit = (entry as i64 + (r.range(20_000_000) as i64 - 10_000_000)).max(0) as u64;
        StepInput { ts: day * SECONDS_PER_DAY + r.range(86_400) as i64, qty_micro: qty, entry_price: entry, exit_price: exit }
    }
    fn gen_transcript(r: &mut Rng) -> Vec<StepInput> {
        let n = 1 + r.range(12) as usize;
        let mut steps = Vec::with_capacity(n);
        let mut day = 0i64;
        for _ in 0..n {
            if r.range(3) == 0 { day += 1; }
            steps.push(gen_step(r, day));
        }
        steps
    }

    struct Committed { states: Vec<EngineState>, transcript_root: String, state_proofs: Vec<Vec<ProofStep>>, step_root: String, step_proofs: Vec<Vec<ProofStep>> }
    fn commit(rules: &RuleParams, steps: &[StepInput]) -> Committed {
        let states = run_transcript(rules, steps);
        let state_leaves: Vec<String> = states.iter().map(|s| hash_leaf(&state_hash(s))).collect();
        let (transcript_root, state_proofs) = build_tree(&state_leaves);
        let step_leaves: Vec<String> = steps.iter().enumerate().map(|(i, s)| hash_leaf(&step_hash(i as u32, s))).collect();
        let (step_root, step_proofs) = build_tree(&step_leaves);
        Committed { states, transcript_root, state_proofs, step_root, step_proofs }
    }

    // ── INVARIANT 0: the engine NEVER panics, even on adversarial extreme steps ──
    #[test]
    fn fuzz_engine_never_panics_on_extreme_steps() {
        for seed in 0..5_000u64 {
            let mut r = Rng::new(seed);
            let rules = RuleParams {
                starting_balance: r.next() as i128 - (i64::MAX as i128),
                profit_target_bps: r.range(70_000) as i128,
                max_daily_loss_bps: r.range(70_000) as i128,
                max_total_drawdown_bps: r.range(70_000) as i128,
                is_trailing_drawdown: r.boolean(),
                min_trading_days: r.range(10) as u32,
            };
            let mut state = genesis_state(&rules);
            for _ in 0..30 {
                let step = StepInput { ts: r.next() as i64, qty_micro: r.next() as i64, entry_price: r.next(), exit_price: r.next() };
                state = apply_step(&state, &step, &rules);
                let _ = (state_hash(&state), step_hash(0, &step), bound_step_leaf(0, 1, 0, &step), derive_outcome(&state, &rules));
            }
        }
        // Reaching here without an overflow panic IS the assertion.
    }

    // ── INVARIANT 1: an HONEST transcript can never be transition-faulted (no false-slash) ──
    #[test]
    fn fuzz_honest_transcript_never_false_slashed() {
        for seed in 0..3_000u64 {
            let mut r = Rng::new(seed.wrapping_mul(2_654_435_761));
            let rules = gen_rules(&mut r);
            let steps = gen_transcript(&mut r);
            let c = commit(&rules, &steps);
            for i in 0..steps.len() {
                let claimed_next = state_hash(&c.states[i + 1]);
                let fault = verify_transition_fault(
                    &c.transcript_root, &c.step_root, i as u32, &c.states[i], &c.state_proofs[i],
                    &claimed_next, &c.state_proofs[i + 1], &steps[i], &c.step_proofs[i], &rules,
                );
                assert!(!fault, "FALSE-SLASH (transition) seed {seed} index {i}");
            }
        }
    }

    // ── INVARIANT 2: a tampered post-state is ALWAYS caught (no missed fraud) ──
    #[test]
    fn fuzz_tampered_state_always_caught() {
        for seed in 0..3_000u64 {
            let mut r = Rng::new(seed.wrapping_mul(40_503).wrapping_add(7));
            let rules = gen_rules(&mut r);
            let steps = gen_transcript(&mut r);
            let states = run_transcript(&rules, &steps);
            let idx = r.range(steps.len() as u64) as usize; // fault the transition into idx+1
            let mut fake = states.clone();
            fake[idx + 1].equity = fake[idx + 1].equity.saturating_add(1 + r.range(1_000_000) as i128);
            let state_leaves: Vec<String> = fake.iter().map(|s| hash_leaf(&state_hash(s))).collect();
            let (transcript_root, state_proofs) = build_tree(&state_leaves);
            let step_leaves: Vec<String> = steps.iter().enumerate().map(|(i, s)| hash_leaf(&step_hash(i as u32, s))).collect();
            let (step_root, step_proofs) = build_tree(&step_leaves);
            let claimed_next = state_hash(&fake[idx + 1]);
            let fault = verify_transition_fault(
                &transcript_root, &step_root, idx as u32, &fake[idx], &state_proofs[idx],
                &claimed_next, &state_proofs[idx + 1], &steps[idx], &step_proofs[idx], &rules,
            );
            assert!(fault, "MISSED FRAUD (tampered state) seed {seed} index {idx}");
        }
    }

    // ── INVARIANT 3: input-authenticity — honest step↔tick never faults; a fabricated trade always does ──
    #[test]
    fn fuzz_input_fault_soundness() {
        for seed in 0..3_000u64 {
            let mut r = Rng::new(seed.wrapping_mul(2_246_822_519));
            let steps = gen_transcript(&mut r);
            let n = steps.len();
            let epoch = 100 + r.range(1_000);
            let batch_leaves: Vec<String> = steps.iter().map(|s| hash_leaf(&tick_preimage(s))).collect();
            let (batch_root, batch_proofs) = build_tree(&batch_leaves);
            let bound: Vec<String> = steps.iter().enumerate().map(|(i, s)| bound_step_leaf(i as u32, epoch, i as u32, s)).collect();
            let (step_root, step_proofs) = build_tree(&bound);
            for i in 0..n {
                let leaf = hash_leaf(&tick_preimage(&steps[i]));
                let fault = verify_input_fault(&step_root, i as u32, epoch, i as u32, &steps[i], &step_proofs[i], &batch_root, &leaf, &batch_proofs[i]);
                assert!(!fault, "FALSE-SLASH (input) seed {seed} i {i}");
            }
            let idx = r.range(n as u64) as usize;
            let mut fake = steps[idx];
            fake.exit_price = fake.exit_price.wrapping_add(1 + r.range(1_000));
            let mut fab = bound.clone();
            fab[idx] = bound_step_leaf(idx as u32, epoch, idx as u32, &fake);
            let (fab_root, fab_proofs) = build_tree(&fab);
            let real_leaf = hash_leaf(&tick_preimage(&steps[idx]));
            let fault = verify_input_fault(&fab_root, idx as u32, epoch, idx as u32, &fake, &fab_proofs[idx], &batch_root, &real_leaf, &batch_proofs[idx]);
            assert!(fault, "MISSED FRAUD (input) seed {seed} idx {idx}");
        }
    }

    // ── INVARIANT 4: positional provenance never faults; a step off its positional slot always does ──
    #[test]
    fn fuzz_provenance_fault_soundness() {
        for seed in 0..3_000u64 {
            let mut r = Rng::new(seed.wrapping_mul(3_266_489_917));
            let k = 1 + r.range(5) as usize;
            let mut entries = Vec::new();
            let (mut prefix, mut epoch) = (0u64, 100u64);
            for _ in 0..k {
                epoch += 1 + r.range(10);
                let tc = 1 + r.range(8) as u32;
                entries.push(CovEntry { epoch, prefix, trade_count: tc, base_offset: 0 });
                prefix += tc as u64;
            }
            let total = prefix;
            let mut bound = Vec::with_capacity(total as usize);
            let mut steps = Vec::with_capacity(total as usize);
            for gi in 0..total as u32 {
                let (e, li) = positional_slot(&entries, gi).unwrap();
                let mut r2 = Rng::new(seed ^ (gi as u64).wrapping_mul(0xABCD));
                let s = gen_step(&mut r2, 0);
                bound.push(bound_step_leaf(gi, e, li, &s));
                steps.push(s);
            }
            let (step_root, step_proofs) = build_tree(&bound);
            for gi in 0..total as u32 {
                let pos = positional_slot(&entries, gi).unwrap();
                let fault = verify_provenance_fault(&step_root, gi, pos.0, pos.1, &steps[gi as usize], &step_proofs[gi as usize], pos);
                assert!(!fault, "FALSE-SLASH (provenance) seed {seed} gi {gi}");
            }
            let gi = r.range(total) as u32;
            let fake_epoch = 9_999_999 + r.range(1_000); // non-existent epoch (the closed escape)
            let mut fab = bound.clone();
            fab[gi as usize] = bound_step_leaf(gi, fake_epoch, 0, &steps[gi as usize]);
            let (fab_root, fab_proofs) = build_tree(&fab);
            let pos = positional_slot(&entries, gi).unwrap();
            let fault = verify_provenance_fault(&fab_root, gi, fake_epoch, 0, &steps[gi as usize], &fab_proofs[gi as usize], pos);
            assert!(fault, "MISSED FRAUD (provenance / non-existent epoch) seed {seed} gi {gi}");
        }
    }

    // ── DEC-62 fuzz support: commit a state chain and return (root, per-index proofs) ──
    fn commit_chain(states: &[EngineState]) -> (String, Vec<Vec<ProofStep>>) {
        let leaves: Vec<String> = states.iter().map(|s| hash_leaf(&state_hash(s))).collect();
        build_tree(&leaves)
    }

    // ── INVARIANT 5: an HONEST withdrawal cycle is never faultable (no false-slash) ──
    #[test]
    fn fuzz_honest_withdrawal_never_false_slashed() {
        for seed in 0..3_000u64 {
            let mut r = Rng::new(seed.wrapping_mul(1_597_334_677));
            let rules = gen_rules(&mut r);
            let split = r.range(10_001) as i128;

            // Cycle 0: a random honest run, then withdraw a random VALID gross out of what it earned.
            let c0_steps = gen_transcript(&mut r);
            let c0 = run_transcript(&rules, &c0_steps);
            let c0_final = *c0.last().unwrap();
            let owed0 = withdrawable_profit(&c0_final, &rules);
            // A random PARTIAL withdrawal — this is the case that must leave the residual reachable.
            let gross = if owed0 > 0 { (r.range(owed0 as u64 + 1)) as i128 } else { 0 };

            // Cycle 1 opens at the honest rebaseline and trades on.
            let genesis1 = rebaseline_after_withdrawal(&c0_final, gross);
            let c1_steps = gen_transcript(&mut r);
            let c1 = run_transcript_from(&genesis1, &rules, &c1_steps);
            let (root1, proofs1) = commit_chain(&c1);
            let last = c1.len() - 1;

            // (a) the honest rebaselined genesis must never be faultable.
            let gf = verify_withdrawal_genesis_fault(
                &root1, &c1[0], &proofs1[0], &c0_final, &state_hash(&c0_final), gross,
            );
            assert!(!gf, "FALSE-SLASH (withdrawal genesis) seed {seed}");

            // (b) an honest claim (exactly what is still owed, exactly the locked split) must never
            //     fault. Includes any residual left unwithdrawn in cycle 0 — a trader must always be
            //     able to reach their own money.
            let owed1 = withdrawable_profit(&c1[last], &rules);
            if owed1 > 0 {
                let trader = trader_entitlement(owed1, split);
                let af = verify_withdrawal_amount_fault(
                    &root1, &c1[last], &proofs1[last], owed1, trader, split, &rules,
                );
                assert!(!af, "FALSE-SLASH (withdrawal amount) seed {seed}");
            }
        }
    }

    // ── INVARIANT 6: re-withdrawing an already-paid profit is ALWAYS caught (the DEC-62 drain) ──
    #[test]
    fn fuzz_repeat_withdrawal_always_caught() {
        for seed in 0..3_000u64 {
            let mut r = Rng::new(seed.wrapping_mul(2_891_336_453).wrapping_add(11));
            let rules = gen_rules(&mut r);
            let split = 1 + r.range(10_000) as i128;

            // Cycle 0 earns something and withdraws ALL of it.
            let c0 = run_transcript(&rules, &gen_transcript(&mut r));
            let c0_final = *c0.last().unwrap();
            let owed0 = withdrawable_profit(&c0_final, &rules);
            if owed0 <= 0 {
                continue; // nothing was earned, so there is nothing to re-withdraw
            }

            // Cycle 1 opens at the honest rebaseline and trades NOTHING — the keeper tries to pay the
            // same profit a second time.
            let genesis1 = rebaseline_after_withdrawal(&c0_final, owed0);
            let c1 = run_transcript_from(&genesis1, &rules, &[]);
            let (root1, proofs1) = commit_chain(&c1);
            let last = c1.len() - 1;
            let fault = verify_withdrawal_amount_fault(
                &root1, &c1[last], &proofs1[last],
                owed0, trader_entitlement(owed0, split), split, &rules,
            );
            assert!(fault, "MISSED FRAUD (repeat withdrawal) seed {seed} owed {owed0}");
        }
    }

    // ── INVARIANT 7: an UNDEBITED (or over-credited) rebaseline is ALWAYS caught ──
    #[test]
    fn fuzz_dishonest_rebaseline_always_caught() {
        for seed in 0..3_000u64 {
            let mut r = Rng::new(seed.wrapping_mul(3_812_015_801).wrapping_add(3));
            let rules = gen_rules(&mut r);
            let c0 = run_transcript(&rules, &gen_transcript(&mut r));
            let c0_final = *c0.last().unwrap();
            let gross = 1 + r.range(1_000_000_000) as i128;

            // The keeper rebaselines with a SHORTFALL — debiting less than the committed withdrawal, so
            // the difference is profit it can sell twice.
            let shortfall = 1 + r.range(gross as u64) as i128;
            let dishonest = rebaseline_after_withdrawal(&c0_final, gross - shortfall);
            let c1 = run_transcript_from(&dishonest, &rules, &[]);
            let (root1, proofs1) = commit_chain(&c1);
            let fault = verify_withdrawal_genesis_fault(
                &root1, &c1[0], &proofs1[0], &c0_final, &state_hash(&c0_final), gross,
            );
            assert!(fault, "MISSED FRAUD (undebited rebaseline) seed {seed} shortfall {shortfall}");
        }
    }

    // ───────── BATCH-ROOT-SCOPE-1: one firm-hour root, many challenges ─────────

    /// The case that was silently corrupting live: two accounts of the SAME firm trade the SAME hour.
    /// The root is per (firm, epoch), so it holds BOTH runs; each challenge's steps sit at its own
    /// `base_offset`. Before this, the root held only whichever account proposed first, and the second
    /// account's honest steps resolved to slots holding the FIRST account's ticks — which made
    /// `prove_input_fault` succeed against an honest operator, permissionlessly.
    #[test]
    fn two_challenges_share_a_firm_hour_root_without_corrupting_each_other() {
        let epoch = 500u64;
        // A trades 2 fills, B trades 3 — grouped by challenge, so A occupies leaves 0..2, B 2..5.
        // A local step builder — `win` lives in the other test module and is not visible here.
        let tick = |ts: i64, pnl: u64| StepInput {
            ts,
            qty_micro: 1_000_000,
            entry_price: 0,
            exit_price: pnl * 1_000_000,
        };
        let a_steps = [tick(1, 10), tick(2, 20)];
        let b_steps = [tick(3, 30), tick(4, 40), tick(5, 50)];
        let leaves: Vec<String> = a_steps
            .iter()
            .chain(b_steps.iter())
            .map(|s| hash_leaf(&tick_preimage(s)))
            .collect();
        let (_batch_root, _proofs) = build_tree(&leaves);

        let a_cov = [CovEntry { epoch, prefix: 0, trade_count: 2, base_offset: 0 }];
        let b_cov = [CovEntry { epoch, prefix: 0, trade_count: 3, base_offset: 2 }];

        // Each challenge's transcript indices map to ITS OWN leaves in the shared root.
        assert_eq!(positional_slot(&a_cov, 0), Some((epoch, 0)));
        assert_eq!(positional_slot(&a_cov, 1), Some((epoch, 1)));
        assert_eq!(positional_slot(&b_cov, 0), Some((epoch, 2)), "B's run starts at its base_offset");
        assert_eq!(positional_slot(&b_cov, 2), Some((epoch, 4)));

        // The two never collide: no slot is claimed by both.
        let a_slots: Vec<u32> = (0..2).map(|i| positional_slot(&a_cov, i).unwrap().1).collect();
        let b_slots: Vec<u32> = (0..3).map(|i| positional_slot(&b_cov, i).unwrap().1).collect();
        assert!(a_slots.iter().all(|s| !b_slots.contains(s)), "runs must not overlap");

        // And B's honest step at its real slot is NOT a fault — the regression that mattered.
        let pos = positional_slot(&b_cov, 0).unwrap();
        let bound: Vec<String> = b_steps
            .iter()
            .enumerate()
            .map(|(i, s)| bound_step_leaf(i as u32, epoch, positional_slot(&b_cov, i as u32).unwrap().1, s))
            .collect();
        let (bstep_root, bstep_proofs) = build_tree(&bound);
        let real_leaf = hash_leaf(&tick_preimage(&b_steps[0]));
        let (batch_root_hex, batch_proofs) = build_tree(&leaves);
        let fault = verify_input_fault(
            &bstep_root, 0, epoch, pos.1, &b_steps[0], &bstep_proofs[0],
            &batch_root_hex, &real_leaf, &batch_proofs[pos.1 as usize],
        );
        assert!(!fault, "B's honest step at its own slot must never fault");
    }

    /// A segment proof binds (challenge, base_offset, trade_count) to the producer's committed index.
    /// Without this the offset would be keeper-asserted, letting an operator weld its transcript to
    /// another account's contiguous run of real, profitable ticks — a theft every fault proof would
    /// stay silent on, because each tick it points at is genuinely committed.
    #[test]
    fn segment_proof_rejects_an_offset_the_producer_never_committed() {
        let a = Pubkey::new_unique();
        let b = Pubkey::new_unique();
        let segs = vec![segment_leaf(&a, 0, 2), segment_leaf(&b, 2, 3)];
        let (seg_root, seg_proofs) = build_tree(&segs);

        assert!(verify_segment(&seg_root, &a, 0, 2, &seg_proofs[0]), "A's real segment must verify");
        assert!(verify_segment(&seg_root, &b, 2, 3, &seg_proofs[1]), "B's real segment must verify");

        // A claiming B's run (the theft) — same proof, shifted offset. Must not verify.
        assert!(!verify_segment(&seg_root, &a, 2, 3, &seg_proofs[0]), "A must not claim B's run");
        // A inflating its own count to swallow B's leaves.
        assert!(!verify_segment(&seg_root, &a, 0, 5, &seg_proofs[0]), "A must not widen its run");
        // B replaying A's proof for its own key.
        assert!(!verify_segment(&seg_root, &b, 0, 2, &seg_proofs[0]), "a proof is bound to its challenge");
    }
}
