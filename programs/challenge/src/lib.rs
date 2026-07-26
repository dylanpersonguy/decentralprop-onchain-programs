// Anchor's own `#[program]` macro expansion still calls the deprecated `AccountInfo::realloc` —
// nothing in application code to fix here. Also carries `too_many_arguments`: the macro emits a
// second copy of that lint against its own generated dispatcher (distinct from the diagnostic at
// each instruction fn's own definition, which the per-function `#[allow]`s below already cover) —
// both need a crate-level allow because neither is reachable from an attribute on our own code.
#![allow(deprecated, clippy::too_many_arguments)]

use anchor_lang::prelude::*;

pub mod envelope;
pub mod settlement;

declare_id!("ENyhfPtpY1BPDFfdMmrUa4XJxuqXSeejgtGBHhhJsEBR");

// Gated on `no-entrypoint` (implied by the `cpi` feature): this program is a path-dependency of
// `dispute` and `firm` for CPI, and an unconditional security_txt! would emit a duplicate
// `.security.txt` link section when this crate is compiled into their binaries.
#[cfg(not(feature = "no-entrypoint"))]
solana_security_txt::security_txt! {
    name: "DecentralProp: Challenge",
    project_url: "https://decentralprop.com",
    contacts: "email:security@decentralprop.com",
    policy: "https://github.com/dylanpersonguy/decentralprop-onchain-programs/blob/main/SECURITY.md",
    preferred_languages: "en",
    source_code: "https://github.com/dylanpersonguy/decentralprop-onchain-programs/tree/main/programs/challenge",
    source_release: "devnet"
}

/// The firm program's on-chain address (`onchain/Anchor.toml`, identical across clusters). F2's
/// mint-time guard reads `firm::FirmState` STRAIGHT FROM THE ACCOUNT BYTES rather than via a typed
/// `Account<'info, FirmState>`, because the challenge crate cannot depend on `firm` — `firm` already
/// depends on `challenge` via CPI, so the reverse edge is a Cargo cycle. The manual read pins ownership
/// to this id. Bytes = base58-decode of the id (kept as an array so the const is `Pubkey::new_from_array`,
/// which is `const`; the `pubkey!` macro path is avoided to keep this dependency-free).
const FIRM_PROGRAM_ID: Pubkey = Pubkey::new_from_array([
    52, 248, 32, 172, 208, 154, 238, 86, 140, 167, 19, 131, 232, 36, 27, 244, 168, 150, 204, 154, 137,
    198, 245, 7, 46, 161, 168, 194, 110, 157, 180, 0,
]);

/// Anchor account discriminator for `firm::FirmState` = `sha256("account:FirmState")[..8]`. Pinned so
/// the guard rejects any firm-program-owned account that is NOT a FirmState (belt-and-braces on top of
/// the owner + length checks) — a wrong account passed for the PDA-seed `firm` can't be mistaken for one.
const FIRM_STATE_DISCRIMINATOR: [u8; 8] = [79, 104, 191, 39, 34, 238, 54, 105];

/// Byte offset of `FirmState.risk_engine_authority`: 8 (Anchor disc) + 32 (`owner: Pubkey`). It is a
/// `Pubkey`, occupying `[40, 72)`. FirmState is append-only (K-1 rotation, bond, token fields are all
/// appended AFTER `bump`), so the offset of these two LEADING fields is stable across every migration.
const FIRM_RISK_ENGINE_AUTHORITY_OFFSET: usize = 40;

/// DecentralProp `challenge_program` (architecture §6, §8, §10, §19).
///
/// Manages the challenge lifecycle and — critically — locks the rule parameters at
/// purchase into an immutable `RulesSnapshot`. The off-chain risk engine evaluates
/// every challenge against *its own* snapshot, never live firm config, which is what
/// makes grandfathering automatic (§9): a trader can never be failed by a rule that
/// did not exist when they bought in.
///
/// This slice covers `purchase_challenge` (lock rules), `settle_challenge` (post the
/// pass/fail outcome + locked payout amounts, open the 24h dispute window) and
/// `close_challenge` (rent reclaim on a terminal challenge). The actual SOL fee
/// split (§17) and the payout buy (§22) land with the treasury / bonding-curve
/// programs; the settled `payout_firma_owed` recorded here is what those will pay.
#[program]
pub mod challenge {
    use super::*;

    /// Purchase a challenge: locks `rules` into the PDA and starts the challenge.
    /// The PDA is seeded on (firm, trader, account_size_tier, phase, nonce) — a multi-phase
    /// evaluation (1-step: Phase1→Funded; 2-step: Phase1→Phase2→Funded) is a distinct PDA per
    /// phase, each with its own immutable `RulesSnapshot` (so the §9 grandfathering guarantee
    /// holds per phase: the rules a trader is judged on were locked when that phase was bought).
    /// `nonce` is a caller-supplied purchase-instance discriminator with no on-chain meaning beyond
    /// the PDA seed — it lets a trader hold any number of challenges of the same size at once (the
    /// caller, e.g. the gateway, picks a fresh one per purchase). `rules` is built off-chain from the
    /// firm baseline + the ARE tier prevailing at purchase.
    pub fn purchase_challenge(
        ctx: Context<PurchaseChallenge>,
        account_size_tier: u8,
        phase: u8,
        rules: RulesSnapshot,
        discount_applied: bool,
        nonce: u64,
    ) -> Result<()> {
        require!(account_size_tier <= MAX_ACCOUNT_SIZE_TIER, ChallengeError::InvalidTier);
        let phase = ChallengePhase::from_u8(phase).ok_or(ChallengeError::InvalidPhase)?;
        require!(
            (rules.trader_split_bps as u32) + (rules.stakeholder_split_bps as u32) <= 10_000,
            ChallengeError::InvalidSplit
        );

        let now = Clock::get()?.unix_timestamp;
        let trader = ctx.accounts.trader.key();
        let firm = ctx.accounts.firm.key();
        let settlement_authority = ctx.accounts.settlement_authority.key();
        // F2 (SETTLEMENT-AUTH-MINT-GUARD): bind the challenge's frozen `settlement_authority` to the
        // firm's LIVE `risk_engine_authority` AT MINT. A mismatch here produces a challenge that is
        // permanently unpayable (the firm payout gate reverts `Unauthorized` forever), so a funded such
        // account's SOL would be stuck; rejecting it at creation makes that state unconstructable. `firm`
        // is a PDA-seed account elsewhere — here it is additionally read for its keeper.
        require_keys_eq!(
            settlement_authority,
            firm_risk_engine_authority(&ctx.accounts.firm.to_account_info())?,
            ChallengeError::SettlementAuthorityMismatch
        );
        let bump = ctx.bumps.challenge;
        let challenge = &mut ctx.accounts.challenge;
        init_challenge_state(
            challenge,
            trader,
            firm,
            settlement_authority,
            account_size_tier,
            phase,
            rules,
            discount_applied,
            now,
            bump,
            nonce,
        )?;

        emit!(ChallengePurchased {
            challenge: challenge.key(),
            firm: challenge.firm,
            trader: challenge.trader,
            account_size_tier,
            phase: phase as u8,
            started_at: now,
        });
        Ok(())
    }

    /// Grant a **free evaluation account** to a staking-giveaway winner (architecture §19). This is
    /// the on-chain fulfillment of the ARE-sized daily giveaway: the winning staker receives a real,
    /// tradeable evaluation challenge WITHOUT paying the §17 fee. It is functionally
    /// `purchase_challenge` with two deliberate differences: (1) the winner neither signs nor pays —
    /// the firm's settlement authority is the sole signer AND the rent payer, because a gift needs no
    /// consent from its recipient; (2) `day_index` + `draw_seed` are stamped into the emitted event
    /// so the grant is publicly, verifiably tied back to the provably-fair draw that picked the winner.
    ///
    /// Security: the same `settlement_authority` co-sign that makes `purchase_challenge`'s locked
    /// `rules` an *authorized* commitment applies here, and the firm program's payout gate still binds
    /// `challenge.settlement_authority == firm.risk_engine_authority` before any funds move — so a
    /// granted (even funded) account can only ever release value through the firm's real authority. A
    /// rogue signer can at worst mint an unpayable challenge for some wallet, at their own rent cost.
    pub fn grant_giveaway_challenge(
        ctx: Context<GrantGiveawayChallenge>,
        account_size_tier: u8,
        phase: u8,
        rules: RulesSnapshot,
        day_index: u32,
        draw_seed: u64,
        nonce: u64,
    ) -> Result<()> {
        require!(account_size_tier <= MAX_ACCOUNT_SIZE_TIER, ChallengeError::InvalidTier);
        let phase = ChallengePhase::from_u8(phase).ok_or(ChallengeError::InvalidPhase)?;
        require!(
            (rules.trader_split_bps as u32) + (rules.stakeholder_split_bps as u32) <= 10_000,
            ChallengeError::InvalidSplit
        );

        let now = Clock::get()?.unix_timestamp;
        let winner = ctx.accounts.winner.key();
        let firm = ctx.accounts.firm.key();
        let settlement_authority = ctx.accounts.settlement_authority.key();
        // F2 (SETTLEMENT-AUTH-MINT-GUARD): identical bind to the mint guard in `purchase_challenge`. A
        // giveaway/funded-provision grant must also produce a payable challenge — the sole signer here IS
        // the settlement authority, so this reduces to "the signer must be the firm's real keeper".
        require_keys_eq!(
            settlement_authority,
            firm_risk_engine_authority(&ctx.accounts.firm.to_account_info())?,
            ChallengeError::SettlementAuthorityMismatch
        );
        let bump = ctx.bumps.challenge;
        let challenge = &mut ctx.accounts.challenge;
        // A giveaway grant charges no fee, so `discount_applied` is false — no §17 loss-back discount
        // was consumed. The resulting challenge is byte-for-byte a normal bought evaluation.
        init_challenge_state(
            challenge,
            winner,
            firm,
            settlement_authority,
            account_size_tier,
            phase,
            rules,
            false,
            now,
            bump,
            nonce,
        )?;

        emit!(GiveawayChallengeGranted {
            challenge: challenge.key(),
            firm: challenge.firm,
            winner: challenge.trader,
            account_size_tier,
            phase: phase as u8,
            day_index,
            draw_seed,
            granted_at: now,
        });
        Ok(())
    }

    /// F2 heal path (SETTLEMENT-AUTH-MINT-GUARD). A challenge minted BEFORE the mint-time guard existed
    /// (or by a since-fixed client) can carry a `settlement_authority` that is not the firm's real
    /// keeper, which makes it PERMANENTLY UNPAYABLE. This lets the firm's CURRENT `risk_engine_authority`
    /// re-point such a challenge's `settlement_authority` to itself, restoring payability without moving
    /// any funds.
    ///
    /// Safe by construction: it can ONLY ever write the firm's live keeper (read from the firm account
    /// and required to equal the signer), so it cannot redirect a challenge to an attacker — the caller
    /// must already BE the firm's keeper, and the only value it can set is that same keeper. It grants no
    /// capability the keeper lacks (the keeper is already the settlement authority for the firm's other
    /// challenges); it merely lets the firm adopt an orphan it could otherwise never pay. Idempotent when
    /// the challenge already points at the current keeper. `firm` is bound to `challenge.firm` by the
    /// account struct, so the keeper read is the RIGHT firm's.
    pub fn repair_settlement_authority(ctx: Context<RepairSettlementAuthority>) -> Result<()> {
        let firm_authority = firm_risk_engine_authority(&ctx.accounts.firm.to_account_info())?;
        require_keys_eq!(
            ctx.accounts.risk_engine_authority.key(),
            firm_authority,
            ChallengeError::Unauthorized
        );
        let challenge = &mut ctx.accounts.challenge;
        let previous = challenge.settlement_authority;
        challenge.settlement_authority = firm_authority;
        emit!(SettlementAuthorityRepaired {
            challenge: challenge.key(),
            firm: challenge.firm,
            previous,
            current: firm_authority,
        });
        Ok(())
    }

    /// **DEPRECATED — trusted path, NON-PAYABLE (M-1).** Settle an active challenge by directly
    /// asserting the outcome, with no transcript commitment or fraud-proof window. It marks the
    /// settlement `Final` immediately but leaves `settlement_window_end == 0`, and the firm payout gate
    /// (`require_firm_settlement_authority`) now REFUSES any settlement with `settlement_window_end == 0`
    /// — so a `settle_challenge`-settled challenge can never release funds. Retained only as an
    /// off-chain status-update shim during migration; new keepers MUST use the `propose_settlement` →
    /// `finalize_settlement` verifiable path. Signed by the firm's settlement authority.
    pub fn settle_challenge(
        ctx: Context<SettleChallenge>,
        passed: bool,
        virtual_profit: i64,
        payout_sol_owed: u64,
        payout_firma_owed: u64,
        settlement_risk_tier: RiskTier,
    ) -> Result<()> {
        let challenge = &mut ctx.accounts.challenge;
        require!(challenge.status == ChallengeStatus::Active, ChallengeError::NotActive);
        // Only a FUNDED challenge can owe a payout. *Passing* an evaluation phase (Phase1/Phase2)
        // is an *advance* — the off-chain engine spawns the next-phase challenge; no funds move.
        // Only the funded account earns a withdrawal (mirrors the off-chain phase chain). A failed
        // settle owes nothing regardless (zeroed below), so the gate only binds on a pass.
        require!(
            !passed
                || challenge.phase == ChallengePhase::Funded
                || (payout_sol_owed == 0 && payout_firma_owed == 0),
            ChallengeError::PayoutBeforeFunded
        );

        let now = Clock::get()?.unix_timestamp;
        challenge.status = if passed { ChallengeStatus::Passed } else { ChallengeStatus::Failed };
        challenge.virtual_profit = virtual_profit;
        challenge.payout_sol_owed = if passed { payout_sol_owed } else { 0 };
        challenge.payout_firma_owed = if passed { payout_firma_owed } else { 0 };
        challenge.settlement_risk_tier = settlement_risk_tier;
        challenge.settled_at = now;
        challenge.dispute_deadline = now
            .checked_add(DISPUTE_WINDOW)
            .ok_or(ChallengeError::MathOverflow)?;
        // Deprecated trusted path: mark Final immediately so the firm payout gate accepts it during
        // migration. The verifiable path reaches Final only AFTER its fraud-proof window.
        challenge.settlement_status = SettlementStatus::Final;

        emit!(ChallengeSettled {
            challenge: challenge.key(),
            passed,
            virtual_profit,
            payout_firma_owed: challenge.payout_firma_owed,
            settled_at: now,
        });
        Ok(())
    }

    /// ───────────────────────── Integrity gate (step 3) ─────────────────────────
    /// Place or lift an on-chain integrity hold on a challenge. While held, the
    /// firm program's payout gate (`require_firm_settlement_authority`) refuses to
    /// enqueue or pay this challenge — so an integrity-engine freeze is enforced
    /// ON-CHAIN and cannot be bypassed by flipping an off-chain flag. Signed by the
    /// firm's settlement authority (the same authority that settles), so only the
    /// firm's real risk-engine authority can hold or release funds.
    pub fn set_integrity_hold(
        ctx: Context<SetIntegrityHold>,
        held: bool,
        evidence_root: [u8; 32],
    ) -> Result<()> {
        let challenge = &mut ctx.accounts.challenge;
        challenge.integrity_hold = held;
        // Bind the hold to the evidence so it can be fault-proven; clear on release.
        challenge.integrity_evidence_root = if held { evidence_root } else { [0u8; 32] };
        emit!(IntegrityHoldSet {
            challenge: challenge.key(),
            held,
        });
        Ok(())
    }

    /// Permissionless integrity FAULT PROOF (step 4): anyone — the affected trader
    /// or a watchtower — reveals the flags behind a hold. If they hash to the
    /// committed `integrity_evidence_root` AND are all identity/advisory detectors
    /// (no behavioural abuse), the hard-coded rules deterministically yield NO
    /// action — so the hold is unjustified and is cleared here, releasing the
    /// payout WITHOUT the operator. This covers the legit multi-firm / multi-
    /// account class that must never be seized; the general behavioural-evidence
    /// recompute is future work.
    pub fn prove_integrity_fault(
        ctx: Context<ProveIntegrityFault>,
        flags: Vec<FaultFlag>,
    ) -> Result<()> {
        let challenge = &mut ctx.accounts.challenge;
        require!(challenge.integrity_hold, ChallengeError::NoIntegrityHold);
        require!(!flags.is_empty(), ChallengeError::EmptyEvidence);
        // Every revealed flag must be an identity/advisory detector.
        for f in flags.iter() {
            require!(ADVISORY_CODES.contains(&f.code), ChallengeError::BehaviouralEvidence);
        }
        // Recompute the evidence root: canonical 6-byte records, sorted, sha256.
        let root = integrity_evidence_root(&flags);
        require!(
            root == challenge.integrity_evidence_root,
            ChallengeError::EvidenceRootMismatch
        );
        // Advisory-only ⇒ rules yield NONE ⇒ the hold is a fault. Clear it.
        challenge.integrity_hold = false;
        challenge.integrity_evidence_root = [0u8; 32];
        emit!(IntegrityFaultProven {
            challenge: challenge.key(),
            flags: flags.len() as u32,
        });
        Ok(())
    }

    /// ───────────────────────── Verifiable settlement (F5) ─────────────────────────
    /// Propose a settlement by COMMITTING to a deterministic, replayable transcript instead of
    /// just asserting numbers. The operator posts the `transcript_root` (Merkle root over the
    /// per-step state-hash chain h_0..h_N), the final state hash, the transcript length, and the
    /// claimed result (passed / virtual_profit / owed). NO funds move and the outcome is NOT yet
    /// applied: the challenge enters `Provisional` and a fraud-proof window opens. Anyone may
    /// disprove it via `prove_settlement_fault` / `prove_result_fault` before `finalize_settlement`.
    /// Signed by the settlement authority. This is the trustless replacement for `settle_challenge`.
    /// ─────────────── H-2 §3b: settlement coverage (positional-provenance binding) ───────────────
    /// Begin a settlement's COVERAGE — the ordered set of real batch epochs the transcript draws from.
    /// One-time per challenge (PDA `["coverage", challenge]`). Built up by `add_coverage_epoch` before
    /// `propose_settlement` consumes + finalises it. Signed by the settlement authority.
    pub fn init_settlement_coverage(ctx: Context<InitSettlementCoverage>) -> Result<()> {
        let challenge = &ctx.accounts.challenge;
        require!(challenge.status == ChallengeStatus::Active, ChallengeError::NotActive);
        require!(
            challenge.settlement_status == SettlementStatus::Unsettled,
            ChallengeError::SettlementAlreadyProposed
        );
        let cov = &mut ctx.accounts.coverage;
        cov.challenge = challenge.key();
        cov.covered_trade_count = 0;
        cov.running_prefix = 0;
        cov.last_epoch = 0;
        cov.finalized = false;
        cov.entries = Vec::new();
        cov.bump = ctx.bumps.coverage;
        Ok(())
    }

    /// Append one REAL batch epoch to the coverage (H-2 §3b). The typed `batch_root` account proves the
    /// epoch EXISTS and is authentic (post-H-1, written by the authorised committer). Epochs MUST be
    /// added in strictly increasing order. Signed by the settlement authority.
    ///
    /// **BATCH-ROOT-SCOPE-1:** this used to record `batch_root.trade_count` — the count of the WHOLE
    /// firm-hour — as if it were this challenge's. That was only ever right when one account traded the
    /// firm's hour; with two, the first to propose owned the root and the second bound a count that was
    /// not its own. The caller must now PROVE its `(base_offset, trade_count)` segment against
    /// `batch_root.segment_root`, so the numbers recorded here are the producer's, not the keeper's.
    pub fn add_coverage_epoch(
        ctx: Context<AddCoverageEpoch>,
        epoch: u64,
        base_offset: u32,
        trade_count: u32,
        segment_proof: Vec<settlement::ProofStep>,
    ) -> Result<()> {
        require!(!ctx.accounts.coverage.finalized, ChallengeError::CoverageFinalized);
        require!(
            ctx.accounts.coverage.entries.len() < MAX_COVERAGE_EPOCHS,
            ChallengeError::CoverageFull
        );
        require!(
            ctx.accounts.coverage.entries.is_empty() || epoch > ctx.accounts.coverage.last_epoch,
            ChallengeError::CoverageEpochOrder
        );
        // The segment must be the one the producer committed for THIS challenge in THIS epoch. Without
        // this the keeper could point its run at another account's real, profitable ticks — a theft no
        // existing fault proof can see, because every tick it references is genuinely committed.
        require!(
            settlement::verify_segment(
                &settlement::root_to_hex(&ctx.accounts.batch_root.segment_root),
                &ctx.accounts.challenge.key(),
                base_offset,
                trade_count,
                &segment_proof,
            ),
            ChallengeError::CoverageSegmentInvalid
        );
        // The run must fit inside the epoch's real leaf space; a segment past the end could never be
        // faulted positionally (there is no tick at that slot to compare against).
        require!(
            base_offset
                .checked_add(trade_count)
                .ok_or(ChallengeError::MathOverflow)?
                <= ctx.accounts.batch_root.trade_count,
            ChallengeError::CoverageSegmentInvalid
        );
        let cov = &mut ctx.accounts.coverage;
        let prefix = cov.running_prefix;
        cov.entries.push(CoverageEntry { epoch, prefix, trade_count, base_offset });
        cov.running_prefix = cov
            .running_prefix
            .checked_add(trade_count as u64)
            .ok_or(ChallengeError::MathOverflow)?;
        cov.covered_trade_count = cov.running_prefix;
        cov.last_epoch = epoch;
        Ok(())
    }

    /// The settlement-coverage counterpart of `add_withdrawal_coverage_epoch_supplemental` — append a
    /// `SupplementalSegment`'s trade count to an EVAL SETTLEMENT's coverage (`["coverage", challenge]`),
    /// with the same bookkeeping `add_coverage_epoch` does for a primary segment, so
    /// `propose_settlement`'s `covered_trade_count == transcript_len - 1` check cannot tell the two
    /// sources apart. `base_offset` is always 0 — see `commit_supplemental_segment`'s doc comment for why
    /// that is deliberate, not a placeholder.
    ///
    /// This did not exist until CoverageSegmentInvalid (err 6022): `resolveSegments` (off-chain) already
    /// falls back to a `SupplementalSegment` for a late-provisioned challenge, for EITHER propose path —
    /// but with no settlement-side counterpart to submit it to, the eval-settlement keeper had only
    /// `add_coverage_epoch` to call, which demands a real Merkle proof against `batch_root.segment_root`.
    /// A supplemental segment's proof is empty by construction (there is no firm-wide tree it could ever
    /// be a member of), so that call was guaranteed to fail `verify_segment` — not a fabrication risk, an
    /// eval that could never be proposed at all whenever it needed this recovery.
    pub fn add_coverage_epoch_supplemental(
        ctx: Context<AddCoverageEpochSupplemental>,
        epoch: u64,
    ) -> Result<()> {
        require!(!ctx.accounts.coverage.finalized, ChallengeError::CoverageFinalized);
        require!(
            ctx.accounts.coverage.entries.len() < MAX_COVERAGE_EPOCHS,
            ChallengeError::CoverageFull
        );
        require!(
            ctx.accounts.coverage.entries.is_empty() || epoch > ctx.accounts.coverage.last_epoch,
            ChallengeError::CoverageEpochOrder
        );
        require!(
            ctx.accounts.supplemental_segment.epoch == epoch,
            ChallengeError::SupplementalEpochMismatch
        );
        let trade_count = ctx.accounts.supplemental_segment.trade_count;
        let cov = &mut ctx.accounts.coverage;
        let prefix = cov.running_prefix;
        cov.entries.push(CoverageEntry { epoch, prefix, trade_count, base_offset: 0 });
        cov.running_prefix =
            cov.running_prefix.checked_add(trade_count as u64).ok_or(ChallengeError::MathOverflow)?;
        cov.covered_trade_count = cov.running_prefix;
        cov.last_epoch = epoch;
        Ok(())
    }

    pub fn propose_settlement(
        ctx: Context<ProposeSettlement>,
        args: ProposeSettlementArgs,
    ) -> Result<()> {
        let challenge = &mut ctx.accounts.challenge;
        require!(challenge.status == ChallengeStatus::Active, ChallengeError::NotActive);
        require!(
            challenge.settlement_status == SettlementStatus::Unsettled,
            ChallengeError::SettlementAlreadyProposed
        );
        require!(args.transcript_len >= 1, ChallengeError::EmptyTranscript);

        // SETTLEMENT-WITHDRAWAL-GAP-1: a FUNDED account can take withdrawal cycles (DEC-61/62) before
        // ever reaching a final settlement here — without this, `propose_settlement` was structurally
        // blind to them: its genesis was always `genesis_state(rules)`, so replaying the full lifetime
        // after a withdrawal re-counted every already-paid dollar, permanently faultable via
        // `prove_result_fault`. This mirrors, read-only, the same withdrawal-history check
        // `propose_funded_withdrawal` already performs when opening its OWN next cycle.
        let last_covered_epoch: u64 = if let Some(counter) = ctx.accounts.withdrawal_counter.as_ref() {
            // Block settling while the current cycle slot is still Provisional (its fraud window
            // hasn't closed, so we don't yet know whether its claimed genesis/amount was honest) —
            // mirrors, in reverse, the existing guard that blocks a withdrawal mid-settlement. A
            // Faulted slot does NOT block: a proven-fraudulent withdrawal attempt didn't happen, so
            // settlement proceeds rebaselined from the last FINAL cycle exactly as if that slot were
            // empty.
            if let Some(open) = ctx.accounts.open_withdrawal.as_ref() {
                require!(open.challenge == challenge.key(), ChallengeError::Unauthorized);
                require!(open.cycle == counter.cycle, ChallengeError::WithdrawalCycleMismatch);
                require!(
                    open.status != SettlementStatus::Provisional,
                    ChallengeError::SettlementBlockedByOpenWithdrawal
                );
            }
            if counter.cycle > 0 {
                let prev = ctx
                    .accounts
                    .last_final_withdrawal
                    .as_ref()
                    .ok_or(ChallengeError::WithdrawalPrevMissing)?;
                require!(prev.challenge == challenge.key(), ChallengeError::Unauthorized);
                require!(prev.cycle == counter.cycle - 1, ChallengeError::WithdrawalCycleMismatch);
                require!(prev.status == SettlementStatus::Final, ChallengeError::WithdrawalPrevNotFinal);
                prev.covered_last_epoch
            } else {
                0
            }
        } else {
            0
        };
        // The settlement's coverage must begin strictly after the last withdrawn epoch — otherwise a
        // trade already paid out via a withdrawal cycle could be re-included here, double-counting it
        // in `covered_trade_count` even though its P&L is separately (and correctly) excluded from the
        // off-chain claim. Mirrors `propose_funded_withdrawal`'s own cross-cycle overlap guard.
        if last_covered_epoch > 0 {
            if let Some(first) = ctx.accounts.coverage.entries.first() {
                require!(first.epoch > last_covered_epoch, ChallengeError::WithdrawalEpochOverlap);
            }
        }

        // H-2 §3b count binding: every transcript step must map to exactly one real committed trade,
        // so `transcript_len - 1` (the number of steps) must equal the coverage's total trade count.
        // Combined with positional provenance (enforced by `prove_input_fault`), this leaves the
        // operator no room to fabricate a trade at a non-existent slot. Finalises (locks) the coverage.
        require!(
            ctx.accounts.coverage.covered_trade_count == (args.transcript_len as u64) - 1,
            ChallengeError::CoverageCountMismatch
        );
        ctx.accounts.coverage.finalized = true;
        // A pass that owes a payout is only valid on a FUNDED challenge (mirrors settle_challenge).
        require!(
            !args.claimed_passed
                || challenge.phase == ChallengePhase::Funded
                || (args.payout_sol_owed == 0 && args.payout_firma_owed == 0),
            ChallengeError::PayoutBeforeFunded
        );

        let now = Clock::get()?.unix_timestamp;
        challenge.settlement_status = SettlementStatus::Provisional;
        challenge.transcript_root = args.transcript_root;
        challenge.step_root = args.step_root;
        challenge.bound_step_root = args.bound_step_root;
        challenge.final_state_hash = args.final_state_hash;
        challenge.transcript_len = args.transcript_len;
        challenge.claimed_passed = args.claimed_passed;
        challenge.claimed_virtual_profit = args.virtual_profit;
        challenge.payout_sol_owed = if args.claimed_passed { args.payout_sol_owed } else { 0 };
        challenge.payout_firma_owed = if args.claimed_passed { args.payout_firma_owed } else { 0 };
        challenge.settlement_risk_tier = args.settlement_risk_tier;
        challenge.settlement_window_end = now
            .checked_add(SETTLEMENT_CHALLENGE_WINDOW)
            .ok_or(ChallengeError::MathOverflow)?;

        emit!(SettlementProposed {
            challenge: challenge.key(),
            transcript_root: args.transcript_root,
            transcript_len: args.transcript_len,
            claimed_passed: args.claimed_passed,
            virtual_profit: args.virtual_profit,
            window_end: challenge.settlement_window_end,
        });
        Ok(())
    }

    /// Disprove a proposed settlement by exhibiting ONE mis-computed step. The challenger reveals
    /// the pre-state at index `i` (with a Merkle proof it is the committed leaf), the operator's
    /// committed post-state hash (with its proof), and the step `i`. The program recomputes the
    /// single honest transition `apply_step(state_i, step_i, rules)` and, if its hash differs from
    /// the committed post-state, the settlement is FAULTED: the claimed result is voided and a
    /// slash event is emitted for the `dispute`/`firm` programs to enforce against the operator
    /// stake. Permissionless — anyone running the public engine can call it.
    #[allow(clippy::too_many_arguments)]
    pub fn prove_settlement_fault(
        ctx: Context<ProveSettlementFault>,
        index: u32,
        prev_state: settlement::EngineState,
        prev_proof: Vec<settlement::ProofStep>,
        claimed_next_state_hash: String,
        next_proof: Vec<settlement::ProofStep>,
        step: settlement::StepInput,
        step_proof: Vec<settlement::ProofStep>,
    ) -> Result<()> {
        let challenger = ctx.accounts.challenger.key();
        let challenge = &mut ctx.accounts.challenge;
        require!(
            challenge.settlement_status == SettlementStatus::Provisional,
            ChallengeError::NotProvisional
        );
        let now = Clock::get()?.unix_timestamp;
        require!(now <= challenge.settlement_window_end, ChallengeError::SettlementWindowClosed);

        let rules = rule_params(&challenge.rules_snapshot);
        let root_hex = settlement::root_to_hex(&challenge.transcript_root);
        let step_root_hex = settlement::root_to_hex(&challenge.step_root);
        let fault = settlement::verify_transition_fault(
            &root_hex,
            &step_root_hex,
            index,
            &prev_state,
            &prev_proof,
            &claimed_next_state_hash,
            &next_proof,
            &step,
            &step_proof,
            &rules,
        );
        require!(fault, ChallengeError::FaultNotProven);

        fault_out(challenge, now, challenger);
        emit!(SettlementFaulted {
            challenge: challenge.key(),
            kind: FaultKind::Transition as u8,
            index,
            challenger,
        });
        Ok(())
    }

    /// Disprove a proposed settlement whose transcript is internally consistent but whose CLAIMED
    /// RESULT (passed / virtual_profit) does not match `derive_outcome(final_state)`. The challenger
    /// reveals the final state (proven to be the committed leaf at the last index); the program
    /// recomputes the deterministic outcome and faults the settlement on any mismatch. Permissionless.
    pub fn prove_result_fault(
        ctx: Context<ProveSettlementFault>,
        final_state: settlement::EngineState,
        final_proof: Vec<settlement::ProofStep>,
    ) -> Result<()> {
        let challenger = ctx.accounts.challenger.key();
        let challenge = &mut ctx.accounts.challenge;
        require!(
            challenge.settlement_status == SettlementStatus::Provisional,
            ChallengeError::NotProvisional
        );
        let now = Clock::get()?.unix_timestamp;
        require!(now <= challenge.settlement_window_end, ChallengeError::SettlementWindowClosed);

        // The revealed final state must match the committed final hash AND be the committed leaf.
        let fh = settlement::state_hash(&final_state);
        require!(
            fh == settlement::root_to_hex(&challenge.final_state_hash),
            ChallengeError::FaultNotProven
        );
        let root_hex = settlement::root_to_hex(&challenge.transcript_root);
        require!(
            settlement::recompute_root(&fh, &final_proof) == root_hex,
            ChallengeError::FaultNotProven
        );

        let rules = rule_params(&challenge.rules_snapshot);
        let honest = settlement::derive_outcome(&final_state, &rules);
        let claimed_profit = challenge.claimed_virtual_profit as i128;
        let mismatch =
            honest.passed != challenge.claimed_passed || honest.virtual_profit != claimed_profit;
        require!(mismatch, ChallengeError::FaultNotProven);

        fault_out(challenge, now, challenger);
        emit!(SettlementFaulted { challenge: challenge.key(), kind: FaultKind::Result as u8, index: 0, challenger });
        Ok(())
    }

    /// Disprove a proposed settlement whose committed GENESIS state (transcript leaf 0) is not the
    /// deterministic `genesis_state(rules)` — i.e. the operator claimed the evaluation started from a
    /// different equity than the locked `starting_balance` (inflating profit through the back door,
    /// which a transition/result fault can't catch because the rest of the chain is consistent with
    /// the lie). The challenger reveals the committed genesis (proven at index 0); the program
    /// recomputes the honest genesis from the locked rules and faults on any mismatch. Permissionless.
    pub fn prove_genesis_fault(
        ctx: Context<ProveSettlementFault>,
        claimed_genesis: settlement::EngineState,
        genesis_proof: Vec<settlement::ProofStep>,
        prev_final_state: Option<settlement::EngineState>,
    ) -> Result<()> {
        let challenger = ctx.accounts.challenger.key();
        let challenge = &mut ctx.accounts.challenge;
        require!(
            challenge.settlement_status == SettlementStatus::Provisional,
            ChallengeError::NotProvisional
        );
        let now = Clock::get()?.unix_timestamp;
        require!(now <= challenge.settlement_window_end, ChallengeError::SettlementWindowClosed);

        // The revealed genesis must be the committed leaf at index 0.
        let gh = settlement::state_hash(&claimed_genesis);
        let root_hex = settlement::root_to_hex(&challenge.transcript_root);
        require!(
            settlement::recompute_root(&gh, &genesis_proof) == root_hex,
            ChallengeError::FaultNotProven
        );

        let rules = rule_params(&challenge.rules_snapshot);
        // SETTLEMENT-WITHDRAWAL-GAP-1: the honest genesis depends on whether a Final withdrawal cycle
        // precedes this settlement — mirrors `propose_funded_withdrawal`'s own cycle-0-vs-cycle-N
        // branch exactly. `propose_settlement` never validates this synchronously (consistent with the
        // no-withdrawal case, which was ALWAYS only checked here); this is where either lie is caught.
        let honest_genesis = if let Some(counter) = ctx.accounts.withdrawal_counter.as_ref() {
            if counter.cycle > 0 {
                let prev = ctx
                    .accounts
                    .last_final_withdrawal
                    .as_ref()
                    .ok_or(ChallengeError::WithdrawalPrevMissing)?;
                require!(prev.challenge == challenge.key(), ChallengeError::Unauthorized);
                require!(prev.cycle == counter.cycle - 1, ChallengeError::WithdrawalCycleMismatch);
                let revealed = prev_final_state.ok_or(ChallengeError::WithdrawalPrevMissing)?;
                require!(
                    settlement::state_hash(&revealed)
                        == settlement::root_to_hex(&prev.final_state_hash),
                    ChallengeError::WithdrawalPrevStateMismatch
                );
                settlement::rebaseline_after_withdrawal(&revealed, prev.gross_micro as i128)
            } else {
                settlement::genesis_state(&rules)
            }
        } else {
            settlement::genesis_state(&rules)
        };
        // Fault iff the committed genesis differs from the honest one just derived.
        require!(claimed_genesis != honest_genesis, ChallengeError::FaultNotProven);

        fault_out(challenge, now, challenger);
        emit!(SettlementFaulted { challenge: challenge.key(), kind: FaultKind::Genesis as u8, index: 0, challenger });
        Ok(())
    }

    /// ─────────────────── H-2: input-authenticity fault (settlement ↔ batch binding) ───────────────────
    /// Disprove a proposed settlement whose committed transcript consumed a **fabricated trade** — a step
    /// welded (via `bound_step_leaf`) to a batch slot `(epoch, leaf_index)` whose REAL committed tick
    /// differs from the operator's step. The challenger reveals the step + its claimed provenance + its
    /// membership in `step_root`, and the real batch leaf at that slot + its membership in the committed
    /// `batch_root` (loaded cross-program — its typed account load proves the root exists and, post-H-1,
    /// was written by the authorised committer). A POSITIVE mismatch faults the settlement; an honest,
    /// correctly-sourced transcript can never be faulted. Permissionless. Two paths against the same real
    /// `batch_root`: an out-of-range provenance (`batch_leaf_index >= trade_count`) is faulted directly
    /// (the slot is past the end of the real batch); an in-range provenance is faulted on a tick mismatch.
    /// Together these close the trade-SWAP AND out-of-range classes for REAL epochs; the remaining
    /// non-existent-epoch case is closed by the propose-time coverage/count binding (§3b of
    /// VERIFIABLE_SETTLEMENT_BATCH_BINDING.md).
    #[allow(clippy::too_many_arguments)]
    pub fn prove_input_fault(
        ctx: Context<ProveInputFault>,
        index: u32,
        batch_epoch: u64,
        batch_leaf_index: u32,
        step: settlement::StepInput,
        step_membership_proof: Vec<settlement::ProofStep>,
        actual_batch_leaf: String,
        batch_membership_proof: Vec<settlement::ProofStep>,
    ) -> Result<()> {
        let challenger = ctx.accounts.challenger.key();
        let batch_root_hex = settlement::root_to_hex(&ctx.accounts.batch_root.merkle_root);
        let challenge = &mut ctx.accounts.challenge;
        require!(
            challenge.settlement_status == SettlementStatus::Provisional,
            ChallengeError::NotProvisional
        );
        let now = Clock::get()?.unix_timestamp;
        require!(now <= challenge.settlement_window_end, ChallengeError::SettlementWindowClosed);

        // H-2 §3b: the operator's committed provenance for step `index` must be the POSITIONAL slot the
        // bound coverage assigns it; `batch_epoch`/`batch_leaf_index` (and thus the passed `batch_root`)
        // must equal that slot. A NON-positional provenance is faulted by `prove_provenance_fault`; here
        // we adjudicate a positionally-correct step against the REAL committed tick at its slot.
        let cov: Vec<settlement::CovEntry> = ctx
            .accounts
            .coverage
            .entries
            .iter()
            .map(|e| settlement::CovEntry { epoch: e.epoch, prefix: e.prefix, trade_count: e.trade_count, base_offset: e.base_offset })
            .collect();
        let pos = settlement::positional_slot(&cov, index).ok_or(ChallengeError::FaultNotProven)?;
        require!((batch_epoch, batch_leaf_index) == pos, ChallengeError::FaultNotProven);

        let step_root_hex = settlement::root_to_hex(&challenge.bound_step_root); // Option A: bound leaves
        let fault = settlement::verify_input_fault(
            &step_root_hex, index, batch_epoch, batch_leaf_index, &step, &step_membership_proof,
            &batch_root_hex, &actual_batch_leaf, &batch_membership_proof,
        );
        require!(fault, ChallengeError::FaultNotProven);

        fault_out(challenge, now, challenger);
        emit!(SettlementFaulted { challenge: challenge.key(), kind: FaultKind::Input as u8, index, challenger });
        Ok(())
    }

    /// PROVENANCE fault (H-2 §3b) — disprove a settlement whose committed step `index` is welded to a
    /// provenance OTHER than the positional slot the bound coverage assigns it (including a NON-EXISTENT
    /// epoch — the last fabrication escape). No `batch_root` is loaded (the committed epoch may not
    /// exist); soundness comes from the committed-leaf membership + the coverage-derived positional slot.
    /// Permissionless. This is the piece that makes the settlement fully trustless against fabrication.
    #[allow(clippy::too_many_arguments)]
    pub fn prove_provenance_fault(
        ctx: Context<ProveProvenanceFault>,
        index: u32,
        committed_epoch: u64,
        committed_leaf_index: u32,
        step: settlement::StepInput,
        step_membership_proof: Vec<settlement::ProofStep>,
    ) -> Result<()> {
        let challenger = ctx.accounts.challenger.key();
        let cov: Vec<settlement::CovEntry> = ctx
            .accounts
            .coverage
            .entries
            .iter()
            .map(|e| settlement::CovEntry { epoch: e.epoch, prefix: e.prefix, trade_count: e.trade_count, base_offset: e.base_offset })
            .collect();
        let challenge = &mut ctx.accounts.challenge;
        require!(
            challenge.settlement_status == SettlementStatus::Provisional,
            ChallengeError::NotProvisional
        );
        let now = Clock::get()?.unix_timestamp;
        require!(now <= challenge.settlement_window_end, ChallengeError::SettlementWindowClosed);

        let pos = settlement::positional_slot(&cov, index).ok_or(ChallengeError::FaultNotProven)?;
        let step_root_hex = settlement::root_to_hex(&challenge.bound_step_root); // Option A: bound leaves
        let fault = settlement::verify_provenance_fault(
            &step_root_hex, index, committed_epoch, committed_leaf_index, &step, &step_membership_proof, pos,
        );
        require!(fault, ChallengeError::FaultNotProven);

        fault_out(challenge, now, challenger);
        emit!(SettlementFaulted { challenge: challenge.key(), kind: FaultKind::Provenance as u8, index, challenger });
        Ok(())
    }

    /// Finalize a Provisional settlement after the fraud-proof window closes with no fault proven.
    /// Applies the committed result: sets `Passed`/`Failed`, locks the owed amounts, opens the 24h
    /// trader dispute window, and marks the settlement `Final` — the gate every payout mover checks.
    /// Permissionless (a keeper crank); the guards make it safe to call on any ready challenge.
    pub fn finalize_settlement(ctx: Context<FinalizeSettlement>) -> Result<()> {
        let challenge = &mut ctx.accounts.challenge;
        require!(
            challenge.settlement_status == SettlementStatus::Provisional,
            ChallengeError::NotProvisional
        );
        let now = Clock::get()?.unix_timestamp;
        require!(now > challenge.settlement_window_end, ChallengeError::SettlementWindowOpen);

        let passed = challenge.claimed_passed;
        challenge.status = if passed { ChallengeStatus::Passed } else { ChallengeStatus::Failed };
        challenge.virtual_profit = challenge.claimed_virtual_profit;
        challenge.payout_sol_owed = if passed { challenge.payout_sol_owed } else { 0 };
        challenge.payout_firma_owed = if passed { challenge.payout_firma_owed } else { 0 };
        challenge.settled_at = now;
        challenge.dispute_deadline = now.checked_add(DISPUTE_WINDOW).ok_or(ChallengeError::MathOverflow)?;
        challenge.settlement_status = SettlementStatus::Final;

        emit!(ChallengeSettled {
            challenge: challenge.key(),
            passed,
            virtual_profit: challenge.virtual_profit,
            payout_firma_owed: challenge.payout_firma_owed,
            settled_at: now,
        });
        Ok(())
    }

    /// ───────────────── DEC-62: funded withdrawals (rebaselined per-cycle transcripts) ─────────────────
    ///
    /// A FUNDED trader withdraws profit WHILE STILL TRADING — the account never concludes, so the
    /// settlement path above (which sets a terminal `Passed`/`Failed`) can't express it. That is
    /// PAYOUT-CHAIN-GAP-1: `enqueue_payout` demands `status == Passed`, a funded account never becomes
    /// Passed, so no funded trader could be paid by ANY route. These instructions are the fuel line.
    ///
    /// The account's life is cut into CYCLES by its withdrawals. Cycle N's transcript covers only the
    /// trades since withdrawal N-1, and its genesis is cycle N-1's final state with the withdrawal
    /// debited (`rebaseline_after_withdrawal`). The transcript stays PURE TRADES, so the H-2 coverage
    /// binding and every existing fault verifier apply unchanged.
    ///
    /// Create the per-challenge cycle counter. Seeds `["wcount", challenge]`. Once per funded challenge;
    /// deliberately a separate PDA rather than a `ChallengeState` field, because `ChallengeState` is
    /// `InitSpace` with no padding and growing it would break deserialization of every live challenge.
    pub fn init_withdrawal_counter(ctx: Context<InitWithdrawalCounter>) -> Result<()> {
        let challenge = &ctx.accounts.challenge;
        require!(challenge.phase == ChallengePhase::Funded, ChallengeError::WithdrawalNotFunded);
        let c = &mut ctx.accounts.counter;
        c.challenge = challenge.key();
        c.cycle = 0;
        c.cumulative_withdrawn_micro = 0;
        c.bump = ctx.bumps.counter;
        Ok(())
    }

    /// Begin withdrawal cycle `cycle`'s coverage — the ordered set of real batch epochs ITS transcript
    /// draws from (H-2 §3b). Per-cycle seeds `["wcoverage", challenge, cycle]`, because the settlement
    /// coverage at `["coverage", challenge]` is one-per-challenge and is consumed+locked by
    /// `propose_settlement`. Same `SettlementCoverage` type and the same count binding.
    pub fn init_withdrawal_coverage(ctx: Context<InitWithdrawalCoverage>, cycle: u32) -> Result<()> {
        require!(ctx.accounts.counter.cycle == cycle, ChallengeError::WithdrawalCycleMismatch);
        let cov = &mut ctx.accounts.coverage;
        cov.challenge = ctx.accounts.challenge.key();
        cov.covered_trade_count = 0;
        cov.running_prefix = 0;
        cov.last_epoch = 0;
        cov.finalized = false;
        cov.entries = Vec::new();
        cov.bump = ctx.bumps.coverage;
        Ok(())
    }

    /// Append one REAL batch epoch to a withdrawal cycle's coverage. Identical contract to
    /// `add_coverage_epoch`, including the BATCH-ROOT-SCOPE-1 segment proof: the typed `batch_root`
    /// proves the epoch exists and is authentic, the segment proof binds THIS challenge's run within the
    /// firm-hour root, epochs go in strictly increasing order, and the running prefix maps step indices
    /// to real trades. Keep the two in lockstep — a guard that exists on the settlement path and not
    /// here is a hole only funded traders fall through (PAYOUT-DELIVER-GATE-1 was exactly that).
    pub fn add_withdrawal_coverage_epoch(
        ctx: Context<AddWithdrawalCoverageEpoch>,
        cycle: u32,
        epoch: u64,
        base_offset: u32,
        trade_count: u32,
        segment_proof: Vec<settlement::ProofStep>,
    ) -> Result<()> {
        let _ = cycle; // seed-only (bound by the PDA derivation below)
        require!(!ctx.accounts.coverage.finalized, ChallengeError::CoverageFinalized);
        require!(
            ctx.accounts.coverage.entries.len() < MAX_COVERAGE_EPOCHS,
            ChallengeError::CoverageFull
        );
        require!(
            ctx.accounts.coverage.entries.is_empty() || epoch > ctx.accounts.coverage.last_epoch,
            ChallengeError::CoverageEpochOrder
        );
        require!(
            settlement::verify_segment(
                &settlement::root_to_hex(&ctx.accounts.batch_root.segment_root),
                &ctx.accounts.challenge.key(),
                base_offset,
                trade_count,
                &segment_proof,
            ),
            ChallengeError::CoverageSegmentInvalid
        );
        require!(
            base_offset
                .checked_add(trade_count)
                .ok_or(ChallengeError::MathOverflow)?
                <= ctx.accounts.batch_root.trade_count,
            ChallengeError::CoverageSegmentInvalid
        );
        let cov = &mut ctx.accounts.coverage;
        let prefix = cov.running_prefix;
        cov.entries.push(CoverageEntry { epoch, prefix, trade_count, base_offset });
        cov.running_prefix =
            cov.running_prefix.checked_add(trade_count as u64).ok_or(ChallengeError::MathOverflow)?;
        cov.covered_trade_count = cov.running_prefix;
        cov.last_epoch = epoch;
        Ok(())
    }

    /// EPOCH-RECOMPOSE-DRIFT-1 — commit a one-shot, per-(challenge, epoch) segment for a challenge that
    /// could not possibly have been in the epoch's PRIMARY `batch_root`, because it did not exist yet
    /// when that root was committed.
    ///
    /// ── The bug this recovers from ──
    ///
    /// A FUNDED challenge used to be minted lazily, only when a withdrawal was first requested
    /// (`ensureFundedChallengeOnchain` off-chain). Between an account going FUNDED and that first
    /// withdrawal, the account traded with no on-chain challenge at all, and the batch producer sealed
    /// every intervening firm-hour without it — `compose_epoch`'s inclusion test is `challengePubkey IS
    /// NOT NULL`, evaluated at commit time. `BatchRoot` is `init`-once, so those hours can never be
    /// re-sealed. The first withdrawal then had to prove its ENTIRE trade history and permanently failed.
    /// Off-chain provisioning is now proactive (before an account's first trade), so this cannot recur —
    /// this instruction exists to unstick the payouts it already broke, and as a bounded safety net for
    /// any future case shaped like it.
    ///
    /// ── Why this is safe to trust the committer on, with NO membership/non-membership proof ──
    ///
    /// The eligibility check below is not "we looked and didn't find a segment" (which would need a
    /// Merkle non-membership proof against `segment_root` — real cryptography, real complexity, real risk
    /// of getting the sorted-tree edge cases wrong). It is stronger: **this challenge account did not
    /// exist on-chain until AFTER `batch_root.committed_at`.** `ChallengeState.started_at` is set once, at
    /// `init_challenge_state`, and never touched again. If it postdates the root's commit, this challenge
    /// is PROVABLY ABSENT from every leaf and every segment in that root — not "probably", not "as far as
    /// we checked" — it could not have existed to be composed. No non-membership proof is stronger than
    /// impossibility of prior existence.
    ///
    /// ── What this deliberately does NOT protect, and why that is an accepted, narrow, disclosed gap ──
    ///
    /// `trade_count` here is asserted by the same settlement authority that will later use it — unlike the
    /// primary path, where the batch producer commits blind to which challenge will eventually need proof,
    /// so a keeper cannot retroactively inflate a REAL historical count. A supplemental segment loses that
    /// separation: nothing on-chain independently re-derives this challenge's real trade count for this
    /// hour. `prove_withdrawal_provenance_fault` (per-step firm-tree membership) is consequently NOT a
    /// meaningful check for a step whose positional slot came from a supplemental segment — there is no
    /// firm tree it could ever be a real member of — so `add_withdrawal_coverage_epoch_supplemental`
    /// assigns `base_offset = 0` inside an isolated, single-challenge slot space, and the off-chain keeper
    /// is expected to never submit a `prove_withdrawal_provenance_fault` for one of these positions (it
    /// would neither prove nor disprove anything real). The remaining fault-proof family —
    /// `prove_withdrawal_genesis_fault` / `prove_withdrawal_amount_fault` / `prove_withdrawal_transition_fault`
    /// / `prove_withdrawal_input_fault` (the hash-chain replay from genesis to `final_state_hash`) — is
    /// completely unaffected and still catches an inflated `trade_count` INDIRECTLY: padding fake profit
    /// into a supplemental epoch changes the replayed equity trajectory, which those proofs already check
    /// against the committed final state. This is the same trust boundary every other keeper-asserted
    /// number in this program already carries (`grossMicro`, `claimed_passed`, etc.) — not a new one.
    pub fn commit_supplemental_segment(
        ctx: Context<CommitSupplementalSegment>,
        epoch: u64,
        trade_count: u32,
    ) -> Result<()> {
        require!(trade_count > 0, ChallengeError::EmptySupplementalSegment);
        require!(
            ctx.accounts.challenge.started_at > ctx.accounts.batch_root.committed_at,
            ChallengeError::SupplementalNotEligible
        );
        let now = Clock::get()?.unix_timestamp;
        let seg = &mut ctx.accounts.supplemental_segment;
        seg.firm = ctx.accounts.challenge.firm;
        seg.challenge = ctx.accounts.challenge.key();
        seg.epoch = epoch;
        seg.trade_count = trade_count;
        seg.committed_at = now;
        seg.bump = ctx.bumps.supplemental_segment;
        emit!(SupplementalSegmentCommitted {
            challenge: ctx.accounts.challenge.key(),
            firm: ctx.accounts.challenge.firm,
            epoch,
            trade_count,
            committed_at: now,
        });
        Ok(())
    }

    /// The withdrawal-coverage counterpart of `commit_supplemental_segment`: append its trade count to
    /// `coverage.entries` with the SAME bookkeeping `add_withdrawal_coverage_epoch` does for a primary
    /// segment, so `propose_funded_withdrawal`'s `covered_trade_count == transcript_len - 1` check cannot
    /// tell the difference between the two sources. `base_offset` is always 0 — see the doc comment above
    /// on why that is deliberate, not a placeholder.
    pub fn add_withdrawal_coverage_epoch_supplemental(
        ctx: Context<AddWithdrawalCoverageEpochSupplemental>,
        cycle: u32,
        epoch: u64,
    ) -> Result<()> {
        let _ = cycle; // seed-only (bound by the PDA derivation below)
        require!(!ctx.accounts.coverage.finalized, ChallengeError::CoverageFinalized);
        require!(
            ctx.accounts.coverage.entries.len() < MAX_COVERAGE_EPOCHS,
            ChallengeError::CoverageFull
        );
        require!(
            ctx.accounts.coverage.entries.is_empty() || epoch > ctx.accounts.coverage.last_epoch,
            ChallengeError::CoverageEpochOrder
        );
        require!(
            ctx.accounts.supplemental_segment.epoch == epoch,
            ChallengeError::SupplementalEpochMismatch
        );
        let trade_count = ctx.accounts.supplemental_segment.trade_count;
        let cov = &mut ctx.accounts.coverage;
        let prefix = cov.running_prefix;
        cov.entries.push(CoverageEntry { epoch, prefix, trade_count, base_offset: 0 });
        cov.running_prefix =
            cov.running_prefix.checked_add(trade_count as u64).ok_or(ChallengeError::MathOverflow)?;
        cov.covered_trade_count = cov.running_prefix;
        cov.last_epoch = epoch;
        Ok(())
    }

    /// Propose withdrawal `cycle` — the trader keeps trading throughout (`status` stays `Active`; this
    /// is the whole point of DEC-61 option B). Opens a **tier-scaled fraud window**
    /// (`withdrawal_window_for_tier` — Healthy/Caution 20min, Warning 24h, Critical 72h), NOT the 24h
    /// `DISPUTE_WINDOW` (that is the trader-dispute constant): a withdrawal is the same threat model as a
    /// settlement on the instruction that actually moves SOL. A healthy firm pays from its own solvent
    /// treasury (self-insuring), so the long window is kept where systemic risk lives; the 20-min floor is
    /// paired with a faster integrity sweep so a sweep still sees every payout (see the fn's doc).
    ///
    /// Two things are bound HERE rather than left to a fault proof, because they can be derived
    /// deterministically and a lie is then impossible instead of merely refutable-within-72h:
    ///
    /// 1. **The genesis.** Cycle 0's honest genesis is `genesis_state(rules)`. Cycle N's is
    ///    `rebaseline_after_withdrawal(prev_final, prev.gross)` — and the program DERIVES it: the keeper
    ///    reveals `prev_final_state`, which must hash to the value committed on `FundedWithdrawal[N-1]`
    ///    (on-chain truth), so the keeper cannot rebaseline to an equity of its choosing.
    /// 2. **The amount.** `gross_micro <= withdrawable_profit(final_state, rules)` and
    ///    `trader_micro <= gross × trader_split_bps`, with `final_state` bound by hash to the committed
    ///    `final_state_hash`. THIS is what makes re-withdrawing an already-paid profit impossible:
    ///    withdraw everything and the next cycle's genesis IS `starting_balance`, so with no new trades
    ///    `withdrawable_profit == 0` and any claim is rejected outright.
    ///
    /// What the 72h window is still for: the committed roots are only assertions that the transcript
    /// FOLLOWS FROM REAL TRADES. `prove_withdrawal_*_fault` (this cycle's chain, its genesis leaf, its
    /// final leaf) refute that, exactly as the settlement fault family does.
    pub fn propose_funded_withdrawal(
        ctx: Context<ProposeFundedWithdrawal>,
        cycle: u32,
        args: ProposeWithdrawalArgs,
        final_state: settlement::EngineState,
        prev_final_state: settlement::EngineState,
    ) -> Result<()> {
        let challenge = &ctx.accounts.challenge;
        // A withdrawal is only meaningful on a live funded account.
        require!(challenge.phase == ChallengePhase::Funded, ChallengeError::WithdrawalNotFunded);
        require!(challenge.status == ChallengeStatus::Active, ChallengeError::NotActive);
        // An account whose settlement is mid-flight must not also be withdrawing — the two would race
        // over the same profit.
        require!(
            challenge.settlement_status == SettlementStatus::Unsettled,
            ChallengeError::SettlementAlreadyProposed
        );
        require!(ctx.accounts.counter.cycle == cycle, ChallengeError::WithdrawalCycleMismatch);
        require!(args.transcript_len >= 1, ChallengeError::EmptyTranscript);

        // H-2 §3b count binding, unchanged from `propose_settlement`: every transcript step must map to
        // exactly one real committed trade. A cycle transcript is pure trades, so this still holds.
        require!(
            ctx.accounts.coverage.covered_trade_count == (args.transcript_len as u64) - 1,
            ChallengeError::CoverageCountMismatch
        );
        ctx.accounts.coverage.finalized = true;

        let rules = rule_params(&challenge.rules_snapshot);

        // ── 0. The cycles must PARTITION the trade timeline. ──
        // Cycle N's coverage must begin strictly after cycle N-1's ended. Without this the rebaseline is
        // pointless: cycle N+1 opens at an honest genesis and simply RE-FEEDS cycle N's already-paid
        // trades — real ticks, real positional slots, so every fault proof is silent — and the trader is
        // paid for the same profit twice. `prev_last_epoch` is the watermark; an empty cycle carries it
        // forward so it can't be laundered backwards.
        let prev_last_epoch = match ctx.accounts.prev_withdrawal.as_ref() {
            Some(p) => p.covered_last_epoch,
            None => 0,
        };
        if cycle > 0 {
            if let Some(first) = ctx.accounts.coverage.entries.first() {
                require!(first.epoch > prev_last_epoch, ChallengeError::WithdrawalEpochOverlap);
            }
        }

        // ── 1. Derive the honest genesis; the keeper only gets to AGREE with it. ──
        let honest_genesis = if cycle == 0 {
            settlement::genesis_state(&rules)
        } else {
            let prev = ctx
                .accounts
                .prev_withdrawal
                .as_ref()
                .ok_or(ChallengeError::WithdrawalPrevMissing)?;
            // Bind the predecessor: it must be THIS challenge's withdrawal for EXACTLY cycle - 1.
            // Without both checks a keeper could pass an older (or another challenge's) withdrawal and
            // rebaseline from a stale, richer equity.
            require!(prev.challenge == challenge.key(), ChallengeError::Unauthorized);
            require!(
                prev.cycle == cycle.checked_sub(1).ok_or(ChallengeError::MathOverflow)?,
                ChallengeError::WithdrawalCycleMismatch
            );
            // Only a Final predecessor can be rebaselined from — a Provisional one may yet be Faulted,
            // and a Faulted one never happened.
            require!(prev.status == SettlementStatus::Final, ChallengeError::WithdrawalPrevNotFinal);
            // The revealed predecessor must be the state committed for cycle N-1.
            require!(
                settlement::state_hash(&prev_final_state)
                    == settlement::root_to_hex(&prev.final_state_hash),
                ChallengeError::WithdrawalPrevStateMismatch
            );
            settlement::rebaseline_after_withdrawal(&prev_final_state, prev.gross_micro as i128)
        };
        require!(
            settlement::state_hash(&honest_genesis)
                == settlement::root_to_hex(&args.genesis_state_hash),
            ChallengeError::WithdrawalGenesisMismatch
        );

        // ── 2. Bind the amount to the committed final state. ──
        require!(
            settlement::state_hash(&final_state) == settlement::root_to_hex(&args.final_state_hash),
            ChallengeError::WithdrawalFinalStateMismatch
        );
        // A breached account owes nothing — and `rebaseline_after_withdrawal` carries `breach` forward
        // stickily, so a breach can never be washed by withdrawing.
        require!(final_state.breach == 0, ChallengeError::WithdrawalBreached);
        let owed = settlement::withdrawable_profit(&final_state, &rules);
        require!(args.gross_micro > 0, ChallengeError::ZeroAmount);
        require!((args.gross_micro as i128) <= owed, ChallengeError::WithdrawalOverclaim);
        require!(
            (args.trader_micro as i128)
                <= settlement::trader_entitlement(
                    args.gross_micro as i128,
                    challenge.rules_snapshot.trader_split_bps as i128,
                ),
            ChallengeError::WithdrawalOverclaim
        );
        require!(args.amount_sol_owed > 0, ChallengeError::ZeroAmount);

        let now = Clock::get()?.unix_timestamp;
        let bump = ctx.bumps.withdrawal;
        let challenge_key = challenge.key();
        let w = &mut ctx.accounts.withdrawal;
        w.challenge = challenge_key;
        w.cycle = cycle;
        w.gross_micro = args.gross_micro;
        w.trader_micro = args.trader_micro;
        w.amount_sol_owed = args.amount_sol_owed;
        w.transcript_root = args.transcript_root;
        w.step_root = args.step_root;
        w.bound_step_root = args.bound_step_root;
        w.genesis_state_hash = args.genesis_state_hash;
        w.final_state_hash = args.final_state_hash;
        w.transcript_len = args.transcript_len;
        // Advance the partition watermark; an empty cycle carries the predecessor's forward.
        w.covered_last_epoch = if ctx.accounts.coverage.entries.is_empty() {
            prev_last_epoch
        } else {
            ctx.accounts.coverage.last_epoch
        };
        w.settlement_risk_tier = args.settlement_risk_tier;
        w.proposed_at = now;
        // Tier-scaled at propose from the grandfathered `settlement_risk_tier` set just above: healthy
        // firms pay fast (20-min floor, paired with a faster integrity sweep), the long window stays
        // where systemic risk lives. Critical still resolves to `SETTLEMENT_CHALLENGE_WINDOW`.
        w.window_end = now
            .checked_add(withdrawal_window_for_tier(w.settlement_risk_tier))
            .ok_or(ChallengeError::MathOverflow)?;
        w.status = SettlementStatus::Provisional;
        w.fault_challenger = Pubkey::default();
        w.bump = bump;

        emit!(FundedWithdrawalProposed {
            challenge: challenge_key,
            trader: ctx.accounts.challenge.trader,
            cycle,
            gross_micro: args.gross_micro,
            amount_sol_owed: args.amount_sol_owed,
            window_end: w.window_end,
        });
        Ok(())
    }

    /// Finalize withdrawal `cycle` after its (tier-scaled) fraud window closes with no fault proven, and advance
    /// the counter so the next withdrawal gets fresh PDAs. Permissionless crank, mirroring
    /// `finalize_settlement`.
    ///
    /// The counter advances HERE, not at delivery. A delivery-advanced counter would wedge the account
    /// forever if a payout can never be fully filled (thin curve, drained treasury): the counter would
    /// never move and the trader could never withdraw again. Advancing at finalize keeps every window
    /// sequential and genuinely live (cycle N+1 cannot be proposed until N's window has closed) while
    /// leaving a stuck delivery recoverable.
    pub fn finalize_funded_withdrawal(
        ctx: Context<FinalizeFundedWithdrawal>,
        cycle: u32,
    ) -> Result<()> {
        let now = Clock::get()?.unix_timestamp;
        {
            let w = &ctx.accounts.withdrawal;
            require!(w.status == SettlementStatus::Provisional, ChallengeError::NotProvisional);
            require!(now > w.window_end, ChallengeError::SettlementWindowOpen);
        }
        let w = &mut ctx.accounts.withdrawal;
        w.status = SettlementStatus::Final;

        let counter = &mut ctx.accounts.counter;
        counter.cycle = cycle.checked_add(1).ok_or(ChallengeError::MathOverflow)?;
        counter.cumulative_withdrawn_micro = counter
            .cumulative_withdrawn_micro
            .checked_add(ctx.accounts.withdrawal.gross_micro.max(0) as u64)
            .ok_or(ChallengeError::MathOverflow)?;

        emit!(FundedWithdrawalFinalized {
            challenge: ctx.accounts.withdrawal.challenge,
            cycle,
            amount_sol_owed: ctx.accounts.withdrawal.amount_sol_owed,
            next_cycle: counter.cycle,
        });
        Ok(())
    }

    /// Disprove a withdrawal whose committed transcript starts somewhere other than the genesis the
    /// chain bound at propose — i.e. the state chain does not actually begin at the rebaselined equity.
    /// `propose_funded_withdrawal` already forces `genesis_state_hash` to equal the honest rebaseline,
    /// so the only lie left is a `transcript_root` whose leaf 0 differs from that commitment. The
    /// challenger reveals the real leaf 0 with its membership proof; a mismatch faults. Permissionless.
    pub fn prove_withdrawal_genesis_fault(
        ctx: Context<ProveWithdrawalFault>,
        cycle: u32,
        claimed_genesis: settlement::EngineState,
        genesis_proof: Vec<settlement::ProofStep>,
    ) -> Result<()> {
        let _ = cycle; // seed-only
        let challenger = ctx.accounts.challenger.key();
        let now = Clock::get()?.unix_timestamp;
        let w = &mut ctx.accounts.withdrawal;
        require!(w.status == SettlementStatus::Provisional, ChallengeError::NotProvisional);
        require!(now <= w.window_end, ChallengeError::SettlementWindowClosed);

        // The revealed leaf 0 must be committed in the transcript, and must differ from the genesis the
        // chain bound at propose. A POSITIVE proof — an honest transcript can never satisfy it.
        let gh = settlement::state_hash(&claimed_genesis);
        require!(
            settlement::recompute_root(&gh, &genesis_proof)
                == settlement::root_to_hex(&w.transcript_root),
            ChallengeError::FaultNotProven
        );
        require!(gh != settlement::root_to_hex(&w.genesis_state_hash), ChallengeError::FaultNotProven);

        withdrawal_fault_out(w, now, challenger);
        emit!(FundedWithdrawalFaulted {
            challenge: w.challenge,
            cycle: w.cycle,
            kind: FaultKind::Genesis as u8,
            index: 0,
            challenger,
        });
        Ok(())
    }

    /// Disprove a withdrawal that claims more than the account has left to be paid — the anti-drain
    /// proof. `propose_funded_withdrawal` binds `gross_micro <= withdrawable_profit(final_state)` with
    /// `final_state` hash-bound to the committed `final_state_hash`, so the remaining lie is a
    /// `final_state_hash` that ISN'T the transcript's last leaf (a fabricated final equity, consistent
    /// with its own hash but not with the committed chain). The challenger reveals the real last leaf
    /// with its membership proof and faults on either an overclaim against it or a mismatch against the
    /// commitment. Permissionless.
    pub fn prove_withdrawal_amount_fault(
        ctx: Context<ProveWithdrawalFault>,
        cycle: u32,
        final_state: settlement::EngineState,
        final_proof: Vec<settlement::ProofStep>,
    ) -> Result<()> {
        let _ = cycle; // seed-only
        let challenger = ctx.accounts.challenger.key();
        let now = Clock::get()?.unix_timestamp;
        let rules = rule_params(&ctx.accounts.challenge.rules_snapshot);
        let split = ctx.accounts.challenge.rules_snapshot.trader_split_bps as i128;
        let w = &mut ctx.accounts.withdrawal;
        require!(w.status == SettlementStatus::Provisional, ChallengeError::NotProvisional);
        require!(now <= w.window_end, ChallengeError::SettlementWindowClosed);

        let fault = settlement::verify_withdrawal_amount_fault(
            &settlement::root_to_hex(&w.transcript_root),
            &final_state,
            &final_proof,
            w.gross_micro as i128,
            w.trader_micro as i128,
            split,
            &rules,
        );
        // Also a fault if the committed final-state hash isn't the state the transcript actually ends
        // on — that is the fabrication the propose-time amount check would otherwise have swallowed.
        let committed_mismatch = settlement::state_hash(&final_state)
            != settlement::root_to_hex(&w.final_state_hash)
            && settlement::recompute_root(
                &settlement::state_hash(&final_state),
                &final_proof,
            ) == settlement::root_to_hex(&w.transcript_root);
        require!(fault || committed_mismatch, ChallengeError::FaultNotProven);

        withdrawal_fault_out(w, now, challenger);
        emit!(FundedWithdrawalFaulted {
            challenge: w.challenge,
            cycle: w.cycle,
            kind: FaultKind::Result as u8,
            index: 0,
            challenger,
        });
        Ok(())
    }

    /// Transition fault against a WITHDRAWAL transcript — the same `verify_transition_fault` the
    /// settlement path uses, verified against `FundedWithdrawal.transcript_root`/`.step_root` instead of
    /// the challenge's. This is what binds the cycle's state chain to correct math over its committed
    /// steps; without it a keeper could fabricate the chain and inflate the final equity. Permissionless.
    #[allow(clippy::too_many_arguments)]
    pub fn prove_withdrawal_transition_fault(
        ctx: Context<ProveWithdrawalFault>,
        cycle: u32,
        index: u32,
        prev_state: settlement::EngineState,
        prev_proof: Vec<settlement::ProofStep>,
        claimed_next_state_hash: String,
        next_proof: Vec<settlement::ProofStep>,
        step: settlement::StepInput,
        step_proof: Vec<settlement::ProofStep>,
    ) -> Result<()> {
        let _ = cycle; // seed-only
        let challenger = ctx.accounts.challenger.key();
        let now = Clock::get()?.unix_timestamp;
        let rules = rule_params(&ctx.accounts.challenge.rules_snapshot);
        let w = &mut ctx.accounts.withdrawal;
        require!(w.status == SettlementStatus::Provisional, ChallengeError::NotProvisional);
        require!(now <= w.window_end, ChallengeError::SettlementWindowClosed);

        let fault = settlement::verify_transition_fault(
            &settlement::root_to_hex(&w.transcript_root),
            &settlement::root_to_hex(&w.step_root),
            index,
            &prev_state,
            &prev_proof,
            &claimed_next_state_hash,
            &next_proof,
            &step,
            &step_proof,
            &rules,
        );
        require!(fault, ChallengeError::FaultNotProven);

        withdrawal_fault_out(w, now, challenger);
        emit!(FundedWithdrawalFaulted {
            challenge: w.challenge,
            cycle: w.cycle,
            kind: FaultKind::Transition as u8,
            index,
            challenger,
        });
        Ok(())
    }

    /// Input-authenticity fault against a WITHDRAWAL transcript (H-2) — the cycle's committed step at
    /// `index` isn't the real trade at the batch slot its coverage positionally assigns it.
    /// Permissionless. Mirrors `prove_input_fault` against the cycle's roots + coverage.
    #[allow(clippy::too_many_arguments)]
    pub fn prove_withdrawal_input_fault(
        ctx: Context<ProveWithdrawalInputFault>,
        cycle: u32,
        index: u32,
        batch_epoch: u64,
        batch_leaf_index: u32,
        step: settlement::StepInput,
        step_membership_proof: Vec<settlement::ProofStep>,
        actual_batch_leaf: String,
        batch_membership_proof: Vec<settlement::ProofStep>,
    ) -> Result<()> {
        let _ = cycle; // seed-only
        let challenger = ctx.accounts.challenger.key();
        let now = Clock::get()?.unix_timestamp;
        let batch_root_hex = settlement::root_to_hex(&ctx.accounts.batch_root.merkle_root);
        let cov: Vec<settlement::CovEntry> = ctx
            .accounts
            .coverage
            .entries
            .iter()
            .map(|e| settlement::CovEntry { epoch: e.epoch, prefix: e.prefix, trade_count: e.trade_count, base_offset: e.base_offset })
            .collect();
        let w = &mut ctx.accounts.withdrawal;
        require!(w.status == SettlementStatus::Provisional, ChallengeError::NotProvisional);
        require!(now <= w.window_end, ChallengeError::SettlementWindowClosed);

        let pos = settlement::positional_slot(&cov, index).ok_or(ChallengeError::FaultNotProven)?;
        require!((batch_epoch, batch_leaf_index) == pos, ChallengeError::FaultNotProven);

        let fault = settlement::verify_input_fault(
            &settlement::root_to_hex(&w.bound_step_root),
            index,
            batch_epoch,
            batch_leaf_index,
            &step,
            &step_membership_proof,
            &batch_root_hex,
            &actual_batch_leaf,
            &batch_membership_proof,
        );
        require!(fault, ChallengeError::FaultNotProven);

        withdrawal_fault_out(w, now, challenger);
        emit!(FundedWithdrawalFaulted {
            challenge: w.challenge,
            cycle: w.cycle,
            kind: FaultKind::Input as u8,
            index,
            challenger,
        });
        Ok(())
    }

    /// Provenance fault against a WITHDRAWAL transcript (H-2 §3b) — the cycle's committed step at
    /// `index` is welded to a provenance other than its positional slot, including a non-existent epoch
    /// (the last fabrication escape). No `batch_root` is loaded. Permissionless.
    pub fn prove_withdrawal_provenance_fault(
        ctx: Context<ProveWithdrawalProvenanceFault>,
        cycle: u32,
        index: u32,
        committed_epoch: u64,
        committed_leaf_index: u32,
        step: settlement::StepInput,
        step_membership_proof: Vec<settlement::ProofStep>,
    ) -> Result<()> {
        let _ = cycle; // seed-only
        let challenger = ctx.accounts.challenger.key();
        let now = Clock::get()?.unix_timestamp;
        let cov: Vec<settlement::CovEntry> = ctx
            .accounts
            .coverage
            .entries
            .iter()
            .map(|e| settlement::CovEntry { epoch: e.epoch, prefix: e.prefix, trade_count: e.trade_count, base_offset: e.base_offset })
            .collect();
        let w = &mut ctx.accounts.withdrawal;
        require!(w.status == SettlementStatus::Provisional, ChallengeError::NotProvisional);
        require!(now <= w.window_end, ChallengeError::SettlementWindowClosed);

        let pos = settlement::positional_slot(&cov, index).ok_or(ChallengeError::FaultNotProven)?;
        let fault = settlement::verify_provenance_fault(
            &settlement::root_to_hex(&w.bound_step_root),
            index,
            committed_epoch,
            committed_leaf_index,
            &step,
            &step_membership_proof,
            pos,
        );
        require!(fault, ChallengeError::FaultNotProven);

        withdrawal_fault_out(w, now, challenger);
        emit!(FundedWithdrawalFaulted {
            challenge: w.challenge,
            cycle: w.cycle,
            kind: FaultKind::Provenance as u8,
            index,
            challenger,
        });
        Ok(())
    }

    /// Reclaim rent once a challenge is in a terminal state. The immutable trade
    /// evidence lives in the batch_program's BatchRoot PDAs — closing this account
    /// does not erase history (§10).
    pub fn close_challenge(ctx: Context<CloseChallenge>) -> Result<()> {
        let status = ctx.accounts.challenge.status;
        require!(
            status == ChallengeStatus::Failed || status == ChallengeStatus::Claimed,
            ChallengeError::NotTerminal
        );
        Ok(())
    }
}

/// Account size tiers 0..=7 ($1k, $5k, $10k, $25k, $50k, $100k, $200k, $1M) — mirrors the
/// 8-tier price-band / catalog ($10). The largest three ($100k+) are gated to bigger plans.
pub const MAX_ACCOUNT_SIZE_TIER: u8 = 7;
/// Max distinct batch epochs a single settlement coverage can bind (H-2 §3b). Settlements covering more
/// trade-epochs than this are unsupported in this version (future: a Merkle coverage commitment).
pub const MAX_COVERAGE_EPOCHS: usize = 64;
/// Dispute window after settlement (24h, §6 step 6).
pub const DISPUTE_WINDOW: i64 = 86_400;
const SECONDS_PER_DAY: i64 = 86_400;
/// Fraud-proof window after a **settlement** is PROPOSED (F5). Funds cannot move until it closes with
/// no fault proven (`finalize_settlement`). 72h (3 days) gives watchtowers meaningful time to
/// replay the full transcript and construct a Merkle fault proof. 24h was too short for a trader
/// or independent watchtower to notice a disputed settlement and respond before finalization.
///
/// This constant governs the **settlement** path unconditionally, and is the **Critical-tier** (longest)
/// anchor for the funded-withdrawal path. Withdrawals scale their window by the firm's risk tier — see
/// `withdrawal_window_for_tier` — so a healthy firm pays out fast; the settlement window itself is never
/// tier-scaled and never shortened for mainnet.
///
/// Three builds, and only the default is honest:
///
/// - **default — 72h.** The real window. The only one that may ever reach mainnet.
/// - **`test-fast` — 30s.** Localnet `anchor test` + automated harnesses that sleep or warp the clock
///   past it (`scripts/litesvm-*`, `scripts/localnet-funded-withdrawal-e2e.ts`).
/// - **`devnet-fast` — 5min.** A HUMAN driving the real deployed devnet site: long enough to watch a
///   withdrawal sit `Provisional` and see the keeper defer, short enough to finish in a sitting.
///   Wins over `test-fast` if both are set, so the combination can't silently produce 30s.
///
/// **The settlement window may NEVER be shortened for mainnet via a build flag.** The 72h default is not
/// padding: 24h was too short for a trader or independent watchtower to notice a disputed settlement and
/// respond before finalization, and a settlement nobody can fraud-prove in time is a keeper-signed
/// treasury drain. A devnet run under a shortened build proves the WIRING, never the window itself — so
/// it cannot stand as evidence that the production fraud window works.
#[cfg(all(not(feature = "test-fast"), not(feature = "devnet-fast")))]
pub const SETTLEMENT_CHALLENGE_WINDOW: i64 = 259_200;
#[cfg(all(feature = "test-fast", not(feature = "devnet-fast")))]
pub const SETTLEMENT_CHALLENGE_WINDOW: i64 = 30;
#[cfg(feature = "devnet-fast")]
pub const SETTLEMENT_CHALLENGE_WINDOW: i64 = 300;

/// Fraud-proof window for a funded **withdrawal** (trader payout), scaled by the firm's risk tier at
/// propose time (`FundedWithdrawal.settlement_risk_tier`, grandfathered so a later tier change can never
/// retroactively extend or shorten a window already opened).
///
/// Why tier-scaled where settlement is flat: a withdrawal is paid from the firm's OWN treasury, so a
/// healthy (solvent) firm choosing to pay fast is self-insuring — the risk it accepts is its own, and the
/// shared backstop tiers are only reachable at Warning/Critical, which is exactly where the long window is
/// kept. The healthy tiers keep a **short floor, never 0**: the on-chain fault-proof watchtower is not yet
/// run (CF-8), so the live defense is the off-chain integrity engine. The 20-min window is deliberately
/// matched to a faster integrity sweep cadence (`INTEGRITY_INTERVAL_MS`, ~15 min) so at least one sweep
/// still sees every payout before its SOL is irreversibly delivered — the two must be kept paired (sweep
/// interval < window). Critical stays pinned to `SETTLEMENT_CHALLENGE_WINDOW` in every build so the
/// longest window and the settlement window agree.
///
/// - **default (mainnet):** Healthy/Caution 20min · Warning 24h · Critical 72h.
/// - **`test-fast`:** 10s · 10s · 20s · 30s (the healthy floor stays clear of one keeper tick so the
///   localnet E2E can observe the "defers while open" state before it closes).
/// - **`devnet-fast`:** 30s · 30s · 150s · 300s.
#[cfg(all(not(feature = "test-fast"), not(feature = "devnet-fast")))]
pub fn withdrawal_window_for_tier(tier: RiskTier) -> i64 {
    match tier {
        RiskTier::Healthy | RiskTier::Caution => 1_200,
        RiskTier::Warning => 86_400,
        RiskTier::Critical => SETTLEMENT_CHALLENGE_WINDOW,
    }
}
#[cfg(all(feature = "test-fast", not(feature = "devnet-fast")))]
pub fn withdrawal_window_for_tier(tier: RiskTier) -> i64 {
    match tier {
        RiskTier::Healthy | RiskTier::Caution => 10,
        RiskTier::Warning => 20,
        RiskTier::Critical => SETTLEMENT_CHALLENGE_WINDOW,
    }
}
#[cfg(feature = "devnet-fast")]
pub fn withdrawal_window_for_tier(tier: RiskTier) -> i64 {
    match tier {
        RiskTier::Healthy | RiskTier::Caution => 30,
        RiskTier::Warning => 150,
        RiskTier::Critical => SETTLEMENT_CHALLENGE_WINDOW,
    }
}

/// Compute the expiry timestamp from `max_trading_days` (0 = unlimited → 0 sentinel).
fn expiry_from_rules(now: i64, max_trading_days: u8) -> Result<i64> {
    if max_trading_days == 0 {
        return Ok(0);
    }
    (max_trading_days as i64)
        .checked_mul(SECONDS_PER_DAY)
        .and_then(|d| now.checked_add(d))
        .ok_or(ChallengeError::MathOverflow.into())
}

/// Project the immutable on-chain `RulesSnapshot` onto the settlement engine's `RuleParams` — the
/// exact subset settlement is a deterministic function of. Same locked terms the engine consumed.
fn rule_params(rules: &RulesSnapshot) -> settlement::RuleParams {
    settlement::RuleParams {
        starting_balance: rules.starting_balance as i128,
        profit_target_bps: rules.profit_target_bps as i128,
        max_daily_loss_bps: rules.max_daily_loss_bps as i128,
        max_total_drawdown_bps: rules.max_total_drawdown_bps as i128,
        is_trailing_drawdown: rules.is_trailing_drawdown,
        min_trading_days: rules.min_trading_days as u32,
    }
}

/// Void a proven-fraudulent settlement: the challenge fails, owes nothing, and is flagged `Faulted`
/// so every payout mover refuses it. The operator-stake slash is enforced by the `dispute`/`firm`
/// programs off this terminal state + the emitted `SettlementFaulted` event.
fn fault_out(challenge: &mut ChallengeState, now: i64, challenger: Pubkey) {
    challenge.settlement_status = SettlementStatus::Faulted;
    challenge.status = ChallengeStatus::Failed;
    challenge.payout_sol_owed = 0;
    challenge.payout_firma_owed = 0;
    challenge.virtual_profit = 0;
    challenge.settled_at = now;
    // Record WHO proved the fault so the `dispute` program can pay them the slash bounty.
    challenge.fault_challenger = challenger;
}

/// F2 (SETTLEMENT-AUTH-MINT-GUARD): read the firm's live `risk_engine_authority` directly from the firm
/// account's raw bytes.
///
/// A challenge whose frozen `settlement_authority` is not the firm's real keeper is mintable today but
/// PERMANENTLY UNPAYABLE — the firm program's `require_firm_settlement_authority` reverts `Unauthorized`
/// on every payout, so a funded such account's SOL is stuck forever (Trustless deep-dive F1/F2). Binding
/// the authority to this value AT MINT makes that unpayable state unconstructable.
///
/// Deserialized BY HAND because the challenge crate cannot depend on `firm` (it would cycle: firm depends
/// on challenge via CPI). The three checks harden the read against a spoofed/wrong account passed for the
/// PDA-seed `firm`: (1) it is firm-program-owned, (2) it is long enough, (3) it carries the FirmState
/// discriminator. Only then is the Pubkey at the fixed `risk_engine_authority` offset trusted.
fn firm_risk_engine_authority(firm_ai: &AccountInfo) -> Result<Pubkey> {
    require_keys_eq!(*firm_ai.owner, FIRM_PROGRAM_ID, ChallengeError::FirmAccountInvalid);
    let data = firm_ai.try_borrow_data()?;
    require!(
        data.len() >= FIRM_RISK_ENGINE_AUTHORITY_OFFSET + 32,
        ChallengeError::FirmAccountInvalid
    );
    require!(data[..8] == FIRM_STATE_DISCRIMINATOR, ChallengeError::FirmAccountInvalid);
    let mut key = [0u8; 32];
    key.copy_from_slice(&data[FIRM_RISK_ENGINE_AUTHORITY_OFFSET..FIRM_RISK_ENGINE_AUTHORITY_OFFSET + 32]);
    Ok(Pubkey::new_from_array(key))
}

/// Initialize a freshly-`init`'d challenge PDA with an authority-attested, immutable rules snapshot.
/// Shared verbatim by `purchase_challenge` (trader-paid) and `grant_giveaway_challenge` (ARE giveaway,
/// no fee): the ONLY difference between the two entry points is who pays rent and whether a fee was
/// charged — the on-chain challenge they produce is identical, so the settle / fraud-proof / payout
/// machinery treats a won evaluation exactly like a bought one. Keeping this one function is what
/// guarantees the two paths can never drift.
#[allow(clippy::too_many_arguments)]
fn init_challenge_state(
    challenge: &mut ChallengeState,
    trader: Pubkey,
    firm: Pubkey,
    settlement_authority: Pubkey,
    account_size_tier: u8,
    phase: ChallengePhase,
    rules: RulesSnapshot,
    discount_applied: bool,
    now: i64,
    bump: u8,
    nonce: u64,
) -> Result<()> {
    // ENVELOPE-1: the rules arrive as caller-supplied instruction data, so bound them before they are
    // locked. Enforced HERE rather than in `purchase_challenge` because this is the single chokepoint
    // both the purchase and the giveaway-grant paths construct challenges through — putting it in one
    // caller would leave the other able to mint an out-of-envelope challenge.
    envelope::validate_rules_envelope(&rules)?;

    challenge.trader = trader;
    challenge.firm = firm;
    challenge.settlement_authority = settlement_authority;
    challenge.account_size_tier = account_size_tier;
    challenge.phase = phase;
    challenge.status = ChallengeStatus::Active;
    challenge.virtual_balance = rules.starting_balance;
    challenge.virtual_profit = 0;
    challenge.payout_sol_owed = 0;
    challenge.payout_firma_owed = 0;
    challenge.integrity_hold = false;
    challenge.integrity_evidence_root = [0u8; 32];
    challenge.settlement_risk_tier = RiskTier::Healthy;
    challenge.started_at = now;
    challenge.expires_at = expiry_from_rules(now, rules.max_trading_days)?;
    challenge.settled_at = 0;
    challenge.dispute_deadline = 0;
    challenge.discount_applied = discount_applied;
    challenge.rules_snapshot = rules;
    // Verifiable-settlement commitments — empty until `propose_settlement` (F5).
    challenge.settlement_status = SettlementStatus::Unsettled;
    challenge.transcript_root = [0u8; 32];
    challenge.step_root = [0u8; 32];
    challenge.bound_step_root = [0u8; 32];
    challenge.final_state_hash = [0u8; 32];
    challenge.transcript_len = 0;
    challenge.claimed_passed = false;
    challenge.claimed_virtual_profit = 0;
    challenge.settlement_window_end = 0;
    challenge.fault_challenger = Pubkey::default();
    challenge.bump = bump;
    challenge.nonce = nonce;
    Ok(())
}

// The `#[instruction(...)]` list must be a PREFIX of `purchase_challenge`'s real wire-order args —
// Anchor deserializes it sequentially from the front of the instruction data to resolve any arg
// referenced in a `seeds = [...]` constraint below. Since `nonce` is the LAST param, every earlier
// param (`rules`, `discount_applied`) must be listed too, even though only tier/phase/nonce feed the
// seeds — omitting them here silently deserializes `nonce` from the wrong byte offset (mid-`rules`),
// producing a `ConstraintSeeds` mismatch between the client's PDA and the program's (caught live).
#[derive(Accounts)]
#[instruction(account_size_tier: u8, phase: u8, rules: RulesSnapshot, discount_applied: bool, nonce: u64)]
pub struct PurchaseChallenge<'info> {
    #[account(mut)]
    pub trader: Signer<'info>,

    /// CHECK: the firm this challenge belongs to — PDA seed only.
    pub firm: UncheckedAccount<'info>,

    /// The firm's settlement / risk-engine authority — MUST co-sign the purchase. This attests
    /// the locked `rules` are authorized by the authority that will settle them: it makes the
    /// on-chain `rules_snapshot` a *verifiable, authorized* commitment rather than caller-supplied
    /// data. A self-set authority simply yields an unpayable challenge — the firm program binds
    /// `settlement_authority == firm.risk_engine_authority` before any payout
    /// (`require_firm_settlement_authority`), so funds can never move for a challenge the firm's
    /// real authority did not authorize here.
    pub settlement_authority: Signer<'info>,

    #[account(
        init,
        payer = trader,
        space = 8 + ChallengeState::INIT_SPACE,
        seeds = [b"challenge", firm.key().as_ref(), trader.key().as_ref(), &[account_size_tier], &[phase], &nonce.to_le_bytes()],
        bump
    )]
    pub challenge: Account<'info, ChallengeState>,

    pub system_program: Program<'info, System>,
}

// Same prefix requirement as `PurchaseChallenge` above — `nonce` is the last of six real args.
#[derive(Accounts)]
#[instruction(account_size_tier: u8, phase: u8, rules: RulesSnapshot, day_index: u32, draw_seed: u64, nonce: u64)]
pub struct GrantGiveawayChallenge<'info> {
    /// The firm's settlement / risk-engine authority — the SOLE signer and the rent payer. It both
    /// authorizes the locked `rules` (exactly as in `purchase_challenge`) and funds the account's
    /// rent, because the winner is not present to sign or pay for a gift.
    #[account(mut)]
    pub settlement_authority: Signer<'info>,

    /// CHECK: the firm this challenge belongs to — PDA seed only.
    pub firm: UncheckedAccount<'info>,

    /// CHECK: the giveaway winner who receives the evaluation — PDA seed only, does NOT sign. The
    /// grant is a gift, so no recipient consent is required; the resulting challenge is inert until
    /// the winner trades it in the UI.
    pub winner: UncheckedAccount<'info>,

    #[account(
        init,
        payer = settlement_authority,
        space = 8 + ChallengeState::INIT_SPACE,
        seeds = [b"challenge", firm.key().as_ref(), winner.key().as_ref(), &[account_size_tier], &[phase], &nonce.to_le_bytes()],
        bump
    )]
    pub challenge: Account<'info, ChallengeState>,

    pub system_program: Program<'info, System>,
}

/// F2 heal — re-point a legacy mismatched challenge's `settlement_authority` to the firm's live keeper.
/// No `init`, no funds move; it only rewrites the one authority field. See `repair_settlement_authority`.
#[derive(Accounts)]
pub struct RepairSettlementAuthority<'info> {
    /// The firm's CURRENT risk-engine authority — must sign, and is the ONLY value written to
    /// `challenge.settlement_authority`. Verified to equal `firm.risk_engine_authority` in the handler,
    /// so this cannot redirect a challenge to anyone but the firm's real keeper.
    pub risk_engine_authority: Signer<'info>,

    /// CHECK: the firm this challenge belongs to. Bound to `challenge.firm` by the constraint below and
    /// read (owner + discriminator + field offset) for its `risk_engine_authority`; never trusted as a
    /// bare key. Binding it to `challenge.firm` guarantees the keeper read is THIS challenge's firm's.
    pub firm: UncheckedAccount<'info>,

    #[account(
        mut,
        seeds = [
            b"challenge",
            challenge.firm.as_ref(),
            challenge.trader.as_ref(),
            &[challenge.account_size_tier],
            &[challenge.phase as u8],
            &challenge.nonce.to_le_bytes(),
        ],
        bump = challenge.bump,
        constraint = challenge.firm == firm.key() @ ChallengeError::Unauthorized,
    )]
    pub challenge: Account<'info, ChallengeState>,
}

#[derive(Accounts)]
pub struct SettleChallenge<'info> {
    pub authority: Signer<'info>,

    #[account(
        mut,
        seeds = [
            b"challenge",
            challenge.firm.as_ref(),
            challenge.trader.as_ref(),
            &[challenge.account_size_tier],
            &[challenge.phase as u8],
            &challenge.nonce.to_le_bytes(),
        ],
        bump = challenge.bump,
        constraint = challenge.settlement_authority == authority.key() @ ChallengeError::Unauthorized,
    )]
    pub challenge: Account<'info, ChallengeState>,
}

/// Integrity hold set/lift — same authority + PDA derivation as `SettleChallenge`.
#[derive(Accounts)]
pub struct SetIntegrityHold<'info> {
    pub authority: Signer<'info>,

    #[account(
        mut,
        seeds = [
            b"challenge",
            challenge.firm.as_ref(),
            challenge.trader.as_ref(),
            &[challenge.account_size_tier],
            &[challenge.phase as u8],
            &challenge.nonce.to_le_bytes(),
        ],
        bump = challenge.bump,
        constraint = challenge.settlement_authority == authority.key() @ ChallengeError::Unauthorized,
    )]
    pub challenge: Account<'info, ChallengeState>,
}

/// Permissionless integrity fault proof — any signer may submit; same challenge PDA.
#[derive(Accounts)]
pub struct ProveIntegrityFault<'info> {
    /// Anyone (the affected trader or a watchtower) may submit the proof; pays fees.
    pub challenger: Signer<'info>,

    #[account(
        mut,
        seeds = [
            b"challenge",
            challenge.firm.as_ref(),
            challenge.trader.as_ref(),
            &[challenge.account_size_tier],
            &[challenge.phase as u8],
            &challenge.nonce.to_le_bytes(),
        ],
        bump = challenge.bump,
    )]
    pub challenge: Account<'info, ChallengeState>,
}

/// One revealed evidence flag for a fault proof. `code` is the off-chain
/// DETECTOR_CODE; `severity` is 0..=3 (LOW..CRITICAL); `score` is fixed-point ×1e6.
#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct FaultFlag {
    pub code: u8,
    pub severity: u8,
    pub score: u32,
}

/// Identity/linkage detector codes (must match the off-chain DETECTOR_CODE map):
/// CROSS_FIRM_CORRELATION=1, CROSS_ACCOUNT_CORRELATION=2, DEVICE_CLUSTER=3,
/// IP_VELOCITY=4. Being multi-firm/multi-account/shared-device is advisory-only —
/// never a stand-alone basis for enforcement — so a hold backed solely by these
/// is a fault.
const ADVISORY_CODES: [u8; 4] = [1, 2, 3, 4];

/// Canonical evidence root: each flag → a 6-byte record [code, severity, score_le4];
/// sort records lexicographically; sha256 the concatenation. Mirrors the off-chain
/// `onchainEvidenceRoot` exactly (parity-tested).
fn integrity_evidence_root(flags: &[FaultFlag]) -> [u8; 32] {
    let mut records: Vec<[u8; 6]> = flags
        .iter()
        .map(|f| {
            let mut r = [0u8; 6];
            r[0] = f.code;
            r[1] = f.severity;
            r[2..6].copy_from_slice(&f.score.to_le_bytes());
            r
        })
        .collect();
    records.sort();
    let mut blob = Vec::with_capacity(records.len() * 6);
    for r in &records {
        blob.extend_from_slice(r);
    }
    anchor_lang::solana_program::hash::hash(&blob).to_bytes()
}

/// Propose a verifiable settlement — authority-gated, same challenge PDA as `SettleChallenge`.
#[derive(Accounts)]
pub struct ProposeSettlement<'info> {
    pub authority: Signer<'info>,

    #[account(
        mut,
        seeds = [
            b"challenge",
            challenge.firm.as_ref(),
            challenge.trader.as_ref(),
            &[challenge.account_size_tier],
            &[challenge.phase as u8],
            &challenge.nonce.to_le_bytes(),
        ],
        bump = challenge.bump,
        constraint = challenge.settlement_authority == authority.key() @ ChallengeError::Unauthorized,
    )]
    pub challenge: Account<'info, ChallengeState>,

    /// The settlement's coverage (H-2 §3b) — must already be built (`init_settlement_coverage` +
    /// `add_coverage_epoch`). `propose_settlement` checks `covered_trade_count == transcript_len - 1`
    /// and finalises (locks) it.
    #[account(
        mut,
        seeds = [b"coverage", challenge.key().as_ref()],
        bump = coverage.bump,
        constraint = coverage.challenge == challenge.key() @ ChallengeError::Unauthorized,
    )]
    pub coverage: Account<'info, SettlementCoverage>,

    /// SETTLEMENT-WITHDRAWAL-GAP-1: this challenge's withdrawal-cycle counter, if `init_withdrawal_counter`
    /// was ever called (a Phase1/Phase2 eval, or a FUNDED eval that never withdrew, has none — `None` is
    /// the common case and behaves exactly as before this fix).
    #[account(
        seeds = [b"wcount", challenge.key().as_ref()],
        bump = withdrawal_counter.bump,
        constraint = withdrawal_counter.challenge == challenge.key() @ ChallengeError::Unauthorized,
    )]
    pub withdrawal_counter: Option<Box<Account<'info, WithdrawalCounter>>>,

    /// The `FundedWithdrawal` at the counter's CURRENT cycle slot, if one has been proposed (Provisional
    /// or Faulted — never Final, since finalize atomically advances the counter past it). Bound in the
    /// HANDLER, not via a seeds constraint, mirroring `ProposeFundedWithdrawal.prev_withdrawal`: a
    /// typed account this program wrote, with both `challenge` and `cycle` checked, is a complete binding.
    pub open_withdrawal: Option<Box<Account<'info, FundedWithdrawal>>>,

    /// The last withdrawal cycle to reach `Final` (slot `counter.cycle - 1`), if any — the state this
    /// settlement's coverage watermark is checked against. Bound in the handler; same reasoning as above.
    pub last_final_withdrawal: Option<Box<Account<'info, FundedWithdrawal>>>,
}

/// Begin a settlement coverage (H-2 §3b) — authority-gated; PDA `["coverage", challenge]`.
#[derive(Accounts)]
pub struct InitSettlementCoverage<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,

    #[account(
        seeds = [
            b"challenge",
            challenge.firm.as_ref(),
            challenge.trader.as_ref(),
            &[challenge.account_size_tier],
            &[challenge.phase as u8],
            &challenge.nonce.to_le_bytes(),
        ],
        bump = challenge.bump,
        constraint = challenge.settlement_authority == authority.key() @ ChallengeError::Unauthorized,
    )]
    pub challenge: Account<'info, ChallengeState>,

    #[account(
        init,
        payer = authority,
        space = 8 + SettlementCoverage::INIT_SPACE,
        seeds = [b"coverage", challenge.key().as_ref()],
        bump
    )]
    pub coverage: Account<'info, SettlementCoverage>,

    pub system_program: Program<'info, System>,
}

/// Append one real batch epoch to a coverage (H-2 §3b) — authority-gated; the typed `batch_root`
/// proves the epoch exists + is authentic.
#[derive(Accounts)]
#[instruction(epoch: u64)]
pub struct AddCoverageEpoch<'info> {
    pub authority: Signer<'info>,

    #[account(
        seeds = [
            b"challenge",
            challenge.firm.as_ref(),
            challenge.trader.as_ref(),
            &[challenge.account_size_tier],
            &[challenge.phase as u8],
            &challenge.nonce.to_le_bytes(),
        ],
        bump = challenge.bump,
        constraint = challenge.settlement_authority == authority.key() @ ChallengeError::Unauthorized,
    )]
    pub challenge: Account<'info, ChallengeState>,

    #[account(
        mut,
        seeds = [b"coverage", challenge.key().as_ref()],
        bump = coverage.bump,
        constraint = coverage.challenge == challenge.key() @ ChallengeError::Unauthorized,
    )]
    pub coverage: Account<'info, SettlementCoverage>,

    /// The real committed trade root for `(challenge.firm, epoch)` — typed ⇒ Anchor proves it exists.
    #[account(
        seeds = [b"batch", challenge.firm.as_ref(), &epoch.to_le_bytes()],
        bump = batch_root.bump,
        seeds::program = batch::ID,
        constraint = batch_root.firm == challenge.firm @ ChallengeError::Unauthorized,
    )]
    pub batch_root: Account<'info, batch::BatchRoot>,
}

/// The settlement-coverage counterpart of `AddWithdrawalCoverageEpochSupplemental`, reading a
/// `SupplementalSegment` instead of proving a Merkle segment against `batch_root`.
#[derive(Accounts)]
#[instruction(epoch: u64)]
pub struct AddCoverageEpochSupplemental<'info> {
    pub authority: Signer<'info>,

    #[account(
        seeds = [
            b"challenge",
            challenge.firm.as_ref(),
            challenge.trader.as_ref(),
            &[challenge.account_size_tier],
            &[challenge.phase as u8],
            &challenge.nonce.to_le_bytes(),
        ],
        bump = challenge.bump,
        constraint = challenge.settlement_authority == authority.key() @ ChallengeError::Unauthorized,
    )]
    pub challenge: Box<Account<'info, ChallengeState>>,

    #[account(
        mut,
        seeds = [b"coverage", challenge.key().as_ref()],
        bump = coverage.bump,
        constraint = coverage.challenge == challenge.key() @ ChallengeError::Unauthorized,
    )]
    pub coverage: Box<Account<'info, SettlementCoverage>>,

    #[account(
        seeds = [b"supp_segment", challenge.key().as_ref(), &epoch.to_le_bytes()],
        bump = supplemental_segment.bump,
        constraint = supplemental_segment.challenge == challenge.key() @ ChallengeError::Unauthorized,
    )]
    pub supplemental_segment: Box<Account<'info, SupplementalSegment>>,
}

/// Submit a fraud proof against a Provisional settlement — PERMISSIONLESS (anyone may challenge).
#[derive(Accounts)]
pub struct ProveSettlementFault<'info> {
    pub challenger: Signer<'info>,

    #[account(
        mut,
        seeds = [
            b"challenge",
            challenge.firm.as_ref(),
            challenge.trader.as_ref(),
            &[challenge.account_size_tier],
            &[challenge.phase as u8],
            &challenge.nonce.to_le_bytes(),
        ],
        bump = challenge.bump,
    )]
    pub challenge: Account<'info, ChallengeState>,

    /// SETTLEMENT-WITHDRAWAL-GAP-1: only read by `prove_genesis_fault` — the other fault kinds
    /// (transition/result/input/provenance) ignore these. `None` for the common no-withdrawal case.
    #[account(
        seeds = [b"wcount", challenge.key().as_ref()],
        bump = withdrawal_counter.bump,
        constraint = withdrawal_counter.challenge == challenge.key() @ ChallengeError::Unauthorized,
    )]
    pub withdrawal_counter: Option<Box<Account<'info, WithdrawalCounter>>>,

    /// The last withdrawal cycle to reach `Final` (slot `counter.cycle - 1`) — the state
    /// `prove_genesis_fault` rebaselines from when one exists. Bound in the handler, as elsewhere.
    pub last_final_withdrawal: Option<Box<Account<'info, FundedWithdrawal>>>,
}

/// Submit an INPUT-AUTHENTICITY fraud proof (H-2) — PERMISSIONLESS. Reads the committed `batch_root`
/// cross-program to compare the operator's committed step against the real trade at its claimed slot.
#[derive(Accounts)]
#[instruction(index: u32, batch_epoch: u64)]
pub struct ProveInputFault<'info> {
    pub challenger: Signer<'info>,

    #[account(
        mut,
        seeds = [
            b"challenge",
            challenge.firm.as_ref(),
            challenge.trader.as_ref(),
            &[challenge.account_size_tier],
            &[challenge.phase as u8],
            &challenge.nonce.to_le_bytes(),
        ],
        bump = challenge.bump,
    )]
    pub challenge: Account<'info, ChallengeState>,

    /// The settlement coverage (H-2 §3b) — gives the positional slot for `index`.
    #[account(
        seeds = [b"coverage", challenge.key().as_ref()],
        bump = coverage.bump,
        constraint = coverage.challenge == challenge.key() @ ChallengeError::FaultNotProven,
    )]
    pub coverage: Account<'info, SettlementCoverage>,

    /// The committed trade root for the challenge's firm + the (positional) epoch. Typed `Account` ⇒
    /// Anchor verifies it is a real `batch::BatchRoot` owned by the batch program.
    #[account(
        seeds = [b"batch", challenge.firm.as_ref(), &batch_epoch.to_le_bytes()],
        bump = batch_root.bump,
        seeds::program = batch::ID,
        constraint = batch_root.firm == challenge.firm @ ChallengeError::FaultNotProven,
    )]
    pub batch_root: Account<'info, batch::BatchRoot>,
}

/// Submit a PROVENANCE fault (H-2 §3b) — PERMISSIONLESS. No `batch_root` (the committed epoch may not
/// exist); the coverage + the committed-leaf membership are sufficient.
#[derive(Accounts)]
pub struct ProveProvenanceFault<'info> {
    pub challenger: Signer<'info>,

    #[account(
        mut,
        seeds = [
            b"challenge",
            challenge.firm.as_ref(),
            challenge.trader.as_ref(),
            &[challenge.account_size_tier],
            &[challenge.phase as u8],
            &challenge.nonce.to_le_bytes(),
        ],
        bump = challenge.bump,
    )]
    pub challenge: Account<'info, ChallengeState>,

    #[account(
        seeds = [b"coverage", challenge.key().as_ref()],
        bump = coverage.bump,
        constraint = coverage.challenge == challenge.key() @ ChallengeError::FaultNotProven,
    )]
    pub coverage: Account<'info, SettlementCoverage>,
}

/// Finalize a Provisional settlement after its window — PERMISSIONLESS (a keeper crank).
#[derive(Accounts)]
pub struct FinalizeSettlement<'info> {
    pub cranker: Signer<'info>,

    #[account(
        mut,
        seeds = [
            b"challenge",
            challenge.firm.as_ref(),
            challenge.trader.as_ref(),
            &[challenge.account_size_tier],
            &[challenge.phase as u8],
            &challenge.nonce.to_le_bytes(),
        ],
        bump = challenge.bump,
    )]
    pub challenge: Account<'info, ChallengeState>,
}

// ───────────────── DEC-62: funded-withdrawal accounts ─────────────────
//
// CHK-11 prefix gotcha: `#[instruction(...)]` must list Anchor's REAL argument prefix up to any arg a
// `seeds = [...]` constraint references, or it deserializes from the wrong byte offset and fails
// `ConstraintSeeds` at RUNTIME, not compile time. Every withdrawal instruction below takes `cycle`
// FIRST precisely so the prefix is the single arg `cycle` — trivially correct, and impossible to break
// by adding an argument later.

/// Create the per-challenge withdrawal cycle counter — settlement-authority gated.
#[derive(Accounts)]
pub struct InitWithdrawalCounter<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,

    #[account(
        seeds = [
            b"challenge",
            challenge.firm.as_ref(),
            challenge.trader.as_ref(),
            &[challenge.account_size_tier],
            &[challenge.phase as u8],
            &challenge.nonce.to_le_bytes(),
        ],
        bump = challenge.bump,
        constraint = challenge.settlement_authority == authority.key() @ ChallengeError::Unauthorized,
    )]
    pub challenge: Box<Account<'info, ChallengeState>>,

    #[account(
        init,
        payer = authority,
        space = 8 + WithdrawalCounter::INIT_SPACE,
        seeds = [b"wcount", challenge.key().as_ref()],
        bump
    )]
    pub counter: Box<Account<'info, WithdrawalCounter>>,

    pub system_program: Program<'info, System>,
}

/// Begin a withdrawal cycle's coverage — settlement-authority gated; PDA `["wcoverage", challenge, cycle]`.
#[derive(Accounts)]
#[instruction(cycle: u32)]
pub struct InitWithdrawalCoverage<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,

    #[account(
        seeds = [
            b"challenge",
            challenge.firm.as_ref(),
            challenge.trader.as_ref(),
            &[challenge.account_size_tier],
            &[challenge.phase as u8],
            &challenge.nonce.to_le_bytes(),
        ],
        bump = challenge.bump,
        constraint = challenge.settlement_authority == authority.key() @ ChallengeError::Unauthorized,
    )]
    pub challenge: Box<Account<'info, ChallengeState>>,

    #[account(
        seeds = [b"wcount", challenge.key().as_ref()],
        bump = counter.bump,
        constraint = counter.challenge == challenge.key() @ ChallengeError::Unauthorized,
    )]
    pub counter: Box<Account<'info, WithdrawalCounter>>,

    #[account(
        init,
        payer = authority,
        space = 8 + SettlementCoverage::INIT_SPACE,
        seeds = [b"wcoverage", challenge.key().as_ref(), &cycle.to_le_bytes()],
        bump
    )]
    pub coverage: Box<Account<'info, SettlementCoverage>>,

    pub system_program: Program<'info, System>,
}

/// Append one real batch epoch to a withdrawal cycle's coverage — authority-gated; the typed
/// `batch_root` proves the epoch exists and is authentic.
#[derive(Accounts)]
#[instruction(cycle: u32, epoch: u64)]
pub struct AddWithdrawalCoverageEpoch<'info> {
    pub authority: Signer<'info>,

    #[account(
        seeds = [
            b"challenge",
            challenge.firm.as_ref(),
            challenge.trader.as_ref(),
            &[challenge.account_size_tier],
            &[challenge.phase as u8],
            &challenge.nonce.to_le_bytes(),
        ],
        bump = challenge.bump,
        constraint = challenge.settlement_authority == authority.key() @ ChallengeError::Unauthorized,
    )]
    pub challenge: Box<Account<'info, ChallengeState>>,

    #[account(
        mut,
        seeds = [b"wcoverage", challenge.key().as_ref(), &cycle.to_le_bytes()],
        bump = coverage.bump,
        constraint = coverage.challenge == challenge.key() @ ChallengeError::Unauthorized,
    )]
    pub coverage: Box<Account<'info, SettlementCoverage>>,

    #[account(
        seeds = [b"batch", challenge.firm.as_ref(), &epoch.to_le_bytes()],
        bump = batch_root.bump,
        seeds::program = batch::ID,
        constraint = batch_root.firm == challenge.firm @ ChallengeError::Unauthorized,
    )]
    pub batch_root: Box<Account<'info, batch::BatchRoot>>,
}

/// EPOCH-RECOMPOSE-DRIFT-1 — mint the one-shot supplemental segment for a challenge that postdates its
/// epoch's primary `batch_root`. `batch_root` is read (not written) purely to check `committed_at`
/// against `challenge.started_at`; see `commit_supplemental_segment`'s doc comment for why that
/// comparison alone is sufficient proof of eligibility.
#[derive(Accounts)]
#[instruction(epoch: u64)]
pub struct CommitSupplementalSegment<'info> {
    #[account(mut)]
    pub committer: Signer<'info>,

    #[account(
        seeds = [
            b"challenge",
            challenge.firm.as_ref(),
            challenge.trader.as_ref(),
            &[challenge.account_size_tier],
            &[challenge.phase as u8],
            &challenge.nonce.to_le_bytes(),
        ],
        bump = challenge.bump,
        constraint = challenge.settlement_authority == committer.key() @ ChallengeError::Unauthorized,
    )]
    pub challenge: Box<Account<'info, ChallengeState>>,

    #[account(
        seeds = [b"batch", challenge.firm.as_ref(), &epoch.to_le_bytes()],
        bump = batch_root.bump,
        seeds::program = batch::ID,
        constraint = batch_root.firm == challenge.firm @ ChallengeError::Unauthorized,
    )]
    pub batch_root: Box<Account<'info, batch::BatchRoot>>,

    #[account(
        init,
        payer = committer,
        space = 8 + SupplementalSegment::INIT_SPACE,
        seeds = [b"supp_segment", challenge.key().as_ref(), &epoch.to_le_bytes()],
        bump,
    )]
    pub supplemental_segment: Box<Account<'info, SupplementalSegment>>,

    pub system_program: Program<'info, System>,
}

/// The withdrawal-coverage counterpart of `AddWithdrawalCoverageEpoch`, reading a `SupplementalSegment`
/// instead of proving a Merkle segment against `batch_root`.
#[derive(Accounts)]
#[instruction(cycle: u32, epoch: u64)]
pub struct AddWithdrawalCoverageEpochSupplemental<'info> {
    pub authority: Signer<'info>,

    #[account(
        seeds = [
            b"challenge",
            challenge.firm.as_ref(),
            challenge.trader.as_ref(),
            &[challenge.account_size_tier],
            &[challenge.phase as u8],
            &challenge.nonce.to_le_bytes(),
        ],
        bump = challenge.bump,
        constraint = challenge.settlement_authority == authority.key() @ ChallengeError::Unauthorized,
    )]
    pub challenge: Box<Account<'info, ChallengeState>>,

    #[account(
        mut,
        seeds = [b"wcoverage", challenge.key().as_ref(), &cycle.to_le_bytes()],
        bump = coverage.bump,
        constraint = coverage.challenge == challenge.key() @ ChallengeError::Unauthorized,
    )]
    pub coverage: Box<Account<'info, SettlementCoverage>>,

    #[account(
        seeds = [b"supp_segment", challenge.key().as_ref(), &epoch.to_le_bytes()],
        bump = supplemental_segment.bump,
        constraint = supplemental_segment.challenge == challenge.key() @ ChallengeError::Unauthorized,
    )]
    pub supplemental_segment: Box<Account<'info, SupplementalSegment>>,
}

/// Propose a funded withdrawal — settlement-authority gated. `prev_withdrawal` is `Option` because
/// cycle 0 has no predecessor to rebaseline from (its honest genesis is `genesis_state(rules)`); from
/// cycle 1 it is REQUIRED, and the handler errors without it.
#[derive(Accounts)]
#[instruction(cycle: u32)]
pub struct ProposeFundedWithdrawal<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,

    #[account(
        seeds = [
            b"challenge",
            challenge.firm.as_ref(),
            challenge.trader.as_ref(),
            &[challenge.account_size_tier],
            &[challenge.phase as u8],
            &challenge.nonce.to_le_bytes(),
        ],
        bump = challenge.bump,
        constraint = challenge.settlement_authority == authority.key() @ ChallengeError::Unauthorized,
    )]
    pub challenge: Box<Account<'info, ChallengeState>>,

    #[account(
        seeds = [b"wcount", challenge.key().as_ref()],
        bump = counter.bump,
        constraint = counter.challenge == challenge.key() @ ChallengeError::Unauthorized,
    )]
    pub counter: Box<Account<'info, WithdrawalCounter>>,

    /// The `init` on these seeds is itself the replay guard: cycle `N` can be proposed exactly once,
    /// ever (a second attempt reverts `AccountAlreadyInUse` at `init` — the CHK-9/CHK-10 shape, here
    /// working FOR us).
    #[account(
        init,
        payer = authority,
        space = 8 + FundedWithdrawal::INIT_SPACE,
        seeds = [b"withdrawal", challenge.key().as_ref(), &cycle.to_le_bytes()],
        bump
    )]
    pub withdrawal: Box<Account<'info, FundedWithdrawal>>,

    /// Cycle `N-1`'s withdrawal — the state the honest genesis is rebaselined FROM. Its
    /// `final_state_hash` is on-chain truth, which is what stops the keeper picking its own genesis.
    ///
    /// Bound in the HANDLER (`challenge` + `cycle == cycle - 1`) rather than by a seeds constraint: the
    /// seeds would need `cycle - 1`, which underflows at cycle 0 where this account is legitimately
    /// absent. A typed `Account` is already proven to be a real `FundedWithdrawal` this program wrote,
    /// so checking both fields is a complete binding.
    pub prev_withdrawal: Option<Box<Account<'info, FundedWithdrawal>>>,

    #[account(
        mut,
        seeds = [b"wcoverage", challenge.key().as_ref(), &cycle.to_le_bytes()],
        bump = coverage.bump,
        constraint = coverage.challenge == challenge.key() @ ChallengeError::Unauthorized,
    )]
    pub coverage: Box<Account<'info, SettlementCoverage>>,

    pub system_program: Program<'info, System>,
}

/// Finalize a funded withdrawal after its window — PERMISSIONLESS (a keeper crank).
#[derive(Accounts)]
#[instruction(cycle: u32)]
pub struct FinalizeFundedWithdrawal<'info> {
    pub cranker: Signer<'info>,

    #[account(
        mut,
        seeds = [b"withdrawal", withdrawal.challenge.as_ref(), &cycle.to_le_bytes()],
        bump = withdrawal.bump,
    )]
    pub withdrawal: Box<Account<'info, FundedWithdrawal>>,

    #[account(
        mut,
        seeds = [b"wcount", withdrawal.challenge.as_ref()],
        bump = counter.bump,
        constraint = counter.challenge == withdrawal.challenge @ ChallengeError::Unauthorized,
        // The counter must still be ON this cycle — finalizing twice, or out of order, is refused.
        constraint = counter.cycle == cycle @ ChallengeError::WithdrawalCycleMismatch,
    )]
    pub counter: Box<Account<'info, WithdrawalCounter>>,
}

/// Submit a fraud proof against a Provisional withdrawal — PERMISSIONLESS (anyone may challenge).
#[derive(Accounts)]
#[instruction(cycle: u32)]
pub struct ProveWithdrawalFault<'info> {
    pub challenger: Signer<'info>,

    #[account(
        seeds = [
            b"challenge",
            challenge.firm.as_ref(),
            challenge.trader.as_ref(),
            &[challenge.account_size_tier],
            &[challenge.phase as u8],
            &challenge.nonce.to_le_bytes(),
        ],
        bump = challenge.bump,
    )]
    pub challenge: Box<Account<'info, ChallengeState>>,

    #[account(
        mut,
        seeds = [b"withdrawal", challenge.key().as_ref(), &cycle.to_le_bytes()],
        bump = withdrawal.bump,
        constraint = withdrawal.challenge == challenge.key() @ ChallengeError::Unauthorized,
    )]
    pub withdrawal: Box<Account<'info, FundedWithdrawal>>,
}

/// Input-authenticity fraud proof against a withdrawal — PERMISSIONLESS; reads the real `batch_root`.
#[derive(Accounts)]
#[instruction(cycle: u32, index: u32, batch_epoch: u64)]
pub struct ProveWithdrawalInputFault<'info> {
    pub challenger: Signer<'info>,

    #[account(
        seeds = [
            b"challenge",
            challenge.firm.as_ref(),
            challenge.trader.as_ref(),
            &[challenge.account_size_tier],
            &[challenge.phase as u8],
            &challenge.nonce.to_le_bytes(),
        ],
        bump = challenge.bump,
    )]
    pub challenge: Box<Account<'info, ChallengeState>>,

    #[account(
        mut,
        seeds = [b"withdrawal", challenge.key().as_ref(), &cycle.to_le_bytes()],
        bump = withdrawal.bump,
        constraint = withdrawal.challenge == challenge.key() @ ChallengeError::Unauthorized,
    )]
    pub withdrawal: Box<Account<'info, FundedWithdrawal>>,

    #[account(
        seeds = [b"wcoverage", challenge.key().as_ref(), &cycle.to_le_bytes()],
        bump = coverage.bump,
        constraint = coverage.challenge == challenge.key() @ ChallengeError::FaultNotProven,
    )]
    pub coverage: Box<Account<'info, SettlementCoverage>>,

    #[account(
        seeds = [b"batch", challenge.firm.as_ref(), &batch_epoch.to_le_bytes()],
        bump = batch_root.bump,
        seeds::program = batch::ID,
        constraint = batch_root.firm == challenge.firm @ ChallengeError::FaultNotProven,
    )]
    pub batch_root: Box<Account<'info, batch::BatchRoot>>,
}

/// Provenance fraud proof against a withdrawal — PERMISSIONLESS; no `batch_root` (the committed epoch
/// may not exist, which is exactly the case this catches).
#[derive(Accounts)]
#[instruction(cycle: u32)]
pub struct ProveWithdrawalProvenanceFault<'info> {
    pub challenger: Signer<'info>,

    #[account(
        seeds = [
            b"challenge",
            challenge.firm.as_ref(),
            challenge.trader.as_ref(),
            &[challenge.account_size_tier],
            &[challenge.phase as u8],
            &challenge.nonce.to_le_bytes(),
        ],
        bump = challenge.bump,
    )]
    pub challenge: Box<Account<'info, ChallengeState>>,

    #[account(
        mut,
        seeds = [b"withdrawal", challenge.key().as_ref(), &cycle.to_le_bytes()],
        bump = withdrawal.bump,
        constraint = withdrawal.challenge == challenge.key() @ ChallengeError::Unauthorized,
    )]
    pub withdrawal: Box<Account<'info, FundedWithdrawal>>,

    #[account(
        seeds = [b"wcoverage", challenge.key().as_ref(), &cycle.to_le_bytes()],
        bump = coverage.bump,
        constraint = coverage.challenge == challenge.key() @ ChallengeError::FaultNotProven,
    )]
    pub coverage: Box<Account<'info, SettlementCoverage>>,
}

/// Per-challenge withdrawal cycle counter (DEC-62). Seeds `["wcount", challenge]`. Deliberately its own
/// PDA rather than a `ChallengeState` field: `ChallengeState` is `InitSpace` with no reserved padding,
/// so adding a field would grow the account and break deserialization of every live challenge.
#[account]
#[derive(InitSpace)]
pub struct WithdrawalCounter {
    pub challenge: Pubkey,
    /// The cycle a withdrawal may be proposed for RIGHT NOW. Advanced by `finalize_funded_withdrawal`,
    /// so cycle `N+1` cannot be proposed until `N`'s 72h fraud window has closed — every window is
    /// forced to be sequential and genuinely live, with no way to pre-authorize a batch of withdrawals
    /// whose windows have all quietly expired.
    pub cycle: u32,
    /// Lifetime gross withdrawn (micro-USD) — observability for the indexer/UI. NOT load-bearing: the
    /// accounting guarantee comes from the rebaselined transcript, not this counter.
    pub cumulative_withdrawn_micro: u64,
    pub bump: u8,
}

/// One funded withdrawal (DEC-62). Seeds `["withdrawal", challenge, cycle]` — the `init` on these seeds
/// is the replay guard. Mirrors the settlement commitment shape so the same fault verifiers apply.
#[account]
#[derive(InitSpace)]
pub struct FundedWithdrawal {
    pub challenge: Pubkey,
    pub cycle: u32,
    /// GROSS profit withdrawn (micro-USD) — the full amount debited from equity at the next cycle's
    /// rebaseline, not the trader's cut: the firm's share leaves the account too (PAYOUT-DEBIT-1).
    pub gross_micro: i64,
    /// The trader's share of `gross_micro` (micro-USD), bound at propose to the locked `trader_split_bps`.
    pub trader_micro: i64,
    /// `trader_micro` converted to lamports at the Pyth settlement price. Keeper-struck: the chain can't
    /// reproduce the price choice, so this carries the SAME trust settlement already accepts
    /// (`prove_result_fault` likewise never checks `payout_sol_owed`) — MASTER_FIXES SETTLE-SOL-PRICE-1.
    pub amount_sol_owed: u64,
    /// Merkle root over THIS cycle's state chain (rebaselined genesis → final).
    pub transcript_root: [u8; 32],
    /// Root over bare `step_hash` leaves — the transition fault verifies here.
    pub step_root: [u8; 32],
    /// Root over provenance-bound `bound_step_leaf` leaves — input/provenance faults verify here.
    pub bound_step_root: [u8; 32],
    /// The genesis the CHAIN derived at propose (rebaseline of cycle N-1, or `genesis_state(rules)` for
    /// cycle 0). The keeper never got to choose it; `prove_withdrawal_genesis_fault` catches a
    /// transcript whose leaf 0 doesn't match it.
    pub genesis_state_hash: [u8; 32],
    /// The final state the amount was bound against at propose.
    pub final_state_hash: [u8; 32],
    pub transcript_len: u32,
    /// The HIGHEST batch epoch this cycle's coverage consumed — the boundary that makes the cycles
    /// PARTITION the trade timeline.
    ///
    /// Without it the whole scheme has a second drain door: cycle N+1 opens at an honestly-rebaselined
    /// genesis, then simply RE-FEEDS cycle N's already-paid trades. Every step is a genuine committed
    /// tick at its correct positional slot, so the input/provenance/transition proofs all find nothing —
    /// equity climbs back to the same final, `withdrawable_profit` reports the same profit, and the
    /// trader is paid for it twice. Proven open against real bytecode before this field existed.
    ///
    /// `propose_funded_withdrawal` therefore requires cycle N's FIRST covered epoch to be strictly
    /// greater than this. A cycle with no trades carries the predecessor's boundary forward, so an empty
    /// cycle can't be used to launder the watermark backwards.
    pub covered_last_epoch: u64,
    /// Firm risk tier at propose — the payout split is grandfathered to it (§22).
    pub settlement_risk_tier: RiskTier,
    pub proposed_at: i64,
    /// Unix time the 72h fraud window closes.
    pub window_end: i64,
    /// Unsettled is unused here; a withdrawal is born Provisional → Final | Faulted.
    pub status: SettlementStatus,
    pub fault_challenger: Pubkey,
    pub bump: u8,
}

#[event]
pub struct FundedWithdrawalProposed {
    pub challenge: Pubkey,
    pub trader: Pubkey,
    pub cycle: u32,
    pub gross_micro: i64,
    pub amount_sol_owed: u64,
    pub window_end: i64,
}

#[event]
pub struct FundedWithdrawalFinalized {
    pub challenge: Pubkey,
    pub cycle: u32,
    pub amount_sol_owed: u64,
    pub next_cycle: u32,
}

#[event]
pub struct FundedWithdrawalFaulted {
    pub challenge: Pubkey,
    pub cycle: u32,
    /// `FaultKind` discriminant.
    pub kind: u8,
    pub index: u32,
    pub challenger: Pubkey,
}

/// Void a proven-fraudulent withdrawal: it owes nothing and the firm program refuses to enqueue or pay
/// it. Mirrors `fault_out` for settlements. The challenge itself is NOT failed — a bad withdrawal
/// proposal is the keeper's fraud, not the trader's, and must not cost the trader their funded account.
fn withdrawal_fault_out(w: &mut FundedWithdrawal, now: i64, challenger: Pubkey) {
    w.status = SettlementStatus::Faulted;
    w.gross_micro = 0;
    w.trader_micro = 0;
    w.amount_sol_owed = 0;
    w.proposed_at = now;
    w.fault_challenger = challenger;
}

#[derive(Accounts)]
pub struct CloseChallenge<'info> {
    #[account(mut, address = challenge.trader)]
    pub trader: Signer<'info>,

    #[account(
        mut,
        close = trader,
        seeds = [
            b"challenge",
            challenge.firm.as_ref(),
            challenge.trader.as_ref(),
            &[challenge.account_size_tier],
            &[challenge.phase as u8],
            &challenge.nonce.to_le_bytes(),
        ],
        bump = challenge.bump,
    )]
    pub challenge: Account<'info, ChallengeState>,
}

/// Per-challenge PDA. Seeds: ["challenge", firm, trader, account_size_tier, phase, nonce] (§19).
#[account]
#[derive(InitSpace)]
pub struct ChallengeState {
    pub trader: Pubkey,
    pub firm: Pubkey,
    /// Authority permitted to settle (the firm's settlement keeper).
    pub settlement_authority: Pubkey,
    pub account_size_tier: u8,
    /// Which evaluation phase this challenge represents (Phase1 / Phase2 / Funded).
    pub phase: ChallengePhase,
    pub status: ChallengeStatus,
    pub rules_snapshot: RulesSnapshot,
    pub virtual_balance: u64,
    pub virtual_profit: i64,
    pub payout_sol_owed: u64,
    pub payout_firma_owed: u64,
    pub settlement_risk_tier: RiskTier,
    pub started_at: i64,
    pub expires_at: i64,
    pub settled_at: i64,
    pub dispute_deadline: i64,
    pub discount_applied: bool,
    /// Integrity gate (step 3): when true, the firm program refuses to enqueue or
    /// pay this challenge's payout EVEN IF the settlement is `Final` — an integrity
    /// freeze enforced on-chain, not just by an off-chain flag. Set only by the
    /// firm's settlement authority via `set_integrity_hold`.
    pub integrity_hold: bool,
    /// Commitment to the evidence behind the hold (canonical 6-byte flag records,
    /// sorted, sha256). Enables a permissionless fault proof: reveal the flags; if
    /// they hash to this root and are all identity/advisory detectors (no
    /// behavioural abuse), the rules deterministically yield NO action, so the
    /// hold is unjustified and is cleared trustlessly. Zero when not held.
    pub integrity_evidence_root: [u8; 32],
    // ── Verifiable settlement commitments (F5) ──
    /// Lifecycle of the verifiable settlement (Unsettled → Provisional → Final | Faulted).
    pub settlement_status: SettlementStatus,
    /// Merkle root over the committed per-step state-hash chain h_0..h_N (raw 32 bytes).
    pub transcript_root: [u8; 32],
    /// Merkle root over the committed step inputs as bare `step_hash(0)..step_hash(N-1)` leaves (raw 32
    /// bytes). `prove_settlement_fault` (transition) verifies the committed step against THIS root.
    pub step_root: [u8; 32],
    /// H-2 Option A: Merkle root over the PROVENANCE-BOUND step leaves
    /// (`bound_step_leaf(index, epoch, leaf_index, step)`), each welded to a firm batch trade tick.
    /// `prove_input_fault` / `prove_provenance_fault` verify against THIS root. Split from `step_root`
    /// because the two fault families need incompatible leaf encodings (`step_hash` vs `bound_step_leaf`)
    /// and one Merkle root can only hold one — so a single transcript could not support both before.
    pub bound_step_root: [u8; 32],
    /// Committed hash of the final state h_N (raw 32 bytes).
    pub final_state_hash: [u8; 32],
    /// Number of states in the transcript (N + 1).
    pub transcript_len: u32,
    /// Operator-claimed pass/fail, applied only at `finalize_settlement` if unchallenged.
    pub claimed_passed: bool,
    /// Operator-claimed virtual profit (micro-USD), bound to the transcript by `prove_result_fault`.
    pub claimed_virtual_profit: i64,
    /// Unix time the fraud-proof window closes; payouts gate on `now > this` + status `Final`.
    pub settlement_window_end: i64,
    /// Who proved the fault (the `prove_*_fault` signer). `default()` until a fault is proven; the
    /// `dispute` program pays this address the slash bounty in `slash_settlement_fault`.
    pub fault_challenger: Pubkey,
    pub bump: u8,
    /// Caller-supplied purchase-instance discriminator (PDA seed only, no on-chain meaning) — lets a
    /// trader hold any number of challenges of the same (firm, account_size_tier, phase) at once, and
    /// forever after: `close_challenge` (rent reclaim on a terminal challenge) has no caller anywhere
    /// in this system, so without a nonce the PDA for a given (firm, trader, tier, phase) would be
    /// permanently occupied by the first-ever purchase, making every later purchase of that same size
    /// revert `AccountAlreadyInUse` (`Custom(0)`) at `init` — see MASTER_FIXES CHK-9/CHK-10/CHK-11.
    pub nonce: u64,
}

/// One covered batch epoch (H-2 §3b). `prefix` is the running sum of `trade_count` over earlier covered
/// epochs, so global step index `i` maps to local trade `i - prefix` of this challenge's run, which sits
/// at `base_offset` inside the firm-hour batch root (BATCH-ROOT-SCOPE-1).
#[derive(AnchorSerialize, AnchorDeserialize, InitSpace, Clone, Copy, PartialEq, Eq, Debug)]
pub struct CoverageEntry {
    pub epoch: u64,
    pub prefix: u64,
    pub trade_count: u32,
    /// Index of this challenge's first leaf within the firm-hour root — proven against
    /// `BatchRoot.segment_root` when the entry was appended, never asserted by the keeper.
    pub base_offset: u32,
}

/// Settlement coverage (H-2 §3b) — the ordered set of real batch epochs a settlement draws from, built
/// by `add_coverage_epoch` (each proven to exist) and consumed by `propose_settlement`
/// (`covered_trade_count == transcript_len - 1`). Seeds: ["coverage", challenge].
#[account]
#[derive(InitSpace)]
pub struct SettlementCoverage {
    pub challenge: Pubkey,
    /// Σ trade_count over all covered epochs (== transcript_len - 1, enforced at propose).
    pub covered_trade_count: u64,
    /// Running prefix while building (equals `covered_trade_count` once built).
    pub running_prefix: u64,
    /// Last appended epoch — enforces strictly-increasing order.
    pub last_epoch: u64,
    /// Locked once `propose_settlement` consumes it.
    pub finalized: bool,
    #[max_len(64)]
    pub entries: Vec<CoverageEntry>,
    pub bump: u8,
}

/// EPOCH-RECOMPOSE-DRIFT-1 — a corrective, per-(challenge, epoch) top-up for a challenge that could not
/// possibly have been in that epoch's primary `BatchRoot`, minted after the fact (`started_at` postdates
/// `BatchRoot.committed_at`). One-shot (`init`-only, never mutated) — same immutability guarantee as
/// `BatchRoot` itself. Seeds: ["supp_segment", challenge, epoch].
#[account]
#[derive(InitSpace)]
pub struct SupplementalSegment {
    pub firm: Pubkey,
    pub challenge: Pubkey,
    pub epoch: u64,
    pub trade_count: u32,
    pub committed_at: i64,
    pub bump: u8,
}

/// Verifiable-settlement lifecycle (F5). Funds may only move when `Final`.
#[derive(AnchorSerialize, AnchorDeserialize, InitSpace, Clone, Copy, PartialEq, Eq, Debug)]
pub enum SettlementStatus {
    /// No settlement proposed yet (challenge still running, or legacy `settle_challenge` path).
    Unsettled,
    /// A transcript-committed settlement is proposed and inside its fraud-proof window.
    Provisional,
    /// The window closed with no fault proven; the result is applied and payable.
    Final,
    /// A fraud proof voided the proposed settlement; nothing is owed.
    Faulted,
}

/// Which kind of fraud was proven (telemetry on the `SettlementFaulted` event).
pub enum FaultKind {
    /// A single state transition `apply_step` was mis-computed.
    Transition = 0,
    /// The transcript was consistent but the claimed result didn't match `derive_outcome`.
    Result = 1,
    /// The committed genesis (leaf 0) wasn't `genesis_state(rules)` — a fabricated starting equity.
    Genesis = 2,
    /// A committed step was a FABRICATED trade — it didn't match the real committed batch tick at the
    /// slot it claimed (H-2 input-authenticity fault).
    Input = 3,
    /// A committed step was welded to a provenance OTHER than its positional slot — including a
    /// non-existent epoch (H-2 §3b provenance fault). Closes the last fabrication escape.
    Provenance = 4,
}

/// Arguments to `propose_settlement` — the operator's transcript commitments + claimed result.
#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct ProposeSettlementArgs {
    pub transcript_root: [u8; 32],
    pub step_root: [u8; 32],
    /// H-2 Option A: root over `bound_step_leaf` leaves (batch-welded); the input/provenance fault
    /// proofs verify against this. May be `[0u8;32]` for a legacy/scalar commitment (those simply
    /// aren't input/provenance-faultable).
    pub bound_step_root: [u8; 32],
    pub final_state_hash: [u8; 32],
    pub transcript_len: u32,
    pub claimed_passed: bool,
    pub virtual_profit: i64,
    pub payout_sol_owed: u64,
    pub payout_firma_owed: u64,
    pub settlement_risk_tier: RiskTier,
}

/// Arguments to `propose_funded_withdrawal` (DEC-62). The keeper's commitments + claimed amounts.
/// `genesis_state_hash` is checked against the genesis the CHAIN derives, so committing it is an act of
/// agreement, not of choice.
#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct ProposeWithdrawalArgs {
    pub transcript_root: [u8; 32],
    pub step_root: [u8; 32],
    pub bound_step_root: [u8; 32],
    pub genesis_state_hash: [u8; 32],
    pub final_state_hash: [u8; 32],
    pub transcript_len: u32,
    /// GROSS withdrawn (micro-USD). Bound at propose: `<= withdrawable_profit(final_state, rules)`.
    pub gross_micro: i64,
    /// The trader's cut (micro-USD). Bound at propose: `<= gross × trader_split_bps / 10_000`.
    pub trader_micro: i64,
    /// `trader_micro` in lamports at the Pyth settlement price (keeper-struck — SETTLE-SOL-PRICE-1).
    pub amount_sol_owed: u64,
    pub settlement_risk_tier: RiskTier,
}

/// Rule parameters locked at purchase — immutable for the life of the challenge (§19).
#[derive(AnchorSerialize, AnchorDeserialize, InitSpace, Clone)]
pub struct RulesSnapshot {
    pub profit_target_bps: u16,
    pub max_daily_loss_bps: u16,
    pub max_total_drawdown_bps: u16,
    pub is_trailing_drawdown: bool,
    pub starting_balance: u64,
    pub min_trading_days: u8,
    pub max_trading_days: u8,
    pub max_open_positions: u8,
    pub max_position_size_bps: u16,
    pub max_leverage_bps: u16,
    pub allow_weekend_holding: bool,
    pub allow_news_trading: bool,
    pub base_spread_bps: u16,
    pub dynamic_spread: bool,
    pub simulate_slippage: bool,
    pub min_hold_time_seconds: u16,
    pub max_price_age_seconds: u8,
    pub consistency_rule_bps: u16,
    pub max_single_trade_profit_bps: u16,
    pub daily_variance_gate: bool,
    pub trader_split_bps: u16,
    pub stakeholder_split_bps: u16,
}

#[derive(AnchorSerialize, AnchorDeserialize, InitSpace, Clone, Copy, PartialEq, Eq, Debug)]
pub enum ChallengeStatus {
    Active,
    Passed,
    Failed,
    Claimed,
}

/// Evaluation phase (mirrors the off-chain `ChallengePhase`). 1-step: Phase1 → Funded;
/// 2-step: Phase1 → Phase2 → Funded. Discriminants 0/1/2 are the `phase` seed byte.
#[derive(AnchorSerialize, AnchorDeserialize, InitSpace, Clone, Copy, PartialEq, Eq, Debug)]
pub enum ChallengePhase {
    Phase1,
    Phase2,
    Funded,
}

impl ChallengePhase {
    /// Map the `phase` seed byte to the enum (0 Phase1, 1 Phase2, 2 Funded); None if out of range.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(ChallengePhase::Phase1),
            1 => Some(ChallengePhase::Phase2),
            2 => Some(ChallengePhase::Funded),
            _ => None,
        }
    }
}

/// Mirrors `firm::RiskTier` (each program owns its types until a shared crate exists).
#[derive(AnchorSerialize, AnchorDeserialize, InitSpace, Clone, Copy, PartialEq, Eq, Debug)]
pub enum RiskTier {
    Healthy,
    Caution,
    Warning,
    Critical,
}

#[event]
pub struct ChallengePurchased {
    pub challenge: Pubkey,
    pub firm: Pubkey,
    pub trader: Pubkey,
    pub account_size_tier: u8,
    pub phase: u8,
    pub started_at: i64,
}

/// EPOCH-RECOMPOSE-DRIFT-1 — emitted by `commit_supplemental_segment`, so a supplemental commit is as
/// visible/auditable off-chain as a primary `BatchRootCommitted` is.
#[event]
pub struct SupplementalSegmentCommitted {
    pub challenge: Pubkey,
    pub firm: Pubkey,
    pub epoch: u64,
    pub trade_count: u32,
    pub committed_at: i64,
}

#[event]
pub struct ChallengeSettled {
    pub challenge: Pubkey,
    pub passed: bool,
    pub virtual_profit: i64,
    pub payout_firma_owed: u64,
    pub settled_at: i64,
}

/// Emitted when a daily staking giveaway is fulfilled on-chain by `grant_giveaway_challenge`. The
/// `day_index` + `draw_seed` tie the grant back to the off-chain provably-fair draw, so anyone can
/// replay the draw for that day and confirm this `winner` is the one it selected.
#[event]
pub struct GiveawayChallengeGranted {
    pub challenge: Pubkey,
    pub firm: Pubkey,
    pub winner: Pubkey,
    pub account_size_tier: u8,
    pub phase: u8,
    /// Day index (days since unix epoch) of the draw that selected the winner.
    pub day_index: u32,
    /// Low 64 bits of the provably-fair draw seed — ties this grant to the verifiable off-chain draw.
    pub draw_seed: u64,
    pub granted_at: i64,
}

#[event]
pub struct IntegrityHoldSet {
    pub challenge: Pubkey,
    pub held: bool,
}

#[event]
pub struct IntegrityFaultProven {
    pub challenge: Pubkey,
    pub flags: u32,
}

#[event]
pub struct SettlementProposed {
    pub challenge: Pubkey,
    pub transcript_root: [u8; 32],
    pub transcript_len: u32,
    pub claimed_passed: bool,
    pub virtual_profit: i64,
    pub window_end: i64,
}

#[event]
pub struct SettlementFaulted {
    pub challenge: Pubkey,
    /// `FaultKind` discriminant (0 = transition, 1 = result).
    pub kind: u8,
    /// The step index a transition fault was proven at (0 for a result fault).
    pub index: u32,
    /// Who proved the fault — the slash bounty recipient (`dispute.slash_settlement_fault`).
    pub challenger: Pubkey,
}

/// F2 heal audit trail — emitted by `repair_settlement_authority` when a challenge's authority is
/// re-pointed to the firm's live keeper. `previous` is the old (unpayable) authority; `current` the
/// keeper it now points at. A no-op repair (already pointing at the keeper) emits `previous == current`.
#[event]
pub struct SettlementAuthorityRepaired {
    pub challenge: Pubkey,
    pub firm: Pubkey,
    pub previous: Pubkey,
    pub current: Pubkey,
}

#[error_code]
pub enum ChallengeError {
    #[msg("account size tier out of range (0..=7)")]
    InvalidTier,
    #[msg("phase out of range (0 Phase1, 1 Phase2, 2 Funded)")]
    InvalidPhase,
    #[msg("only a funded challenge can owe a payout")]
    PayoutBeforeFunded,
    #[msg("trader_split_bps + stakeholder_split_bps exceeds 10000")]
    InvalidSplit,
    #[msg("challenge is not active")]
    NotActive,
    #[msg("challenge is not in a terminal state")]
    NotTerminal,
    #[msg("signer is not the settlement authority")]
    Unauthorized,
    #[msg("arithmetic overflow")]
    MathOverflow,
    #[msg("a settlement has already been proposed for this challenge")]
    SettlementAlreadyProposed,
    #[msg("transcript must contain at least one state")]
    EmptyTranscript,
    #[msg("settlement is not in the Provisional state")]
    NotProvisional,
    #[msg("the fraud-proof window has closed")]
    SettlementWindowClosed,
    #[msg("the fraud-proof window is still open")]
    SettlementWindowOpen,
    #[msg("the submitted proof does not demonstrate a fault")]
    FaultNotProven,
    #[msg("no integrity hold is active on this challenge")]
    NoIntegrityHold,
    #[msg("fault proof must reveal at least one flag")]
    EmptyEvidence,
    #[msg("evidence includes a behavioural flag — not provable as advisory-only")]
    BehaviouralEvidence,
    #[msg("revealed flags do not match the committed evidence root")]
    EvidenceRootMismatch,
    #[msg("settlement coverage is finalized — no more epochs can be added")]
    CoverageFinalized,
    #[msg("settlement coverage is full (MAX_COVERAGE_EPOCHS)")]
    CoverageFull,
    #[msg("coverage epochs must be added in strictly increasing order")]
    CoverageEpochOrder,
    #[msg("transcript_len - 1 must equal the coverage's total trade count")]
    CoverageCountMismatch,
    #[msg("the (base_offset, trade_count) segment is not the one committed for this challenge in this epoch's batch root")]
    CoverageSegmentInvalid,
    // ── DEC-62: funded withdrawals ──
    #[msg("only a FUNDED challenge can take a withdrawal")]
    WithdrawalNotFunded,
    #[msg("withdrawal cycle does not match the on-chain counter")]
    WithdrawalCycleMismatch,
    #[msg("cycle > 0 requires the previous cycle's withdrawal account")]
    WithdrawalPrevMissing,
    #[msg("the previous withdrawal is not Final")]
    WithdrawalPrevNotFinal,
    #[msg("revealed previous final state does not match the committed hash")]
    WithdrawalPrevStateMismatch,
    #[msg("committed genesis is not the honest rebaseline of the previous cycle")]
    WithdrawalGenesisMismatch,
    #[msg("revealed final state does not match the committed hash")]
    WithdrawalFinalStateMismatch,
    #[msg("a breached account cannot withdraw")]
    WithdrawalBreached,
    #[msg("claim exceeds withdrawable profit or the locked trader split")]
    WithdrawalOverclaim,
    #[msg("this cycle's coverage overlaps a previous cycle's trades")]
    WithdrawalEpochOverlap,
    #[msg("amount must be greater than zero")]
    ZeroAmount,
    // ── SETTLEMENT-WITHDRAWAL-GAP-1: propose_settlement's withdrawal-cycle awareness ──
    #[msg("a withdrawal cycle is Provisional (its fraud window hasn't closed) — settle after it resolves")]
    SettlementBlockedByOpenWithdrawal,
    // ENVELOPE-1 (see envelope.rs) — the locked rules must sit inside the published legal envelope.
    #[msg("profit target above the maximum sellable evaluation difficulty")]
    ProfitTargetTooHigh,
    #[msg("daily-loss cap tighter than the minimum sellable")]
    DailyLossTooTight,
    #[msg("total drawdown tighter than the minimum sellable")]
    DrawdownTooTight,
    #[msg("daily-loss cap exceeds the total drawdown (incoherent rules)")]
    DailyLossExceedsDrawdown,
    #[msg("minimum-trading-days gate above the maximum sellable")]
    MinTradingDaysTooHigh,
    #[msg("consistency cap harsher than the minimum sellable")]
    ConsistencyTooTight,
    #[msg("single-trade profit cap harsher than the minimum sellable")]
    SingleTradeCapTooTight,
    #[msg("minimum hold time above the maximum sellable")]
    MinHoldTooLong,
    #[msg("trader profit split below the minimum sellable")]
    TraderSplitTooLow,
    // ── F2 (SETTLEMENT-AUTH-MINT-GUARD) ──
    #[msg("settlement_authority must equal the firm's risk_engine_authority (would be unpayable)")]
    SettlementAuthorityMismatch,
    #[msg("firm account is not a valid firm-program FirmState")]
    FirmAccountInvalid,
    // ── EPOCH-RECOMPOSE-DRIFT-1: supplemental segments for a late-provisioned challenge ──
    #[msg("this challenge existed before its epoch's batch root was committed — it could have been in the primary segment, so a supplemental one is not eligible")]
    SupplementalNotEligible,
    #[msg("a supplemental segment must cover at least one trade")]
    EmptySupplementalSegment,
    #[msg("epoch argument does not match the supplemental segment's committed epoch")]
    SupplementalEpochMismatch,
}

#[cfg(test)]
mod integrity_fault_tests {
    use super::*;

    fn hx(b: &[u8; 32]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    // Parity vector shared with the off-chain TS test (onchain-evidence.test.ts):
    // DEVICE_CLUSTER(code 3) HIGH(2) 0.8 + CROSS_ACCOUNT_CORRELATION(code 2) MEDIUM(1) 0.35.
    #[test]
    fn evidence_root_matches_offchain_vector() {
        let flags = vec![
            FaultFlag { code: 3, severity: 2, score: 800_000 },
            FaultFlag { code: 2, severity: 1, score: 350_000 },
        ];
        let root = integrity_evidence_root(&flags);
        assert_eq!(
            hx(&root),
            "236998e3b1dbd45619efd3062fb78c5a23ad0235dfab5d297c4165f6771e5ded"
        );
        // Order-independent.
        let reordered = vec![
            FaultFlag { code: 2, severity: 1, score: 350_000 },
            FaultFlag { code: 3, severity: 2, score: 800_000 },
        ];
        assert_eq!(integrity_evidence_root(&reordered), root);
    }

    #[test]
    fn single_multifirm_flag_vector() {
        let flags = vec![FaultFlag { code: 1, severity: 2, score: 900_000 }];
        assert_eq!(
            hx(&integrity_evidence_root(&flags)),
            "f3b564694a43347e6444f5b979532e3305d01c97e8dad7317f7d26276cfef742"
        );
    }

    #[test]
    fn advisory_codes_are_identity_detectors() {
        for c in [1u8, 2, 3, 4] {
            assert!(ADVISORY_CODES.contains(&c));
        }
        assert!(!ADVISORY_CODES.contains(&10)); // COPY_TRADE (behavioural)
    }
}
