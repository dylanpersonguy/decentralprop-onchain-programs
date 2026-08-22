// Anchor's own `#[program]` macro expansion still calls the deprecated `AccountInfo::realloc` —
// nothing in application code to fix here. Crate-level (not on the `#[program] mod` item) because
// an outer `#[allow]` on the mod doesn't reach the macro's generated sibling items under `-D warnings`.
#![allow(deprecated)]

use anchor_lang::prelude::*;
use anchor_lang::solana_program::hash::hash as sha256;
use anchor_lang::system_program;

declare_id!("3BTD73nYinwAf3pWR1Fw5H9avyq7dYopVARkmYi9245H");

// Gated on `no-entrypoint` (implied by the `cpi` feature): this program is a path-dependency of
// `firm` for CPI, and an unconditional security_txt! would emit a duplicate `.security.txt`
// link section when this crate is compiled into that binary.
#[cfg(not(feature = "no-entrypoint"))]
solana_security_txt::security_txt! {
    name: "DecentralProp: Dispute",
    project_url: "https://decentralprop.com",
    contacts: "email:info@decentralprop.com",
    policy: "https://github.com/dylanpersonguy/decentralprop-onchain-programs/blob/main/SECURITY.md",
    preferred_languages: "en",
    source_code: "https://github.com/dylanpersonguy/decentralprop-onchain-programs/tree/main/programs/dispute",
    source_release: "devnet"
}

/// DecentralProp `dispute_program` (architecture §6 step 6, §7, §10).
///
/// Closes the trust-model loop. A trader who believes a trade was omitted from the
/// platform's evaluation submits a Merkle inclusion proof; the program verifies
/// **on-chain** that the trade's committed tick hash resolves to the immutable
/// `BatchRoot` for that epoch. The hashing exactly mirrors `@decentralprop/provably-fair`
/// (`leaf:`/`node:` domain-separated SHA-256 over hex strings), so a proof built by
/// the off-chain prover / `pf-verifier` verifies identically here.
///
/// A verified proof opens a dispute with a 7-day resolution deadline. The platform
/// posts an off-chain re-evaluation via `resolve_dispute`; if it never does,
/// `force_dispute_resolution` lets the trader settle in their favour after the
/// deadline — bounding how long the platform can stall (§10). `OperatorStake` backs
/// honest resolution: a proven-fraudulent outcome records a slash.
#[program]
pub mod dispute {
    use super::*;

    /// Firm owner stakes lamports (≥ 2 SOL) to back honest dispute resolution (§10).
    pub fn init_operator_stake(ctx: Context<InitOperatorStake>, amount: u64) -> Result<()> {
        require!(amount >= MIN_OPERATOR_STAKE_LAMPORTS, DisputeError::StakeTooLow);
        system_program::transfer(
            CpiContext::new(
                ctx.accounts.system_program.to_account_info(),
                system_program::Transfer {
                    from: ctx.accounts.firm_owner.to_account_info(),
                    to: ctx.accounts.operator_stake.to_account_info(),
                },
            ),
            amount,
        )?;
        let stake = &mut ctx.accounts.operator_stake;
        stake.firm = ctx.accounts.firm.key();
        stake.staked_lamports = amount;
        stake.slash_count = 0;
        stake.bump = ctx.bumps.operator_stake;
        Ok(())
    }

    /// Create an EMPTY operator bond (`staked_lamports = 0`) for the self-funded path (§10/§14).
    /// PERMISSIONLESS — the keeper calls this once per firm before the firm program's
    /// `fund_operator_bond` crank can deposit unwrapped fee SOL into the PDA (which must exist +
    /// be dispute-owned first). Idempotent by construction: the `init` fails if the bond already
    /// exists, so the keeper only calls it when the account is missing. No minimum is required —
    /// the bond fills over time from the 1% treasury earmark; `sync_bond` credits the balance.
    pub fn init_bond_shell(ctx: Context<InitBondShell>) -> Result<()> {
        let stake = &mut ctx.accounts.operator_stake;
        stake.firm = ctx.accounts.firm.key();
        stake.staked_lamports = 0;
        stake.slash_count = 0;
        stake.suspended = false;
        stake.bump = ctx.bumps.operator_stake;
        Ok(())
    }

    /// Reconcile `staked_lamports` to the OperatorStake PDA's ACTUAL native balance (§10/§14).
    /// PERMISSIONLESS. After `fund_operator_bond` deposits unwrapped fee SOL into the PDA, this sets
    /// `staked_lamports = balance − rent_exempt_minimum` (the truly-seizable amount). Consistent with
    /// the manual `init_operator_stake` / `add_stake` paths (there too `balance − rent == staked`), so
    /// it's a safe general "resync" — and it only ever reflects SOL physically present, so a caller
    /// can't inflate the bond beyond what was actually deposited.
    pub fn sync_bond(ctx: Context<SyncBond>) -> Result<()> {
        let ai = ctx.accounts.operator_stake.to_account_info();
        let rent_min = Rent::get()?.minimum_balance(ai.data_len());
        let actual = ai.lamports().saturating_sub(rent_min);
        let stake = &mut ctx.accounts.operator_stake;
        stake.staked_lamports = actual;
        emit!(OperatorBondSynced { firm: stake.firm, staked_lamports: actual });
        Ok(())
    }

    /// Open a dispute by proving a tick is a member of the committed batch root.
    /// Verification is fully on-chain; an invalid proof reverts and no dispute opens.
    pub fn open_dispute(
        ctx: Context<OpenDispute>,
        epoch: u64,
        tick_hash: String,
        proof: Vec<MerkleStep>,
    ) -> Result<()> {
        // The committed root for this firm/epoch (owned & PDA-checked against batch program).
        let expected = to_hex(&ctx.accounts.batch_root.merkle_root);
        require!(
            recompute_root(&tick_hash, &proof) == expected,
            DisputeError::InvalidProof
        );

        let now = Clock::get()?.unix_timestamp;
        let dispute = &mut ctx.accounts.dispute;
        dispute.challenge = ctx.accounts.challenge.key();
        dispute.trader = ctx.accounts.trader.key();
        dispute.firm = ctx.accounts.challenge.firm;
        dispute.epoch = epoch;
        dispute.kind = DisputeKind::TradeInclusion;
        dispute.status = DisputeStatus::Open;
        dispute.opened_at = now;
        dispute.resolution_deadline = now
            .checked_add(DISPUTE_RESOLUTION_WINDOW)
            .ok_or(DisputeError::MathOverflow)?;
        dispute.bump = ctx.bumps.dispute;

        emit!(DisputeOpened {
            dispute: dispute.key(),
            challenge: dispute.challenge,
            trader: dispute.trader,
            epoch,
            resolution_deadline: dispute.resolution_deadline,
        });
        Ok(())
    }

    /// Post the off-chain re-evaluation outcome. Signed by the firm's settlement
    /// authority. `upheld = true` means the trader was right (platform was wrong): a
    /// proven-fraudulent outcome **slashes the full operator stake 50/50 — winning
    /// trader / DecentralProp dispute fund** (§7/§10), records the slash, and (the SOL
    /// payout itself is drawn from the insurance fund by `firm.settle_dispute_payout`).
    pub fn resolve_dispute(ctx: Context<ResolveDispute>, upheld: bool) -> Result<()> {
        require!(ctx.accounts.dispute.status == DisputeStatus::Open, DisputeError::NotOpen);
        // T-2: this operator-posted path is for trade-inclusion disputes. A timeout dispute is
        // cured by the operator settling (challenge program), or force-resolved after its window.
        require!(
            ctx.accounts.dispute.kind == DisputeKind::TradeInclusion,
            DisputeError::WrongDisputeKind
        );

        if upheld {
            let slashed = ctx.accounts.operator_stake.staked_lamports;
            ctx.accounts.distribute_slash(slashed)?;
            let stake = &mut ctx.accounts.operator_stake;
            stake.staked_lamports = 0;
            stake.slash_count = stake.slash_count.saturating_add(1);
            stake.suspended = true;
            ctx.accounts.dispute.status = DisputeStatus::ResolvedUpheld;
            emit!(OperatorSlashed {
                firm: ctx.accounts.dispute.firm,
                amount: slashed,
                slash_count: ctx.accounts.operator_stake.slash_count,
            });
            emit!(OperatorSuspended {
                firm: ctx.accounts.dispute.firm,
                slash_count: ctx.accounts.operator_stake.slash_count,
            });
        } else {
            ctx.accounts.dispute.status = DisputeStatus::ResolvedRejected;
        }

        emit!(DisputeResolved { dispute: ctx.accounts.dispute.key(), upheld, forced: false });
        Ok(())
    }

    /// After the 7-day deadline with no posted resolution, the trader forces the
    /// dispute resolved in their favour — bounding platform stalling (§10).
    pub fn force_dispute_resolution(ctx: Context<ForceResolve>) -> Result<()> {
        let now = Clock::get()?.unix_timestamp;
        let dispute = &mut ctx.accounts.dispute;
        require!(dispute.status == DisputeStatus::Open, DisputeError::NotOpen);
        // T-2: timeout disputes force-resolve via `force_unsettled_timeout_resolution`, which also
        // re-checks the challenge is still `Unsettled` (the double-pay guard). Keep them off this path.
        require!(dispute.kind == DisputeKind::TradeInclusion, DisputeError::WrongDisputeKind);
        require!(now > dispute.resolution_deadline, DisputeError::DeadlineNotReached);

        dispute.status = DisputeStatus::ForceResolved;
        emit!(DisputeResolved {
            dispute: dispute.key(),
            upheld: true,
            forced: true,
        });
        Ok(())
    }

    /// T-2 — open a dispute WITHOUT a batch root when the operator abandoned settlement. This is the
    /// lever that makes indefinite stall impossible. Gated on the challenge still being `Unsettled`
    /// past `expires_at + SETTLEMENT_GRACE_WINDOW` (the deadline is derived from the challenge's own
    /// `expires_at`, so no challenge-account migration is needed). The operator cures by proposing a
    /// settlement (challenge program); if it never does, `force_unsettled_timeout_resolution` after
    /// the resolution window lets the trader collect from insurance (guardian co-signed, capped).
    pub fn open_unsettled_timeout_dispute(
        ctx: Context<OpenUnsettledTimeoutDispute>,
    ) -> Result<()> {
        let now = Clock::get()?.unix_timestamp;
        let challenge = &ctx.accounts.challenge;
        require!(
            challenge.settlement_status == challenge::SettlementStatus::Unsettled,
            DisputeError::SettlementAlreadyStarted
        );
        // V2-4 entitlement gate: only a FUNDED account can be owed a withdrawal. A Phase-1/Phase-2
        // evaluation left unsettled owes nothing (passing a phase is an off-chain advance, not a
        // payout), so a timeout dispute on a non-funded challenge has no legitimate insurance claim.
        // This eliminates the non-funded abuse class on-chain; the remaining "funded loser" case stays
        // adjudicated by the now-independent (V2-1) guardian at `settle_dispute_payout`.
        require!(
            challenge.phase == challenge::ChallengePhase::Funded,
            DisputeError::NotFundedPhase
        );
        // Effective expiry. `expires_at == 0` is the "unlimited duration" sentinel (max_trading_days
        // == 0) — there is no natural expiry, so we cap the settlement deadline at
        // `started_at + UNLIMITED_EVAL_SETTLEMENT_CAP` instead. Without this, `0 + grace` is ~1970 and
        // `now >` it is always true, letting a trader on an unlimited eval open a timeout dispute
        // immediately.
        let effective_expiry = if challenge.expires_at != 0 {
            challenge.expires_at
        } else {
            challenge
                .started_at
                .checked_add(UNLIMITED_EVAL_SETTLEMENT_CAP)
                .ok_or(DisputeError::MathOverflow)?
        };
        let deadline = effective_expiry
            .checked_add(SETTLEMENT_GRACE_WINDOW)
            .ok_or(DisputeError::MathOverflow)?;
        require!(now > deadline, DisputeError::SettlementDeadlineNotReached);

        let dispute = &mut ctx.accounts.dispute;
        dispute.challenge = challenge.key();
        dispute.trader = ctx.accounts.trader.key();
        dispute.firm = challenge.firm;
        dispute.epoch = 0; // no epoch — a liveness dispute, not trade-inclusion
        dispute.kind = DisputeKind::UnsettledTimeout;
        dispute.status = DisputeStatus::Open;
        dispute.opened_at = now;
        dispute.resolution_deadline = now
            .checked_add(DISPUTE_RESOLUTION_WINDOW)
            .ok_or(DisputeError::MathOverflow)?;
        dispute.bump = ctx.bumps.dispute;

        emit!(DisputeOpened {
            dispute: dispute.key(),
            challenge: dispute.challenge,
            trader: dispute.trader,
            epoch: 0,
            resolution_deadline: dispute.resolution_deadline,
        });
        Ok(())
    }

    /// T-2 — force-resolve an unsettled-timeout dispute in the trader's favour after its resolution
    /// deadline, IF the operator STILL hasn't settled. The `Unsettled` re-check is the double-pay
    /// guard: a cured (settled) challenge is paid via the settlement path, never here. Once
    /// `ForceResolved`, `firm.settle_dispute_payout` draws the capped amount from insurance under the
    /// guardian co-sign (the challenge is `Unsettled`, not `Faulted`, so it takes the guardian path).
    pub fn force_unsettled_timeout_resolution(
        ctx: Context<ForceUnsettledTimeout>,
    ) -> Result<()> {
        let now = Clock::get()?.unix_timestamp;
        require!(
            ctx.accounts.dispute.kind == DisputeKind::UnsettledTimeout,
            DisputeError::WrongDisputeKind
        );
        require!(ctx.accounts.dispute.status == DisputeStatus::Open, DisputeError::NotOpen);
        require!(
            now > ctx.accounts.dispute.resolution_deadline,
            DisputeError::DeadlineNotReached
        );
        require!(
            ctx.accounts.challenge.settlement_status == challenge::SettlementStatus::Unsettled,
            DisputeError::SettlementAlreadyStarted
        );

        let dispute = &mut ctx.accounts.dispute;
        dispute.status = DisputeStatus::ForceResolved;
        emit!(DisputeResolved {
            dispute: dispute.key(),
            upheld: true,
            forced: true,
        });
        Ok(())
    }

    /// Top up an operator's stake without clearing the suspended flag. Useful for partial slashes
    /// (§10 scenarios where the slash was less than the full bond) — restores the bond amount
    /// without requiring a full re-application. If the stake was fully zeroed and suspended, call
    /// `reinstate_operator_stake` instead.
    pub fn add_stake(ctx: Context<AddStake>, amount: u64) -> Result<()> {
        require!(amount > 0, DisputeError::StakeTooLow);
        system_program::transfer(
            CpiContext::new(
                ctx.accounts.system_program.to_account_info(),
                system_program::Transfer {
                    from: ctx.accounts.firm_owner.to_account_info(),
                    to: ctx.accounts.operator_stake.to_account_info(),
                },
            ),
            amount,
        )?;
        ctx.accounts.operator_stake.staked_lamports = ctx
            .accounts
            .operator_stake
            .staked_lamports
            .checked_add(amount)
            .ok_or(DisputeError::MathOverflow)?;
        Ok(())
    }

    /// Re-establish an operator's settlement authority after a slash event (`suspended = true`).
    ///
    /// Requires a fresh deposit of at least `MIN_OPERATOR_STAKE_LAMPORTS`. Clears `suspended` so
    /// the off-chain keeper knows the operator has posted a new economic bond and may resume calling
    /// `propose_settlement`. The on-chain enforcement of `!suspended` in the challenge program is
    /// Phase 6.x — for now this is the off-chain signal that keepers must respect.
    pub fn reinstate_operator_stake(ctx: Context<ReinstateOperatorStake>, amount: u64) -> Result<()> {
        require!(
            ctx.accounts.operator_stake.suspended,
            DisputeError::NotSuspended
        );
        require!(amount >= MIN_OPERATOR_STAKE_LAMPORTS, DisputeError::StakeTooLow);
        system_program::transfer(
            CpiContext::new(
                ctx.accounts.system_program.to_account_info(),
                system_program::Transfer {
                    from: ctx.accounts.firm_owner.to_account_info(),
                    to: ctx.accounts.operator_stake.to_account_info(),
                },
            ),
            amount,
        )?;
        let stake = &mut ctx.accounts.operator_stake;
        stake.staked_lamports = stake
            .staked_lamports
            .checked_add(amount)
            .ok_or(DisputeError::MathOverflow)?;
        stake.suspended = false;
        emit!(OperatorReinstated {
            firm: stake.firm,
            staked_lamports: stake.staked_lamports,
            slash_count: stake.slash_count,
        });
        Ok(())
    }

    /// Slash a firm's operator stake for a PROVEN settlement fault (F5 — the economic teeth).
    /// Once `challenge.prove_settlement_fault` / `prove_result_fault` has voided a settlement
    /// (status `Faulted`), this pays the recorded fault-prover a bounty (`CHALLENGER_BOUNTY_BPS`)
    /// and the remainder to the DP dispute fund, then zeroes the stake. Permissionless; the
    /// per-challenge `settlement_slash` record PDA makes it a one-shot (no double slash). This is
    /// what makes the optimistic fraud-proof game incentive-compatible: a dishonest operator loses
    /// its bond, and the watchtower that caught the fraud is paid to run.
    pub fn slash_settlement_fault(ctx: Context<SlashSettlementFault>) -> Result<()> {
        require!(
            ctx.accounts.challenge.settlement_status == challenge::SettlementStatus::Faulted,
            DisputeError::SettlementNotFaulted
        );
        let firm = ctx.accounts.challenge.firm;
        let challenge_key = ctx.accounts.challenge.key();
        let challenger = ctx.accounts.challenge.fault_challenger;
        let slashed = ctx.accounts.operator_stake.staked_lamports;
        require!(slashed > 0, DisputeError::NothingToSlash);

        ctx.accounts.distribute_fault_slash(slashed)?;

        let new_count = {
            let stake = &mut ctx.accounts.operator_stake;
            stake.staked_lamports = 0;
            stake.slash_count = stake.slash_count.saturating_add(1);
            stake.suspended = true;
            stake.slash_count
        };

        let bump = ctx.bumps.slash_record;
        let rec = &mut ctx.accounts.slash_record;
        rec.challenge = challenge_key;
        rec.challenger = challenger;
        rec.amount = slashed;
        rec.bump = bump;

        emit!(SettlementFaultSlashed {
            firm,
            challenge: challenge_key,
            challenger,
            amount: slashed,
            slash_count: new_count,
        });
        emit!(OperatorSuspended { firm, slash_count: new_count });
        Ok(())
    }

    /// Initialise the dispute config (M-2). One-time; gated to the dispute program's **upgrade
    /// authority** (front-run-proof). Records the canonical `dp_dispute_fund` so the slash-distribution
    /// instructions can no longer pay the protocol's cut to a caller-chosen account.
    pub fn init_dispute_config(ctx: Context<InitDisputeConfig>, dp_dispute_fund: Pubkey) -> Result<()> {
        let cfg = &mut ctx.accounts.dispute_config;
        cfg.admin = ctx.accounts.upgrade_authority.key();
        cfg.dp_dispute_fund = dp_dispute_fund;
        cfg.bump = ctx.bumps.dispute_config;
        emit!(DisputeConfigSet { admin: cfg.admin, dp_dispute_fund });
        Ok(())
    }

    /// Update the canonical DP dispute fund (M-2). Gated to the config `admin`.
    pub fn set_dispute_fund(ctx: Context<SetDisputeFund>, dp_dispute_fund: Pubkey) -> Result<()> {
        let cfg = &mut ctx.accounts.dispute_config;
        cfg.dp_dispute_fund = dp_dispute_fund;
        emit!(DisputeConfigSet { admin: cfg.admin, dp_dispute_fund });
        Ok(())
    }
}

/// Minimum operator stake — 50 SOL (§10).
///
/// Raised from 2 SOL: 2 SOL (~$300) was economically trivial relative to a firm's
/// payout exposure. 50 SOL provides meaningful economic teeth for the fraud-proof game
/// and makes settlement-fault attacks expensive to run repeatedly.
pub const MIN_OPERATOR_STAKE_LAMPORTS: u64 = 50_000_000_000;
/// On-chain re-evaluation deadline after a dispute opens — 7 days (§10).
pub const DISPUTE_RESOLUTION_WINDOW: i64 = 604_800;
/// T-2: grace period after a challenge's `expires_at` within which the operator must propose a
/// settlement. Past `expires_at + this`, an `Unsettled` challenge can be timeout-disputed without a
/// batch root — closing the indefinite-stall gap. 7 days.
pub const SETTLEMENT_GRACE_WINDOW: i64 = 604_800;
/// T-2: for an unlimited-duration eval (`max_trading_days == 0` → `expires_at == 0`), the effective
/// settlement deadline is `started_at + this`. Generous (180 days) so it never fires on a legitimately
/// long-running open-ended eval, but still bounds the stall instead of leaving it infinite.
pub const UNLIMITED_EVAL_SETTLEMENT_CAP: i64 = 180 * 86_400;
/// Share of a settlement-fault slash paid to the fault-prover (50%); the rest goes to the DP dispute
/// fund. Large enough to make running a public watchtower worth the gas + effort.
pub const CHALLENGER_BOUNTY_BPS: u64 = 5_000;

/// One step of a Merkle membership proof — mirrors `MerkleProofStep` in
/// `@decentralprop/provably-fair` (sibling hex hash + which side it sits on).
#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct MerkleStep {
    pub sibling: String,
    pub sibling_on_right: bool,
}

fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

fn sha256_hex(input: &str) -> String {
    to_hex(&sha256(input.as_bytes()).to_bytes())
}

/// Domain-separated leaf/node hashing — must match provably-fair byte-for-byte.
fn hash_leaf(data: &str) -> String {
    sha256_hex(&format!("leaf:{data}"))
}

fn hash_pair(left: &str, right: &str) -> String {
    sha256_hex(&format!("node:{left}{right}"))
}

/// Recompute the Merkle root from a tick hash and its proof path.
fn recompute_root(tick_hash: &str, proof: &[MerkleStep]) -> String {
    let mut h = hash_leaf(tick_hash);
    for step in proof {
        h = if step.sibling_on_right {
            hash_pair(&h, &step.sibling)
        } else {
            hash_pair(&step.sibling, &h)
        };
    }
    h
}

#[derive(Accounts)]
pub struct InitOperatorStake<'info> {
    #[account(mut)]
    pub firm_owner: Signer<'info>,

    /// CHECK: the firm this stake backs — PDA seed only.
    pub firm: UncheckedAccount<'info>,

    #[account(
        init,
        payer = firm_owner,
        space = 8 + OperatorStake::INIT_SPACE,
        seeds = [b"operator_stake", firm.key().as_ref()],
        bump
    )]
    pub operator_stake: Account<'info, OperatorStake>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct AddStake<'info> {
    #[account(mut)]
    pub firm_owner: Signer<'info>,

    /// CHECK: the firm this stake backs — PDA seed for the stake account.
    pub firm: UncheckedAccount<'info>,

    #[account(
        mut,
        seeds = [b"operator_stake", firm.key().as_ref()],
        bump = operator_stake.bump,
    )]
    pub operator_stake: Account<'info, OperatorStake>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct InitBondShell<'info> {
    /// Permissionless payer of the account rent (keeper/cranker). Grants no privilege — the shell is
    /// created empty (`staked_lamports = 0`) and can only ever be funded by real SOL deposits.
    #[account(mut)]
    pub payer: Signer<'info>,

    /// CHECK: the firm this bond backs — PDA seed only.
    pub firm: UncheckedAccount<'info>,

    #[account(
        init,
        payer = payer,
        space = 8 + OperatorStake::INIT_SPACE,
        seeds = [b"operator_stake", firm.key().as_ref()],
        bump
    )]
    pub operator_stake: Account<'info, OperatorStake>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct SyncBond<'info> {
    #[account(
        mut,
        seeds = [b"operator_stake", operator_stake.firm.as_ref()],
        bump = operator_stake.bump,
    )]
    pub operator_stake: Account<'info, OperatorStake>,
}

#[derive(Accounts)]
pub struct ReinstateOperatorStake<'info> {
    #[account(mut)]
    pub firm_owner: Signer<'info>,

    /// CHECK: the firm this stake backs — PDA seed for the stake account.
    pub firm: UncheckedAccount<'info>,

    #[account(
        mut,
        seeds = [b"operator_stake", firm.key().as_ref()],
        bump = operator_stake.bump,
    )]
    pub operator_stake: Account<'info, OperatorStake>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(epoch: u64)]
pub struct OpenDispute<'info> {
    #[account(mut)]
    pub trader: Signer<'info>,

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
        seeds::program = challenge::ID,
        constraint = challenge.trader == trader.key() @ DisputeError::Unauthorized,
    )]
    pub challenge: Account<'info, challenge::ChallengeState>,

    #[account(
        seeds = [b"batch", challenge.firm.as_ref(), &epoch.to_le_bytes()],
        bump = batch_root.bump,
        seeds::program = batch::ID,
        constraint = batch_root.firm == challenge.firm @ DisputeError::FirmMismatch,
    )]
    pub batch_root: Account<'info, batch::BatchRoot>,

    #[account(
        init,
        payer = trader,
        space = 8 + DisputeState::INIT_SPACE,
        seeds = [b"dispute", challenge.key().as_ref()],
        bump
    )]
    pub dispute: Account<'info, DisputeState>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct ResolveDispute<'info> {
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
        seeds::program = challenge::ID,
        address = dispute.challenge,
        constraint = challenge.settlement_authority == authority.key() @ DisputeError::Unauthorized,
    )]
    pub challenge: Account<'info, challenge::ChallengeState>,

    #[account(
        mut,
        seeds = [b"dispute", dispute.challenge.as_ref()],
        bump = dispute.bump,
    )]
    pub dispute: Account<'info, DisputeState>,

    #[account(
        mut,
        seeds = [b"operator_stake", dispute.firm.as_ref()],
        bump = operator_stake.bump,
    )]
    pub operator_stake: Account<'info, OperatorStake>,

    /// The winning trader — receives 50% of the slashed stake. Must match the dispute.
    /// CHECK: validated by address against the dispute's recorded trader.
    #[account(mut, address = dispute.trader @ DisputeError::Unauthorized)]
    pub trader: UncheckedAccount<'info>,

    /// Canonical dispute config — binds the DP dispute fund (M-2).
    #[account(seeds = [b"dispute_config"], bump = dispute_config.bump)]
    pub dispute_config: Account<'info, DisputeConfig>,

    /// DecentralProp dispute fund — receives 50% of the slashed stake. M-2: address-bound to config.
    /// CHECK: validated by address against the canonical `dispute_config.dp_dispute_fund`.
    #[account(mut, address = dispute_config.dp_dispute_fund @ DisputeError::Unauthorized)]
    pub dp_dispute_fund: UncheckedAccount<'info>,
}

impl<'info> ResolveDispute<'info> {
    /// Distribute a slashed operator stake 50/50: winning trader / DP dispute fund.
    /// Lamports are moved directly from the program-owned stake account (the staked
    /// amount sits above the account's rent-exempt minimum).
    fn distribute_slash(&self, amount: u64) -> Result<()> {
        if amount == 0 {
            return Ok(());
        }
        let (trader_cut, dp_cut) = (amount - amount / 2, amount / 2);
        let stake_ai = self.operator_stake.to_account_info();
        **stake_ai.try_borrow_mut_lamports()? -= amount;
        **self.trader.to_account_info().try_borrow_mut_lamports()? += trader_cut;
        **self.dp_dispute_fund.to_account_info().try_borrow_mut_lamports()? += dp_cut;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct ForceResolve<'info> {
    #[account(mut, address = dispute.trader)]
    pub trader: Signer<'info>,

    #[account(
        mut,
        seeds = [b"dispute", dispute.challenge.as_ref()],
        bump = dispute.bump,
    )]
    pub dispute: Account<'info, DisputeState>,
}

/// T-2 — open a timeout dispute. Same shape as `OpenDispute` but with NO `batch_root`: the entry
/// condition is operator abandonment (`challenge.settlement_status == Unsettled` past the deadline),
/// verified from the challenge account, not a Merkle proof.
#[derive(Accounts)]
pub struct OpenUnsettledTimeoutDispute<'info> {
    #[account(mut)]
    pub trader: Signer<'info>,

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
        seeds::program = challenge::ID,
        constraint = challenge.trader == trader.key() @ DisputeError::Unauthorized,
    )]
    pub challenge: Account<'info, challenge::ChallengeState>,

    #[account(
        init,
        payer = trader,
        space = 8 + DisputeState::INIT_SPACE,
        seeds = [b"dispute", challenge.key().as_ref()],
        bump
    )]
    pub dispute: Account<'info, DisputeState>,

    pub system_program: Program<'info, System>,
}

/// T-2 — force-resolve a timeout dispute. Carries the challenge account so the instruction can
/// re-check it is still `Unsettled` (the double-pay guard against an operator who cured late).
#[derive(Accounts)]
pub struct ForceUnsettledTimeout<'info> {
    #[account(mut, address = dispute.trader)]
    pub trader: Signer<'info>,

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
        seeds::program = challenge::ID,
        address = dispute.challenge,
    )]
    pub challenge: Account<'info, challenge::ChallengeState>,

    #[account(
        mut,
        seeds = [b"dispute", dispute.challenge.as_ref()],
        bump = dispute.bump,
    )]
    pub dispute: Account<'info, DisputeState>,
}

#[derive(Accounts)]
pub struct SlashSettlementFault<'info> {
    /// Permissionless crank (pays the record rent) — anyone may trigger the slash on a Faulted settlement.
    #[account(mut)]
    pub cranker: Signer<'info>,

    /// The faulted challenge (typed `Account` ⇒ Anchor verifies it is owned by the challenge program).
    #[account(
        constraint = challenge.settlement_status == challenge::SettlementStatus::Faulted
            @ DisputeError::SettlementNotFaulted,
    )]
    pub challenge: Account<'info, challenge::ChallengeState>,

    #[account(
        mut,
        seeds = [b"operator_stake", challenge.firm.as_ref()],
        bump = operator_stake.bump,
        constraint = operator_stake.firm == challenge.firm @ DisputeError::FirmMismatch,
    )]
    pub operator_stake: Account<'info, OperatorStake>,

    /// The recorded fault-prover — receives the bounty.
    /// CHECK: address-validated against the challenge's recorded `fault_challenger`.
    #[account(mut, address = challenge.fault_challenger @ DisputeError::Unauthorized)]
    pub challenger: UncheckedAccount<'info>,

    /// Canonical dispute config — binds the DP dispute fund (M-2). Previously a permissionless cranker
    /// could send the non-bounty 50% of a fault slash to any account; now it must be the configured fund.
    #[account(seeds = [b"dispute_config"], bump = dispute_config.bump)]
    pub dispute_config: Account<'info, DisputeConfig>,

    /// DecentralProp dispute fund — receives the remainder. M-2: address-bound to config.
    /// CHECK: validated by address against the canonical `dispute_config.dp_dispute_fund`.
    #[account(mut, address = dispute_config.dp_dispute_fund @ DisputeError::Unauthorized)]
    pub dp_dispute_fund: UncheckedAccount<'info>,

    /// One-shot guard: `init` fails if this challenge was already slashed.
    #[account(
        init,
        payer = cranker,
        space = 8 + SettlementSlashRecord::INIT_SPACE,
        seeds = [b"settlement_slash", challenge.key().as_ref()],
        bump
    )]
    pub slash_record: Account<'info, SettlementSlashRecord>,

    pub system_program: Program<'info, System>,
}

impl<'info> SlashSettlementFault<'info> {
    /// Move the slashed lamports out of the program-owned stake: bounty → fault-prover, rest → DP.
    fn distribute_fault_slash(&self, amount: u64) -> Result<()> {
        if amount == 0 {
            return Ok(());
        }
        let bounty = ((amount as u128 * CHALLENGER_BOUNTY_BPS as u128) / 10_000) as u64;
        let dp_cut = amount - bounty;
        let stake_ai = self.operator_stake.to_account_info();
        **stake_ai.try_borrow_mut_lamports()? -= amount;
        **self.challenger.to_account_info().try_borrow_mut_lamports()? += bounty;
        **self.dp_dispute_fund.to_account_info().try_borrow_mut_lamports()? += dp_cut;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct InitDisputeConfig<'info> {
    #[account(mut)]
    pub upgrade_authority: Signer<'info>,

    /// The dispute program's `ProgramData` — `upgrade_authority_address` MUST equal the signer.
    #[account(
        seeds = [crate::ID.as_ref()],
        bump,
        seeds::program = anchor_lang::solana_program::bpf_loader_upgradeable::ID,
        constraint = program_data.upgrade_authority_address == Some(upgrade_authority.key())
            @ DisputeError::Unauthorized,
    )]
    pub program_data: Account<'info, ProgramData>,

    #[account(
        init,
        payer = upgrade_authority,
        space = 8 + DisputeConfig::INIT_SPACE,
        seeds = [b"dispute_config"],
        bump
    )]
    pub dispute_config: Account<'info, DisputeConfig>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct SetDisputeFund<'info> {
    pub admin: Signer<'info>,

    #[account(
        mut,
        seeds = [b"dispute_config"],
        bump = dispute_config.bump,
        constraint = dispute_config.admin == admin.key() @ DisputeError::Unauthorized,
    )]
    pub dispute_config: Account<'info, DisputeConfig>,
}

/// Canonical dispute config (M-2). Seeds: ["dispute_config"]. Binds the DP dispute-fund destination.
#[account]
#[derive(InitSpace)]
pub struct DisputeConfig {
    pub admin: Pubkey,
    pub dp_dispute_fund: Pubkey,
    pub bump: u8,
}

/// Per-challenge dispute record. Seeds: ["dispute", challenge].
#[account]
#[derive(InitSpace)]
pub struct DisputeState {
    pub challenge: Pubkey,
    pub trader: Pubkey,
    pub firm: Pubkey,
    pub epoch: u64,
    /// How this dispute was entered (T-2). `open_dispute` → `TradeInclusion`;
    /// `open_unsettled_timeout_dispute` → `UnsettledTimeout`.
    pub kind: DisputeKind,
    pub status: DisputeStatus,
    pub opened_at: i64,
    pub resolution_deadline: i64,
    pub bump: u8,
}

/// Per-firm operator stake (§10). Seeds: ["operator_stake", firm].
#[account]
#[derive(InitSpace)]
pub struct OperatorStake {
    pub firm: Pubkey,
    pub staked_lamports: u64,
    pub slash_count: u8,
    /// Set to `true` after any slash event. The operator MUST call `reinstate_operator_stake`
    /// (re-depositing ≥ MIN_OPERATOR_STAKE_LAMPORTS) to clear this flag before settlements are
    /// trusted again. Off-chain keepers should refuse to call `propose_settlement` while
    /// `suspended = true`; on-chain enforcement in `challenge_program` is Phase 6.x.
    pub suspended: bool,
    pub bump: u8,
}

/// One-shot record that a challenge's settlement fault was slashed. Seeds: ["settlement_slash", challenge].
#[account]
#[derive(InitSpace)]
pub struct SettlementSlashRecord {
    pub challenge: Pubkey,
    pub challenger: Pubkey,
    pub amount: u64,
    pub bump: u8,
}

#[derive(AnchorSerialize, AnchorDeserialize, InitSpace, Clone, Copy, PartialEq, Eq, Debug)]
pub enum DisputeStatus {
    Open,
    ResolvedUpheld,
    ResolvedRejected,
    ForceResolved,
}

/// How a dispute was entered. Trade-inclusion disputes prove a tick against a committed batch root;
/// unsettled-timeout disputes (T-2) need no root — they open when the operator blew the settlement
/// deadline. The kind gates which force-resolution / resolve path applies.
#[derive(AnchorSerialize, AnchorDeserialize, InitSpace, Clone, Copy, PartialEq, Eq, Debug)]
pub enum DisputeKind {
    TradeInclusion,
    UnsettledTimeout,
}

#[event]
pub struct DisputeConfigSet {
    pub admin: Pubkey,
    pub dp_dispute_fund: Pubkey,
}

#[event]
pub struct DisputeOpened {
    pub dispute: Pubkey,
    pub challenge: Pubkey,
    pub trader: Pubkey,
    pub epoch: u64,
    pub resolution_deadline: i64,
}

#[event]
pub struct DisputeResolved {
    pub dispute: Pubkey,
    pub upheld: bool,
    pub forced: bool,
}

#[event]
pub struct OperatorSlashed {
    pub firm: Pubkey,
    pub amount: u64,
    pub slash_count: u8,
}

#[event]
pub struct SettlementFaultSlashed {
    pub firm: Pubkey,
    pub challenge: Pubkey,
    pub challenger: Pubkey,
    pub amount: u64,
    pub slash_count: u8,
}

/// Emitted when a slash sets `suspended = true` on the operator stake. Off-chain
/// keepers MUST stop calling `propose_settlement` for this firm until `OperatorReinstated`
/// is observed (i.e., until the operator calls `reinstate_operator_stake`).
#[event]
pub struct OperatorSuspended {
    pub firm: Pubkey,
    pub slash_count: u8,
}

/// Emitted when `reinstate_operator_stake` successfully re-bonds the operator.
#[event]
pub struct OperatorReinstated {
    pub firm: Pubkey,
    pub staked_lamports: u64,
    pub slash_count: u8,
}

#[event]
pub struct OperatorBondSynced {
    pub firm: Pubkey,
    pub staked_lamports: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn step(sibling: &str, sibling_on_right: bool) -> MerkleStep {
        MerkleStep { sibling: sibling.to_string(), sibling_on_right }
    }

    /// T-2: an abandoned payout can now stall at most `expires_at + grace` (to open the timeout
    /// dispute) + the resolution window (to force-resolve) — a bounded ~14-day worst case after the
    /// evaluation expires, versus the pre-fix unbounded stall. Guards the constants from drift and
    /// documents the invariant that the deadline is derived from the challenge's own `expires_at`.
    #[test]
    fn t2_windows_bound_the_worst_case_stall() {
        assert_eq!(SETTLEMENT_GRACE_WINDOW, 604_800); // 7 days
        assert_eq!(DISPUTE_RESOLUTION_WINDOW, 604_800); // 7 days
        let expires_at: i64 = 1_000_000;
        let open_deadline = expires_at + SETTLEMENT_GRACE_WINDOW; // timeout dispute becomes openable
        let force_deadline = open_deadline + DISPUTE_RESOLUTION_WINDOW; // then force-resolvable
        assert!(force_deadline > expires_at);
        assert_eq!(force_deadline - expires_at, 1_209_600); // 14 days, bounded
    }

    /// T-2 unlimited-eval guard: when `expires_at == 0` (max_trading_days == 0), the deadline must be
    /// derived from `started_at + UNLIMITED_EVAL_SETTLEMENT_CAP`, NOT from 0 (which would make the
    /// timeout dispute openable immediately). Mirrors the `effective_expiry` branch in the instruction.
    #[test]
    fn t2_unlimited_eval_deadline_is_bounded_not_immediate() {
        let started_at: i64 = 1_700_000_000; // a realistic recent unix time
        let expires_at: i64 = 0; // unlimited sentinel
        let effective_expiry = if expires_at != 0 { expires_at } else { started_at + UNLIMITED_EVAL_SETTLEMENT_CAP };
        let deadline = effective_expiry + SETTLEMENT_GRACE_WINDOW;
        // Not openable at/just after start — bounded ~187 days out, not ~1970.
        assert!(deadline > started_at + 180 * 86_400);
        assert_eq!(UNLIMITED_EVAL_SETTLEMENT_CAP, 15_552_000); // 180 days
    }

    /// Cross-language vector: root + proof generated by `@decentralprop/provably-fair`
    /// (leaves = hashLeaf(["t0".."t4"]), proof for index 1). The on-chain verifier
    /// MUST reproduce the exact same root, or off-chain proofs would never verify.
    #[test]
    fn recompute_root_matches_provably_fair() {
        let proof = vec![
            step("ebdd1abeb12730492ad0c77a54bbcc7b816dbe6d6ca7e440c5e9c694b212e80d", false),
            step("11cb40aa3d0a8c6882509b99fb85346c85279eb1c05c91e65bc5331b9a5618e8", true),
            step("eee2a2e355e9170e1b07e66066733aa55bb9dc1a0a4406f378379e32013834ea", true),
        ];
        let expected = "aadc29691eee46143abfdda0d575bf75a3dc404e9705ad84ac48f58253ba7b2e";
        assert_eq!(recompute_root("t1", &proof), expected);
    }

    #[test]
    fn tampered_tick_hash_fails() {
        let proof = vec![step(
            "ebdd1abeb12730492ad0c77a54bbcc7b816dbe6d6ca7e440c5e9c694b212e80d",
            false,
        )];
        let expected = "aadc29691eee46143abfdda0d575bf75a3dc404e9705ad84ac48f58253ba7b2e";
        assert_ne!(recompute_root("t999", &proof), expected);
    }

    #[test]
    fn hex_encoding_is_lowercase_padded() {
        assert_eq!(to_hex(&[0u8, 15u8, 255u8]), "000fff");
    }
}

#[error_code]
pub enum DisputeError {
    #[msg("Merkle proof does not resolve to the committed batch root")]
    InvalidProof,
    #[msg("batch root firm does not match the challenge firm")]
    FirmMismatch,
    #[msg("signer is not authorized for this action")]
    Unauthorized,
    #[msg("dispute is not open")]
    NotOpen,
    #[msg("resolution deadline has not been reached")]
    DeadlineNotReached,
    #[msg("operator stake is below the 50 SOL minimum")]
    StakeTooLow,
    #[msg("arithmetic overflow")]
    MathOverflow,
    #[msg("challenge settlement is not in the Faulted state")]
    SettlementNotFaulted,
    #[msg("operator stake is already empty — nothing to slash")]
    NothingToSlash,
    #[msg("operator is not suspended — use add_stake to top up instead")]
    NotSuspended,
    #[msg("challenge settlement already started — not eligible for an unsettled-timeout dispute")]
    SettlementAlreadyStarted,
    #[msg("settlement deadline (expires_at + grace) has not been reached")]
    SettlementDeadlineNotReached,
    #[msg("wrong dispute kind for this instruction")]
    WrongDisputeKind,
    #[msg("only a funded challenge can open a timeout dispute — a non-funded phase owes no withdrawal")]
    NotFundedPhase,
}
