// Anchor's own `#[program]` macro expansion still calls the deprecated `AccountInfo::realloc` —
// nothing in application code to fix here. Crate-level (not on the `#[program] mod` item) because
// an outer `#[allow]` on the mod doesn't reach the macro's generated sibling items under `-D warnings`.
#![allow(deprecated)]

use anchor_lang::prelude::*;

declare_id!("29NK1pYubMLCRDi17YUGF3iMoFYyeYhxoSi6PakKdFLx");

// Gated on `no-entrypoint` (implied by the `cpi` feature): this program is a path-dependency of
// `challenge` and `dispute` for CPI, and an unconditional security_txt! would emit a duplicate
// `.security.txt` link section when this crate is compiled into their binaries.
#[cfg(not(feature = "no-entrypoint"))]
solana_security_txt::security_txt! {
    name: "DecentralProp: Batch",
    project_url: "https://decentralprop.com",
    contacts: "email:info@decentralprop.com",
    policy: "https://github.com/dylanpersonguy/decentralprop-onchain-programs/blob/main/SECURITY.md",
    preferred_languages: "en",
    source_code: "https://github.com/dylanpersonguy/decentralprop-onchain-programs/tree/main/programs/batch",
    source_release: "devnet"
}

/// DecentralProp `batch_program` (architecture §10, §19, §25).
///
/// Receives hourly Merkle roots from the off-chain Batch Commit Service and stores
/// them in append-only `BatchRoot` PDAs — immutable trade evidence. A trader later
/// proves a fill is included in a committed root via the `dispute_program`.
///
/// `MAX_COMMIT_DELAY` is enforced on-chain: a root for a given hour epoch must land
/// within 2 hours of that epoch closing. A late commit reverts, leaving the epoch
/// without a root — which the protocol treats as "disputes unsupported for that
/// epoch" (§7, §25), exactly the documented liveness failure mode.
///
/// ── What this window is, and what it is NOT (BATCH-COMMIT-SERVICE-DEAD-1, 2026-07-16) ──
///
/// `MAX_COMMIT_DELAY` is a **liveness guarantee for the trader**: your hour's evidence is on-chain
/// within 2h of that hour closing, or it never is. It is **not** a deadline on a payout.
///
/// It was read as one for a year, because the Batch Commit Service named above **has never run**.
/// It exists (`keepers/src/batch-commit/`) and nothing composes it, so the only thing ever calling
/// `commit_batch_root` was the settlement keeper's propose path, committing an epoch's root lazily
/// **at payout time**. That inverts the design: evidence produced by a consumer, when it happens to
/// be needed, instead of by a producer on the trade timeline. And since `propose_*` requires FULL
/// coverage of a transcript spanning every trade in the cycle, the propose had to land within 2h of
/// the **earliest** trade it covered — so a funded trader whose trading spanned more than ~2 hours,
/// or an evaluation on its mandatory 4-day minimum, could never be settled or paid at all. Two
/// devnet payouts succeeded because their whole cycle happened to sit inside the ~70 min before
/// propose; the path had never been asked a real question.
///
/// The rule this leaves behind: **roots are written by the hourly producer, on the trade timeline,
/// and every consumer READS them.** A propose that finds no root for an epoch it needs must fail —
/// it must never create the evidence it is about to rely on.
#[program]
pub mod batch {
    use super::*;

    /// Initialise the cluster-wide batch config (H-1 fix). One-time; gated to the batch program's
    /// **upgrade authority** (the deployer / platform multisig) so it cannot be front-run — this is the
    /// root of trust that authorises who may commit trade-evidence roots. Records the `admin` (rotation
    /// authority) and the initial authorised `committer` (the hourly batch-commit service key).
    pub fn init_batch_config(ctx: Context<InitBatchConfig>, committer: Pubkey) -> Result<()> {
        let cfg = &mut ctx.accounts.batch_config;
        cfg.admin = ctx.accounts.upgrade_authority.key();
        cfg.committer = committer;
        cfg.bump = ctx.bumps.batch_config;
        emit!(BatchCommitterSet { admin: cfg.admin, committer });
        Ok(())
    }

    /// Rotate the authorised committer (H-1). Gated to the config `admin`.
    pub fn set_batch_committer(ctx: Context<SetBatchCommitter>, committer: Pubkey) -> Result<()> {
        let cfg = &mut ctx.accounts.batch_config;
        cfg.committer = committer;
        emit!(BatchCommitterSet { admin: cfg.admin, committer });
        Ok(())
    }

    /// Commit the Merkle root for one hourly epoch. Append-only: the `init`
    /// constraint makes a second commit for the same (firm, epoch) fail.
    ///
    /// H-1 fix: the `committer` MUST equal the `BatchConfig.committer` (the authorised batch-commit
    /// service). Previously the committer was any signer, so anyone could front-run the keeper with a
    /// bogus root for an epoch (`init` one-shot) and permanently censor that hour's dispute evidence.
    pub fn commit_batch_root(
        ctx: Context<CommitBatchRoot>,
        epoch: u64,
        merkle_root: [u8; 32],
        segment_root: [u8; 32],
        trade_count: u32,
    ) -> Result<()> {
        let now = Clock::get()?.unix_timestamp;
        let (epoch_start, epoch_end) = epoch_window(epoch)?;

        require!(now >= epoch_start, BatchError::FutureEpoch);
        let deadline = epoch_end
            .checked_add(MAX_COMMIT_DELAY)
            .ok_or(BatchError::MathOverflow)?;
        require!(now <= deadline, BatchError::CommitWindowElapsed);

        let root = &mut ctx.accounts.batch_root;
        root.firm = ctx.accounts.firm.key();
        root.epoch = epoch;
        root.merkle_root = merkle_root;
        root.segment_root = segment_root;
        root.committed_at = now;
        root.trade_count = trade_count;
        root.bump = ctx.bumps.batch_root;

        emit!(BatchRootCommitted {
            firm: root.firm,
            epoch,
            merkle_root,
            segment_root,
            committed_at: now,
            trade_count,
        });
        Ok(())
    }
}

/// Seconds in one epoch (one hour).
pub const SECONDS_PER_HOUR: i64 = 3_600;
/// Maximum delay after an epoch closes within which its root must be committed (2h).
pub const MAX_COMMIT_DELAY: i64 = 7_200;

/// Compute the [start, end) unix-second bounds of an hourly epoch.
fn epoch_window(epoch: u64) -> Result<(i64, i64)> {
    let start = i64::try_from(epoch)
        .ok()
        .and_then(|e| e.checked_mul(SECONDS_PER_HOUR))
        .ok_or(BatchError::MathOverflow)?;
    let end = start
        .checked_add(SECONDS_PER_HOUR)
        .ok_or(BatchError::MathOverflow)?;
    Ok((start, end))
}

#[derive(Accounts)]
#[instruction(epoch: u64)]
pub struct CommitBatchRoot<'info> {
    /// Keeper that submits and pays for the commitment — MUST be the authorised committer (H-1).
    #[account(mut, address = batch_config.committer @ BatchError::UnauthorizedCommitter)]
    pub committer: Signer<'info>,

    /// Cluster-wide batch config — binds the committer. Must be initialised (`init_batch_config`).
    #[account(seeds = [b"batch_config"], bump = batch_config.bump)]
    pub batch_config: Account<'info, BatchConfig>,

    /// CHECK: the firm this batch belongs to — used only as a PDA seed, never read.
    pub firm: UncheckedAccount<'info>,

    #[account(
        init,
        payer = committer,
        space = 8 + BatchRoot::INIT_SPACE,
        seeds = [b"batch", firm.key().as_ref(), &epoch.to_le_bytes()],
        bump
    )]
    pub batch_root: Account<'info, BatchRoot>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct InitBatchConfig<'info> {
    #[account(mut)]
    pub upgrade_authority: Signer<'info>,

    /// The batch program's `ProgramData` — its `upgrade_authority_address` MUST equal the signer, so
    /// only the deployer can establish the root of trust (front-run-proof).
    #[account(
        seeds = [crate::ID.as_ref()],
        bump,
        seeds::program = anchor_lang::solana_program::bpf_loader_upgradeable::ID,
        constraint = program_data.upgrade_authority_address == Some(upgrade_authority.key())
            @ BatchError::UnauthorizedCommitter,
    )]
    pub program_data: Account<'info, ProgramData>,

    #[account(
        init,
        payer = upgrade_authority,
        space = 8 + BatchConfig::INIT_SPACE,
        seeds = [b"batch_config"],
        bump
    )]
    pub batch_config: Account<'info, BatchConfig>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct SetBatchCommitter<'info> {
    pub admin: Signer<'info>,

    #[account(
        mut,
        seeds = [b"batch_config"],
        bump = batch_config.bump,
        constraint = batch_config.admin == admin.key() @ BatchError::UnauthorizedCommitter,
    )]
    pub batch_config: Account<'info, BatchConfig>,
}

/// Cluster-wide batch-commit authorisation (H-1). Seeds: ["batch_config"].
#[account]
#[derive(InitSpace)]
pub struct BatchConfig {
    /// Rotation authority (set to the upgrade authority at init).
    pub admin: Pubkey,
    /// The only key permitted to call `commit_batch_root`.
    pub committer: Pubkey,
    pub bump: u8,
}

/// Immutable per-(firm, epoch) Merkle-root commitment. Seeds: ["batch", firm, epoch].
#[account]
#[derive(InitSpace)]
pub struct BatchRoot {
    pub firm: Pubkey,
    pub epoch: u64,
    /// Merkle root over EVERY fill the firm's accounts closed in this epoch, as
    /// `hashLeaf(tick_preimage(tick))` leaves ordered **grouped by challenge** (challenge pubkey
    /// ascending, then close-time ascending within each challenge). The grouping is what makes each
    /// challenge's run contiguous, so a single `base_offset` locates it (see `segment_root`).
    pub merkle_root: [u8; 32],
    /// BATCH-ROOT-SCOPE-1 — Merkle root over this epoch's per-challenge **segments**, one leaf per
    /// challenge that traded: `hashLeaf(segment_preimage(challenge, base_offset, trade_count))`.
    ///
    /// This is the index that lets ONE firm-hour root serve MANY challenges. Without it the root was
    /// keyed per firm but filled with a single account's steps, so the first account to propose in a
    /// firm-hour permanently owned the root (`init` is one-shot) and every other account bound a
    /// `trade_count` that was not its own — a live corruption, not a theoretical one.
    ///
    /// It is load-bearing, not bookkeeping. A `base_offset` merely ASSERTED by the settlement keeper
    /// would let an operator weld its transcript to another account's contiguous run of real,
    /// profitable ticks — a fabrication every existing fault proof stays silent on, because each tick
    /// it points at is genuinely committed. Binding the offset to a root that had to land within
    /// `MAX_COMMIT_DELAY` (before the operator knows which account will withdraw, or what would be
    /// useful to steal) is precisely the property that window exists to buy.
    pub segment_root: [u8; 32],
    pub committed_at: i64,
    /// Total fills across ALL the firm's challenges this epoch (the leaf count of `merkle_root`).
    /// A consumer wanting ONE challenge's count must prove its segment — never read this.
    pub trade_count: u32,
    pub bump: u8,
}

#[event]
pub struct BatchRootCommitted {
    pub firm: Pubkey,
    pub epoch: u64,
    pub merkle_root: [u8; 32],
    pub segment_root: [u8; 32],
    pub committed_at: i64,
    pub trade_count: u32,
}

#[event]
pub struct BatchCommitterSet {
    pub admin: Pubkey,
    pub committer: Pubkey,
}

#[error_code]
pub enum BatchError {
    #[msg("epoch lies in the future — cannot commit a root before the epoch begins")]
    FutureEpoch,
    #[msg("commit window elapsed — MAX_COMMIT_DELAY exceeded for this epoch")]
    CommitWindowElapsed,
    #[msg("arithmetic overflow computing the epoch window")]
    MathOverflow,
    #[msg("signer is not the authorised batch committer (H-1)")]
    UnauthorizedCommitter,
}
