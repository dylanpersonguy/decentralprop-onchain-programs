// Anchor's own `#[program]` macro expansion still calls the deprecated `AccountInfo::realloc` —
// nothing in application code to fix here. Crate-level (not on the `#[program] mod` item) because
// an outer `#[allow]` on the mod doesn't reach the macro's generated sibling items under `-D warnings`.
#![allow(deprecated)]

use anchor_lang::prelude::*;
use anchor_spl::associated_token::{self, AssociatedToken};
use anchor_spl::token::{self, Mint, Token, TokenAccount, Transfer};

declare_id!("DeabUFkCGWWG9CHyDAeYMj9anLmguFacvBnMidpkkxBU");

// Gated on `no-entrypoint` (implied by the `cpi` feature): this program is a path-dependency of
// `firm` for CPI, and an unconditional security_txt! would emit a duplicate `.security.txt`
// link section when this crate is compiled into that binary.
#[cfg(not(feature = "no-entrypoint"))]
solana_security_txt::security_txt! {
    name: "DecentralProp: Bonding Curve",
    project_url: "https://decentralprop.com",
    contacts: "email:security@decentralprop.com",
    policy: "https://github.com/dylanpersonguy/decentralprop-onchain-programs/blob/main/SECURITY.md",
    preferred_languages: "en",
    source_code: "https://github.com/dylanpersonguy/decentralprop-onchain-programs/tree/main/programs/bonding_curve",
    source_release: "devnet"
}

/// DecentralProp `bonding_curve_program` (architecture §10, §16, §20).
///
/// A per-firm constant-product AMM (`x · y = k`) for pre-graduation $FIRMA trading,
/// where `x = real_sol + virtual_sol` and `y = firma_reserve`. The **virtual SOL**
/// seed sets a non-zero starting price without real capital and can never be
/// withdrawn (sells can only draw down `real_sol`). Every buy/sell charges 1%,
/// split 0.5% firm treasury / 0.5% DecentralProp platform. When `real_sol` reaches
/// the tier's graduation threshold, `graduate` is callable **permissionlessly** — the
/// threshold is checked on-chain, so no keeper trust is required.
///
/// VALUE-FLOW LAYER (Phase 3): `buy`/`sell`/`add_curve_reserve` now move real SPL
/// tokens via CPI between the trader's token accounts and the curve's PDA-owned SOL
/// and $FIRMA vaults; the constant-product math (unit-tested vs §20) is unchanged and
/// drives the transfer amounts. The $FIRMA in the curve vault is minted by
/// `firm.distribute_supply` (70% of supply since RESERVE-2026-07-11; was 90% before 20% was
/// carved to the minted Tier-2 reserve) — `firma_reserve` is the accounting mirror of that vault
/// balance.
///
/// Deferred (Phase 4.4): the Raydium migration + LP burn at `graduate`.
#[program]
pub mod bonding_curve {
    use super::*;

    /// Initialise a firm's curve and create its PDA-owned SOL + $FIRMA vaults.
    /// `firma_reserve` is the planned 70% allocation (was 90% pre-RESERVE-2026-07-11);
    /// `firm.distribute_supply` mints exactly that into `firma_vault` so accounting == vault balance.
    pub fn initialize_curve(
        ctx: Context<InitializeCurve>,
        virtual_sol: u64,
        firma_reserve: u64,
        graduation_threshold: u64,
    ) -> Result<()> {
        require!(virtual_sol > 0 && firma_reserve > 0, BondingCurveError::InvalidSeed);
        // Prevent operators from setting a graduation threshold so low that the curve
        // graduates before the Raydium payout path (Phase 4.4) is live. Any threshold
        // below MIN_GRADUATION_THRESHOLD_LAMPORTS would risk trapping payout obligations
        // post-graduation (all three payout instructions gate on !graduated).
        require!(
            graduation_threshold >= MIN_GRADUATION_THRESHOLD_LAMPORTS,
            BondingCurveError::ThresholdTooLow
        );
        let curve = &mut ctx.accounts.curve;
        curve.firm = ctx.accounts.firm.key();
        curve.sol_mint = ctx.accounts.sol_mint.key();
        curve.firma_mint = ctx.accounts.firma_mint.key();
        curve.sol_vault = ctx.accounts.sol_vault.key();
        curve.firma_vault = ctx.accounts.firma_vault.key();
        curve.virtual_sol = virtual_sol;
        curve.real_sol = 0;
        curve.firma_reserve = firma_reserve;
        curve.graduation_threshold = graduation_threshold;
        curve.graduated = false;
        curve.trading_live = false;
        curve.fee_bps = DEFAULT_FEE_BPS;
        curve.firm_fees_accrued = 0;
        curve.platform_fees_accrued = 0;
        curve.bump = ctx.bumps.curve;
        Ok(())
    }

    /// Flip `trading_live` — CPI'd EXCLUSIVELY from `firm.finalize_token_launch`, after that
    /// instruction has confirmed the deploy-fee escrow (if any) fully drained into this same
    /// curve. `firm_state` must sign via its own PDA seeds; only the `firm` program can produce
    /// that signature (Solana's PDA-signing rules), so no other caller can open trading early.
    pub fn open_trading(ctx: Context<OpenTrading>) -> Result<()> {
        require!(!ctx.accounts.curve.trading_live, BondingCurveError::TradingAlreadyLive);
        ctx.accounts.curve.trading_live = true;
        Ok(())
    }

    /// Buy $FIRMA with SOL. 1% fee on the input; the net swaps against the curve.
    /// Transfers: trader SOL → curve vault (net) + firm/platform (fee halves);
    /// curve $FIRMA vault → trader.
    pub fn buy(ctx: Context<Buy>, sol_in: u64, min_firma_out: u64) -> Result<()> {
        let curve = &ctx.accounts.curve;
        require!(!curve.graduated, BondingCurveError::Graduated);
        // Front-running guard: no buys until `open_trading` (CPI'd exclusively from
        // `firm.finalize_token_launch`) flips `trading_live`. RESERVE-3 (2026-07-11): the deploy escrow
        // was removed, so there is no longer any authorized pre-launch buyer — the gate rejects EVERY
        // buy before launch. See the field doc on `BondingCurve.trading_live`.
        require!(curve.trading_live, BondingCurveError::TradingNotLive);

        let fee = fee_amount(sol_in, curve.fee_bps);
        let net = sol_in.checked_sub(fee).ok_or(BondingCurveError::MathOverflow)?;
        let firma_out = buy_output(effective_sol(curve), curve.firma_reserve as u128, net as u128)
            .ok_or(BondingCurveError::MathOverflow)?;
        require!(firma_out >= min_firma_out, BondingCurveError::SlippageExceeded);
        require!(firma_out <= curve.firma_reserve, BondingCurveError::InsufficientLiquidity);

        let (firm_fee, platform_fee) = split_fee(fee);
        ctx.accounts.collect_sol(net, firm_fee, platform_fee)?;
        ctx.accounts.pay_out_firma(firma_out)?;

        let curve = &mut ctx.accounts.curve;
        curve.real_sol = curve.real_sol.checked_add(net).ok_or(BondingCurveError::MathOverflow)?;
        curve.firma_reserve -= firma_out;
        record_fees(curve, firm_fee, platform_fee);

        emit!(Traded { firm: curve.firm, is_buy: true, sol: sol_in, firma: firma_out, fee });
        Ok(())
    }

    /// Sell $FIRMA for SOL. 1% fee on the gross output. Can only draw `real_sol` —
    /// the virtual seed is never withdrawable. Transfers: trader $FIRMA → curve vault;
    /// curve SOL vault → trader (net) + firm/platform (fee halves).
    pub fn sell(ctx: Context<Sell>, firma_in: u64, min_sol_out: u64) -> Result<()> {
        let curve = &ctx.accounts.curve;
        require!(!curve.graduated, BondingCurveError::Graduated);

        let gross = sell_output(effective_sol(curve), curve.firma_reserve as u128, firma_in as u128)
            .ok_or(BondingCurveError::MathOverflow)?;
        require!(gross <= curve.real_sol, BondingCurveError::InsufficientLiquidity);
        let fee = fee_amount(gross, curve.fee_bps);
        let net_out = gross.checked_sub(fee).ok_or(BondingCurveError::MathOverflow)?;
        require!(net_out >= min_sol_out, BondingCurveError::SlippageExceeded);

        let (firm_fee, platform_fee) = split_fee(fee);
        ctx.accounts.take_in_firma(firma_in)?;
        ctx.accounts.pay_out_sol(net_out, firm_fee, platform_fee)?;

        let curve = &mut ctx.accounts.curve;
        curve.real_sol -= gross;
        curve.firma_reserve =
            curve.firma_reserve.checked_add(firma_in).ok_or(BondingCurveError::MathOverflow)?;
        record_fees(curve, firm_fee, platform_fee);

        emit!(Traded { firm: curve.firm, is_buy: false, sol: net_out, firma: firma_in, fee });
        Ok(())
    }

    /// Add real SOL reserve directly (pre-graduation LP fee allocation from challenge
    /// fees, §17). Increases `k` and accelerates graduation. Moves SOL into the vault.
    pub fn add_curve_reserve(ctx: Context<AddReserve>, amount: u64) -> Result<()> {
        require!(!ctx.accounts.curve.graduated, BondingCurveError::Graduated);
        token::transfer(
            CpiContext::new(
                ctx.accounts.token_program.to_account_info(),
                Transfer {
                    from: ctx.accounts.source_sol.to_account_info(),
                    to: ctx.accounts.sol_vault.to_account_info(),
                    authority: ctx.accounts.depositor.to_account_info(),
                },
            ),
            amount,
        )?;
        let curve = &mut ctx.accounts.curve;
        curve.real_sol =
            curve.real_sol.checked_add(amount).ok_or(BondingCurveError::MathOverflow)?;
        emit!(ReserveAdded { firm: curve.firm, amount, real_sol: curve.real_sol });
        Ok(())
    }

    /// Graduate: migrate the curve's real reserves into a **Raydium CP-Swap** pool and lock the LP in
    /// the (protocol-owned) curve PDA. Permissionless crank; threshold verified on-chain (§10).
    ///
    /// GATED by the `graduation` Cargo feature (off in normal builds — see GRADUATION_ENABLED). The
    /// caller passes the 20 CP-Swap `initialize` accounts as `remaining_accounts` in the program's exact
    /// order (derived per RAYDIUM_GRADUATION.md). `creator` (remaining[0]) is this curve PDA, which signs
    /// via `invoke_signed`; `creator_token_0/1` are the curve's own vaults; `creator_lp_token` is
    /// constrained to be owned by the curve PDA → the LP is permanently locked in the protocol.
    ///
    /// **Self-funding:** the cranker fronts the native SOL the curve PDA needs for the CP-Swap
    /// fee/rent (a `System::transfer` to the curve PDA earlier in the same tx) and is reimbursed in
    /// wSOL from reserves here. **open_time**: the pool open timestamp (0 = open immediately).
    ///
    /// ⚠️  Enabling in production ALSO requires a post-graduation payout path — `execute_payout_buy` /
    /// `process_queued_payout` / `draw_universal` buy $FIRMA from the curve and gate on `!graduated`, so
    /// once reserves migrate they would strand. This CPI is necessary but NOT sufficient to go live.
    pub fn graduate<'info>(
        ctx: Context<'_, '_, '_, 'info, Graduate<'info>>,
        open_time: u64,
    ) -> Result<()> {
        require!(GRADUATION_ENABLED, BondingCurveError::GraduationDisabled);
        // Snapshot curve fields into locals — do not hold the Account borrow across the CPI.
        let (curve_key, firm, bump, sol_mint, firma_mint, sol_vault_key, firma_vault_key) = {
            let curve = &ctx.accounts.curve;
            require!(!curve.graduated, BondingCurveError::AlreadyGraduated);
            require!(curve.real_sol >= curve.graduation_threshold, BondingCurveError::ThresholdNotMet);
            (curve.key(), curve.firm, curve.bump, curve.sol_mint, curve.firma_mint, curve.sol_vault, curve.firma_vault)
        };

        let _ = (curve_key, sol_vault_key, firma_vault_key); // (used by the earlier PDA-creator design)

        // Raydium's `initialize` uses `creator` as the System-level rent/fee payer, and a PROGRAM-OWNED
        // PDA cannot be a System payer — so the curve PDA CANNOT be the creator. Instead the (permissionless)
        // cranker is the creator: the curve PDA moves its reserves into the cranker's token accounts
        // (creator_token_0/1) via invoke_signed, then the cranker creates the CP-Swap pool from them.
        //
        // The LP is minted to the cranker's ATA by the CPI below, then LOCKED into the curve-PDA-owned
        // vault in this same instruction (see the LP-LOCK block) — the cranker cannot withdraw the migrated
        // liquidity. The remaining production requirement is the post-graduation PAYOUT PATH (RAYDIUM_GRADUATION.md §5.1).
        let ra = ctx.remaining_accounts;
        require!(ra.len() == RAYDIUM_INIT_ACCOUNTS, BondingCurveError::BadRaydiumAccounts);
        require!(ra[0].key() == ctx.accounts.cranker.key(), BondingCurveError::BadRaydiumAccounts); // creator == cranker

        // Move the curve's reserves into the creator (cranker) token accounts, matched to Raydium's
        // token_0<token_1 ordering. The curve PDA authorises the transfers via invoke_signed.
        ctx.accounts.sol_vault.reload()?;
        ctx.accounts.firma_vault.reload()?;
        let (sol_amt, firma_amt) = (ctx.accounts.sol_vault.amount, ctx.accounts.firma_vault.amount);
        let sol_is_0 = sol_mint.as_ref() < firma_mint.as_ref();
        let (init0, init1) = if sol_is_0 { (sol_amt, firma_amt) } else { (firma_amt, sol_amt) };
        {
            let bumpv = [bump];
            let seeds = curve_signer(&firm, &bumpv);
            let (sol_dest, firma_dest) = if sol_is_0 { (ra[7].clone(), ra[8].clone()) } else { (ra[8].clone(), ra[7].clone()) };
            token::transfer(
                CpiContext::new_with_signer(ctx.accounts.token_program.to_account_info(),
                    Transfer { from: ctx.accounts.sol_vault.to_account_info(), to: sol_dest, authority: ctx.accounts.curve.to_account_info() },
                    &[&seeds]),
                sol_amt,
            )?;
            token::transfer(
                CpiContext::new_with_signer(ctx.accounts.token_program.to_account_info(),
                    Transfer { from: ctx.accounts.firma_vault.to_account_info(), to: firma_dest, authority: ctx.accounts.curve.to_account_info() },
                    &[&seeds]),
                firma_amt,
            )?;
        }

        // Build + invoke CP-Swap `initialize` (creator = cranker, who signs the outer tx → plain invoke).
        let mut data = Vec::with_capacity(8 + 24);
        data.extend_from_slice(&CPSWAP_INITIALIZE_DISCRIMINATOR);
        data.extend_from_slice(&init0.to_le_bytes());
        data.extend_from_slice(&init1.to_le_bytes());
        data.extend_from_slice(&open_time.to_le_bytes());
        const WRITABLE: [usize; 9] = [3, 6, 7, 8, 9, 10, 11, 12, 13];
        let metas: Vec<anchor_lang::solana_program::instruction::AccountMeta> = (0..RAYDIUM_INIT_ACCOUNTS)
            .map(|i| {
                let (signer, writable) = (i == 0, i == 0 || WRITABLE.contains(&i));
                if writable {
                    anchor_lang::solana_program::instruction::AccountMeta::new(ra[i].key(), signer)
                } else {
                    anchor_lang::solana_program::instruction::AccountMeta::new_readonly(ra[i].key(), signer)
                }
            })
            .collect();
        let ix = anchor_lang::solana_program::instruction::Instruction {
            program_id: ctx.accounts.cpmm_program.key(),
            accounts: metas,
            data,
        };
        let mut infos: Vec<AccountInfo> = ra.to_vec();
        infos.push(ctx.accounts.cpmm_program.to_account_info());
        infos.push(ctx.accounts.cranker.to_account_info());
        anchor_lang::solana_program::program::invoke(&ix, &infos)?;

        // ── LP-LOCK (production blocker #2, RAYDIUM_GRADUATION.md §5.2) ──
        // CP-Swap mints the pool LP to the CREATOR's ATA — here the cranker (a wallet). Left there, the
        // cranker could `withdraw` the pool and drain the migrated reserves. So, in this SAME instruction
        // (which the cranker signed), we create the curve-PDA-owned LP ATA and sweep the entire LP balance
        // into it. The curve program exposes NO instruction that transfers/burns from that vault, so the LP
        // is permanently locked in the protocol ("lock-not-burn": the reserves stay, DEX fees accrue to the
        // protocol-held position). A malicious cranker cannot skip this — it is inside `graduate`.
        let lp_mint_ai = ra[6].clone(); // pool_lp_mint (created by the CPI above)
        let creator_lp_ai = ra[9].clone(); // creator_lp_token = ATA(cranker, lp_mint) — where CP-Swap minted
        // Create the curve-owned LP ATA (idempotent; enforces it IS ATA(curve, lp_mint)). Cranker pays rent.
        associated_token::create_idempotent(CpiContext::new(
            ctx.accounts.associated_token_program.to_account_info(),
            associated_token::Create {
                payer: ctx.accounts.cranker.to_account_info(),
                associated_token: ctx.accounts.curve_lp_vault.to_account_info(),
                authority: ctx.accounts.curve.to_account_info(), // OWNER of the vault = curve PDA
                mint: lp_mint_ai.clone(),
                system_program: ctx.accounts.system_program.to_account_info(),
                token_program: ctx.accounts.token_program.to_account_info(),
            },
        ))?;
        // Sweep the full minted LP (cranker authorises the transfer out of its own ATA).
        let lp_amount = {
            let data = creator_lp_ai.try_borrow_data()?;
            TokenAccount::try_deserialize(&mut &data[..])?.amount
        };
        require!(lp_amount > 0, BondingCurveError::LpNotLocked);
        token::transfer(
            CpiContext::new(
                ctx.accounts.token_program.to_account_info(),
                Transfer {
                    from: creator_lp_ai,
                    to: ctx.accounts.curve_lp_vault.to_account_info(),
                    authority: ctx.accounts.cranker.to_account_info(),
                },
            ),
            lp_amount,
        )?;

        // Mark graduated — the reserves now live in the Raydium pool, LP locked in the curve PDA.
        let curve = &mut ctx.accounts.curve;
        curve.graduated = true;
        let (migrated_sol, migrated_firma) = (curve.real_sol, curve.firma_reserve);
        curve.real_sol = 0;
        curve.firma_reserve = 0;
        emit!(CurveGraduated { firm, real_sol: migrated_sol, firma_reserve: migrated_firma });
        Ok(())
    }
}

/// Default trade fee — 1% (§20).
pub const DEFAULT_FEE_BPS: u16 = 100;

/// Phase-gate: graduation is DISABLED by default and only compiled ON via the `graduation` Cargo
/// feature — so a normally-built `.so` (devnet/mainnet) can NEVER graduate, but an isolated
/// mainnet-fork test build (`cargo build-sbf --features graduation`) can prove the Raydium migration.
///
/// ⚠️  DO NOT deploy a `--features graduation` build to a shared cluster until the POST-GRADUATION
/// PAYOUT PATH exists: `execute_payout_buy` / `process_queued_payout` / `draw_universal` all gate on
/// `!graduated` and buy $FIRMA from the curve — once reserves migrate to Raydium those payouts strand.
/// The Raydium pool-create CPI (this feature) is necessary but NOT sufficient to enable in production.
pub const GRADUATION_ENABLED: bool = cfg!(feature = "graduation");

/// Minimum (dust-floor) graduation threshold — 80 SOL. A per-curve `graduation_threshold` below this
/// is rejected at `initialize_curve` to stop griefing/dust graduations. The real target (83 SOL, ≈
/// "this $FIRMA token has committed liquidity"; oracle-free, SOL-denominated — see RAYDIUM_GRADUATION.md)
/// is set per-curve at deploy time (DEFAULT_BOOTSTRAP.graduationThreshold), not here.
///
/// RESERVE-2026-07-11: lowered 100→80 SOL. The default threshold moved 107→83 SOL when the curve
/// share dropped 90%→70% (20% now MINTED to the Tier-2 reserve): to hold the graduation market cap
/// constant on a smaller 700M curve, `virtual_sol == graduation_threshold` re-tunes proportionally
/// (107 × 700/900 ≈ 83), which would otherwise fall under the old 100-SOL floor. Graduation stays
/// feature-flagged off in production (`GRADUATION_ENABLED`), so this only widens the allowed range;
/// 80 SOL keeps a margin below the 83-SOL default and remains a substantial anti-dust floor.
pub const MIN_GRADUATION_THRESHOLD_LAMPORTS: u64 = 80_000_000_000; // 80 SOL dust-floor

/// Raydium CP-Swap `initialize` — 20 accounts + the anchor discriminator sha256("global:initialize")[..8].
pub const RAYDIUM_INIT_ACCOUNTS: usize = 20;
pub const CPSWAP_INITIALIZE_DISCRIMINATOR: [u8; 8] = [175, 175, 109, 31, 13, 152, 155, 237];
/// wSOL reimbursed to the graduation cranker from reserves (covers the native CP-Swap fee + rent they
/// front to the curve PDA). Fixed + generous; the cranker's small margin incentivises cranking.
pub const GRADUATION_CRANK_REIMBURSEMENT: u64 = 500_000_000; // 0.5 SOL

fn effective_sol(curve: &BondingCurve) -> u128 {
    curve.real_sol as u128 + curve.virtual_sol as u128
}

/// Fee = amount × fee_bps / 10000 (floor).
pub fn fee_amount(amount: u64, fee_bps: u16) -> u64 {
    ((amount as u128 * fee_bps as u128) / 10_000) as u64
}

/// Split a fee into (firm 0.5%, platform 0.5%) halves; firm takes the rounding remainder.
pub fn split_fee(fee: u64) -> (u64, u64) {
    let platform = fee / 2;
    (fee - platform, platform)
}

fn record_fees(curve: &mut BondingCurve, firm_fee: u64, platform_fee: u64) {
    curve.firm_fees_accrued = curve.firm_fees_accrued.saturating_add(firm_fee);
    curve.platform_fees_accrued = curve.platform_fees_accrued.saturating_add(platform_fee);
}

/// $FIRMA out for `net_in` SOL: `firma_out = y − ⌈k/(x + net_in)⌉`.
///
/// The pool's retained reserve `k/x'` is rounded UP (ceil), so the trader's output rounds DOWN — every
/// sub-unit of rounding dust stays in the pool, never the trader. This keeps the constant product `k`
/// NON-DECREASING across trades and makes a zero-fee buy→sell round-trip unable to profit even by a
/// single lamport (R40 hardening — quotes must round toward the pool, the standard AMM invariant).
pub fn buy_output(eff_sol: u128, firma_reserve: u128, net_in: u128) -> Option<u64> {
    let k = eff_sol.checked_mul(firma_reserve)?;
    let new_x = eff_sol.checked_add(net_in)?;
    let new_y = k.div_ceil(new_x); // retained reserve rounded UP → output rounded DOWN (toward the pool)
    u64::try_from(firma_reserve.checked_sub(new_y)?).ok()
}

/// Gross SOL out for `firma_in` $FIRMA: `sol_out = x − ⌈k/(y + firma_in)⌉`.
///
/// Symmetric to `buy_output`: the pool's retained SOL is rounded UP so the trader's SOL out rounds DOWN
/// (dust stays in the pool; `k` non-decreasing). See `buy_output` for the rationale (R40).
pub fn sell_output(eff_sol: u128, firma_reserve: u128, firma_in: u128) -> Option<u64> {
    let k = eff_sol.checked_mul(firma_reserve)?;
    let new_y = firma_reserve.checked_add(firma_in)?;
    let new_x = k.div_ceil(new_y); // retained SOL rounded UP → output rounded DOWN (toward the pool)
    u64::try_from(eff_sol.checked_sub(new_x)?).ok()
}

/// Curve PDA signer seeds for transfers out of the curve's vaults.
fn curve_signer<'a>(firm: &'a Pubkey, bump: &'a [u8; 1]) -> [&'a [u8]; 3] {
    [b"bonding_curve", firm.as_ref(), bump]
}

#[derive(Accounts)]
pub struct InitializeCurve<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,

    /// CHECK: the firm this curve belongs to — PDA seed only.
    pub firm: UncheckedAccount<'info>,

    pub sol_mint: Account<'info, Mint>,
    pub firma_mint: Account<'info, Mint>,

    #[account(
        init,
        payer = payer,
        space = 8 + BondingCurve::INIT_SPACE,
        seeds = [b"bonding_curve", firm.key().as_ref()],
        bump
    )]
    pub curve: Account<'info, BondingCurve>,

    #[account(
        init,
        payer = payer,
        token::mint = sol_mint,
        token::authority = curve,
        seeds = [b"curve_sol", firm.key().as_ref()],
        bump
    )]
    pub sol_vault: Account<'info, TokenAccount>,

    #[account(
        init,
        payer = payer,
        token::mint = firma_mint,
        token::authority = curve,
        seeds = [b"curve_firma", firm.key().as_ref()],
        bump
    )]
    pub firma_vault: Account<'info, TokenAccount>,

    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
    pub rent: Sysvar<'info, Rent>,
}

#[derive(Accounts)]
pub struct OpenTrading<'info> {
    #[account(mut, seeds = [b"bonding_curve", curve.firm.as_ref()], bump = curve.bump)]
    pub curve: Account<'info, BondingCurve>,

    /// The exact `firm_state` PDA this curve belongs to, signing via its own seeds — only the
    /// `firm` program can ever produce that signature, so this can't be called by anyone else.
    #[account(address = curve.firm)]
    pub firm_state: Signer<'info>,
}

#[derive(Accounts)]
pub struct Buy<'info> {
    pub trader: Signer<'info>,

    #[account(mut, seeds = [b"bonding_curve", curve.firm.as_ref()], bump = curve.bump)]
    pub curve: Account<'info, BondingCurve>,

    #[account(mut, address = curve.sol_vault)]
    pub sol_vault: Account<'info, TokenAccount>,
    #[account(mut, address = curve.firma_vault)]
    pub firma_vault: Account<'info, TokenAccount>,

    #[account(mut, token::mint = curve.sol_mint, token::authority = trader)]
    pub trader_sol: Account<'info, TokenAccount>,
    #[account(mut, token::mint = curve.firma_mint)]
    pub trader_firma: Account<'info, TokenAccount>,

    // Fee destinations. NOTE (M-4, deferred): a blanket `seeds`-bind of firm_treasury_sol to the firm's
    // treasury PDA breaks the firm program's OWN curve-buy CPIs, which legitimately route the firm fee to
    // DIFFERENT protocol pools (treasury for payouts/deploys, universal_vault for `draw_universal`). The
    // correct binding is per-caller (or an external-vs-internal distinction) — deferred. The F-1/F-2 DoS
    // is already closed at the firm side (treasury-cache reconcile + `>=` guard), so an out-of-band credit
    // here is harmless. The mint is constrained and the caller supplies the destination.
    #[account(mut, token::mint = curve.sol_mint)]
    pub firm_treasury_sol: Account<'info, TokenAccount>,
    #[account(mut, token::mint = curve.sol_mint)]
    pub platform_sol: Account<'info, TokenAccount>,

    pub token_program: Program<'info, Token>,
}

impl<'info> Buy<'info> {
    /// Pull SOL from the trader: net → curve vault, fee halves → firm + platform.
    fn collect_sol(&self, net: u64, firm_fee: u64, platform_fee: u64) -> Result<()> {
        self.transfer_from_trader(&self.sol_vault, net)?;
        self.transfer_from_trader(&self.firm_treasury_sol, firm_fee)?;
        self.transfer_from_trader(&self.platform_sol, platform_fee)
    }

    fn transfer_from_trader(&self, to: &Account<'info, TokenAccount>, amount: u64) -> Result<()> {
        token::transfer(
            CpiContext::new(
                self.token_program.to_account_info(),
                Transfer {
                    from: self.trader_sol.to_account_info(),
                    to: to.to_account_info(),
                    authority: self.trader.to_account_info(),
                },
            ),
            amount,
        )
    }

    /// Send purchased $FIRMA from the curve vault to the trader (curve PDA signs).
    fn pay_out_firma(&self, amount: u64) -> Result<()> {
        let bump = [self.curve.bump];
        let seeds = curve_signer(&self.curve.firm, &bump);
        token::transfer(
            CpiContext::new_with_signer(
                self.token_program.to_account_info(),
                Transfer {
                    from: self.firma_vault.to_account_info(),
                    to: self.trader_firma.to_account_info(),
                    authority: self.curve.to_account_info(),
                },
                &[&seeds],
            ),
            amount,
        )
    }
}

#[derive(Accounts)]
pub struct Sell<'info> {
    pub trader: Signer<'info>,

    #[account(mut, seeds = [b"bonding_curve", curve.firm.as_ref()], bump = curve.bump)]
    pub curve: Account<'info, BondingCurve>,

    #[account(mut, address = curve.sol_vault)]
    pub sol_vault: Account<'info, TokenAccount>,
    #[account(mut, address = curve.firma_vault)]
    pub firma_vault: Account<'info, TokenAccount>,

    #[account(mut, token::mint = curve.sol_mint)]
    pub trader_sol: Account<'info, TokenAccount>,
    #[account(mut, token::mint = curve.firma_mint, token::authority = trader)]
    pub trader_firma: Account<'info, TokenAccount>,

    // Fee destinations (M-4 binding deferred — see Buy; the firm-side reconcile makes credits harmless).
    #[account(mut, token::mint = curve.sol_mint)]
    pub firm_treasury_sol: Account<'info, TokenAccount>,
    #[account(mut, token::mint = curve.sol_mint)]
    pub platform_sol: Account<'info, TokenAccount>,

    pub token_program: Program<'info, Token>,
}

impl<'info> Sell<'info> {
    /// Pull the sold $FIRMA from the trader into the curve vault.
    fn take_in_firma(&self, amount: u64) -> Result<()> {
        token::transfer(
            CpiContext::new(
                self.token_program.to_account_info(),
                Transfer {
                    from: self.trader_firma.to_account_info(),
                    to: self.firma_vault.to_account_info(),
                    authority: self.trader.to_account_info(),
                },
            ),
            amount,
        )
    }

    /// Pay SOL out of the curve vault: net → trader, fee halves → firm + platform.
    fn pay_out_sol(&self, net_out: u64, firm_fee: u64, platform_fee: u64) -> Result<()> {
        self.transfer_from_vault(&self.trader_sol, net_out)?;
        self.transfer_from_vault(&self.firm_treasury_sol, firm_fee)?;
        self.transfer_from_vault(&self.platform_sol, platform_fee)
    }

    fn transfer_from_vault(&self, to: &Account<'info, TokenAccount>, amount: u64) -> Result<()> {
        let bump = [self.curve.bump];
        let seeds = curve_signer(&self.curve.firm, &bump);
        token::transfer(
            CpiContext::new_with_signer(
                self.token_program.to_account_info(),
                Transfer {
                    from: self.sol_vault.to_account_info(),
                    to: to.to_account_info(),
                    authority: self.curve.to_account_info(),
                },
                &[&seeds],
            ),
            amount,
        )
    }
}

#[derive(Accounts)]
pub struct AddReserve<'info> {
    pub depositor: Signer<'info>,

    #[account(mut, seeds = [b"bonding_curve", curve.firm.as_ref()], bump = curve.bump)]
    pub curve: Account<'info, BondingCurve>,

    #[account(mut, address = curve.sol_vault)]
    pub sol_vault: Account<'info, TokenAccount>,

    #[account(mut, token::mint = curve.sol_mint, token::authority = depositor)]
    pub source_sol: Account<'info, TokenAccount>,

    pub token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct Graduate<'info> {
    /// Permissionless cranker — pays the tx + fronts the native SOL the curve PDA needs for the CP-Swap
    /// pool fee/rent (via a `System::transfer` to the curve PDA earlier in the same tx); reimbursed in
    /// wSOL from reserves.
    #[account(mut)]
    pub cranker: Signer<'info>,

    #[account(mut, seeds = [b"bonding_curve", curve.firm.as_ref()], bump = curve.bump)]
    pub curve: Account<'info, BondingCurve>,

    #[account(mut, address = curve.sol_vault)]
    pub sol_vault: Account<'info, TokenAccount>,
    #[account(mut, address = curve.firma_vault)]
    pub firma_vault: Account<'info, TokenAccount>,

    /// CHECK: the Raydium CP-Swap program — validated as the CPI target.
    pub cpmm_program: UncheckedAccount<'info>,

    /// CHECK: the curve-PDA-owned LP vault — created here as ATA(curve, lp_mint) and enforced by
    /// `create_idempotent`; the migrated pool LP is locked into it (blocker #2). Unchecked because the
    /// lp_mint is created during the CPI, so it cannot be typed at instruction entry.
    #[account(mut)]
    pub curve_lp_vault: UncheckedAccount<'info>,

    pub token_program: Program<'info, Token>,
    pub associated_token_program: Program<'info, AssociatedToken>,
    pub system_program: Program<'info, System>,
    // The 20 CP-Swap `initialize` accounts are passed as `remaining_accounts` (RAYDIUM_GRADUATION.md);
    // ra[6] = pool_lp_mint, ra[9] = creator_lp_token (the cranker ATA CP-Swap mints LP into).
}

/// Per-firm bonding curve. Seeds: ["bonding_curve", firm].
#[account]
#[derive(InitSpace)]
pub struct BondingCurve {
    pub firm: Pubkey,
    pub sol_mint: Pubkey,
    pub firma_mint: Pubkey,
    pub sol_vault: Pubkey,
    pub firma_vault: Pubkey,
    /// Virtual seed — sets the starting price, never withdrawable.
    pub virtual_sol: u64,
    /// Real SOL deposited (what sells can draw down; counts toward graduation).
    pub real_sol: u64,
    /// $FIRMA remaining in the curve (mirrors the firma_vault balance).
    pub firma_reserve: u64,
    pub graduation_threshold: u64,
    pub graduated: bool,
    /// Front-running guard (2026-07-09; simplified RESERVE-3 2026-07-11): public trading opens only
    /// once the firm has finished launching its token, so no one can front-run the launch. `false`
    /// from `initialize_curve` until `firm.finalize_token_launch` CPIs into `open_trading`; `buy()`
    /// rejects EVERY buy while this is false. (Pre-RESERVE-3 there was a carve-out for the deploy
    /// escrow's auto-buy legs — that escrow was removed, so the gate is now unconditional.)
    pub trading_live: bool,
    pub fee_bps: u16,
    pub firm_fees_accrued: u64,
    pub platform_fees_accrued: u64,
    pub bump: u8,
}

#[event]
pub struct Traded {
    pub firm: Pubkey,
    pub is_buy: bool,
    pub sol: u64,
    pub firma: u64,
    pub fee: u64,
}

#[event]
pub struct ReserveAdded {
    pub firm: Pubkey,
    pub amount: u64,
    pub real_sol: u64,
}

#[event]
pub struct CurveGraduated {
    pub firm: Pubkey,
    pub real_sol: u64,
    pub firma_reserve: u64,
}

#[error_code]
pub enum BondingCurveError {
    #[msg("virtual_sol and firma_reserve must both be positive")]
    InvalidSeed,
    #[msg("curve has graduated — trade on Raydium instead")]
    Graduated,
    #[msg("curve has already graduated")]
    AlreadyGraduated,
    #[msg("graduation threshold not yet met")]
    ThresholdNotMet,
    #[msg("output below the slippage minimum")]
    SlippageExceeded,
    #[msg("insufficient curve liquidity")]
    InsufficientLiquidity,
    #[msg("arithmetic overflow")]
    MathOverflow,
    #[msg("graduation_threshold is below the protocol minimum — set to at least MIN_GRADUATION_THRESHOLD_LAMPORTS")]
    ThresholdTooLow,
    #[msg("graduation is disabled until Phase 4.4 (Raydium migration) is live — GRADUATION_ENABLED = false")]
    GraduationDisabled,
    #[msg("the supplied Raydium CP-Swap accounts are wrong (count/order/creator/reserve mismatch)")]
    BadRaydiumAccounts,
    #[msg("no LP was minted by the pool — cannot lock the migrated liquidity in the protocol")]
    LpNotLocked,
    #[msg("trading isn't open yet — the firm's token launch hasn't finalized")]
    TradingNotLive,
    #[msg("trading is already live for this curve")]
    TradingAlreadyLive,
}

#[cfg(test)]
mod tests {
    use super::*;

    // §20 "Life of a Bonding Curve" (Basic tier), in 6-decimal base units:
    //   virtual seed = $4,000      → 4_000_000_000
    //   firma reserve = 180,000,000 → 180_000_000_000_000
    //   k = 7.2e23
    const VIRTUAL: u128 = 4_000_000_000;
    const FIRMA: u128 = 180_000_000_000_000;

    #[test]
    fn buy_output_matches_doc_example() {
        // Buy with $10,000 net SOL → new_x = 14,000; doc: ~128.57M $FIRMA out.
        let net_in: u128 = 10_000_000_000;
        let out = buy_output(VIRTUAL, FIRMA, net_in).unwrap();
        // new_y = ⌈7.2e23 / 1.4e10⌉ = 51_428_571_428_572 (rounded UP, toward the pool); out = 180e12 − that.
        // (One base unit less than the old floor-quote — the dust now stays in the pool. R40.)
        assert_eq!(out, 128_571_428_571_428);
    }

    #[test]
    fn price_rises_after_a_buy() {
        // Marginal price = x / y. After a buy, x↑ and y↓, so price strictly rises.
        let net_in: u128 = 1_000_000_000;
        let out = buy_output(VIRTUAL, FIRMA, net_in).unwrap() as u128;
        let price_before = (VIRTUAL as f64) / (FIRMA as f64);
        let price_after = ((VIRTUAL + net_in) as f64) / ((FIRMA - out) as f64);
        assert!(price_after > price_before);
    }

    #[test]
    fn buy_then_sell_roundtrip_never_profits() {
        // Selling back the exact $FIRMA just bought must not return more SOL than
        // put in (constant-product guarantees this even before fees).
        let net_in: u128 = 5_000_000_000;
        let firma_out = buy_output(VIRTUAL, FIRMA, net_in).unwrap();
        let new_real = net_in; // real_sol after buy (net)
        let eff_after = VIRTUAL + new_real;
        let firma_after = FIRMA - firma_out as u128;
        let sol_back = sell_output(eff_after, firma_after, firma_out as u128).unwrap();
        assert!(sol_back as u128 <= net_in);
    }

    #[test]
    fn fee_is_one_percent_split_evenly() {
        assert_eq!(fee_amount(1_000_000, DEFAULT_FEE_BPS), 10_000); // 1%
        let (firm_fee, platform_fee) = split_fee(10_000);
        assert_eq!(firm_fee, 5_000);
        assert_eq!(platform_fee, 5_000);
    }

    #[test]
    fn split_fee_gives_remainder_to_firm() {
        // Odd fee: firm takes the extra unit.
        let (firm_fee, platform_fee) = split_fee(7);
        assert_eq!(firm_fee, 4);
        assert_eq!(platform_fee, 3);
        assert_eq!(firm_fee + platform_fee, 7);
    }

    // ── Adversarial curve invariants (value can't be extracted / leak to rounding) ──

    fn xorshift(seed: u64) -> impl FnMut() -> u64 {
        let mut s = seed.wrapping_mul(0x9E3779B97F4A7C15).wrapping_add(1);
        move || {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            s
        }
    }
    const FEES: [u16; 5] = [0, 1, 50, 100, 300]; // incl. 0% + 3% extremes

    #[test]
    fn curve_roundtrip_never_profits() {
        // THE drain invariant (post-R40-fix): a buy → immediate sell of the exact $FIRMA received can NEVER
        // return more SOL than was put in — EVEN at zero fee, in ANY curve state, incl. degenerate ones.
        // Because the quotes now round toward the pool, the round-trip loses at least the rounding dust; a
        // real fee only widens the loss. Sweep the full space (virtual seed, real reserve incl. 0, $FIRMA
        // reserve) × trade size × fee tiers, replaying the exact `buy`/`sell` handler arithmetic.
        for seed in 0..400_000u64 {
            let mut next = xorshift(seed);
            let virtual_sol = (next() % 100_000_000_000) + 1; // 1 .. 100 SOL seed
            let real_sol = next() % 1_000_000_000_000; // 0 .. 1000 SOL (incl. empty curve)
            let firma_reserve = (next() % 1_000_000_000_000_000) + 1; // 1 .. 1e15
            let fee_bps = FEES[(next() % FEES.len() as u64) as usize]; // incl. 0% — the adversarial case
            let sol_in = (next() % 200_000_000_000) + 1; // 1 .. 200 SOL in

            let x = real_sol as u128 + virtual_sol as u128;
            let y = firma_reserve as u128;

            let net_b = sol_in - fee_amount(sol_in, fee_bps);
            let firma_out = match buy_output(x, y, net_b as u128) {
                Some(v) if v > 0 && (v as u128) <= y => v,
                _ => continue,
            };
            let x2 = x + net_b as u128;
            let y2 = y - firma_out as u128;
            let real_sol_after = real_sol + net_b;
            let gross = match sell_output(x2, y2, firma_out as u128) {
                Some(v) if v <= real_sol_after => v, // handler guard: can't draw the virtual seed
                _ => continue,
            };
            let net_out = gross - fee_amount(gross, fee_bps);

            assert!(
                net_out <= sol_in,
                "ROUND-TRIP PROFIT (seed {seed}): put in {sol_in}, got back {net_out} \
                 (x {x}, y {y}, fee_bps {fee_bps}, firma_out {firma_out}, gross {gross})"
            );
        }
    }

    #[test]
    fn curve_k_never_decreases_on_trades() {
        // Post-R40-fix, the quotes round the pool's retained reserve UP, so the constant product
        // `k = eff_sol × firma_reserve` is NON-DECREASING across every buy and sell — value can only ever
        // accrue to the curve from integer rounding, never leak out.
        for seed in 0..400_000u64 {
            let mut next = xorshift(seed);
            let x = ((next() % 1_100_000_000_000) + 1) as u128;
            let y = ((next() % 1_000_000_000_000_000) + 1) as u128;
            let fee_bps = FEES[(next() % FEES.len() as u64) as usize];
            let amount = (next() % 200_000_000_000) + 1;
            let k0 = x * y;

            let net = (amount - fee_amount(amount, fee_bps)) as u128;
            if let Some(fo) = buy_output(x, y, net) {
                if (fo as u128) <= y {
                    let k1 = (x + net) * (y - fo as u128);
                    assert!(k1 >= k0, "BUY decreased k (seed {seed}): {k1} < {k0}");
                }
            }
            if let Some(g) = sell_output(x, y, amount as u128) {
                if (g as u128) < x {
                    let k1 = (x - g as u128) * (y + amount as u128);
                    assert!(k1 >= k0, "SELL decreased k (seed {seed}): {k1} < {k0}");
                }
            }
        }
    }
}
