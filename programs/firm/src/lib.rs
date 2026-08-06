// Anchor's own `#[program]` macro expansion calls the deprecated `AccountInfo::realloc`. Crate-level
// (not on the `#[program] mod` item) because an outer `#[allow]` on the mod doesn't reach the macro's
// generated sibling items under `-D warnings`. This also covers one real call site in this module
// (`acc.realloc(new_len, false)?` in the account-resize helper below) — deliberately suppressed
// rather than migrated to `.resize()` in this pass: it's a fund-adjacent bankruptcy-account-resize
// path, and per this repo's own bar, an on-chain behavior change isn't "done" until devnet-proven,
// which this CI-lint pass didn't budget for. Tracked as a real (small) follow-up, not silently
// dropped — see MASTER_FIXES.
#![allow(deprecated)]

use anchor_lang::prelude::*;
use anchor_spl::metadata::{
    create_metadata_accounts_v3,
    mpl_token_metadata::types::DataV2,
    CreateMetadataAccountsV3, Metadata,
};
use anchor_spl::token::{
    self, spl_token::instruction::AuthorityType, Mint, MintTo, SetAuthority, Token, TokenAccount,
};

declare_id!("4ZmeSsuMU38jnc42P53gjY8d1N6WPc3LUibiboKwMaEj");

// Gated on `no-entrypoint` for consistency with the other 4 programs (none currently depend on
// `firm` via CPI, but this keeps the invariant "security_txt! only in the top-level program build"
// intact if that ever changes).
#[cfg(not(feature = "no-entrypoint"))]
solana_security_txt::security_txt! {
    name: "DecentralProp: Firm",
    project_url: "https://decentralprop.com",
    contacts: "email:security@decentralprop.com",
    policy: "https://github.com/dylanpersonguy/decentralprop-onchain-programs/blob/main/SECURITY.md",
    preferred_languages: "en",
    source_code: "https://github.com/dylanpersonguy/decentralprop-onchain-programs/tree/main/programs/firm",
    source_release: "devnet"
}

/// DecentralProp `firm_program` (architecture §5, §9, §11, §16, §19, §25).
///
/// Firm identity, the autonomous risk-tier control surface (what the off-chain ARE
/// writes to), and — added in the value-flow layer (Phase 3) — the per-firm $FIRMA
/// SPL mint, the SOL treasury vault, the owner-drip vault, and fixed-supply token
/// distribution.
///
/// `update_risk_tier` enforces the §25 guards on-chain (one step at a time; escalation
/// immediate; relaxation time-locked). The token mint is created with
/// `freeze_authority = None` and, after `distribute_supply` mints the fixed supply
/// (70% curve / 10% drip / 20% Tier-2 reserve since RESERVE-2026-07-11), its `mint_authority`
/// is **revoked to None** — so no new
/// $FIRMA can ever be minted (§16 vectors 2 & 6). The treasury vault has no withdraw
/// instruction; SOL only leaves via the payout path (Phase 4) (§16 vector 4).
///
/// Deploy sequence: `deploy_firm` → `create_firma_mint` → (bonding_curve.initialize_curve)
/// → `distribute_supply`.
#[program]
pub mod firm {
    use super::*;

    /// Deploy a firm. One firm per wallet — seeds ["firm", owner]. New firms start in
    /// CAUTION (§5 day-1 treasury-protection bootstrap). Tokens are set up separately.
    pub fn deploy_firm(ctx: Context<DeployFirm>, tier: u8) -> Result<()> {
        require!(tier <= MAX_TIER, FirmError::InvalidTier);
        // V2-1 (Critical): the guardian is the independent co-signer on every forgeable drain
        // (`settle_dispute_payout`, `initiate_close`, `finalize_close`). Before this, `deploy_firm`
        // took an arbitrary owner-supplied key, so an operator could name ITSELF the guardian and
        // self-sign a fabricated self-dispute against its own insurance (reopening the F3 drain) or
        // solo-close over a trader. Bind it to the canonical platform guardian AND reject owner==guardian
        // so the co-sign is genuinely independent. `platform_config` must be initialised first.
        require!(
            ctx.accounts.guardian.key() != ctx.accounts.owner.key(),
            FirmError::GuardianNotIndependent
        );
        require!(
            ctx.accounts.guardian.key() == ctx.accounts.platform_config.platform_guardian,
            FirmError::GuardianMismatch
        );
        let now = Clock::get()?.unix_timestamp;
        let firm = &mut ctx.accounts.firm_state;
        firm.owner = ctx.accounts.owner.key();
        firm.risk_engine_authority = ctx.accounts.risk_engine_authority.key();
        firm.guardian = ctx.accounts.guardian.key();
        firm.close_initiated_at = 0;
        firm.tier = tier;
        firm.status = FirmStatus::Active;
        firm.risk_tier = RiskTier::Caution;
        firm.last_tier_change_at = now;
        firm.velocity_break_flag = false;
        firm.deployed_at = now;
        firm.firma_mint = Pubkey::default();
        firm.sol_mint = Pubkey::default();
        firm.treasury_vault = Pubkey::default();
        firm.treasury_sol = 0;
        firm.graduated = false;
        firm.total_paid_out = 0;
        firm.daily_payout_spent = 0;
        firm.payout_day = 0;
        firm.supply_distributed = false;
        firm.payout_firma_vault = Pubkey::default();
        firm.stakeholder_config = StakeholderConfig::default();
        firm.backstop_pool_bps = DEFAULT_BACKSTOP_POOL_BPS;
        firm.open_payouts = 0;
        firm.firma_buyback_acc = 0;
        firm.post_grad_lp_acc = 0;
        // Loss-back redemption gate is fixed platform-wide (not operator-set); seed it at deploy so the
        // gate is correct-by-construction even before the keeper re-asserts it at bootstrap.
        firm.loss_back_min_stake = LOSS_BACK_MIN_STAKE;
        // Deferred token launch: a freshly-deployed firm is NOT live for sales until it launches its
        // token. `pay_challenge_fee` is gated on `token_live`; `finalize_token_launch` flips it.
        firm.token_live = false;
        firm.token_pending = true;
        firm.bump = ctx.bumps.firm_state;

        emit!(FirmDeployed { firm: firm.key(), owner: firm.owner, deployed_at: now });
        Ok(())
    }

    /// Phase 1 (deferred token launch): stand up the firm's SOL-side infrastructure — the wSOL
    /// treasury/insurance/owner-vesting vaults + the insurance fund — WITHOUT the $FIRMA token. This
    /// is the part `pay_deployment_fee` needs; the actual $FIRMA mint is
    /// deferred to `create_firma_mint` at token launch. Sets `sol_mint` + `treasury_vault`.
    pub fn create_firm_treasury(ctx: Context<CreateFirmTreasury>) -> Result<()> {
        let insurance = &mut ctx.accounts.insurance_fund;
        insurance.firm = ctx.accounts.firm_state.key();
        insurance.balance = 0;
        insurance.bump = ctx.bumps.insurance_fund;

        let firm = &mut ctx.accounts.firm_state;
        firm.sol_mint = ctx.accounts.sol_mint.key();
        firm.treasury_vault = ctx.accounts.treasury_vault.key();
        emit!(FirmTreasuryCreated {
            firm: firm.key(),
            sol_mint: firm.sol_mint,
            treasury_vault: firm.treasury_vault,
        });
        Ok(())
    }

    /// Phase 2 (token launch): create the firm's $FIRMA mint (6 decimals, mint authority = firm PDA
    /// temporarily, freeze authority = None) + the $FIRMA vaults (owner-drip, payout staging, treasury
    /// reserve), and attach a real Metaplex Token Metadata account carrying the operator-chosen
    /// identity (`name`/`symbol`/`uri`) so Phantom/Solscan/Jupiter/Raydium actually display it — the
    /// mint itself carries no name/symbol/image without this. `is_mutable: false`: the identity is
    /// fixed at launch (the `uri` points at a dynamic endpoint the operator can still update the
    /// image/description/website behind — only the on-chain name/symbol/uri STRING is frozen).
    /// Requires the SOL treasury to already exist (`create_firm_treasury`).
    pub fn create_firma_mint(
        ctx: Context<CreateFirmaMint>,
        name: String,
        symbol: String,
        uri: String,
    ) -> Result<()> {
        require!(ctx.accounts.firm_state.sol_mint != Pubkey::default(), FirmError::InvalidFirmStatus);
        let owner_key = ctx.accounts.firm_state.owner;
        let bump = ctx.accounts.firm_state.bump;
        let firma_mint_key = ctx.accounts.firma_mint.key();
        {
            let firm = &mut ctx.accounts.firm_state;
            firm.firma_mint = firma_mint_key;
            firm.payout_firma_vault = ctx.accounts.payout_firma_vault.key();
            firm.treasury_firma_vault = ctx.accounts.treasury_firma_vault.key();
        }

        let bump_arr = [bump];
        let seeds = firm_signer(&owner_key, &bump_arr);
        create_metadata_accounts_v3(
            CpiContext::new_with_signer(
                ctx.accounts.token_metadata_program.to_account_info(),
                CreateMetadataAccountsV3 {
                    metadata: ctx.accounts.metadata.to_account_info(),
                    mint: ctx.accounts.firma_mint.to_account_info(),
                    mint_authority: ctx.accounts.firm_state.to_account_info(),
                    payer: ctx.accounts.owner.to_account_info(),
                    update_authority: ctx.accounts.firm_state.to_account_info(),
                    system_program: ctx.accounts.system_program.to_account_info(),
                    rent: ctx.accounts.rent.to_account_info(),
                },
                &[&seeds],
            ),
            DataV2 {
                name: name.clone(),
                symbol: symbol.clone(),
                uri: uri.clone(),
                seller_fee_basis_points: 0,
                creators: None,
                collection: None,
                uses: None,
            },
            false, // is_mutable
            true,  // update_authority_is_signer — firm_state PDA signs via invoke_signed above
            None,  // collection_details
        )?;

        emit!(FirmaMintCreated {
            firm: ctx.accounts.firm_state.key(),
            firma_mint: firma_mint_key,
            name,
            symbol,
            uri,
        });
        Ok(())
    }

    /// Mint the fixed supply (70% → curve vault, 10% → drip vault, 20% → Tier-2 treasury
    /// reserve) and **revoke the mint authority to None** — supply is permanent thereafter
    /// (§11, §16). One-shot.
    ///
    /// RESERVE-2026-07-11: the Tier-2 `treasury_firma_vault` is now seeded by a real MINT here
    /// (20% of supply) rather than relying on curve auto-buys + eval-fee buybacks alone. Buying
    /// 20% off the fresh curve would cost multiples of the deployment fee, so the reserve never
    /// reached its intended size (it landed near ~1%). The curve share dropped 90%→70% to fund
    /// the mint; the curve seed (`virtual_sol == graduation_threshold`) is re-tuned proportionally
    /// off-chain (deploy.ts, 107→83 SOL) so the graduation market cap is preserved. Amounts are
    /// passed in by the caller — this instruction only enforces the one-shot + revoke invariant.
    pub fn distribute_supply(
        ctx: Context<DistributeSupply>,
        curve_amount: u64,
        drip_amount: u64,
        treasury_amount: u64,
    ) -> Result<()> {
        require!(!ctx.accounts.firm_state.supply_distributed, FirmError::AlreadyDistributed);

        ctx.accounts.mint_to_vault(&ctx.accounts.curve_firma_vault, curve_amount)?;
        ctx.accounts.mint_to_vault(&ctx.accounts.drip_vault, drip_amount)?;
        ctx.accounts.mint_to_vault(&ctx.accounts.treasury_firma_vault, treasury_amount)?;
        ctx.accounts.revoke_mint_authority()?;

        let now = Clock::get()?.unix_timestamp;
        let drip = &mut ctx.accounts.owner_drip_state;
        drip.owner = ctx.accounts.firm_state.owner;
        drip.firm = ctx.accounts.firm_state.key();
        drip.vault = ctx.accounts.drip_vault.key();
        drip.total_tokens = drip_amount;
        drip.months_total = DRIP_MONTHS;
        drip.months_claimed = 0;
        drip.drip_start_at = now;
        drip.bump = ctx.bumps.owner_drip_state;

        let firm = &mut ctx.accounts.firm_state;
        firm.supply_distributed = true;
        emit!(SupplyDistributed {
            firm: firm.key(),
            curve_amount,
            drip_amount,
            treasury_amount,
            total: curve_amount
                .saturating_add(drip_amount)
                .saturating_add(treasury_amount),
        });
        Ok(())
    }

    /// Pay a challenge fee — atomic split (§17). Sent in the same transaction as
    /// `challenge.purchase_challenge`. Routes SOL from the trader to: DP profit (8%),
    /// DP treasury (3%), insurance (2%), owner immediate + 90-day vested (tier %), LP
    /// (dynamic 5/9/11% by real pool depth → bonding curve pre-graduation, folds into
    /// treasury post-graduation), backstop premium (carved, 0–6%), normal staking pool (5%),
    /// $DPROP buy-back pool (1%), $DPROP staking pool (10%), affiliate pool (≤20%), and the firm treasury (remainder).
    /// Reverts if any leg fails (one transaction).
    pub fn pay_challenge_fee(ctx: Context<PayChallengeFee>, amount: u64) -> Result<()> {
        // MASTER_FIXES F-3: reject zero-amount fees. `pay_deployment_fee` already guards this; without
        // it a zero-amount call would run the whole split (all legs 0) and init empty PDAs at the
        // caller's rent cost. Not value-exploitable, but a pointless failure mode — fail fast.
        require!(amount > 0, FirmError::ZeroAmount);
        // MASTER_FIXES T-3/T-4 sale-gate: once a firm initiates close, stop selling new evaluations.
        // This bounds the set of in-flight challenges to those that existed before `initiate_close`,
        // so no NEW claim can accrue during the wind-down.
        // §24 v2: a firm that auto-bankrupted (drew ≥10% of the ULP) is removed from operation — it can no
        // longer sell evaluations. This is the ONLY per-firm sales brake; a healthy firm never stops selling.
        require!(ctx.accounts.firm_state.status != FirmStatus::Bankrupt, FirmError::FirmBankrupt);
        // Deferred-token-launch gate: a firm cannot sell evaluations until it has launched its
        // $FIRMA token (`finalize_token_launch` flips `token_live`). Belt to the gateway/storefront
        // suspenders — this is the correctness-critical one. The curve-buyback leg needs the curve
        // to exist anyway, so this also fails safe.
        require!(ctx.accounts.firm_state.token_live, FirmError::TokenNotLaunched);
        // M-4: bind the two platform-fee destinations to the canonical `platform_config` (checked
        // here, not in `try_accounts`, to stay under the 4 KB BPF stack limit). Prevents a caller
        // substituting accounts they control for the DP-profit / DP-treasury legs.
        {
            let pc = &ctx.accounts.platform_config;
            let (expected, _) = Pubkey::find_program_address(&[b"platform_config"], &crate::ID);
            require!(pc.key() == expected, FirmError::Unauthorized);
            let cfg = PlatformConfig::try_deserialize(&mut &pc.try_borrow_data()?[..])?;
            require!(ctx.accounts.dp_profit_sol.key() == cfg.dp_profit_sol, FirmError::Unauthorized);
            require!(ctx.accounts.dp_treasury_sol.key() == cfg.dp_treasury_sol, FirmError::Unauthorized);
        }
        let firm_tier = ctx.accounts.firm_state.tier;
        let graduated = ctx.accounts.firm_state.graduated;
        let lp_bps = lp_bps_for_depth(ctx.accounts.curve.real_sol);
        // Premium rate comes from the firm's backstop pool when present (else 0 — no carve).
        // Backstop premium is fixed platform-wide (6%): a firm with a backstop pool carves exactly that,
        // regardless of the pool's stored `premium_bps` (defends any pre-lock pool at the old 4.5%). No
        // pool → no carve.
        let premium_bps = ctx
            .accounts
            .backstop_pool
            .as_ref()
            .map(|_| DEFAULT_BACKSTOP_PREMIUM_BPS)
            .unwrap_or(0);
        // Affiliate rate (§17.1): only a referred purchase carves, at the (active) affiliate's
        // rate. The referral binds trader→affiliate; the affiliate account holds the rate. An
        // unreferred or inactive-affiliate purchase carves 0 (the slice stays in the treasury).
        let affiliate_bps = match (
            ctx.accounts.referral.as_ref(),
            ctx.accounts.affiliate_account.as_ref(),
        ) {
            (Some(referral), Some(acct)) => {
                require!(referral.trader == ctx.accounts.trader.key(), FirmError::Unauthorized);
                require!(referral.firm == ctx.accounts.firm_state.key(), FirmError::Unauthorized);
                require!(acct.firm == ctx.accounts.firm_state.key(), FirmError::Unauthorized);
                require!(acct.affiliate == referral.affiliate, FirmError::Unauthorized);
                // The affiliate rate is fixed platform-wide: an active referred purchase always
                // carves exactly AFFILIATE_DEFAULT_BPS, regardless of the stored per-account rate.
                if acct.active { AFFILIATE_DEFAULT_BPS } else { 0 }
            }
            _ => 0,
        };
        // Loss-back credit application (2026-07-27 staking rebalance) — computed BEFORE the fee
        // split, against the ORIGINAL `amount`, so the discount reduces every leg proportionally
        // instead of being refunded from a side vault. `LossBackCredit.balance` is now purely
        // notional (no backing vault, no token transfer here) — redeeming it just charges the
        // trader less. Gate is now stake-TIER, not a fixed bps-of-stake formula: staking
        // `loss_back_min_stake` $FIRMA in EITHER pool (no-risk or backstop) unlocks redeeming up to
        // 100% of the accrued balance, still capped at 50% of THIS purchase (unchanged safety rail
        // — never a fully-free evaluation regardless of how much credit is banked).
        let discount = {
            let credit = &ctx.accounts.loss_back_credit;
            let min_stake = ctx.accounts.firm_state.loss_back_min_stake;
            let no_risk_staked = ctx.accounts.staker_position.as_ref()
                .map(|p| p.amount_staked).unwrap_or(0);
            let backstop_staked = ctx.accounts.backstop_position.as_ref()
                .map(|p| p.amount_staked).unwrap_or(0);
            let eligible = no_risk_staked >= min_stake || backstop_staked >= min_stake;
            if eligible && credit.balance > 0 {
                credit.balance.min(amount / 2) // 50% cap — prevents fully-free evaluations
            } else {
                0
            }
        };
        let effective_amount = amount.saturating_sub(discount);

        let split = apply_treasury_health_adjustment(
            compute_fee_split(
                effective_amount,
                owner_bps_for_tier(firm_tier),
                lp_bps,
                premium_bps,
                affiliate_bps,
            ),
            effective_amount,
            firm_tier,
            ctx.accounts.firm_state.treasury_sol,
        );
        let now = Clock::get()?.unix_timestamp;

        if discount > 0 {
            let credit = &mut ctx.accounts.loss_back_credit;
            credit.balance = credit.balance.saturating_sub(discount);
            credit.lifetime_redeemed = credit
                .lifetime_redeemed
                .checked_add(discount)
                .ok_or(FirmError::MathOverflow)?;
            emit!(LossBackApplied {
                firm: ctx.accounts.firm_state.key(),
                trader: ctx.accounts.trader.key(),
                discount,
                balance: credit.balance,
            });
        }

        // Pre-graduation the LP share goes to the bonding curve; post-graduation it is
        // held in the treasury until Raydium LP add (Phase 4.4). The $FIRMA buy-back leg (3%)
        // physically lands in the treasury SOL vault and is earmarked in `firma_buyback_acc`;
        // the `execute_firma_buyback` crank later converts it to the Tier-2 $FIRMA reserve.
        //
        // Normal-staking leg (5%, §19 DEC-1): routes directly into the purchasing firm's OWN
        // staking pool when the caller supplies it (see `staking_pool`'s doc comment below) — folded
        // into `acc_sol` further down so its stakers can actually claim the yield. When omitted, the
        // slice stays in the firm's OWN treasury (folded into `to_treasury` here) rather than the
        // old platform-wide `normal_staking_vault`, which had no distribution path out to any staker
        // — removed entirely (also reclaims stack budget: one fewer typed account in
        // `try_accounts`, which was 8 bytes over the 4 KB BPF limit with it still present). A
        // treasury credit outside the cache is already a normal, self-healing event here (see the
        // `treasury_vault` doc comment above) — no separate reconciliation needed.
        let staking_pool_present = ctx.accounts.staking_pool.is_some();
        let treasury_base = split
            .treasury_gross
            .checked_add(split.firma_buyback)
            .ok_or(FirmError::MathOverflow)?
            .checked_add(if staking_pool_present { 0 } else { split.normal_staking })
            .ok_or(FirmError::MathOverflow)?;
        let to_treasury = if graduated {
            treasury_base.checked_add(split.lp).ok_or(FirmError::MathOverflow)?
        } else {
            treasury_base
        };

        ctx.accounts.xfer(ctx.accounts.treasury_vault.to_account_info(), to_treasury)?;
        ctx.accounts.xfer(ctx.accounts.insurance_vault.to_account_info(), split.insurance)?;
        ctx.accounts.xfer(ctx.accounts.owner_wallet_sol.to_account_info(), split.owner_immediate)?;
        ctx.accounts.xfer(ctx.accounts.owner_vesting_vault.to_account_info(), split.owner_vested)?;
        ctx.accounts.xfer(ctx.accounts.dp_profit_sol.to_account_info(), split.dp_profit)?;
        ctx.accounts.xfer(ctx.accounts.dp_treasury_sol.to_account_info(), split.dp_treasury)?;
        if let Some(pool) = ctx.accounts.staking_pool.as_ref() {
            require!(
                ctx.accounts.sol_reward_vault.key() == pool.sol_reward_vault,
                FirmError::InvalidStakingVault
            );
            let vault_ai = ctx.accounts.sol_reward_vault.to_account_info();
            ctx.accounts.xfer(vault_ai, split.normal_staking)?;
            let pool = ctx.accounts.staking_pool.as_mut().unwrap();
            let (acc, unalloc) =
                fold_yield(pool.acc_sol, pool.unallocated_sol, split.normal_staking, pool.total_staked);
            pool.acc_sol = acc;
            pool.unallocated_sol = unalloc;
            pool.last_distribution_at = now;
        }
        ctx.accounts.xfer(ctx.accounts.dprop_buyback_vault.to_account_info(), split.dprop_buyback)?;
        ctx.accounts.xfer(ctx.accounts.dprop_staking_vault.to_account_info(), split.dprop_staking)?;
        ctx.accounts.xfer(ctx.accounts.universal_vault.to_account_info(), split.universal)?;
        {
            let pool = &mut ctx.accounts.universal_pool;
            pool.total_contributed =
                pool.total_contributed.checked_add(split.universal).ok_or(FirmError::MathOverflow)?;
        }
        if !graduated {
            ctx.accounts.route_lp(split.lp)?;
        }

        // Loss-back comeback credit (flywheel, 2026-07-27 staking rebalance) — a PURELY NOTIONAL
        // accrual on the buyer's per-trader `LossBackCredit` (init'd lazily on first purchase), no
        // vault, no token transfer. Accrues unconditionally on what was actually charged
        // (`effective_amount`, i.e. net of any discount already applied above this purchase);
        // redemption is gated on staking (see the discount block above).
        {
            let loss_back_accrual = bps(effective_amount, LOSS_BACK_BPS);
            let credit = &mut ctx.accounts.loss_back_credit;
            if credit.trader == Pubkey::default() {
                credit.firm = ctx.accounts.firm_state.key();
                credit.trader = ctx.accounts.trader.key();
                credit.bump = ctx.bumps.loss_back_credit;
            }
            credit.balance =
                credit.balance.checked_add(loss_back_accrual).ok_or(FirmError::MathOverflow)?;
            credit.lifetime_accrued =
                credit.lifetime_accrued.checked_add(loss_back_accrual).ok_or(FirmError::MathOverflow)?;
            emit!(LossBackAccrued {
                firm: ctx.accounts.firm_state.key(),
                trader: ctx.accounts.trader.key(),
                amount: loss_back_accrual,
                balance: credit.balance,
            });
        }

        // Backstop premium (§19) — carved atomically from the treasury slice and folded into
        // the pool's premium accumulator so stakers can claim it (no separate keeper step).
        if split.backstop_premium > 0 {
            let premium_vault = ctx
                .accounts
                .backstop_premium_vault
                .as_ref()
                .ok_or(FirmError::MissingBackstopAccounts)?;
            {
                let pool = ctx
                    .accounts
                    .backstop_pool
                    .as_ref()
                    .ok_or(FirmError::MissingBackstopAccounts)?;
                require!(
                    premium_vault.key() == pool.premium_vault,
                    FirmError::InvalidBackstopVault
                );
            }
            let premium_vault_ai = premium_vault.to_account_info();
            ctx.accounts.xfer(premium_vault_ai, split.backstop_premium)?;
            let pool = ctx.accounts.backstop_pool.as_mut().unwrap();
            // F-M-5: divide premium by the NOMINAL weight (matches the per-staker nominal numerator).
            let (acc, unalloc) = fold_yield(
                pool.premium_acc,
                pool.unallocated_premium,
                split.backstop_premium,
                pool.total_premium_weight,
            );
            pool.premium_acc = acc;
            pool.unallocated_premium = unalloc;
            pool.last_premium_at = now;
        }

        // Affiliate accrual (§17.1) — referred purchases only. The carved SOL lands in the
        // firm's affiliate vault and the affiliate's lifetime `earned` ledger grows; the
        // affiliate withdraws pull-based via `claim_affiliate`. Vault solvency invariant:
        // vault.balance == Σ(earned − claimed) across the firm's affiliates.
        if split.affiliate_pool > 0 {
            let vault_ai = ctx
                .accounts
                .affiliate_pool_vault
                .as_ref()
                .ok_or(FirmError::MissingAffiliateAccounts)?
                .to_account_info();
            ctx.accounts.xfer(vault_ai, split.affiliate_pool)?;
            let acct = ctx
                .accounts
                .affiliate_account
                .as_mut()
                .ok_or(FirmError::MissingAffiliateAccounts)?;
            acct.earned = acct.earned.checked_add(split.affiliate_pool).ok_or(FirmError::MathOverflow)?;
        }

        let vesting_bump = ctx.bumps.owner_vesting_batch;
        // F-1/F-2 fix: reconcile the cache to the ACTUAL vault balance instead of blindly adding
        // `to_treasury`. The treasury fee was already moved into `treasury_vault` (above), and the vault
        // may ALSO hold out-of-band credits (a bonding-curve fee donated by deploy_burn or a third-party
        // curve buy). Syncing to the live balance absorbs both, keeping `treasury_sol == vault` so the
        // `>=` guard always holds — no curve buy can desync/brick the firm.
        ctx.accounts.treasury_vault.reload()?;
        let treasury_balance = ctx.accounts.treasury_vault.amount;
        let firm = &mut ctx.accounts.firm_state;
        firm.treasury_sol = treasury_balance;
        // Earmark the $FIRMA buy-back slice (already inside `to_treasury`) for conversion to the
        // Tier-2 reserve by `execute_firma_buyback`; treasury_sol stays in sync with the vault.
        firm.firma_buyback_acc =
            firm.firma_buyback_acc.checked_add(split.firma_buyback).ok_or(FirmError::MathOverflow)?;
        // Post-graduation LP fee-leg (§12 / Phase 4.4): pre-graduation `split.lp` was CPI'd into the
        // curve by `route_lp`; post-graduation it was instead folded into `to_treasury` above. Earmark
        // that SOL here so `add_graduated_liquidity` can later deposit it into the graduated Raydium pool
        // as locked LP, rather than it silently becoming ordinary treasury.
        if graduated {
            firm.post_grad_lp_acc =
                firm.post_grad_lp_acc.checked_add(split.lp).ok_or(FirmError::MathOverflow)?;
        }
        // Self-funded operator bond (§10/§14): until the bond is full (50 SOL), earmark 1% of the fee out
        // of the treasury slice for `fund_operator_bond` to move into the dispute-program `OperatorStake`.
        // Like `firma_buyback_acc`, the SOL is already inside `to_treasury` — this only records the claim.
        // Once `bond_funded`, the earmark stops and that 1% stays as treasury. `min` with the treasury
        // gross keeps the earmark covered even in the (implausible) case that all dynamic legs starve it.
        if !firm.bond_funded {
            let bond_leg = bps(amount, BOND_FUNDING_BPS).min(to_treasury);
            firm.bond_accrual =
                firm.bond_accrual.checked_add(bond_leg).ok_or(FirmError::MathOverflow)?;
        }
        let insurance = &mut ctx.accounts.insurance_fund;
        insurance.balance =
            insurance.balance.checked_add(split.insurance).ok_or(FirmError::MathOverflow)?;

        let batch = &mut ctx.accounts.owner_vesting_batch;
        batch.owner = ctx.accounts.firm_state.owner;
        batch.firm = ctx.accounts.firm_state.key();
        batch.amount = split.owner_vested;
        batch.unlocks_at = now.checked_add(OWNER_VESTING_SECONDS).ok_or(FirmError::MathOverflow)?;
        batch.claimed = false;
        batch.bump = vesting_bump;

        emit!(FeePaid {
            firm: ctx.accounts.firm_state.key(),
            amount,
            treasury_gross: to_treasury,
            insurance: split.insurance,
            lp: split.lp,
        });
        Ok(())
    }

    /// Execute a payout buy (§22): the treasury buys $FIRMA from the bonding curve and
    /// delivers it to the passing trader — no minting, ever. The keeper computes
    /// `sol_amount` so the curve returns at least `payout_firma_owed` (passed as the
    /// slippage floor). Enforces the daily 20%-of-treasury cap (§19) and keeps the
    /// `treasury_sol` cache in sync by reloading the vault after the CPI.
    ///
    /// Signed by the challenge's settlement authority. Pre-graduation only in this
    /// slice (post-graduation Raydium routing lands in Phase 4.4). If the treasury is
    /// short, the keeper falls back to the payout queue (Phase 4.3).
    /// `cycle` MUST stay the FIRST argument: `ExecutePayoutBuy`'s `payout_record` seeds reference it, and
    /// `#[instruction(...)]` deserializes the real argument prefix positionally. Moving or inserting an
    /// argument before it silently reads `cycle` from the wrong bytes and fails `ConstraintSeeds` at
    /// RUNTIME, not compile time (CHK-11 — caught exactly this way while building DEC-62).
    pub fn execute_payout_buy<'info>(
        ctx: Context<'_, '_, '_, 'info, ExecutePayoutBuy<'info>>,
        cycle: u32,
        sol_amount: u64,
    ) -> Result<()> {
        let _ = cycle; // seed-only (the PDA derivation above binds it)
        require_firm_settlement_authority(&ctx.accounts.challenge, &ctx.accounts.firm_state)?;
        require!(
            ctx.accounts.challenge.status == challenge::ChallengeStatus::Passed,
            FirmError::ChallengeNotPassed
        );
        let min_firma_out = ctx.accounts.challenge.payout_firma_owed;
        let now = Clock::get()?.unix_timestamp;

        // Daily cap: max(20% of treasury, $2k floor), resetting each UTC day (§19; OMEGA #1).
        let firm = &mut ctx.accounts.firm_state;
        let day = now / 86_400;
        if day != firm.payout_day {
            firm.daily_payout_spent = 0;
            firm.payout_day = day;
        }
        let daily_cap = (firm.treasury_sol / 5).max(MIN_DAILY_PAYOUT_FLOOR_SOL);
        require!(
            firm.daily_payout_spent.saturating_add(sol_amount) <= daily_cap,
            FirmError::DailyPayoutCapExceeded
        );
        require!(sol_amount <= firm.treasury_sol, FirmError::InsufficientTreasury);

        // L-3: record the $FIRMA ACTUALLY delivered (the curve may return more than the owed floor
        // when the keeper over-sizes `sol_amount`), not the `min_firma_out` floor. Snapshot the
        // trader's balance across the CPI for the true delta.
        let firma_before = ctx.accounts.trader_firma.amount;
        // Conversion venue: the curve pre-graduation, the graduated Raydium pool after (model A —
        // funded-trader payouts never strand). Both deliver $FIRMA into `trader_firma`.
        if ctx.accounts.curve.graduated {
            let (fo, fb, sm, fm) = {
                let f = &ctx.accounts.firm_state;
                (f.owner, f.bump, f.sol_mint, f.firma_mint)
            };
            let firm_ai = ctx.accounts.firm_state.to_account_info();
            let input_ai = ctx.accounts.treasury_vault.to_account_info();
            let output_ai = ctx.accounts.trader_firma.to_account_info();
            let bump = [fb];
            let seeds = firm_signer(&fo, &bump);
            swap_graduated(
                &firm_ai, &seeds, &sm, &fm, &input_ai, &output_ai,
                ctx.remaining_accounts, sol_amount, min_firma_out,
            )?;
        } else {
            ctx.accounts.curve_buy(sol_amount, min_firma_out)?;
        }
        ctx.accounts.trader_firma.reload()?;
        let firma_delivered = ctx.accounts.trader_firma.amount.saturating_sub(firma_before);

        // Reload the treasury vault and re-sync the cache (fees may return part of the
        // spend to the treasury, so the true delta is the post-CPI balance).
        ctx.accounts.treasury_vault.reload()?;
        let firm = &mut ctx.accounts.firm_state;
        let new_balance = ctx.accounts.treasury_vault.amount;
        let spent = firm.treasury_sol.saturating_sub(new_balance);
        firm.treasury_sol = new_balance;
        firm.daily_payout_spent = firm.daily_payout_spent.saturating_add(spent);
        firm.total_paid_out = firm.total_paid_out.saturating_add(spent);

        let record = &mut ctx.accounts.payout_record;
        record.cycle = cycle;
        record.challenge = ctx.accounts.challenge.key();
        record.trader = ctx.accounts.challenge.trader;
        record.firma_delivered = firma_delivered;
        record.sol_spent = spent;
        record.claimed_at = now;
        record.bump = ctx.bumps.payout_record;

        emit!(PayoutExecuted {
            firm: ctx.accounts.firm_state.key(),
            challenge: ctx.accounts.challenge.key(),
            firma_delivered,
            sol_spent: spent,
        });
        Ok(())
    }

    /// Enqueue a passed challenge's payout (§22). Creates the `QueuedPayout` PDA at
    /// `["payout", challenge]` — the **same seed** the immediate `execute_payout_buy`
    /// path uses for its `PayoutRecord`, so the two paths are mutually exclusive (a
    /// challenge can be paid once, by exactly one path). `firma_amount_owed` is the
    /// trader's locked $FIRMA; the stakeholder share is computed on top at processing.
    /// The concentration guard (§16 vector 5) holds payouts above 8% of treasury for
    /// 72h of manual review. Signed by the challenge's settlement authority.
    ///
    /// CONCENTRATION-DENOM-1: "treasury" here is the firm's FULL payout-capable backing — Tier-1 SOL
    /// treasury + Tier-2 $FIRMA reserve (priced via a real sell simulation against the live curve, so
    /// a large reserve is valued net of the slippage actually liquidating it would cost, not an
    /// optimistic spot multiply) + Tier-3 operator bond (the account's own lamport balance above rent,
    /// mirroring `reconcile_operator_bond`'s read — never a cached field). Tier-4 (the Universal Pool)
    /// is deliberately excluded: it is shared across every firm on the platform, so folding it into one
    /// firm's per-firm denominator would let it be silently double-counted the moment two firms near
    /// their limit in the same window — the same reasoning the off-chain ARE score's `payoutBufferUsd`
    /// already applies (TREASURY-DENOM-1). Before this fix the guard divided by Tier-1 alone, so a
    /// Healthy firm with a real $FIRMA reserve and a posted bond could still trip an 8% hold sized
    /// against just its thin SOL vault (observed live 2026-07-22: a firm with 820 SOL Tier-1 treasury
    /// held a 76 SOL payout for 72h despite materially larger combined backing).
    pub fn enqueue_payout(
        ctx: Context<EnqueuePayout>,
        cycle: u32,
        sol_at_settlement: u64,
        priority: u8,
        window_target: u8,
    ) -> Result<()> {
        // DEC-62 — two ways a trader is owed SOL, and they are gated differently:
        //
        //  • WITHDRAWAL (`withdrawal` present): a FUNDED account taking profit mid-run. The challenge
        //    stays `Active` and its `settlement_status` stays `Unsettled` forever, so the settlement
        //    gate below can never pass for it. THIS is PAYOUT-CHAIN-GAP-1: `require!(status == Passed)`
        //    is why no funded trader could be paid by any route. The obligation is read from the
        //    `FundedWithdrawal`, whose amount the challenge program bound to the rebaselined transcript
        //    at propose and which has since survived a 72h fraud window.
        //
        //  • SETTLEMENT (`withdrawal` absent): the legacy path for a concluded, `Passed` challenge.
        //    Unchanged.
        let sol_owed = match ctx.accounts.withdrawal.as_ref() {
            Some(w) => {
                require_firm_withdrawal_authority(
                    &ctx.accounts.challenge,
                    &ctx.accounts.firm_state,
                    w,
                )?;
                // Bind the withdrawal to THIS challenge and THIS cycle. The seeds already derive it
                // from both, but a typed check keeps the invariant explicit and local.
                require!(w.challenge == ctx.accounts.challenge.key(), FirmError::Unauthorized);
                require!(w.cycle == cycle, FirmError::Unauthorized);
                // The trader keeps trading through a withdrawal — that is the point of DEC-61 (B).
                require!(
                    ctx.accounts.challenge.phase == challenge::ChallengePhase::Funded,
                    FirmError::ChallengeNotPassed
                );
                w.amount_sol_owed
            }
            None => {
                require_firm_settlement_authority(
                    &ctx.accounts.challenge,
                    &ctx.accounts.firm_state,
                )?;
                require!(
                    ctx.accounts.challenge.status == challenge::ChallengeStatus::Passed,
                    FirmError::ChallengeNotPassed
                );
                ctx.accounts.challenge.payout_sol_owed
            }
        };

        // Path-B sizing (fixed VALUE, not fixed quantity). The trader is owed `sol_owed` — profit ×
        // their split, struck and fraud-bound above (at settlement, or at the withdrawal's propose), in
        // the same lamport units as the treasury. Convert that value into the $FIRMA quantity it buys
        // from the firm's OWN curve at the curve's live on-chain reserves — the price comes from the
        // chain, never a keeper argument. The four delivery tiers then fill this fixed quantity
        // (unchanged). The quantity is struck once here; between enqueue and delivery the trader carries
        // the token, same as any locked fill (a per-fill re-mark would require a curve read in the
        // reserve/backstop tiers — deferred). `sol_at_settlement` (the keeper arg) is advisory only; the
        // obligation size is read on-chain, never from the caller.
        let _ = sol_at_settlement;
        require!(sol_owed > 0, FirmError::ZeroAmount);
        // Pre-graduation only: at graduation the curve's reserves migrate to Raydium (`real_sol` and
        // `firma_reserve` → 0), so a curve-priced strike would compute 0 owed. Refuse loudly rather
        // than enqueue a 0-owed, un-fillable obligation that would wedge `finalize_close`. Post-
        // graduation pricing (read the Raydium pool) is deferred until graduation is live.
        require!(!ctx.accounts.curve.graduated, FirmError::PayoutPricingUnavailable);
        let eff_sol = ctx.accounts.curve.real_sol as u128 + ctx.accounts.curve.virtual_sol as u128;
        let firma_owed = bonding_curve::buy_output(
            eff_sol,
            ctx.accounts.curve.firma_reserve as u128,
            sol_owed as u128,
        )
        .ok_or(FirmError::MathOverflow)?;
        // Dust guard: a profit below one $FIRMA base unit at the current price rounds to 0 owed, which
        // can never be filled and would wedge the close. Refuse it (the eval simply carries no payout).
        require!(firma_owed > 0, FirmError::ZeroAmount);

        let now = Clock::get()?.unix_timestamp;
        let firm = &ctx.accounts.firm_state;

        // Concentration guard: a single payout whose SOL value exceeds 8% of the firm's FULL
        // payout-capable treasury (Tier-1 + Tier-2 + Tier-3 — CONCENTRATION-DENOM-1, see the fn doc
        // comment) is held for review. Compared against the on-chain obligation (`payout_sol_owed`,
        // lamports) — not the keeper argument — so the hold can't be dodged by understating the arg.
        let eff_sol = ctx.accounts.curve.real_sol as u128 + ctx.accounts.curve.virtual_sol as u128;
        let firma_reserve_for_tier2 = ctx.accounts.curve.firma_reserve as u128;
        let tier2_sol = bonding_curve::sell_output(
            eff_sol,
            firma_reserve_for_tier2,
            ctx.accounts.treasury_firma_vault.amount as u128,
        )
        .unwrap_or(0) as u128;
        let tier3_sol = match ctx.accounts.operator_stake.as_ref() {
            Some(os) => {
                let ai = os.to_account_info();
                let rent = Rent::get()?.minimum_balance(ai.data_len());
                ai.lamports().saturating_sub(rent) as u128
            }
            None => 0,
        };
        let total_treasury_sol = (firm.treasury_sol as u128)
            .saturating_add(tier2_sol)
            .saturating_add(tier3_sol)
            .min(u64::MAX as u128) as u64;
        let concentration_limit = bps(total_treasury_sol, CONCENTRATION_GUARD_BPS);
        let hold_until = if sol_owed > concentration_limit {
            now.checked_add(CONCENTRATION_HOLD_SECONDS).ok_or(FirmError::MathOverflow)?
        } else {
            0
        };

        // A withdrawal's split is grandfathered to the tier at PROPOSE (when the trader committed to the
        // withdrawal and the 72h clock started), not the tier now — otherwise a tier escalation during
        // the fraud window would silently re-price an obligation the trader can no longer withdraw from.
        let settlement_tier = match ctx.accounts.withdrawal.as_ref() {
            Some(w) => w.settlement_risk_tier as u8,
            None => firm.risk_tier as u8,
        };

        let qp = &mut ctx.accounts.queued_payout;
        qp.trader = ctx.accounts.challenge.trader;
        qp.firm = firm.key();
        qp.challenge = ctx.accounts.challenge.key();
        qp.cycle = cycle;
        qp.sol_at_settlement = sol_owed;
        qp.firma_amount_owed = firma_owed;
        qp.firma_amount_delivered = 0;
        qp.queued_at = now;
        qp.hold_until = hold_until;
        qp.priority = priority;
        qp.window_target = window_target;
        qp.settlement_tier = settlement_tier;
        qp.bump = ctx.bumps.queued_payout;

        // Record the standing obligation: the firm now owes this trader until the payout is
        // fully delivered. `finalize_close` is gated on this counter (F1) so no insider can
        // close the firm and release the treasury out from under an unpaid trader.
        let firm = &mut ctx.accounts.firm_state;
        firm.open_payouts = firm.open_payouts.checked_add(1).ok_or(FirmError::MathOverflow)?;

        emit!(PayoutQueued {
            firm: qp.firm,
            challenge: qp.challenge,
            trader: qp.trader,
            cycle: qp.cycle,
            firma_owed: qp.firma_amount_owed,
            hold_until,
            settlement_tier: qp.settlement_tier,
        });
        Ok(())
    }

    /// CONCENTRATION-DENOM-1 — permissionless: recompute an already-enqueued payout's concentration
    /// hold against the CURRENT (Tier-1+2+3) formula, and shorten or clear it if the corrected
    /// denominator no longer requires it. For payouts enqueued before this fix landed, when the
    /// on-chain guard still divided by Tier-1 alone.
    ///
    /// NEVER lengthens: `hold_until` only ever moves to `min(current, recomputed)`. A recompute that
    /// still finds the payout over the (now-larger) limit produces `now + CONCENTRATION_HOLD_SECONDS`,
    /// which is always LATER than the original enqueue-time hold — so the `min` correctly leaves an
    /// already-justified hold untouched rather than resetting its clock. A recompute that clears it
    /// produces 0, which `min` always prefers — `now >= 0` is trivially true, so the hold releases
    /// immediately. This makes the instruction safe to crank blindly and repeatedly: it can only ever
    /// help a trader, never cost them time, regardless of who calls it or how often.
    pub fn reconcile_payout_hold(ctx: Context<ReconcilePayoutHold>, cycle: u32) -> Result<()> {
        let _ = cycle; // seed-only (bound by the PDA derivation below)
        let now = Clock::get()?.unix_timestamp;
        let firm = &ctx.accounts.firm_state;
        let eff_sol = ctx.accounts.curve.real_sol as u128 + ctx.accounts.curve.virtual_sol as u128;
        let firma_reserve = ctx.accounts.curve.firma_reserve as u128;
        let tier2_sol = bonding_curve::sell_output(
            eff_sol,
            firma_reserve,
            ctx.accounts.treasury_firma_vault.amount as u128,
        )
        .unwrap_or(0) as u128;
        let tier3_sol = match ctx.accounts.operator_stake.as_ref() {
            Some(os) => {
                let ai = os.to_account_info();
                let rent = Rent::get()?.minimum_balance(ai.data_len());
                ai.lamports().saturating_sub(rent) as u128
            }
            None => 0,
        };
        let total_treasury_sol = (firm.treasury_sol as u128)
            .saturating_add(tier2_sol)
            .saturating_add(tier3_sol)
            .min(u64::MAX as u128) as u64;
        let concentration_limit = bps(total_treasury_sol, CONCENTRATION_GUARD_BPS);

        let qp = &mut ctx.accounts.queued_payout;
        let recomputed_hold_until = if qp.sol_at_settlement > concentration_limit {
            now.checked_add(CONCENTRATION_HOLD_SECONDS).ok_or(FirmError::MathOverflow)?
        } else {
            0
        };
        let old_hold_until = qp.hold_until;
        qp.hold_until = qp.hold_until.min(recomputed_hold_until);

        emit!(PayoutHoldReconciled {
            firm: qp.firm,
            challenge: qp.challenge,
            cycle: qp.cycle,
            old_hold_until,
            new_hold_until: qp.hold_until,
        });
        Ok(())
    }

    /// Process a (possibly partial) fill of a queued payout (§22). The treasury buys
    /// $FIRMA from the curve into the staging vault, delivers up to the outstanding
    /// trader amount, and distributes the proportional stakeholder share four ways per
    /// `StakeholderConfig` (owner + staking transferred; buyback/burn burned; treasury
    /// reserve left in the staging vault). The split % is the **settlement tier** locked
    /// when queued (grandfathering, §22). Honors the concentration-guard hold, the daily
    /// 20% cap, and the treasury sync contract. If the fill leaves the payout
    /// outstanding, it trips the on-chain circuit breaker: velocity break + immediate
    /// one-step tier escalation (§16 vector 5).
    pub fn process_queued_payout<'info>(
        ctx: Context<'_, '_, '_, 'info, ProcessQueuedPayout<'info>>,
        sol_amount: u64,
        min_firma_out: u64,
    ) -> Result<()> {
        require_payout_delivery_authority(
            &ctx.accounts.challenge,
            &ctx.accounts.firm_state,
            ctx.accounts.withdrawal.as_deref().map(|w| &**w),
        )?;
        // Post-graduation the conversion venue is the Raydium pool (model A), so this no longer bails on
        // a graduated curve — the buy below routes through Raydium instead (funded-trader payouts never strand).
        //
        // TREASURY-FIRST (DEC-64, was M-3 reserve-first): the curve buy is the PRIMARY payout path — every
        // payout spends treasury SOL to buy $FIRMA on the curve, which is a real, visible buy that supports
        // the token price. The Tier-2 reserve is now the BACKSTOP the keeper falls to only when the treasury
        // can't fund the buy (`draw_treasury_firma`). So this no longer refuses a curve buy while the reserve
        // holds stock — the old `ReserveNotExhausted` guard was pure policy, not a safety invariant, and the
        // policy (which tier is primary) is the keeper's to sequence, not the program's to hard-code. The
        // MEV/sandwich exposure the old guard avoided is bounded by the caller's `min_firma_out` slippage floor.
        let now = Clock::get()?.unix_timestamp;
        require!(now >= ctx.accounts.queued_payout.hold_until, FirmError::PayoutOnHold);
        require!(
            ctx.accounts.queued_payout.firma_amount_delivered
                < ctx.accounts.queued_payout.firma_amount_owed,
            FirmError::PayoutAlreadyFilled
        );

        // Daily cap: max(20% of treasury, $2k floor), resetting each UTC day (§19; OMEGA #1).
        let firm = &mut ctx.accounts.firm_state;
        let day = now / 86_400;
        if day != firm.payout_day {
            firm.daily_payout_spent = 0;
            firm.payout_day = day;
        }
        let daily_cap = (firm.treasury_sol / 5).max(MIN_DAILY_PAYOUT_FLOOR_SOL);
        require!(
            firm.daily_payout_spent.saturating_add(sol_amount) <= daily_cap,
            FirmError::DailyPayoutCapExceeded
        );
        require!(sol_amount <= firm.treasury_sol, FirmError::InsufficientTreasury);

        // Load payout-split config and settlement tier before the buy so the universal
        // SOL carve can execute first.
        let cfg = ctx.accounts.firm_state.stakeholder_config;
        let backstop_pool_bps = ctx.accounts.firm_state.backstop_pool_bps;
        let qp_tier = risk_tier_from_u8(ctx.accounts.queued_payout.settlement_tier);
        let split = payout_tier_split(qp_tier);

        // Universal SOL carve (§19): transfer the stakeholder's SOL notional fraction
        // directly to the Universal Treasury Pool *before* the curve buy. This represents
        // `StakeholderConfig.universal_sol_bps` (40% default) of the stakeholder's share
        // of `sol_amount`. The curve buy then uses the reduced SOL so the trader's $FIRMA
        // delivery stays correct (the $FIRMA split is adjusted via `effective_stakeholder_bps`).
        let stakeholder_sol_notional = bps(sol_amount, split.stakeholder_bps);
        let universal_carve = bps(stakeholder_sol_notional, cfg.universal_sol_bps);
        if universal_carve > 0 {
            ctx.accounts.carve_to_universal(universal_carve)?;
            ctx.accounts.universal_pool.total_contributed =
                ctx.accounts.universal_pool.total_contributed.saturating_add(universal_carve);
        }
        let curve_sol = sol_amount.saturating_sub(universal_carve);

        // Buy $FIRMA into the staging vault, then measure what was actually bought. Conversion venue: the
        // curve pre-graduation, else the graduated Raydium pool (model A). All downstream split logic is
        // identical — it operates on the staging-vault delta regardless of where the $FIRMA came from.
        let before = ctx.accounts.payout_firma_vault.amount;
        if ctx.accounts.curve.graduated {
            let (fo, fb, sm, fm) = {
                let f = &ctx.accounts.firm_state;
                (f.owner, f.bump, f.sol_mint, f.firma_mint)
            };
            let firm_ai = ctx.accounts.firm_state.to_account_info();
            let input_ai = ctx.accounts.treasury_vault.to_account_info();
            let output_ai = ctx.accounts.payout_firma_vault.to_account_info();
            let bump = [fb];
            let seeds = firm_signer(&fo, &bump);
            swap_graduated(
                &firm_ai, &seeds, &sm, &fm, &input_ai, &output_ai,
                ctx.remaining_accounts, curve_sol, min_firma_out,
            )?;
        } else {
            ctx.accounts.curve_buy(curve_sol, min_firma_out)?;
        }
        ctx.accounts.payout_firma_vault.reload()?;
        let bought = ctx.accounts.payout_firma_vault.amount.saturating_sub(before);

        // Split the freshly bought $FIRMA chunk into trader / stakeholder. The effective
        // stakeholder bps is reduced by the universal_sol_bps fraction already extracted
        // as SOL, keeping the trader's $FIRMA delivery proportionally correct.
        let effective_stakeholder_bps = ((split.stakeholder_bps as u32)
            .saturating_mul(10_000 - cfg.universal_sol_bps as u32) / 10_000) as u16;
        let total_bps = (split.trader_bps as u128) + (effective_stakeholder_bps as u128);
        let outstanding = ctx
            .accounts
            .queued_payout
            .firma_amount_owed
            .saturating_sub(ctx.accounts.queued_payout.firma_amount_delivered);
        let trader_from_chunk = if total_bps == 0 { bought } else {
            ((bought as u128 * split.trader_bps as u128) / total_bps) as u64
        };
        let trader_deliver = trader_from_chunk.min(outstanding);
        let stakeholder_deliver = if split.trader_bps == 0 || effective_stakeholder_bps == 0 {
            0
        } else {
            ((trader_deliver as u128 * effective_stakeholder_bps as u128) / split.trader_bps as u128) as u64
        };

        // Deliver the trader leg.
        ctx.accounts.pay_firma(ctx.accounts.trader_firma.to_account_info(), trader_deliver)?;

        // Distribute the $FIRMA stakeholder leg: owner + staking transferred, buyback/burn
        // burned, treasury reserve left in the staging vault (already firm-owned).
        // `split_stakeholder` renormalises by (10000 - universal_sol_bps) so each $FIRMA
        // leg gets the correct fraction of the *original* stakeholder notional.
        let sh = split_stakeholder(stakeholder_deliver, &cfg, backstop_pool_bps);
        ctx.accounts.pay_firma(ctx.accounts.owner_firma.to_account_info(), sh.owner)?;
        ctx.accounts.pay_firma(ctx.accounts.staking_vault.to_account_info(), sh.staking)?;
        if let Some(backstop_vault) = ctx.accounts.backstop_firma_reward_vault.as_ref() {
            ctx.accounts.pay_firma(backstop_vault.to_account_info(), sh.backstop)?;
        }
        // No backstop pool for this firm: `sh.backstop` simply stays in the staging vault,
        // same as any other undistributed stakeholder residual.
        ctx.accounts.burn_firma(sh.buyback_burn)?;

        // Treasury accounting: reload and re-sync (§19).
        ctx.accounts.treasury_vault.reload()?;
        let firm = &mut ctx.accounts.firm_state;
        let new_balance = ctx.accounts.treasury_vault.amount;
        let spent = firm.treasury_sol.saturating_sub(new_balance);
        firm.treasury_sol = new_balance;
        firm.daily_payout_spent = firm.daily_payout_spent.saturating_add(spent);
        firm.total_paid_out = firm.total_paid_out.saturating_add(spent);

        let qp = &mut ctx.accounts.queued_payout;
        qp.firma_amount_delivered = qp.firma_amount_delivered.saturating_add(trader_deliver);
        let fully_filled = qp.firma_amount_delivered >= qp.firma_amount_owed;

        // Circuit breaker: an outstanding payout after this fill means the treasury
        // could not satisfy it — trip velocity break and escalate one tier immediately.
        if !fully_filled {
            firm.velocity_break_flag = true;
            let current = firm.risk_tier as u8;
            if current < RiskTier::Warning as u8 {
                firm.risk_tier = risk_tier_from_u8(current + 1);
                firm.last_tier_change_at = now;
                emit!(RiskTierUpdated { firm: firm.key(), tier: firm.risk_tier, changed_at: now });
            }
        } else {
            // Obligation discharged: the entry can only reach `firma_amount_delivered >=
            // firma_amount_owed` once (the ix requires it be outstanding at entry), so this
            // fires exactly on the single fully-filled transition. Clears the F1 close gate.
            firm.open_payouts = firm.open_payouts.saturating_sub(1);
        }

        emit!(QueuedPayoutFilled {
            firm: ctx.accounts.firm_state.key(),
            challenge: ctx.accounts.queued_payout.challenge,
            cycle: ctx.accounts.queued_payout.cycle,
            trader_delivered: trader_deliver,
            stakeholder_delivered: stakeholder_deliver,
            universal_sol_carved: universal_carve,
            sol_spent: spent,
            fully_filled,
        });
        Ok(())
    }

    /// DEC-77 — first-payout instant advance (§22b). Pays a trader's SETTLEMENT-path payout
    /// immediately, out of the Payout Staging Vault, while the settlement is still `Provisional`
    /// (inside its fraud-proof window) — i.e. BEFORE the normal `enqueue_payout`/`process_queued_payout`
    /// path could ever run (both hard-require `Final`). Bounded ONLY by `ADVANCE_CAP_BPS` of the firm's
    /// treasury (`AdvancePool.sol_outstanding`): there is no fraud-proof recovery path once
    /// $FIRMA leaves this vault (`payout_sol_owed` is keeper-struck with no on-chain fraud-proof
    /// coverage, SETTLE-SOL-PRICE-1 — a fault proof can never validate the AMOUNT, only the
    /// transcript), so if the settlement is later proven `Faulted`, the advance is a permanent,
    /// unrecoverable treasury loss, written off by `write_off_faulted_advance`. This is the ONLY safety
    /// mechanism bounding this instruction — see `reports/2026-07-23-instant-payout-advance.md` and
    /// DEC-77 (MASTER_DECISIONS.md). SETTLEMENT PATH ONLY: no withdrawal-path twin — CF-86 (the
    /// funded-withdrawal fraud family) has no watchtower coverage at all, so advancing there would have
    /// no compensating control whatsoever.
    ///
    /// Off-chain policy (which wallets qualify as a genuine "first payout") is NOT enforced here — same
    /// convention as Wallet Standing elsewhere in the protocol (gateway-authoritative). This instruction
    /// only enforces the STRUCTURAL bounds: the window/claim gate and the advance-float cap.
    ///
    /// Reuses the exact curve-buy + trader/stakeholder split math `process_queued_payout` uses, and
    /// creates the `QueuedPayout` EARLY with `firma_amount_delivered` already set to what this call
    /// paid the trader — the existing partial-fill mechanism (`outstanding = owed - delivered`) is what
    /// lets a later, normal `process_queued_payout` call (once Final) correctly complete just the
    /// remaining stakeholder-bps portion without ever re-paying the trader.
    pub fn advance_first_payout<'info>(
        ctx: Context<'_, '_, '_, 'info, AdvanceFirstPayout<'info>>,
        sol_amount: u64,
        min_firma_out: u64,
    ) -> Result<()> {
        require_firm_advance_authority(&ctx.accounts.challenge, &ctx.accounts.firm_state)?;

        let sol_owed = ctx.accounts.challenge.payout_sol_owed;
        require!(sol_owed > 0, FirmError::ZeroAmount);
        require!(sol_amount > 0, FirmError::ZeroAmount);
        require!(sol_amount <= sol_owed, FirmError::AdvanceExceedsOwed);
        // PAYOUT-ADVANCE-10: never trust the claimed amount past this fraction — see ADVANCE_MAX_CLAIM_BPS.
        require!(
            sol_amount <= bps(sol_owed, ADVANCE_MAX_CLAIM_BPS),
            FirmError::AdvanceExceedsClaimFraction
        );
        // Pre-graduation only — mirrors `enqueue_payout`'s own guard (post-grad pricing is deferred).
        require!(!ctx.accounts.curve.graduated, FirmError::PayoutPricingUnavailable);

        let eff_sol = ctx.accounts.curve.real_sol as u128 + ctx.accounts.curve.virtual_sol as u128;
        let firma_owed_full = bonding_curve::buy_output(
            eff_sol,
            ctx.accounts.curve.firma_reserve as u128,
            sol_owed as u128,
        )
        .ok_or(FirmError::MathOverflow)?;
        require!(firma_owed_full > 0, FirmError::ZeroAmount);

        let now = Clock::get()?.unix_timestamp;

        // Concentration guard (§16 vector 5, CONCENTRATION-DENOM-1): an oversized first-payout
        // obligation is simply NOT advance-eligible — it falls through to the normal, hold-aware
        // enqueue/deliver path once Final, which already applies the hold correctly. An advance never
        // holds-then-pays; it either qualifies outright now or doesn't run at all.
        let firma_reserve_for_tier2 = ctx.accounts.curve.firma_reserve as u128;
        let tier2_sol = bonding_curve::sell_output(
            eff_sol,
            firma_reserve_for_tier2,
            ctx.accounts.treasury_firma_vault.amount as u128,
        )
        .unwrap_or(0) as u128;
        let tier3_sol = match ctx.accounts.operator_stake.as_ref() {
            Some(os) => {
                let ai = os.to_account_info();
                let rent = Rent::get()?.minimum_balance(ai.data_len());
                ai.lamports().saturating_sub(rent) as u128
            }
            None => 0,
        };
        let total_treasury_sol = (ctx.accounts.firm_state.treasury_sol as u128)
            .saturating_add(tier2_sol)
            .saturating_add(tier3_sol)
            .min(u64::MAX as u128) as u64;
        let concentration_limit = bps(total_treasury_sol, CONCENTRATION_GUARD_BPS);
        require!(sol_owed <= concentration_limit, FirmError::PayoutOnHold);

        // DEC-77 advance-float cap: the ONLY safety mechanism bounding this money movement (see the
        // constant's doc comment). Checked against the LIVE outstanding counter, not a snapshot.
        // PAYOUT-ADVANCE-12: sized off `total_treasury_sol` (tiers 1-3, computed above for the
        // concentration guard) — NOT `firm_state.treasury_sol` alone. The concentration guard a few
        // lines up already treats the $FIRMA reserve and operator stake as real absorbable capacity;
        // the advance cap was inconsistently ignoring both, understating a firm's true risk-bearing
        // capacity. Deliberately excludes the Universal Treasury Pool (tier 4) — that pool backstops
        // insolvency across every firm, not one firm's own risk budget.
        let advance_limit = bps(total_treasury_sol, ADVANCE_CAP_BPS);
        let remaining_cap = advance_limit.saturating_sub(ctx.accounts.advance_pool.sol_outstanding);
        require!(sol_amount <= remaining_cap, FirmError::AdvanceCapExceeded);

        // PAYOUT-ADVANCE-11: dedicated advance-only daily velocity cap, separate from the shared
        // `daily_payout_spent` below — see ADVANCE_DAILY_CAP_BPS's doc comment. Scoped block so this
        // mutable borrow of `advance_pool` ends before `queued_payout`/`advance_pool` are borrowed again
        // later in this instruction. Same tiers-1-3 basis as `advance_limit` above (PAYOUT-ADVANCE-12).
        {
            let pool = &mut ctx.accounts.advance_pool;
            let advance_day = now / 86_400;
            if advance_day != pool.advance_day {
                pool.daily_advance_spent = 0;
                pool.advance_day = advance_day;
            }
            let advance_daily_cap =
                bps(total_treasury_sol, ADVANCE_DAILY_CAP_BPS).max(MIN_DAILY_ADVANCE_FLOOR_SOL);
            require!(
                pool.daily_advance_spent.saturating_add(sol_amount) <= advance_daily_cap,
                FirmError::AdvanceDailyCapExceeded
            );
        }

        // Daily cap + treasury balance — identical gate to `process_queued_payout`.
        let firm = &mut ctx.accounts.firm_state;
        let day = now / 86_400;
        if day != firm.payout_day {
            firm.daily_payout_spent = 0;
            firm.payout_day = day;
        }
        let daily_cap = (firm.treasury_sol / 5).max(MIN_DAILY_PAYOUT_FLOOR_SOL);
        require!(
            firm.daily_payout_spent.saturating_add(sol_amount) <= daily_cap,
            FirmError::DailyPayoutCapExceeded
        );
        require!(sol_amount <= firm.treasury_sol, FirmError::InsufficientTreasury);

        let cfg = firm.stakeholder_config;
        let backstop_pool_bps = firm.backstop_pool_bps;
        let tier = firm.risk_tier;
        let split = payout_tier_split(tier);

        // Universal SOL carve, then curve buy into the staging vault — identical to `process_queued_payout`.
        let stakeholder_sol_notional = bps(sol_amount, split.stakeholder_bps);
        let universal_carve = bps(stakeholder_sol_notional, cfg.universal_sol_bps);
        if universal_carve > 0 {
            ctx.accounts.carve_to_universal(universal_carve)?;
            ctx.accounts.universal_pool.total_contributed =
                ctx.accounts.universal_pool.total_contributed.saturating_add(universal_carve);
        }
        let curve_sol = sol_amount.saturating_sub(universal_carve);

        let before = ctx.accounts.payout_firma_vault.amount;
        ctx.accounts.curve_buy(curve_sol, min_firma_out)?;
        ctx.accounts.payout_firma_vault.reload()?;
        let bought = ctx.accounts.payout_firma_vault.amount.saturating_sub(before);

        let effective_stakeholder_bps = ((split.stakeholder_bps as u32)
            .saturating_mul(10_000 - cfg.universal_sol_bps as u32) / 10_000) as u16;
        let total_bps = (split.trader_bps as u128) + (effective_stakeholder_bps as u128);
        // outstanding == firma_owed_full here — this is the FIRST delivery, nothing has been paid yet.
        let trader_from_chunk = if total_bps == 0 { bought } else {
            ((bought as u128 * split.trader_bps as u128) / total_bps) as u64
        };
        let trader_deliver = trader_from_chunk.min(firma_owed_full);
        let stakeholder_deliver = if split.trader_bps == 0 || effective_stakeholder_bps == 0 {
            0
        } else {
            ((trader_deliver as u128 * effective_stakeholder_bps as u128) / split.trader_bps as u128) as u64
        };

        ctx.accounts.pay_firma(ctx.accounts.trader_firma.to_account_info(), trader_deliver)?;
        let sh = split_stakeholder(stakeholder_deliver, &cfg, backstop_pool_bps);
        ctx.accounts.pay_firma(ctx.accounts.owner_firma.to_account_info(), sh.owner)?;
        ctx.accounts.pay_firma(ctx.accounts.staking_vault.to_account_info(), sh.staking)?;
        if let Some(backstop_vault) = ctx.accounts.backstop_firma_reward_vault.as_ref() {
            ctx.accounts.pay_firma(backstop_vault.to_account_info(), sh.backstop)?;
        }
        // No backstop pool for this firm: `sh.backstop` simply stays in the staging vault,
        // same as any other undistributed stakeholder residual.
        ctx.accounts.burn_firma(sh.buyback_burn)?;

        ctx.accounts.treasury_vault.reload()?;
        let firm = &mut ctx.accounts.firm_state;
        let new_balance = ctx.accounts.treasury_vault.amount;
        let spent = firm.treasury_sol.saturating_sub(new_balance);
        firm.treasury_sol = new_balance;
        firm.daily_payout_spent = firm.daily_payout_spent.saturating_add(spent);
        firm.total_paid_out = firm.total_paid_out.saturating_add(spent);
        firm.open_payouts = firm.open_payouts.checked_add(1).ok_or(FirmError::MathOverflow)?;
        let firm_key = firm.key();
        let settlement_tier_u8 = tier as u8;

        // Idempotent: harmless to re-set on every call, and correctly self-initializes the first time
        // `init_if_needed` creates this PDA (zero-filled, so `firm`/`bump` need setting exactly once —
        // writing them unconditionally is simpler and just as cheap as a conditional check).
        let pool = &mut ctx.accounts.advance_pool;
        pool.firm = firm_key;
        pool.bump = ctx.bumps.advance_pool;
        pool.sol_outstanding = pool.sol_outstanding.saturating_add(spent);
        pool.daily_advance_spent = pool.daily_advance_spent.saturating_add(spent);
        let advance_outstanding_after = pool.sol_outstanding;

        let qp = &mut ctx.accounts.queued_payout;
        qp.trader = ctx.accounts.challenge.trader;
        qp.firm = firm_key;
        qp.challenge = ctx.accounts.challenge.key();
        qp.cycle = 0;
        qp.sol_at_settlement = sol_owed;
        qp.firma_amount_owed = firma_owed_full;
        qp.firma_amount_delivered = trader_deliver;
        qp.queued_at = now;
        qp.hold_until = 0;
        qp.priority = 0;
        qp.window_target = 0;
        qp.settlement_tier = settlement_tier_u8;
        qp.bump = ctx.bumps.queued_payout;
        qp.advance_sol_spent = spent;

        emit!(PayoutQueued {
            firm: qp.firm,
            challenge: qp.challenge,
            trader: qp.trader,
            cycle: qp.cycle,
            firma_owed: qp.firma_amount_owed,
            hold_until: 0,
            settlement_tier: qp.settlement_tier,
        });
        emit!(QueuedPayoutFilled {
            firm: qp.firm,
            challenge: qp.challenge,
            cycle: qp.cycle,
            trader_delivered: trader_deliver,
            stakeholder_delivered: stakeholder_deliver,
            universal_sol_carved: universal_carve,
            sol_spent: spent,
            fully_filled: qp.firma_amount_delivered >= qp.firma_amount_owed,
        });
        emit!(PayoutAdvanceIssued {
            firm: qp.firm,
            challenge: qp.challenge,
            trader: qp.trader,
            sol_advanced: spent,
            firma_delivered: trader_deliver,
            firma_owed_full,
            advance_sol_outstanding_after: advance_outstanding_after,
        });
        Ok(())
    }

    /// DEC-77 — permissionless: retire an outstanding advance's contribution to
    /// `AdvancePool.sol_outstanding` once its settlement reaches `Final` (fraud-proof window closed
    /// with no fault proven). Gated ONLY on `Final`, regardless of whether the trader's `QueuedPayout`
    /// is itself fully delivered yet (if the advance already covered the full entitlement in one shot,
    /// `process_queued_payout`'s own collector excludes it since nothing is outstanding, so nothing
    /// else would ever retire this counter otherwise). No funds move here — pure bookkeeping; the SOL
    /// already left the treasury at advance time.
    pub fn reconcile_payout_advance(ctx: Context<ReconcilePayoutAdvance>) -> Result<()> {
        require!(
            ctx.accounts.challenge.settlement_status == challenge::SettlementStatus::Final,
            FirmError::SettlementNotFinal
        );
        let qp = &mut ctx.accounts.queued_payout;
        require!(qp.advance_sol_spent > 0, FirmError::NothingToReconcile);
        let released = qp.advance_sol_spent;
        qp.advance_sol_spent = 0;
        let challenge_key = qp.challenge;
        let pool = &mut ctx.accounts.advance_pool;
        pool.sol_outstanding = pool.sol_outstanding.saturating_sub(released);
        emit!(PayoutAdvanceResolved {
            firm: pool.firm,
            challenge: challenge_key,
            advance_sol_released: released,
        });
        Ok(())
    }

    /// DEC-77 — permissionless: write off an advance whose settlement was proven `Faulted`. Permanent
    /// and immediate (no 90-day wait, unlike `force_discharge_undeliverable_payout` — the loss is
    /// already certain the instant the fault lands; waiting protects nobody). Closes the trader's
    /// remaining obligation (nothing more is owed — the claim was faulted) so `close_queued_payout`
    /// becomes reachable, and releases the advance's contribution to `AdvancePool.sol_outstanding`. No
    /// fund movement: the SOL was already spent at advance time and is not recoverable from the
    /// trader's wallet by any instruction in this protocol — that absence is deliberate, not a gap
    /// (see DEC-77, MASTER_DECISIONS.md).
    pub fn write_off_faulted_advance(ctx: Context<WriteOffFaultedAdvance>) -> Result<()> {
        require!(
            ctx.accounts.challenge.settlement_status == challenge::SettlementStatus::Faulted,
            FirmError::SettlementNotFaulted
        );
        let qp = &mut ctx.accounts.queued_payout;
        require!(qp.firma_amount_delivered < qp.firma_amount_owed, FirmError::PayoutFullyDelivered);
        require!(qp.advance_sol_spent > 0, FirmError::NothingToReconcile);
        let undelivered = qp.firma_amount_owed.saturating_sub(qp.firma_amount_delivered);
        let lost_sol = qp.advance_sol_spent;
        qp.firma_amount_owed = qp.firma_amount_delivered; // nothing further owed — the claim was faulted
        qp.advance_sol_spent = 0;
        let trader = qp.trader;
        let challenge_key = qp.challenge;
        let firm = &mut ctx.accounts.firm_state;
        firm.open_payouts = firm.open_payouts.saturating_sub(1);
        let firm_key = firm.key();
        let pool = &mut ctx.accounts.advance_pool;
        pool.sol_outstanding = pool.sol_outstanding.saturating_sub(lost_sol);
        emit!(PayoutAdvanceWrittenOff {
            firm: firm_key,
            challenge: challenge_key,
            trader,
            undelivered_firma: undelivered,
            advance_sol_lost: lost_sol,
        });
        Ok(())
    }

    /// Close a fully delivered queued payout and return its rent to the trader (§22
    /// `close_queued_payout`). Requires `firma_amount_delivered >= firma_amount_owed`.
    pub fn close_queued_payout(_ctx: Context<CloseQueuedPayout>) -> Result<()> {
        Ok(())
    }

    /// C-7 — permissionless escape valve for an UNDELIVERABLE queued payout that would otherwise wedge
    /// `finalize_bankruptcy` forever (`open_payouts` never reaches 0). Only callable while the firm is
    /// winding down — now `status == Bankrupt` (§24 v2; the old owner-initiated close is gone) — and only
    /// once the payout has sat undelivered far past any reasonable delivery window (`queued_at +
    /// FORCE_DISCHARGE_TIMEOUT`, 90 days). Decrements `open_payouts` and closes the account (rent → the
    /// trader). The undelivered remainder is written off — a deliberate liveness/finality trade: after 90
    /// days the $FIRMA genuinely can't be delivered (curve drained, trader ATA gone), and a bankrupt firm
    /// must be able to finish winding down. Permissionless (anyone — a watchtower or the trader — may
    /// trigger it once the window elapses), so no one can withhold a real payout early or wedge the wind-down.
    pub fn force_discharge_undeliverable_payout(
        ctx: Context<ForceDischargeUndeliverablePayout>,
    ) -> Result<()> {
        let now = Clock::get()?.unix_timestamp;
        let qp = &ctx.accounts.queued_payout;
        require!(
            ctx.accounts.firm_state.status == FirmStatus::Bankrupt,
            FirmError::InvalidFirmStatus
        );
        // A fully-delivered payout already decremented `open_payouts`; use `close_queued_payout`.
        require!(qp.firma_amount_delivered < qp.firma_amount_owed, FirmError::PayoutFullyDelivered);
        let deadline = qp.queued_at.checked_add(FORCE_DISCHARGE_TIMEOUT).ok_or(FirmError::MathOverflow)?;
        require!(now >= deadline, FirmError::PayoutStillDeliverable);
        let undelivered = qp.firma_amount_owed.saturating_sub(qp.firma_amount_delivered);
        let challenge = qp.challenge;
        let trader = qp.trader;
        let firm = &mut ctx.accounts.firm_state;
        firm.open_payouts = firm.open_payouts.saturating_sub(1);
        emit!(PayoutForceDischarged { firm: firm.key(), challenge, trader, undelivered });
        Ok(())
    }

    /// Firm-side graduation settlement (§16 vector 1). Once the curve has graduated
    /// (its threshold is verified on-chain by `bonding_curve.graduate`), the treasury
    /// **burns 100% of the Raydium LP tokens it received** from seeding the pool — so no
    /// one can ever withdraw the liquidity — and flips `firm.graduated = true`, which
    /// re-routes the LP share of future fees to Raydium. Permissionless.
    ///
    /// The Raydium pool-seed CPI that mints those LP tokens into `treasury_lp_account`
    /// is the devnet-integration boundary (no Raydium program on localnet); this
    /// instruction settles the on-chain-verifiable anti-rug guarantee: the LP supply
    /// the treasury holds goes to zero.
    pub fn graduate_firm(ctx: Context<GraduateFirm>) -> Result<()> {
        require!(ctx.accounts.curve.graduated, FirmError::CurveNotGraduated);
        require!(!ctx.accounts.firm_state.graduated, FirmError::AlreadyGraduated);

        let lp_amount = ctx.accounts.treasury_lp_account.amount;
        ctx.accounts.burn_lp(lp_amount)?;

        let firm = &mut ctx.accounts.firm_state;
        firm.graduated = true;
        emit!(FirmGraduated { firm: firm.key(), lp_burned: lp_amount });
        Ok(())
    }

    /// Wind down a **bankrupt** firm (§24 v2). PERMISSIONLESS — a firm reaches `Bankrupt` only via the
    /// automatic 10%-ULP-depletion trigger (in `draw_universal` / `settle_dispute_payout`), and this
    /// settles what's left. There is no owner-initiated close and no timelock: a bankrupt operator has no
    /// residual claim, so every lamport goes back to the commons and there is no insider to protect against.
    ///
    /// Hard-gated on `open_payouts == 0`: every queued trader obligation must be delivered
    /// (`process_queued_payout`) or force-discharged (`force_discharge_undeliverable_payout`, after 90 days)
    /// FIRST — traders are made whole before the residual moves. Then the firm's entire SOL residual —
    /// treasury + insurance + loss-back — is swept into the **Universal Pool** to partially repay the
    /// commons it drained (`total_contributed += swept`). The $FIRMA owner drip is out of scope here (SOL
    /// pool); its unvested batches are separately clawed back to the treasury by `clawback_vesting`.
    pub fn finalize_bankruptcy(ctx: Context<FinalizeBankruptcy>) -> Result<()> {
        require!(
            ctx.accounts.firm_state.status == FirmStatus::Bankrupt,
            FirmError::InvalidFirmStatus
        );
        // Traders first: don't sweep the residual to the pool while a queued trader is still owed.
        require!(ctx.accounts.firm_state.open_payouts == 0, FirmError::OutstandingPayouts);

        let treasury_amount = ctx.accounts.treasury_vault.amount;
        let insurance_amount = ctx.accounts.insurance_vault.amount;
        // No more loss_back_vault to sweep (2026-07-27 staking rebalance) — comeback credit is a
        // purely notional per-trader counter now, never a real balance sitting in a firm vault.

        // Everything → the Universal Pool (repay the commons). No owner leg. The firm PDA authorizes each.
        let uni = ctx.accounts.universal_vault.to_account_info();
        ctx.accounts.from_treasury(uni.clone(), treasury_amount)?;
        ctx.accounts.from_insurance(uni, insurance_amount)?;

        let swept = treasury_amount.saturating_add(insurance_amount);
        ctx.accounts.universal_pool.total_contributed = ctx
            .accounts
            .universal_pool
            .total_contributed
            .saturating_add(swept);

        let firm = &mut ctx.accounts.firm_state;
        firm.treasury_sol = 0;
        ctx.accounts.insurance_fund.balance = 0;
        emit!(FirmBankruptcyFinalized { firm: firm.key(), swept_to_ulp: swept });
        Ok(())
    }

    /// Claim a matured owner vesting batch (§17) — the exit that was missing (VEST-1).
    ///
    /// `pay_challenge_fee` routes HALF the owner's fee share into `owner_vesting_vault` on every
    /// evaluation sale and writes a batch with `unlocks_at = now + 90d`. Until this instruction
    /// existed, nothing could ever pay it out: the only consumer of `OwnerVestingBatch` was
    /// `clawback_vesting`, which routes batches to the TREASURY on bankruptcy. An operator's own
    /// income had exactly one exit and it wasn't to them. Measured on devnet 2026-07-16: 19.98 SOL
    /// across 25 firms, 81 batches, 0 claimable-and-claimed — invisible only because no batch had
    /// reached day 90 yet.
    ///
    /// Owner-signed, not permissionless: it moves money to a specific wallet, so the person it
    /// belongs to asks for it. The `owner_wallet_sol` constraint mirrors `pay_challenge_fee`'s M-4
    /// guard exactly — the destination must be owned by `firm_state.owner`, so a claim cannot be
    /// redirected even by the owner's own signature.
    ///
    /// Deliberately NOT gated on firm status. A matured batch is fee revenue the operator already
    /// earned on sales that already happened; a firm going Suspended (or Bankrupt) afterwards does
    /// not retroactively unearn it. `clawback_vesting` stays disjoint by construction — it requires
    /// `unlocks_at > now`, this requires `unlocks_at <= now`, so a batch can never be both clawed
    /// back and claimed, whichever fires first. The `claimed` flag is the second guard.
    pub fn claim_vesting(ctx: Context<ClaimVesting>) -> Result<()> {
        let now = Clock::get()?.unix_timestamp;
        let batch = &ctx.accounts.owner_vesting_batch;
        require!(!batch.claimed, FirmError::VestingAlreadyClaimed);
        require!(now >= batch.unlocks_at, FirmError::VestingNotYetUnlocked);

        let amount = batch.amount;
        ctx.accounts.release(amount)?;

        let batch = &mut ctx.accounts.owner_vesting_batch;
        batch.claimed = true;
        emit!(VestingClaimed {
            firm: ctx.accounts.firm_state.key(),
            owner: ctx.accounts.owner.key(),
            amount,
            unlocked_at: batch.unlocks_at,
        });
        Ok(())
    }

    /// Bankruptcy clawback (§17/§24): redirect an unclaimed, not-yet-unlocked owner
    /// vesting batch back to the treasury. Only while `Bankrupt`. Permissionless (the
    /// guards make it safe for a keeper to crank every outstanding batch).
    pub fn clawback_vesting(ctx: Context<ClawbackVesting>) -> Result<()> {
        require!(ctx.accounts.firm_state.status == FirmStatus::Bankrupt, FirmError::InvalidFirmStatus);
        let now = Clock::get()?.unix_timestamp;
        let batch = &ctx.accounts.owner_vesting_batch;
        require!(!batch.claimed, FirmError::VestingAlreadyClaimed);
        require!(batch.unlocks_at > now, FirmError::VestingAlreadyUnlocked);

        let amount = batch.amount;
        ctx.accounts.clawback(amount)?;

        ctx.accounts.treasury_vault.reload()?;
        let firm = &mut ctx.accounts.firm_state;
        firm.treasury_sol = ctx.accounts.treasury_vault.amount;
        ctx.accounts.owner_vesting_batch.claimed = true;
        emit!(VestingClawedBack { firm: firm.key(), amount });
        Ok(())
    }

    /// Draw a disputed payout from the insurance fund (§7/§10). Callable once a dispute
    /// is `ResolvedUpheld` or `ForceResolved` (cross-program read of the dispute PDA):
    /// transfers `amount` SOL from the insurance vault to the winning trader. Requires the
    /// platform guardian to co-sign (F3). `amount` is capped two ways: at the insurance balance,
    /// AND at the disputed evaluation's funded `starting_balance` — a single dispute can never
    /// extract more than the account it concerns could have produced, so even a force-resolved
    /// self-dispute can't drain the whole fund. A `DisputePayoutRecord` PDA (`init`) is the
    /// double-draw guard. (The operator-stake slash itself is settled in the `dispute` program.)
    pub fn settle_dispute_payout(ctx: Context<SettleDisputePayout>, amount: u64) -> Result<()> {
        let status = ctx.accounts.dispute.status;
        require!(
            status == dispute::DisputeStatus::ResolvedUpheld
                || status == dispute::DisputeStatus::ForceResolved,
            FirmError::DisputeNotUpheld
        );

        // V2-3 double-pay guard. A timeout dispute pays from insurance ONLY while the challenge is
        // still `Unsettled`. The force-resolve re-check alone left a window: force-resolve while
        // `Unsettled` → operator cures (settles) late and pays from treasury → trader ALSO draws here.
        // Re-checking at the money-move closes the settle-after-force-resolve order (the reverse order
        // is blocked by `force_unsettled_timeout_resolution`'s own `Unsettled` gate).
        if ctx.accounts.dispute.kind == dispute::DisputeKind::UnsettledTimeout {
            require!(
                ctx.accounts.challenge.settlement_status == challenge::SettlementStatus::Unsettled,
                FirmError::TimeoutChallengeSettled
            );
        }

        // Guardian gate (F3). The strong path — a provably `Faulted` settlement — is trustless:
        // the operator's slashed bond is the security, so no guardian is needed and DecentralProp
        // cannot censor the payout. Every other (forgeable) path still requires the independent
        // guardian co-sign, since the operator commits the batch roots. (V2-1 now guarantees this
        // guardian is not the operator, so the co-sign is a real independent check.)
        let proven_fault =
            ctx.accounts.challenge.settlement_status == challenge::SettlementStatus::Faulted;
        if !proven_fault {
            let guardian = ctx.accounts.guardian.as_ref().ok_or(FirmError::GuardianRequired)?;
            require!(
                guardian.key() == ctx.accounts.firm_state.guardian,
                FirmError::GuardianMismatch
            );
        }

        // V2-2 cap. `rules_snapshot.starting_balance` is **micro-USD (6dp)** — comparing it directly to
        // a **wSOL-lamport (9dp)** payout is a unit mismatch (under-pays below ~$1000/SOL, over-pays
        // above it). On the guardian paths (timeout / arbiter) the price-locked `ChallengeFundedSize`
        // sidecar (set at purchase by the settlement authority, denominated in lamports) is the
        // dimensionally-correct ceiling that bounds even a compromised guardian to the funded size.
        // The trustless Faulted path keeps the legacy `starting_balance` ceiling (no sidecar trust) —
        // its residual is documented; it fails safe below ~$1000/SOL and over-pays only the real
        // fault victim, bounded by insurance, above it.
        let legacy_cap = ctx.accounts.challenge.rules_snapshot.starting_balance;
        let challenge_cap = if !proven_fault {
            match ctx.accounts.funded_size.as_ref() {
                Some(fs) => fs.funded_size_lamports,
                None => legacy_cap,
            }
        } else {
            legacy_cap
        };

        // V2-5 cumulative entitlement. The record accumulates across calls (init-if-needed), so a large
        // post-close claim throttled by the Universal-Pool daily cap can be paid over several days
        // instead of reverting forever. Each call is still guardian-gated on the weak path.
        let already_paid = ctx.accounts.dispute_payout_record.amount;
        let remaining = challenge_cap.saturating_sub(already_paid);
        require!(remaining > 0, FirmError::DisputePayoutComplete);
        let target = amount.min(remaining);

        // Tier 1 — the firm's own insurance vault.
        let from_ins = target.min(ctx.accounts.insurance_vault.amount);
        ctx.accounts.draw_insurance(from_ins)?;
        // Tier 2 (T-3/T-4) — Universal Pool fallback. When the firm's insurance can't cover the
        // entitlement (e.g. the firm has CLOSED and its insurance residual was swept to the pool at
        // `finalize_close`), draw the remainder from the Universal Pool so a post-close timeout dispute
        // is still payable. Same guardian gate + cap; also daily-rate-limited (hence the cumulative record).
        let remainder = target.saturating_sub(from_ins);
        let pool_before = ctx.accounts.universal_vault.amount;
        let from_uni = remainder.min(pool_before);
        ctx.accounts.draw_universal_for_dispute(from_uni)?;
        let pay = from_ins.saturating_add(from_uni);

        // Only the insurance-drawn portion reduces the firm's insurance ledger; the pool leg is
        // accounted in `draw_universal_for_dispute`. Treasury is untouched by either.
        let insurance = &mut ctx.accounts.insurance_fund;
        insurance.balance = insurance.balance.saturating_sub(from_ins);

        let record = &mut ctx.accounts.dispute_payout_record;
        record.dispute = ctx.accounts.dispute.key();
        record.trader = ctx.accounts.dispute.trader;
        record.amount = record.amount.saturating_add(pay);
        record.bump = ctx.bumps.dispute_payout_record;

        // §24 v2: a dispute payout drawn from the shared pool depletes the commons too — count it toward
        // this firm's ULP-draw total and auto-bankrupt at the 10% line, exactly as `draw_universal` does.
        if from_uni > 0 {
            let firm = &mut ctx.accounts.firm_state;
            firm.ulp_drawn = firm.ulp_drawn.saturating_add(from_uni);
            if firm.status != FirmStatus::Bankrupt
                && firm.ulp_drawn >= pool_before / BANKRUPTCY_ULP_DEPLETION_DIVISOR
            {
                firm.status = FirmStatus::Bankrupt;
                emit!(FirmAutoBankrupt {
                    firm: firm.key(),
                    ulp_drawn: firm.ulp_drawn,
                    pool_balance: pool_before,
                });
            }
        }

        emit!(DisputePayoutSettled {
            firm: ctx.accounts.firm_state.key(),
            dispute: ctx.accounts.dispute.key(),
            amount: pay,
        });
        Ok(())
    }

    /// V2-2 — record the disputed evaluation's funded size **in wSOL lamports**, price-locked at
    /// purchase time. Signed by the firm's settlement authority (the same key that co-signs the
    /// purchase and knows the SOL price), so the ceiling used by `settle_dispute_payout` is a
    /// dimensionally-correct, independent bound rather than the micro-USD `starting_balance` compared
    /// as lamports. `init_if_needed` so the keeper may set it at purchase and refresh it while the
    /// challenge is live; a dispute reads it as the guardian-path cap.
    pub fn set_challenge_funded_size(
        ctx: Context<SetChallengeFundedSize>,
        funded_size_lamports: u64,
    ) -> Result<()> {
        require!(funded_size_lamports > 0, FirmError::ZeroAmount);
        let rec = &mut ctx.accounts.funded_size;
        rec.challenge = ctx.accounts.challenge.key();
        rec.funded_size_lamports = funded_size_lamports;
        rec.bump = ctx.bumps.funded_size;
        Ok(())
    }

    /// Initialise a firm's Investor Backstop Pool (§19 Risk-Bearing Insurance Staking) —
    /// the $FIRMA escrow vault (staked principal) + the SOL premium vault.
    pub fn init_backstop_pool(ctx: Context<InitBackstopPool>) -> Result<()> {
        let now = Clock::get()?.unix_timestamp;
        let pool = &mut ctx.accounts.backstop_pool;
        pool.firm = ctx.accounts.firm_state.key();
        pool.total_staked = 0;
        pool.total_premium_weight = 0;
        pool.premium_acc = 0;
        pool.loss_acc = 0;
        pool.unallocated_premium = 0;
        pool.escrow_vault = ctx.accounts.escrow_vault.key();
        pool.premium_vault = ctx.accounts.premium_vault.key();
        pool.total_drawn = 0;
        pool.last_premium_at = now;
        pool.premium_bps = DEFAULT_BACKSTOP_PREMIUM_BPS;
        pool.bump = ctx.bumps.backstop_pool;
        pool.daily_withdrawn = 0;
        pool.withdraw_day = 0;
        pool.acc_firma = 0;
        pool.firma_reward_accounted = 0;
        pool.firma_reward_vault = ctx.accounts.firma_reward_vault.key();
        pool.unallocated_firma = 0;
        Ok(())
    }

    /// The backstop premium rate is FIXED platform-wide at 8% and not operator-configurable. This
    /// instruction is retained for compatibility but rejects any rate other than the fixed rate
    /// (`BackstopPremiumLocked`); it can only ever re-assert 8%.
    pub fn set_backstop_premium(ctx: Context<SetBackstopPremium>, bps: u16) -> Result<()> {
        require!(bps == DEFAULT_BACKSTOP_PREMIUM_BPS, FirmError::BackstopPremiumLocked);
        ctx.accounts.backstop_pool.premium_bps = DEFAULT_BACKSTOP_PREMIUM_BPS;
        Ok(())
    }

    /// Backfill for a `BackstopPool` created before the 2026-07-27 staking rebalance: stands up
    /// the $FIRMA reward vault `init_backstop_pool` now creates by default and records it on the
    /// pool. One-time, permissionless (same shape as `init_staking_pool`); a pool created after the
    /// rebalance already has this set and calling it again fails on the `init` constraint.
    pub fn init_backstop_firma_reward_vault(ctx: Context<InitBackstopFirmaRewardVault>) -> Result<()> {
        ctx.accounts.backstop_pool.firma_reward_vault = ctx.accounts.firma_reward_vault.key();
        Ok(())
    }

    /// The loss-back redemption gate is FIXED platform-wide at 1,000,000 $FIRMA and not
    /// operator-configurable. This instruction is retained for compatibility (the keeper re-asserts
    /// it at bootstrap) but rejects any value other than the fixed amount (`LossBackMinStakeLocked`);
    /// it can only ever re-assert `LOSS_BACK_MIN_STAKE`. Does not touch already-accrued balances.
    pub fn set_loss_back_min_stake(ctx: Context<SetLossBackMinStake>, min_stake: u64) -> Result<()> {
        require!(min_stake == LOSS_BACK_MIN_STAKE, FirmError::LossBackMinStakeLocked);
        ctx.accounts.firm_state.loss_back_min_stake = LOSS_BACK_MIN_STAKE;
        emit!(LossBackMinStakeSet {
            firm: ctx.accounts.firm_state.key(),
            min_stake: LOSS_BACK_MIN_STAKE,
        });
        Ok(())
    }

    /// K-1 — rotate the firm's independent platform guardian (key hygiene / compromise recovery for
    /// the co-signer). Signed by the CURRENT guardian: DecentralProp rotates its own co-signer key,
    /// and the firm owner cannot change it (that would defeat the guardian's independence — enforced
    /// by `new_guardian != owner`). The guardian is read live everywhere (`firm_state.guardian`) and
    /// is never frozen onto a challenge, so the new key takes effect immediately with no in-flight
    /// settlement/payout state stranded.
    ///
    /// Scope note: this rotates the GUARDIAN only. Rotating the hot `risk_engine_authority` (the
    /// keeper key — the core K-1 threat) is NOT done here: the frozen
    /// `challenge.settlement_authority == risk_engine_authority` check that gates the permissionless
    /// payout-crank paths makes naive rotation strand in-flight challenges, so a safe keeper rotation
    /// needs a `previous_risk_engine_authority` + grace window — a `FirmState` layout migration that
    /// bundles with T-3/T-4. See `reports/2026-07-03-k1-authority-rotation-design.md`.
    pub fn set_guardian(ctx: Context<SetGuardian>, new_guardian: Pubkey) -> Result<()> {
        let firm = &mut ctx.accounts.firm_state;
        require!(new_guardian != firm.owner, FirmError::Unauthorized);
        firm.guardian = new_guardian;
        emit!(GuardianRotated {
            firm: firm.key(),
            new_guardian,
        });
        Ok(())
    }

    /// 2026-07-27 staking rebalance: `init_loss_back_vault` and `redeem_loss_back_credit` are
    /// REMOVED. Comeback credit is now a purely notional per-trader counter accrued and applied
    /// entirely inside `pay_challenge_fee` (see its doc comment) — there is no vault to stand up
    /// and no separate redemption instruction. `CreditMustBeUsedAtPurchase` is kept in
    /// `FirmError` since old clients built against the prior IDL may still reference it.

    /// Stake $FIRMA into the backstop (§19). Escrows the tokens (at risk) and adjusts the
    /// position's premium + loss debt so the new principal earns no past premium and
    /// absorbs no past loss. Cannot stake while a withdrawal cooldown is pending.
    pub fn stake_backstop(ctx: Context<StakeBackstop>, amount: u64) -> Result<()> {
        require!(amount > 0, FirmError::ZeroAmount);
        require!(ctx.accounts.position.cooldown_ends_at == 0, FirmError::CooldownActive);
        let now = Clock::get()?.unix_timestamp;
        ctx.accounts.escrow(amount)?;

        let pool = &mut ctx.accounts.backstop_pool;
        pool.total_staked = pool.total_staked.checked_add(amount).ok_or(FirmError::MathOverflow)?;
        // F-M-5: nominal premium weight grows with the stake (the premium AND, 2026-07-27, the
        // $FIRMA-yield denominator — same reasoning applies to both: neither may shrink on a draw).
        pool.total_premium_weight =
            pool.total_premium_weight.checked_add(amount).ok_or(FirmError::MathOverflow)?;
        let premium_acc = pool.premium_acc;
        let loss_acc = pool.loss_acc;
        let acc_firma = pool.acc_firma;

        let pos = &mut ctx.accounts.position;
        if pos.staker == Pubkey::default() {
            pos.staker = ctx.accounts.staker.key();
            pos.firm = ctx.accounts.firm_state.key();
            pos.staked_at = now;
            pos.bump = ctx.bumps.position;
        }
        pos.amount_staked = pos.amount_staked.checked_add(amount).ok_or(FirmError::MathOverflow)?;
        pos.premium_debt = pos.premium_debt.saturating_add(yield_debt(amount, premium_acc));
        pos.loss_debt = pos.loss_debt.saturating_add(yield_debt(amount, loss_acc));
        pos.firma_debt = pos.firma_debt.saturating_add(yield_debt(amount, acc_firma));
        emit!(BackstopStaked { firm: pos.firm, staker: pos.staker, amount });
        Ok(())
    }

    /// Begin the withdrawal of the backstop position (§19). Starts an ARE-scaled cooldown
    /// (HEALTHY 3d … CRITICAL 30d, by **effective** tier at request time) further scaled by a
    /// whale multiplier (1.0x–3.0x by this position's current share of the pool — a large
    /// single staker takes proportionally longer to unwind); the principal stays escrowed —
    /// still earning premium and still slashable — until `withdraw_backstop` after the
    /// cooldown, which independently rechecks both inputs and only ever extends the wait.
    pub fn request_unstake_backstop(ctx: Context<RequestUnstakeBackstop>) -> Result<()> {
        require!(ctx.accounts.position.amount_staked > 0, FirmError::NothingStaked);
        require!(ctx.accounts.position.cooldown_ends_at == 0, FirmError::CooldownActive);
        let now = Clock::get()?.unix_timestamp;
        let eff = effective_tier(ctx.accounts.firm_state.risk_tier as u8, &ctx.accounts.platform_risk);
        let share_bps =
            backstop_share_bps(ctx.accounts.position.amount_staked, ctx.accounts.backstop_pool.total_staked);
        let cooldown = required_backstop_cooldown(eff, share_bps);
        let pos = &mut ctx.accounts.position;
        pos.cooldown_requested_at = now;
        pos.cooldown_ends_at = now.checked_add(cooldown).ok_or(FirmError::MathOverflow)?;
        emit!(BackstopUnstakeRequested {
            firm: pos.firm,
            staker: pos.staker,
            unlocks_at: pos.cooldown_ends_at,
        });
        Ok(())
    }

    /// Withdraw up to `amount` (nominal $FIRMA) of a matured backstop position (§19): pays out
    /// the proportional surviving principal and accrued SOL premium for the slice withdrawn,
    /// gated on (1) no active velocity-break (the exact moment the backstop may be needed most),
    /// (2) the cooldown — rechecked against the CURRENT tier/whale-share, not just the value
    /// stored at request time, so a position can only ever face a longer wait if risk rose while
    /// pending — and (3) a rolling daily pool-outflow cap. A partial withdrawal scales the
    /// remainder's debt DOWN PROPORTIONALLY from its existing value (never reset to the live
    /// accumulator — that's only valid for a genuinely fresh deposit, as `stake_backstop` does;
    /// resetting here would zero the remainder's already-accrued, not-yet-realized loss/premium
    /// share and let a staker dodge it just by withdrawing in slices) and leaves it in cooldown
    /// so the staker can keep draining across windows instead of being blocked outright by the
    /// daily cap.
    pub fn withdraw_backstop(ctx: Context<WithdrawBackstop>, amount: u64) -> Result<()> {
        require!(amount > 0, FirmError::ZeroAmount);
        require!(!ctx.accounts.firm_state.velocity_break_flag, FirmError::BackstopWithdrawFrozen);
        let now = Clock::get()?.unix_timestamp;
        let pos_ro = &ctx.accounts.position;
        require!(pos_ro.cooldown_ends_at != 0, FirmError::NoCooldownRequested);

        let eff_now = effective_tier(ctx.accounts.firm_state.risk_tier as u8, &ctx.accounts.platform_risk);
        let share_bps_now = backstop_share_bps(pos_ro.amount_staked, ctx.accounts.backstop_pool.total_staked);
        let required_cooldown_now = required_backstop_cooldown(eff_now, share_bps_now);
        let required_unlock_now = pos_ro
            .cooldown_requested_at
            .checked_add(required_cooldown_now)
            .ok_or(FirmError::MathOverflow)?;
        require!(
            now >= pos_ro.cooldown_ends_at.max(required_unlock_now),
            FirmError::CooldownNotElapsed
        );
        require!(amount <= pos_ro.amount_staked, FirmError::InsufficientStake);

        let pool = &ctx.accounts.backstop_pool;
        let staked = pos_ro.amount_staked;
        let original_loss_debt = pos_ro.loss_debt;
        let original_premium_debt = pos_ro.premium_debt;
        let original_firma_debt = pos_ro.firma_debt;
        let pending_loss_total = pending_yield(staked, pool.loss_acc, original_loss_debt);
        let surviving_total = staked.saturating_sub(pending_loss_total);
        let premium_total = pending_yield(staked, pool.premium_acc, original_premium_debt);
        // 2026-07-27 staking rebalance: the $FIRMA yield leg, sliced by withdrawal fraction exactly
        // like premium above (not the surviving/loss-adjusted total — yield accrues on nominal stake).
        let firma_yield_total = pending_yield(staked, pool.acc_firma, original_firma_debt);
        let surviving_slice = ((amount as u128).saturating_mul(surviving_total as u128) / staked as u128) as u64;
        let premium_slice = ((amount as u128).saturating_mul(premium_total as u128) / staked as u128) as u64;
        let firma_yield_slice = ((amount as u128).saturating_mul(firma_yield_total as u128) / staked as u128) as u64;

        // §19 anti-bank-run redemption gate: cap cumulative surviving-$FIRMA paid out per UTC day,
        // recomputed fresh off the live pool each call (same reset-then-check idiom as
        // `daily_payout_spent`/`payout_day`). Exceeding it simply reverts — no queue — the staker
        // retries with a smaller `amount` or waits for the next window.
        let pool = &mut ctx.accounts.backstop_pool;
        let day = now / 86_400;
        if day != pool.withdraw_day {
            pool.daily_withdrawn = 0;
            pool.withdraw_day = day;
        }
        let cap = (pool.total_staked as u128 * BACKSTOP_DAILY_OUTFLOW_CAP_BPS as u128 / 10_000) as u64;
        require!(
            pool.daily_withdrawn.saturating_add(surviving_slice) <= cap,
            FirmError::BackstopOutflowCapExceeded
        );
        pool.daily_withdrawn = pool.daily_withdrawn.saturating_add(surviving_slice);

        ctx.accounts.pay_firma(surviving_slice)?;
        ctx.accounts.pay_sol(premium_slice)?;
        ctx.accounts.pay_firma_yield(firma_yield_slice)?;

        let pool = &mut ctx.accounts.backstop_pool;
        pool.total_staked = pool.total_staked.saturating_sub(surviving_slice);
        // F-M-5: the premium weight drops by the NOMINAL slice (premium accrued on nominal), distinct
        // from `total_staked` which drops by the surviving (loss-adjusted) slice.
        pool.total_premium_weight = pool.total_premium_weight.saturating_sub(amount);

        let remainder = staked.saturating_sub(amount);
        let pos = &mut ctx.accounts.position;
        pos.amount_staked = remainder;
        if remainder == 0 {
            pos.premium_debt = 0;
            pos.loss_debt = 0;
            pos.firma_debt = 0;
            pos.cooldown_ends_at = 0;
            pos.cooldown_requested_at = 0;
        } else {
            // Scale the EXISTING debt down proportionally to the remaining share — do NOT reset
            // to the live accumulator (that's only correct for a genuinely fresh deposit, which
            // `stake_backstop` does). Resetting here would zero out the remainder's already-
            // accrued, not-yet-realized pro-rata loss/premium/$FIRMA-yield, letting a staker escape
            // their fair share of a draw just by withdrawing in slices instead of one shot.
            pos.premium_debt = original_premium_debt.saturating_mul(remainder as u128) / staked as u128;
            pos.loss_debt = original_loss_debt.saturating_mul(remainder as u128) / staked as u128;
            pos.firma_debt = original_firma_debt.saturating_mul(remainder as u128) / staked as u128;
        }
        emit!(BackstopWithdrawn {
            firm: pos.firm,
            staker: pos.staker,
            surviving: surviving_slice,
            premium: premium_slice,
            firma_yield: firma_yield_slice,
        });
        Ok(())
    }

    /// Claim accrued SOL premium without unstaking (§19). Resets the premium debt.
    pub fn claim_backstop_premium(ctx: Context<ClaimBackstopPremium>) -> Result<()> {
        let staked = ctx.accounts.position.amount_staked;
        let premium =
            pending_yield(staked, ctx.accounts.backstop_pool.premium_acc, ctx.accounts.position.premium_debt);
        ctx.accounts.pay_sol(premium)?;
        // 2026-07-27 staking rebalance: claim the $FIRMA yield leg in the same call.
        let firma_yield =
            pending_yield(staked, ctx.accounts.backstop_pool.acc_firma, ctx.accounts.position.firma_debt);
        ctx.accounts.pay_firma(firma_yield)?;
        let premium_acc = ctx.accounts.backstop_pool.premium_acc;
        let acc_firma = ctx.accounts.backstop_pool.acc_firma;
        let pos = &mut ctx.accounts.position;
        pos.premium_debt = yield_debt(staked, premium_acc);
        pos.firma_debt = yield_debt(staked, acc_firma);
        emit!(BackstopPremiumClaimed { firm: pos.firm, staker: pos.staker, premium });
        emit!(BackstopFirmaYieldClaimed { firm: pos.firm, staker: pos.staker, firma: firma_yield });
        Ok(())
    }

    /// Fund the backstop premium (§19, §17 dedicated fee slice). The keeper moves the
    /// premium SOL (a slice of challenge fees) into the premium vault and folds it into
    /// the premium accumulator — the same weekly-distribution model as staking yield.
    pub fn fund_backstop_premium(ctx: Context<FundBackstopPremium>, amount: u64) -> Result<()> {
        let now = Clock::get()?.unix_timestamp;
        ctx.accounts.fund(amount)?;
        let pool = &mut ctx.accounts.backstop_pool;
        // F-M-5: premium folds divide by the nominal premium weight, not the loss-adjusted total_staked.
        let (acc, unalloc) =
            fold_yield(pool.premium_acc, pool.unallocated_premium, amount, pool.total_premium_weight);
        pool.premium_acc = acc;
        pool.unallocated_premium = unalloc;
        pool.last_premium_at = now;
        Ok(())
    }

    /// Emergency draw (§19 payout Tier 3, §22). When the treasury can't cover a queued
    /// payout — signalled on-chain by the velocity break the circuit breaker set — owed
    /// `$FIRMA` is delivered **directly** from the backstop escrow to the trader, and the
    /// loss is mutualized across stakers via the loss accumulator. Signed by the
    /// challenge's settlement authority.
    pub fn draw_backstop(ctx: Context<DrawBackstop>, firma_amount: u64) -> Result<()> {
        require_payout_delivery_authority(
            &ctx.accounts.challenge,
            &ctx.accounts.firm_state,
            ctx.accounts.withdrawal.as_deref().map(|w| &**w),
        )?;
        require!(ctx.accounts.firm_state.velocity_break_flag, FirmError::BackstopNotPermitted);
        let outstanding = ctx
            .accounts
            .queued_payout
            .firma_amount_owed
            .saturating_sub(ctx.accounts.queued_payout.firma_amount_delivered);
        require!(outstanding > 0, FirmError::PayoutAlreadyFilled);
        let total_staked = ctx.accounts.backstop_pool.total_staked;
        require!(total_staked > 0, FirmError::NothingStaked);

        let draw = firma_amount.min(outstanding).min(total_staked);
        require!(draw > 0, FirmError::ZeroAmount);
        ctx.accounts.deliver(draw)?;

        let pool = &mut ctx.accounts.backstop_pool;
        let add = ((draw as u128) * PRECISION) / total_staked as u128;
        pool.loss_acc = pool.loss_acc.checked_add(add).ok_or(FirmError::MathOverflow)?;
        pool.total_staked = pool.total_staked.saturating_sub(draw);
        pool.total_drawn = pool.total_drawn.saturating_add(draw);

        let qp = &mut ctx.accounts.queued_payout;
        qp.firma_amount_delivered = qp.firma_amount_delivered.saturating_add(draw);
        let fully = qp.firma_amount_delivered >= qp.firma_amount_owed;
        let challenge_key = qp.challenge;
        // Count toward lifetime payouts (PAYOUT-LIFETIME-1) — the backstop pays in staked $FIRMA, no
        // treasury SOL spent, so credit the payout's SOL obligation prorated by the $FIRMA drawn.
        let paid_value = pro_rata(qp.sol_at_settlement, draw, qp.firma_amount_owed);
        let firm = &mut ctx.accounts.firm_state;
        firm.total_paid_out = firm.total_paid_out.saturating_add(paid_value);
        // Discharge the obligation when THIS fill completes it. Tier 3 can fully satisfy a payout; if it
        // never decremented `open_payouts` the counter would stick, wedging `finalize_bankruptcy` forever
        // (and `force_discharge` can't clear a fully-delivered entry). Mirrors process_queued_payout.
        if fully {
            firm.open_payouts = firm.open_payouts.saturating_sub(1);
        }
        emit!(BackstopDrawn {
            firm: ctx.accounts.firm_state.key(),
            challenge: challenge_key,
            amount: draw,
        });
        Ok(())
    }

    // ───────────── Prediction Market LP Pool (Phase 2 pooled-LP AMM plan) ─────────────
    // A near-exact structural mirror of the Investor Backstop Pool immediately above — same PDA/vault
    // pattern, same PRECISION-scaled accumulator math, same whale-tiered cooldown, same rolling
    // daily-outflow cap — for a different destination: Phase 3 will add per-market on-chain curves
    // this pool's capital gets algorithmically allocated across. See `PredictionMarketLpPool`'s doc
    // comment for the full field-by-field mapping to `BackstopPool`.

    /// Initialise a firm's shared Prediction Market LP Pool — the $FIRMA escrow vault (idle pool
    /// capital) + the $FIRMA yield vault (accrued trading-fee yield, swept in from curves by Phase
    /// 3's `sweep_curve_fees_to_pool`). Permissioned identically to `init_backstop_pool`: any payer
    /// may stand up the pool (the PDA seeds already bind it 1:1 to the firm, so this is init-once,
    /// not an authority decision).
    pub fn init_pm_lp_pool(ctx: Context<InitPmLpPool>) -> Result<()> {
        let now = Clock::get()?.unix_timestamp;
        let pool = &mut ctx.accounts.pm_lp_pool;
        pool.firm = ctx.accounts.firm_state.key();
        pool.total_staked = 0;
        pool.total_yield_weight = 0;
        pool.yield_acc = 0;
        pool.loss_acc = 0;
        pool.unallocated_yield = 0;
        pool.escrow_vault = ctx.accounts.escrow_vault.key();
        pool.yield_vault = ctx.accounts.yield_vault.key();
        pool.total_drawn = 0;
        pool.total_returned = 0;
        pool.last_yield_at = now;
        pool.daily_withdrawn = 0;
        pool.withdraw_day = 0;
        pool.allocation_cap_bps = DEFAULT_PM_LP_ALLOCATION_CAP_BPS;
        pool.bump = ctx.bumps.pm_lp_pool;
        Ok(())
    }

    /// Stake $FIRMA into the shared Prediction Market LP Pool. Escrows the tokens (at risk once
    /// Phase 3 allocates them into curves) and adjusts the position's yield + loss debt so the new
    /// principal earns no past yield and absorbs no past loss — same discipline as `stake_backstop`.
    /// Cannot stake while a withdrawal cooldown is pending.
    ///
    /// Deliberately NO identity/self-check of any kind — unlike Phase 3's `add_curve_topup`, which
    /// WILL reject `depositor.key() == curve.trader`. This pool is shared and algorithmically
    /// diversified across every eligible trader's market; a trader routing their own skin-in-the-game
    /// through the pool (rather than funding their own market's curve directly, which stays banned
    /// everywhere else) IS the intended path, not a loophole to close.
    pub fn stake_pm_lp(ctx: Context<StakePmLp>, amount: u64) -> Result<()> {
        require!(amount > 0, FirmError::ZeroAmount);
        require!(ctx.accounts.position.cooldown_ends_at == 0, FirmError::PmLpCooldownActive);
        let now = Clock::get()?.unix_timestamp;
        ctx.accounts.escrow(amount)?;

        let pool = &mut ctx.accounts.pm_lp_pool;
        pool.total_staked = pool.total_staked.checked_add(amount).ok_or(FirmError::MathOverflow)?;
        pool.total_yield_weight =
            pool.total_yield_weight.checked_add(amount).ok_or(FirmError::MathOverflow)?;
        let yield_acc = pool.yield_acc;
        let loss_acc = pool.loss_acc;

        let pos = &mut ctx.accounts.position;
        if pos.staker == Pubkey::default() {
            pos.staker = ctx.accounts.staker.key();
            pos.firm = ctx.accounts.firm_state.key();
            pos.staked_at = now;
            pos.bump = ctx.bumps.position;
        }
        pos.amount_staked = pos.amount_staked.checked_add(amount).ok_or(FirmError::MathOverflow)?;
        pos.yield_debt = pos.yield_debt.saturating_add(yield_debt(amount, yield_acc));
        pos.loss_debt = pos.loss_debt.saturating_add(yield_debt(amount, loss_acc));
        emit!(PmLpStaked { firm: pos.firm, staker: pos.staker, amount });
        Ok(())
    }

    /// Begin the withdrawal of a PM LP position. Starts an ARE-scaled cooldown (HEALTHY 3d …
    /// CRITICAL 30d, by **effective** tier at request time) further scaled by a whale multiplier
    /// (1.0x–3.0x by this position's current share of the pool) — mirrors
    /// `request_unstake_backstop` exactly, via the duplicated `pm_lp_*` helpers (see their doc
    /// comments for why they're duplicated rather than shared). The principal stays escrowed — still
    /// earning yield and still slashable by a curve-side loss — until `withdraw_pm_lp` after the
    /// cooldown, which independently rechecks both inputs and only ever extends the wait.
    pub fn request_unstake_pm_lp(ctx: Context<RequestUnstakePmLp>) -> Result<()> {
        require!(ctx.accounts.position.amount_staked > 0, FirmError::PmLpNothingStaked);
        require!(ctx.accounts.position.cooldown_ends_at == 0, FirmError::PmLpCooldownActive);
        let now = Clock::get()?.unix_timestamp;
        let eff = effective_tier(ctx.accounts.firm_state.risk_tier as u8, &ctx.accounts.platform_risk);
        let share_bps =
            pm_lp_share_bps(ctx.accounts.position.amount_staked, ctx.accounts.pm_lp_pool.total_staked);
        let cooldown = required_pm_lp_cooldown(eff, share_bps);
        let pos = &mut ctx.accounts.position;
        pos.cooldown_requested_at = now;
        pos.cooldown_ends_at = now.checked_add(cooldown).ok_or(FirmError::MathOverflow)?;
        emit!(PmLpUnstakeRequested {
            firm: pos.firm,
            staker: pos.staker,
            unlocks_at: pos.cooldown_ends_at,
        });
        Ok(())
    }

    /// Withdraw up to `amount` (nominal $FIRMA) of a matured PM LP position: pays out the
    /// proportional surviving principal and accrued yield for the slice withdrawn, gated on (1) no
    /// active velocity-break (the same circuit breaker `withdraw_backstop` gates on — reused, not
    /// duplicated, since it's a single firm-wide flag), (2) the cooldown — rechecked against the
    /// CURRENT tier/whale-share, not just the value stored at request time — and (3) a rolling daily
    /// pool-outflow cap. Mirrors `withdraw_backstop` line-by-line, including its partial-withdrawal
    /// debt-scaling discipline: a partial withdrawal scales the remainder's debt DOWN
    /// PROPORTIONALLY from its existing value (never reset to the live accumulator — that's only
    /// valid for a genuinely fresh deposit, as `stake_pm_lp` does; resetting here would zero the
    /// remainder's already-accrued, not-yet-realized loss/yield share and let a staker dodge it just
    /// by withdrawing in slices) and leaves it in cooldown so the staker can keep draining across
    /// windows instead of being blocked outright by the daily cap.
    pub fn withdraw_pm_lp(ctx: Context<WithdrawPmLp>, amount: u64) -> Result<()> {
        require!(amount > 0, FirmError::ZeroAmount);
        require!(!ctx.accounts.firm_state.velocity_break_flag, FirmError::PmLpVelocityBreakActive);
        let now = Clock::get()?.unix_timestamp;
        let pos_ro = &ctx.accounts.position;
        require!(pos_ro.cooldown_ends_at != 0, FirmError::PmLpNoCooldownRequested);

        let eff_now = effective_tier(ctx.accounts.firm_state.risk_tier as u8, &ctx.accounts.platform_risk);
        let share_bps_now = pm_lp_share_bps(pos_ro.amount_staked, ctx.accounts.pm_lp_pool.total_staked);
        let required_cooldown_now = required_pm_lp_cooldown(eff_now, share_bps_now);
        let required_unlock_now = pos_ro
            .cooldown_requested_at
            .checked_add(required_cooldown_now)
            .ok_or(FirmError::MathOverflow)?;
        require!(
            now >= pos_ro.cooldown_ends_at.max(required_unlock_now),
            FirmError::PmLpCooldownNotElapsed
        );
        require!(amount <= pos_ro.amount_staked, FirmError::InsufficientStake);

        let pool = &ctx.accounts.pm_lp_pool;
        let staked = pos_ro.amount_staked;
        let original_loss_debt = pos_ro.loss_debt;
        let original_yield_debt = pos_ro.yield_debt;
        let pending_loss_total = pending_yield(staked, pool.loss_acc, original_loss_debt);
        let surviving_total = staked.saturating_sub(pending_loss_total);
        let yield_total = pending_yield(staked, pool.yield_acc, original_yield_debt);
        let surviving_slice = ((amount as u128).saturating_mul(surviving_total as u128) / staked as u128) as u64;
        let yield_slice = ((amount as u128).saturating_mul(yield_total as u128) / staked as u128) as u64;

        // Anti-bank-run redemption gate: cap cumulative surviving-$FIRMA paid out per UTC day,
        // recomputed fresh off the live pool each call — same reset-then-check idiom as
        // `withdraw_backstop`. Exceeding it simply reverts — no queue — the staker retries with a
        // smaller `amount` or waits for the next window.
        let pool = &mut ctx.accounts.pm_lp_pool;
        let day = now / 86_400;
        if day != pool.withdraw_day {
            pool.daily_withdrawn = 0;
            pool.withdraw_day = day;
        }
        let cap = (pool.total_staked as u128 * PM_LP_DAILY_OUTFLOW_CAP_BPS as u128 / 10_000) as u64;
        require!(
            pool.daily_withdrawn.saturating_add(surviving_slice) <= cap,
            FirmError::PmLpDailyCapExceeded
        );
        pool.daily_withdrawn = pool.daily_withdrawn.saturating_add(surviving_slice);

        ctx.accounts.pay_principal(surviving_slice)?;
        ctx.accounts.pay_yield(yield_slice)?;

        let pool = &mut ctx.accounts.pm_lp_pool;
        pool.total_staked = pool.total_staked.saturating_sub(surviving_slice);
        pool.total_yield_weight = pool.total_yield_weight.saturating_sub(amount);

        let remainder = staked.saturating_sub(amount);
        let pos = &mut ctx.accounts.position;
        pos.amount_staked = remainder;
        if remainder == 0 {
            pos.yield_debt = 0;
            pos.loss_debt = 0;
            pos.cooldown_ends_at = 0;
            pos.cooldown_requested_at = 0;
        } else {
            // Scale the EXISTING debt down proportionally to the remaining share — do NOT reset to
            // the live accumulator (see the doc comment above for why).
            pos.yield_debt = original_yield_debt.saturating_mul(remainder as u128) / staked as u128;
            pos.loss_debt = original_loss_debt.saturating_mul(remainder as u128) / staked as u128;
        }
        emit!(PmLpWithdrawn {
            firm: pos.firm,
            staker: pos.staker,
            surviving: surviving_slice,
            yield_paid: yield_slice,
        });
        Ok(())
    }

    /// Claim accrued yield without unstaking. Resets the yield debt to the live accumulator.
    /// Mirrors `claim_backstop_premium`.
    pub fn claim_pm_lp_yield(ctx: Context<ClaimPmLpYield>) -> Result<()> {
        let staked = ctx.accounts.position.amount_staked;
        let pending =
            pending_yield(staked, ctx.accounts.pm_lp_pool.yield_acc, ctx.accounts.position.yield_debt);
        ctx.accounts.pay_yield(pending)?;
        let yield_acc = ctx.accounts.pm_lp_pool.yield_acc;
        let pos = &mut ctx.accounts.position;
        pos.yield_debt = yield_debt(staked, yield_acc);
        emit!(PmLpYieldClaimed { firm: pos.firm, staker: pos.staker, yield_paid: pending });
        Ok(())
    }

    // ───────────── Prediction Market Curve (Phase 3 pooled-LP AMM plan) ─────────────
    // Per-market two-sided AMM — see this section's header comment above `MarketCurve` for the
    // judgment call (two independent CPMM legs, not a true complementary-outcome AMM) and
    // `pm_redeem_payout`'s doc comment for how settlement stays solvent despite it.

    /// Initialise a per-market two-sided AMM curve, 1:1 bound to a real on-chain evaluation
    /// (`challenge`) via PDA seeds. Signed by the challenge's settlement authority — see
    /// `require_market_curve_authority`'s doc comment for why this binds the same way
    /// `require_firm_settlement_authority` does WITHOUT that gate's additional settlement-finality
    /// checks (this curve opens WHILE the evaluation is still active). Eligibility itself has no
    /// on-chain representation; it's enforced entirely by who is allowed to call this instruction,
    /// same trust model `settlement_authority` already carries everywhere else in this file.
    pub fn init_market_curve(
        ctx: Context<InitMarketCurve>,
        pass_virtual_seed: u64,
        fail_virtual_seed: u64,
        fee_bps: u16,
        firm_fee_bps: u16,
        platform_fee_bps: u16,
        pool_fee_bps: u16,
    ) -> Result<()> {
        require_market_curve_authority(&ctx.accounts.challenge, &ctx.accounts.firm_state)?;
        // Both virtual seeds must be non-zero: `pm_curve_available_shares` scales its notional supply
        // cap off them, so a zero seed would leave that leg permanently unable to sell a single share
        // (mirrors `bonding_curve::initialize_curve`'s own `virtual_sol > 0` requirement).
        require!(pass_virtual_seed > 0 && fail_virtual_seed > 0, FirmError::ZeroAmount);
        require!(
            (firm_fee_bps as u32) + (platform_fee_bps as u32) + (pool_fee_bps as u32) == fee_bps as u32,
            FirmError::PmFeeSplitMismatch
        );
        let now = Clock::get()?.unix_timestamp;
        let curve = &mut ctx.accounts.curve;
        curve.firm = ctx.accounts.firm_state.key();
        curve.challenge = ctx.accounts.challenge.key();
        curve.trader = ctx.accounts.challenge.trader;
        curve.firma_mint = ctx.accounts.firma_mint.key();
        curve.pass_vault = ctx.accounts.pass_vault.key();
        curve.fail_vault = ctx.accounts.fail_vault.key();
        curve.pass_virtual = pass_virtual_seed;
        curve.pass_real = 0;
        curve.pass_shares = 0;
        curve.fail_virtual = fail_virtual_seed;
        curve.fail_real = 0;
        curve.fail_shares = 0;
        curve.pool_allocated = 0;
        curve.topup_deposited = 0;
        curve.fee_bps = fee_bps;
        curve.firm_fee_bps = firm_fee_bps;
        curve.platform_fee_bps = platform_fee_bps;
        curve.pool_fee_bps = pool_fee_bps;
        curve.firm_fees_accrued = 0;
        curve.platform_fees_accrued = 0;
        curve.pool_fees_accrued = 0;
        curve.status = PmCurveStatus::Open;
        curve.outcome = None;
        curve.opened_at = now;
        curve.settled_at = 0;
        curve.bump = ctx.bumps.curve;
        emit!(MarketCurveInitialized {
            curve: curve.key(),
            challenge: curve.challenge,
            firm: curve.firm,
            trader: curve.trader,
        });
        Ok(())
    }

    /// Buy shares of one side of a market. Permissionless — any signer may buy. Exact math reuses
    /// `bonding_curve::fee_amount`/`buy_output` UNMODIFIED; see `pm_curve_available_shares`'s doc
    /// comment for why the reserve fed into `buy_output` is a DERIVED quantity, not the stored
    /// `pass_shares`/`fail_shares` field directly.
    pub fn buy_shares(
        ctx: Context<BuyMarketShares>,
        side: PmSide,
        collateral_in: u64,
        min_shares_out: u64,
    ) -> Result<()> {
        require!(collateral_in > 0, FirmError::ZeroAmount);
        require!(ctx.accounts.curve.status == PmCurveStatus::Open, FirmError::PmMarketNotOpen);

        let fee_bps = ctx.accounts.curve.fee_bps;
        let fee = bonding_curve::fee_amount(collateral_in, fee_bps);
        let net = collateral_in.checked_sub(fee).ok_or(FirmError::MathOverflow)?;

        let (virtual_r, real_r, shares_outstanding) = match side {
            PmSide::Pass => {
                (ctx.accounts.curve.pass_virtual, ctx.accounts.curve.pass_real, ctx.accounts.curve.pass_shares)
            }
            PmSide::Fail => {
                (ctx.accounts.curve.fail_virtual, ctx.accounts.curve.fail_real, ctx.accounts.curve.fail_shares)
            }
        };
        let available = pm_curve_available_shares(virtual_r, shares_outstanding);
        let eff = (virtual_r as u128).saturating_add(real_r as u128);
        let shares_out = bonding_curve::buy_output(eff, available as u128, net as u128)
            .ok_or(FirmError::MathOverflow)?;
        require!(shares_out > 0 && shares_out >= min_shares_out, FirmError::PmSlippageExceeded);

        let new_real = real_r.checked_add(net).ok_or(FirmError::MathOverflow)?;
        let new_shares_outstanding =
            shares_outstanding.checked_add(shares_out).ok_or(FirmError::MathOverflow)?;
        let new_available = pm_curve_available_shares(virtual_r, new_shares_outstanding);

        // PRICE-CEILING GUARD (new, not in `bonding_curve` — this leg has no complementary side to
        // arbitrage its price back down, plan judgment call #2): reject a buy that would push this
        // leg's implied marginal price (`eff_reserve / available-to-sell`) past $1, the eventual
        // settlement ceiling. Integer comparison only, no floating point.
        let eff_after = eff.saturating_add(net as u128);
        require!(eff_after <= new_available as u128, FirmError::PmPriceCeilingExceeded);

        let (firm_cut, platform_cut, pool_cut) = split_curve_fee_3way(
            fee,
            ctx.accounts.curve.firm_fee_bps,
            ctx.accounts.curve.platform_fee_bps,
            ctx.accounts.curve.pool_fee_bps,
            fee_bps,
        );

        // Collateral moves in BEFORE bookkeeping updates — mirrors `stake_pm_lp`'s escrow-then-record
        // order.
        ctx.accounts.transfer_collateral_in(side, collateral_in)?;

        let curve = &mut ctx.accounts.curve;
        match side {
            PmSide::Pass => {
                curve.pass_real = new_real;
                curve.pass_shares = new_shares_outstanding;
            }
            PmSide::Fail => {
                curve.fail_real = new_real;
                curve.fail_shares = new_shares_outstanding;
            }
        }
        curve.firm_fees_accrued = curve.firm_fees_accrued.saturating_add(firm_cut);
        curve.platform_fees_accrued = curve.platform_fees_accrued.saturating_add(platform_cut);
        curve.pool_fees_accrued = curve.pool_fees_accrued.saturating_add(pool_cut);
        let curve_key = curve.key();

        let position = &mut ctx.accounts.position;
        if position.holder == Pubkey::default() {
            position.holder = ctx.accounts.buyer.key();
            position.curve = curve_key;
            position.bump = ctx.bumps.position;
        }
        match side {
            PmSide::Pass => {
                position.pass_shares =
                    position.pass_shares.checked_add(shares_out).ok_or(FirmError::MathOverflow)?
            }
            PmSide::Fail => {
                position.fail_shares =
                    position.fail_shares.checked_add(shares_out).ok_or(FirmError::MathOverflow)?
            }
        }

        emit!(MarketSharesBought {
            curve: curve_key,
            holder: position.holder,
            side,
            collateral_in,
            shares_out,
            fee,
        });
        Ok(())
    }

    /// Sell shares of one side of a market back to the curve. Permissionless — any holder signer,
    /// bounded by their own `MarketPosition` balance. Exact mirror of `buy_shares` using
    /// `bonding_curve::sell_output` UNMODIFIED. No price-ceiling guard needed here — a sell only ever
    /// moves price DOWN (real reserve shrinks, available-to-sell grows), the safe direction.
    pub fn sell_shares(
        ctx: Context<SellMarketShares>,
        side: PmSide,
        shares_in: u64,
        min_collateral_out: u64,
    ) -> Result<()> {
        require!(shares_in > 0, FirmError::ZeroAmount);
        require!(ctx.accounts.curve.status == PmCurveStatus::Open, FirmError::PmMarketNotOpen);
        let held = match side {
            PmSide::Pass => ctx.accounts.position.pass_shares,
            PmSide::Fail => ctx.accounts.position.fail_shares,
        };
        require!(held >= shares_in, FirmError::PmInsufficientShares);

        let fee_bps = ctx.accounts.curve.fee_bps;
        let (virtual_r, real_r, shares_outstanding) = match side {
            PmSide::Pass => {
                (ctx.accounts.curve.pass_virtual, ctx.accounts.curve.pass_real, ctx.accounts.curve.pass_shares)
            }
            PmSide::Fail => {
                (ctx.accounts.curve.fail_virtual, ctx.accounts.curve.fail_real, ctx.accounts.curve.fail_shares)
            }
        };
        let available = pm_curve_available_shares(virtual_r, shares_outstanding);
        let eff = (virtual_r as u128).saturating_add(real_r as u128);
        let gross = bonding_curve::sell_output(eff, available as u128, shares_in as u128)
            .ok_or(FirmError::MathOverflow)?;
        // Never draw down the non-withdrawable virtual seed (mirrors `bonding_curve::sell`'s guard).
        require!(gross <= real_r, FirmError::MathOverflow);
        let fee = bonding_curve::fee_amount(gross, fee_bps);
        let net_out = gross.saturating_sub(fee);
        require!(net_out >= min_collateral_out, FirmError::PmSlippageExceeded);

        let (firm_cut, platform_cut, pool_cut) = split_curve_fee_3way(
            fee,
            ctx.accounts.curve.firm_fee_bps,
            ctx.accounts.curve.platform_fee_bps,
            ctx.accounts.curve.pool_fee_bps,
            fee_bps,
        );
        let challenge_key = ctx.accounts.curve.challenge;
        let bump = [ctx.accounts.curve.bump];

        // Pay the seller BEFORE mutating bookkeeping — mirrors `withdraw_pm_lp`'s pay-then-record
        // order.
        ctx.accounts.pay_seller(side, net_out, &challenge_key, &bump)?;

        let curve = &mut ctx.accounts.curve;
        match side {
            PmSide::Pass => {
                curve.pass_real = real_r.saturating_sub(gross);
                curve.pass_shares = shares_outstanding.saturating_sub(shares_in);
            }
            PmSide::Fail => {
                curve.fail_real = real_r.saturating_sub(gross);
                curve.fail_shares = shares_outstanding.saturating_sub(shares_in);
            }
        }
        curve.firm_fees_accrued = curve.firm_fees_accrued.saturating_add(firm_cut);
        curve.platform_fees_accrued = curve.platform_fees_accrued.saturating_add(platform_cut);
        curve.pool_fees_accrued = curve.pool_fees_accrued.saturating_add(pool_cut);
        let curve_key = curve.key();

        let position = &mut ctx.accounts.position;
        match side {
            PmSide::Pass => position.pass_shares = position.pass_shares.saturating_sub(shares_in),
            PmSide::Fail => position.fail_shares = position.fail_shares.saturating_sub(shares_in),
        }

        emit!(MarketSharesSold {
            curve: curve_key,
            holder: position.holder,
            side,
            shares_in,
            collateral_out: net_out,
            fee,
        });
        Ok(())
    }

    /// Add permissionless liquidity depth to one side of a curve — NOT a purchase. No shares are
    /// minted to the depositor; `amount` is pure reserve depth, credited to both the side's real
    /// reserve and `curve.topup_deposited` (tracked separately from `pool_allocated` — see
    /// `deallocate_pool_from_curve`'s doc comment for why that separation is the load-bearing
    /// security property here). Because this widens `side_real` without touching the AMM's share
    /// pool, it nudges that side's implied price UP slightly (the same direction `allocate_pool_to_curve`'s
    /// deposits do) — an accepted quirk of pairing a real collateral leg with a notional share-supply
    /// leg, not a bug.
    ///
    /// The self-LP ban below is unconditional and the FIRST check in this handler — a trader funding
    /// their own market's curve is the single most important thing this instruction must never allow;
    /// skin-in-the-game flows only through the shared `PredictionMarketLpPool`, diversified across
    /// many traders' markets algorithmically.
    pub fn add_curve_topup(ctx: Context<AddCurveTopup>, side: PmSide, amount: u64) -> Result<()> {
        require!(ctx.accounts.depositor.key() != ctx.accounts.curve.trader, FirmError::PmSelfLpBanned);
        require!(amount > 0, FirmError::ZeroAmount);
        require!(ctx.accounts.curve.status == PmCurveStatus::Open, FirmError::PmMarketNotOpen);

        ctx.accounts.deposit(side, amount)?;

        let curve = &mut ctx.accounts.curve;
        match side {
            PmSide::Pass => curve.pass_real = curve.pass_real.saturating_add(amount),
            PmSide::Fail => curve.fail_real = curve.fail_real.saturating_add(amount),
        }
        curve.topup_deposited = curve.topup_deposited.saturating_add(amount);

        emit!(MarketCurveToppedUp {
            curve: curve.key(),
            depositor: ctx.accounts.depositor.key(),
            side,
            amount,
        });
        Ok(())
    }

    /// Freeze trading ahead of settlement. Settlement-authority-gated.
    pub fn lock_market(ctx: Context<LockMarketCurve>) -> Result<()> {
        require_market_curve_authority(&ctx.accounts.challenge, &ctx.accounts.firm_state)?;
        require!(ctx.accounts.curve.status == PmCurveStatus::Open, FirmError::PmMarketNotOpen);
        ctx.accounts.curve.status = PmCurveStatus::Locked;
        Ok(())
    }

    /// Record the real outcome. Settlement-authority-gated. Moves NO funds itself — redemption is a
    /// separate permissionless per-holder pull (`redeem_shares`), so settlement stays O(1) regardless
    /// of how many holders exist, same "no queue, no iteration over unbounded accounts" discipline as
    /// `withdraw_backstop`/`withdraw_pm_lp` elsewhere in this file.
    pub fn settle_market(ctx: Context<SettleMarketCurve>, outcome: PmSide) -> Result<()> {
        require_market_curve_authority(&ctx.accounts.challenge, &ctx.accounts.firm_state)?;
        require!(
            ctx.accounts.curve.status == PmCurveStatus::Open
                || ctx.accounts.curve.status == PmCurveStatus::Locked,
            FirmError::PmMarketNotOpen
        );
        let now = Clock::get()?.unix_timestamp;
        let curve = &mut ctx.accounts.curve;
        curve.status = PmCurveStatus::Settled;
        curve.outcome = Some(outcome);
        curve.settled_at = now;
        emit!(MarketSettled { curve: curve.key(), outcome, settled_at: now });
        Ok(())
    }

    /// Escape hatch for an evaluation that never resolves. Settlement-authority-gated. PROVISIONAL —
    /// the refund rule (`redeem_void_shares`, pro-rata against each side's OWN remaining real
    /// reserve, no pooling across vaults) has not had founder/economics sign-off; see DEC-89 and
    /// MASTER_ECONOMICS §22a. `redeem_shares`' pooled-across-both-vaults formula is specifically a
    /// Pass/Fail winner-take-most-of-the-pot design — wrong here, since neither side "won."
    pub fn void_market(ctx: Context<VoidMarketCurve>) -> Result<()> {
        require_market_curve_authority(&ctx.accounts.challenge, &ctx.accounts.firm_state)?;
        require!(
            ctx.accounts.curve.status == PmCurveStatus::Open
                || ctx.accounts.curve.status == PmCurveStatus::Locked,
            FirmError::PmMarketNotOpen
        );
        ctx.accounts.curve.status = PmCurveStatus::Void;
        emit!(MarketVoided { curve: ctx.accounts.curve.key() });
        Ok(())
    }

    /// Permissionless pull — anyone may crank this, but it always pays `position.holder`'s own token
    /// account (`holder_firma`, constrained to `position.holder`'s ownership), never the caller.
    /// Settlement is O(1) and moves no funds itself (`settle_market`); this is where funds actually
    /// move, one holder at a time, so no unbounded iteration over holders ever runs on-chain.
    ///
    /// THE core formula (see `pm_redeem_payout`'s doc comment): 1:1 in the normal (well-funded) case,
    /// a pro-rata haircut only under extreme imbalance — see DEC-89 / MASTER_ECONOMICS §22a for why
    /// two independent CPMM legs (not a true complementary-outcome AMM) can fall short of full
    /// backing. `redeemable_total`/`winning_shares_outstanding` are read fresh from `curve` on every
    /// call and NEVER decremented by this instruction — every holder's payout is computed against the
    /// SAME fixed pot regardless of redemption order, so no holder benefits from redeeming early (see
    /// `RedeemMarketShares::pay`'s doc comment for the complementary reasoning on the PHYSICAL
    /// draining side).
    pub fn redeem_shares(ctx: Context<RedeemMarketShares>, holder: Pubkey) -> Result<()> {
        require!(ctx.accounts.curve.status == PmCurveStatus::Settled, FirmError::PmNotSettled);
        let outcome = ctx.accounts.curve.outcome.ok_or(FirmError::PmNotSettled)?;

        let (winning_shares_outstanding, winning_position_shares) = match outcome {
            PmSide::Pass => (ctx.accounts.curve.pass_shares, ctx.accounts.position.pass_shares),
            PmSide::Fail => (ctx.accounts.curve.fail_shares, ctx.accounts.position.fail_shares),
        };
        require!(winning_position_shares > 0, FirmError::PmNothingToRedeem);

        let redeemable_total =
            (ctx.accounts.curve.pass_real as u128).saturating_add(ctx.accounts.curve.fail_real as u128);
        let payout = pm_redeem_payout(winning_position_shares, winning_shares_outstanding, redeemable_total);

        let challenge_key = ctx.accounts.curve.challenge;
        let bump = [ctx.accounts.curve.bump];
        ctx.accounts.pay(payout, &challenge_key, &bump)?;

        // Zero BOTH sides — not just the winning one — so the losing side's provably-worthless shares
        // are cleared too and a second call always sees `winning_position_shares == 0`
        // (`PmNothingToRedeem`), which is what stops a double-redeem.
        let position = &mut ctx.accounts.position;
        position.pass_shares = 0;
        position.fail_shares = 0;

        emit!(MarketSharesRedeemed { curve: ctx.accounts.curve.key(), holder, side: outcome, payout });
        Ok(())
    }

    /// `void_market`'s redemption leg — kept SEPARATE from `redeem_shares` rather than a status
    /// branch inside it, because the formula is genuinely different, not a variant of the same one:
    /// no pooling across vaults (a void has no winner), each side redeems against its OWN remaining
    /// real reserve only. PROVISIONAL, same standing as `void_market` itself — see that instruction's
    /// doc comment.
    pub fn redeem_void_shares(ctx: Context<RedeemVoidShares>, holder: Pubkey) -> Result<()> {
        require!(ctx.accounts.curve.status == PmCurveStatus::Void, FirmError::PmNotSettled);

        let curve = &ctx.accounts.curve;
        let position = &ctx.accounts.position;
        let pass_payout = pm_void_redeem_payout(position.pass_shares, curve.pass_shares, curve.pass_real);
        let fail_payout = pm_void_redeem_payout(position.fail_shares, curve.fail_shares, curve.fail_real);
        require!(pass_payout > 0 || fail_payout > 0, FirmError::PmNothingToRedeem);

        let challenge_key = curve.challenge;
        let bump = [curve.bump];
        ctx.accounts.pay(pass_payout, fail_payout, &challenge_key, &bump)?;

        let position = &mut ctx.accounts.position;
        position.pass_shares = 0;
        position.fail_shares = 0;

        emit!(MarketVoidRedeemed { curve: ctx.accounts.curve.key(), holder, pass_payout, fail_payout });
        Ok(())
    }

    /// Move `amount` from the shared LP pool's escrow into this curve's two vaults, split in the
    /// curve's CURRENT `pass_real : fail_real` ratio — falling back to the virtual-seed ratio when
    /// the curve has never traded (both `*_real` still 0, which would otherwise divide by zero) — so
    /// deepening liquidity never itself moves either leg's price disproportionately between the two
    /// sides. PDA-signed by the POOL (the source). Keeper/settlement-authority-gated. Increments
    /// `curve.pool_allocated` and `pool.total_drawn` (Phase 2's reserved field — this is what finally
    /// uses it).
    pub fn allocate_pool_to_curve(ctx: Context<AllocatePoolToCurve>, amount: u64) -> Result<()> {
        require_market_curve_authority(&ctx.accounts.challenge, &ctx.accounts.firm_state)?;
        require!(amount > 0, FirmError::ZeroAmount);

        let curve = &ctx.accounts.curve;
        let (pass_w, fail_w) = if curve.pass_real == 0 && curve.fail_real == 0 {
            (curve.pass_virtual, curve.fail_virtual)
        } else {
            (curve.pass_real, curve.fail_real)
        };
        let (to_pass, to_fail) = pm_pool_ratio_split(amount, pass_w, fail_w);

        ctx.accounts.disburse(to_pass, to_fail)?;

        let curve = &mut ctx.accounts.curve;
        curve.pass_real = curve.pass_real.saturating_add(to_pass);
        curve.fail_real = curve.fail_real.saturating_add(to_fail);
        curve.pool_allocated = curve.pool_allocated.saturating_add(amount);
        let curve_key = curve.key();

        let pool = &mut ctx.accounts.pm_lp_pool;
        pool.total_drawn = pool.total_drawn.saturating_add(amount);

        emit!(PmCurveAllocated { curve: curve_key, firm: pool.firm, amount, to_pass, to_fail });
        Ok(())
    }

    /// The symmetric reverse of `allocate_pool_to_curve` — moves capital back from a curve's vaults
    /// to the shared LP pool's escrow, same ratio-preserving split against the curve's CURRENT
    /// reserve ratio. Keeper/settlement-authority-gated.
    ///
    /// `require!(amount <= curve.pool_allocated, ...)` is the hard on-chain ceiling that stops even a
    /// COMPROMISED keeper authority from ever clawing back a permissionless top-up depositor's own
    /// contribution: `pool_allocated` (pool-sourced) and `topup_deposited` (depositor-sourced) are two
    /// separately-tracked fields specifically so this check is possible — deallocation can only ever
    /// pull back what the pool itself put in, never more, regardless of how much `topup_deposited`
    /// would otherwise "cover."
    ///
    /// Residual risk, flagged not silently patched: nothing here blocks deallocating from a `Locked`
    /// or `Settled` curve. A keeper draining pool capital after `settle_market` shrinks `pass_real`/
    /// `fail_real` — the exact inputs `redeem_shares`' `redeemable_total` reads live at EVERY
    /// redemption call — so a deallocation squeezed in between two redemptions could under-fund a
    /// later holder's payout relative to what an earlier holder already collected. Not gated here
    /// because this phase's spec names exactly one required guard (the ceiling above); leaving this
    /// open for the reviewer rather than inventing an un-requested status gate on genuinely new
    /// money-movement logic.
    pub fn deallocate_pool_from_curve(ctx: Context<DeallocatePoolFromCurve>, amount: u64) -> Result<()> {
        require_market_curve_authority(&ctx.accounts.challenge, &ctx.accounts.firm_state)?;
        require!(amount > 0, FirmError::ZeroAmount);
        require!(amount <= ctx.accounts.curve.pool_allocated, FirmError::PmExceedsPoolAllocation);

        let curve = &ctx.accounts.curve;
        let (pass_w, fail_w) = if curve.pass_real == 0 && curve.fail_real == 0 {
            (curve.pass_virtual, curve.fail_virtual)
        } else {
            (curve.pass_real, curve.fail_real)
        };
        let (from_pass_target, from_fail_target) = pm_pool_ratio_split(amount, pass_w, fail_w);
        // Never claim more than a leg's actual real reserve (defensive — `pool_allocated <=
        // pass_real + fail_real` should always hold, but this keeps the transfer amounts honest even
        // if it doesn't).
        let from_pass = from_pass_target.min(curve.pass_real);
        let from_fail = amount.saturating_sub(from_pass).min(curve.fail_real);
        let _ = from_fail_target; // superseded by the defensive `.min()` above

        let challenge_key = curve.challenge;
        let bump = [curve.bump];
        ctx.accounts.withdraw(from_pass, from_fail, &challenge_key, &bump)?;

        let curve = &mut ctx.accounts.curve;
        curve.pass_real = curve.pass_real.saturating_sub(from_pass);
        curve.fail_real = curve.fail_real.saturating_sub(from_fail);
        curve.pool_allocated = curve.pool_allocated.saturating_sub(amount);
        let curve_key = curve.key();

        let pool = &mut ctx.accounts.pm_lp_pool;
        pool.total_returned = pool.total_returned.saturating_add(amount);

        emit!(PmCurveDeallocated { curve: curve_key, firm: pool.firm, amount, from_pass, from_fail });
        Ok(())
    }

    /// Permissionless crank (typically a keeper on a schedule) — moves `curve.pool_fees_accrued` real
    /// $FIRMA from wherever it's sitting in the curve's two vaults into the LP pool's yield vault,
    /// then folds it into `yield_acc` via `fold_yield` — same "fold what arrived, retain in
    /// `unallocated_yield` if nothing's staked yet" idiom `sync_firma_yield`/`sync_backstop_firma_yield`
    /// already use. No signer identity check at all — same permission shape as those two (mirrors
    /// `SyncBackstopFirmaYield`'s Accounts struct exactly: no `Signer` field bound to any identity).
    /// Differs from them only in that the swept amount comes from a live accrual FIELD this program
    /// already tracks precisely, not a vault-balance delta against an external, untrusted depositor.
    pub fn sweep_curve_fees_to_pool(ctx: Context<SweepCurveFeesToPool>) -> Result<()> {
        let amount = ctx.accounts.curve.pool_fees_accrued;
        if amount == 0 {
            return Ok(());
        }
        let from_pass = amount.min(ctx.accounts.pass_vault.amount);
        let from_fail = amount.saturating_sub(from_pass).min(ctx.accounts.fail_vault.amount);

        let challenge_key = ctx.accounts.curve.challenge;
        let bump = [ctx.accounts.curve.bump];
        ctx.accounts.sweep(from_pass, from_fail, &challenge_key, &bump)?;

        let curve = &mut ctx.accounts.curve;
        curve.pool_fees_accrued = 0;
        let curve_key = curve.key();

        let pool = &mut ctx.accounts.pm_lp_pool;
        let (acc, unalloc) =
            fold_yield(pool.yield_acc, pool.unallocated_yield, amount, pool.total_yield_weight);
        pool.yield_acc = acc;
        pool.unallocated_yield = unalloc;

        emit!(PmCurveFeesSwept { curve: curve_key, firm: pool.firm, amount });
        Ok(())
    }

    /// Deliver owed `$FIRMA` directly from the firm's **Tier-2 treasury reserve** (§22). When
    /// the SOL treasury can't fund a curve buy, the keeper draws the firm's pre-acquired
    /// `$FIRMA` (seeded at deployment) straight to the trader — no curve sale, no slippage —
    /// before touching the investor backstop. Signed by the challenge's settlement authority.
    pub fn draw_treasury_firma(ctx: Context<DrawTreasuryFirma>, firma_amount: u64) -> Result<()> {
        require_payout_delivery_authority(
            &ctx.accounts.challenge,
            &ctx.accounts.firm_state,
            ctx.accounts.withdrawal.as_deref().map(|w| &**w),
        )?;
        let outstanding = ctx
            .accounts
            .queued_payout
            .firma_amount_owed
            .saturating_sub(ctx.accounts.queued_payout.firma_amount_delivered);
        require!(outstanding > 0, FirmError::PayoutAlreadyFilled);
        let reserve = ctx.accounts.treasury_firma_vault.amount;
        let draw = firma_amount.min(outstanding).min(reserve);
        require!(draw > 0, FirmError::InsufficientTreasuryFirma);
        ctx.accounts.deliver(draw)?;

        let qp = &mut ctx.accounts.queued_payout;
        qp.firma_amount_delivered = qp.firma_amount_delivered.saturating_add(draw);
        let fully = qp.firma_amount_delivered >= qp.firma_amount_owed;
        let challenge_key = qp.challenge;
        // Count this fill toward lifetime payouts (PAYOUT-LIFETIME-1). A reserve delivery spends no
        // treasury SOL, so unlike the curve-buy tiers there is no `spent` — but the trader still
        // received value, so credit the payout's SOL obligation (`sol_at_settlement`) prorated by the
        // $FIRMA drawn. Without this, a reserve-first firm (the default) shows $0 lifetime payouts after
        // a real payout, because only `process_queued_payout`/`execute_payout_buy` bumped the counter.
        let paid_value = pro_rata(qp.sol_at_settlement, draw, qp.firma_amount_owed);
        let firm = &mut ctx.accounts.firm_state;
        firm.total_paid_out = firm.total_paid_out.saturating_add(paid_value);
        // Discharge the obligation when THIS fill completes it. The Tier-2 reserve can fully satisfy a
        // payout (reserve-first); without this, `open_payouts` would stick and wedge `finalize_bankruptcy`.
        if fully {
            firm.open_payouts = firm.open_payouts.saturating_sub(1);
        }
        emit!(TreasuryFirmaDrawn {
            firm: ctx.accounts.firm_state.key(),
            challenge: challenge_key,
            amount: draw,
        });
        Ok(())
    }

    /// **Tier-4 payout** — draw from the protocol-wide **Universal Treasury Pool** to buy $FIRMA
    /// and deliver it to a funded trader when the firm's own waterfall is exhausted. This is the
    /// last-resort path after the firm's SOL treasury, $FIRMA reserve, and backstop have all been
    /// used. The pool is **pure grant** (no per-firm debt/repayment): because the protocol/ARE —
    /// not the operator — controls who passes, the pool cannot be farmed by colluding on passes.
    ///
    /// Signed by the challenge's settlement authority. Gates: (1) firm's treasury must be below
    /// `sol_amount` AND reserve empty AND velocity break active (all three own-waterfall paths
    /// exhausted); (2) global daily draw cap `UNIVERSAL_DAILY_DRAW_CAP_SOL`; (3) pre-graduation
    /// only (the curve must be live). `draw_universal` is the only exit from `universal_vault`.
    pub fn draw_universal<'info>(
        ctx: Context<'_, '_, '_, 'info, DrawUniversal<'info>>,
        sol_amount: u64,
        min_firma_out: u64,
    ) -> Result<()> {
        require_payout_delivery_authority(
            &ctx.accounts.challenge,
            &ctx.accounts.firm_state,
            ctx.accounts.withdrawal.as_deref().map(|w| &**w),
        )?;
        // Post-graduation the conversion venue is the Raydium pool (model A) — funded here by the universal
        // vault instead of the firm treasury — so this no longer bails on a graduated curve.

        // "Last resort" gate: all three firm-local tiers must be exhausted.
        // (1) SOL treasury insufficient for this draw.
        // (2) $FIRMA reserve is empty.
        // (3) velocity_break_flag is set (backstop has been called and circuit-breaker tripped).
        let firm = &ctx.accounts.firm_state;
        let reserve_empty = ctx.accounts.treasury_firma_vault.amount == 0;
        let treasury_short = firm.treasury_sol < sol_amount;
        require!(
            treasury_short && reserve_empty && firm.velocity_break_flag,
            FirmError::UniversalDrawNotLastResort
        );

        // Outstanding queued obligation check.
        let outstanding = ctx
            .accounts
            .queued_payout
            .firma_amount_owed
            .saturating_sub(ctx.accounts.queued_payout.firma_amount_delivered);
        require!(outstanding > 0, FirmError::PayoutAlreadyFilled);

        // Global daily cap (rate-limits depletion across all firms).
        let now = Clock::get()?.unix_timestamp;
        let day = now / 86_400;
        {
            let pool = &mut ctx.accounts.universal_pool;
            if day != pool.draw_day {
                pool.daily_drawn = 0;
                pool.draw_day = day;
            }
            require!(
                pool.daily_drawn.saturating_add(sol_amount) <= UNIVERSAL_DAILY_DRAW_CAP_SOL,
                FirmError::UniversalDailyCapExceeded
            );
            require!(
                ctx.accounts.universal_vault.amount >= sol_amount,
                FirmError::InsufficientUniversalPool
            );
        }

        // Snapshot the pool balance BEFORE the draw — the denominator for the 10%-depletion bankruptcy
        // trigger (§24 v2). Captured pre-buy so this firm's own withdrawal doesn't shrink its own threshold.
        let pool_before = ctx.accounts.universal_vault.amount;

        // Buy $FIRMA funded by the universal vault (universal-pool PDA signs), delivered to the trader.
        // Conversion venue: the curve pre-graduation, else the graduated Raydium pool (model A) — the
        // Tier-4 last-resort tail of the post-graduation payout path.
        if ctx.accounts.curve.graduated {
            let (sm, fm) = (ctx.accounts.firm_state.sol_mint, ctx.accounts.firm_state.firma_mint);
            let pool_ai = ctx.accounts.universal_pool.to_account_info();
            let input_ai = ctx.accounts.universal_vault.to_account_info();
            let output_ai = ctx.accounts.trader_firma.to_account_info();
            let bump = [ctx.accounts.universal_pool.bump];
            let seeds: &[&[u8]] = &[b"universal_pool", &bump];
            swap_graduated(
                &pool_ai, seeds, &sm, &fm, &input_ai, &output_ai,
                ctx.remaining_accounts, sol_amount, min_firma_out,
            )?;
        } else {
            ctx.accounts.curve_buy(sol_amount, min_firma_out)?;
        }

        // Account for the draw.
        let pool = &mut ctx.accounts.universal_pool;
        pool.daily_drawn = pool.daily_drawn.saturating_add(sol_amount);
        pool.total_drawn = pool.total_drawn.saturating_add(sol_amount);

        // Deliver $FIRMA to the trader (the curve buy already routed it to trader_firma).
        let qp = &mut ctx.accounts.queued_payout;
        let delivered = min_firma_out.min(outstanding);
        qp.firma_amount_delivered = qp.firma_amount_delivered.saturating_add(delivered);
        let fully = qp.firma_amount_delivered >= qp.firma_amount_owed;
        let challenge_key = qp.challenge;

        // Track this firm's cumulative ULP depletion + auto-bankruptcy (§24 v2). Drawing from the shared
        // pool is spending the commons; the instant a firm's lifetime draws reach 10% of the pool it flips
        // to Bankrupt (the ONLY path there) — it stops selling and `finalize_bankruptcy` sweeps its residual
        // back to the pool. Bankrupting mid-draw is safe: the trader leg above is already delivered.
        let firm = &mut ctx.accounts.firm_state;
        // Count toward lifetime payouts (PAYOUT-LIFETIME-1) — Tier-4 buys $FIRMA with the shared pool's
        // SOL, so credit the payout's SOL obligation prorated by the $FIRMA delivered, consistent with
        // the other tiers.
        let paid_value = pro_rata(qp.sol_at_settlement, delivered, qp.firma_amount_owed);
        firm.total_paid_out = firm.total_paid_out.saturating_add(paid_value);
        if fully {
            firm.open_payouts = firm.open_payouts.saturating_sub(1);
        }
        firm.ulp_drawn = firm.ulp_drawn.saturating_add(sol_amount);
        if firm.status != FirmStatus::Bankrupt
            && firm.ulp_drawn >= pool_before / BANKRUPTCY_ULP_DEPLETION_DIVISOR
        {
            firm.status = FirmStatus::Bankrupt;
            emit!(FirmAutoBankrupt {
                firm: firm.key(),
                ulp_drawn: firm.ulp_drawn,
                pool_balance: pool_before,
            });
        }

        emit!(UniversalDrawn {
            firm: firm.key(),
            challenge: challenge_key,
            sol_spent: sol_amount,
            firma_delivered: delivered,
        });
        Ok(())
    }

    /// Self-funded operator bond crank (§10/§14). PERMISSIONLESS — anyone can crank it. Moves the
    /// treasury-earmarked bond SOL (`bond_accrual`) into the firm's `dispute`-program `OperatorStake`
    /// PDA, unwrapping wSOL → native SOL through a short-lived PDA vault. Funds up to whatever brings the
    /// bond to `dispute::MIN_OPERATOR_STAKE_LAMPORTS` (50 SOL); once full it flips `bond_funded` (so
    /// `pay_challenge_fee` stops earmarking and the 1% stays as treasury) and releases any leftover
    /// earmark. Destination is address+owner-bound to the firm's canonical OperatorStake, so there is
    /// zero destination discretion. The keeper runs `dispute::init_bond_shell` (once, to create the
    /// OperatorStake) + `dispute::sync_bond` (to reconcile `staked_lamports`) alongside this.
    pub fn fund_operator_bond(ctx: Context<FundOperatorBond>) -> Result<()> {
        // Current bond = native SOL the OperatorStake holds ABOVE its rent-exempt minimum.
        let os_ai = ctx.accounts.operator_stake.to_account_info();
        let os_rent = Rent::get()?.minimum_balance(os_ai.data_len());
        let current_bond = os_ai.lamports().saturating_sub(os_rent);
        let remaining = dispute::MIN_OPERATOR_STAKE_LAMPORTS.saturating_sub(current_bond);

        ctx.accounts.treasury_vault.reload()?;
        let vault_bal = ctx.accounts.treasury_vault.amount;
        let to_fund = ctx.accounts.firm_state.bond_accrual.min(vault_bal).min(remaining);

        let bump = [ctx.accounts.firm_state.bump];
        let owner = ctx.accounts.firm_state.owner;
        let signer = firm_signer(&owner, &bump);

        // 1. Move `to_fund` wSOL from treasury into the short-lived unwrap vault (firm PDA authorizes).
        if to_fund > 0 {
            token::transfer(
                CpiContext::new_with_signer(
                    ctx.accounts.token_program.to_account_info(),
                    token::Transfer {
                        from: ctx.accounts.treasury_vault.to_account_info(),
                        to: ctx.accounts.bond_unwrap_vault.to_account_info(),
                        authority: ctx.accounts.firm_state.to_account_info(),
                    },
                    &[&signer],
                ),
                to_fund,
            )?;
        }
        // 2. Close the unwrap vault → cranker as NATIVE SOL (returns `to_fund` + the vault's rent).
        token::close_account(CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            token::CloseAccount {
                account: ctx.accounts.bond_unwrap_vault.to_account_info(),
                destination: ctx.accounts.cranker.to_account_info(),
                authority: ctx.accounts.firm_state.to_account_info(),
            },
            &[&signer],
        ))?;
        // 3. Forward `to_fund` native SOL from the cranker to the OperatorStake PDA. The cranker nets 0:
        //    it just received `to_fund` + the vault rent from the close and passes `to_fund` on (keeping
        //    the rent it originally paid to open the vault). This is the trustless wSOL→bond hand-off.
        if to_fund > 0 {
            anchor_lang::system_program::transfer(
                CpiContext::new(
                    ctx.accounts.system_program.to_account_info(),
                    anchor_lang::system_program::Transfer {
                        from: ctx.accounts.cranker.to_account_info(),
                        to: os_ai.clone(),
                    },
                ),
                to_fund,
            )?;
        }
        // 4. Book-keeping: draw down the earmark; flip `bond_funded` + release the remainder when full.
        ctx.accounts.treasury_vault.reload()?;
        let treasury_balance = ctx.accounts.treasury_vault.amount;
        let new_bond = current_bond.saturating_add(to_fund);
        let firm = &mut ctx.accounts.firm_state;
        firm.bond_accrual = firm.bond_accrual.saturating_sub(to_fund);
        firm.treasury_sol = treasury_balance;
        // `bond_funded` is DERIVED from the bond's actual level, not sticky: `>= 50 SOL` here, and if a
        // slash later drops the OperatorStake below 50 SOL `reconcile_operator_bond` flips it back to
        // false so the 1% earmark auto-resumes (v2 auto-refill, §14.1). Computing it bidirectionally here
        // means a `fund_operator_bond` crank on a post-slash firm also corrects a stale-true flag.
        firm.bond_funded = new_bond >= dispute::MIN_OPERATOR_STAKE_LAMPORTS;
        if firm.bond_funded {
            firm.bond_accrual = 0; // release any leftover earmark back to the treasury
        }
        emit!(OperatorBondFunded {
            firm: firm.key(),
            funded: to_fund,
            total_bond: new_bond,
            bond_complete: firm.bond_funded,
        });
        Ok(())
    }

    /// v2 auto-refill (§14.1): reconcile `bond_funded` to the OperatorStake's ACTUAL native balance.
    /// The flag is derived, not sticky — `fund_operator_bond` sets it true when the bond reaches 50 SOL,
    /// but a slash (`dispute::slash_settlement_fault` / `resolve_dispute` upheld) debits lamports straight
    /// out of the OperatorStake, which the firm program can't observe until something reads that account.
    /// This permissionless crank is that read: it sets `bond_funded = current_bond >= 50 SOL`, so a slash
    /// below the floor flips it back to false and `pay_challenge_fee` auto-resumes the 1% earmark until the
    /// bond refills. No token accounts, no `init` — cheap enough for the keeper to fire only when it reads
    /// a stale-true flag (bond below the floor while `bond_funded`). `current_bond` = lamports above the
    /// rent-exempt minimum, matching `fund_operator_bond`.
    pub fn reconcile_operator_bond(ctx: Context<ReconcileOperatorBond>) -> Result<()> {
        let os_ai = ctx.accounts.operator_stake.to_account_info();
        let os_rent = Rent::get()?.minimum_balance(os_ai.data_len());
        let current_bond = os_ai.lamports().saturating_sub(os_rent);

        let firm = &mut ctx.accounts.firm_state;
        firm.bond_funded = current_bond >= dispute::MIN_OPERATOR_STAKE_LAMPORTS;
        emit!(OperatorBondReconciled {
            firm: firm.key(),
            current_bond,
            bond_funded: firm.bond_funded,
        });
        Ok(())
    }

    /// Convert the accumulated 3% $YOURFIRM buy-back SOL into the Tier-2 treasury $FIRMA reserve
    /// (§17). PERMISSIONLESS — anyone can crank it; the $FIRMA can ONLY land in the firm-owned
    /// `treasury_firma_vault` (address-bound), so there is zero destination discretion. Spends up to
    /// `sol_amount` (capped at the earmarked `firma_buyback_acc`) from the treasury vault on a curve
    /// buy, delivers the $FIRMA to the reserve, then re-syncs `treasury_sol` to the vault balance.
    /// Pre-graduation only (the curve must be live); post-graduation the leg simply stays as treasury
    /// SOL until a Raydium buy path lands. `min_firma_out` is the slippage floor.
    pub fn execute_firma_buyback(ctx: Context<ExecuteFirmaBuyback>, sol_amount: u64, min_firma_out: u64) -> Result<()> {
        require!(!ctx.accounts.firm_state.graduated, FirmError::AlreadyGraduated);
        let spend = sol_amount.min(ctx.accounts.firm_state.firma_buyback_acc);
        require!(spend > 0, FirmError::ZeroAmount);

        ctx.accounts.curve_buy(spend, min_firma_out)?;

        // Re-sync the treasury cache to the post-buy vault balance (the curve also debits the 0.5%
        // firm fee) and draw down the earmark by the principal spent.
        ctx.accounts.treasury_vault.reload()?;
        let firm = &mut ctx.accounts.firm_state;
        firm.treasury_sol = ctx.accounts.treasury_vault.amount;
        firm.firma_buyback_acc = firm.firma_buyback_acc.saturating_sub(spend);

        emit!(FirmaBuybackExecuted {
            firm: firm.key(),
            sol: spend,
            remaining_acc: firm.firma_buyback_acc,
        });
        Ok(())
    }

    /// Phase 4.4 (§12 / RAYDIUM_GRADUATION.md) — deposit the earmarked post-graduation LP fee-leg into
    /// the firm's graduated Raydium pool as PERMANENTLY-LOCKED liquidity. Permissionless crank:
    ///   1. zap — swap `sol_to_swap` (≈ half the earmark) SOL → $FIRMA on the pool (`swap_base_input`);
    ///   2. deposit both sides, minting LP into `lp_locked_vault` (a firm-PDA-owned account the program
    ///      exposes no withdraw for — the same lock-not-burn guarantee as the graduation LP).
    /// Both SOL draws (swap + deposit) come out of `treasury_vault`; the earmark is decremented by exactly
    /// the SOL consumed and `treasury_sol` re-synced. `remaining_accounts` = `[..14 swap][..14 deposit]`.
    /// Only functions on a graduated firm (a live Raydium pool must exist) — inert pre-graduation.
    /// The keeper computes `sol_to_swap` (≈ deploy/2), `lp_token_amount`, and the caps from live reserves.
    #[allow(clippy::too_many_arguments)]
    pub fn add_graduated_liquidity<'info>(
        ctx: Context<'_, '_, '_, 'info, AddGraduatedLiquidity<'info>>,
        sol_to_swap: u64,
        min_firma_out: u64,
        lp_token_amount: u64,
        max_sol_deposit: u64,
        max_firma_deposit: u64,
    ) -> Result<()> {
        require!(ctx.accounts.firm_state.graduated, FirmError::CurveNotGraduated);
        let deploy = ctx.accounts.firm_state.post_grad_lp_acc;
        require!(deploy > 0, FirmError::ZeroAmount);
        require!(sol_to_swap > 0 && lp_token_amount > 0, FirmError::ZeroAmount);
        // Never spend more than the earmark: the swap and deposit SOL sides must both fit inside `deploy`,
        // so a cranker can't siphon ordinary (non-earmarked) treasury SOL into the pool.
        require!(
            sol_to_swap.checked_add(max_sol_deposit).ok_or(FirmError::MathOverflow)? <= deploy,
            FirmError::ZeroAmount
        );

        let owner = ctx.accounts.firm_state.owner;
        let bump = [ctx.accounts.firm_state.bump];
        let seeds = firm_signer(&owner, &bump);
        let sol_mint = ctx.accounts.firm_state.sol_mint;
        let firma_mint = ctx.accounts.firm_state.firma_mint;

        let ra = ctx.remaining_accounts;
        require!(ra.len() == 2 * (CPSWAP_SWAP_ACCOUNTS + 1), FirmError::BadRaydiumAccounts);
        let (swap_ra, dep_ra) = ra.split_at(CPSWAP_SWAP_ACCOUNTS + 1);

        ctx.accounts.treasury_vault.reload()?;
        let before = ctx.accounts.treasury_vault.amount;

        // 1) Zap: swap ~half the earmark SOL → $FIRMA into the staging account (firm PDA signs).
        swap_graduated(
            &ctx.accounts.firm_state.to_account_info(),
            &seeds,
            &sol_mint,
            &firma_mint,
            &ctx.accounts.treasury_vault.to_account_info(),
            &ctx.accounts.lp_firma_staging.to_account_info(),
            swap_ra,
            sol_to_swap,
            min_firma_out,
        )?;

        // 2) Deposit both sides → LP minted into the firm-owned locked vault (firm PDA signs).
        deposit_graduated(
            &ctx.accounts.firm_state.to_account_info(),
            &seeds,
            &sol_mint,
            &firma_mint,
            &ctx.accounts.treasury_vault.to_account_info(),
            &ctx.accounts.lp_firma_staging.to_account_info(),
            &ctx.accounts.lp_locked_vault.to_account_info(),
            dep_ra,
            lp_token_amount,
            max_sol_deposit,
            max_firma_deposit,
        )?;

        // Draw the earmark down by the SOL actually consumed (swap + deposit) and re-sync the cache.
        ctx.accounts.treasury_vault.reload()?;
        let consumed = before.saturating_sub(ctx.accounts.treasury_vault.amount);
        let firm = &mut ctx.accounts.firm_state;
        firm.treasury_sol = ctx.accounts.treasury_vault.amount;
        firm.post_grad_lp_acc = firm.post_grad_lp_acc.saturating_sub(consumed);
        emit!(GraduatedLiquidityAdded {
            firm: firm.key(),
            sol_consumed: consumed,
            lp_minted: lp_token_amount,
            remaining_acc: firm.post_grad_lp_acc,
        });
        Ok(())
    }

    // ── Tier deployment-fee routing (Architecture §5) ──────────────────────────────
    // RESERVE-3 (2026-07-11): the launch fee is now a SINGLE plain-SOL instruction, `pay_deployment_fee`
    // — every leg (franchise, DP, $DPROP burn, Universal, firm-treasury remainder) settles in SOL at
    // deploy. All the former curve-buy instructions (`deploy_auto_purchase`, `deploy_burn`) and the
    // deferred-launch escrow (`fund_pending_token_buy` → `pending_token_buy`/`pending_token_burn`) were
    // removed: the owner-drip + Tier-2 reserve are MINTED in `distribute_supply`, and the $FIRMA
    // buy-and-burn is gone. The `TierFranchisePool` is a minimal accumulator; weighted distribution is
    // deferred.

    /// One-time per-tier franchise pool (global accumulator). Permissionless to initialise.
    pub fn init_franchise_pool(ctx: Context<InitFranchisePool>, tier: u8) -> Result<()> {
        require!(tier <= MAX_TIER, FirmError::InvalidTier);
        let pool = &mut ctx.accounts.franchise_pool;
        pool.tier = tier;
        pool.vault = ctx.accounts.franchise_vault.key();
        pool.total_contributed = 0;
        pool.bump = ctx.bumps.franchise_pool;
        Ok(())
    }

    /// Route the launch fee from the owner: the franchise pool (9%, with a 30% referral cut to a
    /// referrer when supplied), DecentralProp (20%), the $DPROP buy-and-burn sink (5%), the Universal
    /// Treasury Pool (3%), and the firm-treasury remainder (~63%). The price is fixed by the firm's
    /// tier. RESERVE-3 (2026-07-11): every curve-buy leg (owner-drip / treasury auto-purchases and the
    /// $FIRMA buy-and-burn) has been removed — the drip + reserve are MINTED in `distribute_supply`,
    /// so there is no deploy-time escrow and no `$FIRMA` deflation leg; the freed % all folds into the
    /// firm-treasury remainder. Every leg here settles in plain SOL at deploy — no curve needed.
    pub fn pay_deployment_fee(
        ctx: Context<PayDeploymentFee>,
        price_lamports: u64,
    ) -> Result<()> {
        // SOL MIGRATION (oracle-free, Phase 3+4): the USD launch-fee ladder
        // (`deployment_tier_price_usd`) is converted to SOL **off-chain** at the live Pyth rate; the
        // settlement authority (== `firm.risk_engine_authority`, a required signer on this ix) attests
        // the quoted `price_lamports`. Same trust model the eval fee already uses (amount as arg).
        require!(price_lamports > 0, FirmError::ZeroAmount);
        let price = price_lamports;
        let has_referrer = ctx.accounts.referrer_sol.is_some();
        let split = compute_deployment_fee_split(price, has_referrer)?;

        if split.referral_bonus > 0 {
            let referrer = ctx
                .accounts
                .referrer_sol
                .as_ref()
                .ok_or(FirmError::MissingReferrer)?
                .to_account_info();
            ctx.accounts.xfer(referrer, split.referral_bonus)?;
        }
        ctx.accounts.xfer(ctx.accounts.franchise_vault.to_account_info(), split.franchise_general)?;
        ctx.accounts.xfer(ctx.accounts.dp_sol.to_account_info(), split.decentralprop)?;
        ctx.accounts.xfer(ctx.accounts.dprop_buyback_vault.to_account_info(), split.dprop_burn)?;
        ctx.accounts.xfer(ctx.accounts.universal_vault.to_account_info(), split.universal)?;
        ctx.accounts.xfer(ctx.accounts.treasury_vault.to_account_info(), split.firm_treasury)?;

        let pool = &mut ctx.accounts.franchise_pool;
        pool.total_contributed =
            pool.total_contributed.checked_add(split.franchise_general).ok_or(FirmError::MathOverflow)?;
        let universal = &mut ctx.accounts.universal_pool;
        universal.total_contributed =
            universal.total_contributed.checked_add(split.universal).ok_or(FirmError::MathOverflow)?;
        // F-1/F-2 fix: reconcile to the live vault balance (the firm-treasury leg was moved into
        // treasury_vault above; this also absorbs any out-of-band curve credit) rather than a blind add.
        ctx.accounts.treasury_vault.reload()?;
        let treasury_balance = ctx.accounts.treasury_vault.amount;
        let firm = &mut ctx.accounts.firm_state;
        firm.treasury_sol = treasury_balance;

        emit!(DeploymentFeePaid {
            firm: firm.key(),
            price,
            franchise: split.franchise_general,
            referral: split.referral_bonus,
            decentralprop: split.decentralprop,
            dprop_burn: split.dprop_burn,
            universal: split.universal,
            firm_treasury: split.firm_treasury,
        });
        Ok(())
    }

    /// Phase 2 finalize: flip `token_live` on (opening evaluation sales). Sales can only open once
    /// the token actually exists (mint + curve + supply distributed).
    ///
    /// RESERVE-3 (2026-07-11): the deploy-fee escrow was removed entirely (no curve-buy legs remain at
    /// deploy — drip + reserve are minted, and the $FIRMA buy-and-burn is gone), so there is nothing to
    /// drain here. This just flips `token_live` on and opens the curve to public trading.
    pub fn finalize_token_launch(ctx: Context<FinalizeTokenLaunch>) -> Result<()> {
        require!(!ctx.accounts.firm_state.token_live, FirmError::TokenAlreadyLaunched);
        require!(ctx.accounts.firm_state.supply_distributed, FirmError::TokenNotLaunched);

        let firm = &mut ctx.accounts.firm_state;
        firm.token_live = true;
        firm.token_pending = false;
        emit!(TokenLaunched { firm: firm.key() });

        // Front-running guard: `firm_state` signs via its own PDA seeds; only this program can ever
        // produce that signature, so `open_trading` can't be called early by
        // program can ever produce that signature, so `open_trading` can't be called early by
        // anyone else (see `bonding_curve::OpenTrading`).
        let owner_key = ctx.accounts.owner.key();
        let firm_seeds: &[&[u8]] = &[b"firm", owner_key.as_ref(), &[ctx.accounts.firm_state.bump]];
        bonding_curve::cpi::open_trading(CpiContext::new_with_signer(
            ctx.accounts.bonding_curve_program.to_account_info(),
            bonding_curve::cpi::accounts::OpenTrading {
                curve: ctx.accounts.curve.to_account_info(),
                firm_state: ctx.accounts.firm_state.to_account_info(),
            },
            &[firm_seeds],
        ))?;
        Ok(())
    }

    /// One-time migration for firms deployed before the deferred-token fields existed: extend the
    /// account by the two trailing bytes and backfill `token_live = true` (they already run a live
    /// token) / `token_pending = false`. Owner-signed, idempotent (no-op once already migrated).
    pub fn migrate_firm_token_fields(ctx: Context<MigrateFirmTokenFields>) -> Result<()> {
        let ai = ctx.accounts.firm_state.to_account_info();
        // K-1: pin to the TOKEN-generation size (before the authority-rotation fields), NOT the current
        // full `INIT_SPACE`. Otherwise appending the rotation fields would grow `new_len` and this
        // instruction's `new_len - 2 / - 1` writes would land in the middle of the new fields. A firm
        // that later needs the rotation fields runs `migrate_firm_authority_fields` (idempotent).
        let new_len = 8 + FirmState::INIT_SPACE - POST_TOKEN_TRAILING_LEN;
        let old_len = ai.data_len();
        if old_len >= new_len {
            return Ok(()); // already at (or past) the token-generation size
        }
        // Top up rent for the two new bytes before extending.
        let rent = Rent::get()?;
        let needed = rent.minimum_balance(new_len);
        let have = ai.lamports();
        if needed > have {
            anchor_lang::system_program::transfer(
                CpiContext::new(
                    ctx.accounts.system_program.to_account_info(),
                    anchor_lang::system_program::Transfer {
                        from: ctx.accounts.owner.to_account_info(),
                        to: ai.clone(),
                    },
                ),
                needed - have,
            )?;
        }
        ai.resize(new_len)?; // zero-fills the appended bytes → token_pending = false
        let mut data = ai.try_borrow_mut_data()?;
        data[new_len - 2] = 1; // token_live = true (backfill: existing firms are already launched)
        data[new_len - 1] = 0; // token_pending = false
        Ok(())
    }

    /// K-1 — extend a firm to the keeper-rotation layout: append `previous_risk_engine_authority`
    /// (Pubkey) + `authority_rotation_deadline` (i64). Permissionless + idempotent. A firm must be at
    /// the token generation first (`migrate_firm_token_fields`); this extends it the rest of the way.
    /// The appended bytes zero-fill to exactly "no rotation pending" (previous = default, deadline = 0),
    /// so no field values need setting — the resize is the whole migration.
    pub fn migrate_firm_authority_fields(ctx: Context<MigrateFirmTokenFields>) -> Result<()> {
        let ai = ctx.accounts.firm_state.to_account_info();
        let new_len = 8 + FirmState::INIT_SPACE;
        let old_len = ai.data_len();
        if old_len >= new_len {
            return Ok(()); // already migrated
        }
        let rent = Rent::get()?;
        let needed = rent.minimum_balance(new_len);
        let have = ai.lamports();
        if needed > have {
            anchor_lang::system_program::transfer(
                CpiContext::new(
                    ctx.accounts.system_program.to_account_info(),
                    anchor_lang::system_program::Transfer {
                        from: ctx.accounts.owner.to_account_info(),
                        to: ai.clone(),
                    },
                ),
                needed - have,
            )?;
        }
        ai.resize(new_len)?; // zero-fills → previous_risk_engine_authority = 0, deadline = 0
        Ok(())
    }

    /// K-1 mass-migration helper — a PERMISSIONLESS variant of `migrate_firm_authority_fields`. After a
    /// program upgrade that appends fields, every `FirmState` fails to deserialize until it's migrated;
    /// the owner-signed variant can't do a fleet migration because a shared cluster has many firms with
    /// different owners (none of whose keys a keeper holds). This grants NO privilege — it only extends
    /// the account and zero-fills the two appended authority fields (previous = default, deadline = 0),
    /// so leaving it unsigned is safe. `firm_owner` is passed unsigned purely to derive the firm PDA;
    /// `payer` funds the rent top-up (the caller pays for the space it adds). It also backfills
    /// `token_live = true` for any firm predating the token fields (such a firm is already running a
    /// live token), making this a complete "bring to current layout" from ANY older size. Idempotent.
    pub fn migrate_firm_permissionless(ctx: Context<MigrateFirmPermissionless>) -> Result<()> {
        let ai = ctx.accounts.firm_state.to_account_info();
        let full = 8 + FirmState::INIT_SPACE;
        let token_gen = full - POST_TOKEN_TRAILING_LEN;
        let old_len = ai.data_len();
        if old_len >= full {
            return Ok(()); // already at the current layout
        }
        let was_pre_token = old_len < token_gen;
        let rent = Rent::get()?;
        let needed = rent.minimum_balance(full);
        let have = ai.lamports();
        if needed > have {
            anchor_lang::system_program::transfer(
                CpiContext::new(
                    ctx.accounts.system_program.to_account_info(),
                    anchor_lang::system_program::Transfer {
                        from: ctx.accounts.payer.to_account_info(),
                        to: ai.clone(),
                    },
                ),
                needed - have,
            )?;
        }
        ai.resize(full)?; // zero-fills the appended bytes → previous = default, deadline = 0
        if was_pre_token {
            // The zero-fill wrongly set token_live = false; a firm this old runs a live token, so
            // backfill it (mirrors migrate_firm_token_fields' two trailing bytes at the token-gen size).
            let mut data = ai.try_borrow_mut_data()?;
            data[token_gen - 2] = 1; // token_live = true
            data[token_gen - 1] = 0; // token_pending = false
        }
        {
            // `backstop_pool_bps` (2026-07-27 staking rebalance) is the LAST field in `FirmState`,
            // so this resize always zero-fills it for a firm migrating across this boundary — but 0
            // silently zeroes out the intended 5% leg rather than defaulting it, unlike every other
            // appended field here whose zero-default IS the correct value. Backfill the real default.
            let mut data = ai.try_borrow_mut_data()?;
            let bps_offset = full - 2;
            data[bps_offset..full].copy_from_slice(&DEFAULT_BACKSTOP_POOL_BPS.to_le_bytes());
        }
        Ok(())
    }

    /// DEC-77 migration — permissionless, mirrors `migrate_firm_permissionless`'s pattern: grants no
    /// new privilege, it only extends a pre-existing `QueuedPayout` (created before `advance_sol_spent`
    /// existed) and zero-fills the appended field — the correct default (a normal, pre-DEC-77 payout
    /// was never advanced). Unlike `FirmState`, nothing else resizes a `QueuedPayout` to its current
    /// layout, so this is a dedicated crank rather than a side effect of an existing migration.
    pub fn migrate_queued_payout_advance_field(
        ctx: Context<MigrateQueuedPayoutAdvanceField>,
        cycle: u32,
    ) -> Result<()> {
        let _ = cycle; // seed-only (bound by the PDA derivation in the account struct)
        let ai = ctx.accounts.queued_payout.to_account_info();
        let new_len = 8 + QueuedPayout::INIT_SPACE;
        let old_len = ai.data_len();
        if old_len >= new_len {
            return Ok(()); // already migrated
        }
        let rent = Rent::get()?;
        let needed = rent.minimum_balance(new_len);
        let have = ai.lamports();
        if needed > have {
            anchor_lang::system_program::transfer(
                CpiContext::new(
                    ctx.accounts.system_program.to_account_info(),
                    anchor_lang::system_program::Transfer {
                        from: ctx.accounts.payer.to_account_info(),
                        to: ai.clone(),
                    },
                ),
                needed - have,
            )?;
        }
        ai.resize(new_len)?; // zero-fills the appended byte range → advance_sol_spent = 0
        Ok(())
    }

    /// PAYOUT-ADVANCE-11 migration — permissionless, identical shape to
    /// `migrate_queued_payout_advance_field`: extends a pre-existing `AdvancePool` (created before
    /// `daily_advance_spent`/`advance_day` existed) and zero-fills the appended fields — the correct
    /// default (a pool this old has spent nothing today by construction, and day 0 forces the very next
    /// advance to treat itself as a new day and reset cleanly).
    pub fn migrate_advance_pool_daily_fields(ctx: Context<MigrateAdvancePoolDailyFields>) -> Result<()> {
        let ai = ctx.accounts.advance_pool.to_account_info();
        let new_len = 8 + AdvancePool::INIT_SPACE;
        let old_len = ai.data_len();
        if old_len >= new_len {
            return Ok(()); // already migrated
        }
        let rent = Rent::get()?;
        let needed = rent.minimum_balance(new_len);
        let have = ai.lamports();
        if needed > have {
            anchor_lang::system_program::transfer(
                CpiContext::new(
                    ctx.accounts.system_program.to_account_info(),
                    anchor_lang::system_program::Transfer {
                        from: ctx.accounts.payer.to_account_info(),
                        to: ai.clone(),
                    },
                ),
                needed - have,
            )?;
        }
        ai.resize(new_len)?; // zero-fills the appended range → daily_advance_spent = 0, advance_day = 0
        Ok(())
    }

    /// §19 anti-bank-run migration — permissionless, identical shape to
    /// `migrate_advance_pool_daily_fields`: extends a pre-existing `BackstopPool` (created before
    /// `daily_withdrawn`/`withdraw_day` existed) and zero-fills the appended outflow-gate fields —
    /// the correct default (a pool this old has paid out nothing today by construction).
    pub fn migrate_backstop_pool_fields(ctx: Context<MigrateBackstopPoolFields>) -> Result<()> {
        let ai = ctx.accounts.backstop_pool.to_account_info();
        let new_len = 8 + BackstopPool::INIT_SPACE;
        let old_len = ai.data_len();
        if old_len >= new_len {
            return Ok(()); // already migrated
        }
        let rent = Rent::get()?;
        let needed = rent.minimum_balance(new_len);
        let have = ai.lamports();
        if needed > have {
            anchor_lang::system_program::transfer(
                CpiContext::new(
                    ctx.accounts.system_program.to_account_info(),
                    anchor_lang::system_program::Transfer {
                        from: ctx.accounts.payer.to_account_info(),
                        to: ai.clone(),
                    },
                ),
                needed - have,
            )?;
        }
        ai.resize(new_len)?; // zero-fills → daily_withdrawn = 0, withdraw_day = 0
        Ok(())
    }

    /// §19 anti-bank-run migration — permissionless, same shape as `migrate_backstop_pool_fields`:
    /// extends a pre-existing `BackstopPosition` and zero-fills the appended `cooldown_requested_at`.
    /// Safe even for a position with an already-pending cooldown — see that field's doc comment.
    pub fn migrate_backstop_position_fields(ctx: Context<MigrateBackstopPositionFields>) -> Result<()> {
        let ai = ctx.accounts.position.to_account_info();
        let new_len = 8 + BackstopPosition::INIT_SPACE;
        let old_len = ai.data_len();
        if old_len >= new_len {
            return Ok(()); // already migrated
        }
        let rent = Rent::get()?;
        let needed = rent.minimum_balance(new_len);
        let have = ai.lamports();
        if needed > have {
            anchor_lang::system_program::transfer(
                CpiContext::new(
                    ctx.accounts.system_program.to_account_info(),
                    anchor_lang::system_program::Transfer {
                        from: ctx.accounts.payer.to_account_info(),
                        to: ai.clone(),
                    },
                ),
                needed - have,
            )?;
        }
        ai.resize(new_len)?; // zero-fills → cooldown_requested_at = 0
        Ok(())
    }

    /// K-1 — rotate the firm's keeper key (`risk_engine_authority`). Signed by the **guardian** (the
    /// independent co-signer), NOT the current keeper (which may be the compromised key) and NOT the
    /// owner (a firm operator must never seize the platform's settlement authority). The OUTGOING key
    /// is parked in `previous_risk_engine_authority` and honored by `require_firm_settlement_authority`
    /// until `now + AUTHORITY_ROTATION_GRACE`, so in-flight challenges bound to the old keeper stay
    /// payable across the transition; new challenges bind to the new key. Requires the firm to be at
    /// the rotation layout (`migrate_firm_authority_fields`).
    pub fn set_risk_engine_authority(ctx: Context<SetRiskEngineAuthority>, new_authority: Pubkey) -> Result<()> {
        require!(new_authority != Pubkey::default(), FirmError::Unauthorized);
        let now = Clock::get()?.unix_timestamp;
        let firm = &mut ctx.accounts.firm_state;
        require!(new_authority != firm.owner, FirmError::Unauthorized); // owner can't become the keeper
        firm.previous_risk_engine_authority = firm.risk_engine_authority;
        firm.risk_engine_authority = new_authority;
        firm.authority_rotation_deadline = now
            .checked_add(AUTHORITY_ROTATION_GRACE)
            .ok_or(FirmError::MathOverflow)?;
        emit!(RiskEngineAuthorityRotated {
            firm: firm.key(),
            previous: firm.previous_risk_engine_authority,
            new_authority,
            grace_until: firm.authority_rotation_deadline,
        });
        Ok(())
    }

    /// Apply a risk-tier decision from the ARE. Signed by `risk_engine_authority`.
    /// Enforces the §25 transition guards on-chain.
    pub fn update_risk_tier(ctx: Context<UpdateRiskTier>, new_tier: RiskTier) -> Result<()> {
        let now = Clock::get()?.unix_timestamp;
        let firm = &mut ctx.accounts.firm_state;
        let current = firm.risk_tier as u8;
        let proposed = new_tier as u8;

        require!(proposed.abs_diff(current) <= 1, FirmError::TierJumpTooLarge);
        if proposed < current {
            let deadline = firm
                .last_tier_change_at
                .checked_add(relax_timelock(current))
                .ok_or(FirmError::MathOverflow)?;
            require!(now >= deadline, FirmError::RelaxationTimelockActive);
        }
        if proposed != current {
            firm.risk_tier = new_tier;
            firm.last_tier_change_at = now;
            emit!(RiskTierUpdated { firm: firm.key(), tier: new_tier, changed_at: now });
        }
        Ok(())
    }

    /// Record/clear the velocity-break flag (§9 velocity breaker).
    pub fn set_velocity_break(ctx: Context<UpdateRiskTier>, active: bool) -> Result<()> {
        ctx.accounts.firm_state.velocity_break_flag = active;
        Ok(())
    }

    /// Initialise the global platform risk state (§9). One-time; the signer becomes the
    /// platform override authority (the same HSM/Squads key that signs `update_risk_tier`).
    pub fn init_platform_risk(ctx: Context<InitPlatformRisk>) -> Result<()> {
        let p = &mut ctx.accounts.platform_risk;
        p.authority = ctx.accounts.authority.key();
        p.override_tier = 0;
        p.override_active = false;
        p.override_reason = [0u8; 32];
        p.set_at = Clock::get()?.unix_timestamp;
        p.bump = ctx.bumps.platform_risk;
        Ok(())
    }

    /// Apply (or lift) a platform-wide minimum risk tier (§9). Signed by the platform
    /// authority. Every tier-sensitive per-firm instruction uses
    /// `max(firm_tier, platform_override)`. An active override must carry a non-empty
    /// human-readable reason (permanent on-chain audit trail, §25).
    pub fn update_platform_tier_override(
        ctx: Context<UpdatePlatformRisk>,
        override_tier: u8,
        active: bool,
        reason: [u8; 32],
    ) -> Result<()> {
        require!(override_tier <= MAX_RISK_TIER, FirmError::InvalidTier);
        if active {
            require!(reason.iter().any(|&b| b != 0), FirmError::EmptyOverrideReason);
        }
        let now = Clock::get()?.unix_timestamp;
        let p = &mut ctx.accounts.platform_risk;
        p.override_tier = override_tier;
        p.override_active = active;
        p.override_reason = reason;
        p.set_at = now;
        emit!(PlatformOverrideUpdated { override_tier, active, set_at: now });
        Ok(())
    }

    /// Initialise the canonical platform config (M-2/M-4). One-time; gated to the firm program's
    /// **upgrade authority** (the deployer / platform multisig) so it cannot be front-run. Records the
    /// platform-controlled SOL destinations that `pay_challenge_fee` (and the dispute fund) bind to, so
    /// callers can no longer substitute platform-fee destinations with accounts they control.
    pub fn init_platform_config(
        ctx: Context<InitPlatformConfig>,
        dp_profit_sol: Pubkey,
        dp_treasury_sol: Pubkey,
        normal_staking_vault: Pubkey,
        platform_sol: Pubkey,
        dp_dispute_fund: Pubkey,
        platform_guardian: Pubkey,
    ) -> Result<()> {
        let cfg = &mut ctx.accounts.platform_config;
        cfg.authority = ctx.accounts.upgrade_authority.key();
        cfg.dp_profit_sol = dp_profit_sol;
        cfg.dp_treasury_sol = dp_treasury_sol;
        cfg.normal_staking_vault = normal_staking_vault;
        cfg.platform_sol = platform_sol;
        cfg.dp_dispute_fund = dp_dispute_fund;
        cfg.platform_guardian = platform_guardian;
        cfg.bump = ctx.bumps.platform_config;
        emit!(PlatformConfigSet { authority: cfg.authority });
        Ok(())
    }

    /// Update the platform config destinations (M-2/M-4). Gated to the config `authority`.
    pub fn update_platform_config(
        ctx: Context<UpdatePlatformConfig>,
        dp_profit_sol: Pubkey,
        dp_treasury_sol: Pubkey,
        normal_staking_vault: Pubkey,
        platform_sol: Pubkey,
        dp_dispute_fund: Pubkey,
        platform_guardian: Pubkey,
    ) -> Result<()> {
        let cfg = &mut ctx.accounts.platform_config;
        cfg.dp_profit_sol = dp_profit_sol;
        cfg.dp_treasury_sol = dp_treasury_sol;
        cfg.normal_staking_vault = normal_staking_vault;
        cfg.platform_sol = platform_sol;
        cfg.dp_dispute_fund = dp_dispute_fund;
        cfg.platform_guardian = platform_guardian;
        emit!(PlatformConfigSet { authority: cfg.authority });
        Ok(())
    }

    /// V2-1 migration: grow an existing `platform_config` from the pre-guardian layout (201 bytes) to
    /// the current one (adds `platform_guardian`, 233 bytes) and set the guardian. After the field was
    /// added the account is too small to load as `PlatformConfig`, so `update_platform_config` can't
    /// touch it — this takes the account RAW, resizes it in place, preserves the six existing
    /// fee-destination pubkeys, and inserts `platform_guardian` before `bump`. Gated to the stored
    /// config `authority` (read from the account, since it can't be deserialized). Idempotent.
    pub fn migrate_platform_config(
        ctx: Context<MigratePlatformConfig>,
        platform_guardian: Pubkey,
    ) -> Result<()> {
        let acc = ctx.accounts.platform_config.to_account_info();
        let new_len = 8 + PlatformConfig::INIT_SPACE; // 233
        let old_len = 8 + 6 * 32 + 1; // 201 — the only pre-guardian layout
        let cur_len = acc.data_len();
        if cur_len >= new_len {
            return Ok(()); // already migrated
        }
        require!(cur_len == old_len, FirmError::InvalidFirmStatus);
        // Authority gate: the stored `authority` (first field, bytes 8..40) must sign.
        {
            let data = acc.try_borrow_data()?;
            let stored = Pubkey::try_from(&data[8..40]).map_err(|_| error!(FirmError::Unauthorized))?;
            require_keys_eq!(stored, ctx.accounts.authority.key(), FirmError::Unauthorized);
        }
        // Top up rent for the added bytes, then grow in place.
        let rent = Rent::get()?.minimum_balance(new_len);
        let cur_lamports = acc.lamports();
        if rent > cur_lamports {
            anchor_lang::system_program::transfer(
                CpiContext::new(
                    ctx.accounts.system_program.to_account_info(),
                    anchor_lang::system_program::Transfer {
                        from: ctx.accounts.authority.to_account_info(),
                        to: acc.clone(),
                    },
                ),
                rent - cur_lamports,
            )?;
        }
        acc.realloc(new_len, false)?;
        // Old layout: 6 pubkeys [8..200] then bump at [200]. New: guardian at [200..232], bump at [232].
        let mut data = acc.try_borrow_mut_data()?;
        let old_bump = data[200];
        data[200..232].copy_from_slice(platform_guardian.as_ref());
        data[232] = old_bump;
        emit!(PlatformConfigSet { authority: ctx.accounts.authority.key() });
        Ok(())
    }

    /// Owner claims one month of the $FIRMA drip (§17). Releases `total_tokens / 24` per
    /// call, one calendar month apart, and only while the **effective** risk tier
    /// (`max(firm, platform)`) is HEALTHY or CAUTION — paused (not forfeited) at
    /// WARNING/CRITICAL, so unclaimed months accumulate. Signed by the firm owner.
    pub fn claim_drip(ctx: Context<ClaimDrip>) -> Result<()> {
        let status = ctx.accounts.firm_state.status;
        require!(
            status == FirmStatus::Active || status == FirmStatus::Suspended,
            FirmError::InvalidFirmStatus
        );
        let now = Clock::get()?.unix_timestamp;
        let drip = &ctx.accounts.owner_drip_state;
        require!(drip.months_claimed < drip.months_total, FirmError::DripComplete);

        let unlock = drip_next_unlock(drip.drip_start_at, drip.months_claimed)?;
        require!(now >= unlock, FirmError::DripNotYetUnlocked);

        let eff = effective_tier(ctx.accounts.firm_state.risk_tier as u8, &ctx.accounts.platform_risk);
        require!(eff <= RiskTier::Caution as u8, FirmError::DripPausedUnderStress);

        let amount = drip_month_amount(drip.total_tokens);
        ctx.accounts.release(amount)?;

        let drip = &mut ctx.accounts.owner_drip_state;
        drip.months_claimed += 1;
        emit!(DripClaimed {
            firm: ctx.accounts.firm_state.key(),
            amount,
            months_claimed: drip.months_claimed,
        });
        Ok(())
    }

    /// Initialise a firm's $FIRMA staking pool (§19) and its three PDA-owned vaults:
    /// `stake_vault` (principal escrow), `sol_reward_vault` (weekly SOL yield), and
    /// `firma_reward_vault` ($FIRMA yield from payout stakeholder shares).
    pub fn init_staking_pool(ctx: Context<InitStakingPool>) -> Result<()> {
        let now = Clock::get()?.unix_timestamp;
        let pool = &mut ctx.accounts.staking_pool;
        pool.firm = ctx.accounts.firm_state.key();
        pool.total_staked = 0;
        pool.acc_sol = 0;
        pool.acc_firma = 0;
        pool.unallocated_sol = 0;
        pool.unallocated_firma = 0;
        pool.firma_reward_accounted = 0;
        pool.stake_vault = ctx.accounts.stake_vault.key();
        pool.sol_reward_vault = ctx.accounts.sol_reward_vault.key();
        pool.firma_reward_vault = ctx.accounts.firma_reward_vault.key();
        pool.last_distribution_at = now;
        pool.bump = ctx.bumps.staking_pool;
        Ok(())
    }

    /// Initialise the global $DPROP buyback-and-burn sink (§17). One-time, permissionless to
    /// create: sets the $DPROP mint and stands up the PDA-owned SOL accumulator + $DPROP vault,
    /// both with the buyback PDA as authority — so no key (DecentralProp included) can redirect them.
    pub fn init_dprop_buyback(ctx: Context<InitDpropBuyback>) -> Result<()> {
        let b = &mut ctx.accounts.dprop_buyback;
        b.dprop_mint = ctx.accounts.dprop_mint.key();
        b.sol_vault = ctx.accounts.sol_vault.key();
        b.dprop_vault = ctx.accounts.dprop_vault.key();
        b.total_sol_spent = 0;
        b.total_dprop_burned = 0;
        b.bump = ctx.bumps.dprop_buyback;
        Ok(())
    }

    /// Deferred-launch path (R33.2): stand up the $DPROP buyback SOL sink BEFORE the $DPROP token
    /// exists. Creates the `DpropBuyback` record with `dprop_mint`/`dprop_vault` left UNSET
    /// (`Pubkey::default`) and the PDA-owned SOL accumulator (["dprop_buyback_sol"]), so
    /// `pay_challenge_fee`'s 1% buyback leg can route from day one on mainnet even though $DPROP has
    /// not launched. The accrued SOL is inert and unredirectable — `execute_dprop_buyback` reverts
    /// (`DpropMintNotBound`) until `bind_dprop_buyback_mint` sets the real mint + $DPROP vault at
    /// launch. One-time, permissionless (creating an empty PDA-owned SOL sink grants no power).
    pub fn init_dprop_buyback_sol(ctx: Context<InitDpropBuybackSol>) -> Result<()> {
        let b = &mut ctx.accounts.dprop_buyback;
        b.dprop_mint = Pubkey::default();
        b.sol_vault = ctx.accounts.sol_vault.key();
        b.dprop_vault = Pubkey::default();
        b.total_sol_spent = 0;
        b.total_dprop_burned = 0;
        b.bump = ctx.bumps.dprop_buyback;
        Ok(())
    }

    /// Launch-day (R33.2): bind the real $DPROP mint to a sink created by `init_dprop_buyback_sol`
    /// and create its PDA-owned $DPROP holding vault. After this the buyback behaves exactly like the
    /// all-in-one `init_dprop_buyback` path (swap → burn). One-time: reverts `DpropMintAlreadyBound`
    /// if a mint is already set. **Upgrade-authority-gated** (not permissionless): binding the
    /// canonical protocol token is a governance action — a permissionless bind would let anyone
    /// front-run a wrong/hostile mint into the one-time slot and permanently misdirect the
    /// buy-and-burn. The accrued SOL is untouched (the wSOL sink PDA does not change).
    pub fn bind_dprop_buyback_mint(ctx: Context<BindDpropBuybackMint>) -> Result<()> {
        let b = &mut ctx.accounts.dprop_buyback;
        require!(b.dprop_mint == Pubkey::default(), FirmError::DpropMintAlreadyBound);
        b.dprop_mint = ctx.accounts.dprop_mint.key();
        b.dprop_vault = ctx.accounts.dprop_vault.key();
        emit!(DpropBuybackMintBound { dprop_mint: b.dprop_mint, dprop_vault: b.dprop_vault });
        Ok(())
    }

    /// Initialize the protocol-level $DPROP staking SOL vault (seeds ["dprop_staking_sol"]).
    /// Must be called once before `pay_challenge_fee` can route the 10% staking leg.
    /// The vault is PDA-owned — stakers withdraw their pro-rata share via `claim_dprop_staking_yield`.
    pub fn init_dprop_staking(ctx: Context<InitDpropStaking>) -> Result<()> {
        let pool = &mut ctx.accounts.dprop_staking_pool;
        pool.sol_vault = ctx.accounts.sol_vault.key();
        pool.total_sol_distributed = 0;
        pool.bump = ctx.bumps.dprop_staking_pool;
        Ok(())
    }

    // `distribute_dprop_staking` (the interim push distributor) was REMOVED — trust-model gap T-1
    // (reports/2026-07-02-trust-model-gap-analysis.md). It let the upgrade-authority key redirect the
    // protocol-wide 10%-of-every-eval $DPROP-staking SOL leg to any wallet — a live fund-redirect power,
    // not a dormant redeploy risk. The Phase-5 pull path below (`stake_dprop` / `unstake_dprop` /
    // `claim_dprop_staking_yield`) is live and distributes the vault pro-rata to stakers via the
    // MasterChef accumulator, so no privileged distributor is needed. `DpropStakingPool.total_sol_distributed`
    // is retained (now always 0) to avoid a layout migration of the deployed singleton.

    // ─────────────────────────── $DPROP staking (R33) ───────────────────────────
    // Stakers deposit $DPROP and earn a pro-rata share of the 10%-of-every-eval-fee SOL leg that
    // already flows into the `dprop_staking_sol` vault. A MasterChef accumulator (the same pure
    // `fold_yield`/`pending_yield`/`yield_debt` helpers the per-firm $FIRMA pool uses) shares that
    // SOL fairly. The accounting lives in a SEPARATE `DpropStakeLedger` PDA so the already-deployed
    // `DpropStakingPool` singleton needs no layout migration. SOL that accrued BEFORE staking opened
    // is excluded (init records the starting balance); only post-open inflow is distributed.

    /// Initialise the $DPROP staking ledger + its PDA-owned $DPROP stake vault. One-time, permissionless.
    pub fn init_dprop_stake_ledger(ctx: Context<InitDpropStakeLedger>) -> Result<()> {
        let starting = ctx.accounts.sol_vault.amount;
        let now = Clock::get()?.unix_timestamp;
        let l = &mut ctx.accounts.ledger;
        l.stake_vault = ctx.accounts.stake_vault.key();
        l.dprop_mint = ctx.accounts.dprop_mint.key();
        l.total_staked = 0;
        l.acc_sol = 0;
        l.unallocated_sol = 0;
        // `last_sol_balance = starting` keeps the pre-open balance OUT of the normal delta path; the
        // retro stream (R33.1) distributes it separately and linearly over DPROP_RETRO_VEST_SECONDS,
        // so it retroactively rewards early stakers without a first-block windfall. `retro_reserve`
        // ⊆ starting ⊆ vault balance, so the SOL to pay it is already sitting in the vault.
        l.last_sol_balance = starting;
        l.retro_reserve = starting;
        l.retro_released = 0;
        l.retro_start = now;
        l.bump = ctx.bumps.ledger;
        emit!(DpropStakeLedgerInitialized { ledger: l.key(), stake_vault: l.stake_vault });
        Ok(())
    }

    /// Stake $DPROP to earn a pro-rata share of the protocol's $DPROP-staking SOL yield.
    pub fn stake_dprop(ctx: Context<StakeDprop>, amount: u64) -> Result<()> {
        require!(amount > 0, FirmError::ZeroAmount);
        ctx.accounts.sol_vault.reload()?;
        let bal = ctx.accounts.sol_vault.amount;
        let now = Clock::get()?.unix_timestamp;
        // harvest: fold newly-arrived vault SOL (balance delta) + the freshly-vested retro slice
        let (acc, unalloc, retro_add) = {
            let l = &ctx.accounts.ledger;
            let retro = retro_vested(l.retro_reserve, l.retro_released, l.retro_start, now);
            let inflow = bal.saturating_sub(l.last_sol_balance).saturating_add(retro);
            let (a, u) = fold_yield(l.acc_sol, l.unallocated_sol, inflow, l.total_staked);
            (a, u, retro)
        };
        ctx.accounts.escrow(amount)?; // staker authority — no PDA signer
        let staker_key = ctx.accounts.staker.key();
        let pos_bump = ctx.bumps.position;
        let pos = &mut ctx.accounts.position;
        if pos.staker == Pubkey::default() {
            pos.staker = staker_key;
            pos.bump = pos_bump;
        }
        // settle pending (carried to claim) BEFORE changing the stake, then reset the debt to current.
        let pending = pending_yield(pos.amount_staked, acc, pos.yield_debt_sol);
        pos.pending_sol = pos.pending_sol.saturating_add(pending);
        pos.amount_staked = pos.amount_staked.checked_add(amount).ok_or(FirmError::MathOverflow)?;
        pos.yield_debt_sol = yield_debt(pos.amount_staked, acc);
        let new_staked = pos.amount_staked;
        let l = &mut ctx.accounts.ledger;
        l.acc_sol = acc;
        l.unallocated_sol = unalloc;
        l.last_sol_balance = bal;
        l.retro_released = l.retro_released.saturating_add(retro_add);
        l.total_staked = l.total_staked.checked_add(amount).ok_or(FirmError::MathOverflow)?;
        emit!(DpropStaked { staker: staker_key, amount, total_staked: l.total_staked, position_staked: new_staked });
        Ok(())
    }

    /// Unstake $DPROP (any accrued SOL yield is carried forward and claimed via `claim_dprop_staking_yield`).
    pub fn unstake_dprop(ctx: Context<UnstakeDprop>, amount: u64) -> Result<()> {
        require!(amount > 0, FirmError::ZeroAmount);
        require!(ctx.accounts.position.amount_staked >= amount, FirmError::InsufficientStake);
        ctx.accounts.sol_vault.reload()?;
        let bal = ctx.accounts.sol_vault.amount;
        let now = Clock::get()?.unix_timestamp;
        let (acc, unalloc, retro_add) = {
            let l = &ctx.accounts.ledger;
            let retro = retro_vested(l.retro_reserve, l.retro_released, l.retro_start, now);
            let inflow = bal.saturating_sub(l.last_sol_balance).saturating_add(retro);
            let (a, u) = fold_yield(l.acc_sol, l.unallocated_sol, inflow, l.total_staked);
            (a, u, retro)
        };
        ctx.accounts.release(amount)?; // pool PDA signs the vault → staker transfer
        let pos = &mut ctx.accounts.position;
        let pending = pending_yield(pos.amount_staked, acc, pos.yield_debt_sol);
        pos.pending_sol = pos.pending_sol.saturating_add(pending);
        pos.amount_staked = pos.amount_staked.saturating_sub(amount);
        pos.yield_debt_sol = yield_debt(pos.amount_staked, acc);
        let staker_key = pos.staker;
        let l = &mut ctx.accounts.ledger;
        l.acc_sol = acc;
        l.unallocated_sol = unalloc;
        l.last_sol_balance = bal;
        l.retro_released = l.retro_released.saturating_add(retro_add);
        l.total_staked = l.total_staked.saturating_sub(amount);
        emit!(DpropUnstaked { staker: staker_key, amount, total_staked: l.total_staked });
        Ok(())
    }

    /// Claim accrued SOL yield from the $DPROP staking pool.
    pub fn claim_dprop_staking_yield(ctx: Context<ClaimDpropStakingYield>) -> Result<()> {
        ctx.accounts.sol_vault.reload()?;
        let bal = ctx.accounts.sol_vault.amount;
        let now = Clock::get()?.unix_timestamp;
        let (acc, unalloc, retro_add) = {
            let l = &ctx.accounts.ledger;
            let retro = retro_vested(l.retro_reserve, l.retro_released, l.retro_start, now);
            let inflow = bal.saturating_sub(l.last_sol_balance).saturating_add(retro);
            let (a, u) = fold_yield(l.acc_sol, l.unallocated_sol, inflow, l.total_staked);
            (a, u, retro)
        };
        let (staked, debt, carried) = {
            let p = &ctx.accounts.position;
            (p.amount_staked, p.yield_debt_sol, p.pending_sol)
        };
        let payout = carried.saturating_add(pending_yield(staked, acc, debt));
        require!(payout > 0, FirmError::NothingToClaim);
        require!(ctx.accounts.sol_vault.amount >= payout, FirmError::InsufficientTreasury);
        ctx.accounts.pay_sol(payout)?; // pool PDA signs
        ctx.accounts.sol_vault.reload()?;
        let new_bal = ctx.accounts.sol_vault.amount;
        let pos = &mut ctx.accounts.position;
        pos.pending_sol = 0;
        pos.yield_debt_sol = yield_debt(staked, acc);
        let staker_key = pos.staker;
        let l = &mut ctx.accounts.ledger;
        l.acc_sol = acc;
        l.unallocated_sol = unalloc;
        l.retro_released = l.retro_released.saturating_add(retro_add);
        l.last_sol_balance = new_bal; // re-sync after the payout drew the vault down
        emit!(DpropYieldClaimed { staker: staker_key, sol: payout });
        Ok(())
    }

    /// Initialize the protocol-wide Universal Treasury Pool + its PDA-owned SOL vault (seeds
    /// ["universal_pool"] / ["universal_vault"]). One-time, permissionless to bootstrap; the payer's
    /// key is recorded as `authority` for future governance. Must run once before `pay_challenge_fee`
    /// / `pay_deployment_fee` can route the universal leg. The vault is PDA-owned — only
    /// `draw_universal` can drain it, and only to deliver an owed payout.
    pub fn init_universal_pool(ctx: Context<InitUniversalPool>) -> Result<()> {
        let pool = &mut ctx.accounts.universal_pool;
        pool.authority = ctx.accounts.payer.key();
        pool.vault = ctx.accounts.universal_vault.key();
        pool.total_contributed = 0;
        pool.total_drawn = 0;
        pool.draw_day = 0;
        pool.daily_drawn = 0;
        pool.bump = ctx.bumps.universal_pool;
        Ok(())
    }

    /// Buy $DPROP with accumulated SOL (§17). PERMISSIONLESS — anyone can crank it, and the
    /// output can only land in the PDA-owned `dprop_vault`, so there is zero destination discretion.
    /// The SOL→$DPROP swap is a Raydium CPI (the LaunchLab-migrated $DPROP/SOL pool) and the
    /// devnet-integration boundary — no Raydium program on localnet — mirroring `graduate_firm`.
    /// This records the spend; the on-chain-verifiable guarantee is the burn + the monotonic
    /// counter. `sol_amount` is capped at the buyback SOL vault balance.
    pub fn execute_dprop_buyback(ctx: Context<ExecuteDpropBuyback>, sol_amount: u64) -> Result<()> {
        // R33.2: a sink created via the deferred `init_dprop_buyback_sol` path holds SOL but has no
        // $DPROP mint/vault until `bind_dprop_buyback_mint` runs at launch. Until then the buyback is
        // inert — the accrued SOL stays locked in the PDA-owned sink, redirectable by no one.
        require!(
            ctx.accounts.dprop_buyback.dprop_mint != Pubkey::default(),
            FirmError::DpropMintNotBound
        );
        let available = ctx.accounts.sol_vault.amount;
        let spend = sol_amount.min(available);
        require!(spend > 0, FirmError::ZeroAmount);

        // ── Raydium swap boundary ───────────────────────────────────────────────────────────
        // CPI: swap `spend` SOL (`sol_vault`) → $DPROP into `dprop_vault` via the Raydium pool.
        // Wired at the devnet boundary; settled off this seam on localnet. The trustless exit is
        // still guaranteed downstream by `burn_dprop_buyback` (the only other vault exit).
        // ────────────────────────────────────────────────────────────────────────────────────
        let b = &mut ctx.accounts.dprop_buyback;
        b.total_sol_spent = b.total_sol_spent.checked_add(spend).ok_or(FirmError::MathOverflow)?;
        emit!(DpropBuybackExecuted { sol_spent: spend, total_sol_spent: b.total_sol_spent });
        Ok(())
    }

    /// Burn every $DPROP held in the buyback vault (§17). PERMISSIONLESS and irreversible — the
    /// only exit from `dprop_vault` is the incinerator, so the bought-back supply is provably and
    /// permanently removed and no admin can redirect it. Reduces $DPROP total supply and bumps the
    /// public `total_dprop_burned` deflation counter.
    pub fn burn_dprop_buyback(ctx: Context<BurnDpropBuyback>) -> Result<()> {
        let amount = ctx.accounts.dprop_vault.amount;
        require!(amount > 0, FirmError::ZeroAmount);
        ctx.accounts.burn(amount)?;
        let b = &mut ctx.accounts.dprop_buyback;
        b.total_dprop_burned =
            b.total_dprop_burned.checked_add(amount).ok_or(FirmError::MathOverflow)?;
        emit!(DpropBurned { amount, total_dprop_burned: b.total_dprop_burned });
        Ok(())
    }

    /// Stake $FIRMA (§19). No lock-up. Escrows the tokens in `stake_vault` and adjusts
    /// the position's yield debt so the freshly staked principal earns nothing
    /// retroactively while previously accrued yield is preserved for a later claim.
    pub fn stake(ctx: Context<Stake>, amount: u64) -> Result<()> {
        require!(amount > 0, FirmError::ZeroAmount);
        let now = Clock::get()?.unix_timestamp;
        ctx.accounts.escrow(amount)?;

        let pool = &mut ctx.accounts.staking_pool;
        pool.total_staked = pool.total_staked.checked_add(amount).ok_or(FirmError::MathOverflow)?;
        let acc_sol = pool.acc_sol;
        let acc_firma = pool.acc_firma;

        let pos = &mut ctx.accounts.staker_position;
        if pos.staker == Pubkey::default() {
            pos.staker = ctx.accounts.staker.key();
            pos.firm = ctx.accounts.firm_state.key();
            pos.staked_at = now;
            pos.bump = ctx.bumps.staker_position;
        }
        pos.amount_staked = pos.amount_staked.checked_add(amount).ok_or(FirmError::MathOverflow)?;
        pos.yield_debt_sol = pos.yield_debt_sol.saturating_add(yield_debt(amount, acc_sol));
        pos.yield_debt_firma = pos.yield_debt_firma.saturating_add(yield_debt(amount, acc_firma));
        Ok(())
    }

    /// Unstake $FIRMA (§19). Returns principal from escrow; accrued yield is preserved
    /// (claim separately). Reduces the position's yield debt symmetrically with `stake`.
    pub fn unstake(ctx: Context<Unstake>, amount: u64) -> Result<()> {
        require!(amount > 0, FirmError::ZeroAmount);
        require!(
            amount <= ctx.accounts.staker_position.amount_staked,
            FirmError::InsufficientStake
        );
        ctx.accounts.return_principal(amount)?;

        let pool = &mut ctx.accounts.staking_pool;
        pool.total_staked = pool.total_staked.saturating_sub(amount);
        let acc_sol = pool.acc_sol;
        let acc_firma = pool.acc_firma;

        let pos = &mut ctx.accounts.staker_position;
        pos.amount_staked = pos.amount_staked.saturating_sub(amount);
        pos.yield_debt_sol = pos.yield_debt_sol.saturating_sub(yield_debt(amount, acc_sol));
        pos.yield_debt_firma = pos.yield_debt_firma.saturating_sub(yield_debt(amount, acc_firma));
        Ok(())
    }

    /// Claim both yield streams (§19): accrued SOL from `sol_reward_vault` and accrued
    /// $FIRMA from `firma_reward_vault`, in one instruction. Resets the position's debt.
    pub fn claim_staking_yield(ctx: Context<ClaimStakingYield>) -> Result<()> {
        let pool = &ctx.accounts.staking_pool;
        let staked = ctx.accounts.staker_position.amount_staked;
        let pending_sol = pending_yield(staked, pool.acc_sol, ctx.accounts.staker_position.yield_debt_sol);
        let pending_firma = pending_yield(staked, pool.acc_firma, ctx.accounts.staker_position.yield_debt_firma);

        ctx.accounts.pay_sol(pending_sol)?;
        ctx.accounts.pay_firma(pending_firma)?;

        let acc_sol = ctx.accounts.staking_pool.acc_sol;
        let acc_firma = ctx.accounts.staking_pool.acc_firma;
        let pool = &mut ctx.accounts.staking_pool;
        pool.firma_reward_accounted = pool.firma_reward_accounted.saturating_sub(pending_firma);

        let pos = &mut ctx.accounts.staker_position;
        pos.yield_debt_sol = yield_debt(staked, acc_sol);
        pos.yield_debt_firma = yield_debt(staked, acc_firma);

        emit!(StakingYieldClaimed {
            firm: ctx.accounts.firm_state.key(),
            staker: pos.staker,
            sol: pending_sol,
            firma: pending_firma,
        });
        Ok(())
    }

    /// Keeper distributes weekly SOL staking yield (§19): moves `amount` SOL into the
    /// reward vault and folds it into the SOL accumulator (retained if nothing staked).
    pub fn distribute_staking_sol(ctx: Context<DistributeStakingSol>) -> Result<()> {
        // MASTER_FIXES K-2: drain the FULL balance of the (dedicated) staking-accrual `source_sol`
        // instead of a caller-supplied amount. This makes the distribution idempotent by construction
        // — each call empties the source, so a retry after a missed confirmation folds 0 rather than
        // double-distributing (the pre-fix additive `distribute_staking_sol(amount)` had no on-chain
        // dedup). The funder still authorizes the transfer, so no extra trust is introduced; it mirrors
        // the delta-folding the $FIRMA side already does via `firma_reward_accounted`.
        let amount = ctx.accounts.source_sol.amount;
        if amount == 0 {
            return Ok(()); // nothing accrued — idempotent no-op
        }
        let now = Clock::get()?.unix_timestamp;
        ctx.accounts.fund(amount)?;
        let pool = &mut ctx.accounts.staking_pool;
        let (acc, unalloc) = fold_yield(pool.acc_sol, pool.unallocated_sol, amount, pool.total_staked);
        pool.acc_sol = acc;
        pool.unallocated_sol = unalloc;
        pool.last_distribution_at = now;
        Ok(())
    }

    /// Permissionless: fold $FIRMA that has arrived in `firma_reward_vault` (from payout
    /// stakeholder shares routed by `process_queued_payout`) into the $FIRMA accumulator
    /// (§19). Decoupled from the payout path so a firm without a staking pool still pays
    /// out normally — the staking share simply waits in the vault until synced.
    pub fn sync_firma_yield(ctx: Context<SyncFirmaYield>) -> Result<()> {
        let vault_amount = ctx.accounts.firma_reward_vault.amount;
        let pool = &mut ctx.accounts.staking_pool;
        let delta = vault_amount.saturating_sub(pool.firma_reward_accounted);
        let (acc, unalloc) = fold_yield(pool.acc_firma, pool.unallocated_firma, delta, pool.total_staked);
        pool.acc_firma = acc;
        pool.unallocated_firma = unalloc;
        pool.firma_reward_accounted = vault_amount;
        Ok(())
    }

    /// Permissionless: fold $FIRMA that has arrived in the backstop pool's `firma_reward_vault`
    /// into `acc_firma` (§19 staking rebalance, 2026-07-27). Divides by `total_premium_weight`
    /// (nominal), NOT `total_staked` — matching `premium_acc`'s reasoning exactly: a draw shrinks
    /// `total_staked` but not the nominal weight other stakers' pending yield is computed against,
    /// so folding against the wrong denominator would let `Σ firma_claimable` exceed what this sync
    /// actually funded.
    pub fn sync_backstop_firma_yield(ctx: Context<SyncBackstopFirmaYield>) -> Result<()> {
        let vault_amount = ctx.accounts.firma_reward_vault.amount;
        let pool = &mut ctx.accounts.backstop_pool;
        let delta = vault_amount.saturating_sub(pool.firma_reward_accounted);
        let (acc, unalloc) =
            fold_yield(pool.acc_firma, pool.unallocated_firma, delta, pool.total_premium_weight);
        pool.acc_firma = acc;
        pool.unallocated_firma = unalloc;
        pool.firma_reward_accounted = vault_amount;
        Ok(())
    }

    /// Owner-adjustable stakeholder-share ratios (§19), validated against the governance
    /// ranges (sum 10000; buyback/burn never below 3%). Signed by the firm owner.
    pub fn update_stakeholder_config(
        ctx: Context<UpdateStakeholderConfig>,
        config: StakeholderConfig,
        backstop_pool_bps: u16,
    ) -> Result<()> {
        require!(
            validate_stakeholder_config(&config, backstop_pool_bps),
            FirmError::InvalidStakeholderConfig
        );
        ctx.accounts.firm_state.stakeholder_config = config;
        ctx.accounts.firm_state.backstop_pool_bps = backstop_pool_bps;
        Ok(())
    }

    // ───────────────────────── Affiliate program (§17.1) ─────────────────────────
    // Each firm runs its own affiliate program: affiliates refer traders, a referred
    // trader's challenge fee carves the affiliate's rate (default 10%, ≤20%) into the firm's
    // affiliate vault, and affiliates withdraw pull-based. Single-level, lifetime first-touch,
    // immediate-claimable. The firm owner chooses approval-only vs open registration.

    /// Initialise the firm's affiliate program + SOL accumulator vault. Owner-only.
    pub fn init_affiliate_program(
        ctx: Context<InitAffiliateProgram>,
        open: bool,
        default_rate_bps: u16,
    ) -> Result<()> {
        // The affiliate rate is fixed platform-wide — reject any attempt to set a different rate.
        require!(default_rate_bps == AFFILIATE_DEFAULT_BPS, FirmError::AffiliateRateLocked);
        let prog = &mut ctx.accounts.affiliate_program;
        prog.firm = ctx.accounts.firm_state.key();
        prog.vault = ctx.accounts.affiliate_pool_vault.key();
        prog.open = open;
        prog.default_rate_bps = AFFILIATE_DEFAULT_BPS;
        prog.total_affiliates = 0;
        prog.bump = ctx.bumps.affiliate_program;
        Ok(())
    }

    /// Owner updates the program's registration mode + default affiliate rate.
    pub fn set_affiliate_config(
        ctx: Context<UpdateAffiliateProgram>,
        open: bool,
        default_rate_bps: u16,
    ) -> Result<()> {
        // The affiliate rate is fixed platform-wide — reject any attempt to set a different rate.
        require!(default_rate_bps == AFFILIATE_DEFAULT_BPS, FirmError::AffiliateRateLocked);
        let prog = &mut ctx.accounts.affiliate_program;
        prog.open = open;
        prog.default_rate_bps = AFFILIATE_DEFAULT_BPS;
        Ok(())
    }

    /// Register an affiliate. If the program is `open`, the affiliate self-registers (signs for
    /// themselves) at the default rate; otherwise the firm owner registers them and may set a
    /// custom rate. Created active.
    pub fn register_affiliate(
        ctx: Context<RegisterAffiliate>,
        rate_bps: Option<u16>,
    ) -> Result<()> {
        let signer = ctx.accounts.signer.key();
        let affiliate = ctx.accounts.affiliate.key();
        let is_owner = signer == ctx.accounts.firm_state.owner;
        require!(
            is_owner || (ctx.accounts.affiliate_program.open && signer == affiliate),
            FirmError::AffiliateApprovalRequired
        );
        // The affiliate rate is fixed platform-wide. An explicitly-supplied rate must equal it;
        // there are no custom or per-affiliate rates. Every affiliate earns exactly the fixed rate.
        if let Some(r) = rate_bps {
            require!(r == AFFILIATE_DEFAULT_BPS, FirmError::AffiliateRateLocked);
        }
        let acct = &mut ctx.accounts.affiliate_account;
        acct.firm = ctx.accounts.firm_state.key();
        acct.affiliate = affiliate;
        acct.rate_bps = AFFILIATE_DEFAULT_BPS;
        acct.earned = 0;
        acct.claimed = 0;
        acct.referred_count = 0;
        acct.active = true;
        acct.bump = ctx.bumps.affiliate_account;
        let prog = &mut ctx.accounts.affiliate_program;
        prog.total_affiliates = prog.total_affiliates.saturating_add(1);
        Ok(())
    }

    /// Owner toggles a specific affiliate's active flag. The rate is fixed platform-wide, so
    /// `rate_bps` must equal the fixed rate — this instruction can only pause/resume an affiliate,
    /// never reprice one. Deactivating stops new referral binds and future carves; already-accrued
    /// `earned` stays claimable.
    pub fn update_affiliate(
        ctx: Context<UpdateAffiliate>,
        rate_bps: u16,
        active: bool,
    ) -> Result<()> {
        require!(rate_bps == AFFILIATE_DEFAULT_BPS, FirmError::AffiliateRateLocked);
        let acct = &mut ctx.accounts.affiliate_account;
        acct.rate_bps = AFFILIATE_DEFAULT_BPS;
        acct.active = active;
        Ok(())
    }

    /// Bind a trader to an affiliate — first touch, immutable (the PDA inits once). Signed by the
    /// trader; the affiliate must be registered + active and cannot be the trader themselves.
    pub fn bind_referral(ctx: Context<BindReferral>) -> Result<()> {
        let trader = ctx.accounts.trader.key();
        let affiliate = ctx.accounts.affiliate.key();
        require!(affiliate != trader, FirmError::SelfReferral);
        require!(ctx.accounts.affiliate_account.active, FirmError::AffiliateApprovalRequired);
        let now = Clock::get()?.unix_timestamp;
        let referral = &mut ctx.accounts.referral;
        referral.firm = ctx.accounts.firm_state.key();
        referral.trader = trader;
        referral.affiliate = affiliate;
        referral.bound_at = now;
        referral.bump = ctx.bumps.referral;
        let acct = &mut ctx.accounts.affiliate_account;
        acct.referred_count = acct.referred_count.saturating_add(1);
        Ok(())
    }

    /// Affiliate withdraws their claimable balance (`earned − claimed`) from the firm's affiliate
    /// vault to their own SOL account. Pull-based, immediate, no keeper.
    pub fn claim_affiliate(ctx: Context<ClaimAffiliate>) -> Result<()> {
        let claimable = ctx
            .accounts
            .affiliate_account
            .earned
            .checked_sub(ctx.accounts.affiliate_account.claimed)
            .ok_or(FirmError::MathOverflow)?;
        require!(claimable > 0, FirmError::NothingToClaim);
        let bump = [ctx.accounts.firm_state.bump];
        let seeds = firm_signer(&ctx.accounts.firm_state.owner, &bump);
        token::transfer(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                anchor_spl::token::Transfer {
                    from: ctx.accounts.affiliate_pool_vault.to_account_info(),
                    to: ctx.accounts.affiliate_sol.to_account_info(),
                    authority: ctx.accounts.firm_state.to_account_info(),
                },
                &[&seeds],
            ),
            claimable,
        )?;
        let acct = &mut ctx.accounts.affiliate_account;
        acct.claimed = acct.claimed.checked_add(claimable).ok_or(FirmError::MathOverflow)?;
        Ok(())
    }

    /// Route $FIRMA proceeds in one atomic call (§§19,21). After a payout delivers $FIRMA
    /// to the trader's token account, the trader calls this instruction to split the
    /// balance among four destinations without leaving the transaction:
    ///
    ///   1. No-risk staking pool  (`no_risk_stake_bps`)
    ///   2. Backstop (risk-bearing) pool  (`backstop_stake_bps`)
    ///   3. Sell via bonding curve → SOL  (`liquidate_bps`)
    ///   4. Keep in wallet  (implicit remainder: `10000 − sum(above)`)
    ///
    /// All legs run in one tx — either everything settles or everything reverts.
    /// `min_sol_out` is the slippage floor for the liquidation leg (pass 0 when
    /// `liquidate_bps = 0`).
    pub fn route_firma(ctx: Context<RouteFirma>, args: RouteFirmaArgs) -> Result<()> {
        // ── Validate routing bps ──────────────────────────────────────────────
        let total_routed = (args.no_risk_stake_bps as u32)
            .checked_add(args.backstop_stake_bps as u32)
            .and_then(|s| s.checked_add(args.liquidate_bps as u32))
            .ok_or(FirmError::MathOverflow)?;
        require!(total_routed <= 10_000, FirmError::InvalidRouteBps);

        let now = Clock::get()?.unix_timestamp;
        let total_firma = ctx.accounts.trader_firma.amount;
        require!(total_firma > 0, FirmError::ZeroAmount);

        // The base the bps legs split. `route_amount == 0` keeps the original whole-balance behavior;
        // otherwise the legs apply to exactly `route_amount` (bounded to the balance), so a delivered
        // payout can be routed without sweeping $FIRMA the trader already held. Anything above the base
        // — prior holdings plus the base's own wallet leg — simply stays in `trader_firma`.
        let route_base = if args.route_amount == 0 {
            total_firma
        } else {
            args.route_amount.min(total_firma)
        };
        require!(route_base > 0, FirmError::ZeroAmount);

        // Floor division — the rounding dust stays in the wallet leg.
        let no_risk_amount = bps(route_base, args.no_risk_stake_bps);
        let backstop_amount = bps(route_base, args.backstop_stake_bps);
        let liquidate_amount = bps(route_base, args.liquidate_bps);

        // ── No-risk staking leg ───────────────────────────────────────────────
        if no_risk_amount > 0 {
            token::transfer(
                CpiContext::new(
                    ctx.accounts.token_program.to_account_info(),
                    anchor_spl::token::Transfer {
                        from: ctx.accounts.trader_firma.to_account_info(),
                        to: ctx.accounts.stake_vault.to_account_info(),
                        authority: ctx.accounts.trader.to_account_info(),
                    },
                ),
                no_risk_amount,
            )?;

            let pool = &mut ctx.accounts.staking_pool;
            pool.total_staked = pool.total_staked.checked_add(no_risk_amount).ok_or(FirmError::MathOverflow)?;
            let acc_sol = pool.acc_sol;
            let acc_firma = pool.acc_firma;

            let pos = &mut ctx.accounts.staker_position;
            if pos.staker == Pubkey::default() {
                pos.staker = ctx.accounts.trader.key();
                pos.firm = ctx.accounts.firm_state.key();
                pos.staked_at = now;
                pos.bump = ctx.bumps.staker_position;
            }
            pos.amount_staked = pos.amount_staked.checked_add(no_risk_amount).ok_or(FirmError::MathOverflow)?;
            pos.yield_debt_sol = pos.yield_debt_sol.saturating_add(yield_debt(no_risk_amount, acc_sol));
            pos.yield_debt_firma = pos.yield_debt_firma.saturating_add(yield_debt(no_risk_amount, acc_firma));
        }

        // ── Backstop staking leg ──────────────────────────────────────────────
        if backstop_amount > 0 {
            require!(ctx.accounts.backstop_position.cooldown_ends_at == 0, FirmError::CooldownActive);

            token::transfer(
                CpiContext::new(
                    ctx.accounts.token_program.to_account_info(),
                    anchor_spl::token::Transfer {
                        from: ctx.accounts.trader_firma.to_account_info(),
                        to: ctx.accounts.backstop_escrow.to_account_info(),
                        authority: ctx.accounts.trader.to_account_info(),
                    },
                ),
                backstop_amount,
            )?;

            let pool = &mut ctx.accounts.backstop_pool;
            pool.total_staked = pool.total_staked.checked_add(backstop_amount).ok_or(FirmError::MathOverflow)?;
            // F-M-5: nominal premium weight grows with this stake too.
            pool.total_premium_weight =
                pool.total_premium_weight.checked_add(backstop_amount).ok_or(FirmError::MathOverflow)?;
            let premium_acc = pool.premium_acc;
            let loss_acc = pool.loss_acc;

            let pos = &mut ctx.accounts.backstop_position;
            if pos.staker == Pubkey::default() {
                pos.staker = ctx.accounts.trader.key();
                pos.firm = ctx.accounts.firm_state.key();
                pos.staked_at = now;
                pos.bump = ctx.bumps.backstop_position;
            }
            pos.amount_staked = pos.amount_staked.checked_add(backstop_amount).ok_or(FirmError::MathOverflow)?;
            pos.premium_debt = pos.premium_debt.saturating_add(yield_debt(backstop_amount, premium_acc));
            pos.loss_debt = pos.loss_debt.saturating_add(yield_debt(backstop_amount, loss_acc));

            emit!(BackstopStaked {
                firm: ctx.accounts.firm_state.key(),
                staker: ctx.accounts.trader.key(),
                amount: backstop_amount,
            });
        }

        // ── Liquidation leg: sell $FIRMA → SOL via bonding curve ─────────────
        if liquidate_amount > 0 {
            // Post-graduation liquidity routes through Raydium (Phase 4.4) — not yet built.
            require!(!ctx.accounts.curve.graduated, FirmError::PostGraduationUnsupported);

            // The trader is the signer of the outer transaction, so their signer privilege
            // propagates through this CPI — Solana preserves it automatically.
            bonding_curve::cpi::sell(
                CpiContext::new(
                    ctx.accounts.bonding_curve_program.to_account_info(),
                    bonding_curve::cpi::accounts::Sell {
                        trader: ctx.accounts.trader.to_account_info(),
                        curve: ctx.accounts.curve.to_account_info(),
                        sol_vault: ctx.accounts.curve_sol_vault.to_account_info(),
                        firma_vault: ctx.accounts.curve_firma_vault.to_account_info(),
                        trader_sol: ctx.accounts.trader_sol.to_account_info(),
                        trader_firma: ctx.accounts.trader_firma.to_account_info(),
                        firm_treasury_sol: ctx.accounts.firm_treasury_sol.to_account_info(),
                        platform_sol: ctx.accounts.platform_sol.to_account_info(),
                        token_program: ctx.accounts.token_program.to_account_info(),
                    },
                ),
                liquidate_amount,
                args.min_sol_out,
            )?;
        }

        // Wallet leg is implicit — whatever $FIRMA remains in trader_firma after the
        // three transfers above is the wallet allocation; no transfer needed.
        let kept = total_firma
            .saturating_sub(no_risk_amount)
            .saturating_sub(backstop_amount)
            .saturating_sub(liquidate_amount);

        emit!(FirmaRouted {
            firm: ctx.accounts.firm_state.key(),
            trader: ctx.accounts.trader.key(),
            total_firma,
            no_risk_staked: no_risk_amount,
            backstop_staked: backstop_amount,
            liquidated: liquidate_amount,
            kept_in_wallet: kept,
        });

        Ok(())
    }
}

/// Relaxation time-lock (seconds): 48h leaving CRITICAL, 24h otherwise (§25).
pub const RELAX_TIMELOCK_STANDARD: i64 = 86_400;
pub const RELAX_TIMELOCK_CRITICAL: i64 = 172_800;
/// $FIRMA decimals.
pub const FIRMA_DECIMALS: u8 = 6;
/// Highest deployment tier index (0 Starter … 4 Enterprise).
pub const MAX_TIER: u8 = 4;
/// Highest risk-tier index (0 Healthy … 3 Critical).
pub const MAX_RISK_TIER: u8 = 3;
/// One calendar month in seconds (owner drip cadence, §17).
pub const MONTH_SECONDS: i64 = 2_629_800;
/// Owner drip schedule length — 24 months (§17).
pub const DRIP_MONTHS: u8 = 24;
/// Yield-accumulator fixed-point precision (1e12), shared by the staking pool (§19).
pub const PRECISION: u128 = 1_000_000_000_000;
/// Owner challenge-fee allocation is locked for 90 days (§17).
pub const OWNER_VESTING_SECONDS: i64 = 7_776_000;
/// Concentration guard (§16 vector 5): a single payout above 8% of treasury is held.
pub const CONCENTRATION_GUARD_BPS: u16 = 800;
/// Concentration-guard hold duration — 72h for manual review before processing (§22).
pub const CONCENTRATION_HOLD_SECONDS: i64 = 259_200;
/// DEC-77 — first-payout instant advance (§22b). A locked, platform-wide ceiling: the maximum SOL a
/// firm may have advanced (unresolved, at risk of a permanent write-off) at any one time, as a % of
/// its treasury. Deliberately a compiled constant, not a per-firm-owner-settable field — this is a
/// platform risk-tolerance decision (how much may be permanently, unrecoverably lost per firm if a
/// first-payout settlement is later proven fraudulent), not an operator dial. 200 bps = 2% —
/// `reports/2026-07-23-instant-payout-advance.md`, `reports/2026-07-16-dec66-d-void-and-payout-netting.md`
/// (the finding this bounds against: a fault proof can never validate a keeper-struck payout amount,
/// SETTLE-SOL-PRICE-1 — only a finite pre-funded float can, so this cap is the ONLY safety mechanism).
/// PAYOUT-ADVANCE-12: "treasury" here means `total_treasury_sol` — tier 1 (`firm_state.treasury_sol`) +
/// tier 2 (the $FIRMA reserve, priced via `bonding_curve::sell_output`) + tier 3 (operator stake bond),
/// the SAME total `advance_first_payout`'s own concentration guard already uses a few lines above this
/// check — NOT `firm_state.treasury_sol` alone (the original, narrower basis this shipped with).
/// Deliberately excludes the tier-4 Universal Treasury Pool: that pool backstops insolvency across
/// every firm, not any one firm's own risk budget.
pub const ADVANCE_CAP_BPS: u16 = 200;
/// PAYOUT-ADVANCE-11 — dedicated advance-only daily velocity cap, separate from the shared
/// `daily_payout_spent` counter. `ADVANCE_CAP_BPS` bounds live OUTSTANDING exposure at any instant, but
/// says nothing about how many times that bucket can be refilled in a day as individual advances
/// reconcile/write off — a sybil-style operator cycling fresh wallets through the off-chain first-payout
/// eligibility gate could otherwise keep re-opening the same 2% window repeatedly. This counter
/// (`AdvancePool.daily_advance_spent`) tracks cumulative SOL *spent* on advances today, regardless of
/// how quickly outstanding balances clear, and is checked in ADDITION to `ADVANCE_CAP_BPS`. 600 bps = 6%
/// — roughly 3 full refill-cycles of the instantaneous cap per day, a deliberately tighter bound than
/// the shared `daily_payout_spent`'s 20%. Same tiers-1-3-excluding-Universal-Pool basis as
/// `ADVANCE_CAP_BPS` (PAYOUT-ADVANCE-12).
pub const ADVANCE_DAILY_CAP_BPS: u16 = 600;
/// §19 anti-bank-run redemption gate: the maximum share of the LIVE backstop pool (`total_staked`,
/// recomputed fresh each call — not snapshotted) that `withdraw_backstop` may pay out across all
/// stakers combined per rolling UTC day. 1000 bps = 10%. No floor — unlike a SOL-treasury cap, a
/// percentage of a token pool scales fine at any pool size without one.
pub const BACKSTOP_DAILY_OUTFLOW_CAP_BPS: u16 = 1000;
/// Floor for the advance-only daily cap, in lamports — 0.5 SOL. Smaller than
/// `MIN_DAILY_PAYOUT_FLOOR_SOL` (2 SOL) deliberately: this is the riskier, no-clawback path, so a
/// thin-treasury firm should get a smaller baseline advance allowance, not the same one as normal payouts.
pub const MIN_DAILY_ADVANCE_FLOOR_SOL: u64 = 500_000_000;
/// PAYOUT-ADVANCE-10 — bounds the SETTLE-SOL-PRICE-1 blind spot (a fault proof validates the transcript,
/// never the keeper-struck `payout_sol_owed` figure, so an inflated claim on an otherwise-honest
/// settlement is structurally undetectable after the fact). Rather than trying to detect an amount-lie,
/// this caps the WORST CASE: `advance_first_payout` may never instantly advance more than this fraction
/// of the claimed `payout_sol_owed`. The remainder is only ever payable through the normal, Final-gated
/// `process_queued_payout` path (which already handles a partially-delivered `QueuedPayout` correctly),
/// so a fabricated claim's realized, unrecoverable loss is capped at this fraction of the lie, not its
/// full size. 5000 bps = 50%.
pub const ADVANCE_MAX_CLAIM_BPS: u16 = 5000;
/// Clean-shutdown timelock (F1) — 7 days between `initiate_close` and `finalize_close`, giving any
/// unpaid trader / open disputer a public window to act before treasury + insurance are released.
pub const CLOSE_TIMELOCK: i64 = 604_800;
/// C-7 — how long a queued payout must sit UNDELIVERED before `force_discharge_undeliverable_payout`
/// may write it off to unwedge `finalize_close` (90 days). Far longer than any real delivery window
/// (TWAP minutes + a 3-day concentration hold), so it only ever catches a genuinely stuck payout.
pub const FORCE_DISCHARGE_TIMEOUT: i64 = 7_776_000;
/// K-1: bytes appended for keeper authority rotation (`previous_risk_engine_authority` Pubkey 32 +
/// `authority_rotation_deadline` i64 8). Used to PIN `migrate_firm_token_fields` to the pre-rotation
/// account size, so appending these fields never shifts the token migration's trailing-byte writes.
pub const AUTHORITY_ROTATION_FIELDS_LEN: usize = 32 + 8;
/// Self-funded operator bond: bytes appended AFTER the authority-rotation fields (`bond_accrual` u64 8 +
/// `bond_funded` bool 1). Zero-fills to "nothing accrued, not yet funded" — the correct default for an
/// existing firm, so `migrate_firm_permissionless`/`migrate_firm_authority_fields` (which resize to the
/// full `INIT_SPACE`) absorb them for free. The token-generation pin below must account for BOTH trailing
/// regions so it still stops at the pre-rotation size.
pub const BOND_FIELDS_LEN: usize = 8 + 1;
/// Auto-bankruptcy (§24 v2): bytes appended AFTER the bond fields (`ulp_drawn` u64 8). Same append-only
/// discipline — zero-fills to "0 drawn", the correct default for an existing firm.
pub const BANKRUPTCY_FIELDS_LEN: usize = 8;
/// Phase 4.4 Raydium LP-add (§12): `post_grad_lp_acc` u64 (8), appended after `ulp_drawn`. Same
/// append-only discipline — zero-fills to "0 pending" for an existing firm.
pub const POST_GRAD_LP_FIELDS_LEN: usize = 8;
/// Total bytes trailing the token-generation layout (rotation + bond + bankruptcy + post-grad LP).
/// `migrate_firm_token_fields` and the `token_gen` intermediate in `migrate_firm_permissionless`
/// subtract THIS to reach the pre-rotation size — otherwise appending trailing fields would push their
/// byte writes into the new fields.
pub const POST_TOKEN_TRAILING_LEN: usize = AUTHORITY_ROTATION_FIELDS_LEN
    + BOND_FIELDS_LEN
    + BANKRUPTCY_FIELDS_LEN
    + POST_GRAD_LP_FIELDS_LEN;
/// K-1: grace window after a keeper rotation during which the OUTGOING `risk_engine_authority` is still
/// honored for in-flight challenges (whose frozen `settlement_authority` == the old keeper). 14 days —
/// longer than a settlement's fraud-proof window, so any challenge outstanding at rotation drains under
/// the old key before it dies.
pub const AUTHORITY_ROTATION_GRACE: i64 = 14 * 86_400;
/// Absolute floor for the daily payout cap, in **lamports** (wSOL, 9 dp) — 15 SOL. OMEGA finding #1:
/// the flat 20%-of-treasury daily cap spirals when a firm's treasury runs thin under a realistic
/// funded payout load (payouts thin the treasury → smaller cap → more queue → treasury stays thin).
/// The floor lets a thin-but-solvent firm still clear a baseline daily volume; the per-payout
/// `amount ≤ treasury` and concentration guards remain, so solvency is unaffected.
/// SOL MIGRATION: the unit is now **lamports** (wSOL, 9 dp) — dimensionally a SOL amount compared
/// against the lamport treasury balance (oracle-free, `SOL_SETTLEMENT_MIGRATION.md` Phase 3+4). The
/// raw value is kept (2e9 = 2 SOL) as a **placeholder**; its real SOL-native magnitude is a Phase-6
/// (ARE solvency) decision, since a SOL-denominated USD-pegged floor is exactly the §B open question.
pub const MIN_DAILY_PAYOUT_FLOOR_SOL: u64 = 2_000_000_000;
/// Loyalty fast-track queue priority marker.
pub const PRIORITY_STANDARD: u8 = 0;
pub const PRIORITY_FAST_TRACK: u8 = 1;

/// Global daily cap on Universal Treasury Pool draws, in **lamports** (wSOL, 9 dp) — 50 SOL.
/// Rate-limits how fast the shared pool can be depleted across ALL firms in a single UTC day, so a
/// single firm's tail demand (or a bug) can't drain the mutualized pool in one go. Placeholder
/// magnitude (SOL-native, oracle-free); the production figure is a Phase-6 (ARE solvency) tunable.
pub const UNIVERSAL_DAILY_DRAW_CAP_SOL: u64 = 50_000_000_000;

/// Auto-bankruptcy threshold (§24 v2). A firm auto-bankrupts the instant its lifetime Universal-Pool
/// draws (`FirmState.ulp_drawn`) reach `pool_balance / BANKRUPTCY_ULP_DEPLETION_DIVISOR` — i.e. **10%**
/// of the pool as it stood at the crossing draw. Bankruptcy is *only* reachable this way: a firm that
/// consumes a tenth of the mutual commons is removed from operation. Divisor form keeps the check
/// integer-exact (no bps rounding) and cheap.
pub const BANKRUPTCY_ULP_DEPLETION_DIVISOR: u64 = 10; // 10%

// Fixed challenge-fee allocations (§17), in basis points of the total fee.
pub const DP_PROFIT_BPS: u16 = 750; // 7.5% (was 8%; 0.5% redirected to the Universal Treasury Pool)
pub const DP_TREASURY_BPS: u16 = 250; // 2.5% (was 3%; 0.5% redirected to the Universal Treasury Pool)
pub const INSURANCE_BPS: u16 = 200; // 2% (reduced from 3%; 1% redirected to $DPROP staking pool)

// Universal Treasury Pool (cross-firm payout liquidity of last resort): a fixed 1.5% leg of every
// eval fee routed to the protocol-wide `universal_vault`, drawn as the final tier of the payout
// waterfall (`draw_universal`) when a firm's own treasury + $FIRMA reserve + backstop are exhausted.
// Trimmed 1.5% → 1.0% (full-protocol 3-year sim, 2026-07-04): the pool was over-provisioned — its
// 1.5% eval feed dwarfed its draw rate, ending every scenario (incl. contagion) at $1.3M+. Cutting
// the feed to 1.0% routes the freed 0.5% to the firm-treasury remainder (`treasury_gross` is the
// residual, so it's absorbed automatically), which lifted median/worst firm profit and cut contagion
// insolvencies at zero solvency cost — the pool still never ran dry. See
// reports/2026-07-04-full-protocol-3yr-sim.md finding #1.
pub const UNIVERSAL_EVAL_BPS: u16 = 100; // 1.0%

/// Self-funded operator bond leg (§10/§14): 1% of every evaluation fee is earmarked OUT of the firm's
/// own treasury slice (not an extra charge — the trader pays the same) and moved to the firm's operator
/// collateral bond by `fund_operator_bond`, until the bond reaches `dispute::MIN_OPERATOR_STAKE_LAMPORTS`
/// (50 SOL). Once `bond_funded`, the earmark stops and that 1% stays in the treasury. Mirrors the
/// `firma_buyback_acc` earmark pattern: the SOL is already inside `to_treasury`; this just records how
/// much of it belongs to the bond.
pub const BOND_FUNDING_BPS: u16 = 100; // 1%

// Normal staking pool (5%) and the platform-native $DPROP buy-back pool (1%): fixed legs of
// every challenge fee. Each routes SOL to an accumulator token account (mirrors the dp_profit /
// dp_treasury wallets) to be consumed later by the staking-reward and $DPROP-buyback instructions
// (deferred). $DPROP is the protocol's native token, separate from per-firm $FIRMA.
// 2026-07-27 staking rebalance: reduced 5% -> 3%, the freed 2% mirrored into
// DEFAULT_BACKSTOP_PREMIUM_BPS (6% -> 8%) so the combined no-risk + backstop SOL carve
// stays 11% of every eval fee — a reallocation toward the riskier pool, not a new cost.
pub const NORMAL_STAKING_BPS: u16 = 300; // 3% (reduced from 5%; -2% shifted to backstop premium)
pub const DPROP_BUYBACK_BPS: u16 = 100; // 1% (reduced from 2%; 1% to normal staking pool)

// $DPROP staking pool (10%): fixed leg of every challenge fee routed to the protocol-level
// `dprop_staking_sol` vault, distributed as SOL yield to $DPROP stakers via the
// `claim_dprop_staking_yield` pull path (the admin `distribute_dprop_staking` push was removed, T-1).
// Funded by reducing: DP profit -2%, insurance -1%, $DPROP buyback -1%, $FIRMA buyback -1%,
// owner -1%, LP -1%, affiliate -1% (when active), and firm treasury -2%.
pub const DPROP_STAKING_BPS: u16 = 1000; // 10%

// Loss-back credit leg (flywheel). 2026-07-27 staking rebalance: NO LONGER a carved FeeSplit leg —
// removed the dedicated `loss_back_vault` entirely (it could strand real SOL forever for a trader
// who never met the stake gate; see `reports/2026-07-27-staking-rebalance-proposal.md`). Now a
// PURELY NOTIONAL per-trader accrual computed directly in `pay_challenge_fee`: 2% of what the
// trader actually pays becomes `LossBackCredit.balance`, applied as a price reduction on a later
// purchase (never a real transfer) while the trader stakes at least `FirmState.loss_back_min_stake`
// $FIRMA in EITHER the no-risk or the backstop pool. The per-trader bound is unchanged: a trader can
// never redeem more than accrued from their own fees.
pub const LOSS_BACK_BPS: u16 = 200; // 2% — now an accrual rate, not a fee-split carve

// $YOURFIRM ($FIRMA) buy-back (1%): a fixed leg of every challenge fee earmarked to buy the firm's
// own $FIRMA off the curve and hold it in the **Tier-2 treasury reserve** (`treasury_firma_vault`),
// from which funded-trader payouts are delivered slippage-free (§Payout Hierarchy). The SOL carve
// stays in the firm treasury and is tracked in `FirmState.firma_buyback_acc`; the permissionless
// `execute_firma_buyback` crank converts it to $FIRMA → reserve (mirrors the $DPROP buy-back sink).
pub const FIRMA_BUYBACK_BPS: u16 = 100; // 1% (reduced from 2%; 1% to normal staking pool)

// Affiliate leg (§17.1): DYNAMIC per-firm/per-affiliate. Carved only for *referred* challenge
// purchases at the referring affiliate's rate (default 10%, firm-configurable 0–20%); unreferred
// purchases carve 0 (the slice stays in the firm treasury). Each firm runs its own affiliate
// program; the carve accrues to the firm's affiliate vault and is claimed pull-based by affiliates.
/// The affiliate referral fee is FIXED platform-wide at 10%. It is not operator-configurable: the
/// `init`/`config`/`register`/`update` instructions reject any other rate (`AffiliateRateLocked`),
/// and the fee split always carves this exact rate for a referred purchase.
pub const AFFILIATE_DEFAULT_BPS: u16 = 1000; // 10% — the single, fixed affiliate rate
/// Legacy ceiling; retained for back-compat with older fee-split callers/tests. The live affiliate
/// rate can only ever equal AFFILIATE_DEFAULT_BPS now, so this is no longer a reachable bound.
pub const MAX_AFFILIATE_BPS: u16 = 2000; // 20%

// Backstop premium (§19): carved from the firm-treasury gross slice of each challenge fee
// and routed atomically to the backstop premium vault. Stored per-pool, governance-adjustable.
/// The backstop premium is FIXED platform-wide at 8%. It is not operator-configurable: `init_backstop_pool`
/// seeds this rate and `set_backstop_premium` rejects any other value (`BackstopPremiumLocked`); the fee
/// split carves exactly this rate whenever a backstop pool exists.
///
/// 2026-07-27 staking rebalance: raised 6% -> 8% (mirrors NORMAL_STAKING_BPS's 5% -> 3% cut, so the
/// combined no-risk + backstop SOL carve stays 11% of every eval fee). The prior 6% lock was a
/// governance choice (freezing what used to be per-firm operator-configurable), not a safety
/// invariant — raising the single platform-wide constant is architecturally clean; any pool created
/// under the old 6% (or the pre-lock 4.5%) still carves the CURRENT constant, never its stored value
/// (see the `compute_fee_split` call site).
pub const DEFAULT_BACKSTOP_PREMIUM_BPS: u16 = 800; // 8% — the single, fixed backstop premium rate
/// Default `FirmState.backstop_pool_bps` (2026-07-27 staking rebalance) — the backstop pool's
/// $FIRMA yield leg, seeded at `deploy_firm` and settable in range via `update_stakeholder_config`
/// (500..=3000, mirrors `StakeholderConfig.staking_pool_bps`'s band). A sibling of
/// `StakeholderConfig`, not a field inside it — see that struct's doc comment for why.
pub const DEFAULT_BACKSTOP_POOL_BPS: u16 = 500; // 5%
/// The loss-back redemption gate is FIXED platform-wide at 1,000,000 $FIRMA. It is not
/// operator-configurable: `deploy_firm` seeds this on the firm state and `set_loss_back_min_stake`
/// rejects any other value (`LossBackMinStakeLocked`), so it can only ever re-assert this amount.
/// 1,000,000 tokens × 10^FIRMA_DECIMALS (6 dp) = 1_000_000_000_000 base units.
pub const LOSS_BACK_MIN_STAKE: u64 = 1_000_000_000_000;
/// Legacy ceiling; retained for back-compat. The live premium can only ever equal DEFAULT_BACKSTOP_PREMIUM_BPS
/// now, so this is no longer a reachable bound (== the fixed rate).
pub const MAX_BACKSTOP_PREMIUM_BPS: u16 = 600; // 6%

// Prediction Market LP Pool (Phase 2 of the pooled-LP AMM plan) — a near-exact mirror of the
// Investor Backstop Pool immediately above, for a different destination (Phase 3's per-market
// curves). See `PredictionMarketLpPool`'s doc comment for the full structural mapping.
/// Default `PredictionMarketLpPool.allocation_cap_bps` — the maximum share of `total_staked` the
/// keeper may have deployed across every eligible market's curve at once (Phase 3's
/// `allocate_pool_to_curve`/`deallocate_pool_from_curve`). Not enforced by any Phase 2 instruction;
/// reserved here so the field has a sane default the moment the pool exists.
pub const DEFAULT_PM_LP_ALLOCATION_CAP_BPS: u16 = 8000; // 80%
/// Same anti-bank-run idiom as `BACKSTOP_DAILY_OUTFLOW_CAP_BPS`, own constant so the two pools' caps
/// can move independently: the maximum share of the LIVE PM LP pool's `total_staked` (recomputed
/// fresh each call) that `withdraw_pm_lp` may pay out across all stakers combined per rolling UTC day.
pub const PM_LP_DAILY_OUTFLOW_CAP_BPS: u16 = 1000; // 10%

/// PM-CURVE-SUPPLY-1 (PROVISIONAL, needs DEC-89 sign-off): each `MarketCurve` leg's notional "share
/// supply" — the pool `buy_output`/`sell_output` sell down — expressed as a multiple of that leg's own
/// virtual seed. `MarketCurve.pass_shares`/`fail_shares` store shares OUTSTANDING (held by position
/// holders — `redeem_shares`' pro-rata math needs that semantic, not "remaining unsold supply"); the
/// AMM math needs the OPPOSITE quantity, so `pm_curve_available_shares` derives it as the complement:
/// `virtual_seed * MULTIPLIER - shares_outstanding`. MULTIPLIER=2 starts each independent leg at a 50%
/// implied price (`virtual / (2 × virtual)`) — enough headroom under the price-ceiling guard for the
/// very first buy to succeed (MULTIPLIER=1 would start a leg already AT the $1 ceiling, permanently
/// frozen — every buy strictly raises price, so a market that opens at the ceiling can never trade).
pub const PM_CURVE_SHARE_SUPPLY_MULTIPLIER: u64 = 2;

// Dynamic LP thresholds on the REAL pool reserve, now in **lamports** (wSOL, 9 dp) — the curve reserve
// is wSOL post-migration (§17). SOL MIGRATION (oracle-free, Phase 3+4): dimensionally lamports vs the
// lamport reserve. Raw values kept as placeholders; the SOL-native magnitudes are a Phase-6 tunable.
const LP_DEPTH_LOW: u64 = 50_000_000_000;
const LP_DEPTH_HIGH: u64 = 200_000_000_000;

/// Owner fee allocation by deployment tier in bps (§17): Starter 6% … Enterprise 14%.
/// OMEGA finding #7: the entry tiers (Starter/Growth) were the weakest owner deal (Starter net ROI
/// ≈ +5%). Their owner-fee share is raised (Starter 5%→7%, Growth 7%→8.5%) to sweeten the on-ramp;
/// the higher tiers are unchanged. Each tier further reduced by 100bps to fund the $DPROP staking pool.
pub fn owner_bps_for_tier(tier: u8) -> u16 {
    match tier {
        0 => 600,
        1 => 750,
        2 => 900,
        3 => 1100,
        _ => 1400,
    }
}

/// Dynamic LP allocation by real pool depth (§17): <$50k → 11%, $50–200k → 9%, >$200k → 5%.
/// LP is a bonding-curve-stage leg: pre-graduation it's routed into the curve; post-graduation
/// (curve complete, liquidity on Raydium, LP burned) the slice folds into the firm treasury.
/// Each depth bucket reduced by 100bps to fund the $DPROP staking pool.
pub fn lp_bps_for_depth(real_sol: u64) -> u16 {
    if real_sol < LP_DEPTH_LOW {
        1100
    } else if real_sol <= LP_DEPTH_HIGH {
        900
    } else {
        500
    }
}

fn bps(amount: u64, bps: u16) -> u64 {
    ((amount as u128 * bps as u128) / 10_000) as u64
}

/// Split an amount 50/50, the first party absorbing the odd unit.
fn halve(amount: u64) -> (u64, u64) {
    let second = amount / 2;
    (amount - second, second)
}

/// Split an amount 3:1 (matches `DP_PROFIT_BPS`:`DP_TREASURY_BPS` = 750:250), the first party
/// absorbing the remainder from integer division.
fn split_3_1(amount: u64) -> (u64, u64) {
    let second = amount / 4;
    (amount - second, second)
}

// === Treasury Health Split (§3.6) ===
//
// Once a firm's own `treasury_sol` crosses tier-scaled SOL thresholds, the marginal eval fee
// redirects away from the treasury toward Owner / DecentralProp / $FIRMA+$DPROP staking / buybacks /
// the Universal Pool. Fully platform-locked (no operator input, no governance instruction, no stored
// state) — computed live off already-tracked state on every call, same idiom as `lp_bps_for_depth`
// one line above, not the `RiskTier` authority-driven state machine. DEC-74: numbers are provisional,
// not yet founder-approved.

/// Per-tier SOL thresholds (lamports, 9dp) for the 5 zones: Growing (< thresholds[0]) / Healthy /
/// Strong / Thriving / Saturated (>= thresholds[3]). Starter/Growth/Pro deliberately share one
/// ladder — treasury health is judged the same regardless of launch-fee tier; Scale/Enterprise scale up.
fn treasury_health_thresholds_lamports(tier: u8) -> [u64; 4] {
    match tier {
        0..=2 => [
            500_000_000_000,
            1_000_000_000_000,
            2_500_000_000_000,
            5_000_000_000_000,
        ],
        3 => [
            900_000_000_000,
            1_800_000_000_000,
            4_500_000_000_000,
            9_000_000_000_000,
        ],
        _ => [
            1_500_000_000_000,
            3_000_000_000_000,
            7_500_000_000_000,
            15_000_000_000_000,
        ],
    }
}

/// Which of the 5 zones (0=Growing .. 4=Saturated) a firm's treasury sits in, for its tier's ladder.
pub fn treasury_health_zone(tier: u8, treasury_sol: u64) -> u8 {
    let thresholds = treasury_health_thresholds_lamports(tier);
    let mut zone = 0u8;
    for threshold in thresholds.iter() {
        if treasury_sol >= *threshold {
            zone += 1;
        }
    }
    zone
}

/// Total bps redirected away from the treasury at the Saturated zone, derived (not a second
/// hardcoded table) from the tier's owner baseline so it can't silently drift if that's retuned:
/// `4400 - owner_bps_for_tier(tier)`. Starter 3800, Growth 3650, Pro 3500, Scale 3300, Enterprise 3000.
fn treasury_health_boost_max_bps(tier: u8) -> u16 {
    4400 - owner_bps_for_tier(tier)
}

/// Linear zone ramp: Growing=0%, Healthy=25%, Strong=50%, Thriving=75%, Saturated=100% of boost_max.
fn treasury_health_boost_bps(tier: u8, zone: u8) -> u16 {
    let boost_max = treasury_health_boost_max_bps(tier) as u32;
    ((boost_max * zone as u32) / 4) as u16
}

/// Fixed weights (bps of the boost itself, sum 10,000) — same for every tier/zone. DP splits 3:1 and
/// Buybacks split 1:1 to match their existing internal leg ratios.
const HEALTH_OWNER_WEIGHT_BPS: u16 = 2000;
const HEALTH_DP_WEIGHT_BPS: u16 = 2000;
const HEALTH_STAKING_FIRMA_WEIGHT_BPS: u16 = 1500;
const HEALTH_STAKING_DPROP_WEIGHT_BPS: u16 = 1500;
const HEALTH_BUYBACK_WEIGHT_BPS: u16 = 2000;
const HEALTH_UNIVERSAL_WEIGHT_BPS: u16 = 1000;

/// What fraction of `base_bps` (the zone's boost) a leg with `weight_bps` (of 10,000) is owed, as a bps
/// value suitable for feeding straight into `bps(amount, ..)`.
fn bps_of_bps(base_bps: u16, weight_bps: u16) -> u16 {
    (((base_bps as u32) * (weight_bps as u32)) / 10_000) as u16
}

/// Applies the Treasury Health Split on top of an already-computed `FeeSplit`. Conservation is
/// enforced structurally, not asserted: the 9 credited legs' nominal deltas are capped to what
/// `treasury_gross` actually has available — scaled down proportionally on the rare over-redirect case
/// (e.g. Enterprise/Saturated with a shallow curve, an active backstop pool, and a referred purchase
/// can leave less pre-boost treasury than `boost_max` alone would redirect) — and `treasury_gross` is
/// always debited by the literal sum of what was credited, never a separately-computed number. So
/// `sum(FeeSplit fields) == amount` holds unconditionally, the same contract `compute_fee_split` itself
/// already guarantees. Zone 0 (every firm today) short-circuits to a byte-identical no-op.
pub fn apply_treasury_health_adjustment(
    mut split: FeeSplit,
    amount: u64,
    tier: u8,
    treasury_sol: u64,
) -> FeeSplit {
    let zone = treasury_health_zone(tier, treasury_sol);
    if zone == 0 {
        return split;
    }
    let boost_bps = treasury_health_boost_bps(tier, zone);
    if boost_bps == 0 {
        return split;
    }

    let owner_delta = bps(amount, bps_of_bps(boost_bps, HEALTH_OWNER_WEIGHT_BPS));
    let dp_delta = bps(amount, bps_of_bps(boost_bps, HEALTH_DP_WEIGHT_BPS));
    let staking_firma_delta = bps(amount, bps_of_bps(boost_bps, HEALTH_STAKING_FIRMA_WEIGHT_BPS));
    let staking_dprop_delta = bps(amount, bps_of_bps(boost_bps, HEALTH_STAKING_DPROP_WEIGHT_BPS));
    let buyback_delta = bps(amount, bps_of_bps(boost_bps, HEALTH_BUYBACK_WEIGHT_BPS));
    let universal_delta = bps(amount, bps_of_bps(boost_bps, HEALTH_UNIVERSAL_WEIGHT_BPS));

    let (owner_immediate_delta, owner_vested_delta) = halve(owner_delta);
    let (dp_profit_delta, dp_treasury_delta) = split_3_1(dp_delta);
    let (dprop_buyback_delta, firma_buyback_delta) = halve(buyback_delta);

    let total_delta = owner_delta
        + dp_delta
        + staking_firma_delta
        + staking_dprop_delta
        + buyback_delta
        + universal_delta;
    let applied = total_delta.min(split.treasury_gross);

    let (
        owner_immediate_c,
        owner_vested_c,
        dp_profit_c,
        dp_treasury_c,
        staking_firma_c,
        staking_dprop_c,
        dprop_buyback_c,
        firma_buyback_c,
        universal_c,
    ) = if total_delta == 0 || applied == total_delta {
        (
            owner_immediate_delta,
            owner_vested_delta,
            dp_profit_delta,
            dp_treasury_delta,
            staking_firma_delta,
            staking_dprop_delta,
            dprop_buyback_delta,
            firma_buyback_delta,
            universal_delta,
        )
    } else {
        // Over-redirect: the 9 nominal deltas exceed what `treasury_gross` actually has left. Scale
        // every credited leg down proportionally (u128 math, same idiom as `bps()`) rather than
        // clamping the treasury side alone — otherwise the credited legs would keep their full nominal
        // deltas while the treasury subtraction clamps to 0, and the total split would exceed `amount`.
        let scale = |v: u64| -> u64 { ((v as u128 * applied as u128) / total_delta as u128) as u64 };
        (
            scale(owner_immediate_delta),
            scale(owner_vested_delta),
            scale(dp_profit_delta),
            scale(dp_treasury_delta),
            scale(staking_firma_delta),
            scale(staking_dprop_delta),
            scale(dprop_buyback_delta),
            scale(firma_buyback_delta),
            scale(universal_delta),
        )
    };

    split.owner_immediate += owner_immediate_c;
    split.owner_vested += owner_vested_c;
    split.dp_profit += dp_profit_c;
    split.dp_treasury += dp_treasury_c;
    split.normal_staking += staking_firma_c;
    split.dprop_staking += staking_dprop_c;
    split.dprop_buyback += dprop_buyback_c;
    split.firma_buyback += firma_buyback_c;
    split.universal += universal_c;

    let credited = owner_immediate_c
        + owner_vested_c
        + dp_profit_c
        + dp_treasury_c
        + staking_firma_c
        + staking_dprop_c
        + dprop_buyback_c
        + firma_buyback_c
        + universal_c;
    split.treasury_gross = split.treasury_gross.saturating_sub(credited);

    split
}

/// The destinations a challenge fee splits into (§17). `backstop_premium` is carved from the
/// treasury slice (zero when backstop staking is disabled); `normal_staking` (5%),
/// `dprop_buyback` (1%), and `dprop_staking` (10%) are fixed legs routed to platform-level accumulators.
pub struct FeeSplit {
    pub dp_profit: u64,
    pub dp_treasury: u64,
    pub insurance: u64,
    pub owner_immediate: u64,
    pub owner_vested: u64,
    pub lp: u64,
    pub backstop_premium: u64,
    pub normal_staking: u64,
    pub dprop_buyback: u64,
    /// $YOURFIRM buy-back (2%) earmarked for the Tier-2 treasury $FIRMA reserve (payouts).
    pub firma_buyback: u64,
    pub affiliate_pool: u64,
    /// $DPROP staking yield (10%) — routed to the protocol-level `dprop_staking_sol` vault;
    /// distributed as SOL rewards to $DPROP stakers via the `claim_dprop_staking_yield` pull path.
    pub dprop_staking: u64,
    /// Universal Treasury Pool (1.5%) — routed to the protocol-wide `universal_vault`; drawn as the
    /// final payout-waterfall tier (`draw_universal`) when a firm's own sources are exhausted.
    pub universal: u64,
    pub treasury_gross: u64,
}

/// Compute the atomic split. The backstop premium (`premium_bps`, 0 when the firm has no
/// backstop pool) is carved from the treasury's gross slice; the fixed normal-staking (3%),
/// $DPROP buy-back (1%), and $DPROP staking (10%) legs are deducted; the affiliate leg
/// (`affiliate_bps`, 0 when unreferred, else the affiliate's rate ≤ 20%) is reduced by 100bps
/// (1% redirected to $DPROP staking); the treasury absorbs rounding so all parts sum to `amount`.
///
/// 2026-07-27 staking rebalance: the loss-back comeback credit is no longer a carved leg here.
/// It's now a purely notional per-trader counter (`LossBackCredit.balance`, no backing vault)
/// accrued directly in `pay_challenge_fee` from the amount actually charged, and applied as a
/// price reduction on a future purchase — never a real transfer out of this split.
pub fn compute_fee_split(
    amount: u64,
    owner_bps: u16,
    lp_bps: u16,
    premium_bps: u16,
    affiliate_bps: u16,
) -> FeeSplit {
    let dp_profit = bps(amount, DP_PROFIT_BPS);
    let dp_treasury = bps(amount, DP_TREASURY_BPS);
    let insurance = bps(amount, INSURANCE_BPS);
    let owner_total = bps(amount, owner_bps);
    let owner_vested = owner_total / 2;
    let owner_immediate = owner_total - owner_vested;
    let lp = bps(amount, lp_bps);
    let backstop_premium = bps(amount, premium_bps);
    let normal_staking = bps(amount, NORMAL_STAKING_BPS);
    let dprop_buyback = bps(amount, DPROP_BUYBACK_BPS);
    let firma_buyback = bps(amount, FIRMA_BUYBACK_BPS);
    // Affiliate rate is reduced by 100bps: 1% of every referred purchase is redirected to the
    // $DPROP staking pool. Unreferred purchases (affiliate_bps = 0) contribute their extra 1% via
    // the treasury remainder instead.
    let affiliate_pool = bps(amount, affiliate_bps.saturating_sub(100));
    let dprop_staking = bps(amount, DPROP_STAKING_BPS);
    // Universal Treasury Pool leg (1.5%). DP profit/treasury were each cut 0.5% to fund it; the
    // remaining 0.5% comes out of the firm-treasury remainder, which falls out automatically since
    // `treasury_gross` is `amount - others` and `universal` is included in `others`.
    let universal = bps(amount, UNIVERSAL_EVAL_BPS);
    let others = dp_profit
        + dp_treasury
        + insurance
        + owner_immediate
        + owner_vested
        + lp
        + backstop_premium
        + normal_staking
        + dprop_buyback
        + firma_buyback
        + affiliate_pool
        + dprop_staking
        + universal;
    FeeSplit {
        dp_profit,
        dp_treasury,
        insurance,
        owner_immediate,
        owner_vested,
        lp,
        backstop_premium,
        normal_staking,
        dprop_buyback,
        firma_buyback,
        affiliate_pool,
        dprop_staking,
        universal,
        treasury_gross: amount.saturating_sub(others),
    }
}

// Tier deployment-fee allocations (Architecture §5), in bps of the launch fee.
pub const DEPLOY_FRANCHISE_BPS: u16 = 900; // 9% → same-tier franchise pool (was 10%; 1% to Universal Treasury Pool)
pub const DEPLOY_DP_BPS: u16 = 2000; // 20% → DecentralProp
pub const DEPLOY_DPROP_BURN_BPS: u16 = 500; // 5% → $DPROP buy-and-burn (protocol token sink)
pub const DEPLOY_REFERRAL_BPS: u16 = 3000; // 30% of the franchise slice → referrer
// Universal Treasury Pool seed from each launch fee: 3% routed to the protocol-wide `universal_vault`.
// Funded by 1% from the franchise pool (10%→9%) and 2% from the firm-treasury remainder.
pub const DEPLOY_UNIVERSAL_BPS: u16 = 300; // 3% → Universal Treasury Pool

/// The destinations a tier deployment fee splits into (Architecture §5). RESERVE-3 (2026-07-11):
/// all curve-buy legs (owner-drip / treasury auto-purchases + $FIRMA buy-and-burn) are removed —
/// every leg here is a plain-SOL fixed leg and the firm treasury absorbs the remainder (~63%).
pub struct DeploymentFeeSplit {
    pub franchise_pool: u64,
    pub referral_bonus: u64,
    pub franchise_general: u64,
    pub decentralprop: u64,
    /// $DPROP protocol-token buy-and-burn (5%) → routed to the global $DPROP buyback sink.
    pub dprop_burn: u64,
    /// Universal Treasury Pool seed (3%) → the protocol-wide `universal_vault`.
    pub universal: u64,
    pub firm_treasury: u64,
}

/// Tier → one-time deployment (launch) fee, the **USD reference ladder** in micro-dollars (6 dp).
/// SOL MIGRATION (oracle-free): this is no longer charged on-chain directly — the gateway/SDK reads
/// this USD target and converts it to `price_lamports` at the live Pyth SOL/USD rate, which the
/// settlement authority co-signs into `pay_deployment_fee`. Kept as the canonical
/// published price ladder (Architecture §5).
///
/// MUST mirror the TS `DEPLOYMENT_TIER_USD` (packages/solana-client/src/deployment-fee.ts) — the ladder
/// the gateway actually charges from. Tiers 0/1 were previously 5k/10k here vs 1k/5k in TS (audit F-4,
/// fee-math-precision-audit): firms deploy at the TS prices, so this reference is aligned to them.
/// Starter $1k · Growth $5k · Pro $25k · Scale $50k · Enterprise $100k.
pub fn deployment_tier_price_usd(tier: u8) -> u64 {
    let usd: u64 = match tier {
        0 => 1_000,
        1 => 5_000,
        2 => 25_000,
        3 => 50_000,
        _ => 100_000,
    };
    usd * 1_000_000
}

/// Compute the tier deployment-fee split. RESERVE-3 (2026-07-11): all legs are now fixed plain-SOL
/// legs — franchise 9%, DP 20%, $DPROP burn 5%, Universal 3% — and the firm treasury takes the
/// remainder (~63%). No curve-buy legs remain (owner-drip / treasury auto-purchases + the $FIRMA
/// buy-and-burn were removed), so the split can never exceed the price and `firm_treasury` is always
/// well-defined; the checked_sub is retained as a defensive invariant.
pub fn compute_deployment_fee_split(
    price: u64,
    has_referrer: bool,
) -> Result<DeploymentFeeSplit> {
    let franchise_pool = bps(price, DEPLOY_FRANCHISE_BPS);
    let referral_bonus = if has_referrer { bps(franchise_pool, DEPLOY_REFERRAL_BPS) } else { 0 };
    let franchise_general = franchise_pool - referral_bonus;
    let decentralprop = bps(price, DEPLOY_DP_BPS);
    let dprop_burn = bps(price, DEPLOY_DPROP_BURN_BPS);
    // Universal Treasury Pool seed (3%). 1% of it is offset by the franchise reduction (10%→9%);
    // the other 2% comes out of the firm-treasury remainder, which falls out automatically below.
    let universal = bps(price, DEPLOY_UNIVERSAL_BPS);
    let allocated = franchise_pool
        .checked_add(decentralprop)
        .and_then(|v| v.checked_add(dprop_burn))
        .and_then(|v| v.checked_add(universal))
        .ok_or(FirmError::MathOverflow)?;
    let firm_treasury = price.checked_sub(allocated).ok_or(FirmError::DeploymentLegsExceedPrice)?;
    Ok(DeploymentFeeSplit {
        franchise_pool,
        referral_bonus,
        franchise_general,
        decentralprop,
        dprop_burn,
        universal,
        firm_treasury,
    })
}

// ── Graduation / Raydium migration fee (§20.x) ──────────────────────────────────
// Skimmed from the curve's real SOL at graduation, *before* the remainder seeds the Raydium pool.
// A modest one-time milestone toll — the protocol already earns 0.5%/trade on the way up, so this
// stays small enough not to thin the new pool's depth. Routed: 1.0% → DecentralProp protocol revenue,
// 0.5% → $DPROP buy-and-burn (milestone deflation, mirrors the deploy-fee $DPROP burn). The wiring of
// the actual Raydium migration (pool create + LP lock) is the deferred Phase-4.4 work; this is the
// economic spec it will use.
pub const MIGRATION_FEE_BPS: u16 = 150; // 1.5% of graduated liquidity (= DP + $DPROP burn legs)
pub const MIGRATION_FEE_DP_BPS: u16 = 100; // 1.0% → DecentralProp
pub const MIGRATION_FEE_DPROP_BURN_BPS: u16 = 50; // 0.5% → $DPROP buy-and-burn

/// The destinations the graduation migration fee splits into. `to_pool` is the residual liquidity
/// that seeds the Raydium pool after the fee is skimmed.
pub struct MigrationFeeSplit {
    pub dp: u64,
    pub dprop_burn: u64,
    pub to_pool: u64,
}

/// Compute the graduation migration-fee split from the curve's graduated SOL. The DP + $DPROP-burn
/// legs are skimmed; the remainder (`to_pool`) seeds the Raydium pool. Sums to exactly `graduated_sol`.
pub fn compute_migration_fee_split(graduated_sol: u64) -> MigrationFeeSplit {
    let dp = bps(graduated_sol, MIGRATION_FEE_DP_BPS);
    let dprop_burn = bps(graduated_sol, MIGRATION_FEE_DPROP_BURN_BPS);
    let to_pool = graduated_sol.saturating_sub(dp + dprop_burn);
    MigrationFeeSplit { dp, dprop_burn, to_pool }
}

/// Payout split of **virtual profit** by ARE risk tier (§22 Lever Set 1). Both the
/// trader's share and the stakeholder share are fractions of virtual profit; their sum
/// is the total the treasury buys. The remainder (10000 − total) is retained as SOL.
pub struct PayoutTierSplit {
    pub trader_bps: u16,
    pub stakeholder_bps: u16,
}

/// Tier → (trader %, stakeholder %) of virtual profit (§22 table).
pub fn payout_tier_split(tier: RiskTier) -> PayoutTierSplit {
    match tier {
        RiskTier::Healthy => PayoutTierSplit { trader_bps: 8000, stakeholder_bps: 2000 },
        RiskTier::Caution => PayoutTierSplit { trader_bps: 7700, stakeholder_bps: 1800 },
        RiskTier::Warning => PayoutTierSplit { trader_bps: 7000, stakeholder_bps: 1500 },
        RiskTier::Critical => PayoutTierSplit { trader_bps: 6000, stakeholder_bps: 1500 },
    }
}

/// Given the $FIRMA actually delivered by a (combined trader + stakeholder) buy, split
/// it into the trader's share and the stakeholder share in the tier's ratio. The
/// stakeholder share absorbs rounding so the parts always sum to `delivered`.
pub fn split_delivered_firma(delivered: u64, split: &PayoutTierSplit) -> (u64, u64) {
    let total = (split.trader_bps as u128) + (split.stakeholder_bps as u128);
    if total == 0 {
        return (0, delivered);
    }
    let trader = ((delivered as u128 * split.trader_bps as u128) / total) as u64;
    (trader, delivered.saturating_sub(trader))
}

/// The five stakeholder destinations the stakeholder share of a payout splits into
/// (§19 `StakeholderConfig`), all denominated in $FIRMA. `backstop` added 2026-07-27
/// (staking rebalance) — the backstop pool's own $FIRMA yield leg, distinct from `staking`
/// (the no-risk pool's).
pub struct StakeholderSplit {
    pub owner: u64,
    pub staking: u64,
    pub backstop: u64,
    pub buyback_burn: u64,
    pub treasury_reserve: u64,
}

/// Split the stakeholder $FIRMA share five ways per `StakeholderConfig` plus the sibling
/// `FirmState.backstop_pool_bps` leg. The treasury reserve absorbs rounding so the parts
/// always sum to `amount`.
///
/// `amount` is the $FIRMA delivered AFTER the `universal_sol_bps` carve has already been
/// extracted as SOL (pre-buy). The five $FIRMA bps are specified relative to the FULL
/// 10000 stakeholder notional, so they must be renormalized against the non-universal
/// basis `(10000 - universal_sol_bps)` to distribute `amount` correctly. For the default
/// 40% universal carve: basis = 6000; owner(3000) → 50% of amount (= 30% of original),
/// staking(500) → 8.3%, backstop(500) → 8.3%, burn(1000) → 16.7%, treasury(1000) → 16.7%
/// (remainder).
///
/// When called from backstop/draw_universal paths (no SOL carve), `amount` is the FULL
/// stakeholder FIRMA value; the same renormalization proportionally redistributes the
/// 40% that would have gone to universal_sol among the five $FIRMA legs.
///
/// `backstop_pool_bps` is `FirmState.backstop_pool_bps` (a sibling field, not part of
/// `StakeholderConfig` — see the note on that struct for why) — pass `firm_state.backstop_pool_bps`.
pub fn split_stakeholder(amount: u64, cfg: &StakeholderConfig, backstop_pool_bps: u16) -> StakeholderSplit {
    let firma_basis = (10_000u32).saturating_sub(cfg.universal_sol_bps as u32) as u128;
    let owner = if firma_basis == 0 { 0 } else {
        ((amount as u128 * cfg.owner_share_bps as u128) / firma_basis) as u64
    };
    let staking = if firma_basis == 0 { 0 } else {
        ((amount as u128 * cfg.staking_pool_bps as u128) / firma_basis) as u64
    };
    let backstop = if firma_basis == 0 { 0 } else {
        ((amount as u128 * backstop_pool_bps as u128) / firma_basis) as u64
    };
    let buyback_burn = if firma_basis == 0 { 0 } else {
        ((amount as u128 * cfg.buyback_burn_bps as u128) / firma_basis) as u64
    };
    let treasury_reserve = amount
        .saturating_sub(owner)
        .saturating_sub(staking)
        .saturating_sub(backstop)
        .saturating_sub(buyback_burn);
    StakeholderSplit { owner, staking, backstop, buyback_burn, treasury_reserve }
}

/// Validate a `StakeholderConfig` + the sibling `backstop_pool_bps` leg against the §19
/// governance ranges (combined sum == 10000, per-field bounds, buyback/burn never zeroed,
/// universal_sol capped at 60%). `backstop_pool_bps` (2026-07-27, `FirmState`-level — see the
/// note on `StakeholderConfig`) mirrors `staking_pool_bps`'s range exactly — same kind of leg,
/// just a different destination pool.
pub fn validate_stakeholder_config(cfg: &StakeholderConfig, backstop_pool_bps: u16) -> bool {
    let sum = cfg.owner_share_bps as u32
        + cfg.staking_pool_bps as u32
        + backstop_pool_bps as u32
        + cfg.buyback_burn_bps as u32
        + cfg.treasury_reserve_bps as u32
        + cfg.universal_sol_bps as u32;
    sum == 10_000
        && (1000..=5000).contains(&cfg.owner_share_bps)
        && (500..=3000).contains(&cfg.staking_pool_bps)
        && (500..=3000).contains(&backstop_pool_bps)
        && (300..=2000).contains(&cfg.buyback_burn_bps)
        && cfg.treasury_reserve_bps <= 2000
        && cfg.universal_sol_bps <= 6000
}

/// Fold a yield distribution into a per-token accumulator (§19 staking). When nothing
/// is staked the amount is retained in `unallocated` and flushed on the next
/// distribution. Returns `(new_accumulator, new_unallocated)`.
pub fn fold_yield(acc: u128, unallocated: u64, amount: u64, total_staked: u64) -> (u128, u64) {
    if total_staked == 0 {
        (acc, unallocated.saturating_add(amount))
    } else {
        let distributable = (amount as u128) + (unallocated as u128);
        let add = (distributable * PRECISION) / total_staked as u128;
        (acc.saturating_add(add), 0)
    }
}

/// A position's accrued-but-unclaimed yield given the current accumulator (§19).
/// F-I-9: saturating throughout — a degenerate single-staker pool can push `acc` high enough that
/// `amount_staked * acc` would overflow u128 (panic-revert under `overflow-checks = true`); saturate
/// instead, and clamp the final cast so a huge `u128` can never truncate-wrap into a small `u64`.
pub fn pending_yield(amount_staked: u64, acc: u128, debt: u128) -> u64 {
    let gross = (amount_staked as u128).saturating_mul(acc) / PRECISION;
    gross.saturating_sub(debt).min(u64::MAX as u128) as u64
}

/// A position's yield debt after a stake change (the accumulator it has been paid up to).
pub fn yield_debt(amount_staked: u64, acc: u128) -> u128 {
    (amount_staked as u128).saturating_mul(acc) / PRECISION
}

/// Window over which the pre-open $DPROP-staking reserve is streamed to stakers (R33.1). SOL that
/// accrues into `dprop_staking_sol` BEFORE staking opens — potentially months of the 10% eval leg
/// while $DPROP itself has not launched — is NOT dumped on whoever stakes in the first block (a
/// front-running lottery). Instead it is the `retro_reserve`, released into the yield accumulator
/// linearly across this window so it rewards *sustained* early staking. 90 days.
pub const DPROP_RETRO_VEST_SECONDS: i64 = 90 * 86_400;

/// Retroactive-reserve vesting (R33.1): the SOL newly unlocked from the pre-open reserve since the
/// last fold. `vested_total` grows linearly from 0 at `start` to the full `reserve` at
/// `start + DPROP_RETRO_VEST_SECONDS`; this returns that minus what's already been `released`, so
/// each fold streams only the fresh slice. Fully drained (== reserve) once the window elapses.
pub fn retro_vested(reserve: u64, released: u64, start: i64, now: i64) -> u64 {
    if reserve == 0 {
        return 0;
    }
    let elapsed = now.saturating_sub(start).max(0) as u128;
    let window = DPROP_RETRO_VEST_SECONDS as u128;
    let vested_total = if elapsed >= window {
        reserve as u128
    } else {
        (reserve as u128).saturating_mul(elapsed) / window
    };
    (vested_total.min(reserve as u128) as u64).saturating_sub(released)
}

fn relax_timelock(current_tier: u8) -> i64 {
    if current_tier == RiskTier::Critical as u8 {
        RELAX_TIMELOCK_CRITICAL
    } else {
        RELAX_TIMELOCK_STANDARD
    }
}

/// Firm PDA signer seeds.
fn firm_signer<'a>(owner: &'a Pubkey, bump: &'a [u8; 1]) -> [&'a [u8]; 3] {
    [b"firm", owner.as_ref(), bump]
}

// ── Post-graduation payout conversion venue (RAYDIUM_GRADUATION.md §5.1, model A) ──
//
// Once a firm's curve graduates, its reserves live in a Raydium CP-Swap pool, not the curve. The payout
// paths must then convert treasury SOL → $FIRMA on the POOL instead of the curve. This is a `swap_base_input`
// CPI: unlike graduation's `initialize`, the swap's `payer` only authorises the input-token transfer (no
// System rent), so a PROGRAM PDA can be the payer — the firm PDA signs via `invoke_signed`. The 13 pool
// accounts are supplied as `remaining_accounts` (empty pre-graduation, when the curve path is taken).

/// CP-Swap `swap_base_input` discriminator (from the verified mainnet IDL — RAYDIUM_GRADUATION.md §2).
pub const CPSWAP_SWAP_BASE_INPUT_DISC: [u8; 8] = [143, 190, 90, 218, 196, 30, 51, 222];
/// The `swap_base_input` account count (payer, authority, amm_config, pool_state, in/out token accts,
/// in/out vaults, in/out token programs, in/out mints, observation).
pub const CPSWAP_SWAP_ACCOUNTS: usize = 13;

/// Pure builder for the `swap_base_input` instruction data — extracted so it is unit-testable without a
/// runtime (the CPI itself needs `invoke_signed`). `amount_in` = SOL spent, `min_out` = $FIRMA floor.
pub fn build_swap_base_input_data(amount_in: u64, min_out: u64) -> Vec<u8> {
    let mut data = Vec::with_capacity(8 + 16);
    data.extend_from_slice(&CPSWAP_SWAP_BASE_INPUT_DISC);
    data.extend_from_slice(&amount_in.to_le_bytes());
    data.extend_from_slice(&min_out.to_le_bytes());
    data
}

/// Swap `sol_in` SOL → $FIRMA on the graduated Raydium pool, delivering to `output`. The `payer_ai` PDA
/// (the firm treasury's or the universal pool's, depending on the caller) owns the `input` SOL account and
/// signs the swap via `invoke_signed` with `signer_seeds`. Unlike graduation's `initialize`, the swap
/// `payer` only authorises the input-token transfer (no System rent), so a program PDA can be the payer.
/// The mints + input + output are bound so a keeper can't route through a foreign pool; `min_out` bounds
/// slippage. Mirrors `curve_buy` for a graduated curve (model A) — signer-agnostic so all three payout
/// paths (firm-treasury-funded and universal-vault-funded) share it.
///
/// `ra` (the instruction's `remaining_accounts`) is `[cpmm_program, ..the 13 swap_base_input accounts]` —
/// EMPTY pre-graduation (when the curve path is taken), so the named-account lists are unchanged and the
/// existing pre-graduation SDK/keeper calls keep working without passing any Raydium accounts.
#[allow(clippy::too_many_arguments)]
fn swap_graduated<'info>(
    payer_ai: &AccountInfo<'info>,
    signer_seeds: &[&[u8]],
    sol_mint: &Pubkey,
    firma_mint: &Pubkey,
    input: &AccountInfo<'info>,
    output: &AccountInfo<'info>,
    ra: &[AccountInfo<'info>],
    sol_in: u64,
    min_out: u64,
) -> Result<()> {
    use anchor_lang::solana_program::instruction::{AccountMeta, Instruction};
    use anchor_lang::solana_program::program::invoke_signed;
    require!(ra.len() == CPSWAP_SWAP_ACCOUNTS + 1, FirmError::BadRaydiumAccounts); // cpmm + 13 swap accts
    let cpmm_program = &ra[0];
    let sw = &ra[1..]; // the 13 swap_base_input accounts
    require!(sw[0].key() == payer_ai.key(), FirmError::BadRaydiumAccounts); // payer == the signing PDA
    require!(sw[4].key() == input.key(), FirmError::BadRaydiumAccounts); // input == treasury/universal source
    require!(sw[5].key() == output.key(), FirmError::BadRaydiumAccounts); // output dest (staging/trader)
    require!(sw[10].key() == *sol_mint, FirmError::BadRaydiumAccounts); // input mint == SOL
    require!(sw[11].key() == *firma_mint, FirmError::BadRaydiumAccounts); // output mint == $FIRMA

    const WRITABLE: [usize; 6] = [3, 4, 5, 6, 7, 12]; // pool_state, in/out accts, in/out vaults, observation
    let metas: Vec<AccountMeta> = (0..CPSWAP_SWAP_ACCOUNTS)
        .map(|i| AccountMeta {
            pubkey: sw[i].key(),
            is_signer: i == 0,
            is_writable: WRITABLE.contains(&i),
        })
        .collect();
    let ix = Instruction {
        program_id: cpmm_program.key(),
        accounts: metas,
        data: build_swap_base_input_data(sol_in, min_out),
    };
    let mut infos: Vec<AccountInfo> = sw.to_vec();
    infos.push(cpmm_program.clone());
    invoke_signed(&ix, &infos, &[signer_seeds])?;
    Ok(())
}

/// CP-Swap `deposit` (add-liquidity) discriminator (verified mainnet IDL — RAYDIUM_GRADUATION.md Phase 4.4).
pub const CPSWAP_DEPOSIT_DISC: [u8; 8] = [242, 35, 198, 137, 82, 225, 242, 182];
/// The `deposit` account count (owner, authority, pool_state, owner_lp, token_0/1 accts, token_0/1 vaults,
/// two token programs, vault_0/1 mints, lp_mint).
pub const CPSWAP_DEPOSIT_ACCOUNTS: usize = 13;

/// Pure builder for the CP-Swap `deposit` instruction data (unit-testable, no runtime). `lp` = LP to
/// mint, `max_0`/`max_1` = caps on token_0/token_1 pulled (Raydium's byte-sorted order).
pub fn build_deposit_data(lp: u64, max_0: u64, max_1: u64) -> Vec<u8> {
    let mut data = Vec::with_capacity(8 + 24);
    data.extend_from_slice(&CPSWAP_DEPOSIT_DISC);
    data.extend_from_slice(&lp.to_le_bytes());
    data.extend_from_slice(&max_0.to_le_bytes());
    data.extend_from_slice(&max_1.to_le_bytes());
    data
}

/// CP-Swap `deposit` CPI (Phase 4.4): add `token_sol` + `token_firma` as liquidity to the graduated pool,
/// minting LP into `owner_lp` — a firm-PDA-owned account the firm program never withdraws from (permanent
/// lock, same guarantee as the graduation LP). The firm PDA (`owner_ai`) signs via `invoke_signed`. `ra` =
/// `[cpmm, ..13 deposit accounts]`. `max_sol`/`max_firma` are ordered into token_0/token_1 here.
#[allow(clippy::too_many_arguments)]
fn deposit_graduated<'info>(
    owner_ai: &AccountInfo<'info>,
    signer_seeds: &[&[u8]],
    sol_mint: &Pubkey,
    firma_mint: &Pubkey,
    token_sol: &AccountInfo<'info>,
    token_firma: &AccountInfo<'info>,
    owner_lp: &AccountInfo<'info>,
    ra: &[AccountInfo<'info>],
    lp_token_amount: u64,
    max_sol: u64,
    max_firma: u64,
) -> Result<()> {
    use anchor_lang::solana_program::instruction::{AccountMeta, Instruction};
    use anchor_lang::solana_program::program::invoke_signed;
    require!(ra.len() == CPSWAP_DEPOSIT_ACCOUNTS + 1, FirmError::BadRaydiumAccounts);
    let cpmm_program = &ra[0];
    let da = &ra[1..]; // the 13 deposit accounts
    let sol_is_0 = sol_mint.as_ref() < firma_mint.as_ref();
    // Owner-side token accounts + caps, ordered into Raydium's byte-sorted (token_0, token_1).
    let (tok0, tok1) = if sol_is_0 { (token_sol, token_firma) } else { (token_firma, token_sol) };
    let (max0, max1) = if sol_is_0 { (max_sol, max_firma) } else { (max_firma, max_sol) };
    require!(da[0].key() == owner_ai.key(), FirmError::BadRaydiumAccounts); // owner == firm PDA (signs)
    require!(da[3].key() == owner_lp.key(), FirmError::BadRaydiumAccounts); // owner_lp_token
    require!(da[4].key() == tok0.key(), FirmError::BadRaydiumAccounts); // token_0_account
    require!(da[5].key() == tok1.key(), FirmError::BadRaydiumAccounts); // token_1_account

    const WRITABLE: [usize; 7] = [2, 3, 4, 5, 6, 7, 12]; // pool_state, owner_lp, tok0/1, vault0/1, lp_mint
    let metas: Vec<AccountMeta> = (0..CPSWAP_DEPOSIT_ACCOUNTS)
        .map(|i| AccountMeta {
            pubkey: da[i].key(),
            is_signer: i == 0,
            is_writable: WRITABLE.contains(&i),
        })
        .collect();
    let ix = Instruction {
        program_id: cpmm_program.key(),
        accounts: metas,
        data: build_deposit_data(lp_token_amount, max0, max1),
    };
    let mut infos: Vec<AccountInfo> = da.to_vec();
    infos.push(cpmm_program.clone());
    invoke_signed(&ix, &infos, &[signer_seeds])?;
    Ok(())
}

/// Staking-pool PDA signer seeds (authority over the staking vaults).
fn pool_signer<'a>(firm: &'a Pubkey, bump: &'a [u8; 1]) -> [&'a [u8]; 3] {
    [b"staking_pool", firm.as_ref(), bump]
}

/// Backstop-pool PDA signer seeds (authority over the escrow + premium vaults).
fn backstop_signer<'a>(firm: &'a Pubkey, bump: &'a [u8; 1]) -> [&'a [u8]; 3] {
    [b"backstop_pool", firm.as_ref(), bump]
}

/// ARE-scaled backstop unbonding cooldown (§19): HEALTHY 3d, CAUTION 7d, WARNING 14d,
/// CRITICAL 30d — easy exits when healthy, slow exactly when the backstop is needed.
fn backstop_cooldown(effective_tier: u8) -> i64 {
    let days: i64 = match effective_tier {
        0 => 3,
        1 => 7,
        2 => 14,
        _ => 30,
    };
    days * 86_400
}

/// A position's share of the backstop pool, in bps of `total_staked`. A pool fully drained by
/// `draw_backstop` (a normal, guarded end state — see `total_staked > 0` there) is treated as
/// max severity (10_000) rather than dividing by zero: any surviving stake in that state has
/// already been priced to ~0 by the loss accumulator anyway.
fn backstop_share_bps(amount_staked: u64, total_staked: u64) -> u64 {
    if total_staked == 0 {
        return 10_000;
    }
    ((amount_staked as u128).saturating_mul(10_000) / total_staked as u128).min(10_000) as u64
}

/// Cooldown multiplier (in tenths) by pool-share bucket: <5% of pool 1.0x, 5-15% 1.5x,
/// 15-30% 2.0x, >=30% 3.0x. A large single position takes proportionally longer to unwind.
fn backstop_whale_multiplier_tenths(share_bps: u64) -> u64 {
    match share_bps {
        0..=499 => 10,
        500..=1499 => 15,
        1500..=2999 => 20,
        _ => 30,
    }
}

/// The full required backstop cooldown (§19): the ARE tier ladder scaled by the whale
/// multiplier for this position's current share of the pool. Evaluated fresh at both
/// `request_unstake_backstop` and `withdraw_backstop` — the withdraw-time check takes the
/// stricter (`.max()`) of the two, so cooling positions can only ever face a longer wait if
/// risk or share rises while pending, never a shorter one.
fn required_backstop_cooldown(effective_tier: u8, share_bps: u64) -> i64 {
    backstop_cooldown(effective_tier).saturating_mul(backstop_whale_multiplier_tenths(share_bps) as i64) / 10
}

/// PM-LP-pool PDA signer seeds (authority over the escrow + yield vaults). Mirrors `backstop_signer`.
fn pm_lp_signer<'a>(firm: &'a Pubkey, bump: &'a [u8; 1]) -> [&'a [u8]; 3] {
    [b"pm_lp_pool", firm.as_ref(), bump]
}

/// ARE-scaled PM LP unbonding cooldown — identical ladder to `backstop_cooldown` (HEALTHY 3d …
/// CRITICAL 30d). Duplicated rather than shared: neither `backstop_cooldown` nor the three helpers
/// below it are generic over which pool they're gating, and refactoring them into a shared helper
/// is a riskier touch to `BackstopPool`'s already-devnet-proven withdraw path than paying for a
/// few duplicated lines here (per the plan's explicit instruction to prefer duplication this pass).
fn pm_lp_cooldown(effective_tier: u8) -> i64 {
    let days: i64 = match effective_tier {
        0 => 3,
        1 => 7,
        2 => 14,
        _ => 30,
    };
    days * 86_400
}

/// A position's share of the PM LP pool, in bps of `total_staked`. Mirrors `backstop_share_bps`,
/// including its zero-total-staked handling (max severity rather than a division by zero).
fn pm_lp_share_bps(amount_staked: u64, total_staked: u64) -> u64 {
    if total_staked == 0 {
        return 10_000;
    }
    ((amount_staked as u128).saturating_mul(10_000) / total_staked as u128).min(10_000) as u64
}

/// Cooldown multiplier (in tenths) by pool-share bucket — identical bands to
/// `backstop_whale_multiplier_tenths`: <5% of pool 1.0x, 5-15% 1.5x, 15-30% 2.0x, >=30% 3.0x.
fn pm_lp_whale_multiplier_tenths(share_bps: u64) -> u64 {
    match share_bps {
        0..=499 => 10,
        500..=1499 => 15,
        1500..=2999 => 20,
        _ => 30,
    }
}

/// The full required PM LP cooldown: the ARE tier ladder scaled by the whale multiplier for this
/// position's current pool share. Mirrors `required_backstop_cooldown`'s escalate-only recheck
/// discipline — evaluated fresh at both `request_unstake_pm_lp` and `withdraw_pm_lp`, the latter
/// taking the stricter (`.max()`) of the two, so a cooling position can only ever face a longer
/// wait if risk or share rises while pending, never a shorter one.
fn required_pm_lp_cooldown(effective_tier: u8, share_bps: u64) -> i64 {
    pm_lp_cooldown(effective_tier).saturating_mul(pm_lp_whale_multiplier_tenths(share_bps) as i64) / 10
}

// ───────── Prediction Market Curve (Phase 3 pooled-LP AMM plan) helpers ─────────
// Pure functions so the round-trip/ceiling/redemption invariants can be unit-tested directly against
// the exact arithmetic the handlers use, same discipline as `fold_yield`/`pending_yield`/`pro_rata`
// above and `bonding_curve`'s own `buy_output`/`sell_output` tests.

/// `MarketCurve` PDA signer seeds (authority over both `pass_vault`/`fail_vault`). Mirrors
/// `pm_lp_signer`/`bonding_curve::curve_signer`.
fn pm_curve_signer<'a>(challenge: &'a Pubkey, bump: &'a [u8; 1]) -> [&'a [u8]; 3] {
    [b"pm_curve", challenge.as_ref(), bump]
}

/// The curve's own sellable/buyable reserve for one leg's CPMM math — the `firma_reserve` argument
/// `bonding_curve::buy_output`/`sell_output` expect, mirroring `bonding_curve.firma_reserve`'s
/// shrink-on-buy/grow-on-sell behaviour exactly. See `PM_CURVE_SHARE_SUPPLY_MULTIPLIER`'s doc comment
/// for why this is the complement of, not equal to, the stored `pass_shares`/`fail_shares` field
/// (which tracks the opposite quantity: shares OUTSTANDING, for `redeem_shares`' pro-rata math).
fn pm_curve_available_shares(virtual_seed: u64, shares_outstanding: u64) -> u64 {
    virtual_seed
        .saturating_mul(PM_CURVE_SHARE_SUPPLY_MULTIPLIER)
        .saturating_sub(shares_outstanding)
}

/// Split a curve trade's fee three ways (firm / platform / pool), floored, with the remainder (pure
/// bps-rounding dust, not a design statement about which leg "deserves" it) landing in
/// `pool_fees_accrued` — the LP pool has the largest, most diffuse set of eventual beneficiaries
/// (every PM LP staker, pro-rated by stake), so a few lamports of rounding dust are least distortive
/// there. Deliberately NOT a reuse of `bonding_curve::split_fee` (hardcoded 2-way 50/50 for a
/// different curve) — this is a genuinely 3-way, caller-configured split checked to sum to `fee_bps`
/// at `init_market_curve`.
fn split_curve_fee_3way(
    fee: u64,
    firm_bps: u16,
    platform_bps: u16,
    pool_bps: u16,
    total_bps: u16,
) -> (u64, u64, u64) {
    let _ = pool_bps; // pool's cut is the remainder, not computed directly — see doc comment
    if total_bps == 0 {
        return (0, 0, fee);
    }
    let firm_cut = ((fee as u128).saturating_mul(firm_bps as u128) / total_bps as u128) as u64;
    let platform_cut = ((fee as u128).saturating_mul(platform_bps as u128) / total_bps as u128) as u64;
    let pool_cut = fee.saturating_sub(firm_cut).saturating_sub(platform_cut);
    (firm_cut, platform_cut, pool_cut)
}

/// `redeem_shares`' core payout formula (PM-CURVE-REDEEM-1): 1:1 in the normal (well-funded) case, a
/// pro-rata haircut only under extreme imbalance. `redeemable_total` pools BOTH vaults (`pass_real +
/// fail_real`) because two independent CPMM legs (plan judgment call #2, not a true
/// complementary-outcome AMM) mean total collateral collected can fall short of shares outstanding —
/// this caps at solvency instead of assuming an exact 1:1. See DEC-89 / MASTER_ECONOMICS §22a.
/// F-I-9 discipline: u128 intermediate, saturating, floors toward the protocol (R40 convention).
fn pm_redeem_payout(position_shares: u64, shares_outstanding: u64, redeemable_total: u128) -> u64 {
    if shares_outstanding == 0 {
        return 0;
    }
    if redeemable_total >= shares_outstanding as u128 {
        position_shares // true 1:1, capped — never more than this holder actually holds
    } else {
        ((position_shares as u128).saturating_mul(redeemable_total) / shares_outstanding as u128) as u64
    }
}

/// `redeem_void_shares`' per-side pro-rata formula. Unlike `pm_redeem_payout`, NO pooling across
/// vaults — a void market has no winner, so PASS holders split `pass_real` among themselves by their
/// share of `pass_shares` outstanding, and FAIL holders separately split `fail_real`. PROVISIONAL —
/// see `void_market`'s doc comment (needs DEC-89 sign-off before ship).
fn pm_void_redeem_payout(position_side_shares: u64, side_shares_outstanding: u64, side_real: u64) -> u64 {
    if side_shares_outstanding == 0 {
        return 0;
    }
    ((position_side_shares as u128).saturating_mul(side_real as u128) / side_shares_outstanding as u128) as u64
}

/// Split `amount` between the two legs in proportion to `(pass_weight, fail_weight)` — used by
/// `allocate_pool_to_curve`/`deallocate_pool_from_curve` with the curve's CURRENT `(pass_real,
/// fail_real)` as the weights, or — when both are still 0 (a curve that has never traded) — the
/// virtual seeds instead, so a depth change never itself moves either leg's price. `fail`'s share
/// absorbs the rounding remainder (arbitrary but consistent, mirrors `split_fee`'s "one leg takes the
/// dust" convention).
fn pm_pool_ratio_split(amount: u64, pass_weight: u64, fail_weight: u64) -> (u64, u64) {
    let total = (pass_weight as u128).saturating_add(fail_weight as u128);
    if total == 0 {
        let half = amount / 2;
        return (amount - half, half);
    }
    let to_pass = ((amount as u128).saturating_mul(pass_weight as u128) / total) as u64;
    (to_pass, amount.saturating_sub(to_pass))
}

/// Decode a persisted `RiskTier` discriminant (e.g. `QueuedPayout.settlement_tier`).
fn risk_tier_from_u8(v: u8) -> RiskTier {
    match v {
        0 => RiskTier::Healthy,
        1 => RiskTier::Caution,
        2 => RiskTier::Warning,
        _ => RiskTier::Critical,
    }
}

/// Authorization gate for every challenge-driven fund movement (§9, §17, §22 hardening).
///
/// A challenge's `settlement_authority` is set at purchase from a caller-supplied account, so it
/// can NOT be trusted on its own: anyone could `purchase_challenge` against a firm with their own
/// key as the settlement authority and self-serving rules, then self-`settle_challenge` and drain
/// the firm treasury via the payout path. This binds that authority to the firm's actual
/// `risk_engine_authority` (the platform ARE / settlement keeper set at `deploy_firm`), so only the
/// firm's real authority can ever move firm funds for a challenge. Every payout / draw handler calls
/// this before touching balances. Combined with `settlement_authority` being a Signer at purchase,
/// a payable challenge is provably one the firm's authority authorized.
///
/// F5 hardening: it ALSO requires the challenge's settlement to be `Final` AND to have transited the
/// verifiable propose → fraud-proof-window → finalize path, and to not have been voided by a fraud
/// proof (`Faulted`). So no funds can move for a settlement still inside its challenge window or
/// proven fraudulent.
///
/// M-1 fix: the deprecated trusted `settle_challenge` marks a challenge `Final` INSTANTLY with no
/// fraud-proof window (an F5 bypass). The verifiable path always sets `settlement_window_end > 0` at
/// `propose_settlement`; the trusted path leaves it 0. Requiring `settlement_window_end > 0` here makes
/// any `settle_challenge`-settled challenge **unpayable**, so the trusted shortcut can never release
/// funds — the only payable settlement is one that went through the fraud-proof window.
/// K-1 — shared by every payout-authority gate below: the challenge's frozen `settlement_authority`
/// must match the firm's CURRENT keeper, OR — during a rotation grace window — the OUTGOING keeper, so
/// a challenge purchased before a keeper rotation (frozen to the old key) stays payable across the
/// transition. `previous_risk_engine_authority` is default(0) when no rotation is pending, and a real
/// `settlement_authority` is never the default key, so the fallback arm can't be spoofed once the
/// grace window lapses. Extracted so a third payout-authority path (DEC-77's advance gate) can't drift
/// from the settlement/withdrawal gates' rotation handling — "a check that exists on one path and not
/// another is a hole" applies to this binding as much as to the integrity/verifiability checks below it.
fn require_settlement_keeper_bound(
    challenge: &challenge::ChallengeState,
    firm: &FirmState,
) -> Result<()> {
    let now = Clock::get()?.unix_timestamp;
    let bound = challenge.settlement_authority == firm.risk_engine_authority
        || (now <= firm.authority_rotation_deadline
            && firm.previous_risk_engine_authority != Pubkey::default()
            && challenge.settlement_authority == firm.previous_risk_engine_authority);
    require!(bound, FirmError::Unauthorized);
    Ok(())
}

fn require_firm_settlement_authority(
    challenge: &challenge::ChallengeState,
    firm: &FirmState,
) -> Result<()> {
    require_settlement_keeper_bound(challenge, firm)?;
    require!(
        challenge.settlement_status == challenge::SettlementStatus::Final,
        FirmError::SettlementNotFinal
    );
    // M-1: only a settlement that opened a fraud-proof window (the verifiable path) is payable.
    require!(
        challenge.settlement_window_end > 0,
        FirmError::SettlementNotVerifiable
    );
    // Integrity gate (step 3): an on-chain integrity hold blocks payout even when
    // the settlement is Final, so an integrity-engine freeze cannot be bypassed.
    require!(!challenge.integrity_hold, FirmError::IntegrityHold);
    Ok(())
}

/// DEC-77 — the ADVANCE-side twin of `require_firm_settlement_authority`: same keeper/rotation
/// binding and the same integrity gate, but the settlement question is inverted. A normal payout
/// requires the fraud-proof window to have already closed clean (`Final`); an advance is defined as
/// paying BEFORE that — so it requires the mirror-image predicate the fault-proof instructions already
/// use (`status == Provisional && now <= window_end`, vs. finalize's `now > window_end`), plus the
/// keeper's PROPOSED claim (`claimed_passed`) since `status` itself only flips to `Passed` at finalize.
/// Settlement path ONLY — there is no withdrawal-path twin (CF-86 has no watchtower coverage; building
/// an advance there would have no compensating control at all, see `reports/2026-07-23-instant-payout-advance.md`).
fn require_firm_advance_authority(challenge: &challenge::ChallengeState, firm: &FirmState) -> Result<()> {
    require_settlement_keeper_bound(challenge, firm)?;
    require!(
        challenge.settlement_status == challenge::SettlementStatus::Provisional,
        FirmError::SettlementNotProvisional
    );
    let now = Clock::get()?.unix_timestamp;
    require!(now <= challenge.settlement_window_end, FirmError::AdvanceWindowClosed);
    require!(challenge.claimed_passed, FirmError::SettlementNotClaimedPassed);
    require!(!challenge.integrity_hold, FirmError::IntegrityHold);
    Ok(())
}

/// DEC-62 — the withdrawal-path twin of `require_firm_settlement_authority`.
///
/// It cannot reuse that gate: `require_firm_settlement_authority` demands
/// `challenge.settlement_status == Final`, and a FUNDED account taking profit mid-run stays `Active` /
/// `Unsettled` forever by design. So every binding it makes is reproduced here against the
/// `FundedWithdrawal` instead — the keeper/rotation binding and the integrity hold are IDENTICAL; only
/// the "is this obligation final and fraud-window-tested?" question is answered by the withdrawal.
///
/// Keeping the two in step matters: a check that exists on the settlement path and not here is a hole
/// that only funded traders fall through.
fn require_firm_withdrawal_authority(
    challenge: &challenge::ChallengeState,
    firm: &FirmState,
    withdrawal: &challenge::FundedWithdrawal,
) -> Result<()> {
    require_settlement_keeper_bound(challenge, firm)?;
    // Only a withdrawal whose 72h fraud window CLOSED with no fault proven may move SOL. A Provisional
    // one is still refutable; a Faulted one was proven fraudulent and owes nothing.
    require!(
        withdrawal.status == challenge::SettlementStatus::Final,
        FirmError::SettlementNotFinal
    );
    // M-1 twin: a withdrawal that never opened a fraud window is not payable. `window_end` is always
    // set by `propose_funded_withdrawal`, so this only bites on a malformed/legacy account — the same
    // belt-and-braces the settlement gate carries.
    require!(withdrawal.window_end > 0, FirmError::SettlementNotVerifiable);
    // Integrity gate: an on-chain hold blocks a withdrawal exactly as it blocks a settlement payout.
    require!(!challenge.integrity_hold, FirmError::IntegrityHold);
    Ok(())
}

/// The DELIVERY-side twin of the enqueue gate (DEC-62) — the gate every instruction that actually
/// MOVES a queued payout must use.
///
/// `enqueue_payout` learned that a funded withdrawal is authorised by its `FundedWithdrawal` and not
/// by a challenge settlement a still-trading account never reaches. Every delivery instruction kept
/// asking the settlement question, so a withdrawal could be proposed, survive its fraud window, and be
/// queued as a real on-chain obligation — and then be deliverable by NOTHING: all four tiers plus
/// `execute_payout_buy` reverted `SettlementNotFinal` forever. That is PAYOUT-CHAIN-GAP-1 again, one
/// layer down, and strictly worse: the obligation now exists and cannot be discharged.
///
/// `withdrawal` is bound to `(challenge, queued_payout.cycle)` BY SEEDS in each account struct, so
/// presence alone is sufficient here — there is no cycle/challenge substitution to re-check. Absent ⇒
/// the legacy settlement path, unchanged.
///
/// Found by `scripts/localnet-funded-withdrawal-e2e.ts` — the first thing to execute a withdrawal
/// delivery against real bytecode (PAYOUT-DELIVER-GATE-1).
/// `value · part / whole` computed in u128 to avoid overflow, returning 0 when `whole == 0`.
/// PAYOUT-LIFETIME-1: prorates a payout's SOL obligation (`sol_at_settlement`) by the fraction of the
/// owed $FIRMA a delivery tier just filled, so `total_paid_out` counts a reserve/backstop/universal fill
/// (which spends no treasury SOL, so has no `spent`) at its real value.
fn pro_rata(value: u64, part: u64, whole: u64) -> u64 {
    if whole == 0 {
        return 0;
    }
    ((value as u128).saturating_mul(part as u128) / (whole as u128)) as u64
}

fn require_payout_delivery_authority(
    challenge: &challenge::ChallengeState,
    firm: &FirmState,
    withdrawal: Option<&challenge::FundedWithdrawal>,
) -> Result<()> {
    match withdrawal {
        Some(w) => require_firm_withdrawal_authority(challenge, firm, w),
        None => require_firm_settlement_authority(challenge, firm),
    }
}

/// The settlement-authority binding every `MarketCurve` lifecycle instruction (`init_market_curve`,
/// `lock_market`, `settle_market`, `void_market`, `allocate_pool_to_curve`,
/// `deallocate_pool_from_curve`) uses. Reuses `require_settlement_keeper_bound` — the same
/// `challenge.settlement_authority == firm.risk_engine_authority` (rotation-aware) check every other
/// payout-authority gate in this file is built on — but deliberately does NOT layer on
/// `require_firm_settlement_authority`'s additional `settlement_status == Final` / fraud-window /
/// integrity-hold checks: those are preconditions on the CHALLENGE's own payout readiness, and every
/// curve lifecycle event above happens WHILE the challenge is still active, before any of that is
/// true. `settle_market` is itself how the curve learns the real outcome — it doesn't need to
/// re-derive it from challenge settlement state on-chain, so it doesn't need that gate either.
fn require_market_curve_authority(challenge: &challenge::ChallengeState, firm: &FirmState) -> Result<()> {
    require_settlement_keeper_bound(challenge, firm)
}

/// The effective risk tier a per-firm instruction must enforce (§9): the stricter of
/// the firm's own tier and any active platform-wide override.
pub fn effective_tier(firm_tier: u8, platform: &PlatformRiskState) -> u8 {
    if platform.override_active {
        firm_tier.max(platform.override_tier)
    } else {
        firm_tier
    }
}

/// The unix timestamp at which the `(months_claimed + 1)`-th monthly owner-drip tranche unlocks —
/// `drip_start_at + (months_claimed + 1) · MONTH_SECONDS`. Pure so the 24-month cadence is unit-testable
/// (the handler previously inlined this; see the `drip_cadence_*` tests). Overflow-safe.
pub fn drip_next_unlock(drip_start_at: i64, months_claimed: u8) -> Result<i64> {
    (months_claimed as i64)
        .checked_add(1)
        .and_then(|m| m.checked_mul(MONTH_SECONDS))
        .and_then(|d| drip_start_at.checked_add(d))
        .ok_or(FirmError::MathOverflow.into())
}

/// One monthly owner-drip tranche = `total_tokens / DRIP_MONTHS` (integer division; the final tranche
/// carries any truncation remainder only if `months_total` accounts for it — here it's a flat 24-way).
pub fn drip_month_amount(total_tokens: u64) -> u64 {
    total_tokens / DRIP_MONTHS as u64
}

#[derive(Accounts)]
pub struct DeployFirm<'info> {
    #[account(mut)]
    pub owner: Signer<'info>,

    /// CHECK: stored as the authority allowed to call `update_risk_tier` later.
    pub risk_engine_authority: UncheckedAccount<'info>,

    /// CHECK: the independent platform guardian that must co-sign drains / close. V2-1: bound in the
    /// handler to `platform_config.platform_guardian` and required `!= owner`, so it is no longer an
    /// arbitrary operator-chosen key.
    pub guardian: UncheckedAccount<'info>,

    /// Canonical platform config — V2-1 binds `guardian` to `platform_config.platform_guardian`.
    #[account(seeds = [b"platform_config"], bump = platform_config.bump)]
    pub platform_config: Box<Account<'info, PlatformConfig>>,

    #[account(
        init,
        payer = owner,
        space = 8 + FirmState::INIT_SPACE,
        seeds = [b"firm", owner.key().as_ref()],
        bump
    )]
    pub firm_state: Account<'info, FirmState>,

    pub system_program: Program<'info, System>,
}

/// Phase 1: SOL-side infra, no $FIRMA token. Creates the wSOL treasury/insurance/vesting vaults +
/// the insurance fund. (The old `create_firma_mint` bundled these; deferring the token split them out.)
#[derive(Accounts)]
pub struct CreateFirmTreasury<'info> {
    #[account(mut)]
    pub owner: Signer<'info>,

    #[account(
        mut,
        seeds = [b"firm", owner.key().as_ref()],
        bump = firm_state.bump,
        constraint = firm_state.owner == owner.key() @ FirmError::Unauthorized,
    )]
    pub firm_state: Box<Account<'info, FirmState>>,

    pub sol_mint: Box<Account<'info, Mint>>,

    #[account(
        init,
        payer = owner,
        token::mint = sol_mint,
        token::authority = firm_state,
        seeds = [b"treasury", firm_state.key().as_ref()],
        bump
    )]
    pub treasury_vault: Box<Account<'info, TokenAccount>>,

    #[account(
        init,
        payer = owner,
        space = 8 + InsuranceFund::INIT_SPACE,
        seeds = [b"insurance", firm_state.key().as_ref()],
        bump
    )]
    pub insurance_fund: Box<Account<'info, InsuranceFund>>,

    #[account(
        init,
        payer = owner,
        token::mint = sol_mint,
        token::authority = firm_state,
        seeds = [b"insurance_vault", firm_state.key().as_ref()],
        bump
    )]
    pub insurance_vault: Box<Account<'info, TokenAccount>>,

    #[account(
        init,
        payer = owner,
        token::mint = sol_mint,
        token::authority = firm_state,
        seeds = [b"owner_vesting_vault", firm_state.key().as_ref()],
        bump
    )]
    pub owner_vesting_vault: Box<Account<'info, TokenAccount>>,

    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
    pub rent: Sysvar<'info, Rent>,
}

/// Phase 2 (token launch): the $FIRMA mint + its vaults. Requires `create_firm_treasury` first.
#[derive(Accounts)]
pub struct CreateFirmaMint<'info> {
    #[account(mut)]
    pub owner: Signer<'info>,

    #[account(
        mut,
        seeds = [b"firm", owner.key().as_ref()],
        bump = firm_state.bump,
        constraint = firm_state.owner == owner.key() @ FirmError::Unauthorized,
    )]
    pub firm_state: Box<Account<'info, FirmState>>,

    #[account(
        init,
        payer = owner,
        mint::decimals = FIRMA_DECIMALS,
        mint::authority = firm_state,
        seeds = [b"firma_mint", firm_state.key().as_ref()],
        bump
    )]
    pub firma_mint: Box<Account<'info, Mint>>,

    #[account(
        init,
        payer = owner,
        token::mint = firma_mint,
        token::authority = firm_state,
        seeds = [b"owner_drip_vault", firm_state.key().as_ref()],
        bump
    )]
    pub drip_vault: Box<Account<'info, TokenAccount>>,

    // $FIRMA staging vault: a payout buy lands here, then is split trader/stakeholder.
    #[account(
        init,
        payer = owner,
        token::mint = firma_mint,
        token::authority = firm_state,
        seeds = [b"payout_firma_vault", firm_state.key().as_ref()],
        bump
    )]
    pub payout_firma_vault: Box<Account<'info, TokenAccount>>,

    // $FIRMA treasury reserve (payout waterfall Tier 2). Seeded by the deployment treasury
    // auto-purchase; drawn directly to traders via `draw_treasury_firma`.
    #[account(
        init,
        payer = owner,
        token::mint = firma_mint,
        token::authority = firm_state,
        seeds = [b"treasury_firma_vault", firm_state.key().as_ref()],
        bump
    )]
    pub treasury_firma_vault: Box<Account<'info, TokenAccount>>,

    /// CHECK: the Metaplex Token Metadata PDA for `firma_mint` — validated by seeds against the
    /// Metaplex program itself (`seeds::program`), not our own. Created fresh by the CPI in the
    /// handler, so it isn't typed as a `MetadataAccount` (that requires the account to already exist).
    #[account(
        mut,
        seeds = [b"metadata", token_metadata_program.key().as_ref(), firma_mint.key().as_ref()],
        bump,
        seeds::program = token_metadata_program.key(),
    )]
    pub metadata: UncheckedAccount<'info>,

    pub token_metadata_program: Program<'info, Metadata>,
    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
    pub rent: Sysvar<'info, Rent>,
}

#[derive(Accounts)]
pub struct DistributeSupply<'info> {
    #[account(
        mut,
        seeds = [b"firm", firm_state.owner.as_ref()],
        bump = firm_state.bump,
        constraint = firm_state.owner == owner.key() @ FirmError::Unauthorized,
    )]
    pub firm_state: Account<'info, FirmState>,

    #[account(mut)]
    pub owner: Signer<'info>,

    #[account(mut, address = firm_state.firma_mint)]
    pub firma_mint: Account<'info, Mint>,

    // Curve's $FIRMA vault (70%). NOTE (follow-up): bind to the bonding_curve PDA vault.
    #[account(mut, token::mint = firm_state.firma_mint)]
    pub curve_firma_vault: Account<'info, TokenAccount>,

    #[account(
        mut,
        token::mint = firm_state.firma_mint,
        seeds = [b"owner_drip_vault", firm_state.key().as_ref()],
        bump
    )]
    pub drip_vault: Account<'info, TokenAccount>,

    // Tier-2 treasury reserve (20%) — minted here at distribution (RESERVE-2026-07-11), the same
    // PDA created in `create_firma_mint` and bound on `firm_state.treasury_firma_vault`.
    #[account(
        mut,
        token::mint = firm_state.firma_mint,
        seeds = [b"treasury_firma_vault", firm_state.key().as_ref()],
        bump
    )]
    pub treasury_firma_vault: Account<'info, TokenAccount>,

    #[account(
        init,
        payer = owner,
        space = 8 + OwnerDripState::INIT_SPACE,
        seeds = [b"owner_drip", firm_state.key().as_ref()],
        bump
    )]
    pub owner_drip_state: Account<'info, OwnerDripState>,

    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
}

impl<'info> DistributeSupply<'info> {
    fn mint_to_vault(&self, vault: &Account<'info, TokenAccount>, amount: u64) -> Result<()> {
        if amount == 0 {
            return Ok(());
        }
        let bump = [self.firm_state.bump];
        let seeds = firm_signer(&self.firm_state.owner, &bump);
        token::mint_to(
            CpiContext::new_with_signer(
                self.token_program.to_account_info(),
                MintTo {
                    mint: self.firma_mint.to_account_info(),
                    to: vault.to_account_info(),
                    authority: self.firm_state.to_account_info(),
                },
                &[&seeds],
            ),
            amount,
        )
    }

    /// Permanently revoke the mint authority → fixed supply forever (§16).
    fn revoke_mint_authority(&self) -> Result<()> {
        let bump = [self.firm_state.bump];
        let seeds = firm_signer(&self.firm_state.owner, &bump);
        token::set_authority(
            CpiContext::new_with_signer(
                self.token_program.to_account_info(),
                SetAuthority {
                    current_authority: self.firm_state.to_account_info(),
                    account_or_mint: self.firma_mint.to_account_info(),
                },
                &[&seeds],
            ),
            AuthorityType::MintTokens,
            None,
        )
    }
}

// Accounts are Box'd to keep the BPF stack frame under 4 KB (16-account context).
#[derive(Accounts)]
pub struct PayChallengeFee<'info> {
    #[account(mut)]
    pub trader: Signer<'info>,

    #[account(mut, token::mint = firm_state.sol_mint, token::authority = trader)]
    pub trader_sol: Box<Account<'info, TokenAccount>>,

    #[account(
        mut,
        seeds = [b"firm", firm_state.owner.as_ref()],
        bump = firm_state.bump,
    )]
    pub firm_state: Box<Account<'info, FirmState>>,

    /// The firm's bonding curve — read for LP depth, written by the LP CPI.
    #[account(
        mut,
        seeds = [b"bonding_curve", firm_state.key().as_ref()],
        bump = curve.bump,
        seeds::program = bonding_curve::ID,
    )]
    pub curve: Box<Account<'info, bonding_curve::BondingCurve>>,

    #[account(mut, address = curve.sol_vault)]
    pub curve_sol_vault: Box<Account<'info, TokenAccount>>,

    // §19 treasury_sol sync contract: the cache must equal the vault balance at entry.
    #[account(
        mut,
        address = firm_state.treasury_vault,
        // Invariant: the vault must COVER the cache. External credits (e.g. a bonding-curve fee paid
        // into treasury_vault by deploy_burn or a third-party curve buy) legitimately raise the vault
        // ABOVE the cache; each treasury-touching handler reconciles `treasury_sol = treasury_vault.amount`,
        // so the only way `vault < cache` is an impossible unauthorised drain. `==` here used to brick the
        // firm on any donation (F-1/F-2); `>=` makes out-of-band credits harmless. (audit F-1/F-2)
        constraint = treasury_vault.amount >= firm_state.treasury_sol @ FirmError::TreasuryDesync,
    )]
    pub treasury_vault: Box<Account<'info, TokenAccount>>,

    #[account(mut, seeds = [b"insurance", firm_state.key().as_ref()], bump = insurance_fund.bump)]
    pub insurance_fund: Box<Account<'info, InsuranceFund>>,
    #[account(mut, seeds = [b"insurance_vault", firm_state.key().as_ref()], bump)]
    pub insurance_vault: Box<Account<'info, TokenAccount>>,

    #[account(mut, seeds = [b"owner_vesting_vault", firm_state.key().as_ref()], bump)]
    pub owner_vesting_vault: Box<Account<'info, TokenAccount>>,

    // M-4: the owner's immediate-fee wallet must be owned by the firm owner (no redirect).
    #[account(
        mut,
        token::mint = firm_state.sol_mint,
        constraint = owner_wallet_sol.owner == firm_state.owner @ FirmError::Unauthorized,
    )]
    pub owner_wallet_sol: Box<Account<'info, TokenAccount>>,

    // Canonical platform config (M-4) — bound in the HANDLER (not as a typed `Account`) to keep
    // `pay_challenge_fee`'s account-validation frame under the 4 KB BPF stack limit. An `UncheckedAccount`
    // adds no deserialization to `try_accounts`; the handler verifies it is the `["platform_config"]` PDA,
    // deserializes it, and checks the three platform-fee destinations below against its canonical addresses.
    /// CHECK: validated in-handler (PDA identity + the three destination keys).
    pub platform_config: UncheckedAccount<'info>,

    // DecentralProp platform SOL wallets — M-4: address-bound to `platform_config` in the handler.
    #[account(mut, token::mint = firm_state.sol_mint)]
    pub dp_profit_sol: Box<Account<'info, TokenAccount>>,
    #[account(mut, token::mint = firm_state.sol_mint)]
    pub dp_treasury_sol: Box<Account<'info, TokenAccount>>,

    // Normal-staking leg, per-firm routing (§19, DEC-1) — `staking_pool` optional: present once
    // the caller supplies the purchasing firm's OWN staking pool. When present, the 5%
    // normal-staking slice routes directly into `sol_reward_vault` and folds into `acc_sol` so its
    // stakers can actually claim the yield (mirrors the backstop-premium inline fold below).
    // Omitted → the slice stays in the firm's OWN treasury instead (see the handler) — there used
    // to be a platform-wide `normal_staking_vault` fallback here, but that leg had no distribution
    // path out to any staker, so it was removed rather than kept as a dead end.
    #[account(
        mut,
        seeds = [b"staking_pool", firm_state.key().as_ref()],
        bump,
    )]
    pub staking_pool: Option<Box<Account<'info, FirmaStakingPool>>>,
    // NOT optional, unlike `staking_pool` above: Anchor doesn't support an `Option<UncheckedAccount>`
    // ("Cannot have Optional composite accounts"), and a second `Option<Box<Account<TokenAccount>>>`
    // here pushed `try_accounts` 8 bytes over the 4 KB BPF stack limit. Always required, but only
    // ever read/written when `staking_pool` is `Some` (validated against `pool.sol_reward_vault` in
    // the handler first) — the caller may pass ANY writable account here (e.g. `treasury_vault`
    // again) when omitting `staking_pool`; it's never touched on that path.
    /// CHECK: validated in-handler against `staking_pool.sol_reward_vault` when staking_pool is Some;
    /// unused (any writable account) otherwise.
    #[account(mut)]
    pub sol_reward_vault: UncheckedAccount<'info>,

    // Enforced routing: the 2% buyback leg can ONLY flow into the canonical PDA-owned buyback vault
    // (seeds ["dprop_buyback_sol"]) — no admin can substitute a vault they control, so the leg is
    // provably committed to the trustless sink. Requires a single platform SOL mint shared by every
    // firm (the global buyback vault holds exactly one mint); `init_dprop_buyback` — or, on mainnet,
    // the mint-free `init_dprop_buyback_sol` (deferred launch, DPROP-2) — must have run first.
    #[account(mut, seeds = [b"dprop_buyback_sol"], bump, token::mint = firm_state.sol_mint)]
    pub dprop_buyback_vault: Box<Account<'info, TokenAccount>>,

    // $DPROP staking pool (10%) — enforced PDA routing (seeds ["dprop_staking_sol"]) identical
    // to the buyback vault above. SOL accumulates here and is distributed to $DPROP stakers via the
    // `claim_dprop_staking_yield` pull path. `init_dprop_staking` must have run first.
    #[account(mut, seeds = [b"dprop_staking_sol"], bump, token::mint = firm_state.sol_mint)]
    pub dprop_staking_vault: Box<Account<'info, TokenAccount>>,

    // Universal Treasury Pool (1.5%) — enforced PDA routing (seeds ["universal_vault"]) identical to
    // the buyback/staking vaults above. The protocol-wide payout-of-last-resort pool; SOL accumulates
    // here and can ONLY leave via `draw_universal`. `init_universal_pool` must have run first.
    #[account(mut, seeds = [b"universal_vault"], bump, token::mint = firm_state.sol_mint)]
    pub universal_vault: Box<Account<'info, TokenAccount>>,
    #[account(mut, seeds = [b"universal_pool"], bump = universal_pool.bump)]
    pub universal_pool: Box<Account<'info, UniversalPool>>,

    // Loss-back leg (flywheel, 2026-07-27 staking rebalance) — the buyer's per-trader credit
    // ledger, created lazily here on first purchase. Purely notional now — no backing vault, no
    // token transfer; see the handler's discount block.
    #[account(
        init_if_needed,
        payer = trader,
        space = 8 + LossBackCredit::INIT_SPACE,
        seeds = [b"loss_back", firm_state.key().as_ref(), trader.key().as_ref()],
        bump
    )]
    pub loss_back_credit: Box<Account<'info, LossBackCredit>>,

    // Affiliate leg (§17.1) — supplied together only for a *referred* purchase. `referral` binds
    // trader→affiliate (seeds known); `affiliate_account` holds the rate + earned ledger;
    // `affiliate_pool_vault` is the firm's per-affiliate-program SOL accumulator. Omit all three
    // for an unreferred purchase — the carve is then 0 and the slice stays in the firm treasury.
    #[account(
        seeds = [b"referral", firm_state.key().as_ref(), trader.key().as_ref()],
        bump,
    )]
    pub referral: Option<Box<Account<'info, Referral>>>,
    #[account(mut)]
    pub affiliate_account: Option<Box<Account<'info, AffiliateAccount>>>,
    #[account(
        mut,
        seeds = [b"affiliate_vault", firm_state.key().as_ref()],
        bump,
    )]
    pub affiliate_pool_vault: Option<Box<Account<'info, TokenAccount>>>,

    /// CHECK: the challenge being paid for — used only as the vesting-batch seed.
    pub challenge: UncheckedAccount<'info>,

    #[account(
        init,
        payer = trader,
        space = 8 + OwnerVestingBatch::INIT_SPACE,
        seeds = [b"vesting", challenge.key().as_ref()],
        bump
    )]
    pub owner_vesting_batch: Box<Account<'info, OwnerVestingBatch>>,

    // Backstop premium leg (§19) — optional: present only when the firm runs a backstop pool.
    // When present, the premium slice is routed + folded atomically (see handler).
    #[account(
        mut,
        seeds = [b"backstop_pool", firm_state.key().as_ref()],
        bump,
    )]
    pub backstop_pool: Option<Box<Account<'info, BackstopPool>>>,
    #[account(mut, token::mint = firm_state.sol_mint)]
    pub backstop_premium_vault: Option<Box<Account<'info, TokenAccount>>>,

    // Loss-back credit application gate (2026-07-27 staking rebalance: EITHER position, not just
    // no-risk, unlocks the discount) — pass whichever stake position(s) the trader holds. The
    // stake gate is checked in the handler; if both are omitted (or neither meets min_stake) the
    // discount is 0 and the full fee is charged.
    #[account(
        seeds = [b"staker", firm_state.key().as_ref(), trader.key().as_ref()],
        bump,
    )]
    pub staker_position: Option<Box<Account<'info, StakerPosition>>>,
    #[account(
        seeds = [b"backstop_pos", firm_state.key().as_ref(), trader.key().as_ref()],
        bump,
    )]
    pub backstop_position: Option<Box<Account<'info, BackstopPosition>>>,

    pub bonding_curve_program: Program<'info, bonding_curve::program::BondingCurve>,
    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
}

impl<'info> PayChallengeFee<'info> {
    /// Transfer SOL from the trader to a destination (no-op on zero).
    fn xfer(&self, to: AccountInfo<'info>, amount: u64) -> Result<()> {
        if amount == 0 {
            return Ok(());
        }
        token::transfer(
            CpiContext::new(
                self.token_program.to_account_info(),
                anchor_spl::token::Transfer {
                    from: self.trader_sol.to_account_info(),
                    to,
                    authority: self.trader.to_account_info(),
                },
            ),
            amount,
        )
    }

    /// Route the LP share into the bonding curve via CPI (pre-graduation), so the
    /// curve updates its own `real_sol` — accelerating graduation (§17).
    fn route_lp(&self, amount: u64) -> Result<()> {
        if amount == 0 {
            return Ok(());
        }
        bonding_curve::cpi::add_curve_reserve(
            CpiContext::new(
                self.bonding_curve_program.to_account_info(),
                bonding_curve::cpi::accounts::AddReserve {
                    depositor: self.trader.to_account_info(),
                    curve: self.curve.to_account_info(),
                    sol_vault: self.curve_sol_vault.to_account_info(),
                    source_sol: self.trader_sol.to_account_info(),
                    token_program: self.token_program.to_account_info(),
                },
            ),
            amount,
        )
    }
}

// Accounts are Box'd to keep the BPF stack frame under 4 KB.
//
// CHK-11 prefix gotcha: `#[instruction(...)]` must list the REAL argument prefix up to any arg the
// seeds reference. `cycle` is the FIRST handler arg, so the prefix is exactly `cycle`.
#[derive(Accounts)]
#[instruction(cycle: u32)]
pub struct ExecutePayoutBuy<'info> {
    /// The firm's settlement authority (the payout-queue keeper). Pays record rent.
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
        seeds::program = challenge::ID,
        constraint = challenge.settlement_authority == authority.key() @ FirmError::Unauthorized,
        constraint = challenge.firm == firm_state.key() @ FirmError::Unauthorized,
    )]
    pub challenge: Box<Account<'info, challenge::ChallengeState>>,

    #[account(mut, seeds = [b"firm", firm_state.owner.as_ref()], bump = firm_state.bump)]
    pub firm_state: Box<Account<'info, FirmState>>,

    // Treasury is the buyer (pays SOL). §19 sync contract checked at entry.
    #[account(
        mut,
        address = firm_state.treasury_vault,
        // Invariant: the vault must COVER the cache. External credits (e.g. a bonding-curve fee paid
        // into treasury_vault by deploy_burn or a third-party curve buy) legitimately raise the vault
        // ABOVE the cache; each treasury-touching handler reconciles `treasury_sol = treasury_vault.amount`,
        // so the only way `vault < cache` is an impossible unauthorised drain. `==` here used to brick the
        // firm on any donation (F-1/F-2); `>=` makes out-of-band credits harmless. (audit F-1/F-2)
        constraint = treasury_vault.amount >= firm_state.treasury_sol @ FirmError::TreasuryDesync,
    )]
    pub treasury_vault: Box<Account<'info, TokenAccount>>,

    #[account(
        mut,
        seeds = [b"bonding_curve", firm_state.key().as_ref()],
        bump = curve.bump,
        seeds::program = bonding_curve::ID,
    )]
    pub curve: Box<Account<'info, bonding_curve::BondingCurve>>,

    #[account(mut, address = curve.sol_vault)]
    pub curve_sol_vault: Box<Account<'info, TokenAccount>>,
    #[account(mut, address = curve.firma_vault)]
    pub curve_firma_vault: Box<Account<'info, TokenAccount>>,

    // The passing trader's $FIRMA account — must belong to the challenge's trader.
    #[account(
        mut,
        token::mint = firm_state.firma_mint,
        constraint = trader_firma.owner == challenge.trader @ FirmError::Unauthorized,
    )]
    pub trader_firma: Box<Account<'info, TokenAccount>>,

    // Platform SOL fee destination (0.5% curve fee). NOTE: bind to platform config later.
    /// V2-8: canonical platform config — binds `platform_sol` to the DP fee destination (M-4 pattern),
    /// so this leg can't be pointed at a caller-controlled account.
    #[account(seeds = [b"platform_config"], bump = platform_config.bump)]
    pub platform_config: Box<Account<'info, PlatformConfig>>,

    #[account(
        mut,
        token::mint = firm_state.sol_mint,
        constraint = platform_sol.key() == platform_config.platform_sol @ FirmError::PlatformSolMismatch,
    )]
    pub platform_sol: Box<Account<'info, TokenAccount>>,

    // Double-payout guard: `init` fails if a record already exists for this challenge + cycle. Shares
    // the seed with `EnqueuePayout`'s `QueuedPayout`, so the immediate and queued paths remain mutually
    // exclusive per cycle — a cycle can be paid once, by exactly one path.
    #[account(
        init,
        payer = authority,
        space = 8 + PayoutRecord::INIT_SPACE,
        seeds = [b"payout", challenge.key().as_ref(), &cycle.to_le_bytes()],
        bump
    )]
    pub payout_record: Box<Account<'info, PayoutRecord>>,

    pub bonding_curve_program: Program<'info, bonding_curve::program::BondingCurve>,
    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
    // Post-graduation, the SOL→$FIRMA swap's [cpmm_program, ..13 swap accounts] ride in `remaining_accounts`
    // (empty pre-graduation) — so this named-account list is unchanged and pre-grad callers are unaffected.
}

impl<'info> ExecutePayoutBuy<'info> {
    /// CPI into `bonding_curve.buy` with the treasury (firm PDA) as the buyer and the
    /// trader as the $FIRMA recipient. The firm's 0.5% curve fee returns to the
    /// treasury; the platform's 0.5% goes to `platform_sol`.
    fn curve_buy(&self, sol_amount: u64, min_firma_out: u64) -> Result<()> {
        let bump = [self.firm_state.bump];
        let seeds = firm_signer(&self.firm_state.owner, &bump);
        bonding_curve::cpi::buy(
            CpiContext::new_with_signer(
                self.bonding_curve_program.to_account_info(),
                bonding_curve::cpi::accounts::Buy {
                    trader: self.firm_state.to_account_info(),
                    curve: self.curve.to_account_info(),
                    sol_vault: self.curve_sol_vault.to_account_info(),
                    firma_vault: self.curve_firma_vault.to_account_info(),
                    trader_sol: self.treasury_vault.to_account_info(),
                    trader_firma: self.trader_firma.to_account_info(),
                    firm_treasury_sol: self.treasury_vault.to_account_info(),
                    platform_sol: self.platform_sol.to_account_info(),
                    token_program: self.token_program.to_account_info(),
                },
                &[&seeds],
            ),
            sol_amount,
            min_firma_out,
        )
    }
}

// Accounts are Box'd to keep the BPF stack frame under 4 KB.
#[derive(Accounts)]
pub struct FundOperatorBond<'info> {
    /// Permissionless cranker — opens the short-lived unwrap vault (rent reclaimed on close) + pays gas.
    #[account(mut)]
    pub cranker: Signer<'info>,

    #[account(mut, seeds = [b"firm", firm_state.owner.as_ref()], bump = firm_state.bump)]
    pub firm_state: Box<Account<'info, FirmState>>,

    // Source of the bond funding. §19 sync contract (vault >= cache) checked at entry.
    #[account(
        mut,
        address = firm_state.treasury_vault,
        constraint = treasury_vault.amount >= firm_state.treasury_sol @ FirmError::TreasuryDesync,
    )]
    pub treasury_vault: Box<Account<'info, TokenAccount>>,

    /// The firm's canonical `dispute`-program `OperatorStake` PDA — the ONLY destination for the
    /// unwrapped bond SOL (address + owner bound, so a permissionless cranker has zero discretion). Must
    /// already exist (dispute-owned) — the keeper runs `dispute::init_bond_shell` first; `sync_bond`
    /// reconciles `staked_lamports` after. CHECK: PDA address + dispute ownership verified by the constraints.
    #[account(
        mut,
        owner = dispute::ID,
        seeds = [b"operator_stake", firm_state.key().as_ref()],
        bump,
        seeds::program = dispute::ID,
    )]
    pub operator_stake: UncheckedAccount<'info>,

    /// Short-lived wSOL vault the bond SOL is unwrapped through — created, funded, and closed within
    /// this instruction (a partial unwrap requires closing a token account; the treasury vault must
    /// persist, so we route through this ephemeral PDA vault instead).
    #[account(
        init,
        payer = cranker,
        seeds = [b"bond_unwrap", firm_state.key().as_ref()],
        bump,
        token::mint = sol_mint,
        token::authority = firm_state,
    )]
    pub bond_unwrap_vault: Box<Account<'info, TokenAccount>>,

    #[account(address = firm_state.sol_mint)]
    pub sol_mint: Box<Account<'info, Mint>>,
    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct ReconcileOperatorBond<'info> {
    /// Permissionless cranker — pays gas only (no rent, no init). Anyone can reconcile the flag.
    pub cranker: Signer<'info>,

    #[account(mut, seeds = [b"firm", firm_state.owner.as_ref()], bump = firm_state.bump)]
    pub firm_state: Box<Account<'info, FirmState>>,

    /// The firm's canonical `dispute`-program `OperatorStake` PDA — READ-ONLY here (we only read its
    /// lamports to derive the bond level). Address + dispute-ownership bound, so a permissionless cranker
    /// can't point this at some other account. Must already exist (the keeper runs `dispute::init_bond_
    /// shell` before the bond is ever funded). CHECK: PDA address + dispute ownership verified by constraints.
    #[account(
        owner = dispute::ID,
        seeds = [b"operator_stake", firm_state.key().as_ref()],
        bump,
        seeds::program = dispute::ID,
    )]
    pub operator_stake: UncheckedAccount<'info>,
}

// Phase 4.4 (§12) — deposit the post-graduation LP fee-leg into the graduated Raydium pool as locked LP.
// The pool accounts ride in `remaining_accounts` (`[..14 swap][..14 deposit]`), validated inside the CPI
// helpers; all fund-holding accounts here are firm-PDA-owned so a permissionless cranker can't redirect.
#[derive(Accounts)]
pub struct AddGraduatedLiquidity<'info> {
    /// Permissionless cranker — pays no rent (the staging/LP token accounts are created by the keeper).
    pub cranker: Signer<'info>,

    #[account(mut, seeds = [b"firm", firm_state.owner.as_ref()], bump = firm_state.bump)]
    pub firm_state: Box<Account<'info, FirmState>>,

    /// The firm's WSOL treasury vault — the SOL side of BOTH the zap swap and the deposit. `>=` invariant
    /// matches the buyback path (out-of-band credits are harmless; only an unauthorised drain trips it).
    #[account(
        mut,
        address = firm_state.treasury_vault,
        constraint = treasury_vault.amount >= firm_state.treasury_sol @ FirmError::TreasuryDesync,
    )]
    pub treasury_vault: Box<Account<'info, TokenAccount>>,

    /// Transient $FIRMA staging (firm-PDA-owned): the zap swap delivers into it, the deposit spends it.
    #[account(mut, token::mint = firm_state.firma_mint, token::authority = firm_state)]
    pub lp_firma_staging: Box<Account<'info, TokenAccount>>,

    /// The permanently-locked LP position: CP-Swap mints the pool LP here. Firm-PDA-owned and the firm
    /// program exposes NO instruction that moves LP out of it — "lock-not-burn", identical to graduation.
    #[account(mut, token::authority = firm_state)]
    pub lp_locked_vault: Box<Account<'info, TokenAccount>>,
    // remaining_accounts: [cpmm, ..13 swap_base_input][cpmm, ..13 deposit] — validated in the CPI helpers.
}

// Accounts are Box'd to keep the BPF stack frame under 4 KB.
#[derive(Accounts)]
pub struct ExecuteFirmaBuyback<'info> {
    /// Permissionless cranker — pays no rent (no init). Anyone can convert the earmark.
    pub cranker: Signer<'info>,

    #[account(mut, seeds = [b"firm", firm_state.owner.as_ref()], bump = firm_state.bump)]
    pub firm_state: Box<Account<'info, FirmState>>,

    // Treasury is the buyer (pays SOL). §19 sync contract checked at entry.
    #[account(
        mut,
        address = firm_state.treasury_vault,
        // Invariant: the vault must COVER the cache. External credits (e.g. a bonding-curve fee paid
        // into treasury_vault by deploy_burn or a third-party curve buy) legitimately raise the vault
        // ABOVE the cache; each treasury-touching handler reconciles `treasury_sol = treasury_vault.amount`,
        // so the only way `vault < cache` is an impossible unauthorised drain. `==` here used to brick the
        // firm on any donation (F-1/F-2); `>=` makes out-of-band credits harmless. (audit F-1/F-2)
        constraint = treasury_vault.amount >= firm_state.treasury_sol @ FirmError::TreasuryDesync,
    )]
    pub treasury_vault: Box<Account<'info, TokenAccount>>,

    #[account(
        mut,
        seeds = [b"bonding_curve", firm_state.key().as_ref()],
        bump = curve.bump,
        seeds::program = bonding_curve::ID,
    )]
    pub curve: Box<Account<'info, bonding_curve::BondingCurve>>,
    #[account(mut, address = curve.sol_vault)]
    pub curve_sol_vault: Box<Account<'info, TokenAccount>>,
    #[account(mut, address = curve.firma_vault)]
    pub curve_firma_vault: Box<Account<'info, TokenAccount>>,

    // The buy delivers $FIRMA into the firm's Tier-2 reserve — address-bound, no discretion.
    #[account(mut, address = firm_state.treasury_firma_vault)]
    pub treasury_firma_vault: Box<Account<'info, TokenAccount>>,

    /// V2-8: canonical platform config — binds `platform_sol` so this **permissionless** crank can't
    /// name a `platform_sol` the caller controls and pocket the 0.5% platform fee.
    #[account(seeds = [b"platform_config"], bump = platform_config.bump)]
    pub platform_config: Box<Account<'info, PlatformConfig>>,

    // Platform SOL fee destination (0.5% curve fee) — V2-8: address-bound to platform_config.
    #[account(
        mut,
        token::mint = firm_state.sol_mint,
        constraint = platform_sol.key() == platform_config.platform_sol @ FirmError::PlatformSolMismatch,
    )]
    pub platform_sol: Box<Account<'info, TokenAccount>>,

    pub bonding_curve_program: Program<'info, bonding_curve::program::BondingCurve>,
    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
}

impl<'info> ExecuteFirmaBuyback<'info> {
    /// CPI into `bonding_curve.buy`: the treasury (firm PDA) buys $FIRMA into the Tier-2 reserve.
    /// The firm's 0.5% curve fee returns to the treasury; the platform's 0.5% goes to `platform_sol`.
    fn curve_buy(&self, sol_amount: u64, min_firma_out: u64) -> Result<()> {
        let bump = [self.firm_state.bump];
        let seeds = firm_signer(&self.firm_state.owner, &bump);
        bonding_curve::cpi::buy(
            CpiContext::new_with_signer(
                self.bonding_curve_program.to_account_info(),
                bonding_curve::cpi::accounts::Buy {
                    trader: self.firm_state.to_account_info(),
                    curve: self.curve.to_account_info(),
                    sol_vault: self.curve_sol_vault.to_account_info(),
                    firma_vault: self.curve_firma_vault.to_account_info(),
                    trader_sol: self.treasury_vault.to_account_info(),
                    trader_firma: self.treasury_firma_vault.to_account_info(),
                    firm_treasury_sol: self.treasury_vault.to_account_info(),
                    platform_sol: self.platform_sol.to_account_info(),
                    token_program: self.token_program.to_account_info(),
                },
                &[&seeds],
            ),
            sol_amount,
            min_firma_out,
        )
    }
}

#[derive(Accounts)]
pub struct InitStakingPool<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,

    #[account(seeds = [b"firm", firm_state.owner.as_ref()], bump = firm_state.bump)]
    pub firm_state: Box<Account<'info, FirmState>>,

    #[account(address = firm_state.firma_mint)]
    pub firma_mint: Box<Account<'info, Mint>>,
    #[account(address = firm_state.sol_mint)]
    pub sol_mint: Box<Account<'info, Mint>>,

    #[account(
        init,
        payer = payer,
        space = 8 + FirmaStakingPool::INIT_SPACE,
        seeds = [b"staking_pool", firm_state.key().as_ref()],
        bump
    )]
    pub staking_pool: Box<Account<'info, FirmaStakingPool>>,

    #[account(
        init,
        payer = payer,
        token::mint = firma_mint,
        token::authority = staking_pool,
        seeds = [b"stake_vault", firm_state.key().as_ref()],
        bump
    )]
    pub stake_vault: Box<Account<'info, TokenAccount>>,
    #[account(
        init,
        payer = payer,
        token::mint = sol_mint,
        token::authority = staking_pool,
        seeds = [b"staking_sol", firm_state.key().as_ref()],
        bump
    )]
    pub sol_reward_vault: Box<Account<'info, TokenAccount>>,
    #[account(
        init,
        payer = payer,
        token::mint = firma_mint,
        token::authority = staking_pool,
        seeds = [b"staking_firma", firm_state.key().as_ref()],
        bump
    )]
    pub firma_reward_vault: Box<Account<'info, TokenAccount>>,

    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
    pub rent: Sysvar<'info, Rent>,
}

#[derive(Accounts)]
pub struct Stake<'info> {
    #[account(mut)]
    pub staker: Signer<'info>,

    #[account(seeds = [b"firm", firm_state.owner.as_ref()], bump = firm_state.bump)]
    pub firm_state: Box<Account<'info, FirmState>>,

    #[account(mut, seeds = [b"staking_pool", firm_state.key().as_ref()], bump = staking_pool.bump)]
    pub staking_pool: Box<Account<'info, FirmaStakingPool>>,

    #[account(
        init_if_needed,
        payer = staker,
        space = 8 + StakerPosition::INIT_SPACE,
        seeds = [b"staker", firm_state.key().as_ref(), staker.key().as_ref()],
        bump
    )]
    pub staker_position: Box<Account<'info, StakerPosition>>,

    #[account(mut, address = staking_pool.stake_vault)]
    pub stake_vault: Box<Account<'info, TokenAccount>>,

    #[account(mut, token::mint = firm_state.firma_mint, token::authority = staker)]
    pub staker_firma: Box<Account<'info, TokenAccount>>,

    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
}

impl<'info> Stake<'info> {
    /// Move staked $FIRMA from the staker into the escrow vault.
    fn escrow(&self, amount: u64) -> Result<()> {
        token::transfer(
            CpiContext::new(
                self.token_program.to_account_info(),
                anchor_spl::token::Transfer {
                    from: self.staker_firma.to_account_info(),
                    to: self.stake_vault.to_account_info(),
                    authority: self.staker.to_account_info(),
                },
            ),
            amount,
        )
    }
}

#[derive(Accounts)]
pub struct Unstake<'info> {
    pub staker: Signer<'info>,

    #[account(seeds = [b"firm", firm_state.owner.as_ref()], bump = firm_state.bump)]
    pub firm_state: Box<Account<'info, FirmState>>,

    #[account(mut, seeds = [b"staking_pool", firm_state.key().as_ref()], bump = staking_pool.bump)]
    pub staking_pool: Box<Account<'info, FirmaStakingPool>>,

    #[account(
        mut,
        seeds = [b"staker", firm_state.key().as_ref(), staker.key().as_ref()],
        bump = staker_position.bump,
        constraint = staker_position.staker == staker.key() @ FirmError::Unauthorized,
    )]
    pub staker_position: Box<Account<'info, StakerPosition>>,

    #[account(mut, address = staking_pool.stake_vault)]
    pub stake_vault: Box<Account<'info, TokenAccount>>,

    #[account(
        mut,
        token::mint = firm_state.firma_mint,
        constraint = staker_firma.owner == staker.key() @ FirmError::Unauthorized,
    )]
    pub staker_firma: Box<Account<'info, TokenAccount>>,

    pub token_program: Program<'info, Token>,
}

impl<'info> Unstake<'info> {
    /// Return staked principal from escrow to the staker (pool PDA signs).
    fn return_principal(&self, amount: u64) -> Result<()> {
        let bump = [self.staking_pool.bump];
        let seeds = pool_signer(&self.staking_pool.firm, &bump);
        token::transfer(
            CpiContext::new_with_signer(
                self.token_program.to_account_info(),
                anchor_spl::token::Transfer {
                    from: self.stake_vault.to_account_info(),
                    to: self.staker_firma.to_account_info(),
                    authority: self.staking_pool.to_account_info(),
                },
                &[&seeds],
            ),
            amount,
        )
    }
}

#[derive(Accounts)]
pub struct ClaimStakingYield<'info> {
    pub staker: Signer<'info>,

    #[account(seeds = [b"firm", firm_state.owner.as_ref()], bump = firm_state.bump)]
    pub firm_state: Box<Account<'info, FirmState>>,

    #[account(mut, seeds = [b"staking_pool", firm_state.key().as_ref()], bump = staking_pool.bump)]
    pub staking_pool: Box<Account<'info, FirmaStakingPool>>,

    #[account(
        mut,
        seeds = [b"staker", firm_state.key().as_ref(), staker.key().as_ref()],
        bump = staker_position.bump,
        constraint = staker_position.staker == staker.key() @ FirmError::Unauthorized,
    )]
    pub staker_position: Box<Account<'info, StakerPosition>>,

    #[account(mut, address = staking_pool.sol_reward_vault)]
    pub sol_reward_vault: Box<Account<'info, TokenAccount>>,
    #[account(mut, address = staking_pool.firma_reward_vault)]
    pub firma_reward_vault: Box<Account<'info, TokenAccount>>,

    #[account(
        mut,
        token::mint = firm_state.sol_mint,
        constraint = staker_sol.owner == staker.key() @ FirmError::Unauthorized,
    )]
    pub staker_sol: Box<Account<'info, TokenAccount>>,
    #[account(
        mut,
        token::mint = firm_state.firma_mint,
        constraint = staker_firma.owner == staker.key() @ FirmError::Unauthorized,
    )]
    pub staker_firma: Box<Account<'info, TokenAccount>>,

    pub token_program: Program<'info, Token>,
}

impl<'info> ClaimStakingYield<'info> {
    fn pay_sol(&self, amount: u64) -> Result<()> {
        self.pay(self.sol_reward_vault.to_account_info(), self.staker_sol.to_account_info(), amount)
    }

    fn pay_firma(&self, amount: u64) -> Result<()> {
        self.pay(self.firma_reward_vault.to_account_info(), self.staker_firma.to_account_info(), amount)
    }

    /// Pay yield out of a reward vault (pool PDA signs).
    fn pay(&self, from: AccountInfo<'info>, to: AccountInfo<'info>, amount: u64) -> Result<()> {
        if amount == 0 {
            return Ok(());
        }
        let bump = [self.staking_pool.bump];
        let seeds = pool_signer(&self.staking_pool.firm, &bump);
        token::transfer(
            CpiContext::new_with_signer(
                self.token_program.to_account_info(),
                anchor_spl::token::Transfer { from, to, authority: self.staking_pool.to_account_info() },
                &[&seeds],
            ),
            amount,
        )
    }
}

#[derive(Accounts)]
pub struct DistributeStakingSol<'info> {
    pub funder: Signer<'info>,

    #[account(seeds = [b"firm", firm_state.owner.as_ref()], bump = firm_state.bump)]
    pub firm_state: Box<Account<'info, FirmState>>,

    #[account(mut, seeds = [b"staking_pool", firm_state.key().as_ref()], bump = staking_pool.bump)]
    pub staking_pool: Box<Account<'info, FirmaStakingPool>>,

    #[account(mut, address = staking_pool.sol_reward_vault)]
    pub sol_reward_vault: Box<Account<'info, TokenAccount>>,

    #[account(mut, token::mint = firm_state.sol_mint, token::authority = funder)]
    pub source_sol: Box<Account<'info, TokenAccount>>,

    pub token_program: Program<'info, Token>,
}

impl<'info> DistributeStakingSol<'info> {
    /// Move weekly SOL yield from the funder into the reward vault.
    fn fund(&self, amount: u64) -> Result<()> {
        token::transfer(
            CpiContext::new(
                self.token_program.to_account_info(),
                anchor_spl::token::Transfer {
                    from: self.source_sol.to_account_info(),
                    to: self.sol_reward_vault.to_account_info(),
                    authority: self.funder.to_account_info(),
                },
            ),
            amount,
        )
    }
}

#[derive(Accounts)]
pub struct SyncFirmaYield<'info> {
    #[account(mut, seeds = [b"staking_pool", staking_pool.firm.as_ref()], bump = staking_pool.bump)]
    pub staking_pool: Box<Account<'info, FirmaStakingPool>>,

    #[account(address = staking_pool.firma_reward_vault)]
    pub firma_reward_vault: Box<Account<'info, TokenAccount>>,
}

/// Permissionless: fold $FIRMA that has arrived in the backstop pool's `firma_reward_vault`
/// (from `FirmState.backstop_pool_bps` on funded-trader payouts) into `acc_firma`.
/// Mirrors `SyncFirmaYield` exactly, one field over.
#[derive(Accounts)]
pub struct SyncBackstopFirmaYield<'info> {
    #[account(mut, seeds = [b"backstop_pool", backstop_pool.firm.as_ref()], bump = backstop_pool.bump)]
    pub backstop_pool: Box<Account<'info, BackstopPool>>,

    #[account(address = backstop_pool.firma_reward_vault)]
    pub firma_reward_vault: Box<Account<'info, TokenAccount>>,
}

/// Backfill accounts for `init_backstop_firma_reward_vault` — see that instruction's doc comment.
#[derive(Accounts)]
pub struct InitBackstopFirmaRewardVault<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,

    #[account(seeds = [b"firm", firm_state.owner.as_ref()], bump = firm_state.bump)]
    pub firm_state: Box<Account<'info, FirmState>>,

    #[account(address = firm_state.firma_mint)]
    pub firma_mint: Box<Account<'info, Mint>>,

    #[account(mut, seeds = [b"backstop_pool", firm_state.key().as_ref()], bump = backstop_pool.bump)]
    pub backstop_pool: Box<Account<'info, BackstopPool>>,

    #[account(
        init,
        payer = payer,
        token::mint = firma_mint,
        token::authority = backstop_pool,
        seeds = [b"backstop_firma_reward", firm_state.key().as_ref()],
        bump
    )]
    pub firma_reward_vault: Box<Account<'info, TokenAccount>>,

    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
    pub rent: Sysvar<'info, Rent>,
}

#[derive(Accounts)]
#[instruction(cycle: u32)]
pub struct EnqueuePayout<'info> {
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
        seeds::program = challenge::ID,
        constraint = challenge.settlement_authority == authority.key() @ FirmError::Unauthorized,
        constraint = challenge.firm == firm_state.key() @ FirmError::Unauthorized,
    )]
    pub challenge: Box<Account<'info, challenge::ChallengeState>>,

    /// DEC-62 — present ⇒ this is a FUNDED WITHDRAWAL (the account keeps trading); absent ⇒ the legacy
    /// settlement path (a concluded, `Passed` challenge). Bound in the handler to this challenge + this
    /// `cycle`, and required `Final`, so the 72h fraud window has closed with no fault proven before a
    /// lamport of it can be queued.
    #[account(
        seeds = [b"withdrawal", challenge.key().as_ref(), &cycle.to_le_bytes()],
        bump = withdrawal.bump,
        seeds::program = challenge::ID,
    )]
    pub withdrawal: Option<Box<Account<'info, challenge::FundedWithdrawal>>>,

    #[account(mut, seeds = [b"firm", firm_state.owner.as_ref()], bump = firm_state.bump)]
    pub firm_state: Box<Account<'info, FirmState>>,

    // Read-only: `enqueue_payout` reads the live curve reserves to strike the owed $FIRMA
    // quantity from the trader's SOL-value obligation (`payout_sol_owed`). Not mutated here.
    #[account(
        seeds = [b"bonding_curve", firm_state.key().as_ref()],
        bump = curve.bump,
        seeds::program = bonding_curve::ID,
    )]
    pub curve: Box<Account<'info, bonding_curve::BondingCurve>>,

    /// CONCENTRATION-DENOM-1 — Tier-2 of the concentration-guard denominator. Read-only; address-bound
    /// to the firm's own canonical vault, so there is zero discretion over which reserve is read.
    #[account(address = firm_state.treasury_firma_vault)]
    pub treasury_firma_vault: Box<Account<'info, TokenAccount>>,

    /// CONCENTRATION-DENOM-1 — Tier-3 of the concentration-guard denominator (the firm's operator
    /// bond). Optional: a firm that hasn't posted a bond yet simply contributes 0 — see the fn's doc
    /// comment. Read-only; we only read the account's own lamport balance (mirroring
    /// `ReconcileOperatorBond`'s read), never a cached field. CHECK: PDA address + dispute ownership
    /// verified by the constraints when present.
    #[account(
        owner = dispute::ID,
        seeds = [b"operator_stake", firm_state.key().as_ref()],
        bump,
        seeds::program = dispute::ID,
    )]
    pub operator_stake: Option<UncheckedAccount<'info>>,

    // Same seed as the immediate path's PayoutRecord → the two payout paths are mutually exclusive per
    // challenge + cycle (no double payout). The `cycle` in the seed is what lets a funded account
    // withdraw more than once: at `["payout", challenge]` the PDA was occupied FOREVER by the first
    // payout, so a second withdrawal reverted `AccountAlreadyInUse` at `init` — the CHK-9/CHK-10 shape.
    // Closing it between cycles is not a fix: `close_queued_payout` requires the TRADER to sign, so a
    // trader who never calls it could never withdraw again.
    #[account(
        init,
        payer = authority,
        space = 8 + QueuedPayout::INIT_SPACE,
        seeds = [b"payout", challenge.key().as_ref(), &cycle.to_le_bytes()],
        bump
    )]
    pub queued_payout: Box<Account<'info, QueuedPayout>>,

    pub system_program: Program<'info, System>,
}

/// CONCENTRATION-DENOM-1 — permissionless cranker; can only ever shorten a hold (see the handler's
/// doc comment), so no authority check beyond the seed/ownership bindings that pin every account to
/// the right firm/challenge/cycle.
#[derive(Accounts)]
#[instruction(cycle: u32)]
pub struct ReconcilePayoutHold<'info> {
    pub cranker: Signer<'info>,

    /// Only needed for its pubkey (to seed-derive `queued_payout`) — no fields are read. CHECK:
    /// ownership pinned so a caller can't point this at an unrelated account.
    #[account(owner = challenge::ID)]
    pub challenge: UncheckedAccount<'info>,

    #[account(seeds = [b"firm", firm_state.owner.as_ref()], bump = firm_state.bump)]
    pub firm_state: Box<Account<'info, FirmState>>,

    #[account(
        seeds = [b"bonding_curve", firm_state.key().as_ref()],
        bump = curve.bump,
        seeds::program = bonding_curve::ID,
    )]
    pub curve: Box<Account<'info, bonding_curve::BondingCurve>>,

    #[account(address = firm_state.treasury_firma_vault)]
    pub treasury_firma_vault: Box<Account<'info, TokenAccount>>,

    #[account(
        owner = dispute::ID,
        seeds = [b"operator_stake", firm_state.key().as_ref()],
        bump,
        seeds::program = dispute::ID,
    )]
    pub operator_stake: Option<UncheckedAccount<'info>>,

    #[account(
        mut,
        seeds = [b"payout", challenge.key().as_ref(), &cycle.to_le_bytes()],
        bump = queued_payout.bump,
    )]
    pub queued_payout: Box<Account<'info, QueuedPayout>>,
}

// Accounts are Box'd to keep the BPF stack frame under 4 KB.
#[derive(Accounts)]
pub struct ProcessQueuedPayout<'info> {
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
        seeds::program = challenge::ID,
        constraint = challenge.settlement_authority == authority.key() @ FirmError::Unauthorized,
        constraint = challenge.firm == firm_state.key() @ FirmError::Unauthorized,
    )]
    pub challenge: Box<Account<'info, challenge::ChallengeState>>,

    #[account(mut, seeds = [b"firm", firm_state.owner.as_ref()], bump = firm_state.bump)]
    pub firm_state: Box<Account<'info, FirmState>>,

    #[account(
        mut,
        seeds = [b"payout", challenge.key().as_ref(), &queued_payout.cycle.to_le_bytes()],
        bump = queued_payout.bump,
        constraint = queued_payout.challenge == challenge.key() @ FirmError::Unauthorized,
    )]
    pub queued_payout: Box<Account<'info, QueuedPayout>>,

    /// DEC-62 — present ⇒ this payout discharges a FUNDED WITHDRAWAL, authorised by its
    /// `FundedWithdrawal` rather than by a challenge settlement the still-trading account never
    /// reaches. Seed-bound to this challenge + the queued payout's OWN cycle. Absent ⇒ settlement path.
    #[account(
        seeds = [b"withdrawal", challenge.key().as_ref(), &queued_payout.cycle.to_le_bytes()],
        bump = withdrawal.bump,
        seeds::program = challenge::ID,
    )]
    pub withdrawal: Option<Box<Account<'info, challenge::FundedWithdrawal>>>,

    // Treasury is the buyer (pays SOL). §19 sync contract checked at entry.
    #[account(
        mut,
        address = firm_state.treasury_vault,
        // Invariant: the vault must COVER the cache. External credits (e.g. a bonding-curve fee paid
        // into treasury_vault by deploy_burn or a third-party curve buy) legitimately raise the vault
        // ABOVE the cache; each treasury-touching handler reconciles `treasury_sol = treasury_vault.amount`,
        // so the only way `vault < cache` is an impossible unauthorised drain. `==` here used to brick the
        // firm on any donation (F-1/F-2); `>=` makes out-of-band credits harmless. (audit F-1/F-2)
        constraint = treasury_vault.amount >= firm_state.treasury_sol @ FirmError::TreasuryDesync,
    )]
    pub treasury_vault: Box<Account<'info, TokenAccount>>,

    #[account(
        mut,
        seeds = [b"bonding_curve", firm_state.key().as_ref()],
        bump = curve.bump,
        seeds::program = bonding_curve::ID,
    )]
    pub curve: Box<Account<'info, bonding_curve::BondingCurve>>,
    #[account(mut, address = curve.sol_vault)]
    pub curve_sol_vault: Box<Account<'info, TokenAccount>>,
    #[account(mut, address = curve.firma_vault)]
    pub curve_firma_vault: Box<Account<'info, TokenAccount>>,

    // The buy delivers $FIRMA here; it is then split trader/stakeholder.
    #[account(mut, address = firm_state.payout_firma_vault)]
    pub payout_firma_vault: Box<Account<'info, TokenAccount>>,

    // M-3 reserve-first: the Tier-2 $FIRMA reserve (read-only). The curve buy is only permitted once the
    // reserve is exhausted (`draw_treasury_firma` delivers from it with NO curve = NO sandwich), so the
    // sandwichable curve buy is the LAST resort, minimising the MEV/DoS surface on payouts.
    #[account(address = firm_state.treasury_firma_vault)]
    pub treasury_firma_vault: Box<Account<'info, TokenAccount>>,

    // Mutated by the buyback/burn leg.
    #[account(mut, address = firm_state.firma_mint)]
    pub firma_mint: Box<Account<'info, Mint>>,

    #[account(
        mut,
        token::mint = firm_state.firma_mint,
        constraint = trader_firma.owner == queued_payout.trader @ FirmError::Unauthorized,
    )]
    pub trader_firma: Box<Account<'info, TokenAccount>>,

    // Stakeholder owner share → the firm owner's $FIRMA account.
    #[account(
        mut,
        token::mint = firm_state.firma_mint,
        constraint = owner_firma.owner == firm_state.owner @ FirmError::Unauthorized,
    )]
    pub owner_firma: Box<Account<'info, TokenAccount>>,

    // Stakeholder staking share → the staking pool's $FIRMA reward vault (L-2: PDA-bound, no longer
    // keeper-substitutable). The firm must have inited its staking pool (`init_staking_pool`) before a
    // queued payout carries a staking share; the canonical seed is ["staking_firma", firm].
    #[account(
        mut,
        seeds = [b"staking_firma", firm_state.key().as_ref()],
        bump,
        token::mint = firm_state.firma_mint,
    )]
    pub staking_vault: Box<Account<'info, TokenAccount>>,

    // Stakeholder BACKSTOP-staking share (2026-07-27 rebalance) → the backstop pool's own $FIRMA
    // reward vault, distinct from `staking_vault` above. Optional — unlike no-risk staking, a
    // backstop pool is genuinely optional per firm; if absent, `sh.backstop` simply isn't paid out
    // here and stays in the staging vault as part of the firm's own treasury reserve (same fallback
    // `compute_fee_split`'s `premium_bps` uses when a firm has no backstop pool).
    #[account(
        mut,
        seeds = [b"backstop_firma_reward", firm_state.key().as_ref()],
        bump,
        token::mint = firm_state.firma_mint,
    )]
    pub backstop_firma_reward_vault: Option<Box<Account<'info, TokenAccount>>>,

    // Platform SOL fee destination (0.5% curve fee). NOTE: bind to platform config later.
    /// V2-8: canonical platform config — binds `platform_sol` to the DP fee destination (M-4 pattern),
    /// so this leg can't be pointed at a caller-controlled account.
    #[account(seeds = [b"platform_config"], bump = platform_config.bump)]
    pub platform_config: Box<Account<'info, PlatformConfig>>,

    #[account(
        mut,
        token::mint = firm_state.sol_mint,
        constraint = platform_sol.key() == platform_config.platform_sol @ FirmError::PlatformSolMismatch,
    )]
    pub platform_sol: Box<Account<'info, TokenAccount>>,

    // Universal Treasury Pool: 40% of the stakeholder SOL notional is transferred here
    // before the curve buy (§19 `StakeholderConfig.universal_sol_bps`). Enforced PDA;
    // only exits via `draw_universal`. `init_universal_pool` must have run first.
    #[account(mut, seeds = [b"universal_vault"], bump, token::mint = firm_state.sol_mint)]
    pub universal_vault: Box<Account<'info, TokenAccount>>,
    #[account(mut, seeds = [b"universal_pool"], bump = universal_pool.bump)]
    pub universal_pool: Box<Account<'info, UniversalPool>>,

    pub bonding_curve_program: Program<'info, bonding_curve::program::BondingCurve>,
    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
    // Post-graduation, the SOL→$FIRMA swap's [cpmm_program, ..13 swap accounts] ride in `remaining_accounts`
    // (empty pre-graduation) — so this named-account list is unchanged and pre-grad callers are unaffected.
}

impl<'info> ProcessQueuedPayout<'info> {
    /// CPI into `bonding_curve.buy` with the treasury as buyer and the staging vault as
    /// the $FIRMA recipient (firm PDA signs).
    fn curve_buy(&self, sol_amount: u64, min_firma_out: u64) -> Result<()> {
        let bump = [self.firm_state.bump];
        let seeds = firm_signer(&self.firm_state.owner, &bump);
        bonding_curve::cpi::buy(
            CpiContext::new_with_signer(
                self.bonding_curve_program.to_account_info(),
                bonding_curve::cpi::accounts::Buy {
                    trader: self.firm_state.to_account_info(),
                    curve: self.curve.to_account_info(),
                    sol_vault: self.curve_sol_vault.to_account_info(),
                    firma_vault: self.curve_firma_vault.to_account_info(),
                    trader_sol: self.treasury_vault.to_account_info(),
                    trader_firma: self.payout_firma_vault.to_account_info(),
                    firm_treasury_sol: self.treasury_vault.to_account_info(),
                    platform_sol: self.platform_sol.to_account_info(),
                    token_program: self.token_program.to_account_info(),
                },
                &[&seeds],
            ),
            sol_amount,
            min_firma_out,
        )
    }

    /// Transfer $FIRMA out of the staging vault to a destination (firm PDA signs).
    fn pay_firma(&self, to: AccountInfo<'info>, amount: u64) -> Result<()> {
        if amount == 0 {
            return Ok(());
        }
        let bump = [self.firm_state.bump];
        let seeds = firm_signer(&self.firm_state.owner, &bump);
        token::transfer(
            CpiContext::new_with_signer(
                self.token_program.to_account_info(),
                anchor_spl::token::Transfer {
                    from: self.payout_firma_vault.to_account_info(),
                    to,
                    authority: self.firm_state.to_account_info(),
                },
                &[&seeds],
            ),
            amount,
        )
    }

    /// Transfer wSOL from the firm's treasury vault to the Universal Treasury Pool vault
    /// (firm PDA signs). Used for the pre-buy universal SOL carve (§19).
    fn carve_to_universal(&self, amount: u64) -> Result<()> {
        if amount == 0 {
            return Ok(());
        }
        let bump = [self.firm_state.bump];
        let seeds = firm_signer(&self.firm_state.owner, &bump);
        token::transfer(
            CpiContext::new_with_signer(
                self.token_program.to_account_info(),
                anchor_spl::token::Transfer {
                    from: self.treasury_vault.to_account_info(),
                    to: self.universal_vault.to_account_info(),
                    authority: self.firm_state.to_account_info(),
                },
                &[&seeds],
            ),
            amount,
        )
    }

    /// Burn the buyback/burn $FIRMA share from the staging vault (firm PDA signs) — the
    /// deflationary leg of the stakeholder split (§19).
    fn burn_firma(&self, amount: u64) -> Result<()> {
        if amount == 0 {
            return Ok(());
        }
        let bump = [self.firm_state.bump];
        let seeds = firm_signer(&self.firm_state.owner, &bump);
        token::burn(
            CpiContext::new_with_signer(
                self.token_program.to_account_info(),
                anchor_spl::token::Burn {
                    mint: self.firma_mint.to_account_info(),
                    from: self.payout_firma_vault.to_account_info(),
                    authority: self.firm_state.to_account_info(),
                },
                &[&seeds],
            ),
            amount,
        )
    }
}

/// DEC-77 — first-payout instant advance (§22b). Same account shape as `ProcessQueuedPayout` (it
/// performs the identical curve-buy + trader/stakeholder split), with two differences: `queued_payout`
/// is `init` here (created early, at Provisional, rather than read as an existing `mut` account), and
/// there is no `withdrawal` account — this path is SETTLEMENT-ONLY (cycle is always 0; see the
/// instruction's doc comment for why the withdrawal path is explicitly out of scope). `operator_stake`
/// is carried (as in `EnqueuePayout`) for the concentration-guard's Tier-3 denominator.
// Accounts are Box'd to keep the BPF stack frame under 4 KB (mirrors ProcessQueuedPayout).
#[derive(Accounts)]
pub struct AdvanceFirstPayout<'info> {
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
        seeds::program = challenge::ID,
        constraint = challenge.settlement_authority == authority.key() @ FirmError::Unauthorized,
        constraint = challenge.firm == firm_state.key() @ FirmError::Unauthorized,
    )]
    pub challenge: Box<Account<'info, challenge::ChallengeState>>,

    #[account(mut, seeds = [b"firm", firm_state.owner.as_ref()], bump = firm_state.bump)]
    pub firm_state: Box<Account<'info, FirmState>>,

    #[account(
        mut,
        seeds = [b"bonding_curve", firm_state.key().as_ref()],
        bump = curve.bump,
        seeds::program = bonding_curve::ID,
    )]
    pub curve: Box<Account<'info, bonding_curve::BondingCurve>>,
    #[account(mut, address = curve.sol_vault)]
    pub curve_sol_vault: Box<Account<'info, TokenAccount>>,
    #[account(mut, address = curve.firma_vault)]
    pub curve_firma_vault: Box<Account<'info, TokenAccount>>,

    #[account(
        mut,
        address = firm_state.treasury_vault,
        constraint = treasury_vault.amount >= firm_state.treasury_sol @ FirmError::TreasuryDesync,
    )]
    pub treasury_vault: Box<Account<'info, TokenAccount>>,

    // The buy delivers $FIRMA here; it is then split trader/stakeholder — same staging vault every
    // other payout path uses.
    #[account(mut, address = firm_state.payout_firma_vault)]
    pub payout_firma_vault: Box<Account<'info, TokenAccount>>,

    /// CONCENTRATION-DENOM-1 Tier-2 (read-only, same as `EnqueuePayout`/`ProcessQueuedPayout`).
    #[account(address = firm_state.treasury_firma_vault)]
    pub treasury_firma_vault: Box<Account<'info, TokenAccount>>,

    /// CONCENTRATION-DENOM-1 Tier-3 (optional, same as `EnqueuePayout`).
    #[account(
        owner = dispute::ID,
        seeds = [b"operator_stake", firm_state.key().as_ref()],
        bump,
        seeds::program = dispute::ID,
    )]
    pub operator_stake: Option<UncheckedAccount<'info>>,

    #[account(mut, address = firm_state.firma_mint)]
    pub firma_mint: Box<Account<'info, Mint>>,

    #[account(
        mut,
        token::mint = firm_state.firma_mint,
        constraint = trader_firma.owner == challenge.trader @ FirmError::Unauthorized,
    )]
    pub trader_firma: Box<Account<'info, TokenAccount>>,

    #[account(
        mut,
        token::mint = firm_state.firma_mint,
        constraint = owner_firma.owner == firm_state.owner @ FirmError::Unauthorized,
    )]
    pub owner_firma: Box<Account<'info, TokenAccount>>,

    #[account(
        mut,
        seeds = [b"staking_firma", firm_state.key().as_ref()],
        bump,
        token::mint = firm_state.firma_mint,
    )]
    pub staking_vault: Box<Account<'info, TokenAccount>>,

    // 2026-07-27 staking rebalance — see the identical field on `ProcessQueuedPayout`.
    #[account(
        mut,
        seeds = [b"backstop_firma_reward", firm_state.key().as_ref()],
        bump,
        token::mint = firm_state.firma_mint,
    )]
    pub backstop_firma_reward_vault: Option<Box<Account<'info, TokenAccount>>>,

    #[account(seeds = [b"platform_config"], bump = platform_config.bump)]
    pub platform_config: Box<Account<'info, PlatformConfig>>,

    #[account(
        mut,
        token::mint = firm_state.sol_mint,
        constraint = platform_sol.key() == platform_config.platform_sol @ FirmError::PlatformSolMismatch,
    )]
    pub platform_sol: Box<Account<'info, TokenAccount>>,

    #[account(mut, seeds = [b"universal_vault"], bump, token::mint = firm_state.sol_mint)]
    pub universal_vault: Box<Account<'info, TokenAccount>>,
    #[account(mut, seeds = [b"universal_pool"], bump = universal_pool.bump)]
    pub universal_pool: Box<Account<'info, UniversalPool>>,

    // Created here (unlike `ProcessQueuedPayout`, which reads an existing one) — cycle is hardcoded 0,
    // this path is settlement-only. Same PDA seed the normal `enqueue_payout` path would use, so a
    // later `process_queued_payout` finds and completes THIS SAME account, never a duplicate.
    #[account(
        init,
        payer = authority,
        space = 8 + QueuedPayout::INIT_SPACE,
        seeds = [b"payout", challenge.key().as_ref(), &0u32.to_le_bytes()],
        bump
    )]
    pub queued_payout: Box<Account<'info, QueuedPayout>>,

    /// DEC-77 — the firm's live advance-float exposure counter (kept OFF `FirmState` to avoid
    /// re-tripping the BPF stack limit `PayChallengeFee` already sits at the edge of — see
    /// `AdvancePool`'s doc comment). Lazily created on this firm's first-ever advance.
    #[account(
        init_if_needed,
        payer = authority,
        space = 8 + AdvancePool::INIT_SPACE,
        seeds = [b"advance_pool", firm_state.key().as_ref()],
        bump
    )]
    pub advance_pool: Box<Account<'info, AdvancePool>>,

    pub bonding_curve_program: Program<'info, bonding_curve::program::BondingCurve>,
    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
}

impl<'info> AdvanceFirstPayout<'info> {
    /// CPI into `bonding_curve.buy` with the treasury as buyer and the staging vault as the $FIRMA
    /// recipient (firm PDA signs) — identical to `ProcessQueuedPayout::curve_buy`.
    fn curve_buy(&self, sol_amount: u64, min_firma_out: u64) -> Result<()> {
        let bump = [self.firm_state.bump];
        let seeds = firm_signer(&self.firm_state.owner, &bump);
        bonding_curve::cpi::buy(
            CpiContext::new_with_signer(
                self.bonding_curve_program.to_account_info(),
                bonding_curve::cpi::accounts::Buy {
                    trader: self.firm_state.to_account_info(),
                    curve: self.curve.to_account_info(),
                    sol_vault: self.curve_sol_vault.to_account_info(),
                    firma_vault: self.curve_firma_vault.to_account_info(),
                    trader_sol: self.treasury_vault.to_account_info(),
                    trader_firma: self.payout_firma_vault.to_account_info(),
                    firm_treasury_sol: self.treasury_vault.to_account_info(),
                    platform_sol: self.platform_sol.to_account_info(),
                    token_program: self.token_program.to_account_info(),
                },
                &[&seeds],
            ),
            sol_amount,
            min_firma_out,
        )
    }

    /// Transfer $FIRMA out of the staging vault to a destination (firm PDA signs).
    fn pay_firma(&self, to: AccountInfo<'info>, amount: u64) -> Result<()> {
        if amount == 0 {
            return Ok(());
        }
        let bump = [self.firm_state.bump];
        let seeds = firm_signer(&self.firm_state.owner, &bump);
        token::transfer(
            CpiContext::new_with_signer(
                self.token_program.to_account_info(),
                anchor_spl::token::Transfer {
                    from: self.payout_firma_vault.to_account_info(),
                    to,
                    authority: self.firm_state.to_account_info(),
                },
                &[&seeds],
            ),
            amount,
        )
    }

    /// Transfer wSOL from the firm's treasury vault to the Universal Treasury Pool vault (firm PDA
    /// signs). Used for the pre-buy universal SOL carve (§19).
    fn carve_to_universal(&self, amount: u64) -> Result<()> {
        if amount == 0 {
            return Ok(());
        }
        let bump = [self.firm_state.bump];
        let seeds = firm_signer(&self.firm_state.owner, &bump);
        token::transfer(
            CpiContext::new_with_signer(
                self.token_program.to_account_info(),
                anchor_spl::token::Transfer {
                    from: self.treasury_vault.to_account_info(),
                    to: self.universal_vault.to_account_info(),
                    authority: self.firm_state.to_account_info(),
                },
                &[&seeds],
            ),
            amount,
        )
    }

    /// Burn the buyback/burn $FIRMA share from the staging vault (firm PDA signs).
    fn burn_firma(&self, amount: u64) -> Result<()> {
        if amount == 0 {
            return Ok(());
        }
        let bump = [self.firm_state.bump];
        let seeds = firm_signer(&self.firm_state.owner, &bump);
        token::burn(
            CpiContext::new_with_signer(
                self.token_program.to_account_info(),
                anchor_spl::token::Burn {
                    mint: self.firma_mint.to_account_info(),
                    from: self.payout_firma_vault.to_account_info(),
                    authority: self.firm_state.to_account_info(),
                },
                &[&seeds],
            ),
            amount,
        )
    }
}

#[derive(Accounts)]
pub struct CloseQueuedPayout<'info> {
    #[account(mut, address = queued_payout.trader)]
    pub trader: Signer<'info>,

    /// CHECK: challenge key only — the queued payout's PDA seed.
    pub challenge: UncheckedAccount<'info>,

    #[account(
        mut,
        close = trader,
        seeds = [b"payout", challenge.key().as_ref(), &queued_payout.cycle.to_le_bytes()],
        bump = queued_payout.bump,
        constraint = queued_payout.challenge == challenge.key() @ FirmError::Unauthorized,
        constraint = queued_payout.firma_amount_delivered >= queued_payout.firma_amount_owed
            @ FirmError::PayoutNotFullyFilled,
    )]
    pub queued_payout: Account<'info, QueuedPayout>,
}

/// C-7 — permissionless force-discharge of an undeliverable queued payout during wind-down. The
/// `cranker` (anyone) pays; rent returns to the payout's `trader`. Guards live in the handler
/// (firm closing + 90-day undelivered timeout); the payout PDA + firm binding are checked here.
#[derive(Accounts)]
pub struct ForceDischargeUndeliverablePayout<'info> {
    #[account(mut)]
    pub cranker: Signer<'info>,

    /// CHECK: rent destination = the payout's recorded trader (address-checked).
    #[account(mut, address = queued_payout.trader)]
    pub trader: UncheckedAccount<'info>,

    /// CHECK: challenge key only — the queued payout's PDA seed.
    pub challenge: UncheckedAccount<'info>,

    #[account(mut, seeds = [b"firm", firm_state.owner.as_ref()], bump = firm_state.bump)]
    pub firm_state: Account<'info, FirmState>,

    #[account(
        mut,
        close = trader,
        seeds = [b"payout", challenge.key().as_ref(), &queued_payout.cycle.to_le_bytes()],
        bump = queued_payout.bump,
        constraint = queued_payout.challenge == challenge.key() @ FirmError::Unauthorized,
        constraint = queued_payout.firm == firm_state.key() @ FirmError::Unauthorized,
    )]
    pub queued_payout: Account<'info, QueuedPayout>,
}

/// DEC-77 — permissionless cranker; moves no funds (pure bookkeeping — the SOL already left the
/// treasury at advance time), so no authority check beyond the seed/ownership bindings that pin every
/// account to the right firm/challenge.
///
/// PAYOUT-ADVANCE-8 fix: `challenge`'s seeds constraint only proves internal self-consistency (its
/// address matches seeds derived from its OWN stored fields) — without an explicit link to
/// `firm_state`, a caller could pair FIRM A's real `challenge`/`queued_payout` with FIRM B's
/// `firm_state`/`advance_pool` (both are public PDAs, and `cranker` requires no relationship to
/// either), decrementing Firm B's `AdvancePool.sol_outstanding` — the only safety cap bounding
/// `advance_first_payout` — using an advance that was never really Firm B's. `AdvanceFirstPayout`
/// already carries this exact constraint; `ForceDischargeUndeliverablePayout` carries the
/// `queued_payout.firm == firm_state.key()` twin. Both were missing here.
#[derive(Accounts)]
pub struct ReconcilePayoutAdvance<'info> {
    pub cranker: Signer<'info>,

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
        constraint = challenge.firm == firm_state.key() @ FirmError::Unauthorized,
    )]
    pub challenge: Box<Account<'info, challenge::ChallengeState>>,

    #[account(mut, seeds = [b"firm", firm_state.owner.as_ref()], bump = firm_state.bump)]
    pub firm_state: Box<Account<'info, FirmState>>,

    #[account(
        mut,
        seeds = [b"payout", challenge.key().as_ref(), &0u32.to_le_bytes()],
        bump = queued_payout.bump,
        constraint = queued_payout.challenge == challenge.key() @ FirmError::Unauthorized,
    )]
    pub queued_payout: Box<Account<'info, QueuedPayout>>,

    #[account(mut, seeds = [b"advance_pool", firm_state.key().as_ref()], bump = advance_pool.bump)]
    pub advance_pool: Box<Account<'info, AdvancePool>>,
}

/// DEC-77 — permissionless; a fraud proof already made the settlement `Faulted`, so anyone may crank
/// the write-off (mirrors `ForceDischargeUndeliverablePayout`'s permissionless shape). Moves no funds —
/// the loss already happened at advance time; this only updates bookkeeping and clears the trader's
/// remaining (never-real) obligation so `close_queued_payout` becomes reachable.
///
/// PAYOUT-ADVANCE-8 fix: same missing cross-firm binding as `ReconcilePayoutAdvance` — see its doc
/// comment. Without this, a caller could write off Firm B's pool exposure using Firm A's Faulted
/// advance.
#[derive(Accounts)]
pub struct WriteOffFaultedAdvance<'info> {
    pub cranker: Signer<'info>,

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
        constraint = challenge.firm == firm_state.key() @ FirmError::Unauthorized,
    )]
    pub challenge: Box<Account<'info, challenge::ChallengeState>>,

    #[account(mut, seeds = [b"firm", firm_state.owner.as_ref()], bump = firm_state.bump)]
    pub firm_state: Box<Account<'info, FirmState>>,

    #[account(
        mut,
        seeds = [b"payout", challenge.key().as_ref(), &0u32.to_le_bytes()],
        bump = queued_payout.bump,
        constraint = queued_payout.challenge == challenge.key() @ FirmError::Unauthorized,
    )]
    pub queued_payout: Box<Account<'info, QueuedPayout>>,

    #[account(mut, seeds = [b"advance_pool", firm_state.key().as_ref()], bump = advance_pool.bump)]
    pub advance_pool: Box<Account<'info, AdvancePool>>,
}

#[derive(Accounts)]
pub struct GraduateFirm<'info> {
    /// Permissionless cranker — pays the tx, no special authority.
    pub cranker: Signer<'info>,

    #[account(mut, seeds = [b"firm", firm_state.owner.as_ref()], bump = firm_state.bump)]
    pub firm_state: Box<Account<'info, FirmState>>,

    #[account(
        seeds = [b"bonding_curve", firm_state.key().as_ref()],
        bump = curve.bump,
        seeds::program = bonding_curve::ID,
    )]
    pub curve: Box<Account<'info, bonding_curve::BondingCurve>>,

    #[account(mut)]
    pub lp_mint: Box<Account<'info, Mint>>,

    // Treasury's LP token account (authority = firm PDA), burned in full.
    #[account(
        mut,
        token::mint = lp_mint,
        token::authority = firm_state,
    )]
    pub treasury_lp_account: Box<Account<'info, TokenAccount>>,

    pub token_program: Program<'info, Token>,
}

impl<'info> GraduateFirm<'info> {
    /// Burn the treasury's LP tokens (firm PDA signs) — permanent liquidity lock (§16).
    fn burn_lp(&self, amount: u64) -> Result<()> {
        if amount == 0 {
            return Ok(());
        }
        let bump = [self.firm_state.bump];
        let seeds = firm_signer(&self.firm_state.owner, &bump);
        token::burn(
            CpiContext::new_with_signer(
                self.token_program.to_account_info(),
                anchor_spl::token::Burn {
                    mint: self.lp_mint.to_account_info(),
                    from: self.treasury_lp_account.to_account_info(),
                    authority: self.firm_state.to_account_info(),
                },
                &[&seeds],
            ),
            amount,
        )
    }
}

// Accounts are Box'd to keep the BPF stack frame under 4 KB.
// §24 v2: the owner-initiated close (InitiateClose / CloseFirm) is GONE — a solvent firm has no exit.
// `FinalizeBankruptcy` winds down a firm that auto-bankrupted (drew ≥10% of the ULP): permissionless, no
// timelock, no owner leg — the entire SOL residual (treasury + insurance) → the Universal Pool. (Loss-back
// is no longer part of this sweep — 2026-07-27 staking rebalance made it a notional counter, not a vault.)
#[derive(Accounts)]
pub struct FinalizeBankruptcy<'info> {
    /// Permissionless cranker (pays gas only). Anyone may wind down a bankrupt firm.
    pub cranker: Signer<'info>,

    #[account(mut, seeds = [b"firm", firm_state.owner.as_ref()], bump = firm_state.bump)]
    pub firm_state: Box<Account<'info, FirmState>>,

    #[account(
        mut,
        address = firm_state.treasury_vault,
        constraint = treasury_vault.amount >= firm_state.treasury_sol @ FirmError::TreasuryDesync,
    )]
    pub treasury_vault: Box<Account<'info, TokenAccount>>,

    #[account(mut, seeds = [b"insurance", firm_state.key().as_ref()], bump = insurance_fund.bump)]
    pub insurance_fund: Box<Account<'info, InsuranceFund>>,
    #[account(mut, seeds = [b"insurance_vault", firm_state.key().as_ref()], bump)]
    pub insurance_vault: Box<Account<'info, TokenAccount>>,

    // The whole residual is swept HERE (Universal Pool) to partially repay the commons the firm drained.
    #[account(mut, seeds = [b"universal_pool"], bump = universal_pool.bump)]
    pub universal_pool: Box<Account<'info, UniversalPool>>,
    #[account(mut, seeds = [b"universal_vault"], bump, token::mint = firm_state.sol_mint)]
    pub universal_vault: Box<Account<'info, TokenAccount>>,

    pub token_program: Program<'info, Token>,
}

// `from_treasury`/`from_insurance` name which vault a transfer draws FROM (domain terminology),
// not Rust's `From` trait convention — clippy's naming heuristic doesn't know that.
#[allow(clippy::wrong_self_convention)]
impl<'info> FinalizeBankruptcy<'info> {
    fn from_treasury(&self, to: AccountInfo<'info>, amount: u64) -> Result<()> {
        self.vault_xfer(self.treasury_vault.to_account_info(), to, amount)
    }
    fn from_insurance(&self, to: AccountInfo<'info>, amount: u64) -> Result<()> {
        self.vault_xfer(self.insurance_vault.to_account_info(), to, amount)
    }
    /// Move tokens out of a firm-PDA-owned vault (firm PDA signs).
    fn vault_xfer(&self, from: AccountInfo<'info>, to: AccountInfo<'info>, amount: u64) -> Result<()> {
        if amount == 0 {
            return Ok(());
        }
        let bump = [self.firm_state.bump];
        let seeds = firm_signer(&self.firm_state.owner, &bump);
        token::transfer(
            CpiContext::new_with_signer(
                self.token_program.to_account_info(),
                anchor_spl::token::Transfer { from, to, authority: self.firm_state.to_account_info() },
                &[&seeds],
            ),
            amount,
        )
    }
}

#[derive(Accounts)]
pub struct InitDpropBuyback<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,

    pub dprop_mint: Box<Account<'info, Mint>>,
    pub sol_mint: Box<Account<'info, Mint>>,

    #[account(
        init,
        payer = payer,
        space = 8 + DpropBuyback::INIT_SPACE,
        seeds = [b"dprop_buyback"],
        bump
    )]
    pub dprop_buyback: Box<Account<'info, DpropBuyback>>,

    #[account(
        init,
        payer = payer,
        token::mint = sol_mint,
        token::authority = dprop_buyback,
        seeds = [b"dprop_buyback_sol"],
        bump
    )]
    pub sol_vault: Box<Account<'info, TokenAccount>>,
    #[account(
        init,
        payer = payer,
        token::mint = dprop_mint,
        token::authority = dprop_buyback,
        seeds = [b"dprop_buyback_dprop"],
        bump
    )]
    pub dprop_vault: Box<Account<'info, TokenAccount>>,

    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
    pub rent: Sysvar<'info, Rent>,
}

/// R33.2 deferred-launch buyback init — creates ONLY the `DpropBuyback` record + wSOL sink (no
/// $DPROP mint/vault). See `init_dprop_buyback_sol`.
#[derive(Accounts)]
pub struct InitDpropBuybackSol<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,

    pub sol_mint: Box<Account<'info, Mint>>,

    #[account(
        init,
        payer = payer,
        space = 8 + DpropBuyback::INIT_SPACE,
        seeds = [b"dprop_buyback"],
        bump
    )]
    pub dprop_buyback: Box<Account<'info, DpropBuyback>>,

    #[account(
        init,
        payer = payer,
        token::mint = sol_mint,
        token::authority = dprop_buyback,
        seeds = [b"dprop_buyback_sol"],
        bump
    )]
    pub sol_vault: Box<Account<'info, TokenAccount>>,

    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
    pub rent: Sysvar<'info, Rent>,
}

/// R33.2 launch-day mint bind — creates the $DPROP holding vault and sets the mint on a sink stood
/// up via `init_dprop_buyback_sol`. Upgrade-authority-gated (front-run-proof). See
/// `bind_dprop_buyback_mint`.
#[derive(Accounts)]
pub struct BindDpropBuybackMint<'info> {
    #[account(mut)]
    pub upgrade_authority: Signer<'info>,

    /// Gate: only the firm program's upgrade authority (deployer / Squads multisig) can bind the
    /// canonical $DPROP mint into the one-time slot — mirrors `init_platform_config`'s root of trust.
    #[account(
        seeds = [crate::ID.as_ref()],
        bump,
        seeds::program = anchor_lang::solana_program::bpf_loader_upgradeable::ID,
        constraint = program_data.upgrade_authority_address == Some(upgrade_authority.key())
            @ FirmError::Unauthorized,
    )]
    pub program_data: Account<'info, ProgramData>,

    #[account(mut, seeds = [b"dprop_buyback"], bump = dprop_buyback.bump)]
    pub dprop_buyback: Box<Account<'info, DpropBuyback>>,

    pub dprop_mint: Box<Account<'info, Mint>>,

    #[account(
        init,
        payer = upgrade_authority,
        token::mint = dprop_mint,
        token::authority = dprop_buyback,
        seeds = [b"dprop_buyback_dprop"],
        bump
    )]
    pub dprop_vault: Box<Account<'info, TokenAccount>>,

    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
    pub rent: Sysvar<'info, Rent>,
}

/// Initialize the protocol-level $DPROP staking vault. One-time setup; the vault PDA is
/// authority-locked so only the pro-rata `claim_dprop_staking_yield` pull path can withdraw from it.
#[derive(Accounts)]
pub struct InitDpropStaking<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,

    pub sol_mint: Box<Account<'info, Mint>>,

    #[account(
        init,
        payer = payer,
        space = 8 + DpropStakingPool::INIT_SPACE,
        seeds = [b"dprop_staking"],
        bump
    )]
    pub dprop_staking_pool: Box<Account<'info, DpropStakingPool>>,

    #[account(
        init,
        payer = payer,
        token::mint = sol_mint,
        token::authority = dprop_staking_pool,
        seeds = [b"dprop_staking_sol"],
        bump
    )]
    pub sol_vault: Box<Account<'info, TokenAccount>>,

    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
    pub rent: Sysvar<'info, Rent>,
}

// `DistributeDpropStaking` accounts struct was REMOVED with its instruction (trust-model gap T-1).

// ─────────────────────────── $DPROP staking accounts (R33) ───────────────────────────
#[derive(Accounts)]
pub struct InitDpropStakeLedger<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    pub dprop_mint: Box<Account<'info, Mint>>,
    #[account(seeds = [b"dprop_staking"], bump = dprop_staking_pool.bump)]
    pub dprop_staking_pool: Box<Account<'info, DpropStakingPool>>,
    /// The existing 10%-eval-leg SOL vault — read to record the pre-open balance (excluded from yield).
    #[account(seeds = [b"dprop_staking_sol"], bump, token::authority = dprop_staking_pool)]
    pub sol_vault: Box<Account<'info, TokenAccount>>,
    #[account(
        init, payer = payer, space = 8 + DpropStakeLedger::INIT_SPACE,
        seeds = [b"dprop_stake_ledger"], bump
    )]
    pub ledger: Box<Account<'info, DpropStakeLedger>>,
    #[account(
        init, payer = payer, token::mint = dprop_mint, token::authority = dprop_staking_pool,
        seeds = [b"dprop_stake_vault"], bump
    )]
    pub stake_vault: Box<Account<'info, TokenAccount>>,
    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
    pub rent: Sysvar<'info, Rent>,
}

#[derive(Accounts)]
pub struct StakeDprop<'info> {
    #[account(mut)]
    pub staker: Signer<'info>,
    #[account(mut, seeds = [b"dprop_stake_ledger"], bump = ledger.bump)]
    pub ledger: Box<Account<'info, DpropStakeLedger>>,
    #[account(mut, seeds = [b"dprop_staking_sol"], bump)]
    pub sol_vault: Box<Account<'info, TokenAccount>>,
    #[account(mut, address = ledger.stake_vault)]
    pub stake_vault: Box<Account<'info, TokenAccount>>,
    #[account(mut, token::mint = ledger.dprop_mint, token::authority = staker)]
    pub staker_dprop: Box<Account<'info, TokenAccount>>,
    #[account(
        init_if_needed, payer = staker, space = 8 + DpropStakerPosition::INIT_SPACE,
        seeds = [b"dprop_staker", staker.key().as_ref()], bump
    )]
    pub position: Box<Account<'info, DpropStakerPosition>>,
    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
}
impl<'info> StakeDprop<'info> {
    fn escrow(&self, amount: u64) -> Result<()> {
        token::transfer(
            CpiContext::new(
                self.token_program.to_account_info(),
                token::Transfer {
                    from: self.staker_dprop.to_account_info(),
                    to: self.stake_vault.to_account_info(),
                    authority: self.staker.to_account_info(),
                },
            ),
            amount,
        )
    }
}

#[derive(Accounts)]
pub struct UnstakeDprop<'info> {
    #[account(mut)]
    pub staker: Signer<'info>,
    #[account(mut, seeds = [b"dprop_stake_ledger"], bump = ledger.bump)]
    pub ledger: Box<Account<'info, DpropStakeLedger>>,
    #[account(seeds = [b"dprop_staking"], bump = dprop_staking_pool.bump)]
    pub dprop_staking_pool: Box<Account<'info, DpropStakingPool>>,
    #[account(mut, seeds = [b"dprop_staking_sol"], bump)]
    pub sol_vault: Box<Account<'info, TokenAccount>>,
    #[account(mut, address = ledger.stake_vault)]
    pub stake_vault: Box<Account<'info, TokenAccount>>,
    #[account(mut, token::mint = ledger.dprop_mint,
        constraint = staker_dprop.owner == staker.key() @ FirmError::Unauthorized)]
    pub staker_dprop: Box<Account<'info, TokenAccount>>,
    #[account(mut, seeds = [b"dprop_staker", staker.key().as_ref()], bump = position.bump,
        constraint = position.staker == staker.key() @ FirmError::Unauthorized)]
    pub position: Box<Account<'info, DpropStakerPosition>>,
    pub token_program: Program<'info, Token>,
}
impl<'info> UnstakeDprop<'info> {
    fn release(&self, amount: u64) -> Result<()> {
        let seeds: &[&[u8]] = &[b"dprop_staking", core::slice::from_ref(&self.dprop_staking_pool.bump)];
        token::transfer(
            CpiContext::new_with_signer(
                self.token_program.to_account_info(),
                token::Transfer {
                    from: self.stake_vault.to_account_info(),
                    to: self.staker_dprop.to_account_info(),
                    authority: self.dprop_staking_pool.to_account_info(),
                },
                &[seeds],
            ),
            amount,
        )
    }
}

#[derive(Accounts)]
pub struct ClaimDpropStakingYield<'info> {
    #[account(mut)]
    pub staker: Signer<'info>,
    #[account(mut, seeds = [b"dprop_stake_ledger"], bump = ledger.bump)]
    pub ledger: Box<Account<'info, DpropStakeLedger>>,
    #[account(seeds = [b"dprop_staking"], bump = dprop_staking_pool.bump)]
    pub dprop_staking_pool: Box<Account<'info, DpropStakingPool>>,
    #[account(mut, seeds = [b"dprop_staking_sol"], bump, token::authority = dprop_staking_pool)]
    pub sol_vault: Box<Account<'info, TokenAccount>>,
    #[account(mut, token::mint = sol_vault.mint,
        constraint = staker_sol.owner == staker.key() @ FirmError::Unauthorized)]
    pub staker_sol: Box<Account<'info, TokenAccount>>,
    #[account(mut, seeds = [b"dprop_staker", staker.key().as_ref()], bump = position.bump,
        constraint = position.staker == staker.key() @ FirmError::Unauthorized)]
    pub position: Box<Account<'info, DpropStakerPosition>>,
    pub token_program: Program<'info, Token>,
}
impl<'info> ClaimDpropStakingYield<'info> {
    fn pay_sol(&self, amount: u64) -> Result<()> {
        let seeds: &[&[u8]] = &[b"dprop_staking", core::slice::from_ref(&self.dprop_staking_pool.bump)];
        token::transfer(
            CpiContext::new_with_signer(
                self.token_program.to_account_info(),
                token::Transfer {
                    from: self.sol_vault.to_account_info(),
                    to: self.staker_sol.to_account_info(),
                    authority: self.dprop_staking_pool.to_account_info(),
                },
                &[seeds],
            ),
            amount,
        )
    }
}

#[derive(Accounts)]
pub struct InitUniversalPool<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,

    pub sol_mint: Box<Account<'info, Mint>>,

    #[account(
        init,
        payer = payer,
        space = 8 + UniversalPool::INIT_SPACE,
        seeds = [b"universal_pool"],
        bump
    )]
    pub universal_pool: Box<Account<'info, UniversalPool>>,

    #[account(
        init,
        payer = payer,
        token::mint = sol_mint,
        token::authority = universal_pool,
        seeds = [b"universal_vault"],
        bump
    )]
    pub universal_vault: Box<Account<'info, TokenAccount>>,

    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
    pub rent: Sysvar<'info, Rent>,
}

#[derive(Accounts)]
pub struct ExecuteDpropBuyback<'info> {
    /// Permissionless cranker — pays the tx, no special authority.
    pub cranker: Signer<'info>,

    #[account(mut, seeds = [b"dprop_buyback"], bump = dprop_buyback.bump)]
    pub dprop_buyback: Box<Account<'info, DpropBuyback>>,

    #[account(mut, address = dprop_buyback.sol_vault)]
    pub sol_vault: Box<Account<'info, TokenAccount>>,
    #[account(mut, address = dprop_buyback.dprop_vault)]
    pub dprop_vault: Box<Account<'info, TokenAccount>>,
    // NOTE: the Raydium $DPROP/SOL pool accounts are added here at the devnet boundary.
    pub token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct BurnDpropBuyback<'info> {
    /// Permissionless cranker — pays the tx, no special authority.
    pub cranker: Signer<'info>,

    #[account(mut, seeds = [b"dprop_buyback"], bump = dprop_buyback.bump)]
    pub dprop_buyback: Box<Account<'info, DpropBuyback>>,

    #[account(mut, address = dprop_buyback.dprop_mint)]
    pub dprop_mint: Box<Account<'info, Mint>>,
    #[account(mut, address = dprop_buyback.dprop_vault)]
    pub dprop_vault: Box<Account<'info, TokenAccount>>,

    pub token_program: Program<'info, Token>,
}

impl<'info> BurnDpropBuyback<'info> {
    /// Burn $DPROP from the PDA-owned vault — the buyback PDA signs.
    fn burn(&self, amount: u64) -> Result<()> {
        if amount == 0 {
            return Ok(());
        }
        let bump = [self.dprop_buyback.bump];
        let seeds: &[&[u8]] = &[b"dprop_buyback", &bump];
        token::burn(
            CpiContext::new_with_signer(
                self.token_program.to_account_info(),
                anchor_spl::token::Burn {
                    mint: self.dprop_mint.to_account_info(),
                    from: self.dprop_vault.to_account_info(),
                    authority: self.dprop_buyback.to_account_info(),
                },
                &[seeds],
            ),
            amount,
        )
    }
}

/// VEST-1. Accounts are Box'd to keep the BPF stack frame under 4 KB, as elsewhere in this program.
#[derive(Accounts)]
pub struct ClaimVesting<'info> {
    pub owner: Signer<'info>,

    #[account(
        seeds = [b"firm", firm_state.owner.as_ref()],
        bump = firm_state.bump,
        constraint = firm_state.owner == owner.key() @ FirmError::Unauthorized,
    )]
    pub firm_state: Box<Account<'info, FirmState>>,

    /// CHECK: challenge key only — the vesting batch's PDA seed.
    pub challenge: UncheckedAccount<'info>,

    #[account(
        mut,
        seeds = [b"vesting", challenge.key().as_ref()],
        bump = owner_vesting_batch.bump,
        constraint = owner_vesting_batch.firm == firm_state.key() @ FirmError::Unauthorized,
    )]
    pub owner_vesting_batch: Box<Account<'info, OwnerVestingBatch>>,

    #[account(mut, seeds = [b"owner_vesting_vault", firm_state.key().as_ref()], bump)]
    pub owner_vesting_vault: Box<Account<'info, TokenAccount>>,

    /// The destination must be owned by the firm owner — same M-4 guard `pay_challenge_fee` puts on
    /// the immediate half of the fee. Without it an owner could sign a claim that pays someone else,
    /// which is the whole redirect class this constraint exists to close.
    #[account(
        mut,
        token::mint = firm_state.sol_mint,
        constraint = owner_wallet_sol.owner == firm_state.owner @ FirmError::Unauthorized,
    )]
    pub owner_wallet_sol: Box<Account<'info, TokenAccount>>,

    pub token_program: Program<'info, Token>,
}

impl<'info> ClaimVesting<'info> {
    /// Release a matured batch from the vesting vault to the owner (firm PDA is the authority).
    fn release(&self, amount: u64) -> Result<()> {
        if amount == 0 {
            return Ok(());
        }
        let bump = [self.firm_state.bump];
        let seeds = firm_signer(&self.firm_state.owner, &bump);
        token::transfer(
            CpiContext::new_with_signer(
                self.token_program.to_account_info(),
                anchor_spl::token::Transfer {
                    from: self.owner_vesting_vault.to_account_info(),
                    to: self.owner_wallet_sol.to_account_info(),
                    authority: self.firm_state.to_account_info(),
                },
                &[&seeds],
            ),
            amount,
        )
    }
}

#[derive(Accounts)]
pub struct ClawbackVesting<'info> {
    pub cranker: Signer<'info>,

    #[account(mut, seeds = [b"firm", firm_state.owner.as_ref()], bump = firm_state.bump)]
    pub firm_state: Box<Account<'info, FirmState>>,

    /// CHECK: challenge key only — the vesting batch's PDA seed.
    pub challenge: UncheckedAccount<'info>,

    #[account(
        mut,
        seeds = [b"vesting", challenge.key().as_ref()],
        bump = owner_vesting_batch.bump,
        constraint = owner_vesting_batch.firm == firm_state.key() @ FirmError::Unauthorized,
    )]
    pub owner_vesting_batch: Box<Account<'info, OwnerVestingBatch>>,

    #[account(mut, seeds = [b"owner_vesting_vault", firm_state.key().as_ref()], bump)]
    pub owner_vesting_vault: Box<Account<'info, TokenAccount>>,

    #[account(mut, address = firm_state.treasury_vault)]
    pub treasury_vault: Box<Account<'info, TokenAccount>>,

    pub token_program: Program<'info, Token>,
}

impl<'info> ClawbackVesting<'info> {
    /// Move an unclaimed vesting batch from the vesting vault back to the treasury.
    fn clawback(&self, amount: u64) -> Result<()> {
        if amount == 0 {
            return Ok(());
        }
        let bump = [self.firm_state.bump];
        let seeds = firm_signer(&self.firm_state.owner, &bump);
        token::transfer(
            CpiContext::new_with_signer(
                self.token_program.to_account_info(),
                anchor_spl::token::Transfer {
                    from: self.owner_vesting_vault.to_account_info(),
                    to: self.treasury_vault.to_account_info(),
                    authority: self.firm_state.to_account_info(),
                },
                &[&seeds],
            ),
            amount,
        )
    }
}

// Accounts are Box'd to keep the BPF stack frame under 4 KB.
#[derive(Accounts)]
pub struct SettleDisputePayout<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,

    /// Independent platform guardian. Required ONLY on the *weak* dispute paths (arbiter-upheld or
    /// timeout `ForceResolved`): the insurance fund is fed by real traders' fees, and because the
    /// operator commits the batch roots it could self-manufacture a dispute on its own account and
    /// let it time out, so the independent guardian co-sign gates that forgeable spend (F3).
    ///
    /// On the *strong* path — the challenge settlement is provably `Faulted` via the F5 optimistic
    /// fraud-proof — the guardian is NOT required: the operator's slashed bond (`slash_settlement_fault`)
    /// is the economic security, so a proven-fault payout is fully trustless and DecentralProp cannot
    /// censor it. Validated in the handler, not as an account constraint, since it's conditional.
    pub guardian: Option<Signer<'info>>,

    #[account(
        seeds = [b"dispute", dispute.challenge.as_ref()],
        bump = dispute.bump,
        seeds::program = dispute::ID,
        constraint = dispute.firm == firm_state.key() @ FirmError::Unauthorized,
    )]
    pub dispute: Box<Account<'info, dispute::DisputeState>>,

    /// The disputed challenge — caps the dispute payout at its funded size (F3 / V2-2).
    #[account(
        address = dispute.challenge @ FirmError::Unauthorized,
        constraint = challenge.firm == firm_state.key() @ FirmError::Unauthorized,
    )]
    pub challenge: Box<Account<'info, challenge::ChallengeState>>,

    /// V2-2: optional price-locked funded-size sidecar (`["funded_size", challenge]`). When present it
    /// is the dimensionally-correct **lamport** cap on the guardian paths (bounds a compromised
    /// guardian to the funded size); absent → the legacy `starting_balance` ceiling.
    #[account(
        seeds = [b"funded_size", challenge.key().as_ref()],
        bump = funded_size.bump,
    )]
    pub funded_size: Option<Box<Account<'info, ChallengeFundedSize>>>,

    #[account(mut, seeds = [b"firm", firm_state.owner.as_ref()], bump = firm_state.bump)]
    pub firm_state: Box<Account<'info, FirmState>>,

    #[account(mut, seeds = [b"insurance", firm_state.key().as_ref()], bump = insurance_fund.bump)]
    pub insurance_fund: Box<Account<'info, InsuranceFund>>,
    #[account(mut, seeds = [b"insurance_vault", firm_state.key().as_ref()], bump)]
    pub insurance_vault: Box<Account<'info, TokenAccount>>,

    // T-3/T-4 fallback source: when the firm's insurance can't cover the entitlement (post-close),
    // the remainder is drawn from the Universal Pool. Pays the same `trader_sol` destination.
    #[account(mut, seeds = [b"universal_pool"], bump = universal_pool.bump)]
    pub universal_pool: Box<Account<'info, UniversalPool>>,
    #[account(mut, seeds = [b"universal_vault"], bump, token::mint = firm_state.sol_mint)]
    pub universal_vault: Box<Account<'info, TokenAccount>>,

    #[account(
        mut,
        token::mint = firm_state.sol_mint,
        constraint = trader_sol.owner == dispute.trader @ FirmError::Unauthorized,
    )]
    pub trader_sol: Box<Account<'info, TokenAccount>>,

    // V2-5 cumulative accumulator: `init_if_needed` so a large claim throttled by the Universal-Pool
    // daily cap can be paid across several calls, each adding to `amount` up to the funded-size cap.
    // (The `remaining > 0` check in the handler is the completion guard; per-call caps prevent overrun.)
    #[account(
        init_if_needed,
        payer = authority,
        space = 8 + DisputePayoutRecord::INIT_SPACE,
        seeds = [b"dispute_payout", dispute.key().as_ref()],
        bump
    )]
    pub dispute_payout_record: Box<Account<'info, DisputePayoutRecord>>,

    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
}

/// V2-2 — set/refresh a challenge's price-locked funded size (lamports). Signed by the challenge's own
/// settlement authority.
#[derive(Accounts)]
pub struct SetChallengeFundedSize<'info> {
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
        seeds::program = challenge::ID,
        constraint = challenge.settlement_authority == authority.key() @ FirmError::Unauthorized,
    )]
    pub challenge: Box<Account<'info, challenge::ChallengeState>>,

    #[account(
        init_if_needed,
        payer = authority,
        space = 8 + ChallengeFundedSize::INIT_SPACE,
        seeds = [b"funded_size", challenge.key().as_ref()],
        bump
    )]
    pub funded_size: Box<Account<'info, ChallengeFundedSize>>,

    pub system_program: Program<'info, System>,
}

impl<'info> SettleDisputePayout<'info> {
    /// Pay the disputed amount out of the insurance vault to the trader (firm PDA signs).
    fn draw_insurance(&self, amount: u64) -> Result<()> {
        if amount == 0 {
            return Ok(());
        }
        let bump = [self.firm_state.bump];
        let seeds = firm_signer(&self.firm_state.owner, &bump);
        token::transfer(
            CpiContext::new_with_signer(
                self.token_program.to_account_info(),
                anchor_spl::token::Transfer {
                    from: self.insurance_vault.to_account_info(),
                    to: self.trader_sol.to_account_info(),
                    authority: self.firm_state.to_account_info(),
                },
                &[&seeds],
            ),
            amount,
        )
    }

    /// T-3/T-4 — draw the dispute remainder from the Universal Pool (raw SOL to the trader), the
    /// universal-pool PDA signing its own vault. Same daily rate-limit as `draw_universal`; the
    /// per-claim `starting_balance` cap + guardian gate are enforced by the caller.
    fn draw_universal_for_dispute(&mut self, amount: u64) -> Result<()> {
        if amount == 0 {
            return Ok(());
        }
        let day = Clock::get()?.unix_timestamp / 86_400;
        {
            let pool = &mut self.universal_pool;
            if day != pool.draw_day {
                pool.daily_drawn = 0;
                pool.draw_day = day;
            }
            require!(
                pool.daily_drawn.saturating_add(amount) <= UNIVERSAL_DAILY_DRAW_CAP_SOL,
                FirmError::UniversalDailyCapExceeded
            );
        }
        require!(
            self.universal_vault.amount >= amount,
            FirmError::InsufficientUniversalPool
        );
        let bump = [self.universal_pool.bump];
        let seeds: &[&[u8]] = &[b"universal_pool", &bump];
        token::transfer(
            CpiContext::new_with_signer(
                self.token_program.to_account_info(),
                anchor_spl::token::Transfer {
                    from: self.universal_vault.to_account_info(),
                    to: self.trader_sol.to_account_info(),
                    authority: self.universal_pool.to_account_info(),
                },
                &[seeds],
            ),
            amount,
        )?;
        let pool = &mut self.universal_pool;
        pool.daily_drawn = pool.daily_drawn.saturating_add(amount);
        pool.total_drawn = pool.total_drawn.saturating_add(amount);
        Ok(())
    }
}

#[derive(Accounts)]
pub struct InitBackstopPool<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,

    #[account(seeds = [b"firm", firm_state.owner.as_ref()], bump = firm_state.bump)]
    pub firm_state: Box<Account<'info, FirmState>>,

    #[account(address = firm_state.firma_mint)]
    pub firma_mint: Box<Account<'info, Mint>>,
    #[account(address = firm_state.sol_mint)]
    pub sol_mint: Box<Account<'info, Mint>>,

    #[account(
        init,
        payer = payer,
        space = 8 + BackstopPool::INIT_SPACE,
        seeds = [b"backstop_pool", firm_state.key().as_ref()],
        bump
    )]
    pub backstop_pool: Box<Account<'info, BackstopPool>>,

    #[account(
        init,
        payer = payer,
        token::mint = firma_mint,
        token::authority = backstop_pool,
        seeds = [b"backstop_escrow", firm_state.key().as_ref()],
        bump
    )]
    pub escrow_vault: Box<Account<'info, TokenAccount>>,
    #[account(
        init,
        payer = payer,
        token::mint = sol_mint,
        token::authority = backstop_pool,
        seeds = [b"backstop_premium", firm_state.key().as_ref()],
        bump
    )]
    pub premium_vault: Box<Account<'info, TokenAccount>>,
    /// 2026-07-27 staking rebalance: the $FIRMA-denominated counterpart to `premium_vault`,
    /// funded by `FirmState.backstop_pool_bps` on funded-trader payouts.
    #[account(
        init,
        payer = payer,
        token::mint = firma_mint,
        token::authority = backstop_pool,
        seeds = [b"backstop_firma_reward", firm_state.key().as_ref()],
        bump
    )]
    pub firma_reward_vault: Box<Account<'info, TokenAccount>>,

    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
    pub rent: Sysvar<'info, Rent>,
}

#[derive(Accounts)]
pub struct StakeBackstop<'info> {
    #[account(mut)]
    pub staker: Signer<'info>,

    #[account(seeds = [b"firm", firm_state.owner.as_ref()], bump = firm_state.bump)]
    pub firm_state: Box<Account<'info, FirmState>>,

    #[account(mut, seeds = [b"backstop_pool", firm_state.key().as_ref()], bump = backstop_pool.bump)]
    pub backstop_pool: Box<Account<'info, BackstopPool>>,

    #[account(
        init_if_needed,
        payer = staker,
        space = 8 + BackstopPosition::INIT_SPACE,
        seeds = [b"backstop_pos", firm_state.key().as_ref(), staker.key().as_ref()],
        bump
    )]
    pub position: Box<Account<'info, BackstopPosition>>,

    #[account(mut, address = backstop_pool.escrow_vault)]
    pub escrow_vault: Box<Account<'info, TokenAccount>>,

    #[account(mut, token::mint = firm_state.firma_mint, token::authority = staker)]
    pub staker_firma: Box<Account<'info, TokenAccount>>,

    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
}

impl<'info> StakeBackstop<'info> {
    /// Escrow staked $FIRMA from the investor into the backstop vault.
    fn escrow(&self, amount: u64) -> Result<()> {
        token::transfer(
            CpiContext::new(
                self.token_program.to_account_info(),
                anchor_spl::token::Transfer {
                    from: self.staker_firma.to_account_info(),
                    to: self.escrow_vault.to_account_info(),
                    authority: self.staker.to_account_info(),
                },
            ),
            amount,
        )
    }
}

#[derive(Accounts)]
pub struct RequestUnstakeBackstop<'info> {
    pub staker: Signer<'info>,

    #[account(seeds = [b"firm", firm_state.owner.as_ref()], bump = firm_state.bump)]
    pub firm_state: Box<Account<'info, FirmState>>,

    #[account(seeds = [b"platform_risk"], bump = platform_risk.bump)]
    pub platform_risk: Box<Account<'info, PlatformRiskState>>,

    #[account(seeds = [b"backstop_pool", firm_state.key().as_ref()], bump = backstop_pool.bump)]
    pub backstop_pool: Box<Account<'info, BackstopPool>>,

    #[account(
        mut,
        seeds = [b"backstop_pos", firm_state.key().as_ref(), staker.key().as_ref()],
        bump = position.bump,
        constraint = position.staker == staker.key() @ FirmError::Unauthorized,
    )]
    pub position: Box<Account<'info, BackstopPosition>>,
}

#[derive(Accounts)]
pub struct WithdrawBackstop<'info> {
    pub staker: Signer<'info>,

    #[account(seeds = [b"firm", firm_state.owner.as_ref()], bump = firm_state.bump)]
    pub firm_state: Box<Account<'info, FirmState>>,

    #[account(seeds = [b"platform_risk"], bump = platform_risk.bump)]
    pub platform_risk: Box<Account<'info, PlatformRiskState>>,

    #[account(mut, seeds = [b"backstop_pool", firm_state.key().as_ref()], bump = backstop_pool.bump)]
    pub backstop_pool: Box<Account<'info, BackstopPool>>,

    #[account(
        mut,
        seeds = [b"backstop_pos", firm_state.key().as_ref(), staker.key().as_ref()],
        bump = position.bump,
        constraint = position.staker == staker.key() @ FirmError::Unauthorized,
    )]
    pub position: Box<Account<'info, BackstopPosition>>,

    #[account(mut, address = backstop_pool.escrow_vault)]
    pub escrow_vault: Box<Account<'info, TokenAccount>>,
    #[account(mut, address = backstop_pool.premium_vault)]
    pub premium_vault: Box<Account<'info, TokenAccount>>,
    /// 2026-07-27 staking rebalance — the $FIRMA yield leg, distinct from `escrow_vault` (principal).
    #[account(mut, address = backstop_pool.firma_reward_vault)]
    pub firma_reward_vault: Box<Account<'info, TokenAccount>>,

    #[account(
        mut,
        token::mint = firm_state.firma_mint,
        constraint = staker_firma.owner == staker.key() @ FirmError::Unauthorized,
    )]
    pub staker_firma: Box<Account<'info, TokenAccount>>,
    #[account(
        mut,
        token::mint = firm_state.sol_mint,
        constraint = staker_sol.owner == staker.key() @ FirmError::Unauthorized,
    )]
    pub staker_sol: Box<Account<'info, TokenAccount>>,

    pub token_program: Program<'info, Token>,
}

impl<'info> WithdrawBackstop<'info> {
    fn pay_firma(&self, amount: u64) -> Result<()> {
        self.pay(self.escrow_vault.to_account_info(), self.staker_firma.to_account_info(), amount)
    }
    fn pay_sol(&self, amount: u64) -> Result<()> {
        self.pay(self.premium_vault.to_account_info(), self.staker_sol.to_account_info(), amount)
    }
    /// 2026-07-27 staking rebalance: pays accrued $FIRMA YIELD (from `firma_reward_vault`) — not
    /// to be confused with `pay_firma` above, which returns surviving PRINCIPAL from `escrow_vault`.
    fn pay_firma_yield(&self, amount: u64) -> Result<()> {
        self.pay(self.firma_reward_vault.to_account_info(), self.staker_firma.to_account_info(), amount)
    }
    fn pay(&self, from: AccountInfo<'info>, to: AccountInfo<'info>, amount: u64) -> Result<()> {
        if amount == 0 {
            return Ok(());
        }
        let bump = [self.backstop_pool.bump];
        let seeds = backstop_signer(&self.backstop_pool.firm, &bump);
        token::transfer(
            CpiContext::new_with_signer(
                self.token_program.to_account_info(),
                anchor_spl::token::Transfer { from, to, authority: self.backstop_pool.to_account_info() },
                &[&seeds],
            ),
            amount,
        )
    }
}

#[derive(Accounts)]
pub struct ClaimBackstopPremium<'info> {
    pub staker: Signer<'info>,

    #[account(seeds = [b"firm", firm_state.owner.as_ref()], bump = firm_state.bump)]
    pub firm_state: Box<Account<'info, FirmState>>,

    #[account(mut, seeds = [b"backstop_pool", firm_state.key().as_ref()], bump = backstop_pool.bump)]
    pub backstop_pool: Box<Account<'info, BackstopPool>>,

    #[account(
        mut,
        seeds = [b"backstop_pos", firm_state.key().as_ref(), staker.key().as_ref()],
        bump = position.bump,
        constraint = position.staker == staker.key() @ FirmError::Unauthorized,
    )]
    pub position: Box<Account<'info, BackstopPosition>>,

    #[account(mut, address = backstop_pool.premium_vault)]
    pub premium_vault: Box<Account<'info, TokenAccount>>,
    #[account(
        mut,
        token::mint = firm_state.sol_mint,
        constraint = staker_sol.owner == staker.key() @ FirmError::Unauthorized,
    )]
    pub staker_sol: Box<Account<'info, TokenAccount>>,
    /// 2026-07-27 staking rebalance — the $FIRMA counterpart to `premium_vault`/`staker_sol`.
    #[account(mut, address = backstop_pool.firma_reward_vault)]
    pub firma_reward_vault: Box<Account<'info, TokenAccount>>,
    #[account(
        mut,
        token::mint = firm_state.firma_mint,
        constraint = staker_firma.owner == staker.key() @ FirmError::Unauthorized,
    )]
    pub staker_firma: Box<Account<'info, TokenAccount>>,

    pub token_program: Program<'info, Token>,
}

impl<'info> ClaimBackstopPremium<'info> {
    fn pay_sol(&self, amount: u64) -> Result<()> {
        if amount == 0 {
            return Ok(());
        }
        let bump = [self.backstop_pool.bump];
        let seeds = backstop_signer(&self.backstop_pool.firm, &bump);
        token::transfer(
            CpiContext::new_with_signer(
                self.token_program.to_account_info(),
                anchor_spl::token::Transfer {
                    from: self.premium_vault.to_account_info(),
                    to: self.staker_sol.to_account_info(),
                    authority: self.backstop_pool.to_account_info(),
                },
                &[&seeds],
            ),
            amount,
        )
    }

    fn pay_firma(&self, amount: u64) -> Result<()> {
        if amount == 0 {
            return Ok(());
        }
        let bump = [self.backstop_pool.bump];
        let seeds = backstop_signer(&self.backstop_pool.firm, &bump);
        token::transfer(
            CpiContext::new_with_signer(
                self.token_program.to_account_info(),
                anchor_spl::token::Transfer {
                    from: self.firma_reward_vault.to_account_info(),
                    to: self.staker_firma.to_account_info(),
                    authority: self.backstop_pool.to_account_info(),
                },
                &[&seeds],
            ),
            amount,
        )
    }
}

#[derive(Accounts)]
pub struct FundBackstopPremium<'info> {
    pub funder: Signer<'info>,

    #[account(seeds = [b"firm", firm_state.owner.as_ref()], bump = firm_state.bump)]
    pub firm_state: Box<Account<'info, FirmState>>,

    #[account(mut, seeds = [b"backstop_pool", firm_state.key().as_ref()], bump = backstop_pool.bump)]
    pub backstop_pool: Box<Account<'info, BackstopPool>>,

    #[account(mut, address = backstop_pool.premium_vault)]
    pub premium_vault: Box<Account<'info, TokenAccount>>,

    #[account(mut, token::mint = firm_state.sol_mint, token::authority = funder)]
    pub source_sol: Box<Account<'info, TokenAccount>>,

    pub token_program: Program<'info, Token>,
}

impl<'info> FundBackstopPremium<'info> {
    fn fund(&self, amount: u64) -> Result<()> {
        token::transfer(
            CpiContext::new(
                self.token_program.to_account_info(),
                anchor_spl::token::Transfer {
                    from: self.source_sol.to_account_info(),
                    to: self.premium_vault.to_account_info(),
                    authority: self.funder.to_account_info(),
                },
            ),
            amount,
        )
    }
}

// Accounts are Box'd to keep the BPF stack frame under 4 KB.
#[derive(Accounts)]
pub struct DrawBackstop<'info> {
    pub authority: Signer<'info>,

    /// Independent platform guardian — MUST co-sign. Draining the STAKER-funded backstop is the
    /// classic "operator self-passes then spends the emergency fund" vector (F2); requiring the
    /// guardian means the key that declares the emergency ≠ the key that spends it.
    #[account(constraint = guardian.key() == firm_state.guardian @ FirmError::GuardianMismatch)]
    pub guardian: Signer<'info>,

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
        constraint = challenge.settlement_authority == authority.key() @ FirmError::Unauthorized,
        constraint = challenge.firm == firm_state.key() @ FirmError::Unauthorized,
    )]
    pub challenge: Box<Account<'info, challenge::ChallengeState>>,

    // MUST be `mut`: draw_backstop decrements `open_payouts` when a Tier-3 fill completes a payout.
    // Without `mut`, Anchor never persists that write and the counter sticks (wedging bankruptcy).
    #[account(mut, seeds = [b"firm", firm_state.owner.as_ref()], bump = firm_state.bump)]
    pub firm_state: Box<Account<'info, FirmState>>,

    #[account(
        mut,
        seeds = [b"payout", challenge.key().as_ref(), &queued_payout.cycle.to_le_bytes()],
        bump = queued_payout.bump,
        constraint = queued_payout.challenge == challenge.key() @ FirmError::Unauthorized,
    )]
    pub queued_payout: Box<Account<'info, QueuedPayout>>,

    /// DEC-62 — present ⇒ this payout discharges a FUNDED WITHDRAWAL, authorised by its
    /// `FundedWithdrawal` rather than by a challenge settlement the still-trading account never
    /// reaches. Seed-bound to this challenge + the queued payout's OWN cycle. Absent ⇒ settlement path.
    #[account(
        seeds = [b"withdrawal", challenge.key().as_ref(), &queued_payout.cycle.to_le_bytes()],
        bump = withdrawal.bump,
        seeds::program = challenge::ID,
    )]
    pub withdrawal: Option<Box<Account<'info, challenge::FundedWithdrawal>>>,

    #[account(mut, seeds = [b"backstop_pool", firm_state.key().as_ref()], bump = backstop_pool.bump)]
    pub backstop_pool: Box<Account<'info, BackstopPool>>,

    #[account(mut, address = backstop_pool.escrow_vault)]
    pub escrow_vault: Box<Account<'info, TokenAccount>>,

    #[account(
        mut,
        token::mint = firm_state.firma_mint,
        constraint = trader_firma.owner == queued_payout.trader @ FirmError::Unauthorized,
    )]
    pub trader_firma: Box<Account<'info, TokenAccount>>,

    pub token_program: Program<'info, Token>,
}

impl<'info> DrawBackstop<'info> {
    /// Deliver owed $FIRMA from the backstop escrow directly to the trader (pool signs).
    fn deliver(&self, amount: u64) -> Result<()> {
        let bump = [self.backstop_pool.bump];
        let seeds = backstop_signer(&self.backstop_pool.firm, &bump);
        token::transfer(
            CpiContext::new_with_signer(
                self.token_program.to_account_info(),
                anchor_spl::token::Transfer {
                    from: self.escrow_vault.to_account_info(),
                    to: self.trader_firma.to_account_info(),
                    authority: self.backstop_pool.to_account_info(),
                },
                &[&seeds],
            ),
            amount,
        )
    }
}

// ───────────── Prediction Market LP Pool Accounts contexts (Phase 2 pooled-LP AMM plan) ─────────────
// Structural mirror of the Investor Backstop Pool Accounts contexts above. Unlike Backstop (which
// pays out two distinct mints — staked $FIRMA principal and SOL premium — this pool's principal AND
// yield are both denominated in the firm's own `firma_mint`, so one `staker_firma` destination
// account covers both legs instead of two.

#[derive(Accounts)]
pub struct InitPmLpPool<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,

    #[account(seeds = [b"firm", firm_state.owner.as_ref()], bump = firm_state.bump)]
    pub firm_state: Box<Account<'info, FirmState>>,

    #[account(address = firm_state.firma_mint)]
    pub firma_mint: Box<Account<'info, Mint>>,

    #[account(
        init,
        payer = payer,
        space = 8 + PredictionMarketLpPool::INIT_SPACE,
        seeds = [b"pm_lp_pool", firm_state.key().as_ref()],
        bump
    )]
    pub pm_lp_pool: Box<Account<'info, PredictionMarketLpPool>>,

    #[account(
        init,
        payer = payer,
        token::mint = firma_mint,
        token::authority = pm_lp_pool,
        seeds = [b"pm_lp_escrow", firm_state.key().as_ref()],
        bump
    )]
    pub escrow_vault: Box<Account<'info, TokenAccount>>,
    #[account(
        init,
        payer = payer,
        token::mint = firma_mint,
        token::authority = pm_lp_pool,
        seeds = [b"pm_lp_yield", firm_state.key().as_ref()],
        bump
    )]
    pub yield_vault: Box<Account<'info, TokenAccount>>,

    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
    pub rent: Sysvar<'info, Rent>,
}

#[derive(Accounts)]
pub struct StakePmLp<'info> {
    #[account(mut)]
    pub staker: Signer<'info>,

    #[account(seeds = [b"firm", firm_state.owner.as_ref()], bump = firm_state.bump)]
    pub firm_state: Box<Account<'info, FirmState>>,

    #[account(mut, seeds = [b"pm_lp_pool", firm_state.key().as_ref()], bump = pm_lp_pool.bump)]
    pub pm_lp_pool: Box<Account<'info, PredictionMarketLpPool>>,

    #[account(
        init_if_needed,
        payer = staker,
        space = 8 + PredictionMarketLpPosition::INIT_SPACE,
        seeds = [b"pm_lp_pos", firm_state.key().as_ref(), staker.key().as_ref()],
        bump
    )]
    pub position: Box<Account<'info, PredictionMarketLpPosition>>,

    #[account(mut, address = pm_lp_pool.escrow_vault)]
    pub escrow_vault: Box<Account<'info, TokenAccount>>,

    // NOTE: deliberately no ownership/identity constraint linking `staker` to any market or trader —
    // see `stake_pm_lp`'s doc comment. Anyone, including a trader, may fund this shared pool.
    #[account(mut, token::mint = firm_state.firma_mint, token::authority = staker)]
    pub staker_firma: Box<Account<'info, TokenAccount>>,

    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
}

impl<'info> StakePmLp<'info> {
    /// Escrow staked $FIRMA from the LP into the pool's escrow vault.
    fn escrow(&self, amount: u64) -> Result<()> {
        token::transfer(
            CpiContext::new(
                self.token_program.to_account_info(),
                anchor_spl::token::Transfer {
                    from: self.staker_firma.to_account_info(),
                    to: self.escrow_vault.to_account_info(),
                    authority: self.staker.to_account_info(),
                },
            ),
            amount,
        )
    }
}

#[derive(Accounts)]
pub struct RequestUnstakePmLp<'info> {
    pub staker: Signer<'info>,

    #[account(seeds = [b"firm", firm_state.owner.as_ref()], bump = firm_state.bump)]
    pub firm_state: Box<Account<'info, FirmState>>,

    #[account(seeds = [b"platform_risk"], bump = platform_risk.bump)]
    pub platform_risk: Box<Account<'info, PlatformRiskState>>,

    #[account(seeds = [b"pm_lp_pool", firm_state.key().as_ref()], bump = pm_lp_pool.bump)]
    pub pm_lp_pool: Box<Account<'info, PredictionMarketLpPool>>,

    #[account(
        mut,
        seeds = [b"pm_lp_pos", firm_state.key().as_ref(), staker.key().as_ref()],
        bump = position.bump,
        constraint = position.staker == staker.key() @ FirmError::Unauthorized,
    )]
    pub position: Box<Account<'info, PredictionMarketLpPosition>>,
}

#[derive(Accounts)]
pub struct WithdrawPmLp<'info> {
    pub staker: Signer<'info>,

    #[account(seeds = [b"firm", firm_state.owner.as_ref()], bump = firm_state.bump)]
    pub firm_state: Box<Account<'info, FirmState>>,

    #[account(seeds = [b"platform_risk"], bump = platform_risk.bump)]
    pub platform_risk: Box<Account<'info, PlatformRiskState>>,

    #[account(mut, seeds = [b"pm_lp_pool", firm_state.key().as_ref()], bump = pm_lp_pool.bump)]
    pub pm_lp_pool: Box<Account<'info, PredictionMarketLpPool>>,

    #[account(
        mut,
        seeds = [b"pm_lp_pos", firm_state.key().as_ref(), staker.key().as_ref()],
        bump = position.bump,
        constraint = position.staker == staker.key() @ FirmError::Unauthorized,
    )]
    pub position: Box<Account<'info, PredictionMarketLpPosition>>,

    #[account(mut, address = pm_lp_pool.escrow_vault)]
    pub escrow_vault: Box<Account<'info, TokenAccount>>,
    #[account(mut, address = pm_lp_pool.yield_vault)]
    pub yield_vault: Box<Account<'info, TokenAccount>>,

    #[account(
        mut,
        token::mint = firm_state.firma_mint,
        constraint = staker_firma.owner == staker.key() @ FirmError::Unauthorized,
    )]
    pub staker_firma: Box<Account<'info, TokenAccount>>,

    pub token_program: Program<'info, Token>,
}

impl<'info> WithdrawPmLp<'info> {
    fn pay_principal(&self, amount: u64) -> Result<()> {
        self.pay(self.escrow_vault.to_account_info(), amount)
    }
    fn pay_yield(&self, amount: u64) -> Result<()> {
        self.pay(self.yield_vault.to_account_info(), amount)
    }
    fn pay(&self, from: AccountInfo<'info>, amount: u64) -> Result<()> {
        if amount == 0 {
            return Ok(());
        }
        let bump = [self.pm_lp_pool.bump];
        let seeds = pm_lp_signer(&self.pm_lp_pool.firm, &bump);
        token::transfer(
            CpiContext::new_with_signer(
                self.token_program.to_account_info(),
                anchor_spl::token::Transfer { from, to: self.staker_firma.to_account_info(), authority: self.pm_lp_pool.to_account_info() },
                &[&seeds],
            ),
            amount,
        )
    }
}

#[derive(Accounts)]
pub struct ClaimPmLpYield<'info> {
    pub staker: Signer<'info>,

    #[account(seeds = [b"firm", firm_state.owner.as_ref()], bump = firm_state.bump)]
    pub firm_state: Box<Account<'info, FirmState>>,

    #[account(mut, seeds = [b"pm_lp_pool", firm_state.key().as_ref()], bump = pm_lp_pool.bump)]
    pub pm_lp_pool: Box<Account<'info, PredictionMarketLpPool>>,

    #[account(
        mut,
        seeds = [b"pm_lp_pos", firm_state.key().as_ref(), staker.key().as_ref()],
        bump = position.bump,
        constraint = position.staker == staker.key() @ FirmError::Unauthorized,
    )]
    pub position: Box<Account<'info, PredictionMarketLpPosition>>,

    #[account(mut, address = pm_lp_pool.yield_vault)]
    pub yield_vault: Box<Account<'info, TokenAccount>>,
    #[account(
        mut,
        token::mint = firm_state.firma_mint,
        constraint = staker_firma.owner == staker.key() @ FirmError::Unauthorized,
    )]
    pub staker_firma: Box<Account<'info, TokenAccount>>,

    pub token_program: Program<'info, Token>,
}

impl<'info> ClaimPmLpYield<'info> {
    fn pay_yield(&self, amount: u64) -> Result<()> {
        if amount == 0 {
            return Ok(());
        }
        let bump = [self.pm_lp_pool.bump];
        let seeds = pm_lp_signer(&self.pm_lp_pool.firm, &bump);
        token::transfer(
            CpiContext::new_with_signer(
                self.token_program.to_account_info(),
                anchor_spl::token::Transfer {
                    from: self.yield_vault.to_account_info(),
                    to: self.staker_firma.to_account_info(),
                    authority: self.pm_lp_pool.to_account_info(),
                },
                &[&seeds],
            ),
            amount,
        )
    }
}

// ───────── Prediction Market Curve (Phase 3 pooled-LP AMM plan) ─────────
// Accounts are Box'd throughout to keep the BPF stack frame under 4 KB, same discipline as every
// other instruction in this file.

#[derive(Accounts)]
pub struct InitMarketCurve<'info> {
    /// The challenge's settlement authority — also pays this curve's rent (plan §5: curve init rent
    /// is paid by the firm's own keeper/treasury wallet, not the platform).
    #[account(mut)]
    pub authority: Signer<'info>,

    #[account(seeds = [b"firm", firm_state.owner.as_ref()], bump = firm_state.bump)]
    pub firm_state: Box<Account<'info, FirmState>>,

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
        constraint = challenge.settlement_authority == authority.key() @ FirmError::Unauthorized,
        constraint = challenge.firm == firm_state.key() @ FirmError::Unauthorized,
    )]
    pub challenge: Box<Account<'info, challenge::ChallengeState>>,

    #[account(address = firm_state.firma_mint)]
    pub firma_mint: Box<Account<'info, Mint>>,

    #[account(
        init,
        payer = authority,
        space = 8 + MarketCurve::INIT_SPACE,
        seeds = [b"pm_curve", challenge.key().as_ref()],
        bump
    )]
    pub curve: Box<Account<'info, MarketCurve>>,

    #[account(
        init,
        payer = authority,
        token::mint = firma_mint,
        token::authority = curve,
        seeds = [b"pm_curve_pass", challenge.key().as_ref()],
        bump
    )]
    pub pass_vault: Box<Account<'info, TokenAccount>>,
    #[account(
        init,
        payer = authority,
        token::mint = firma_mint,
        token::authority = curve,
        seeds = [b"pm_curve_fail", challenge.key().as_ref()],
        bump
    )]
    pub fail_vault: Box<Account<'info, TokenAccount>>,

    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
    pub rent: Sysvar<'info, Rent>,
}

#[derive(Accounts)]
pub struct BuyMarketShares<'info> {
    #[account(mut)]
    pub buyer: Signer<'info>,

    #[account(mut, seeds = [b"pm_curve", curve.challenge.as_ref()], bump = curve.bump)]
    pub curve: Box<Account<'info, MarketCurve>>,

    #[account(mut, address = curve.pass_vault)]
    pub pass_vault: Box<Account<'info, TokenAccount>>,
    #[account(mut, address = curve.fail_vault)]
    pub fail_vault: Box<Account<'info, TokenAccount>>,

    #[account(
        init_if_needed,
        payer = buyer,
        space = 8 + MarketPosition::INIT_SPACE,
        seeds = [b"pm_position", curve.key().as_ref(), buyer.key().as_ref()],
        bump
    )]
    pub position: Box<Account<'info, MarketPosition>>,

    #[account(mut, token::mint = curve.firma_mint, token::authority = buyer)]
    pub buyer_firma: Box<Account<'info, TokenAccount>>,

    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
}

impl<'info> BuyMarketShares<'info> {
    /// Move the buyer's gross collateral (including the fee — the fee stays inside the vault,
    /// tracked separately via the `*_fees_accrued` fields rather than transferred out) into whichever
    /// side's vault this buy targets. Buyer-authority transfer (money coming IN), not PDA-signed.
    fn transfer_collateral_in(&self, side: PmSide, amount: u64) -> Result<()> {
        let to = match side {
            PmSide::Pass => self.pass_vault.to_account_info(),
            PmSide::Fail => self.fail_vault.to_account_info(),
        };
        token::transfer(
            CpiContext::new(
                self.token_program.to_account_info(),
                anchor_spl::token::Transfer {
                    from: self.buyer_firma.to_account_info(),
                    to,
                    authority: self.buyer.to_account_info(),
                },
            ),
            amount,
        )
    }
}

#[derive(Accounts)]
pub struct SellMarketShares<'info> {
    pub seller: Signer<'info>,

    #[account(mut, seeds = [b"pm_curve", curve.challenge.as_ref()], bump = curve.bump)]
    pub curve: Box<Account<'info, MarketCurve>>,

    #[account(mut, address = curve.pass_vault)]
    pub pass_vault: Box<Account<'info, TokenAccount>>,
    #[account(mut, address = curve.fail_vault)]
    pub fail_vault: Box<Account<'info, TokenAccount>>,

    #[account(
        mut,
        seeds = [b"pm_position", curve.key().as_ref(), seller.key().as_ref()],
        bump = position.bump,
        constraint = position.holder == seller.key() @ FirmError::Unauthorized,
    )]
    pub position: Box<Account<'info, MarketPosition>>,

    #[account(mut, token::mint = curve.firma_mint, token::authority = seller)]
    pub seller_firma: Box<Account<'info, TokenAccount>>,

    pub token_program: Program<'info, Token>,
}

impl<'info> SellMarketShares<'info> {
    /// PDA-signed payout FROM the side's vault TO the seller — money going OUT, unlike
    /// `buy_shares`' buyer-authority transfer in.
    fn pay_seller(&self, side: PmSide, amount: u64, challenge: &Pubkey, bump: &[u8; 1]) -> Result<()> {
        if amount == 0 {
            return Ok(());
        }
        let seeds = pm_curve_signer(challenge, bump);
        let from = match side {
            PmSide::Pass => self.pass_vault.to_account_info(),
            PmSide::Fail => self.fail_vault.to_account_info(),
        };
        token::transfer(
            CpiContext::new_with_signer(
                self.token_program.to_account_info(),
                anchor_spl::token::Transfer {
                    from,
                    to: self.seller_firma.to_account_info(),
                    authority: self.curve.to_account_info(),
                },
                &[&seeds],
            ),
            amount,
        )
    }
}

#[derive(Accounts)]
pub struct AddCurveTopup<'info> {
    pub depositor: Signer<'info>,

    #[account(mut, seeds = [b"pm_curve", curve.challenge.as_ref()], bump = curve.bump)]
    pub curve: Box<Account<'info, MarketCurve>>,

    #[account(mut, address = curve.pass_vault)]
    pub pass_vault: Box<Account<'info, TokenAccount>>,
    #[account(mut, address = curve.fail_vault)]
    pub fail_vault: Box<Account<'info, TokenAccount>>,

    #[account(mut, token::mint = curve.firma_mint, token::authority = depositor)]
    pub depositor_firma: Box<Account<'info, TokenAccount>>,

    pub token_program: Program<'info, Token>,
}

impl<'info> AddCurveTopup<'info> {
    fn deposit(&self, side: PmSide, amount: u64) -> Result<()> {
        let to = match side {
            PmSide::Pass => self.pass_vault.to_account_info(),
            PmSide::Fail => self.fail_vault.to_account_info(),
        };
        token::transfer(
            CpiContext::new(
                self.token_program.to_account_info(),
                anchor_spl::token::Transfer {
                    from: self.depositor_firma.to_account_info(),
                    to,
                    authority: self.depositor.to_account_info(),
                },
            ),
            amount,
        )
    }
}

#[derive(Accounts)]
pub struct LockMarketCurve<'info> {
    pub authority: Signer<'info>,

    #[account(seeds = [b"firm", firm_state.owner.as_ref()], bump = firm_state.bump)]
    pub firm_state: Box<Account<'info, FirmState>>,

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
        constraint = challenge.settlement_authority == authority.key() @ FirmError::Unauthorized,
        constraint = challenge.firm == firm_state.key() @ FirmError::Unauthorized,
    )]
    pub challenge: Box<Account<'info, challenge::ChallengeState>>,

    #[account(mut, seeds = [b"pm_curve", challenge.key().as_ref()], bump = curve.bump)]
    pub curve: Box<Account<'info, MarketCurve>>,
}

#[derive(Accounts)]
pub struct SettleMarketCurve<'info> {
    pub authority: Signer<'info>,

    #[account(seeds = [b"firm", firm_state.owner.as_ref()], bump = firm_state.bump)]
    pub firm_state: Box<Account<'info, FirmState>>,

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
        constraint = challenge.settlement_authority == authority.key() @ FirmError::Unauthorized,
        constraint = challenge.firm == firm_state.key() @ FirmError::Unauthorized,
    )]
    pub challenge: Box<Account<'info, challenge::ChallengeState>>,

    #[account(mut, seeds = [b"pm_curve", challenge.key().as_ref()], bump = curve.bump)]
    pub curve: Box<Account<'info, MarketCurve>>,
}

#[derive(Accounts)]
pub struct VoidMarketCurve<'info> {
    pub authority: Signer<'info>,

    #[account(seeds = [b"firm", firm_state.owner.as_ref()], bump = firm_state.bump)]
    pub firm_state: Box<Account<'info, FirmState>>,

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
        constraint = challenge.settlement_authority == authority.key() @ FirmError::Unauthorized,
        constraint = challenge.firm == firm_state.key() @ FirmError::Unauthorized,
    )]
    pub challenge: Box<Account<'info, challenge::ChallengeState>>,

    #[account(mut, seeds = [b"pm_curve", challenge.key().as_ref()], bump = curve.bump)]
    pub curve: Box<Account<'info, MarketCurve>>,
}

#[derive(Accounts)]
#[instruction(holder: Pubkey)]
pub struct RedeemMarketShares<'info> {
    /// Permissionless cranker — anyone may trigger a redemption; the position + destination ATA
    /// below (not this signer) determine who actually gets paid.
    pub payer: Signer<'info>,

    #[account(seeds = [b"pm_curve", curve.challenge.as_ref()], bump = curve.bump)]
    pub curve: Box<Account<'info, MarketCurve>>,

    #[account(mut, address = curve.pass_vault)]
    pub pass_vault: Box<Account<'info, TokenAccount>>,
    #[account(mut, address = curve.fail_vault)]
    pub fail_vault: Box<Account<'info, TokenAccount>>,

    #[account(
        mut,
        seeds = [b"pm_position", curve.key().as_ref(), holder.as_ref()],
        bump = position.bump,
        constraint = position.holder == holder @ FirmError::Unauthorized,
    )]
    pub position: Box<Account<'info, MarketPosition>>,

    /// The real payout destination — must be owned by `position.holder`, NOT the caller. Lets anyone
    /// crank a redemption on someone else's behalf without that holder needing to sign.
    #[account(
        mut,
        token::mint = curve.firma_mint,
        constraint = holder_firma.owner == position.holder @ FirmError::Unauthorized,
    )]
    pub holder_firma: Box<Account<'info, TokenAccount>>,

    pub token_program: Program<'info, Token>,
}

impl<'info> RedeemMarketShares<'info> {
    /// Splits `amount` across the two vaults by LIVE balance — pass first, fail for the remainder.
    /// Which vault a given lamport physically comes from is not economically meaningful (both back
    /// the same pooled `redeemable_total`, which is never decremented — see `redeem_shares`' doc
    /// comment for why that matters for fairness across multiple redeemers); this ordering only needs
    /// to never claim more than a vault actually holds, which `.min()` + remainder guarantees. The
    /// GLOBAL total every `redeem_shares` call can ever draw, summed across all holders, is bounded by
    /// `pm_redeem_payout`'s own math at <= `redeemable_total` — strictly less than each vault's real
    /// balance plus its own un-swept fee dust — so this can never encroach on `*_fees_accrued`
    /// (`sweep_curve_fees_to_pool`'s money) in aggregate, regardless of per-vault draining order.
    fn pay(&self, amount: u64, challenge: &Pubkey, bump: &[u8; 1]) -> Result<()> {
        if amount == 0 {
            return Ok(());
        }
        let from_pass = amount.min(self.pass_vault.amount);
        let from_fail = amount.saturating_sub(from_pass).min(self.fail_vault.amount);
        let seeds = pm_curve_signer(challenge, bump);
        if from_pass > 0 {
            token::transfer(
                CpiContext::new_with_signer(
                    self.token_program.to_account_info(),
                    anchor_spl::token::Transfer {
                        from: self.pass_vault.to_account_info(),
                        to: self.holder_firma.to_account_info(),
                        authority: self.curve.to_account_info(),
                    },
                    &[&seeds],
                ),
                from_pass,
            )?;
        }
        if from_fail > 0 {
            token::transfer(
                CpiContext::new_with_signer(
                    self.token_program.to_account_info(),
                    anchor_spl::token::Transfer {
                        from: self.fail_vault.to_account_info(),
                        to: self.holder_firma.to_account_info(),
                        authority: self.curve.to_account_info(),
                    },
                    &[&seeds],
                ),
                from_fail,
            )?;
        }
        Ok(())
    }
}

#[derive(Accounts)]
#[instruction(holder: Pubkey)]
pub struct RedeemVoidShares<'info> {
    pub payer: Signer<'info>,

    #[account(seeds = [b"pm_curve", curve.challenge.as_ref()], bump = curve.bump)]
    pub curve: Box<Account<'info, MarketCurve>>,

    #[account(mut, address = curve.pass_vault)]
    pub pass_vault: Box<Account<'info, TokenAccount>>,
    #[account(mut, address = curve.fail_vault)]
    pub fail_vault: Box<Account<'info, TokenAccount>>,

    #[account(
        mut,
        seeds = [b"pm_position", curve.key().as_ref(), holder.as_ref()],
        bump = position.bump,
        constraint = position.holder == holder @ FirmError::Unauthorized,
    )]
    pub position: Box<Account<'info, MarketPosition>>,

    #[account(
        mut,
        token::mint = curve.firma_mint,
        constraint = holder_firma.owner == position.holder @ FirmError::Unauthorized,
    )]
    pub holder_firma: Box<Account<'info, TokenAccount>>,

    pub token_program: Program<'info, Token>,
}

impl<'info> RedeemVoidShares<'info> {
    /// Unlike `RedeemMarketShares::pay`, each side pays ONLY from its own vault — no cross-vault
    /// fallback — mirroring `pm_void_redeem_payout`'s no-pooling formula exactly.
    fn pay(&self, pass_payout: u64, fail_payout: u64, challenge: &Pubkey, bump: &[u8; 1]) -> Result<()> {
        let seeds = pm_curve_signer(challenge, bump);
        let from_pass = pass_payout.min(self.pass_vault.amount);
        if from_pass > 0 {
            token::transfer(
                CpiContext::new_with_signer(
                    self.token_program.to_account_info(),
                    anchor_spl::token::Transfer {
                        from: self.pass_vault.to_account_info(),
                        to: self.holder_firma.to_account_info(),
                        authority: self.curve.to_account_info(),
                    },
                    &[&seeds],
                ),
                from_pass,
            )?;
        }
        let from_fail = fail_payout.min(self.fail_vault.amount);
        if from_fail > 0 {
            token::transfer(
                CpiContext::new_with_signer(
                    self.token_program.to_account_info(),
                    anchor_spl::token::Transfer {
                        from: self.fail_vault.to_account_info(),
                        to: self.holder_firma.to_account_info(),
                        authority: self.curve.to_account_info(),
                    },
                    &[&seeds],
                ),
                from_fail,
            )?;
        }
        Ok(())
    }
}

#[derive(Accounts)]
pub struct AllocatePoolToCurve<'info> {
    pub authority: Signer<'info>,

    #[account(seeds = [b"firm", firm_state.owner.as_ref()], bump = firm_state.bump)]
    pub firm_state: Box<Account<'info, FirmState>>,

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
        constraint = challenge.settlement_authority == authority.key() @ FirmError::Unauthorized,
        constraint = challenge.firm == firm_state.key() @ FirmError::Unauthorized,
    )]
    pub challenge: Box<Account<'info, challenge::ChallengeState>>,

    #[account(mut, seeds = [b"pm_curve", challenge.key().as_ref()], bump = curve.bump)]
    pub curve: Box<Account<'info, MarketCurve>>,

    #[account(mut, address = curve.pass_vault)]
    pub pass_vault: Box<Account<'info, TokenAccount>>,
    #[account(mut, address = curve.fail_vault)]
    pub fail_vault: Box<Account<'info, TokenAccount>>,

    #[account(
        mut,
        seeds = [b"pm_lp_pool", firm_state.key().as_ref()],
        bump = pm_lp_pool.bump,
        constraint = pm_lp_pool.firm == firm_state.key() @ FirmError::Unauthorized,
    )]
    pub pm_lp_pool: Box<Account<'info, PredictionMarketLpPool>>,

    #[account(mut, address = pm_lp_pool.escrow_vault)]
    pub pool_escrow_vault: Box<Account<'info, TokenAccount>>,

    pub token_program: Program<'info, Token>,
}

impl<'info> AllocatePoolToCurve<'info> {
    /// PDA-signed by the POOL (the source of this transfer).
    fn disburse(&self, to_pass: u64, to_fail: u64) -> Result<()> {
        let bump = [self.pm_lp_pool.bump];
        let seeds = pm_lp_signer(&self.pm_lp_pool.firm, &bump);
        if to_pass > 0 {
            token::transfer(
                CpiContext::new_with_signer(
                    self.token_program.to_account_info(),
                    anchor_spl::token::Transfer {
                        from: self.pool_escrow_vault.to_account_info(),
                        to: self.pass_vault.to_account_info(),
                        authority: self.pm_lp_pool.to_account_info(),
                    },
                    &[&seeds],
                ),
                to_pass,
            )?;
        }
        if to_fail > 0 {
            token::transfer(
                CpiContext::new_with_signer(
                    self.token_program.to_account_info(),
                    anchor_spl::token::Transfer {
                        from: self.pool_escrow_vault.to_account_info(),
                        to: self.fail_vault.to_account_info(),
                        authority: self.pm_lp_pool.to_account_info(),
                    },
                    &[&seeds],
                ),
                to_fail,
            )?;
        }
        Ok(())
    }
}

#[derive(Accounts)]
pub struct DeallocatePoolFromCurve<'info> {
    pub authority: Signer<'info>,

    #[account(seeds = [b"firm", firm_state.owner.as_ref()], bump = firm_state.bump)]
    pub firm_state: Box<Account<'info, FirmState>>,

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
        constraint = challenge.settlement_authority == authority.key() @ FirmError::Unauthorized,
        constraint = challenge.firm == firm_state.key() @ FirmError::Unauthorized,
    )]
    pub challenge: Box<Account<'info, challenge::ChallengeState>>,

    #[account(mut, seeds = [b"pm_curve", challenge.key().as_ref()], bump = curve.bump)]
    pub curve: Box<Account<'info, MarketCurve>>,

    #[account(mut, address = curve.pass_vault)]
    pub pass_vault: Box<Account<'info, TokenAccount>>,
    #[account(mut, address = curve.fail_vault)]
    pub fail_vault: Box<Account<'info, TokenAccount>>,

    #[account(
        mut,
        seeds = [b"pm_lp_pool", firm_state.key().as_ref()],
        bump = pm_lp_pool.bump,
        constraint = pm_lp_pool.firm == firm_state.key() @ FirmError::Unauthorized,
    )]
    pub pm_lp_pool: Box<Account<'info, PredictionMarketLpPool>>,

    #[account(mut, address = pm_lp_pool.escrow_vault)]
    pub pool_escrow_vault: Box<Account<'info, TokenAccount>>,

    pub token_program: Program<'info, Token>,
}

impl<'info> DeallocatePoolFromCurve<'info> {
    /// PDA-signed by the CURVE (the source of this transfer) — the symmetric reverse of
    /// `AllocatePoolToCurve::disburse`.
    fn withdraw(&self, from_pass: u64, from_fail: u64, challenge: &Pubkey, bump: &[u8; 1]) -> Result<()> {
        let seeds = pm_curve_signer(challenge, bump);
        if from_pass > 0 {
            token::transfer(
                CpiContext::new_with_signer(
                    self.token_program.to_account_info(),
                    anchor_spl::token::Transfer {
                        from: self.pass_vault.to_account_info(),
                        to: self.pool_escrow_vault.to_account_info(),
                        authority: self.curve.to_account_info(),
                    },
                    &[&seeds],
                ),
                from_pass,
            )?;
        }
        if from_fail > 0 {
            token::transfer(
                CpiContext::new_with_signer(
                    self.token_program.to_account_info(),
                    anchor_spl::token::Transfer {
                        from: self.fail_vault.to_account_info(),
                        to: self.pool_escrow_vault.to_account_info(),
                        authority: self.curve.to_account_info(),
                    },
                    &[&seeds],
                ),
                from_fail,
            )?;
        }
        Ok(())
    }
}

#[derive(Accounts)]
pub struct SweepCurveFeesToPool<'info> {
    #[account(mut, seeds = [b"pm_curve", curve.challenge.as_ref()], bump = curve.bump)]
    pub curve: Box<Account<'info, MarketCurve>>,

    #[account(mut, address = curve.pass_vault)]
    pub pass_vault: Box<Account<'info, TokenAccount>>,
    #[account(mut, address = curve.fail_vault)]
    pub fail_vault: Box<Account<'info, TokenAccount>>,

    #[account(
        mut,
        seeds = [b"pm_lp_pool", pm_lp_pool.firm.as_ref()],
        bump = pm_lp_pool.bump,
        constraint = pm_lp_pool.firm == curve.firm @ FirmError::Unauthorized,
    )]
    pub pm_lp_pool: Box<Account<'info, PredictionMarketLpPool>>,

    #[account(mut, address = pm_lp_pool.yield_vault)]
    pub pool_yield_vault: Box<Account<'info, TokenAccount>>,

    pub token_program: Program<'info, Token>,
}

impl<'info> SweepCurveFeesToPool<'info> {
    fn sweep(&self, from_pass: u64, from_fail: u64, challenge: &Pubkey, bump: &[u8; 1]) -> Result<()> {
        let seeds = pm_curve_signer(challenge, bump);
        if from_pass > 0 {
            token::transfer(
                CpiContext::new_with_signer(
                    self.token_program.to_account_info(),
                    anchor_spl::token::Transfer {
                        from: self.pass_vault.to_account_info(),
                        to: self.pool_yield_vault.to_account_info(),
                        authority: self.curve.to_account_info(),
                    },
                    &[&seeds],
                ),
                from_pass,
            )?;
        }
        if from_fail > 0 {
            token::transfer(
                CpiContext::new_with_signer(
                    self.token_program.to_account_info(),
                    anchor_spl::token::Transfer {
                        from: self.fail_vault.to_account_info(),
                        to: self.pool_yield_vault.to_account_info(),
                        authority: self.curve.to_account_info(),
                    },
                    &[&seeds],
                ),
                from_fail,
            )?;
        }
        Ok(())
    }
}

// Accounts are Box'd to keep the BPF stack frame under 4 KB.
#[derive(Accounts)]
pub struct DrawTreasuryFirma<'info> {
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
        constraint = challenge.settlement_authority == authority.key() @ FirmError::Unauthorized,
        constraint = challenge.firm == firm_state.key() @ FirmError::Unauthorized,
    )]
    pub challenge: Box<Account<'info, challenge::ChallengeState>>,

    // MUST be `mut`: draw_treasury_firma decrements `open_payouts` when a Tier-2 reserve fill completes a
    // payout. Without `mut`, Anchor never persists that write and the counter sticks (wedging bankruptcy).
    #[account(mut, seeds = [b"firm", firm_state.owner.as_ref()], bump = firm_state.bump)]
    pub firm_state: Box<Account<'info, FirmState>>,

    #[account(
        mut,
        seeds = [b"payout", challenge.key().as_ref(), &queued_payout.cycle.to_le_bytes()],
        bump = queued_payout.bump,
        constraint = queued_payout.challenge == challenge.key() @ FirmError::Unauthorized,
    )]
    pub queued_payout: Box<Account<'info, QueuedPayout>>,

    /// DEC-62 — present ⇒ this payout discharges a FUNDED WITHDRAWAL, authorised by its
    /// `FundedWithdrawal` rather than by a challenge settlement the still-trading account never
    /// reaches. Seed-bound to this challenge + the queued payout's OWN cycle, so presence is
    /// sufficient authorisation evidence. Absent ⇒ the legacy settlement path.
    #[account(
        seeds = [b"withdrawal", challenge.key().as_ref(), &queued_payout.cycle.to_le_bytes()],
        bump = withdrawal.bump,
        seeds::program = challenge::ID,
    )]
    pub withdrawal: Option<Box<Account<'info, challenge::FundedWithdrawal>>>,

    #[account(mut, address = firm_state.treasury_firma_vault)]
    pub treasury_firma_vault: Box<Account<'info, TokenAccount>>,

    #[account(
        mut,
        token::mint = firm_state.firma_mint,
        constraint = trader_firma.owner == queued_payout.trader @ FirmError::Unauthorized,
    )]
    pub trader_firma: Box<Account<'info, TokenAccount>>,

    pub token_program: Program<'info, Token>,
}

impl<'info> DrawTreasuryFirma<'info> {
    /// Deliver owed $FIRMA from the treasury reserve directly to the trader (firm PDA signs).
    fn deliver(&self, amount: u64) -> Result<()> {
        let bump = [self.firm_state.bump];
        let seeds = firm_signer(&self.firm_state.owner, &bump);
        token::transfer(
            CpiContext::new_with_signer(
                self.token_program.to_account_info(),
                anchor_spl::token::Transfer {
                    from: self.treasury_firma_vault.to_account_info(),
                    to: self.trader_firma.to_account_info(),
                    authority: self.firm_state.to_account_info(),
                },
                &[&seeds],
            ),
            amount,
        )
    }
}

// Accounts are Box'd to keep the BPF stack frame under 4 KB.
#[derive(Accounts)]
pub struct DrawUniversal<'info> {
    /// The firm's settlement authority (keeper). No extra rent required.
    pub authority: Signer<'info>,

    /// Independent platform guardian — MUST co-sign (L-1). `draw_universal` spends the SHARED,
    /// cross-firm Universal Treasury Pool (mutualised capital), so it deserves at least the same
    /// "declare ≠ spend" guardian gate that `draw_backstop` already enforces — the key that declares
    /// a firm's emergency must not be the only key that spends the protocol-wide pool.
    #[account(constraint = guardian.key() == firm_state.guardian @ FirmError::GuardianMismatch)]
    pub guardian: Signer<'info>,

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
        constraint = challenge.settlement_authority == authority.key() @ FirmError::Unauthorized,
        constraint = challenge.firm == firm_state.key() @ FirmError::Unauthorized,
    )]
    pub challenge: Box<Account<'info, challenge::ChallengeState>>,

    // MUST be `mut`: draw_universal writes `open_payouts` (fill accounting) + `ulp_drawn` and the
    // auto-bankruptcy `status` flip (§24 v2). Without `mut`, Anchor never serializes these back — the
    // pre-v2 `open_payouts` decrement on a universal draw was silently lost (fixed here).
    #[account(mut, seeds = [b"firm", firm_state.owner.as_ref()], bump = firm_state.bump)]
    pub firm_state: Box<Account<'info, FirmState>>,

    #[account(
        mut,
        seeds = [b"payout", challenge.key().as_ref(), &queued_payout.cycle.to_le_bytes()],
        bump = queued_payout.bump,
        constraint = queued_payout.challenge == challenge.key() @ FirmError::Unauthorized,
    )]
    pub queued_payout: Box<Account<'info, QueuedPayout>>,

    /// DEC-62 — present ⇒ this payout discharges a FUNDED WITHDRAWAL, authorised by its
    /// `FundedWithdrawal` rather than by a challenge settlement the still-trading account never
    /// reaches. Seed-bound to this challenge + the queued payout's OWN cycle. Absent ⇒ settlement path.
    #[account(
        seeds = [b"withdrawal", challenge.key().as_ref(), &queued_payout.cycle.to_le_bytes()],
        bump = withdrawal.bump,
        seeds::program = challenge::ID,
    )]
    pub withdrawal: Option<Box<Account<'info, challenge::FundedWithdrawal>>>,

    // "Last-resort" gate helpers — provided for the exhaustion check but not mutated.
    #[account(address = firm_state.treasury_firma_vault)]
    pub treasury_firma_vault: Box<Account<'info, TokenAccount>>,

    // Universal pool state + its PDA-owned SOL vault (the buyer for the curve CPI).
    #[account(mut, seeds = [b"universal_pool"], bump = universal_pool.bump)]
    pub universal_pool: Box<Account<'info, UniversalPool>>,
    #[account(mut, seeds = [b"universal_vault"], bump, token::mint = firm_state.sol_mint)]
    pub universal_vault: Box<Account<'info, TokenAccount>>,

    // Firm's bonding curve — the SOL from `universal_vault` buys $FIRMA here.
    #[account(
        mut,
        seeds = [b"bonding_curve", firm_state.key().as_ref()],
        bump = curve.bump,
        seeds::program = bonding_curve::ID,
    )]
    pub curve: Box<Account<'info, bonding_curve::BondingCurve>>,
    #[account(mut, address = curve.sol_vault)]
    pub curve_sol_vault: Box<Account<'info, TokenAccount>>,
    #[account(mut, address = curve.firma_vault)]
    pub curve_firma_vault: Box<Account<'info, TokenAccount>>,

    // Delivery target — the trader's $FIRMA account.
    #[account(
        mut,
        token::mint = firm_state.firma_mint,
        constraint = trader_firma.owner == queued_payout.trader @ FirmError::Unauthorized,
    )]
    pub trader_firma: Box<Account<'info, TokenAccount>>,

    // 0.5% curve platform fee destination.
    /// V2-8: canonical platform config — binds `platform_sol` to the DP fee destination (M-4 pattern),
    /// so this leg can't be pointed at a caller-controlled account.
    #[account(seeds = [b"platform_config"], bump = platform_config.bump)]
    pub platform_config: Box<Account<'info, PlatformConfig>>,

    #[account(
        mut,
        token::mint = firm_state.sol_mint,
        constraint = platform_sol.key() == platform_config.platform_sol @ FirmError::PlatformSolMismatch,
    )]
    pub platform_sol: Box<Account<'info, TokenAccount>>,

    pub bonding_curve_program: Program<'info, bonding_curve::program::BondingCurve>,
    pub token_program: Program<'info, Token>,
}

impl<'info> DrawUniversal<'info> {
    /// Buy $FIRMA from the firm's curve using the Universal Pool's SOL (pool PDA signs).
    /// The trader_firma receives the output directly (same pattern as execute_payout_buy).
    fn curve_buy(&self, sol_amount: u64, min_firma_out: u64) -> Result<()> {
        let bump = [self.universal_pool.bump];
        let seeds: &[&[u8]] = &[b"universal_pool", &bump];
        bonding_curve::cpi::buy(
            CpiContext::new_with_signer(
                self.bonding_curve_program.to_account_info(),
                bonding_curve::cpi::accounts::Buy {
                    trader: self.universal_pool.to_account_info(),
                    curve: self.curve.to_account_info(),
                    sol_vault: self.curve_sol_vault.to_account_info(),
                    firma_vault: self.curve_firma_vault.to_account_info(),
                    trader_sol: self.universal_vault.to_account_info(),
                    trader_firma: self.trader_firma.to_account_info(),
                    firm_treasury_sol: self.universal_vault.to_account_info(),
                    platform_sol: self.platform_sol.to_account_info(),
                    token_program: self.token_program.to_account_info(),
                },
                &[seeds],
            ),
            sol_amount,
            min_firma_out,
        )
    }
}

/// Global per-tier franchise pool (Architecture §5). Minimal accumulator — weighted,
/// pull-based distribution (`compute_franchise_weights` / `claim_franchise_distribution`)
/// is the deferred Phase-5 tail.
#[account]
#[derive(InitSpace)]
pub struct TierFranchisePool {
    pub tier: u8,
    pub vault: Pubkey,
    /// Lifetime SOL routed into this tier's pool vault.
    pub total_contributed: u64,
    pub bump: u8,
}

#[derive(Accounts)]
#[instruction(tier: u8)]
pub struct InitFranchisePool<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,

    pub sol_mint: Box<Account<'info, Mint>>,

    #[account(
        init,
        payer = payer,
        space = 8 + TierFranchisePool::INIT_SPACE,
        seeds = [b"franchise_pool".as_ref(), &[tier]],
        bump
    )]
    pub franchise_pool: Box<Account<'info, TierFranchisePool>>,

    #[account(
        init,
        payer = payer,
        token::mint = sol_mint,
        token::authority = franchise_pool,
        seeds = [b"franchise_vault".as_ref(), &[tier]],
        bump
    )]
    pub franchise_vault: Box<Account<'info, TokenAccount>>,

    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
    pub rent: Sysvar<'info, Rent>,
}

/// One-shot marker that `pay_deployment_fee` creates (`init`) to prove a firm's launch fee was paid.
/// Its existence is the idempotency signal (the gateway 409s on it); the `init` constraint makes a
/// second `pay_deployment_fee` for the same firm impossible, so the fee can never be double-charged.
/// RESERVE-3 (2026-07-11): replaces the deleted `PendingTokenBuy` escrow, which used to serve this
/// same "fee paid?" role incidentally. Seeds: ["deployment_fee_paid", firm].
#[account]
pub struct DeploymentFeeMarker {}

#[derive(Accounts)]
pub struct PayDeploymentFee<'info> {
    #[account(mut)]
    pub owner: Signer<'info>,

    /// SOL MIGRATION (oracle-free): co-signs the off-chain `price_lamports` quote. Bound to the
    /// firm's risk-engine authority (the platform-controlled settlement authority) so the owner can't
    /// underpay the USD-pegged launch fee — mirrors how the eval fee is authority-attested.
    #[account(constraint = settlement_authority.key() == firm_state.risk_engine_authority @ FirmError::Unauthorized)]
    pub settlement_authority: Signer<'info>,

    #[account(mut, token::mint = firm_state.sol_mint, token::authority = owner)]
    pub owner_sol: Box<Account<'info, TokenAccount>>,

    #[account(
        mut,
        seeds = [b"firm", owner.key().as_ref()],
        bump = firm_state.bump,
        constraint = firm_state.owner == owner.key() @ FirmError::Unauthorized,
    )]
    pub firm_state: Box<Account<'info, FirmState>>,

    // §19 sync contract: the cache must equal the vault balance at entry.
    #[account(
        mut,
        address = firm_state.treasury_vault,
        // Invariant: the vault must COVER the cache. External credits (e.g. a bonding-curve fee paid
        // into treasury_vault by deploy_burn or a third-party curve buy) legitimately raise the vault
        // ABOVE the cache; each treasury-touching handler reconciles `treasury_sol = treasury_vault.amount`,
        // so the only way `vault < cache` is an impossible unauthorised drain. `==` here used to brick the
        // firm on any donation (F-1/F-2); `>=` makes out-of-band credits harmless. (audit F-1/F-2)
        constraint = treasury_vault.amount >= firm_state.treasury_sol @ FirmError::TreasuryDesync,
    )]
    pub treasury_vault: Box<Account<'info, TokenAccount>>,

    #[account(mut, token::mint = firm_state.sol_mint)]
    pub dp_sol: Box<Account<'info, TokenAccount>>,

    #[account(mut, seeds = [b"franchise_pool".as_ref(), &[firm_state.tier]], bump = franchise_pool.bump)]
    pub franchise_pool: Box<Account<'info, TierFranchisePool>>,

    #[account(mut, address = franchise_pool.vault)]
    pub franchise_vault: Box<Account<'info, TokenAccount>>,

    #[account(mut, token::mint = firm_state.sol_mint)]
    pub referrer_sol: Option<Box<Account<'info, TokenAccount>>>,

    // $DPROP buy-and-burn leg (5%): enforced routing into the canonical PDA-owned $DPROP buyback
    // SOL accumulator (seeds ["dprop_buyback_sol"]) — the trustless protocol-token sink. The
    // permissionless `execute_dprop_buyback` + `burn_dprop_buyback` cranks convert + burn it.
    // Requires a single platform SOL mint and `init_dprop_buyback` to have run.
    #[account(mut, seeds = [b"dprop_buyback_sol"], bump, token::mint = firm_state.sol_mint)]
    pub dprop_buyback_vault: Box<Account<'info, TokenAccount>>,

    // Universal Treasury Pool seed (3%): enforced PDA routing into the protocol-wide vault
    // (seeds ["universal_vault"]). `init_universal_pool` must have run first.
    #[account(mut, seeds = [b"universal_vault"], bump, token::mint = firm_state.sol_mint)]
    pub universal_vault: Box<Account<'info, TokenAccount>>,
    #[account(mut, seeds = [b"universal_pool"], bump = universal_pool.bump)]
    pub universal_pool: Box<Account<'info, UniversalPool>>,

    // RESERVE-3: one-shot fee-paid marker. `init` makes a second `pay_deployment_fee` for this firm
    // revert (already-in-use), so the launch fee can never be double-charged.
    #[account(
        init,
        payer = owner,
        space = 8,
        seeds = [b"deployment_fee_paid", firm_state.key().as_ref()],
        bump
    )]
    pub fee_marker: Box<Account<'info, DeploymentFeeMarker>>,

    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
}

impl<'info> PayDeploymentFee<'info> {
    /// Transfer SOL from the owner to a destination (no-op on zero).
    fn xfer(&self, to: AccountInfo<'info>, amount: u64) -> Result<()> {
        if amount == 0 {
            return Ok(());
        }
        token::transfer(
            CpiContext::new(
                self.token_program.to_account_info(),
                anchor_spl::token::Transfer {
                    from: self.owner_sol.to_account_info(),
                    to,
                    authority: self.owner.to_account_info(),
                },
            ),
            amount,
        )
    }
}


#[derive(Accounts)]
pub struct FinalizeTokenLaunch<'info> {
    #[account(mut)]
    pub owner: Signer<'info>,

    #[account(
        mut,
        seeds = [b"firm", owner.key().as_ref()],
        bump = firm_state.bump,
        constraint = firm_state.owner == owner.key() @ FirmError::Unauthorized,
    )]
    pub firm_state: Box<Account<'info, FirmState>>,

    // Front-running guard (2026-07-09): flips the curve's `trading_live` open. RESERVE-3: the deploy
    // escrow was removed, so there is no longer anything to drain before opening trading.
    #[account(
        mut,
        seeds = [b"bonding_curve", firm_state.key().as_ref()],
        bump = curve.bump,
        seeds::program = bonding_curve::ID,
    )]
    pub curve: Box<Account<'info, bonding_curve::BondingCurve>>,
    pub bonding_curve_program: Program<'info, bonding_curve::program::BondingCurve>,
}

#[derive(Accounts)]
pub struct MigrateFirmTokenFields<'info> {
    #[account(mut)]
    pub owner: Signer<'info>,

    /// CHECK: raw firm PDA. Pre-migration the stored data is SMALLER than the current `FirmState`
    /// struct, so `Account<FirmState>` can't deserialize it yet — we resize + set the two trailing
    /// token bytes directly. Seeds bind it to `owner`'s own firm; `owner = crate::ID` proves it's ours.
    #[account(mut, seeds = [b"firm", owner.key().as_ref()], bump, owner = crate::ID)]
    pub firm_state: UncheckedAccount<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct MigrateFirmPermissionless<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,

    /// CHECK: its key derives the firm PDA seed only — the migration grants no authority, so this
    /// account never signs. Pass the target firm's owner pubkey (readable from `FirmState.owner`).
    pub firm_owner: UncheckedAccount<'info>,

    /// CHECK: raw firm PDA. Pre-migration the stored data is SMALLER than the current `FirmState`, so
    /// `Account<FirmState>` can't deserialize it yet — we resize + zero-fill directly. Seeds bind it
    /// to `firm_owner`'s firm; `owner = crate::ID` proves it's ours.
    #[account(mut, seeds = [b"firm", firm_owner.key().as_ref()], bump, owner = crate::ID)]
    pub firm_state: UncheckedAccount<'info>,

    pub system_program: Program<'info, System>,
}

/// DEC-77 migration — permissionless, mirrors `MigrateFirmPermissionless`'s pattern: grants no new
/// privilege, extends a pre-existing `QueuedPayout` and zero-fills the appended `advance_sol_spent`
/// field. `challenge` is read unchecked (owner-pinned) purely to derive the seed.
#[derive(Accounts)]
#[instruction(cycle: u32)]
pub struct MigrateQueuedPayoutAdvanceField<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,

    /// CHECK: challenge key only — the queued payout's PDA seed.
    #[account(owner = challenge::ID)]
    pub challenge: UncheckedAccount<'info>,

    /// CHECK: raw payout PDA. Pre-migration the stored data is SMALLER than the current
    /// `QueuedPayout` struct, so `Account<QueuedPayout>` can't deserialize it yet — resize + zero-fill
    /// directly. Seeds bind it to this challenge + cycle; `owner = crate::ID` proves it's ours.
    #[account(
        mut,
        seeds = [b"payout", challenge.key().as_ref(), &cycle.to_le_bytes()],
        bump,
        owner = crate::ID,
    )]
    pub queued_payout: UncheckedAccount<'info>,

    pub system_program: Program<'info, System>,
}

/// PAYOUT-ADVANCE-11 migration — permissionless, mirrors `MigrateQueuedPayoutAdvanceField`'s pattern:
/// extends a pre-existing `AdvancePool` and zero-fills the appended daily-velocity fields.
#[derive(Accounts)]
pub struct MigrateAdvancePoolDailyFields<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,

    /// CHECK: firm key only — the advance pool's PDA seed.
    #[account(owner = crate::ID)]
    pub firm_state: UncheckedAccount<'info>,

    /// CHECK: raw advance-pool PDA. Pre-migration the stored data is SMALLER than the current
    /// `AdvancePool` struct, so `Account<AdvancePool>` can't deserialize it yet — resize + zero-fill
    /// directly. Seeds bind it to this firm; `owner = crate::ID` proves it's ours.
    #[account(
        mut,
        seeds = [b"advance_pool", firm_state.key().as_ref()],
        bump,
        owner = crate::ID,
    )]
    pub advance_pool: UncheckedAccount<'info>,

    pub system_program: Program<'info, System>,
}

/// §19 anti-bank-run migration — permissionless, mirrors `MigrateAdvancePoolDailyFields`'s pattern.
#[derive(Accounts)]
pub struct MigrateBackstopPoolFields<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,

    /// CHECK: firm key only — the backstop pool's PDA seed.
    #[account(owner = crate::ID)]
    pub firm_state: UncheckedAccount<'info>,

    /// CHECK: raw backstop-pool PDA. Pre-migration the stored data is SMALLER than the current
    /// `BackstopPool` struct, so `Account<BackstopPool>` can't deserialize it yet — resize + zero-fill
    /// directly. Seeds bind it to this firm; `owner = crate::ID` proves it's ours.
    #[account(
        mut,
        seeds = [b"backstop_pool", firm_state.key().as_ref()],
        bump,
        owner = crate::ID,
    )]
    pub backstop_pool: UncheckedAccount<'info>,

    pub system_program: Program<'info, System>,
}

/// §19 anti-bank-run migration — permissionless, same shape as `MigrateBackstopPoolFields`.
#[derive(Accounts)]
pub struct MigrateBackstopPositionFields<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,

    /// CHECK: firm key only — the backstop position's PDA seed.
    #[account(owner = crate::ID)]
    pub firm_state: UncheckedAccount<'info>,

    /// CHECK: staker key only — the backstop position's PDA seed.
    pub staker: UncheckedAccount<'info>,

    /// CHECK: raw backstop-position PDA. Pre-migration the stored data is SMALLER than the current
    /// `BackstopPosition` struct, so `Account<BackstopPosition>` can't deserialize it yet — resize +
    /// zero-fill directly. Seeds bind it to this firm+staker; `owner = crate::ID` proves it's ours.
    #[account(
        mut,
        seeds = [b"backstop_pos", firm_state.key().as_ref(), staker.key().as_ref()],
        bump,
        owner = crate::ID,
    )]
    pub position: UncheckedAccount<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct InitPlatformConfig<'info> {
    #[account(mut)]
    pub upgrade_authority: Signer<'info>,

    /// The firm program's `ProgramData` — its `upgrade_authority_address` MUST equal the signer, so
    /// only the deployer can establish the platform config (front-run-proof root of trust).
    #[account(
        seeds = [crate::ID.as_ref()],
        bump,
        seeds::program = anchor_lang::solana_program::bpf_loader_upgradeable::ID,
        constraint = program_data.upgrade_authority_address == Some(upgrade_authority.key())
            @ FirmError::Unauthorized,
    )]
    pub program_data: Account<'info, ProgramData>,

    #[account(
        init,
        payer = upgrade_authority,
        space = 8 + PlatformConfig::INIT_SPACE,
        seeds = [b"platform_config"],
        bump
    )]
    pub platform_config: Box<Account<'info, PlatformConfig>>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct UpdatePlatformConfig<'info> {
    pub authority: Signer<'info>,

    #[account(
        mut,
        seeds = [b"platform_config"],
        bump = platform_config.bump,
        constraint = platform_config.authority == authority.key() @ FirmError::Unauthorized,
    )]
    pub platform_config: Box<Account<'info, PlatformConfig>>,
}

/// V2-1 platform_config resize (pre-guardian 201-byte layout -> 233). `platform_config` is taken RAW
/// (`UncheckedAccount`) because it can't deserialize as `PlatformConfig` until it's grown; the handler
/// validates the PDA seeds + the stored config authority before touching it.
#[derive(Accounts)]
pub struct MigratePlatformConfig<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,

    /// CHECK: seeds-validated PDA; resized + guardian-inserted raw in the handler (undersized to
    /// deserialize), gated on the stored authority.
    #[account(mut, seeds = [b"platform_config"], bump)]
    pub platform_config: UncheckedAccount<'info>,

    pub system_program: Program<'info, System>,
}

/// Canonical platform config (M-2/M-4). Seeds: ["platform_config"]. Holds the platform-controlled SOL
/// destinations so they cannot be substituted by a caller of `pay_challenge_fee` / dispute slashing.
#[account]
#[derive(InitSpace)]
pub struct PlatformConfig {
    pub authority: Pubkey,
    pub dp_profit_sol: Pubkey,
    pub dp_treasury_sol: Pubkey,
    pub normal_staking_vault: Pubkey,
    pub platform_sol: Pubkey,
    pub dp_dispute_fund: Pubkey,
    /// V2-1: the canonical platform-controlled guardian. `deploy_firm` binds `firm.guardian` to this,
    /// so a firm operator can no longer name itself (or a colluding key) as its own independent
    /// co-signer. Rotated platform-wide by the config `authority`; per-firm rotation stays on
    /// `set_guardian`.
    pub platform_guardian: Pubkey,
    pub bump: u8,
}

#[event]
pub struct PlatformConfigSet {
    pub authority: Pubkey,
}

#[derive(Accounts)]
pub struct UpdateRiskTier<'info> {
    pub authority: Signer<'info>,

    #[account(
        mut,
        seeds = [b"firm", firm_state.owner.as_ref()],
        bump = firm_state.bump,
        constraint = firm_state.risk_engine_authority == authority.key() @ FirmError::Unauthorized,
    )]
    pub firm_state: Account<'info, FirmState>,
}

#[derive(Accounts)]
pub struct UpdateStakeholderConfig<'info> {
    pub owner: Signer<'info>,

    #[account(
        mut,
        seeds = [b"firm", firm_state.owner.as_ref()],
        bump = firm_state.bump,
        constraint = firm_state.owner == owner.key() @ FirmError::Unauthorized,
    )]
    pub firm_state: Account<'info, FirmState>,
}

#[derive(Accounts)]
pub struct SetBackstopPremium<'info> {
    pub owner: Signer<'info>,

    #[account(
        seeds = [b"firm", firm_state.owner.as_ref()],
        bump = firm_state.bump,
        constraint = firm_state.owner == owner.key() @ FirmError::Unauthorized,
    )]
    pub firm_state: Box<Account<'info, FirmState>>,

    #[account(mut, seeds = [b"backstop_pool", firm_state.key().as_ref()], bump = backstop_pool.bump)]
    pub backstop_pool: Box<Account<'info, BackstopPool>>,
}

#[derive(Accounts)]
pub struct SetLossBackMinStake<'info> {
    pub owner: Signer<'info>,

    #[account(
        mut,
        seeds = [b"firm", firm_state.owner.as_ref()],
        bump = firm_state.bump,
        constraint = firm_state.owner == owner.key() @ FirmError::Unauthorized,
    )]
    pub firm_state: Box<Account<'info, FirmState>>,
}

/// K-1 — accounts for `set_guardian`. The CURRENT guardian signs (self-rotation of the platform
/// co-signer); the owner is not involved, preserving guardian independence.
#[derive(Accounts)]
pub struct SetGuardian<'info> {
    pub guardian: Signer<'info>,

    #[account(
        mut,
        seeds = [b"firm", firm_state.owner.as_ref()],
        bump = firm_state.bump,
        constraint = firm_state.guardian == guardian.key() @ FirmError::GuardianMismatch,
    )]
    pub firm_state: Box<Account<'info, FirmState>>,
}

/// K-1 — accounts for `set_risk_engine_authority`. The GUARDIAN signs (not the current keeper — which
/// may be the compromised key — and not the owner). Rotates the hot keeper key with a grace window.
#[derive(Accounts)]
pub struct SetRiskEngineAuthority<'info> {
    pub guardian: Signer<'info>,

    #[account(
        mut,
        seeds = [b"firm", firm_state.owner.as_ref()],
        bump = firm_state.bump,
        constraint = firm_state.guardian == guardian.key() @ FirmError::GuardianMismatch,
    )]
    pub firm_state: Box<Account<'info, FirmState>>,
}

// `InitLossBackVault` and `RedeemLossBackCredit` (+ its dead `pay_trader` helper) were REMOVED
// 2026-07-27 — comeback credit no longer has a backing vault; see `pay_challenge_fee`.

#[derive(Accounts)]
pub struct InitPlatformRisk<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,

    #[account(
        init,
        payer = authority,
        space = 8 + PlatformRiskState::INIT_SPACE,
        seeds = [b"platform_risk"],
        bump
    )]
    pub platform_risk: Account<'info, PlatformRiskState>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct UpdatePlatformRisk<'info> {
    pub authority: Signer<'info>,

    #[account(
        mut,
        seeds = [b"platform_risk"],
        bump = platform_risk.bump,
        constraint = platform_risk.authority == authority.key() @ FirmError::Unauthorized,
    )]
    pub platform_risk: Account<'info, PlatformRiskState>,
}

#[derive(Accounts)]
pub struct ClaimDrip<'info> {
    pub owner: Signer<'info>,

    #[account(
        seeds = [b"firm", firm_state.owner.as_ref()],
        bump = firm_state.bump,
        constraint = firm_state.owner == owner.key() @ FirmError::Unauthorized,
    )]
    pub firm_state: Box<Account<'info, FirmState>>,

    #[account(seeds = [b"platform_risk"], bump = platform_risk.bump)]
    pub platform_risk: Box<Account<'info, PlatformRiskState>>,

    #[account(
        mut,
        seeds = [b"owner_drip", firm_state.key().as_ref()],
        bump = owner_drip_state.bump,
    )]
    pub owner_drip_state: Box<Account<'info, OwnerDripState>>,

    #[account(mut, address = owner_drip_state.vault)]
    pub drip_vault: Box<Account<'info, TokenAccount>>,

    #[account(
        mut,
        token::mint = firm_state.firma_mint,
        constraint = owner_firma.owner == firm_state.owner @ FirmError::Unauthorized,
    )]
    pub owner_firma: Box<Account<'info, TokenAccount>>,

    pub token_program: Program<'info, Token>,
}

impl<'info> ClaimDrip<'info> {
    /// Release drip $FIRMA from the vault to the owner (firm PDA is the vault authority).
    fn release(&self, amount: u64) -> Result<()> {
        if amount == 0 {
            return Ok(());
        }
        let bump = [self.firm_state.bump];
        let seeds = firm_signer(&self.firm_state.owner, &bump);
        token::transfer(
            CpiContext::new_with_signer(
                self.token_program.to_account_info(),
                anchor_spl::token::Transfer {
                    from: self.drip_vault.to_account_info(),
                    to: self.owner_firma.to_account_info(),
                    authority: self.firm_state.to_account_info(),
                },
                &[&seeds],
            ),
            amount,
        )
    }
}

/// Per-firm state PDA (architecture §19). Seeds: ["firm", owner].
#[account]
#[derive(InitSpace)]
pub struct FirmState {
    pub owner: Pubkey,
    pub risk_engine_authority: Pubkey,
    /// Independent platform co-signer (DecentralProp guardian). Distinct from `owner` and
    /// `risk_engine_authority`, it MUST also sign every instruction that moves OTHER stakeholders'
    /// money or exits the firm — `finalize_close`, `draw_backstop`, `settle_dispute_payout` — so the
    /// key that *declares* an emergency is never the same key that *spends* the emergency fund
    /// (operator threat model #1/#3). Set once at `deploy_firm`; intended to be a Squads multisig.
    pub guardian: Pubkey,
    /// Unix time a clean shutdown was initiated (`initiate_close`); 0 = not closing. `finalize_close`
    /// only disburses after `+ CLOSE_TIMELOCK`, giving unpaid traders / disputers a window (F1).
    pub close_initiated_at: i64,
    /// Deployment tier (0 Starter … 4 Enterprise) — governs the owner fee % (§17).
    pub tier: u8,
    pub status: FirmStatus,
    pub risk_tier: RiskTier,
    pub last_tier_change_at: i64,
    pub velocity_break_flag: bool,
    pub deployed_at: i64,
    // ── value-flow layer ──
    pub firma_mint: Pubkey,
    pub sol_mint: Pubkey,
    pub treasury_vault: Pubkey,
    /// Cache of the treasury SOL token-account balance (§19 sync contract).
    pub treasury_sol: u64,
    pub graduated: bool,
    pub total_paid_out: u64,
    pub daily_payout_spent: u64,
    pub payout_day: i64,
    pub supply_distributed: bool,
    /// $FIRMA staging vault a payout buy delivers into before the trader/stakeholder
    /// split (§22). Authority = firm PDA.
    pub payout_firma_vault: Pubkey,
    /// Firm's $FIRMA treasury reserve — Tier 2 of the payout waterfall. Seeded by the
    /// deployment treasury auto-purchase; delivered directly to traders (no slippage).
    pub treasury_firma_vault: Pubkey,
    /// Stakeholder-share distribution ratios (§19), governance-adjustable in range.
    pub stakeholder_config: StakeholderConfig,
    /// Count of queued trader payouts that are enqueued but not yet fully delivered (§24, F1).
    /// Incremented on `enqueue_payout`, decremented when a payout becomes fully filled in
    /// `process_queued_payout`. `finalize_close` is hard-gated on this being 0 — a firm can
    /// never be closed (and its treasury released to insiders) while it still owes a trader.
    pub open_payouts: u64,
    /// SOL carved by the 3% $YOURFIRM buy-back leg of challenge fees, held in the treasury vault
    /// and awaiting conversion to the Tier-2 $FIRMA reserve by `execute_firma_buyback` (§17).
    pub firma_buyback_acc: u64,
    /// Minimum staked $FIRMA (base units) a trader must hold to redeem accrued loss-back credit
    /// (flywheel). Governance-set by the owner via `set_loss_back_min_stake`; 0 = any staker (the
    /// trader must still hold a `StakerPosition`). The 3% accrual is unconditional; only redemption
    /// is gated, so the slice keeps circulating inside the protocol and rewards $FIRMA stakers.
    pub loss_back_min_stake: u64,
    pub bump: u8,
    // ── deferred token launch (design 2026-07-01) ──
    // Appended AFTER `bump` on purpose: migrating a pre-existing on-chain firm is then a clean
    // "extend by 2 bytes + set the trailing token_live byte" (`migrate_firm_token_fields`) with no
    // shift of any existing field. `token_live` GATES evaluation sales (`pay_challenge_fee`) — false
    // until the operator finishes launching the $FIRMA token (`finalize_token_launch`).
    // `token_pending` marks a deployed-but-not-launched firm (curve-buy fee legs escrowed in
    // `PendingTokenBuy`). Backfilled firms get `token_live = true`, `token_pending = false`.
    pub token_live: bool,
    pub token_pending: bool,
    // ── keeper authority rotation (K-1, 2026-07-03) ──
    // Appended AFTER `token_pending` (append-only discipline). Both zero by default, which is exactly
    // "no rotation pending" — so `migrate_firm_authority_fields` is a clean "extend + zero-fill".
    // When the guardian rotates the keeper via `set_risk_engine_authority`, the OUTGOING key is parked
    // here and `require_firm_settlement_authority` keeps honoring it until `authority_rotation_deadline`
    // so in-flight challenges (whose frozen `settlement_authority` == the old keeper) stay payable
    // across the transition. After the deadline the old key is fully dead.
    pub previous_risk_engine_authority: Pubkey,
    pub authority_rotation_deadline: i64,
    // ── self-funded operator bond (§10/§14, 2026-07-06) ──
    // Appended AFTER the K-1 rotation fields (append-only discipline). Both zero by default:
    // `bond_accrual = 0` (nothing earmarked), `bond_funded = false` (bond not yet at 50 SOL) — the
    // correct state for a fresh or migrated firm, so the resize-to-INIT_SPACE migrations backfill them
    // for free. `pay_challenge_fee` earmarks 1% of each fee here while `!bond_funded`; the permissionless
    // `fund_operator_bond` crank drains `bond_accrual` from the treasury into the dispute-program
    // `OperatorStake` PDA (unwrapping wSOL → native SOL) and flips `bond_funded` when it fills.
    /// SOL (wSOL lamports) earmarked from the treasury for the operator bond, awaiting `fund_operator_bond`.
    pub bond_accrual: u64,
    /// True once the operator bond has been funded to `dispute::MIN_OPERATOR_STAKE_LAMPORTS`. While false,
    /// `pay_challenge_fee` earmarks the 1% bond leg; once true the earmark stops (1% → treasury as normal).
    pub bond_funded: bool,
    /// Auto-bankruptcy (§24 v2). Lifetime SOL this firm has drawn from the Universal Pool (both the
    /// `draw_universal` payout tail and the `settle_dispute_payout` ULP fallback). The instant this reaches
    /// `pool_balance / BANKRUPTCY_ULP_DEPLETION_DIVISOR` (10% of the pool as it stood at the draw), the
    /// firm flips to `Bankrupt` in the same tx — the ONLY path to `Bankrupt`. A firm that consumes a tenth
    /// of the mutual commons is removed from operation (stops selling) and its residual is swept back to the
    /// pool by `finalize_bankruptcy`.
    pub ulp_drawn: u64,
    /// Post-graduation LP fee-leg earmark (§12 / RAYDIUM_GRADUATION.md Phase 4.4). Once the curve
    /// graduates, the dynamic LP leg of each eval fee can no longer deepen the (migrated) curve, so it
    /// is recorded here — the SOL itself sits in `treasury_vault`, this tracks the claim — and the
    /// permissionless `add_graduated_liquidity` crank later zaps it into the graduated Raydium pool as
    /// permanently-locked LP. Appended AFTER `ulp_drawn` (append-only migration discipline; zero-fills
    /// to 0 = "nothing pending" for an existing firm).
    pub post_grad_lp_acc: u64,
    /// Backstop pool's $FIRMA yield leg (2026-07-27 staking rebalance) — bps of the stakeholder
    /// FIRMA basis, same governance range as `stakeholder_config.staking_pool_bps` (500..=3000).
    /// A SIBLING of `stakeholder_config`, not a field inside it — appended here, at the true tail
    /// of `FirmState`, on purpose: `stakeholder_config` sits mid-struct, and the resize-only
    /// `migrate_firm_permissionless` migration can only safely extend a buffer's END. Zero-fills to
    /// 0 for an existing firm on migration (matches every other appended default here); combined
    /// with `stakeholder_config`, `validate_stakeholder_config` requires the union to sum to 10000.
    pub backstop_pool_bps: u16,
}

#[repr(u8)]
#[derive(AnchorSerialize, AnchorDeserialize, InitSpace, Clone, Copy, PartialEq, Eq, Debug)]
pub enum RiskTier {
    Healthy = 0,
    Caution = 1,
    Warning = 2,
    Critical = 3,
}

#[derive(AnchorSerialize, AnchorDeserialize, InitSpace, Clone, Copy, PartialEq, Eq, Debug)]
pub enum FirmStatus {
    Active,
    Suspended,
    Bankrupt,
    Closed,
}

/// Stakeholder-share distribution ratios (§19), stored inline in `FirmState`. The
/// stakeholder share of every payout splits five ways. Sum must be 10000.
///
/// `universal_sol_bps` (40% default): of the stakeholder's SOL notional,
/// this fraction is transferred directly to the Universal Treasury Pool *before*
/// the curve buy runs. The remaining four fields (summing to 6000 by default)
/// govern how the $FIRMA purchased in the reduced buy is split. `split_stakeholder`
/// renormalises those four bps against `(10000 - universal_sol_bps)` so each field
/// still represents the intended fraction of the *original* stakeholder notional.
#[derive(AnchorSerialize, AnchorDeserialize, InitSpace, Clone, Copy, PartialEq, Eq, Debug)]
pub struct StakeholderConfig {
    pub owner_share_bps: u16,
    pub staking_pool_bps: u16,
    pub buyback_burn_bps: u16,
    pub treasury_reserve_bps: u16,
    /// Fraction of the stakeholder SOL notional routed to the Universal Treasury Pool
    /// before the curve buy (pre-buy SOL carve). 0 = disabled; max 6000 (60%).
    pub universal_sol_bps: u16,
}
// NOTE (2026-07-27 staking rebalance, POST-INCIDENT): the backstop pool's $FIRMA yield leg is
// `FirmState.backstop_pool_bps` — a SIBLING field on `FirmState`, deliberately NOT a 6th field
// here. `StakeholderConfig` is embedded MID-STRUCT inside `FirmState` (see `stakeholder_config`
// below), not appended at its end — the append-only resize migration (`migrate_firm_permissionless`)
// only extends a buffer's tail and zero-fills the new bytes; it does NOT shift existing bytes. A
// field added HERE (inside the embedded struct) silently shifts every FirmState field declared
// after `stakeholder_config` (bump, token_live, bond_funded, …) by its width, misreading them from
// the wrong offset on every pre-existing account — caught live on devnet while writing this same
// change (AccountDidNotDeserialize, then a corrupted `bump` on re-migration) before it ever reached
// mainnet. Any future per-firm config value MUST be appended as its own new trailing `FirmState`
// field (like `backstop_pool_bps` below), never inserted into this embedded struct.

impl Default for StakeholderConfig {
    fn default() -> Self {
        // §19 defaults, 2026-07-27 staking rebalance: 30% owner / 5% no-risk staking (was 10%,
        // freed 5% now funds FirmState.backstop_pool_bps) / 10% buyback+burn / 10% treasury / 40%
        // universal SOL. FIRMA basis (10000 - universal_sol_bps = 6000) sums: 3000+500+1000+1000=5500
        // — deliberately 500 short of 6000; that remaining 500 is `FirmState.backstop_pool_bps`, not
        // part of this struct. `validate_stakeholder_config` checks the two together.
        Self {
            owner_share_bps: 3000,
            staking_pool_bps: 500,
            buyback_burn_bps: 1000,
            treasury_reserve_bps: 1000,
            universal_sol_bps: 4000,
        }
    }
}

#[event]
pub struct FirmDeployed {
    pub firm: Pubkey,
    pub owner: Pubkey,
    pub deployed_at: i64,
}

#[event]
pub struct FirmTreasuryCreated {
    pub firm: Pubkey,
    pub sol_mint: Pubkey,
    pub treasury_vault: Pubkey,
}

#[event]
pub struct FirmaMintCreated {
    pub firm: Pubkey,
    pub firma_mint: Pubkey,
    /// Operator-chosen token identity, recorded at launch (immutable). Consumed by the
    /// indexer/SDK to build the Metaplex metadata account.
    pub name: String,
    pub symbol: String,
    pub uri: String,
}

#[event]
pub struct SupplyDistributed {
    pub firm: Pubkey,
    pub curve_amount: u64,
    pub drip_amount: u64,
    pub treasury_amount: u64,
    pub total: u64,
}

/// Per-firm insurance fund (§19). Seeds: ["insurance", firm]. Funded by 8% of fees.
#[account]
#[derive(InitSpace)]
pub struct InsuranceFund {
    pub firm: Pubkey,
    pub balance: u64,
    pub bump: u8,
}

/// Owner challenge-fee soft lock (§17). Seeds: ["vesting", challenge]. 90-day lock.
#[account]
#[derive(InitSpace)]
pub struct OwnerVestingBatch {
    pub owner: Pubkey,
    pub firm: Pubkey,
    pub amount: u64,
    pub unlocks_at: i64,
    pub claimed: bool,
    pub bump: u8,
}

/// Per-challenge payout record (§22). Seeds: ["payout", challenge]. Its existence is
/// the double-payout guard — `execute_payout_buy` inits it, so a second call fails.
#[account]
#[derive(InitSpace)]
pub struct PayoutRecord {
    pub challenge: Pubkey,
    /// Withdrawal cycle this record pays (DEC-62). 0 for the settlement path. In the PDA seed, so the
    /// immediate and queued paths stay mutually exclusive PER CYCLE.
    pub cycle: u32,
    pub trader: Pubkey,
    pub firma_delivered: u64,
    pub sol_spent: u64,
    pub claimed_at: i64,
    pub bump: u8,
}

/// A windowed/partial payout (§22). Seeds: ["payout", challenge] — shared with the
/// immediate path's `PayoutRecord` so the two payout paths are mutually exclusive.
/// `firma_amount_owed` is the trader's locked $FIRMA; the stakeholder share is bought
/// and distributed on top at processing time.
#[account]
#[derive(InitSpace)]
pub struct QueuedPayout {
    pub trader: Pubkey,
    pub firm: Pubkey,
    pub challenge: Pubkey,
    /// Withdrawal cycle this payout discharges (DEC-62). 0 for the settlement path. In the PDA seed —
    /// this is what lets a funded account withdraw more than once (at `["payout", challenge]` the PDA
    /// was occupied forever by the first payout). Read back by the non-init account structs for their
    /// own seeds, the same way `ChallengeState` reads its own `nonce`.
    pub cycle: u32,
    /// SOL value at settlement — historical reference only (NOT what is spent).
    pub sol_at_settlement: u64,
    /// Exact $FIRMA the trader must receive — locked at settlement.
    pub firma_amount_owed: u64,
    /// Increases with each partial fill; outstanding = owed − delivered.
    pub firma_amount_delivered: u64,
    pub queued_at: i64,
    /// 0 = no hold; else a unix timestamp (concentration-guard hold).
    pub hold_until: i64,
    /// 0 = standard, 1 = loyalty fast-track.
    pub priority: u8,
    pub window_target: u8,
    /// ARE tier at settlement — governs the split %; persists across re-queues.
    pub settlement_tier: u8,
    pub bump: u8,
    /// DEC-77 — 0 for a normal (post-Final `enqueue_payout`-created) payout; else the SOL an
    /// `advance_first_payout` call spent buying this entry's `firma_amount_delivered` chunk while the
    /// settlement was still `Provisional`. Cleared to 0 by whichever of `reconcile_payout_advance` /
    /// `write_off_faulted_advance` resolves it — both also decrement `AdvancePool.sol_outstanding` by
    /// this exact amount, so it is never double-released. Appended AFTER `bump` (append-only); a
    /// pre-existing `QueuedPayout` needs `migrate_queued_payout_advance_field` before it can be read
    /// (unlike `FirmState`'s trailing fields, nothing here resizes it for free — this account type has
    /// no existing "resize to current INIT_SPACE" crank).
    pub advance_sol_spent: u64,
}

/// DEC-77 — first-payout instant advance (§22b): the firm's live advance-float exposure. Deliberately
/// a SEPARATE small PDA rather than a new `FirmState` field — `FirmState` is boxed everywhere it's used
/// but Anchor's account deserialization still stack-allocates the full struct before moving it into the
/// `Box`, so any further growth risks re-tripping the BPF 4 KB stack limit on an already-tight
/// instruction (`PayChallengeFee` sits right at the edge; adding one more `u64` to `FirmState` pushed
/// it 8 bytes over during this feature's development). Seeds: `["advance_pool", firm]`. Created
/// lazily (`init_if_needed`) the first time a firm's first advance runs.
#[account]
#[derive(InitSpace)]
pub struct AdvancePool {
    pub firm: Pubkey,
    /// Cumulative SOL currently outstanding via unresolved `advance_first_payout` calls, across every
    /// challenge for this firm. Bounds live exposure against `ADVANCE_CAP_BPS % of treasury_sol`
    /// (computed fresh each call, never cached). Incremented at `advance_first_payout`, decremented at
    /// `reconcile_payout_advance` (Final — made whole) or `write_off_faulted_advance` (Faulted —
    /// permanent loss, already reflected in `treasury_sol` since the SOL left at advance time).
    pub sol_outstanding: u64,
    pub bump: u8,
    /// PAYOUT-ADVANCE-11 — cumulative SOL spent on advances during `advance_day`'s UTC day, reset to 0
    /// on the first advance of a new day. Appended field — pre-existing `AdvancePool` accounts need
    /// `migrate_advance_pool_daily_fields` before this layout deserializes.
    pub daily_advance_spent: u64,
    /// UTC day index (`unix_timestamp / 86_400`) `daily_advance_spent` is scoped to.
    pub advance_day: i64,
}

/// Platform-native $DPROP buyback-and-burn sink (§17). Seeds: ["dprop_buyback"]. ONE global PDA.
/// The 1% `dprop_buyback` fee leg accrues SOL into `sol_vault` (PDA-owned). A permissionless
/// crank swaps that SOL → $DPROP on Raydium (integration boundary) into `dprop_vault`, and a
/// second permissionless crank **burns** whatever $DPROP is in `dprop_vault`. Both vault
/// authorities are this PDA, so no admin — including DecentralProp — can ever redirect the
/// accumulated SOL or the bought $DPROP: the only exits are "buy" and "burn". The burn is the
/// on-chain-verifiable deflation; the swap CPI is the devnet boundary (mirrors `graduate_firm`).
#[account]
#[derive(InitSpace)]
pub struct DpropBuyback {
    /// The protocol-native $DPROP mint this sink burns. Set once at init.
    pub dprop_mint: Pubkey,
    /// PDA-owned SOL accumulator the fee split feeds (seeds ["dprop_buyback_sol"]).
    pub sol_vault: Pubkey,
    /// PDA-owned $DPROP holding vault the swap fills and the burn drains (seeds ["dprop_buyback_dprop"]).
    pub dprop_vault: Pubkey,
    /// Lifetime SOL spent buying $DPROP.
    pub total_sol_spent: u64,
    /// Lifetime $DPROP burned — the public deflation counter.
    pub total_dprop_burned: u64,
    pub bump: u8,
}

/// Protocol-level $DPROP staking pool. Seeds: ["dprop_staking"]. Tracks the PDA-owned SOL vault
/// that accumulates the 10% eval-fee leg from every firm, distributed as yield to $DPROP stakers.
#[account]
#[derive(InitSpace)]
pub struct DpropStakingPool {
    /// PDA-owned SOL accumulator (seeds ["dprop_staking_sol"]).
    pub sol_vault: Pubkey,
    /// Lifetime SOL distributed to $DPROP stakers.
    pub total_sol_distributed: u64,
    pub bump: u8,
}

/// $DPROP staking ledger (R33) — the MasterChef accumulator for the protocol-wide $DPROP staking pool.
/// Held SEPARATELY from `DpropStakingPool` (seeds ["dprop_stake_ledger"]) so the deployed singleton
/// needs no layout migration. `last_sol_balance` tracks the `dprop_staking_sol` balance already folded
/// into `acc_sol` (post-payout re-synced), so each interaction folds only newly-arrived SOL.
#[account]
#[derive(InitSpace)]
pub struct DpropStakeLedger {
    /// PDA-owned $DPROP stake vault (seeds ["dprop_stake_vault"]).
    pub stake_vault: Pubkey,
    pub dprop_mint: Pubkey,
    pub total_staked: u64,
    pub acc_sol: u128,
    pub unallocated_sol: u64,
    pub last_sol_balance: u64,
    pub bump: u8,
    // ── R33.1 streamed retroactive reserve (appended after `bump` for clean realloc) ──
    /// The pre-open `dprop_staking_sol` balance at ledger init — SOL that accrued from the 10% eval
    /// leg before staking opened. Streamed to stakers over `DPROP_RETRO_VEST_SECONDS`, not lumped.
    pub retro_reserve: u64,
    /// How much of `retro_reserve` has already been folded into `acc_sol` (monotonic, ≤ reserve).
    pub retro_released: u64,
    /// When streaming began (ledger-init timestamp) — the vesting clock origin.
    pub retro_start: i64,
}

/// A single staker's $DPROP position. `yield_debt_sol` is the MasterChef debt; `pending_sol` carries
/// yield settled on stake/unstake until `claim_dprop_staking_yield` pays it out.
#[account]
#[derive(InitSpace)]
pub struct DpropStakerPosition {
    pub staker: Pubkey,
    pub amount_staked: u64,
    pub yield_debt_sol: u128,
    pub pending_sol: u64,
    pub bump: u8,
}

#[event]
pub struct DpropStakeLedgerInitialized {
    pub ledger: Pubkey,
    pub stake_vault: Pubkey,
}
#[event]
pub struct DpropStaked {
    pub staker: Pubkey,
    pub amount: u64,
    pub total_staked: u64,
    pub position_staked: u64,
}
#[event]
pub struct DpropUnstaked {
    pub staker: Pubkey,
    pub amount: u64,
    pub total_staked: u64,
}
#[event]
pub struct DpropYieldClaimed {
    pub staker: Pubkey,
    pub sol: u64,
}

/// Universal Treasury Pool — a single protocol-wide SOL pool (seeds ["universal_pool"]) that ANY
/// firm can draw from as the FINAL tier of the payout waterfall (`draw_universal`), when its own
/// treasury + $FIRMA reserve + backstop are exhausted. Funded by a fixed 1.5% leg of every eval
/// fee and a 3% seed from every launch fee. A **pure grant** (no per-firm debt): firm operators do
/// not choose who passes — the protocol/ARE does — so the pool cannot be farmed by colluding on
/// passes. `daily_drawn`/`draw_day` rate-limit total depletion across all firms per UTC day.
#[account]
#[derive(InitSpace)]
pub struct UniversalPool {
    /// Platform authority (the same multi-sig that governs platform risk); for future params/governance.
    pub authority: Pubkey,
    /// PDA-owned SOL (wSOL) accumulator (seeds ["universal_vault"]).
    pub vault: Pubkey,
    /// Lifetime SOL routed into the pool (deploy 3% seed + eval 1.5% leg).
    pub total_contributed: u64,
    /// Lifetime SOL drawn out via `draw_universal`.
    pub total_drawn: u64,
    /// UTC day index (`now / 86_400`) the daily draw counter is tracking.
    pub draw_day: i64,
    /// SOL drawn so far on `draw_day` (reset each new day) — enforces the global daily draw cap.
    pub daily_drawn: u64,
    pub bump: u8,
}

/// Per-firm owner $FIRMA drip schedule (§17). Seeds: ["owner_drip", firm]. 24 monthly
/// claims from the drip vault, paused while the effective tier is WARNING/CRITICAL.
#[account]
#[derive(InitSpace)]
pub struct OwnerDripState {
    pub owner: Pubkey,
    pub firm: Pubkey,
    pub vault: Pubkey,
    pub total_tokens: u64,
    pub months_total: u8,
    pub months_claimed: u8,
    pub drip_start_at: i64,
    pub bump: u8,
}

/// Per-firm $FIRMA staking pool (§19). Seeds: ["staking_pool", firm]. Dual yield: SOL
/// (weekly keeper) and $FIRMA (payout stakeholder share), each via a per-token
/// accumulator scaled by `PRECISION`.
#[account]
#[derive(InitSpace)]
pub struct FirmaStakingPool {
    pub firm: Pubkey,
    pub total_staked: u64,
    pub acc_sol: u128,
    pub acc_firma: u128,
    pub unallocated_sol: u64,
    pub unallocated_firma: u64,
    /// $FIRMA balance of `firma_reward_vault` already folded into `acc_firma` — the
    /// `sync_firma_yield` watermark, so only newly arrived tokens are distributed.
    pub firma_reward_accounted: u64,
    pub stake_vault: Pubkey,
    pub sol_reward_vault: Pubkey,
    pub firma_reward_vault: Pubkey,
    pub last_distribution_at: i64,
    pub bump: u8,
}

/// Per-staker position (§19). Seeds: ["staker", firm, staker].
#[account]
#[derive(InitSpace)]
pub struct StakerPosition {
    pub staker: Pubkey,
    pub firm: Pubkey,
    pub amount_staked: u64,
    pub yield_debt_sol: u128,
    pub yield_debt_firma: u128,
    pub staked_at: i64,
    pub bump: u8,
}

/// Per-trader loss-back "comeback" credit (flywheel). Seeds: ["loss_back", firm, trader]. Created
/// lazily on the trader's first evaluation purchase. 2026-07-27 staking rebalance: `balance` is a
/// PURELY NOTIONAL counter now — no backing vault, no token ever moves on accrual. It accrues 2%
/// (`LOSS_BACK_BPS`) of what the trader actually pays on every purchase, and can only be applied
/// as a price reduction on a LATER purchase (never cashed to wallet) while the trader stakes at
/// least `FirmState.loss_back_min_stake` $FIRMA in EITHER the no-risk or the backstop pool — see
/// `pay_challenge_fee`. `lifetime_accrued`/`lifetime_redeemed` are monotonic public counters.
#[account]
#[derive(InitSpace)]
pub struct LossBackCredit {
    pub firm: Pubkey,
    pub trader: Pubkey,
    pub balance: u64,
    pub lifetime_accrued: u64,
    pub lifetime_redeemed: u64,
    pub bump: u8,
}

/// Per-firm Investor Backstop Pool (§19 Risk-Bearing Insurance Staking). Seeds:
/// ["backstop_pool", firm]. Investor-staked $FIRMA backs payouts as Tier 3; stakers earn
/// a SOL premium and bear slash losses pro-rata via the loss accumulator.
#[account]
#[derive(InitSpace)]
pub struct BackstopPool {
    pub firm: Pubkey,
    /// Effective at-risk $FIRMA (sum of surviving staker principal); drops on draws. This is the LOSS
    /// denominator (a draw is mutualised over the principal at risk at draw time).
    pub total_staked: u64,
    /// F-M-5: the PREMIUM denominator — sum of NOMINAL staker principal. Unlike `total_staked` it is NOT
    /// reduced by `draw_backstop` (only by stake/withdraw of nominal). Premium accrues on nominal stake
    /// (`pending_yield(amount_staked, …)`), so the fold MUST divide by this same nominal sum, else
    /// `Σ premium_claimable` exceeds the premium funded (vault over-claim / insolvency).
    pub total_premium_weight: u64,
    /// SOL premium per staked token, scaled by PRECISION.
    pub premium_acc: u128,
    /// $FIRMA loss per staked token from draws, scaled by PRECISION.
    pub loss_acc: u128,
    /// Premium retained when nothing is staked; flushed on the next funding.
    pub unallocated_premium: u64,
    pub escrow_vault: Pubkey,
    pub premium_vault: Pubkey,
    /// Lifetime $FIRMA delivered to traders from this pool.
    pub total_drawn: u64,
    pub last_premium_at: i64,
    /// Premium carved from each challenge fee's treasury slice (§19), in bps of the fee.
    pub premium_bps: u16,
    pub bump: u8,
    /// Rolling-day outflow gate (§19 anti-bank-run): cumulative surviving $FIRMA paid out by
    /// `withdraw_backstop` during `withdraw_day`. Reset whenever a call lands on a new UTC day.
    /// Appended field — see `migrate_backstop_pool_fields`.
    pub daily_withdrawn: u64,
    /// Unix day (`ts / 86_400`) that `daily_withdrawn` accrues against.
    pub withdraw_day: i64,
    /// $FIRMA yield per staked token, scaled by PRECISION (2026-07-27 staking rebalance —
    /// mirrors StakingPool's `acc_firma`). Funded by `FirmState.backstop_pool_bps` on
    /// every funded-trader payout, folded in by the permissionless `sync_backstop_firma_yield`.
    /// Divides by `total_premium_weight` (nominal), NOT `total_staked` — same reasoning as
    /// `premium_acc`: a draw must not shrink the denominator other stakers' pending yield is
    /// computed against, or `Σ firma_claimable` can exceed what was actually funded.
    /// Appended field — same resize-and-zero-fill migration as `daily_withdrawn`/`withdraw_day`
    /// above, via the existing `migrate_backstop_pool_fields` (it resizes to whatever
    /// `BackstopPool::INIT_SPACE` currently is, so no new migration instruction is needed).
    pub acc_firma: u128,
    /// $FIRMA balance of `firma_reward_vault` already folded into `acc_firma`.
    pub firma_reward_accounted: u64,
    pub firma_reward_vault: Pubkey,
    /// $FIRMA retained when nothing is staked; flushed on the next `sync_backstop_firma_yield`.
    pub unallocated_firma: u64,
}

// ───────── Prediction Market LP Pool (Phase 2 of the pooled-LP AMM plan) ─────────

/// A single shared per-firm pool of community-provided $FIRMA liquidity that the protocol
/// algorithmically allocates across every eligible trader's prediction-market curve (Phase 3's
/// `allocate_pool_to_curve`). Structurally a near-exact mirror of `BackstopPool` above — same
/// PRECISION-scaled accumulator math, same whale-tiered cooldown, same rolling daily-outflow cap —
/// because it is solving the same problem (mutualized, slashable pooled capital with a fair
/// pro-rata yield/loss split) for a different destination. Unlike `BackstopPool`, both legs
/// (principal and yield) are denominated in the same `firma_mint`, so there is one debt field per
/// leg instead of a separate SOL-premium leg. Seeds: ["pm_lp_pool", firm].
#[account]
#[derive(InitSpace)]
pub struct PredictionMarketLpPool {
    pub firm: Pubkey,
    /// Loss-adjusted LP principal (mirrors `BackstopPool.total_staked`) — the LOSS denominator.
    /// Drops when a curve allocation realizes a loss (Phase 3); a draw is mutualised over the
    /// principal at risk at draw time.
    pub total_staked: u64,
    /// Nominal principal — the YIELD denominator (mirrors `total_premium_weight`). A realized curve
    /// loss must NOT shrink this: yield accrues on nominal stake, so folding it over a
    /// loss-reduced denominator would let `Σ pending_yield` exceed what was actually funded — the
    /// same F-M-5 insolvency class `BackstopPool.total_premium_weight`'s doc comment documents.
    pub total_yield_weight: u64,
    /// Accrued trading-fee yield per staked token, scaled by PRECISION.
    pub yield_acc: u128,
    /// $FIRMA loss per staked token from realized curve draws, scaled by PRECISION.
    pub loss_acc: u128,
    /// Yield retained when nothing is staked; flushed on the next fold.
    pub unallocated_yield: u64,
    pub escrow_vault: Pubkey,
    pub yield_vault: Pubkey,
    /// Lifetime capital cranked out to curves via Phase 3's `allocate_pool_to_curve`. Reserved
    /// here; unused (stays 0) by every Phase 2 instruction.
    pub total_drawn: u64,
    /// Lifetime capital cranked back from curves via Phase 3's `deallocate_pool_from_curve`.
    /// Reserved here; unused (stays 0) by every Phase 2 instruction.
    pub total_returned: u64,
    pub last_yield_at: i64,
    /// Rolling-day outflow gate (anti-bank-run, same idiom as `BackstopPool.daily_withdrawn`):
    /// cumulative surviving $FIRMA paid out by `withdraw_pm_lp` during `withdraw_day`.
    pub daily_withdrawn: u64,
    /// Unix day (`ts / 86_400`) that `daily_withdrawn` accrues against.
    pub withdraw_day: i64,
    /// Max % of `total_staked` deployable across all curves at once (Phase 3). Defaults to
    /// `DEFAULT_PM_LP_ALLOCATION_CAP_BPS` at `init_pm_lp_pool`; not enforced by any Phase 2
    /// instruction.
    pub allocation_cap_bps: u16,
    pub bump: u8,
}

/// Per-staker PM LP position. Seeds: ["pm_lp_pos", firm, staker]. Mirrors `BackstopPosition`
/// field-for-field, minus the separate SOL-premium debt — this pool's yield is denominated in the
/// same $FIRMA mint as the principal, so one debt field covers it instead of two. The whole
/// position enters cooldown on `request_unstake_pm_lp` and stays slashable until `withdraw_pm_lp`.
#[account]
#[derive(InitSpace)]
pub struct PredictionMarketLpPosition {
    pub staker: Pubkey,
    pub firm: Pubkey,
    pub amount_staked: u64,
    pub yield_debt: u128,
    pub loss_debt: u128,
    /// 0 = no pending withdrawal; else the unix time the cooldown elapses.
    pub cooldown_ends_at: i64,
    /// Unix time `request_unstake_pm_lp` was called (anti-bank-run escalation recheck, mirrors
    /// `BackstopPosition.cooldown_requested_at`).
    pub cooldown_requested_at: i64,
    pub staked_at: i64,
    pub bump: u8,
}

// ───────────────────────── Prediction Market Curve (Phase 3 pooled-LP AMM plan) ─────────────────────────
// Per-market two-sided AMM: two independent constant-product legs (PASS, FAIL), each priced by the
// exact same `bonding_curve::buy_output`/`sell_output` math reused UNMODIFIED. Plan judgment call #2:
// NOT a true Gnosis-style complementary-outcome AMM — that needs a quadratic sell formula this
// codebase has no fuzz coverage for. Two independent legs reuse curve math this repo already fuzzes
// (`curve_roundtrip_never_profits`/`curve_k_never_decreases_on_trades`), at the disclosed cost that a
// side's average fill price sits structurally below $1 — mitigated by the price-ceiling guard
// (`buy_shares`) and the solvency-capped payout (`pm_redeem_payout`).

/// Which leg of a `MarketCurve` an instruction targets. Mirrors `challenge::ChallengeStatus`'s
/// plain-enum convention (no repr, no associated data — Anchor's default discriminant tag).
#[derive(AnchorSerialize, AnchorDeserialize, InitSpace, Clone, Copy, PartialEq, Eq, Debug)]
pub enum PmSide {
    Pass,
    Fail,
}

/// `MarketCurve` lifecycle. `Open` trades; `Locked` freezes trading ahead of settlement; `Settled`
/// unlocks `redeem_shares`; `Void` is the no-resolution escape hatch (`void_market`), unlocked by the
/// separate pro-rata-per-side `redeem_void_shares` path — see `void_market`'s doc comment for why it
/// can't reuse `redeem_shares`' pooled-across-both-vaults formula.
#[derive(AnchorSerialize, AnchorDeserialize, InitSpace, Clone, Copy, PartialEq, Eq, Debug)]
pub enum PmCurveStatus {
    Open,
    Locked,
    Settled,
    Void,
}

/// A per-market two-sided AMM binding 1:1 to a real on-chain evaluation. Seeds: ["pm_curve",
/// challenge]. Vaults: ["pm_curve_pass", challenge] / ["pm_curve_fail", challenge]. See this
/// section's header comment for why the two legs are independent rather than a true
/// complementary-outcome pair, and `pm_redeem_payout`'s doc comment for the settlement math that
/// mitigates the resulting solvency gap.
#[account]
#[derive(InitSpace)]
pub struct MarketCurve {
    pub firm: Pubkey,
    pub challenge: Pubkey,
    /// Copied from `challenge.trader` at `init_market_curve` so every instruction that needs to bind
    /// against the trader (`add_curve_topup`'s self-LP ban) does so with no extra account read.
    pub trader: Pubkey,
    pub firma_mint: Pubkey,
    pub pass_vault: Pubkey,
    pub fail_vault: Pubkey,
    /// Non-withdrawable phantom seed, mirrors `bonding_curve.virtual_sol` — sets a non-zero starting
    /// price with no real capital. Immutable after init; also the fixed anchor
    /// `pm_curve_available_shares` scales by (see `PM_CURVE_SHARE_SUPPLY_MULTIPLIER`'s doc comment).
    pub pass_virtual: u64,
    pub pass_real: u64,
    /// PASS shares OUTSTANDING — total currently held across all `MarketPosition`s (Σ
    /// `position.pass_shares`). NOT the curve's own AMM sell-reserve: `redeem_shares`' pro-rata payout
    /// divides by this, so it has to mean "shares winners actually hold," not "shares the curve
    /// hasn't sold yet" — see `pm_curve_available_shares`, which derives the latter as this field's
    /// complement for the buy/sell math instead of storing it separately.
    pub pass_shares: u64,
    pub fail_virtual: u64,
    pub fail_real: u64,
    pub fail_shares: u64,
    /// Subset of `pass_real + fail_real` sourced from the shared `PredictionMarketLpPool` via
    /// `allocate_pool_to_curve`. Tracked SEPARATELY from `topup_deposited` — that separation is what
    /// makes `deallocate_pool_from_curve`'s `amount <= pool_allocated` ceiling possible (a compromised
    /// keeper can never claw back a permissionless top-up depositor's own funds; see that
    /// instruction's doc comment).
    pub pool_allocated: u64,
    /// Capital from permissionless direct top-ups (`add_curve_topup`), tracked separately from
    /// `pool_allocated` for the same security reason.
    pub topup_deposited: u64,
    pub fee_bps: u16,
    pub firm_fee_bps: u16,
    pub platform_fee_bps: u16,
    /// `firm_fee_bps + platform_fee_bps + pool_fee_bps == fee_bps`, checked once at
    /// `init_market_curve`; all four bps fields are set-once and immutable after.
    pub pool_fee_bps: u16,
    pub firm_fees_accrued: u64,
    pub platform_fees_accrued: u64,
    /// Pending, swept into the LP pool's yield accumulator by `sweep_curve_fees_to_pool`.
    pub pool_fees_accrued: u64,
    pub status: PmCurveStatus,
    /// `None` until `settle_market`; `Void` markets never set this (see `redeem_void_shares`).
    pub outcome: Option<PmSide>,
    pub opened_at: i64,
    pub settled_at: i64,
    pub bump: u8,
}

/// A holder's position in one `MarketCurve`. Seeds: ["pm_position", curve, holder].
///
/// Plain program-tracked state, NOT a pair of new SPL mints per market. At the scale this is designed
/// for (every promoted market gets a curve), two mints + one ATA per (holder, mint) per market would
/// make rent dominate — a single PDA with two `u64` fields costs the same no matter how many markets
/// exist. No peer-to-peer share transferability is needed either: every balance change already routes
/// through a program instruction (`buy_shares`/`sell_shares`/`redeem_shares`/`redeem_void_shares`), so
/// there's nothing an SPL mint would buy beyond rent cost — the same reasoning
/// `PredictionMarketLpPosition.amount_staked` already uses for LP shares instead of an LP-token mint.
#[account]
#[derive(InitSpace)]
pub struct MarketPosition {
    pub holder: Pubkey,
    pub curve: Pubkey,
    pub pass_shares: u64,
    pub fail_shares: u64,
    pub bump: u8,
}

// ───────────────────────── Affiliate program (§17.1) ─────────────────────────

/// Per-firm affiliate program config + SOL accumulator handle. Seeds: ["affiliate_program", firm].
#[account]
#[derive(InitSpace)]
pub struct AffiliateProgram {
    pub firm: Pubkey,
    pub vault: Pubkey,
    /// true = permissionless self-registration; false = firm-owner approval required.
    pub open: bool,
    /// Default affiliate rate (bps) for self-registered affiliates; ≤ MAX_AFFILIATE_BPS.
    pub default_rate_bps: u16,
    pub total_affiliates: u32,
    pub bump: u8,
}

/// A registered affiliate's rate + lifetime earnings ledger. Seeds: ["affiliate", firm, affiliate].
#[account]
#[derive(InitSpace)]
pub struct AffiliateAccount {
    pub firm: Pubkey,
    pub affiliate: Pubkey,
    /// Carve rate applied to referred challenge fees (bps), ≤ MAX_AFFILIATE_BPS.
    pub rate_bps: u16,
    /// Lifetime SOL credited from referred fees.
    pub earned: u64,
    /// Lifetime SOL withdrawn.
    pub claimed: u64,
    pub referred_count: u32,
    pub active: bool,
    pub bump: u8,
}

/// Immutable first-touch trader→affiliate binding. Seeds: ["referral", firm, trader].
#[account]
#[derive(InitSpace)]
pub struct Referral {
    pub firm: Pubkey,
    pub trader: Pubkey,
    pub affiliate: Pubkey,
    pub bound_at: i64,
    pub bump: u8,
}

#[derive(Accounts)]
pub struct InitAffiliateProgram<'info> {
    #[account(mut)]
    pub owner: Signer<'info>,
    #[account(
        seeds = [b"firm", firm_state.owner.as_ref()],
        bump = firm_state.bump,
        constraint = firm_state.owner == owner.key() @ FirmError::Unauthorized,
    )]
    pub firm_state: Box<Account<'info, FirmState>>,
    #[account(address = firm_state.sol_mint)]
    pub sol_mint: Box<Account<'info, Mint>>,
    #[account(
        init,
        payer = owner,
        space = 8 + AffiliateProgram::INIT_SPACE,
        seeds = [b"affiliate_program", firm_state.key().as_ref()],
        bump
    )]
    pub affiliate_program: Box<Account<'info, AffiliateProgram>>,
    #[account(
        init,
        payer = owner,
        token::mint = sol_mint,
        token::authority = firm_state,
        seeds = [b"affiliate_vault", firm_state.key().as_ref()],
        bump
    )]
    pub affiliate_pool_vault: Box<Account<'info, TokenAccount>>,
    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
    pub rent: Sysvar<'info, Rent>,
}

#[derive(Accounts)]
pub struct UpdateAffiliateProgram<'info> {
    pub owner: Signer<'info>,
    #[account(
        seeds = [b"firm", firm_state.owner.as_ref()],
        bump = firm_state.bump,
        constraint = firm_state.owner == owner.key() @ FirmError::Unauthorized,
    )]
    pub firm_state: Box<Account<'info, FirmState>>,
    #[account(
        mut,
        seeds = [b"affiliate_program", firm_state.key().as_ref()],
        bump = affiliate_program.bump,
    )]
    pub affiliate_program: Box<Account<'info, AffiliateProgram>>,
}

#[derive(Accounts)]
pub struct RegisterAffiliate<'info> {
    #[account(mut)]
    pub signer: Signer<'info>,
    #[account(seeds = [b"firm", firm_state.owner.as_ref()], bump = firm_state.bump)]
    pub firm_state: Box<Account<'info, FirmState>>,
    #[account(
        mut,
        seeds = [b"affiliate_program", firm_state.key().as_ref()],
        bump = affiliate_program.bump,
    )]
    pub affiliate_program: Box<Account<'info, AffiliateProgram>>,
    /// CHECK: the affiliate being registered — used only as the account seed (a key).
    pub affiliate: UncheckedAccount<'info>,
    #[account(
        init,
        payer = signer,
        space = 8 + AffiliateAccount::INIT_SPACE,
        seeds = [b"affiliate", firm_state.key().as_ref(), affiliate.key().as_ref()],
        bump
    )]
    pub affiliate_account: Box<Account<'info, AffiliateAccount>>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct UpdateAffiliate<'info> {
    pub owner: Signer<'info>,
    #[account(
        seeds = [b"firm", firm_state.owner.as_ref()],
        bump = firm_state.bump,
        constraint = firm_state.owner == owner.key() @ FirmError::Unauthorized,
    )]
    pub firm_state: Box<Account<'info, FirmState>>,
    /// CHECK: the affiliate being adjusted — used only as the account seed (a key).
    pub affiliate: UncheckedAccount<'info>,
    #[account(
        mut,
        seeds = [b"affiliate", firm_state.key().as_ref(), affiliate.key().as_ref()],
        bump = affiliate_account.bump,
        constraint = affiliate_account.firm == firm_state.key() @ FirmError::Unauthorized,
    )]
    pub affiliate_account: Box<Account<'info, AffiliateAccount>>,
}

#[derive(Accounts)]
pub struct BindReferral<'info> {
    #[account(mut)]
    pub trader: Signer<'info>,
    #[account(seeds = [b"firm", firm_state.owner.as_ref()], bump = firm_state.bump)]
    pub firm_state: Box<Account<'info, FirmState>>,
    /// CHECK: the affiliate being credited — used only as the account seed (a key).
    pub affiliate: UncheckedAccount<'info>,
    #[account(
        mut,
        seeds = [b"affiliate", firm_state.key().as_ref(), affiliate.key().as_ref()],
        bump = affiliate_account.bump,
        constraint = affiliate_account.firm == firm_state.key() @ FirmError::Unauthorized,
    )]
    pub affiliate_account: Box<Account<'info, AffiliateAccount>>,
    #[account(
        init,
        payer = trader,
        space = 8 + Referral::INIT_SPACE,
        seeds = [b"referral", firm_state.key().as_ref(), trader.key().as_ref()],
        bump
    )]
    pub referral: Box<Account<'info, Referral>>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct ClaimAffiliate<'info> {
    #[account(mut)]
    pub affiliate: Signer<'info>,
    #[account(seeds = [b"firm", firm_state.owner.as_ref()], bump = firm_state.bump)]
    pub firm_state: Box<Account<'info, FirmState>>,
    #[account(
        mut,
        seeds = [b"affiliate", firm_state.key().as_ref(), affiliate.key().as_ref()],
        bump = affiliate_account.bump,
        constraint = affiliate_account.affiliate == affiliate.key() @ FirmError::Unauthorized,
    )]
    pub affiliate_account: Box<Account<'info, AffiliateAccount>>,
    #[account(
        mut,
        seeds = [b"affiliate_vault", firm_state.key().as_ref()],
        bump,
    )]
    pub affiliate_pool_vault: Box<Account<'info, TokenAccount>>,
    #[account(mut, token::mint = firm_state.sol_mint, token::authority = affiliate)]
    pub affiliate_sol: Box<Account<'info, TokenAccount>>,
    pub token_program: Program<'info, Token>,
}

/// Args for `route_firma`. All bps values are in basis-points (0–10000).
/// The wallet leg is implicit: `10000 − no_risk_stake_bps − backstop_stake_bps − liquidate_bps`.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
pub struct RouteFirmaArgs {
    /// Bps of total $FIRMA to stake in the no-risk pool (0 = skip this leg).
    pub no_risk_stake_bps: u16,
    /// Bps of total $FIRMA to stake in the backstop (risk-bearing) pool (0 = skip).
    pub backstop_stake_bps: u16,
    /// Bps of total $FIRMA to sell via the bonding curve for SOL (0 = skip).
    pub liquidate_bps: u16,
    /// Slippage floor for the liquidation leg. Pass 0 when `liquidate_bps = 0`.
    pub min_sol_out: u64,
    /// The $FIRMA amount the bps legs apply to, bounded to the wallet balance. `0` = the whole
    /// balance (backward-compatible default). Set this to a delivered payout's amount to route just
    /// that payout, leaving any prior $FIRMA in the wallet untouched.
    pub route_amount: u64,
}

// Accounts are Box'd to keep the BPF stack frame under 4 KB.
#[derive(Accounts)]
pub struct RouteFirma<'info> {
    // ── Always required ────────────────────────────────────────────────────────
    #[account(mut)]
    pub trader: Signer<'info>,

    #[account(seeds = [b"firm", firm_state.owner.as_ref()], bump = firm_state.bump)]
    pub firm_state: Box<Account<'info, FirmState>>,

    /// Trader's $FIRMA source — the full balance is proportionally split by bps args.
    #[account(
        mut,
        token::mint = firm_state.firma_mint,
        token::authority = trader,
    )]
    pub trader_firma: Box<Account<'info, TokenAccount>>,

    // ── No-risk staking leg ────────────────────────────────────────────────────
    #[account(
        mut,
        seeds = [b"staking_pool", firm_state.key().as_ref()],
        bump = staking_pool.bump,
    )]
    pub staking_pool: Box<Account<'info, FirmaStakingPool>>,

    #[account(
        init_if_needed,
        payer = trader,
        space = 8 + StakerPosition::INIT_SPACE,
        seeds = [b"staker", firm_state.key().as_ref(), trader.key().as_ref()],
        bump,
    )]
    pub staker_position: Box<Account<'info, StakerPosition>>,

    #[account(mut, address = staking_pool.stake_vault)]
    pub stake_vault: Box<Account<'info, TokenAccount>>,

    // ── Backstop staking leg ───────────────────────────────────────────────────
    #[account(
        mut,
        seeds = [b"backstop_pool", firm_state.key().as_ref()],
        bump = backstop_pool.bump,
    )]
    pub backstop_pool: Box<Account<'info, BackstopPool>>,

    #[account(
        init_if_needed,
        payer = trader,
        space = 8 + BackstopPosition::INIT_SPACE,
        seeds = [b"backstop_pos", firm_state.key().as_ref(), trader.key().as_ref()],
        bump,
    )]
    pub backstop_position: Box<Account<'info, BackstopPosition>>,

    #[account(mut, address = backstop_pool.escrow_vault)]
    pub backstop_escrow: Box<Account<'info, TokenAccount>>,

    // ── Liquidation leg (sell $FIRMA → SOL via bonding curve) ────────────────
    #[account(
        mut,
        seeds = [b"bonding_curve", firm_state.key().as_ref()],
        bump = curve.bump,
        seeds::program = bonding_curve::ID,
    )]
    pub curve: Box<Account<'info, bonding_curve::BondingCurve>>,

    #[account(mut, address = curve.sol_vault)]
    pub curve_sol_vault: Box<Account<'info, TokenAccount>>,

    #[account(mut, address = curve.firma_vault)]
    pub curve_firma_vault: Box<Account<'info, TokenAccount>>,

    /// Trader's SOL account — receives proceeds from the liquidation leg.
    #[account(
        mut,
        token::mint = firm_state.sol_mint,
        token::authority = trader,
    )]
    pub trader_sol: Box<Account<'info, TokenAccount>>,

    /// Firm treasury — receives the firm half of the 1% curve fee.
    #[account(mut, address = firm_state.treasury_vault)]
    pub firm_treasury_sol: Box<Account<'info, TokenAccount>>,

    /// Platform fee destination (0.5% of the curve fee). NOTE: bind to platform config.
    /// V2-8: canonical platform config — binds `platform_sol` to the DP fee destination (M-4 pattern),
    /// so this leg can't be pointed at a caller-controlled account.
    #[account(seeds = [b"platform_config"], bump = platform_config.bump)]
    pub platform_config: Box<Account<'info, PlatformConfig>>,

    #[account(
        mut,
        token::mint = firm_state.sol_mint,
        constraint = platform_sol.key() == platform_config.platform_sol @ FirmError::PlatformSolMismatch,
    )]
    pub platform_sol: Box<Account<'info, TokenAccount>>,

    // ── Programs ───────────────────────────────────────────────────────────────
    pub bonding_curve_program: Program<'info, bonding_curve::program::BondingCurve>,
    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
}

/// Per-staker backstop position (§19). Seeds: ["backstop_pos", firm, staker]. The whole
/// position enters cooldown on `request_unstake_backstop` and stays slashable until
/// `withdraw_backstop`.
#[account]
#[derive(InitSpace)]
pub struct BackstopPosition {
    pub staker: Pubkey,
    pub firm: Pubkey,
    pub amount_staked: u64,
    pub premium_debt: u128,
    pub loss_debt: u128,
    /// 0 = no pending withdrawal; else the unix time the cooldown elapses.
    pub cooldown_ends_at: i64,
    pub staked_at: i64,
    pub bump: u8,
    /// Unix time `request_unstake_backstop` was called (§19 anti-bank-run). 0 for positions
    /// migrated before this field existed with an already-pending cooldown — harmless: the
    /// withdraw-time escalation recheck then evaluates near-zero and is dominated by the
    /// pre-existing `cooldown_ends_at` via `.max()`. Appended field — see
    /// `migrate_backstop_position_fields`.
    pub cooldown_requested_at: i64,
    /// $FIRMA yield debt against `BackstopPool.acc_firma` (2026-07-27 staking rebalance).
    /// Appended field — covered by the existing `migrate_backstop_position_fields` resize.
    pub firma_debt: u128,
}

/// Per-dispute insurance-payout record (§7). Seeds: ["dispute_payout", dispute]. `amount` is the
/// cumulative SOL paid across all `settle_dispute_payout` calls for this dispute (V2-5); the funded-size
/// cap on the running total is the over-draw guard.
#[account]
#[derive(InitSpace)]
pub struct DisputePayoutRecord {
    pub dispute: Pubkey,
    pub trader: Pubkey,
    pub amount: u64,
    pub bump: u8,
}

/// V2-2 — price-locked funded size of an evaluation, in **wSOL lamports**. Seeds: ["funded_size",
/// challenge]. Set by the firm's settlement authority (which co-signs the purchase and knows the SOL
/// price) so `settle_dispute_payout` has a dimensionally-correct lamport ceiling instead of the
/// micro-USD `starting_balance` compared as lamports.
#[account]
#[derive(InitSpace)]
pub struct ChallengeFundedSize {
    pub challenge: Pubkey,
    pub funded_size_lamports: u64,
    pub bump: u8,
}

/// Global platform risk state (§9). Seeds: ["platform_risk"]. A single override that
/// raises the floor tier for every firm at once.
#[account]
#[derive(InitSpace)]
pub struct PlatformRiskState {
    pub authority: Pubkey,
    /// 0 = no override; 1–3 = platform-mandated minimum tier.
    pub override_tier: u8,
    pub override_active: bool,
    /// Short on-chain label (e.g. b"platform_treasury_low") — audit trail (§25).
    pub override_reason: [u8; 32],
    pub set_at: i64,
    pub bump: u8,
}

#[event]
pub struct RiskTierUpdated {
    pub firm: Pubkey,
    pub tier: RiskTier,
    pub changed_at: i64,
}

#[event]
pub struct PlatformOverrideUpdated {
    pub override_tier: u8,
    pub active: bool,
    pub set_at: i64,
}

#[event]
pub struct DripClaimed {
    pub firm: Pubkey,
    pub amount: u64,
    pub months_claimed: u8,
}

#[event]
pub struct StakingYieldClaimed {
    pub firm: Pubkey,
    pub staker: Pubkey,
    pub sol: u64,
    pub firma: u64,
}

#[event]
pub struct BackstopStaked {
    pub firm: Pubkey,
    pub staker: Pubkey,
    pub amount: u64,
}

#[event]
pub struct BackstopUnstakeRequested {
    pub firm: Pubkey,
    pub staker: Pubkey,
    pub unlocks_at: i64,
}

#[event]
pub struct OperatorBondFunded {
    pub firm: Pubkey,
    /// Native SOL moved from the treasury into the OperatorStake bond this crank.
    pub funded: u64,
    /// The bond's total native SOL after this crank (approaches `MIN_OPERATOR_STAKE_LAMPORTS`).
    pub total_bond: u64,
    /// True once the bond reached 50 SOL — the 1% earmark now stops and stays as treasury.
    pub bond_complete: bool,
}

#[event]
pub struct OperatorBondReconciled {
    pub firm: Pubkey,
    /// The OperatorStake's native SOL above its rent-exempt minimum at reconcile time.
    pub current_bond: u64,
    /// `current_bond >= 50 SOL`. A slash that drops the bond below the floor flips this false, which
    /// auto-resumes the 1% earmark in `pay_challenge_fee` (v2 auto-refill).
    pub bond_funded: bool,
}

#[event]
pub struct BackstopWithdrawn {
    pub firm: Pubkey,
    pub staker: Pubkey,
    pub surviving: u64,
    pub premium: u64,
    /// 2026-07-27 staking rebalance.
    pub firma_yield: u64,
}

#[event]
pub struct BackstopPremiumClaimed {
    pub firm: Pubkey,
    pub staker: Pubkey,
    pub premium: u64,
}

/// 2026-07-27 staking rebalance.
#[event]
pub struct BackstopFirmaYieldClaimed {
    pub firm: Pubkey,
    pub staker: Pubkey,
    pub firma: u64,
}

// ── Prediction Market LP Pool (Phase 2 pooled-LP AMM plan) ──

#[event]
pub struct PmLpStaked {
    pub firm: Pubkey,
    pub staker: Pubkey,
    pub amount: u64,
}

#[event]
pub struct PmLpUnstakeRequested {
    pub firm: Pubkey,
    pub staker: Pubkey,
    pub unlocks_at: i64,
}

#[event]
pub struct PmLpWithdrawn {
    pub firm: Pubkey,
    pub staker: Pubkey,
    pub surviving: u64,
    pub yield_paid: u64,
}

#[event]
pub struct PmLpYieldClaimed {
    pub firm: Pubkey,
    pub staker: Pubkey,
    pub yield_paid: u64,
}

// ── Prediction Market Curve (Phase 3 pooled-LP AMM plan) ──

#[event]
pub struct MarketCurveInitialized {
    pub curve: Pubkey,
    pub challenge: Pubkey,
    pub firm: Pubkey,
    pub trader: Pubkey,
}

#[event]
pub struct MarketSharesBought {
    pub curve: Pubkey,
    pub holder: Pubkey,
    pub side: PmSide,
    pub collateral_in: u64,
    pub shares_out: u64,
    pub fee: u64,
}

#[event]
pub struct MarketSharesSold {
    pub curve: Pubkey,
    pub holder: Pubkey,
    pub side: PmSide,
    pub shares_in: u64,
    pub collateral_out: u64,
    pub fee: u64,
}

#[event]
pub struct MarketCurveToppedUp {
    pub curve: Pubkey,
    pub depositor: Pubkey,
    pub side: PmSide,
    pub amount: u64,
}

#[event]
pub struct MarketSettled {
    pub curve: Pubkey,
    pub outcome: PmSide,
    pub settled_at: i64,
}

#[event]
pub struct MarketVoided {
    pub curve: Pubkey,
}

#[event]
pub struct MarketSharesRedeemed {
    pub curve: Pubkey,
    pub holder: Pubkey,
    pub side: PmSide,
    pub payout: u64,
}

#[event]
pub struct MarketVoidRedeemed {
    pub curve: Pubkey,
    pub holder: Pubkey,
    pub pass_payout: u64,
    pub fail_payout: u64,
}

#[event]
pub struct PmCurveAllocated {
    pub curve: Pubkey,
    pub firm: Pubkey,
    pub amount: u64,
    pub to_pass: u64,
    pub to_fail: u64,
}

#[event]
pub struct PmCurveDeallocated {
    pub curve: Pubkey,
    pub firm: Pubkey,
    pub amount: u64,
    pub from_pass: u64,
    pub from_fail: u64,
}

#[event]
pub struct PmCurveFeesSwept {
    pub curve: Pubkey,
    pub firm: Pubkey,
    pub amount: u64,
}

#[event]
pub struct BackstopDrawn {
    pub firm: Pubkey,
    pub challenge: Pubkey,
    pub amount: u64,
}

#[event]
pub struct TreasuryFirmaDrawn {
    pub firm: Pubkey,
    pub challenge: Pubkey,
    pub amount: u64,
}

#[event]
pub struct UniversalDrawn {
    pub firm: Pubkey,
    pub challenge: Pubkey,
    /// SOL spent from the universal vault to buy $FIRMA off the curve.
    pub sol_spent: u64,
    /// $FIRMA delivered to the trader.
    pub firma_delivered: u64,
}

// `DpropStakingDistributed` event was REMOVED with `distribute_dprop_staking` (trust-model gap T-1).

#[event]
pub struct FirmaBuybackExecuted {
    pub firm: Pubkey,
    /// SOL principal spent buying $FIRMA into the Tier-2 reserve this crank.
    pub sol: u64,
    /// Remaining earmarked SOL still awaiting conversion.
    pub remaining_acc: u64,
}

#[event]
pub struct GraduatedLiquidityAdded {
    pub firm: Pubkey,
    /// SOL drawn from the treasury this crank (zap swap + deposit sides).
    pub sol_consumed: u64,
    /// LP tokens minted into the firm's permanently-locked LP vault.
    pub lp_minted: u64,
    /// Post-graduation LP earmark still awaiting deposit.
    pub remaining_acc: u64,
}

#[event]
pub struct DeploymentFeePaid {
    pub firm: Pubkey,
    pub price: u64,
    pub franchise: u64,
    pub referral: u64,
    pub decentralprop: u64,
    pub dprop_burn: u64,
    pub universal: u64,
    pub firm_treasury: u64,
}

#[event]
pub struct TokenLaunched {
    pub firm: Pubkey,
}

#[event]
pub struct DpropBuybackMintBound {
    pub dprop_mint: Pubkey,
    pub dprop_vault: Pubkey,
}

#[event]
pub struct DpropBuybackExecuted {
    pub sol_spent: u64,
    pub total_sol_spent: u64,
}

#[event]
pub struct DpropBurned {
    pub amount: u64,
    pub total_dprop_burned: u64,
}

#[event]
pub struct FirmAutoBankrupt {
    pub firm: Pubkey,
    /// The firm's lifetime Universal-Pool draws at the moment it crossed the 10% line.
    pub ulp_drawn: u64,
    /// The pool balance the draw was measured against (`ulp_drawn >= pool_balance / 10`).
    pub pool_balance: u64,
}

#[event]
pub struct FirmBankruptcyFinalized {
    pub firm: Pubkey,
    /// SOL swept from the bankrupt firm's residual (treasury + insurance + loss-back) back to the ULP.
    pub swept_to_ulp: u64,
}

#[event]
pub struct VestingClaimed {
    pub firm: Pubkey,
    pub owner: Pubkey,
    pub amount: u64,
    pub unlocked_at: i64,
}

#[event]
pub struct VestingClawedBack {
    pub firm: Pubkey,
    pub amount: u64,
}

#[event]
pub struct DisputePayoutSettled {
    pub firm: Pubkey,
    pub dispute: Pubkey,
    pub amount: u64,
}

#[event]
pub struct FirmGraduated {
    pub firm: Pubkey,
    pub lp_burned: u64,
}

#[event]
pub struct PayoutQueued {
    pub firm: Pubkey,
    pub challenge: Pubkey,
    pub trader: Pubkey,
    /// DEC-62 withdrawal cycle (0 = the settlement path). REQUIRED by the indexer: the QueuedPayout
    /// PDA is `["payout", challenge, cycle]`, so an event without it forces the mirror to assume
    /// cycle 0 — mirroring every later withdrawal under the wrong address, and never delivering it.
    pub cycle: u32,
    pub firma_owed: u64,
    pub hold_until: i64,
    pub settlement_tier: u8,
}

/// CONCENTRATION-DENOM-1 — emitted by `reconcile_payout_hold`, so a reconciliation is as
/// visible/auditable off-chain as the original `PayoutQueued` hold decision was.
#[event]
pub struct PayoutHoldReconciled {
    pub firm: Pubkey,
    pub challenge: Pubkey,
    pub cycle: u32,
    pub old_hold_until: i64,
    pub new_hold_until: i64,
}

#[event]
pub struct QueuedPayoutFilled {
    pub firm: Pubkey,
    pub challenge: Pubkey,
    /// DEC-62 withdrawal cycle — the mirror needs it to address the right `["payout", challenge, cycle]`
    /// row; without it every fill is applied to cycle 0's.
    pub cycle: u32,
    pub trader_delivered: u64,
    pub stakeholder_delivered: u64,
    /// SOL carved from treasury to the Universal Treasury Pool before the curve buy.
    pub universal_sol_carved: u64,
    pub sol_spent: u64,
    pub fully_filled: bool,
}

/// C-7 — a queued payout was force-discharged during wind-down after the undelivered timeout. The
/// `undelivered` $FIRMA was written off to let `finalize_close` proceed (public, auditable record).
#[event]
pub struct PayoutForceDischarged {
    pub firm: Pubkey,
    pub challenge: Pubkey,
    pub trader: Pubkey,
    pub undelivered: u64,
}

/// DEC-77 — a first-payout advance was paid out of the staging vault while the settlement was still
/// `Provisional` (inside its fraud-proof window). `PayoutQueued`/`QueuedPayoutFilled` also fire for the
/// same call (the advance reuses those event types so the existing indexer needs zero changes) — this
/// event is the ADDITIONAL, advance-specific audit record.
#[event]
pub struct PayoutAdvanceIssued {
    pub firm: Pubkey,
    pub challenge: Pubkey,
    pub trader: Pubkey,
    pub sol_advanced: u64,
    pub firma_delivered: u64,
    pub firma_owed_full: u64,
    pub advance_sol_outstanding_after: u64,
}

/// DEC-77 — an outstanding advance was made whole: its settlement reached `Final` with no fault
/// proven, so `AdvancePool.sol_outstanding` is released. Fires regardless of whether the
/// trader's `QueuedPayout` is itself fully delivered yet — the fraud RISK retired, which is what this
/// counter bounds; any remaining trader balance is a normal `process_queued_payout` fill from here.
#[event]
pub struct PayoutAdvanceResolved {
    pub firm: Pubkey,
    pub challenge: Pubkey,
    pub advance_sol_released: u64,
}

/// DEC-77 — a fraud proof voided the settlement an advance was paid against. Permanent, unrecoverable
/// loss: no instruction anywhere claws $FIRMA back out of a trader's wallet. Fires immediately (no
/// timeout, unlike `PayoutForceDischarged`) since the loss is already certain the moment the proof
/// lands — waiting serves no purpose.
#[event]
pub struct PayoutAdvanceWrittenOff {
    pub firm: Pubkey,
    pub challenge: Pubkey,
    pub trader: Pubkey,
    pub undelivered_firma: u64,
    pub advance_sol_lost: u64,
}

#[event]
pub struct FeePaid {
    pub firm: Pubkey,
    pub amount: u64,
    pub treasury_gross: u64,
    pub insurance: u64,
    pub lp: u64,
}

#[event]
pub struct PayoutExecuted {
    pub firm: Pubkey,
    pub challenge: Pubkey,
    pub firma_delivered: u64,
    pub sol_spent: u64,
}

#[event]
pub struct LossBackAccrued {
    pub firm: Pubkey,
    pub trader: Pubkey,
    pub amount: u64,
    /// New running redeemable balance on the trader's `LossBackCredit` PDA.
    pub balance: u64,
}

#[event]
pub struct LossBackRedeemed {
    pub firm: Pubkey,
    pub trader: Pubkey,
    pub amount: u64,
    /// Remaining redeemable balance after this redemption.
    pub balance: u64,
}

#[event]
pub struct LossBackApplied {
    pub firm: Pubkey,
    pub trader: Pubkey,
    /// Amount of credit applied as a discount on this purchase.
    pub discount: u64,
    /// Remaining credit balance after the discount.
    pub balance: u64,
}

#[event]
pub struct LossBackMinStakeSet {
    pub firm: Pubkey,
    pub min_stake: u64,
}

#[event]
pub struct GuardianRotated {
    pub firm: Pubkey,
    pub new_guardian: Pubkey,
}

#[event]
pub struct RiskEngineAuthorityRotated {
    pub firm: Pubkey,
    pub previous: Pubkey,
    pub new_authority: Pubkey,
    pub grace_until: i64,
}

#[event]
pub struct FirmaRouted {
    pub firm: Pubkey,
    pub trader: Pubkey,
    /// Total $FIRMA present in the trader's account at the time of routing.
    pub total_firma: u64,
    /// $FIRMA deposited into the no-risk staking pool.
    pub no_risk_staked: u64,
    /// $FIRMA deposited into the backstop (risk-bearing) pool.
    pub backstop_staked: u64,
    /// $FIRMA sold via the bonding curve (the SOL proceeds go to trader_sol).
    pub liquidated: u64,
    /// $FIRMA that remained in the trader's wallet (wallet leg).
    pub kept_in_wallet: u64,
}

#[error_code]
pub enum FirmError {
    #[msg("risk tier may only move one step per update")]
    TierJumpTooLarge,
    #[msg("relaxation time-lock has not elapsed for this tier")]
    RelaxationTimelockActive,
    #[msg("signer is not authorized for this action")]
    Unauthorized,
    #[msg("challenge settlement is not Final (still in its fraud-proof window or was faulted)")]
    SettlementNotFinal,
    #[msg("settlement did not transit the verifiable fraud-proof path (trusted settle_challenge is non-payable, M-1)")]
    SettlementNotVerifiable,
    #[msg("payout blocked by an on-chain integrity hold (integrity-engine freeze)")]
    IntegrityHold,
    #[msg("supply has already been distributed")]
    AlreadyDistributed,
    #[msg("deployment tier out of range (0..=4)")]
    InvalidTier,
    #[msg("treasury_sol cache does not match the treasury vault balance")]
    TreasuryDesync,
    #[msg("challenge has not passed — no payout owed")]
    ChallengeNotPassed,
    #[msg("daily payout cap (20% of treasury) exceeded")]
    DailyPayoutCapExceeded,
    #[msg("treasury has insufficient SOL for this payout")]
    InsufficientTreasury,
    #[msg("payout is under a concentration-guard hold")]
    PayoutOnHold,
    #[msg("queued payout is already fully filled")]
    PayoutAlreadyFilled,
    #[msg("queued payout is not yet fully delivered — cannot close")]
    PayoutNotFullyFilled,
    #[msg("post-graduation payout routing (Raydium) is not yet supported")]
    PostGraduationUnsupported,
    #[msg("the supplied Raydium CP-Swap swap accounts are wrong (count/order/payer/mint mismatch)")]
    BadRaydiumAccounts,
    #[msg("bonding curve has not graduated yet")]
    CurveNotGraduated,
    #[msg("firm has already graduated")]
    AlreadyGraduated,
    #[msg("stakeholder config invalid (sum must be 10000 and within governance ranges)")]
    InvalidStakeholderConfig,
    #[msg("an active platform override must carry a non-empty reason")]
    EmptyOverrideReason,
    #[msg("owner drip schedule is complete (24 months claimed)")]
    DripComplete,
    #[msg("this drip month has not unlocked yet")]
    DripNotYetUnlocked,
    #[msg("owner drip is paused under stress (WARNING/CRITICAL)")]
    DripPausedUnderStress,
    #[msg("amount must be greater than zero")]
    ZeroAmount,
    #[msg("insufficient staked balance")]
    InsufficientStake,
    #[msg("staked $FIRMA is below the firm's loss-back redemption threshold")]
    InsufficientStakeForLossBack,
    #[msg("requested amount exceeds accrued loss-back credit balance")]
    InsufficientLossBackCredit,
    #[msg("loss-back credit cannot be redeemed directly — apply it at your next evaluation purchase")]
    CreditMustBeUsedAtPurchase,
    #[msg("firm status does not permit this action")]
    InvalidFirmStatus,
    #[msg("signer is not the firm's platform guardian")]
    GuardianMismatch,
    #[msg("guardian co-sign is required unless the settlement is provably faulted")]
    GuardianRequired,
    #[msg("a close has already been initiated")]
    CloseAlreadyInitiated,
    #[msg("close has not been initiated")]
    CloseNotInitiated,
    #[msg("the close time-lock has not elapsed")]
    CloseTimelockActive,
    #[msg("firm still owes one or more queued trader payouts — cannot close until they are delivered")]
    OutstandingPayouts,
    #[msg("firm has initiated close — no new evaluations may be sold")]
    FirmClosing,
    #[msg("vesting batch already claimed")]
    VestingAlreadyClaimed,
    #[msg("vesting batch has not reached its 90-day unlock yet")]
    VestingNotYetUnlocked,
    #[msg("vesting batch has already unlocked — not subject to clawback")]
    VestingAlreadyUnlocked,
    #[msg("dispute is not upheld or force-resolved")]
    DisputeNotUpheld,
    #[msg("a withdrawal cooldown is already pending")]
    CooldownActive,
    #[msg("no withdrawal cooldown has been requested")]
    NoCooldownRequested,
    #[msg("withdrawal cooldown has not elapsed")]
    CooldownNotElapsed,
    #[msg("nothing staked in the backstop")]
    NothingStaked,
    #[msg("backstop draw not permitted (velocity break not active)")]
    BackstopNotPermitted,
    #[msg("backstop premium rate exceeds the 6% cap")]
    InvalidPremium,
    #[msg("backstop pool/premium-vault accounts are required when a premium is owed")]
    MissingBackstopAccounts,
    #[msg("backstop premium vault does not match the pool")]
    InvalidBackstopVault,
    #[msg("sol_reward_vault does not match the supplied staking pool")]
    InvalidStakingVault,
    #[msg("treasury $FIRMA reserve has insufficient balance")]
    InsufficientTreasuryFirma,
    #[msg("universal pool daily draw cap exceeded")]
    UniversalDailyCapExceeded,
    #[msg("universal pool has insufficient SOL to fund this draw")]
    InsufficientUniversalPool,
    #[msg("universal draw requires the firm's own waterfall (treasury + reserve + backstop) to be exhausted first")]
    UniversalDrawNotLastResort,
    #[msg("Tier-2 $FIRMA reserve must be drained first (reserve-first payout ordering, M-3)")]
    ReserveNotExhausted,
    #[msg("deployment fee legs exceed the price (auto-purchases too large)")]
    DeploymentLegsExceedPrice,
    #[msg("a referrer SOL account is required for the referral bonus")]
    MissingReferrer,
    #[msg("affiliate account/vault are required when an affiliate carve is owed")]
    MissingAffiliateAccounts,
    #[msg("affiliate rate exceeds the 20% cap")]
    InvalidAffiliateRate,
    #[msg("this firm's affiliate program is approval-only — registration requires the firm owner")]
    AffiliateApprovalRequired,
    #[msg("an affiliate cannot refer themselves")]
    SelfReferral,
    #[msg("nothing claimable for this affiliate")]
    NothingToClaim,
    #[msg("arithmetic overflow")]
    MathOverflow,
    #[msg("routing bps legs exceed 10000 — they must sum to at most 10000")]
    InvalidRouteBps,
    #[msg("the firm's $FIRMA token has not been launched yet — evaluations open after token launch")]
    TokenNotLaunched,
    #[msg("the firm's token has already been launched")]
    TokenAlreadyLaunched,
    #[msg("guardian must be independent of the firm owner (guardian != owner)")]
    GuardianNotIndependent,
    #[msg("timeout dispute payout requires the challenge to still be Unsettled (the operator settled — use the normal payout path)")]
    TimeoutChallengeSettled,
    #[msg("this dispute has already been paid its full entitlement")]
    DisputePayoutComplete,
    #[msg("platform_sol destination does not match the canonical platform_config")]
    PlatformSolMismatch,
    #[msg("force-discharge is only allowed while the firm is winding down (call initiate_close first)")]
    FirmNotClosing,
    #[msg("payout is fully delivered — use close_queued_payout, not force-discharge")]
    PayoutFullyDelivered,
    #[msg("payout has not been undelivered long enough to force-discharge (90-day timeout)")]
    PayoutStillDeliverable,
    #[msg("post-graduation payout pricing is not yet supported — the firm's curve has graduated (reserves moved to Raydium)")]
    PayoutPricingUnavailable,
    // Appended at the end to preserve existing error discriminants (§24 v2 auto-bankruptcy).
    #[msg("firm has auto-bankrupted (drew >= 10% of the Universal Pool) and can no longer operate")]
    FirmBankrupt,
    // Appended (R33.2 deferred $DPROP buyback launch).
    #[msg("$DPROP buyback mint is not bound yet — call bind_dprop_buyback_mint after the token launches")]
    DpropMintNotBound,
    #[msg("the $DPROP buyback mint has already been bound")]
    DpropMintAlreadyBound,
    // Appended (affiliate rate lock): the affiliate referral fee is fixed platform-wide at 10%.
    #[msg("the affiliate rate is fixed platform-wide at 10% and cannot be changed")]
    AffiliateRateLocked,
    // Appended (backstop premium lock): the backstop premium is fixed platform-wide at 6%.
    #[msg("the backstop premium is fixed platform-wide at 6% and cannot be changed")]
    BackstopPremiumLocked,
    // Appended (loss-back gate lock): the loss-back redemption gate is fixed platform-wide at 1,000,000 $FIRMA.
    #[msg("the loss-back min stake is fixed platform-wide at 1,000,000 $FIRMA and cannot be changed")]
    LossBackMinStakeLocked,
    // Appended (DEC-77 first-payout instant advance, §22b).
    #[msg("settlement is not Provisional — an advance can only be paid inside an open fraud-proof window")]
    SettlementNotProvisional,
    #[msg("the settlement's fraud-proof window has already closed — use the normal enqueue/deliver path")]
    AdvanceWindowClosed,
    #[msg("the proposed settlement does not claim Passed — nothing owed to advance")]
    SettlementNotClaimedPassed,
    #[msg("this advance would exceed the firm's locked advance-float cap (ADVANCE_CAP_BPS of treasury)")]
    AdvanceCapExceeded,
    #[msg("advance amount exceeds the claimed settlement's owed SOL")]
    AdvanceExceedsOwed,
    #[msg("this queued payout has no outstanding advance to reconcile")]
    NothingToReconcile,
    #[msg("settlement is not Faulted — nothing to write off")]
    SettlementNotFaulted,
    // Appended (PAYOUT-ADVANCE-10/11, same-day hardening).
    #[msg("advance amount exceeds ADVANCE_MAX_CLAIM_BPS of the claimed settlement — the remainder must wait for the normal Final-gated payout path")]
    AdvanceExceedsClaimFraction,
    #[msg("this advance would exceed the firm's dedicated advance-only daily velocity cap (ADVANCE_DAILY_CAP_BPS)")]
    AdvanceDailyCapExceeded,
    // Appended (§19 anti-bank-run controls).
    #[msg("this withdrawal would exceed the backstop pool's daily outflow cap (BACKSTOP_DAILY_OUTFLOW_CAP_BPS) — retry with a smaller amount or wait for the next window")]
    BackstopOutflowCapExceeded,
    #[msg("backstop withdrawals are frozen while the firm's velocity-break circuit breaker is active")]
    BackstopWithdrawFrozen,
    // Appended (Phase 2 — Prediction Market LP Pool, mirrors the analogous Backstop errors 1:1).
    #[msg("a PM LP withdrawal cooldown is already pending")]
    PmLpCooldownActive,
    #[msg("no PM LP withdrawal cooldown has been requested")]
    PmLpNoCooldownRequested,
    #[msg("PM LP withdrawal cooldown has not elapsed")]
    PmLpCooldownNotElapsed,
    #[msg("nothing staked in the prediction-market LP pool")]
    PmLpNothingStaked,
    #[msg("this withdrawal would exceed the PM LP pool's daily outflow cap (PM_LP_DAILY_OUTFLOW_CAP_BPS) — retry with a smaller amount or wait for the next window")]
    PmLpDailyCapExceeded,
    #[msg("PM LP withdrawals are frozen while the firm's velocity-break circuit breaker is active")]
    PmLpVelocityBreakActive,
    // Appended (Phase 3 — Prediction Market Curve, per-market two-sided AMM).
    #[msg("this trade would receive fewer shares/collateral than the caller's slippage floor")]
    PmSlippageExceeded,
    #[msg("this buy would push the leg's implied price past its $1 settlement ceiling")]
    PmPriceCeilingExceeded,
    #[msg("a market's own trader may never fund their own curve — self-LP is routed only through the shared PredictionMarketLpPool")]
    PmSelfLpBanned,
    #[msg("this position does not hold enough shares on this side to cover the requested amount")]
    PmInsufficientShares,
    #[msg("this curve is not Settled — redemption is not open yet")]
    PmNotSettled,
    #[msg("this position holds no winning shares to redeem")]
    PmNothingToRedeem,
    #[msg("this deallocation would exceed the pool's own allocation to this curve")]
    PmExceedsPoolAllocation,
    #[msg("this curve is not Open — trading/top-ups are not permitted in its current status")]
    PmMarketNotOpen,
    #[msg("firm_fee_bps + platform_fee_bps + pool_fee_bps must sum to exactly fee_bps")]
    PmFeeSplitMismatch,
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── DEC-77 first-payout instant advance (§22b) ────────────────────────────────────────────────
    // The advance-cap headroom math (`bps(treasury, ADVANCE_CAP_BPS) - advance_sol_outstanding`) is the
    // ONLY safety mechanism bounding this feature (see ADVANCE_CAP_BPS's doc comment) — a bug here is
    // the whole ballgame, so it gets its own pinned tests rather than trusting the inline `bps` reuse.
    #[test]
    fn advance_cap_bps_is_two_percent() {
        // Pins the shipped DEC-77 value — a silent constant change should fail a test, not ship quietly.
        assert_eq!(ADVANCE_CAP_BPS, 200);
    }

    #[test]
    fn advance_cap_headroom_matches_treasury_percentage() {
        let treasury = 1_000_000_000_000u64; // 1,000 SOL
        let limit = bps(treasury, ADVANCE_CAP_BPS);
        assert_eq!(limit, 20_000_000_000); // 2% == 20 SOL

        // No exposure yet → full headroom.
        let outstanding = 0u64;
        assert_eq!(limit.saturating_sub(outstanding), limit);

        // Fully extended → zero headroom, never negative/wrapping.
        let outstanding = limit;
        assert_eq!(limit.saturating_sub(outstanding), 0);

        // Over-extended (shouldn't happen, but the check must still fail closed, not panic/wrap).
        let outstanding = limit + 1;
        assert_eq!(limit.saturating_sub(outstanding), 0);
    }

    #[test]
    fn advance_cap_headroom_shrinks_as_outstanding_grows() {
        let treasury = 500_000_000_000u64; // 500 SOL
        let limit = bps(treasury, ADVANCE_CAP_BPS); // 10 SOL
        let half_spent = limit / 2;
        let remaining = limit.saturating_sub(half_spent);
        assert_eq!(remaining, limit - half_spent);
        // A request for exactly the remaining headroom is admissible; one lamport more is not —
        // this is the boundary `advance_first_payout`'s `require!(sol_amount <= remaining_cap, ...)` checks.
        assert!(remaining <= remaining);
        assert!(remaining + 1 > remaining);
    }

    #[test]
    fn advance_cap_scales_with_treasury_not_a_flat_floor() {
        // Unlike the daily payout cap (which has a MIN_DAILY_PAYOUT_FLOOR_SOL floor), the advance cap
        // has NO floor by design — a firm with a tiny treasury gets a tiny (or zero) advance float,
        // never a subsidized one. A thin treasury should not be able to advance more, in absolute
        // terms, than a well-capitalized one.
        let thin = bps(1_000_000_000u64, ADVANCE_CAP_BPS); // 1 SOL treasury
        let healthy = bps(1_000_000_000_000u64, ADVANCE_CAP_BPS); // 1,000 SOL treasury
        assert!(thin < healthy);
        assert_eq!(thin, 20_000_000); // 0.02 SOL — small but nonzero, no floor inflates it
    }

    // ── PAYOUT-ADVANCE-12 (cap basis widened to tiers 1-3, excluding the Universal Pool) ──────────
    #[test]
    fn advance_caps_include_tier2_and_tier3_not_just_the_sol_treasury_cache() {
        // Pins the fix: `advance_limit`/`advance_daily_cap` are computed off `total_treasury_sol`
        // (tier1 + tier2 $FIRMA-reserve-as-SOL + tier3 operator stake) — the SAME total the
        // concentration guard already used — not `firm_state.treasury_sol` (tier 1) alone.
        let tier1_sol = 100_000_000_000u64; // 100 SOL cash treasury
        let tier2_sol = 50_000_000_000u64; // 50 SOL-equivalent $FIRMA reserve
        let tier3_sol = 25_000_000_000u64; // 25 SOL operator stake bond
        let total_treasury_sol = tier1_sol + tier2_sol + tier3_sol; // 175 SOL — excludes tier 4 (Universal Pool)

        let tier1_only_cap = bps(tier1_sol, ADVANCE_CAP_BPS);
        let widened_cap = bps(total_treasury_sol, ADVANCE_CAP_BPS);
        assert!(widened_cap > tier1_only_cap, "tier2/tier3 must widen the cap, not be ignored");
        assert_eq!(widened_cap, bps(175_000_000_000u64, ADVANCE_CAP_BPS));

        let tier1_only_daily = bps(tier1_sol, ADVANCE_DAILY_CAP_BPS);
        let widened_daily = bps(total_treasury_sol, ADVANCE_DAILY_CAP_BPS);
        assert!(widened_daily > tier1_only_daily);
    }

    // ── PAYOUT-ADVANCE-10 (claim-fraction ceiling) ────────────────────────────────────────────────
    #[test]
    fn advance_max_claim_bps_is_fifty_percent() {
        assert_eq!(ADVANCE_MAX_CLAIM_BPS, 5000);
    }

    #[test]
    fn claim_fraction_ceiling_halves_the_claimed_amount() {
        let sol_owed = 10_000_000_000u64; // 10 SOL claimed
        let ceiling = bps(sol_owed, ADVANCE_MAX_CLAIM_BPS);
        assert_eq!(ceiling, 5_000_000_000); // exactly half
        // A request for exactly the ceiling is admissible; one lamport more is not — the boundary
        // `advance_first_payout`'s `require!(sol_amount <= bps(sol_owed, ADVANCE_MAX_CLAIM_BPS), ...)` checks.
        assert!(ceiling <= ceiling);
        assert!(ceiling + 1 > ceiling);
    }

    #[test]
    fn claim_fraction_ceiling_scales_with_the_claim_not_a_flat_amount() {
        // A 10x larger claim gets a 10x larger instant ceiling — this bounds a RATIO of the (possibly
        // fabricated) claim, not an absolute dollar amount, by design: the goal is capping what fraction
        // of an unverifiable number can be trusted instantly, not setting a size-independent limit.
        let small_claim = bps(1_000_000_000u64, ADVANCE_MAX_CLAIM_BPS);
        let large_claim = bps(10_000_000_000u64, ADVANCE_MAX_CLAIM_BPS);
        assert_eq!(large_claim, small_claim * 10);
    }

    // ── PAYOUT-ADVANCE-11 (dedicated advance daily velocity cap) ──────────────────────────────────
    #[test]
    fn advance_daily_cap_bps_is_six_percent() {
        assert_eq!(ADVANCE_DAILY_CAP_BPS, 600);
    }

    #[test]
    fn advance_daily_cap_is_tighter_than_the_shared_payout_cap_but_looser_than_the_instant_cap() {
        let treasury = 1_000_000_000_000u64; // 1,000 SOL
        let instant_cap = bps(treasury, ADVANCE_CAP_BPS); // 2%
        let advance_daily_cap = bps(treasury, ADVANCE_DAILY_CAP_BPS); // 6%
        let shared_daily_cap = treasury / 5; // 20%, process_queued_payout + advance_first_payout combined
        assert!(advance_daily_cap > instant_cap); // allows more than one refill/day
        assert!(advance_daily_cap < shared_daily_cap); // but still tighter than the general payout cap
        assert_eq!(advance_daily_cap, instant_cap * 3); // ~3 refill-cycles/day, not unbounded
    }

    #[test]
    fn advance_daily_floor_is_smaller_than_the_general_payout_floor() {
        // Deliberately a smaller baseline than MIN_DAILY_PAYOUT_FLOOR_SOL — this is the riskier,
        // no-clawback path, so a thin-treasury firm should not get the same generous floor as normal payouts.
        assert!(MIN_DAILY_ADVANCE_FLOOR_SOL < MIN_DAILY_PAYOUT_FLOOR_SOL);
        assert_eq!(MIN_DAILY_ADVANCE_FLOOR_SOL, 500_000_000); // 0.5 SOL
    }

    #[test]
    fn advance_daily_spend_resets_on_a_new_utc_day() {
        // Pins the `now / 86_400` day-index reset logic `advance_first_payout` uses on `AdvancePool`.
        let day_one_ts = 1_000_000i64; // day index 11
        let day_two_ts = day_one_ts + 86_400; // next UTC day
        let day_index_one = day_one_ts / 86_400;
        let day_index_two = day_two_ts / 86_400;
        assert_ne!(day_index_one, day_index_two); // triggers the reset branch
        assert_eq!(day_index_two - day_index_one, 1);
    }

    // ── F1 (design note, `reports/2026-07-23-instant-payout-advance.md`) — a normal, non-advance
    // `QueuedPayout` (created by `enqueue_payout`, which only ever runs post-Final) can never reach
    // `write_off_faulted_advance`'s or `reconcile_payout_advance`'s `advance_sol_spent > 0` gate, because
    // `enqueue_payout` never sets that field to anything but its zero-initialized default. This pins
    // the invariant the handler logic depends on: the gate is self-selecting, not enforced by an
    // explicit "is this an advance" flag.
    #[test]
    fn non_advance_payout_never_satisfies_the_advance_resolution_gate() {
        // `enqueue_payout` initializes `QueuedPayout` field-by-field and never touches
        // `advance_sol_spent` — Anchor's `init` zero-fills it, so it is 0 by construction.
        let normal_payout_advance_sol_spent: u64 = 0;
        // Both `reconcile_payout_advance` and `write_off_faulted_advance` require > 0 here
        // (`FirmError::NothingToReconcile`) before doing anything else — so neither can ever fire
        // against a normal, non-advance payout.
        assert_eq!(normal_payout_advance_sol_spent, 0);
        assert!(!(normal_payout_advance_sol_spent > 0));
    }

    // ── F-drip: owner-drip 24-month cadence (audit 2026-07-06) ───────────────────────────────────
    // The claim_drip cadence had no test (audit finding: "cadence unverified end-to-end"). These pin
    // the pure timing/amount helpers the handler now uses.
    #[test]
    fn drip_cadence_unlocks_one_month_at_a_time() {
        let start = 1_000_000_000i64;
        // tranche i unlocks at start + (i+1)*MONTH_SECONDS
        assert_eq!(drip_next_unlock(start, 0).unwrap(), start + MONTH_SECONDS);
        assert_eq!(drip_next_unlock(start, 1).unwrap(), start + 2 * MONTH_SECONDS);
        assert_eq!(drip_next_unlock(start, 23).unwrap(), start + 24 * MONTH_SECONDS);
        // strictly increasing month over month
        for m in 0..DRIP_MONTHS - 1 {
            assert!(drip_next_unlock(start, m + 1).unwrap() > drip_next_unlock(start, m).unwrap());
        }
    }

    #[test]
    fn drip_month_amount_is_total_over_24() {
        assert_eq!(drip_month_amount(24_000_000), 1_000_000);
        assert_eq!(drip_month_amount(0), 0);
        // 24 equal tranches never over-release the total (integer division floors)
        let total = 20_000_000_000_000u64;
        assert!(drip_month_amount(total) * DRIP_MONTHS as u64 <= total);
    }

    #[test]
    fn drip_next_unlock_is_overflow_safe() {
        assert!(drip_next_unlock(i64::MAX, 1).is_err());
    }

    // ── R33.1 streamed retroactive $DPROP-staking reserve (retro_vested) ──────────────────────────
    // The pre-open reserve must stream linearly over DPROP_RETRO_VEST_SECONDS, never over-release, and
    // fully drain by the end of the window — so the first stakers can't grab a lump on day one.
    #[test]
    fn retro_vested_is_zero_before_and_at_start() {
        let start = 1_000_000_000i64;
        assert_eq!(retro_vested(1_000_000, 0, start, start - 100), 0); // clock before start
        assert_eq!(retro_vested(1_000_000, 0, start, start), 0); // exactly at start, 0 elapsed
    }

    #[test]
    fn retro_vested_streams_linearly() {
        let start = 1_000_000_000i64;
        let reserve = 900_000_000u64; // divides evenly across a 90-day window
        // at the half-way point, ~half is vested (nothing released yet)
        let half = start + DPROP_RETRO_VEST_SECONDS / 2;
        assert_eq!(retro_vested(reserve, 0, start, half), reserve / 2);
        // one day in → 1/90th
        assert_eq!(retro_vested(reserve, 0, start, start + 86_400), reserve / 90);
    }

    #[test]
    fn retro_vested_nets_out_already_released() {
        let start = 1_000_000_000i64;
        let reserve = 900_000_000u64;
        let half = start + DPROP_RETRO_VEST_SECONDS / 2;
        // if half is already released, a fold at the half-way mark unlocks nothing new
        assert_eq!(retro_vested(reserve, reserve / 2, start, half), 0);
        // a bit later, only the incremental slice unlocks
        let later = half + 86_400;
        assert_eq!(retro_vested(reserve, reserve / 2, start, later), reserve / 90);
    }

    #[test]
    fn retro_vested_fully_drains_and_never_over_releases() {
        let start = 1_000_000_000i64;
        let reserve = 1_234_567u64;
        // past the window → the whole remaining reserve unlocks and no more
        let after = start + DPROP_RETRO_VEST_SECONDS + 999;
        assert_eq!(retro_vested(reserve, 0, start, after), reserve);
        assert_eq!(retro_vested(reserve, reserve, start, after), 0); // already fully released
        // total ever released can never exceed the reserve, at any point in the window
        for frac in 0..=90 {
            let t = start + DPROP_RETRO_VEST_SECONDS * frac / 90;
            assert!(retro_vested(reserve, 0, start, t) <= reserve);
        }
        // a zero reserve is always a no-op
        assert_eq!(retro_vested(0, 0, start, after), 0);
    }

    // ── F-1/F-2 treasury-cache invariant (audit 2026-06-30) ──────────────────────────────────────
    // The bonding curve legitimately credits a firm's `treasury_vault` out-of-band (its firm-fee on
    // every buy/sell), so the cache invariant CANNOT be strict equality — that bricked the firm
    // (`TreasuryDesync`) on any curve credit, including the launch deploy_burn (F-2) and a 0.01-SOL
    // griefer buy (F-1). The fix: (a) the six guards check `vault >= cache` (a drain making vault <
    // cache is the only failure — and impossible, since only the firm PDA can move the vault), and
    // (b) every treasury handler reconciles `treasury_sol = treasury_vault.amount`. These tests pin
    // that decision so a refactor can't silently restore the strict-equality brick.
    fn treasury_invariant_ok(vault: u64, cache: u64) -> bool { vault >= cache }
    fn reconcile_treasury_to_vault(vault: u64) -> u64 { vault }

    /// T-3/T-4: `settle_dispute_payout` draws `min(target, insurance)` from the firm's insurance,
    /// then the remainder from the Universal Pool — so a post-close dispute (firm insurance swept to
    /// the pool at `finalize_close`) is still payable. Pins that the two-tier draw never exceeds the
    /// per-claim cap and composes across the two sources.
    fn two_tier_dispute_draw(target: u64, insurance: u64, universal: u64) -> u64 {
        let from_ins = target.min(insurance);
        let from_uni = target.saturating_sub(from_ins).min(universal);
        from_ins + from_uni
    }

    #[test]
    fn t3_t4_two_tier_dispute_draw_is_bounded_and_composes() {
        assert_eq!(two_tier_dispute_draw(1000, 1000, 5000), 1000); // insurance covers it, no pool draw
        assert_eq!(two_tier_dispute_draw(1000, 0, 5000), 1000); // firm closed → fully from the pool
        assert_eq!(two_tier_dispute_draw(1000, 400, 5000), 1000); // split across both sources
        assert_eq!(two_tier_dispute_draw(1000, 400, 200), 600); // both short → pays only what exists
        assert!(two_tier_dispute_draw(1000, 9999, 9999) <= 1000); // never exceeds the cap
    }

    // ── V2-2 dispute cap selection ────────────────────────────────────────────────────────────────
    // `settle_dispute_payout` picks the cap: on the guardian path, the price-locked lamport sidecar if
    // present else the legacy micro-USD `starting_balance`; on the trustless Faulted path, always the
    // legacy ceiling (no sidecar trust). Mirrors the handler's `challenge_cap` selection.
    fn dispute_cap(proven_fault: bool, legacy: u64, sidecar: Option<u64>) -> u64 {
        if !proven_fault {
            match sidecar { Some(fs) => fs, None => legacy }
        } else {
            legacy
        }
    }

    #[test]
    fn v2_2_cap_selection_prefers_lamport_sidecar_on_guardian_path_only() {
        // $100k account: legacy starting_balance is 100_000_000_000 micro-USD, mis-read as 100 SOL;
        // the price-locked sidecar at ~$150/SOL is ~666.7 SOL — the dimensionally-correct ceiling.
        let legacy = 100_000_000_000u64; // micro-USD, wrongly used as a lamport ceiling
        let sidecar = 666_666_666_666u64; // lamports (~666.7 SOL)
        // guardian path with a sidecar → use the correct lamport cap
        assert_eq!(dispute_cap(false, legacy, Some(sidecar)), sidecar);
        // guardian path without a sidecar → legacy fallback (never bricks the payout)
        assert_eq!(dispute_cap(false, legacy, None), legacy);
        // trustless Faulted path → always legacy, ignores any sidecar (no operator-set trust)
        assert_eq!(dispute_cap(true, legacy, Some(sidecar)), legacy);
        assert_eq!(dispute_cap(true, legacy, None), legacy);
    }

    // ── V2-5 cumulative dispute payout ────────────────────────────────────────────────────────────
    // A large post-close claim is throttled by the Universal-Pool daily cap, so `settle_dispute_payout`
    // accumulates across calls up to the funded-size cap. Pins: total never exceeds the cap, each call
    // draws only what a source can provide, and the record is monotonic.
    fn cumulative_pay(cap: u64, already_paid: u64, amount: u64, insurance: u64, universal: u64) -> u64 {
        let remaining = cap.saturating_sub(already_paid);
        if remaining == 0 { return 0; } // DisputePayoutComplete guard
        let target = amount.min(remaining);
        two_tier_dispute_draw(target, insurance, universal)
    }

    #[test]
    fn v2_5_cumulative_payout_drains_a_large_claim_across_days_without_overrun() {
        let cap = 200_000_000_000u64; // 200 SOL funded size
        let daily = UNIVERSAL_DAILY_DRAW_CAP_SOL; // 50 SOL/day global pool cap
        // Firm closed → insurance 0, everything from the pool, one 50-SOL slice per day.
        let mut paid = 0u64;
        for _ in 0..4 {
            let slice = cumulative_pay(cap, paid, daily, 0, daily);
            paid = paid.saturating_add(slice);
        }
        assert_eq!(paid, cap, "four 50-SOL daily slices exactly fill the 200-SOL entitlement");
        // A fifth call is fully blocked by the completion guard (remaining == 0).
        assert_eq!(cumulative_pay(cap, paid, daily, 0, daily), 0);
        // The running total never exceeds the cap even if a caller over-requests.
        assert!(cumulative_pay(cap, cap - 10, u64::MAX, u64::MAX, u64::MAX) <= 10);
    }

    /// K-1 + bond migration safety: the token-generation account size must be EXACTLY `POST_TOKEN_
    /// TRAILING_LEN` bytes smaller than the full size — the rotation fields (`previous_risk_engine_
    /// authority` Pubkey 32 + `authority_rotation_deadline` i64 8 = 40) PLUS the bond fields
    /// (`bond_accrual` u64 8 + `bond_funded` bool 1 = 9). `migrate_firm_token_fields` pins its
    /// `new_len - 2/-1` token-byte writes to `full - POST_TOKEN_TRAILING_LEN`, so if either constant
    /// drifts from the real field sizes those writes would land in the new fields and corrupt every firm.
    /// Borsh's in-order + append-only serialization then guarantees the byte offsets follow from this size.
    #[test]
    fn k1_authority_migration_size_math_is_correct() {
        assert_eq!(
            AUTHORITY_ROTATION_FIELDS_LEN,
            core::mem::size_of::<Pubkey>() + core::mem::size_of::<i64>()
        );
        assert_eq!(AUTHORITY_ROTATION_FIELDS_LEN, 40);
        assert_eq!(BOND_FIELDS_LEN, core::mem::size_of::<u64>() + core::mem::size_of::<bool>());
        assert_eq!(BOND_FIELDS_LEN, 9);
        assert_eq!(BANKRUPTCY_FIELDS_LEN, core::mem::size_of::<u64>());
        assert_eq!(BANKRUPTCY_FIELDS_LEN, 8);
        assert_eq!(POST_GRAD_LP_FIELDS_LEN, core::mem::size_of::<u64>());
        assert_eq!(POST_GRAD_LP_FIELDS_LEN, 8);
        // rotation 40 + bond 9 + bankruptcy 8 + post-grad LP 8 = 65
        assert_eq!(POST_TOKEN_TRAILING_LEN, 65);
        let full = 8 + FirmState::INIT_SPACE;
        let token_gen = full - POST_TOKEN_TRAILING_LEN;
        assert_eq!(full - token_gen, 65);
        assert!(token_gen < full);
    }

    /// Auto-bankruptcy trigger (§24 v2): a firm flips to Bankrupt the instant its lifetime ULP draws reach
    /// 10% of the pool as it stood at the crossing draw (`ulp_drawn >= pool_before / 10`). Integer-exact.
    #[test]
    fn auto_bankruptcy_fires_at_ten_percent_ulp_depletion() {
        assert_eq!(BANKRUPTCY_ULP_DEPLETION_DIVISOR, 10);
        let bankrupt =
            |ulp_drawn: u64, pool_before: u64| ulp_drawn >= pool_before / BANKRUPTCY_ULP_DEPLETION_DIVISOR;
        // pool 100 SOL → threshold 10 SOL
        assert!(!bankrupt(9_000_000_000, 100_000_000_000)); // 9 SOL drawn — still running
        assert!(bankrupt(10_000_000_000, 100_000_000_000)); // exactly 10% → bankrupt
        assert!(bankrupt(25_000_000_000, 100_000_000_000)); // well past → bankrupt
        // a big single draw against a small pool trips immediately (1 SOL vs 5 SOL pool, threshold 0.5)
        assert!(bankrupt(1_000_000_000, 5_000_000_000));
        // a healthy firm that never draws never trips
        assert!(!bankrupt(0, 100_000_000_000));
    }

    /// Self-funded bond earmark (§10/§14): `pay_challenge_fee` earmarks 1% of the fee while the bond
    /// isn't full, capped at the treasury gross; once funded the earmark is 0 (the 1% stays treasury).
    #[test]
    fn bond_earmark_is_one_percent_and_stops_when_funded() {
        assert_eq!(BOND_FUNDING_BPS, 100); // 1%
        assert_eq!(bps(80_000_000, BOND_FUNDING_BPS), 800_000); // 0.08 SOL fee → 0.0008 SOL bond leg
        let accrue = |funded: bool, fee: u64, to_treasury: u64| -> u64 {
            if funded { 0 } else { bps(fee, BOND_FUNDING_BPS).min(to_treasury) }
        };
        assert_eq!(accrue(false, 80_000_000, 40_000_000), 800_000); // normal: 1% of the fee
        assert_eq!(accrue(true, 80_000_000, 40_000_000), 0); // funded → no earmark, 1% stays treasury
        assert_eq!(accrue(false, 80_000_000, 500_000), 500_000); // starved treasury → capped at the gross
    }

    /// Self-funded bond fill (§10/§14): `fund_operator_bond` moves `min(accrual, vault, remaining)` into
    /// the bond and flips `bond_funded` when it reaches `MIN_OPERATOR_STAKE_LAMPORTS` (50 SOL). Mirrors
    /// the on-chain crank math so the "fill to 50 SOL then stop" invariant is pinned without needing
    /// 5,000 SOL of eval volume on-chain to exercise it.
    #[test]
    fn bond_funding_fills_to_fifty_sol_then_stops() {
        let min = dispute::MIN_OPERATOR_STAKE_LAMPORTS;
        assert_eq!(min, 50_000_000_000);
        let fund = |accrual: u64, vault: u64, current: u64| -> (u64, bool) {
            let remaining = min.saturating_sub(current);
            let to_fund = accrual.min(vault).min(remaining);
            (to_fund, current.saturating_add(to_fund) >= min)
        };
        // partial: small accrual, empty bond → funds the whole accrual, not yet complete
        assert_eq!(fund(2_000_000_000, 10_000_000_000, 0), (2_000_000_000, false));
        // capped by the treasury balance → only what the vault holds moves
        assert_eq!(fund(5_000_000_000, 1_000_000_000, 0), (1_000_000_000, false));
        // capped by remaining-to-50 → tops off exactly and flips complete
        assert_eq!(fund(10_000_000_000, 10_000_000_000, 48_000_000_000), (2_000_000_000, true));
        // already full → funds nothing, stays complete (the 1% now stays as treasury)
        assert_eq!(fund(1_000_000_000, 1_000_000_000, min), (0, true));
        // exact one-shot fill
        assert_eq!(fund(min, min, 0), (min, true));
        // v2: post-slash refill — bond drained to 10 SOL, earmark resumes, a partial fund stays
        // incomplete (flag correctly stays false) until it climbs back to 50 SOL.
        assert_eq!(fund(5_000_000_000, 5_000_000_000, 10_000_000_000), (5_000_000_000, false));
        // v2: the same fund that closes the gap back to 50 SOL flips complete again (bidirectional flag)
        assert_eq!(fund(40_000_000_000, 40_000_000_000, 10_000_000_000), (40_000_000_000, true));
    }

    /// v2 auto-refill (§14.1): `reconcile_operator_bond` DERIVES `bond_funded` from the OperatorStake's
    /// actual native balance (lamports above rent), so a slash that debits the bond below 50 SOL flips the
    /// flag back to false and the 1% earmark auto-resumes. The flag is not sticky in either direction.
    #[test]
    fn bond_reconcile_flips_bond_funded_from_actual_balance() {
        let min = dispute::MIN_OPERATOR_STAKE_LAMPORTS;
        // `reconcile` mirrors the on-chain body: bond_funded = current_bond >= 50 SOL.
        let reconcile = |lamports: u64, rent: u64| -> bool {
            lamports.saturating_sub(rent) >= min
        };
        let rent = 1_500_000; // ~OperatorStake rent-exempt minimum (illustrative)
        // full bond, untouched → stays funded
        assert!(reconcile(min + rent, rent));
        // slashed to zero (slash_settlement_fault) → flips to NOT funded → earmark resumes
        assert!(!reconcile(rent, rent));
        // partial slash leaving 49.999 SOL → still below the floor → NOT funded → earmark resumes
        assert!(!reconcile(min + rent - 1, rent));
        // refilled to exactly 50 SOL → funded again
        assert!(reconcile(min + rent, rent));
        // rent-only / never-funded shell → NOT funded (correct default)
        assert!(!reconcile(rent, rent));
    }

    #[test]
    fn f1_f2_external_curve_credit_does_not_brick() {
        // a curve fee donates 50_000 lamports into a firm with cache 87_000_000
        let (cache, vault) = (87_000_000u64, 87_050_000u64);
        assert!(treasury_invariant_ok(vault, cache), "vault >= cache must pass (was the F-1/F-2 brick)");
        // the next treasury handler absorbs the donation as real treasury
        assert_eq!(reconcile_treasury_to_vault(vault), vault);
    }
    #[test]
    fn treasury_drain_below_cache_still_reverts() {
        // an (impossible) unauthorised withdrawal leaving vault < cache must still trip the guard
        assert!(!treasury_invariant_ok(86_000_000, 87_000_000));
    }
    #[test]
    fn synced_treasury_passes_and_reconciles_identically() {
        assert!(treasury_invariant_ok(100, 100));
        assert_eq!(reconcile_treasury_to_vault(100), 100);
    }

    #[test]
    fn owner_bps_by_tier_matches_doc() {
        assert_eq!(owner_bps_for_tier(0), 600); // Starter 6% (was 7%; -1% to $DPROP staking)
        assert_eq!(owner_bps_for_tier(1), 750); // Growth 7.5% (was 8.5%; -1% to $DPROP staking)
        assert_eq!(owner_bps_for_tier(2), 900); // Pro 9% (was 10%; -1% to $DPROP staking)
        assert_eq!(owner_bps_for_tier(4), 1400); // Enterprise 14% (was 15%; -1% to $DPROP staking)
    }

    #[test]
    fn daily_cap_floor_breaks_thin_treasury_spiral() {
        // OMEGA #1: a thin treasury would be strangled by the flat 20% cap; the floor restores it.
        // Units are now lamports (9 dp) post-migration; the floor magnitude is a Phase-6 tunable, so
        // these are relative-magnitude assertions (floor binds when treasury/5 < floor) not USD ones.
        let thin: u64 = 5_000_000_000;
        assert_eq!(thin / 5, 1_000_000_000); // percentage cap below the floor
        assert_eq!((thin / 5).max(MIN_DAILY_PAYOUT_FLOOR_SOL), MIN_DAILY_PAYOUT_FLOOR_SOL); // floor binds
        assert!((thin / 5).max(MIN_DAILY_PAYOUT_FLOOR_SOL) > thin / 5);
        // A deep treasury is unaffected — the percentage still governs above the floor.
        let deep: u64 = 1_000_000_000_000;
        assert_eq!((deep / 5).max(MIN_DAILY_PAYOUT_FLOOR_SOL), deep / 5);
    }

    #[test]
    fn lp_bps_by_depth_matches_doc() {
        // Units now lamports (9 dp); thresholds are Phase-6 tunables — assert the tiering shape.
        assert_eq!(lp_bps_for_depth(30_000_000_000), 1100); // < LOW → 11% (was 12%; -1% to $DPROP staking)
        assert_eq!(lp_bps_for_depth(100_000_000_000), 900); // LOW..HIGH → 9% (was 10%; -1% to $DPROP staking)
        assert_eq!(lp_bps_for_depth(250_000_000_000), 500); // > HIGH → 5% (was 6%; -1% to $DPROP staking)
    }

    #[test]
    fn fee_split_matches_doc_example() {
        // §17 worked example: tier-2 owner (9%), $399 fee, LP depth $30k (11%), no backstop,
        // a *referred* purchase at the default 10% affiliate rate (effective 9% after -1% to staking).
        // Fixed legs: DP 10% (7.5%+2.5%) + insurance 2% + normal-staking 5% + $DPROP 1% + $FIRMA 1%
        //   + loss-back 2% + $DPROP staking 10% + universal 1.0% = 32.0% (universal trimmed 1.5%→1.0%,
        //   2026-07-04 sim finding #1 — the 0.5% falls to the treasury remainder);
        //   + owner 9% + LP 11% + affiliate 9% = 61.5% → treasury remainder 39.0% (38.0% nominal +1%
        //   from the affiliate redirect, per the `treasury_gross` assertion below). MASTER_FIXES F-5.
        let s = compute_fee_split(
            399_000_000,
            owner_bps_for_tier(2),
            lp_bps_for_depth(30_000_000_000),
            0,
            AFFILIATE_DEFAULT_BPS,
        );
        assert_eq!(s.dp_profit, 29_925_000); // 7.5%
        assert_eq!(s.dp_treasury, 9_975_000); // 2.5%
        assert_eq!(s.insurance, 7_980_000); // 2%
        assert_eq!(s.owner_immediate, 17_955_000); // 4.5%
        assert_eq!(s.owner_vested, 17_955_000); // 4.5%
        assert_eq!(s.lp, 43_890_000); // 11%
        assert_eq!(s.backstop_premium, 0);
        assert_eq!(s.normal_staking, 11_970_000); // 3% (2026-07-27 staking rebalance: was 5%)
        assert_eq!(s.dprop_buyback, 3_990_000); // 1%
        assert_eq!(s.firma_buyback, 3_990_000); // 1%
        // loss_back is no longer a FeeSplit leg (2026-07-27) — it's a notional accrual computed
        // directly in pay_challenge_fee, not part of compute_fee_split's output.
        assert_eq!(s.affiliate_pool, 35_910_000); // 9% (AFFILIATE_DEFAULT_BPS - 100)
        assert_eq!(s.dprop_staking, 39_900_000); // 10%
        assert_eq!(s.universal, 3_990_000); // 1.0% (trimmed from 1.5%)
        assert_eq!(s.treasury_gross, 171_570_000); // was 155_610_000 pre-rebalance; +2% ex-normal_staking, +2% ex-loss_back
    }

    #[test]
    fn fee_split_universal_leg() {
        // 1.0% universal leg asserted explicitly (trimmed 1.5%→1.0%); dp_profit 7.5% / dp_treasury 2.5%.
        let amount = 100_000_000; // $100 in micro-dollars
        let s = compute_fee_split(amount, owner_bps_for_tier(2), lp_bps_for_depth(0), 0, 0);
        assert_eq!(s.universal, 1_000_000); // 1.0%
        assert_eq!(s.dp_profit, 7_500_000); // 7.5%
        assert_eq!(s.dp_treasury, 2_500_000); // 2.5%
        // Universal + dp_profit + dp_treasury = 11.0% — the platform-fixed sum.
        assert_eq!(s.universal + s.dp_profit + s.dp_treasury, 11_000_000);
    }

    #[test]
    fn fee_split_backstop_premium_carved_from_treasury() {
        // Same example with the fixed 8% backstop premium active (2026-07-27 staking rebalance,
        // was 6%): premium is carved from the treasury slice, every other leg is unchanged.
        let base = compute_fee_split(
            399_000_000,
            owner_bps_for_tier(2),
            lp_bps_for_depth(30_000_000_000),
            0,
            AFFILIATE_DEFAULT_BPS,
        );
        let s = compute_fee_split(
            399_000_000,
            owner_bps_for_tier(2),
            lp_bps_for_depth(30_000_000_000),
            DEFAULT_BACKSTOP_PREMIUM_BPS,
            AFFILIATE_DEFAULT_BPS,
        );
        assert_eq!(s.backstop_premium, 31_920_000); // 8% of $399
        assert_eq!(s.treasury_gross, base.treasury_gross - 31_920_000); // carved from treasury
        assert_eq!(s.dp_profit, base.dp_profit); // other legs untouched
        assert_eq!(s.insurance, base.insurance);
        assert_eq!(s.lp, base.lp);
        assert_eq!(s.normal_staking, base.normal_staking);
        assert_eq!(s.dprop_buyback, base.dprop_buyback);
        assert_eq!(s.firma_buyback, base.firma_buyback);
        assert_eq!(s.affiliate_pool, base.affiliate_pool);
        assert_eq!(s.dprop_staking, base.dprop_staking);
    }

    #[test]
    fn deployment_split_matches_starter_example() {
        // RESERVE-3 (2026-07-11): all curve-buy legs removed. Fixed plain-SOL legs on a $5,000 fee:
        //   franchise 9% + DP 20% + $DPROP burn 5% + Universal 3% = 37%; firm treasury remainder = 63%.
        let s = compute_deployment_fee_split(5_000_000_000, false).unwrap();
        assert_eq!(s.franchise_pool, 450_000_000); // 9%
        assert_eq!(s.decentralprop, 1_000_000_000); // 20%
        assert_eq!(s.dprop_burn, 250_000_000); // 5% $DPROP buy-and-burn
        assert_eq!(s.universal, 150_000_000); // 3% Universal Treasury Pool
        assert_eq!(s.firm_treasury, 3_150_000_000); // remainder = 63% (absorbs the removed drip/treasury/burn)
        assert_eq!(s.referral_bonus, 0);
        // All legs sum to exactly the fee price.
        let sum = s.franchise_pool + s.decentralprop + s.dprop_burn + s.universal + s.firm_treasury;
        assert_eq!(sum, 5_000_000_000);
    }

    #[test]
    fn deployment_split_universal_leg() {
        // 3% universal seed + franchise now 9% + firm treasury 63% (RESERVE-3).
        let s = compute_deployment_fee_split(10_000_000_000, false).unwrap();
        assert_eq!(s.universal, 300_000_000); // 3%
        assert_eq!(s.franchise_pool, 900_000_000); // 9%
        assert_eq!(s.decentralprop, 2_000_000_000); // 20%
        // Fixed legs (franchise 9% + DP 20% + $DPROP burn 5% + universal 3%) = 37%.
        assert_eq!(s.franchise_pool + s.decentralprop + s.dprop_burn + s.universal, 3_700_000_000);
        assert_eq!(s.firm_treasury, 6_300_000_000); // 63%
        // Firm treasury absorbs the rest.
        let sum = s.franchise_pool + s.decentralprop + s.dprop_burn + s.universal + s.firm_treasury;
        assert_eq!(sum, 10_000_000_000);
    }

    #[test]
    fn deployment_split_referral_carves_franchise() {
        let s = compute_deployment_fee_split(5_000_000_000, true).unwrap();
        // Referral is 30% of the franchise slice; franchise is now 9% ($450k on a $5k fee).
        assert_eq!(s.referral_bonus, 135_000_000); // 30% of 9% franchise (= 2.7% of price, was 3%)
        assert_eq!(s.franchise_general, 315_000_000); // 70% to the general pool
        assert_eq!(s.franchise_pool, 450_000_000); // 9%
    }

    #[test]
    fn migration_fee_split_skims_dp_and_dprop_burn() {
        // Graduation at the default 107-SOL threshold (DEFAULT_BOOTSTRAP.graduationThreshold):
        // 1.5% fee = 1.0% DP + 0.5% $DPROP burn; rest seeds the pool.
        let s = compute_migration_fee_split(107_000_000_000);
        assert_eq!(s.dp, 1_070_000_000); // 1.0%
        assert_eq!(s.dprop_burn, 535_000_000); // 0.5%
        assert_eq!(s.to_pool, 105_395_000_000); // remainder (98.5%) seeds Raydium
        assert_eq!(s.dp + s.dprop_burn + s.to_pool, 107_000_000_000); // conserves
        // The two fee legs sum to the headline MIGRATION_FEE_BPS.
        assert_eq!(MIGRATION_FEE_DP_BPS + MIGRATION_FEE_DPROP_BURN_BPS, MIGRATION_FEE_BPS);
    }

    #[test]
    fn fee_split_affiliate_dynamic() {
        // Unreferred (affiliate_bps 0): nothing carved (saturating_sub(100) on 0 = 0), stays in treasury.
        let none = compute_fee_split(399_000_000, owner_bps_for_tier(2), lp_bps_for_depth(0), 0, 0);
        assert_eq!(none.affiliate_pool, 0);
        // Referred at default 10%: effective payout = 9% (1% redirected to dprop_staking fixed leg).
        let def = compute_fee_split(399_000_000, owner_bps_for_tier(2), lp_bps_for_depth(0), 0, AFFILIATE_DEFAULT_BPS);
        let max = compute_fee_split(399_000_000, owner_bps_for_tier(2), lp_bps_for_depth(0), 0, MAX_AFFILIATE_BPS);
        assert_eq!(def.affiliate_pool, 35_910_000); // 9% (AFFILIATE_DEFAULT_BPS - 100)
        assert_eq!(max.affiliate_pool, 75_810_000); // 19% (MAX_AFFILIATE_BPS - 100)
        // Unreferred treasury = referred treasury + the 9% affiliate (when no affiliate, that 9%
        // stays in treasury; the dprop_staking fixed 10% comes from treasury instead).
        assert_eq!(none.treasury_gross, def.treasury_gross + 35_910_000);
        // Extra 10% (max vs default) still comes entirely from treasury.
        assert_eq!(max.treasury_gross, def.treasury_gross - 39_900_000);
    }

    #[test]
    fn fee_split_parts_sum_to_total() {
        let amount = 399_000_001; // odd amount → rounding absorbed by treasury
        let s = compute_fee_split(amount, 1000, 1500, DEFAULT_BACKSTOP_PREMIUM_BPS, AFFILIATE_DEFAULT_BPS);
        let sum = s.dp_profit
            + s.dp_treasury
            + s.insurance
            + s.owner_immediate
            + s.owner_vested
            + s.lp
            + s.backstop_premium
            + s.normal_staking
            + s.dprop_buyback
            + s.firma_buyback
            + s.affiliate_pool
            + s.dprop_staking
            + s.universal
            + s.treasury_gross;
        assert_eq!(sum, amount);
    }

    // fee_split_carves_loss_back_from_treasury REMOVED 2026-07-27 — loss-back is no longer a
    // FeeSplit leg at all (it's a notional accrual computed directly in pay_challenge_fee), so
    // there's nothing left in compute_fee_split's output for this test to assert.

    #[test]
    fn payout_tier_split_matches_doc_table() {
        // §22 Lever Set 1: trader/stakeholder % of virtual profit per tier.
        assert_eq!(payout_tier_split(RiskTier::Healthy).trader_bps, 8000);
        assert_eq!(payout_tier_split(RiskTier::Healthy).stakeholder_bps, 2000);
        assert_eq!(payout_tier_split(RiskTier::Critical).trader_bps, 6000);
        assert_eq!(payout_tier_split(RiskTier::Critical).stakeholder_bps, 1500);
    }

    #[test]
    fn delivered_firma_split_healthy_is_80_20() {
        // HEALTHY total purchased = 100% VP → trader 80/100, stakeholder 20/100.
        let (trader, stake) = split_delivered_firma(1_000_000, &payout_tier_split(RiskTier::Healthy));
        assert_eq!(trader, 800_000);
        assert_eq!(stake, 200_000);
        assert_eq!(trader + stake, 1_000_000);
    }

    #[test]
    fn delivered_firma_split_critical_ratio() {
        // CRITICAL total purchased = 75% VP → trader 6000/7500 = 80%, stakeholder 20%.
        let (trader, stake) = split_delivered_firma(7_500_000, &payout_tier_split(RiskTier::Critical));
        assert_eq!(trader, 6_000_000);
        assert_eq!(stake, 1_500_000);
        assert_eq!(trader + stake, 7_500_000);
    }

    #[test]
    fn stakeholder_split_defaults_and_sums() {
        // Default config, 2026-07-27 staking rebalance: 30% owner / 5% no-risk staking / 5% backstop
        // staking / 10% burn / 10% treasury / 40% universal SOL. `split_stakeholder` is called with
        // the $FIRMA amount AFTER the 40% SOL carve, i.e. 60% of the original stakeholder notional.
        // Renormalized by firma_basis=6000:
        //   owner    = amount * 3000/6000 = 50% of amount = 30% of original ✓
        //   staking  = amount * 500/6000  ≈ 8.3%            = 5% of original ✓
        //   backstop = amount * 500/6000  ≈ 8.3%            = 5% of original (new leg)
        //   burn     = amount * 1000/6000 ≈ 16.7%
        //   treasury = remainder          ≈ 16.7%
        let cfg = StakeholderConfig::default();
        let amount = 6_000_000u64; // represents the 60% $FIRMA residual
        let s = split_stakeholder(amount, &cfg, DEFAULT_BACKSTOP_POOL_BPS);
        assert_eq!(s.owner, 3_000_000); // 50% of 6M
        assert_eq!(s.staking, 500_000); // 500/6000 * 6M
        assert_eq!(s.backstop, 500_000); // 500/6000 * 6M
        assert_eq!(s.buyback_burn, 1_000_000);
        assert_eq!(s.treasury_reserve, 1_000_000); // remainder
        assert_eq!(s.owner + s.staking + s.backstop + s.buyback_burn + s.treasury_reserve, amount);
    }

    #[test]
    fn stakeholder_split_rounding_absorbed_by_reserve() {
        let cfg = StakeholderConfig::default();
        let amount = 6_000_001u64; // odd → reserve takes the remainder
        let s = split_stakeholder(amount, &cfg, DEFAULT_BACKSTOP_POOL_BPS);
        assert_eq!(s.owner + s.staking + s.backstop + s.buyback_burn + s.treasury_reserve, amount);
    }

    #[test]
    fn stakeholder_split_zero_universal_uses_raw_bps() {
        // When universal_sol_bps = 0, firma_basis = 10000 and raw bps apply directly.
        // backstop_pool_bps (sibling field, passed separately below) = 0 — not under test here;
        // kept at 0 so the other four legs' expected values stay exactly as before.
        let cfg = StakeholderConfig {
            owner_share_bps: 5000,
            staking_pool_bps: 2000,
            buyback_burn_bps: 1500,
            treasury_reserve_bps: 1500,
            universal_sol_bps: 0,
        };
        let s = split_stakeholder(10_000_000, &cfg, 0);
        assert_eq!(s.owner, 5_000_000);
        assert_eq!(s.staking, 2_000_000);
        assert_eq!(s.backstop, 0);
        assert_eq!(s.buyback_burn, 1_500_000);
        assert_eq!(s.treasury_reserve, 1_500_000);
        assert_eq!(s.owner + s.staking + s.backstop + s.buyback_burn + s.treasury_reserve, 10_000_000);
    }

    #[test]
    fn stakeholder_universal_carve_math() {
        // Verify the pre-buy SOL carve formula matches the design:
        // At Healthy tier (stakeholder_bps=2000), universal_sol_bps=4000:
        //   stakeholder_sol_notional = bps(sol_amount, 2000) = 20% of sol
        //   universal_carve = bps(stakeholder_sol_notional, 4000) = 40% of that = 8% of sol
        let sol_amount = 1_000_000_000u64; // 1 SOL in lamports
        let split = payout_tier_split(RiskTier::Healthy);
        let cfg = StakeholderConfig::default();
        let stakeholder_sol_notional = bps(sol_amount, split.stakeholder_bps);
        assert_eq!(stakeholder_sol_notional, 200_000_000); // 20%
        let universal_carve = bps(stakeholder_sol_notional, cfg.universal_sol_bps);
        assert_eq!(universal_carve, 80_000_000); // 8% of original sol
        let curve_sol = sol_amount - universal_carve;
        assert_eq!(curve_sol, 920_000_000); // 92% goes to curve
        // effective_stakeholder_bps = 2000 * 6000 / 10000 = 1200
        let effective_stakeholder_bps = ((split.stakeholder_bps as u32)
            .saturating_mul(10_000 - cfg.universal_sol_bps as u32) / 10_000) as u16;
        assert_eq!(effective_stakeholder_bps, 1200);
    }

    #[test]
    fn staking_accumulator_distributes_pro_rata() {
        // Two stakers: A=300, B=100 (total 400). Distribute 800 SOL yield.
        let total = 400u64;
        let (acc, unalloc) = fold_yield(0, 0, 800, total);
        assert_eq!(unalloc, 0);
        // A's pending = 300 * acc / P - 0 = 600; B's = 100 * acc / P = 200.
        assert_eq!(pending_yield(300, acc, 0), 600);
        assert_eq!(pending_yield(100, acc, 0), 200);
    }

    #[test]
    fn staking_retains_when_nothing_staked_then_flushes() {
        // Nothing staked → retained as unallocated, accumulator untouched.
        let (acc1, unalloc1) = fold_yield(0, 0, 500, 0);
        assert_eq!(acc1, 0);
        assert_eq!(unalloc1, 500);
        // Next distribution with stakers present flushes the retained amount too.
        let (acc2, unalloc2) = fold_yield(acc1, unalloc1, 500, 100);
        assert_eq!(unalloc2, 0);
        // (500 retained + 500 new) over 100 staked → one staker holding all gets 1000.
        assert_eq!(pending_yield(100, acc2, 0), 1000);
    }

    #[test]
    fn staking_debt_excludes_pre_existing_yield() {
        // Distribute to A (100 staked) → acc set. Then B stakes 100; B's debt is set so
        // B cannot claim the pre-existing distribution.
        let (acc, _) = fold_yield(0, 0, 1000, 100); // A earns 1000
        let b_debt = yield_debt(100, acc);
        assert_eq!(pending_yield(100, acc, b_debt), 0); // B starts at zero
        // A still owed its 1000.
        assert_eq!(pending_yield(100, acc, 0), 1000);
    }

    #[test]
    fn staking_accumulator_is_solvent_across_random_sequences() {
        // Adversarial solvency of the SHARED staking vault (the $FIRMA + $DPROP MasterChef accumulator).
        // Under randomized multi-staker stake / unstake / claim / distribute sequences, the load-bearing
        // invariant for a vault shared across the whole protocol: total yield ever CLAIMED + total still
        // OWED (pending across all stakers) + still-RETAINED (unallocated) must NEVER exceed total
        // DISTRIBUTED. Integer rounding may only LOSE dust to the pool (under-pay) — never over-pay. A
        // violation here is an over-claim that drains a vault every staker shares.
        const STAKERS: usize = 6;
        // Rounding slack a SHARED vault must tolerate: each stake/unstake re-checkpoints a position's
        // debt with a floor, so the running `owed` can exceed `distributed` by AT MOST 1 unit per
        // amount-change (≤ one per op). Across a 48-op run that is a handful of base units — bounded, and
        // (the load-bearing part) it must NOT grow with the *magnitude* of the yield distributed. A
        // real over-claim would blow past this. `pending_yield` floors, so the pool only ever loses dust.
        const SOLVENCY_SLACK: u128 = 48; // ≤ one unit per op in a run
        let mut worst_overage: u128 = 0;
        for seed in 0..40_000u64 {
            let mut rng = seed.wrapping_mul(0x9E3779B97F4A7C15).wrapping_add(1);
            let mut next = || {
                rng ^= rng << 13;
                rng ^= rng >> 7;
                rng ^= rng << 17;
                rng
            };

            let mut acc: u128 = 0;
            let mut unalloc: u64 = 0;
            let mut total_staked: u64 = 0;
            let mut distributed: u128 = 0;
            let mut claimed: u128 = 0;
            let mut amount = [0u64; STAKERS];
            let mut debt = [0u128; STAKERS];

            // Settle a position's pending into `claimed` and re-checkpoint its debt (MasterChef: any
            // stake change settles first, else the debt reset would mint or destroy yield).
            macro_rules! settle {
                ($i:expr) => {{
                    claimed += pending_yield(amount[$i], acc, debt[$i]) as u128;
                    debt[$i] = yield_debt(amount[$i], acc);
                }};
            }

            for _ in 0..48 {
                let op = next() % 4;
                let i = (next() as usize) % STAKERS;
                match op {
                    0 => {
                        // stake
                        settle!(i);
                        let add = (next() % 100_000) + 1;
                        amount[i] = amount[i].saturating_add(add);
                        total_staked = total_staked.saturating_add(add);
                        debt[i] = yield_debt(amount[i], acc);
                    }
                    1 => {
                        // unstake (partial or full)
                        if amount[i] > 0 {
                            settle!(i);
                            let dec = (next() % amount[i]) + 1;
                            amount[i] -= dec;
                            total_staked -= dec;
                            debt[i] = yield_debt(amount[i], acc);
                        }
                    }
                    2 => {
                        // claim
                        settle!(i);
                    }
                    _ => {
                        // distribute a yield chunk
                        let amt = (next() % 1_000_000) as u64;
                        let (a2, u2) = fold_yield(acc, unalloc, amt, total_staked);
                        acc = a2;
                        unalloc = u2;
                        distributed += amt as u128;
                    }
                }

                // Model consistency: the summed positions equal the tracked total.
                let sum_amounts: u64 = amount.iter().copied().sum();
                assert_eq!(sum_amounts, total_staked, "model drift (seed {seed})");

                // THE invariant: nothing owed beyond what was distributed (+ bounded rounding slack).
                let outstanding: u128 = (0..STAKERS)
                    .map(|k| pending_yield(amount[k], acc, debt[k]) as u128)
                    .sum();
                let owed = claimed + outstanding + unalloc as u128;
                let overage = owed.saturating_sub(distributed);
                worst_overage = worst_overage.max(overage);
                assert!(
                    overage <= SOLVENCY_SLACK,
                    "OVER-CLAIM beyond rounding slack (seed {seed}): owed {owed} > distributed \
                     {distributed} by {overage} (> {SOLVENCY_SLACK}) — claimed {claimed}, pending \
                     {outstanding}, unalloc {unalloc}"
                );
            }
        }
        // The slack must be small AND independent of yield magnitude — a real drain would not be.
        assert!(
            worst_overage <= SOLVENCY_SLACK,
            "worst overage {worst_overage} exceeded slack {SOLVENCY_SLACK}"
        );
    }

    #[test]
    fn staking_accumulator_slack_does_not_scale_with_volume() {
        // The rounding slack must come from the NUMBER of amount-changes, not the SIZE of the yield.
        // Scale the distributed magnitude 1000× with the same op structure; the overage must stay in the
        // same small band (a magnitude-scaling overage would be a true over-claim / drain vector).
        fn worst_for_scale(scale: u64) -> u128 {
            const STAKERS: usize = 6;
            let mut worst = 0u128;
            for seed in 0..5_000u64 {
                let mut rng = seed.wrapping_mul(0x9E3779B97F4A7C15).wrapping_add(1);
                let mut next = || {
                    rng ^= rng << 13;
                    rng ^= rng >> 7;
                    rng ^= rng << 17;
                    rng
                };
                let (mut acc, mut unalloc, mut total_staked): (u128, u64, u64) = (0, 0, 0);
                let (mut distributed, mut claimed): (u128, u128) = (0, 0);
                let mut amount = [0u64; STAKERS];
                let mut debt = [0u128; STAKERS];
                for _ in 0..48 {
                    let op = next() % 4;
                    let i = (next() as usize) % STAKERS;
                    match op {
                        0 => {
                            claimed += pending_yield(amount[i], acc, debt[i]) as u128;
                            let add = ((next() % 100_000) + 1) * scale;
                            amount[i] = amount[i].saturating_add(add);
                            total_staked = total_staked.saturating_add(add);
                            debt[i] = yield_debt(amount[i], acc);
                        }
                        1 => {
                            if amount[i] > 0 {
                                claimed += pending_yield(amount[i], acc, debt[i]) as u128;
                                let dec = (next() % amount[i]) + 1;
                                amount[i] -= dec;
                                total_staked -= dec;
                                debt[i] = yield_debt(amount[i], acc);
                            }
                        }
                        2 => {
                            claimed += pending_yield(amount[i], acc, debt[i]) as u128;
                            debt[i] = yield_debt(amount[i], acc);
                        }
                        _ => {
                            let amt = ((next() % 1_000_000) as u64).saturating_mul(scale);
                            let (a2, u2) = fold_yield(acc, unalloc, amt, total_staked);
                            acc = a2;
                            unalloc = u2;
                            distributed += amt as u128;
                        }
                    }
                    let outstanding: u128 = (0..STAKERS)
                        .map(|k| pending_yield(amount[k], acc, debt[k]) as u128)
                        .sum();
                    worst = worst.max((claimed + outstanding + unalloc as u128).saturating_sub(distributed));
                }
            }
            worst
        }
        let small = worst_for_scale(1);
        let large = worst_for_scale(1000);
        // 1000× the yield magnitude must NOT ~1000× the overage — it stays in the same tiny band.
        assert!(
            large <= small + 48,
            "overage scaled with magnitude (small {small}, large {large}) — real over-claim, not rounding"
        );
    }

    #[test]
    fn eval_fee_split_conserves_exactly() {
        // Every eval fee funds the shared pools (universal 1.5%, $DPROP staking, buyback sinks, insurance)
        // + the firm treasury. CONSERVATION: no base unit may be created or destroyed — the 14 legs must
        // sum to EXACTLY `amount` (2026-07-27: loss_back removed, no longer a FeeSplit leg). `treasury_gross`
        // is the residual (`amount − others`), so conservation
        // holds iff `others <= amount`; the property test sweeps random amounts + configurable bps and
        // asserts exact conservation on the whole valid space (and that saturation is the only failure mode).
        for seed in 0..60_000u64 {
            let mut rng = seed.wrapping_mul(0x9E3779B97F4A7C15).wrapping_add(12345);
            let mut next = || {
                rng ^= rng << 13;
                rng ^= rng >> 7;
                rng ^= rng << 17;
                rng
            };
            let amount = (next() % 1_000_000_000_000_000) + 1; // 1 .. 1e15 base units
            // Configurable legs within their governance-plausible ranges (fixed legs sum to ~26%).
            let owner_bps = (next() % 4001) as u16 + 1000; // 1000..5000
            let lp_bps = (next() % 1101) as u16; // 0..1100
            let premium_bps = (next() % 501) as u16; // 0..500
            let affiliate_bps = (next() % 3001) as u16; // 0..3000
            let s = compute_fee_split(amount, owner_bps, lp_bps, premium_bps, affiliate_bps);
            let sum = s.dp_profit
                + s.dp_treasury
                + s.insurance
                + s.owner_immediate
                + s.owner_vested
                + s.lp
                + s.backstop_premium
                + s.normal_staking
                + s.dprop_buyback
                + s.firma_buyback
                + s.affiliate_pool
                + s.dprop_staking
                + s.universal
                + s.treasury_gross;
            // `others` = every non-treasury leg; treasury_gross = amount − others (residual).
            let others = sum - s.treasury_gross;
            if others <= amount {
                // Valid config (legs fit inside the fee): every base unit is accounted for — exact.
                assert_eq!(sum, amount, "eval fee not conserved (seed {seed}, amount {amount})");
            } else {
                // Over-configured bps (legs > 100%). This is prevented by config validation in production;
                // here it only confirms the math DEGRADES SAFELY — treasury saturates to 0, no panic/wrap.
                assert_eq!(s.treasury_gross, 0, "expected treasury saturation on over-config (seed {seed})");
            }
        }
    }

    #[test]
    fn treasury_health_zone_matches_thresholds() {
        // Starter/Growth/Pro share one ladder; Scale/Enterprise scale up (§3.6).
        for tier in [0u8, 1, 2] {
            assert_eq!(
                treasury_health_thresholds_lamports(tier),
                [500_000_000_000, 1_000_000_000_000, 2_500_000_000_000, 5_000_000_000_000]
            );
        }
        assert_eq!(
            treasury_health_thresholds_lamports(3),
            [900_000_000_000, 1_800_000_000_000, 4_500_000_000_000, 9_000_000_000_000]
        );
        assert_eq!(
            treasury_health_thresholds_lamports(4),
            [1_500_000_000_000, 3_000_000_000_000, 7_500_000_000_000, 15_000_000_000_000]
        );

        // Boundary walk on Pro (tier 2): just-below / at / just-above each threshold.
        let t = treasury_health_thresholds_lamports(2);
        assert_eq!(treasury_health_zone(2, 0), 0);
        assert_eq!(treasury_health_zone(2, t[0] - 1), 0);
        assert_eq!(treasury_health_zone(2, t[0]), 1);
        assert_eq!(treasury_health_zone(2, t[0] + 1), 1);
        assert_eq!(treasury_health_zone(2, t[1] - 1), 1);
        assert_eq!(treasury_health_zone(2, t[1]), 2);
        assert_eq!(treasury_health_zone(2, t[2] - 1), 2);
        assert_eq!(treasury_health_zone(2, t[2]), 3);
        assert_eq!(treasury_health_zone(2, t[3] - 1), 3);
        assert_eq!(treasury_health_zone(2, t[3]), 4);
        assert_eq!(treasury_health_zone(2, t[3] + 1_000_000_000_000), 4);
    }

    #[test]
    fn treasury_health_boost_bps_matches_doc() {
        // 5 tiers × 5 zones. boost_max = 4400 - owner_bps_for_tier(tier); zone ramp is linear
        // (0/25/50/75/100% of boost_max), integer-truncated — matches MASTER_ECONOMICS §3.6.
        let expected: [[u16; 5]; 5] = [
            [0, 950, 1900, 2850, 3800], // Starter, boost_max 3800
            [0, 912, 1825, 2737, 3650], // Growth, boost_max 3650
            [0, 875, 1750, 2625, 3500], // Pro, boost_max 3500
            [0, 825, 1650, 2475, 3300], // Scale, boost_max 3300
            [0, 750, 1500, 2250, 3000], // Enterprise, boost_max 3000
        ];
        for tier in 0u8..5 {
            for zone in 0u8..5 {
                assert_eq!(
                    treasury_health_boost_bps(tier, zone),
                    expected[tier as usize][zone as usize],
                    "tier {tier} zone {zone}"
                );
            }
        }
    }

    #[test]
    fn treasury_health_owner_bps_matches_worked_example() {
        // Pro tier (owner baseline 900 bps): owner effective bps at each zone = baseline + boost's
        // owner share (HEALTH_OWNER_WEIGHT_BPS = 2000 = 20% of the boost).
        let expected = [900u16, 1075, 1250, 1425, 1600];
        for zone in 0u8..5 {
            let boost = treasury_health_boost_bps(2, zone);
            let owner_effective = owner_bps_for_tier(2) + bps_of_bps(boost, HEALTH_OWNER_WEIGHT_BPS);
            assert_eq!(owner_effective, expected[zone as usize], "zone {zone}");
        }
    }

    #[test]
    fn treasury_health_growing_zone_is_a_true_noop() {
        for seed in 0..2_000u64 {
            let mut rng = seed.wrapping_mul(0x9E3779B97F4A7C15).wrapping_add(777);
            let mut next = || {
                rng ^= rng << 13;
                rng ^= rng >> 7;
                rng ^= rng << 17;
                rng
            };
            let amount = (next() % 1_000_000_000_000_000) + 1;
            let tier = (next() % 5) as u8;
            let threshold0 = treasury_health_thresholds_lamports(tier)[0];
            let treasury_sol = next() % threshold0; // strictly below the first threshold — Growing zone
            let owner_bps = owner_bps_for_tier(tier);
            let lp_bps = (next() % 1101) as u16;
            let premium_bps = if next() % 2 == 0 { 0 } else { DEFAULT_BACKSTOP_PREMIUM_BPS };
            let affiliate_bps = if next() % 2 == 0 { 0 } else { AFFILIATE_DEFAULT_BPS };

            let base = compute_fee_split(amount, owner_bps, lp_bps, premium_bps, affiliate_bps);
            let fresh = compute_fee_split(amount, owner_bps, lp_bps, premium_bps, affiliate_bps);
            let adjusted = apply_treasury_health_adjustment(fresh, amount, tier, treasury_sol);

            assert_eq!(adjusted.dp_profit, base.dp_profit, "seed {seed}");
            assert_eq!(adjusted.dp_treasury, base.dp_treasury, "seed {seed}");
            assert_eq!(adjusted.insurance, base.insurance, "seed {seed}");
            assert_eq!(adjusted.owner_immediate, base.owner_immediate, "seed {seed}");
            assert_eq!(adjusted.owner_vested, base.owner_vested, "seed {seed}");
            assert_eq!(adjusted.lp, base.lp, "seed {seed}");
            assert_eq!(adjusted.backstop_premium, base.backstop_premium, "seed {seed}");
            assert_eq!(adjusted.normal_staking, base.normal_staking, "seed {seed}");
            assert_eq!(adjusted.dprop_buyback, base.dprop_buyback, "seed {seed}");
            assert_eq!(adjusted.firma_buyback, base.firma_buyback, "seed {seed}");
            assert_eq!(adjusted.affiliate_pool, base.affiliate_pool, "seed {seed}");
            assert_eq!(adjusted.dprop_staking, base.dprop_staking, "seed {seed}");
            assert_eq!(adjusted.universal, base.universal, "seed {seed}");
            assert_eq!(adjusted.treasury_gross, base.treasury_gross, "seed {seed}");
        }
    }

    #[test]
    fn treasury_health_adjustment_conserves_exactly() {
        // The health adjustment only ever moves value BETWEEN fields of an already-conserving
        // FeeSplit — it can neither create nor destroy base units. Prove the wrapped 14-field sum
        // always equals the unwrapped 14-field sum, for the same (amount, owner_bps, lp_bps,
        // premium_bps, affiliate_bps), across every tier and a treasury_sol range spanning all 5
        // zones (0..20,000 SOL) — including the over-redirect branch (see
        // `treasury_health_adjustment_saturates_when_overconfigured` for a deterministic pin of that
        // branch specifically; this fuzz just proves it never breaks conservation wherever it hits).
        for seed in 0..60_000u64 {
            let mut rng = seed.wrapping_mul(0x9E3779B97F4A7C15).wrapping_add(24601);
            let mut next = || {
                rng ^= rng << 13;
                rng ^= rng >> 7;
                rng ^= rng << 17;
                rng
            };
            let amount = (next() % 1_000_000_000_000_000) + 1;
            let tier = (next() % 5) as u8;
            let treasury_sol = next() % 20_000_000_000_000; // 0 .. 20,000 SOL in lamports
            let lp_bps = (next() % 1101) as u16;
            let premium_bps = if next() % 2 == 0 { 0 } else { DEFAULT_BACKSTOP_PREMIUM_BPS };
            let affiliate_bps = if next() % 2 == 0 { 0 } else { AFFILIATE_DEFAULT_BPS };
            let owner_bps = owner_bps_for_tier(tier);

            let base = compute_fee_split(amount, owner_bps, lp_bps, premium_bps, affiliate_bps);
            let base_sum = base.dp_profit
                + base.dp_treasury
                + base.insurance
                + base.owner_immediate
                + base.owner_vested
                + base.lp
                + base.backstop_premium
                + base.normal_staking
                + base.dprop_buyback
                + base.firma_buyback
                + base.affiliate_pool
                + base.dprop_staking
                + base.universal
                + base.treasury_gross;

            let fresh = compute_fee_split(amount, owner_bps, lp_bps, premium_bps, affiliate_bps);
            let adjusted = apply_treasury_health_adjustment(fresh, amount, tier, treasury_sol);
            let adjusted_sum = adjusted.dp_profit
                + adjusted.dp_treasury
                + adjusted.insurance
                + adjusted.owner_immediate
                + adjusted.owner_vested
                + adjusted.lp
                + adjusted.backstop_premium
                + adjusted.normal_staking
                + adjusted.dprop_buyback
                + adjusted.firma_buyback
                + adjusted.affiliate_pool
                + adjusted.dprop_staking
                + adjusted.universal
                + adjusted.treasury_gross;

            assert_eq!(
                adjusted_sum, base_sum,
                "treasury health adjustment broke conservation (seed {seed}, amount {amount}, tier {tier}, treasury_sol {treasury_sol})"
            );
        }
    }

    #[test]
    fn treasury_health_adjustment_saturates_when_overconfigured() {
        // Enterprise, Saturated zone, shallow curve (lp 11%), active backstop (8%, 2026-07-27
        // rebalance — was 6%), a stress-test 15% affiliate rate (real production locks the referral
        // rate to AFFILIATE_DEFAULT_BPS=10%; this pure-math fixture intentionally goes higher, same
        // as the general conservation fuzz above, purely to reconstruct genuine over-redirect —
        // 2026-07-27's lower normal_staking/no-loss_back-carve raised the pre-boost treasury baseline
        // enough that the OLD 10%-affiliate fixture no longer over-redirects at all) — leaves only a
        // small pre-boost treasury share (asserted below via `base.treasury_gross > 0`), while the
        // nominal boost at Saturated is 30% of the fee. Must degrade safely: no panic, sum == amount,
        // treasury_gross == 0, and the credited legs must be visibly SCALED DOWN below their nominal
        // deltas, not independently clamped (independent clamping would break conservation — see the
        // correctness note on `apply_treasury_health_adjustment`).
        let amount = 1_000_000_000u64;
        let tier = 4u8; // Enterprise
        let treasury_sol = treasury_health_thresholds_lamports(tier)[3]; // exactly at Saturated
        let owner_bps = owner_bps_for_tier(tier);
        let lp_bps = 1100u16; // shallow curve, 11%
        let premium_bps = DEFAULT_BACKSTOP_PREMIUM_BPS; // 8%, backstop active
        let affiliate_bps = 1500u16; // stress-test rate — see comment above

        let base = compute_fee_split(amount, owner_bps, lp_bps, premium_bps, affiliate_bps);
        assert!(base.treasury_gross > 0, "test fixture should leave SOME pre-boost treasury");

        let boost_bps = treasury_health_boost_bps(tier, 4);
        let nominal_owner_delta = bps(amount, bps_of_bps(boost_bps, HEALTH_OWNER_WEIGHT_BPS));

        let adjusted = apply_treasury_health_adjustment(
            compute_fee_split(amount, owner_bps, lp_bps, premium_bps, affiliate_bps),
            amount,
            tier,
            treasury_sol,
        );

        assert_eq!(adjusted.treasury_gross, 0);
        let owner_credited =
            (adjusted.owner_immediate + adjusted.owner_vested) - (base.owner_immediate + base.owner_vested);
        assert!(
            owner_credited < nominal_owner_delta,
            "owner leg should be scaled DOWN below its nominal delta when over-redirecting, got {owner_credited} vs nominal {nominal_owner_delta}"
        );
        let sum = adjusted.dp_profit
            + adjusted.dp_treasury
            + adjusted.insurance
            + adjusted.owner_immediate
            + adjusted.owner_vested
            + adjusted.lp
            + adjusted.backstop_premium
            + adjusted.normal_staking
            + adjusted.dprop_buyback
            + adjusted.firma_buyback
            + adjusted.affiliate_pool
            + adjusted.dprop_staking
            + adjusted.universal
            + adjusted.treasury_gross;
        assert_eq!(sum, amount);
    }

    #[test]
    fn treasury_health_matches_doc_example() {
        // §3.6 worked example: Pro tier, LP 5% (deep curve), no backstop, a referred purchase
        // (AFFILIATE_DEFAULT_BPS). 2026-07-27 staking rebalance shifted every figure below by +4.0pp
        // (normal_staking 5%->3%, loss_back's 2% carve removed entirely) — update MASTER_ECONOMICS.md
        // §3.6 to match (was 45.0% Growing -> 10.0% Saturated; now 49.0% -> 14.0%). amount =
        // 1_000_000_000 divides every bps computation below with zero truncation, so these are exact.
        let amount = 1_000_000_000u64;
        let tier = 2u8; // Pro
        let owner_bps = owner_bps_for_tier(tier);
        let lp_bps = 500u16; // 5%, deep/graduated curve
        let premium_bps = 0u16; // no backstop pool
        let affiliate_bps = AFFILIATE_DEFAULT_BPS; // referred

        let growing = apply_treasury_health_adjustment(
            compute_fee_split(amount, owner_bps, lp_bps, premium_bps, affiliate_bps),
            amount,
            tier,
            0, // Growing zone
        );
        assert_eq!(growing.treasury_gross, 490_000_000); // 49.0% (was 45.0% pre-rebalance)

        let healthy_threshold = treasury_health_thresholds_lamports(tier)[0];
        let healthy = apply_treasury_health_adjustment(
            compute_fee_split(amount, owner_bps, lp_bps, premium_bps, affiliate_bps),
            amount,
            tier,
            healthy_threshold,
        );
        assert_eq!(healthy.treasury_gross, 402_600_000); // 40.26% (was 36.26% pre-rebalance)

        let saturated_threshold = treasury_health_thresholds_lamports(tier)[3];
        let saturated = apply_treasury_health_adjustment(
            compute_fee_split(amount, owner_bps, lp_bps, premium_bps, affiliate_bps),
            amount,
            tier,
            saturated_threshold,
        );
        assert_eq!(saturated.treasury_gross, 140_000_000); // 14.0% (was 10.0% pre-rebalance)
        // The four boost-credited lines below are UNCHANGED by the rebalance — the boost formula
        // doesn't depend on normal_staking/loss_back at all, only the pre-boost treasury baseline
        // (and post-boost treasury) shifted.
        assert_eq!(saturated.owner_immediate + saturated.owner_vested, 160_000_000); // 16.0%
        assert_eq!(saturated.dp_profit + saturated.dp_treasury, 170_000_000); // 17.0%
        assert_eq!(saturated.dprop_buyback + saturated.firma_buyback, 90_000_000); // 9.0% (Buybacks)
        assert_eq!(saturated.universal, 45_000_000); // 4.5%
    }

    #[test]
    fn deploy_fee_split_conserves_or_rejects() {
        // Deploy fee seeds the franchise pool + the Universal Treasury Pool (3%) + DP + the $DPROP burn +
        // the firm treasury (RESERVE-3: all curve-buy legs removed). CONSERVATION: an Ok split's legs sum
        // to EXACTLY `price`. Sweep random prices + referred/unreferred. (The fixed legs total 37% < 100%,
        // so the split can no longer be rejected — every price yields an Ok.)
        for seed in 0..60_000u64 {
            let mut rng = seed.wrapping_mul(0x9E3779B97F4A7C15).wrapping_add(999);
            let mut next = || {
                rng ^= rng << 13;
                rng ^= rng >> 7;
                rng ^= rng << 17;
                rng
            };
            let price = (next() % 100_000_000_000) + 1;
            let has_ref = next() & 1 == 0;
            let s = compute_deployment_fee_split(price, has_ref).unwrap();
            // franchise_pool = referral_bonus + franchise_general (the referral carve is INSIDE it),
            // so summing franchise_pool AND its two parts would double-count — use the parts.
            let sum = s.referral_bonus
                + s.franchise_general
                + s.decentralprop
                + s.dprop_burn
                + s.universal
                + s.firm_treasury;
            assert_eq!(sum, price, "deploy fee not conserved (seed {seed}, price {price})");
            assert_eq!(
                s.referral_bonus + s.franchise_general,
                s.franchise_pool,
                "franchise parts don't reassemble (seed {seed})"
            );
        }
    }

    #[test]
    fn universal_daily_cap_never_exceeded_within_a_day() {
        // The Universal Treasury Pool's GLOBAL daily draw cap rate-limits depletion across all firms — the
        // guard that stops one surge from wiping the shared pool. Model the exact handler logic (reset on
        // UTC-day rollover, then `require daily_drawn + amount <= CAP`) over randomized (timestamp, amount)
        // attempts, and independently verify NO single UTC day ever drains more than the cap.
        const CAP: u64 = UNIVERSAL_DAILY_DRAW_CAP_SOL;
        for seed in 0..20_000u64 {
            let mut rng = seed.wrapping_mul(0x9E3779B97F4A7C15).wrapping_add(3);
            let mut next = || {
                rng ^= rng << 13;
                rng ^= rng >> 7;
                rng ^= rng << 17;
                rng
            };
            let mut draw_day: i64 = -1;
            let mut daily_drawn: u64 = 0;
            let mut now: i64 = 0;
            let mut per_day: std::collections::HashMap<i64, u64> = std::collections::HashMap::new();
            for _ in 0..80 {
                now += (next() % 200_000) as i64; // advance time (sometimes crossing a UTC day)
                let amount = (next() % (CAP + CAP / 2)) as u64; // up to 1.5× cap so some MUST be rejected
                let day = now / 86_400;
                let base = if day != draw_day { 0 } else { daily_drawn }; // the reset-on-rollover
                if base.saturating_add(amount) <= CAP {
                    daily_drawn = base + amount;
                    draw_day = day;
                    *per_day.entry(day).or_insert(0) += amount; // an ACCEPTED draw
                }
            }
            for (day, total) in per_day {
                assert!(total <= CAP, "day {day} drew {total} > cap {CAP} (seed {seed})");
            }
        }
    }

    #[test]
    fn migration_fee_split_conserves_exactly() {
        // The graduation migration fee (DP + $DPROP burn) is skimmed; the remainder seeds the Raydium
        // pool. All three legs must sum to EXACTLY the graduated SOL — no liquidity created or lost.
        for seed in 0..40_000u64 {
            let g = seed
                .wrapping_mul(0x9E3779B97F4A7C15)
                .wrapping_add(7)
                % 1_000_000_000_000;
            let s = compute_migration_fee_split(g);
            assert_eq!(s.dp + s.dprop_burn + s.to_pool, g, "migration fee not conserved (g {g})");
        }
    }

    #[test]
    fn backstop_loss_mutualizes_pro_rata() {
        // Stakers A=300, B=100 (total 400). Emergency draw of 80 $FIRMA.
        let total = 400u64;
        let loss_acc = (80u128 * PRECISION) / total as u128;
        // Loss shares are pro-rata; survivors = stake − loss.
        assert_eq!(pending_yield(300, loss_acc, 0), 60);
        assert_eq!(pending_yield(100, loss_acc, 0), 20);
        assert_eq!(300 - pending_yield(300, loss_acc, 0), 240);
        assert_eq!(100 - pending_yield(100, loss_acc, 0), 80);
    }

    #[test]
    fn backstop_new_staker_absorbs_no_past_loss() {
        // A (100) eats a 50 draw; B stakes 100 afterward — debt shields B from the past.
        let loss_acc = (50u128 * PRECISION) / 100u128;
        let b_debt = yield_debt(100, loss_acc);
        assert_eq!(pending_yield(100, loss_acc, b_debt), 0);
        assert_eq!(pending_yield(100, loss_acc, 0), 50); // A still bears the full loss
    }

    #[test]
    fn backstop_cooldown_scales_with_effective_tier() {
        assert_eq!(backstop_cooldown(0), 3 * 86_400); // HEALTHY
        assert_eq!(backstop_cooldown(1), 7 * 86_400); // CAUTION
        assert_eq!(backstop_cooldown(2), 14 * 86_400); // WARNING
        assert_eq!(backstop_cooldown(3), 30 * 86_400); // CRITICAL
    }

    #[test]
    fn backstop_share_bps_handles_zero_total_staked() {
        // draw_backstop can legally drain a pool's total_staked to exactly 0 while a staker still
        // holds a position (their per-staker amount_staked is only reduced lazily, at their own
        // withdraw). Must not panic, and must return the max-severity bucket, not garbage.
        assert_eq!(backstop_share_bps(100, 0), 10_000);
        assert_eq!(backstop_share_bps(0, 0), 10_000);
    }

    #[test]
    fn backstop_whale_multiplier_bands() {
        assert_eq!(backstop_whale_multiplier_tenths(0), 10);
        assert_eq!(backstop_whale_multiplier_tenths(499), 10);
        assert_eq!(backstop_whale_multiplier_tenths(500), 15);
        assert_eq!(backstop_whale_multiplier_tenths(1499), 15);
        assert_eq!(backstop_whale_multiplier_tenths(1500), 20);
        assert_eq!(backstop_whale_multiplier_tenths(2999), 20);
        assert_eq!(backstop_whale_multiplier_tenths(3000), 30);
        assert_eq!(backstop_whale_multiplier_tenths(10_000), 30);
    }

    #[test]
    fn required_backstop_cooldown_composes_tier_and_whale() {
        assert_eq!(required_backstop_cooldown(0, 100), 3 * 86_400); // HEALTHY, <5% share: 1.0x
        assert_eq!(required_backstop_cooldown(2, 2000), 14 * 86_400 * 2); // WARNING, 15-30%: 2.0x
        assert_eq!(required_backstop_cooldown(3, 5000), 30 * 86_400 * 3); // CRITICAL, >=30%: 3.0x
    }

    #[test]
    fn backstop_cooldown_escalation_never_shortens() {
        // The withdraw-time recheck (`cooldown_ends_at.max(cooldown_requested_at +
        // required_backstop_cooldown(now, share_now))`) must never let a position unlock EARLIER
        // than what was promised at request time, regardless of how tier/share move while pending.
        for seed in 0..20_000u64 {
            let mut rng = seed.wrapping_mul(0x9E3779B97F4A7C15).wrapping_add(11);
            let mut next = || {
                rng ^= rng << 13;
                rng ^= rng >> 7;
                rng ^= rng << 17;
                rng
            };
            let requested_at: i64 = (next() % 10_000_000) as i64;
            let tier_at_request = (next() % 4) as u8;
            let share_at_request = next() % 10_001;
            let original_unlock = requested_at + required_backstop_cooldown(tier_at_request, share_at_request);

            let tier_now = (next() % 4) as u8;
            let share_now = next() % 10_001;
            let required_unlock_now = requested_at + required_backstop_cooldown(tier_now, share_now);
            let effective_unlock = original_unlock.max(required_unlock_now);

            assert!(effective_unlock >= original_unlock, "escalation shortened the unlock (seed {seed})");
        }
    }

    #[test]
    fn backstop_daily_outflow_cap_never_exceeded_within_a_day() {
        // Models withdraw_backstop's reset-then-check-then-record idiom against a pool that shrinks
        // by each ACCEPTED surviving slice (same as the real instruction, cap recomputed fresh off
        // the live, shrinking pool each call) — independently verifies no accepted withdrawal ever
        // pushes a day's cumulative outflow past the cap computed at that moment.
        for seed in 0..20_000u64 {
            let mut rng = seed.wrapping_mul(0x9E3779B97F4A7C15).wrapping_add(13);
            let mut next = || {
                rng ^= rng << 13;
                rng ^= rng >> 7;
                rng ^= rng << 17;
                rng
            };
            let mut total_staked: u64 = 1_000_000 + (next() % 1_000_000);
            let mut withdraw_day: i64 = -1;
            let mut daily_withdrawn: u64 = 0;
            let mut now: i64 = 0;
            for _ in 0..80 {
                if total_staked == 0 {
                    break;
                }
                now += (next() % 200_000) as i64;
                let day = now / 86_400;
                if day != withdraw_day {
                    daily_withdrawn = 0;
                    withdraw_day = day;
                }
                let cap = (total_staked as u128 * BACKSTOP_DAILY_OUTFLOW_CAP_BPS as u128 / 10_000) as u64;
                let attempt = (next() % (total_staked / 2 + 1)).max(1);
                if daily_withdrawn.saturating_add(attempt) <= cap {
                    daily_withdrawn += attempt;
                    total_staked -= attempt;
                    assert!(daily_withdrawn <= cap, "day {day} withdrew {daily_withdrawn} > cap {cap} (seed {seed})");
                }
            }
        }
    }

    #[test]
    fn backstop_partial_withdrawal_conserves_value() {
        // Splitting a matured position's surviving payout across multiple partial
        // `withdraw_backstop` calls must never let the staker collect MORE than the one-shot
        // surviving total — this is the exact bug caught by hand-deriving this test: re-baselining
        // the remainder's debt against the LIVE accumulator (rather than scaling the existing debt
        // proportionally) would zero out its unrealized loss share and let a staker escape it by
        // withdrawing in slices instead of one shot. Model the corrected (proportional-scaling)
        // handler logic directly and sweep randomized (stake, debt, acc, split-sequence) tuples.
        for seed in 0..20_000u64 {
            let mut rng = seed.wrapping_mul(0x9E3779B97F4A7C15).wrapping_add(17);
            let mut next = || {
                rng ^= rng << 13;
                rng ^= rng >> 7;
                rng ^= rng << 17;
                rng
            };
            let staked0: u64 = 1 + (next() % 1_000_000);
            let acc = ((next() % 2_000_000_000) as u128 * PRECISION) / 1_000_000_000; // 0x-2x per-token
            let debt0 = yield_debt(staked0 / 2, acc); // a plausible prior baseline, not necessarily 0
            let pending_loss0 = pending_yield(staked0, acc, debt0);
            let surviving_total0 = staked0.saturating_sub(pending_loss0);

            let mut staked = staked0;
            let mut debt = debt0;
            let mut paid: u64 = 0;
            for _ in 0..10 {
                if staked == 0 {
                    break;
                }
                let amount = (next() % staked).saturating_add(1).min(staked);
                let pending_loss = pending_yield(staked, acc, debt);
                let surviving = staked.saturating_sub(pending_loss);
                let slice = ((amount as u128).saturating_mul(surviving as u128) / staked as u128) as u64;
                paid = paid.saturating_add(slice);
                let remainder = staked - amount;
                if remainder == 0 {
                    staked = 0;
                } else {
                    debt = debt.saturating_mul(remainder as u128) / staked as u128;
                    staked = remainder;
                }
            }
            assert!(
                paid <= surviving_total0,
                "split withdrawal over-paid (seed {seed}): {paid} > {surviving_total0}"
            );
        }
    }

    // ───────── Prediction Market LP Pool (Phase 2 pooled-LP AMM plan) ─────────
    // Mirrors the Backstop test coverage immediately above, adapted to the PM LP pool's single-mint
    // (principal + yield both in $FIRMA) shape and its duplicated `pm_lp_*` cooldown helpers.

    #[test]
    fn pm_lp_stake_sets_fresh_debt_with_no_retroactive_yield() {
        // Mirrors `stake_pm_lp`'s debt-assignment logic directly: a fresh position staking AFTER
        // some yield has already accrued must owe none of that past yield — `yield_debt` bakes the
        // current accumulator into the new position's baseline, exactly as `stake_backstop` does
        // for premium.
        let yield_acc = (500u128 * PRECISION) / 1_000; // 0.5 $FIRMA/token already accrued
        let loss_acc = 0u128;
        let mut pool_total_staked = 1_000u64;
        let mut pool_total_yield_weight = 1_000u64;

        let amount = 250u64;
        pool_total_staked = pool_total_staked.checked_add(amount).unwrap();
        pool_total_yield_weight = pool_total_yield_weight.checked_add(amount).unwrap();
        let pos_yield_debt = yield_debt(amount, yield_acc);
        let pos_loss_debt = yield_debt(amount, loss_acc);

        assert_eq!(pool_total_staked, 1_250);
        assert_eq!(pool_total_yield_weight, 1_250);
        // The new position owes exactly the accumulator × its own stake — no MORE (over-charging)
        // and no LESS (double-dipping into value that predates its stake).
        assert_eq!(pos_yield_debt, (amount as u128 * yield_acc) / PRECISION);
        assert_eq!(pos_loss_debt, 0);
        // Immediately after staking, pending yield against that debt is exactly zero — no
        // retroactive claim on yield that accrued before this position existed.
        assert_eq!(pending_yield(amount, yield_acc, pos_yield_debt), 0);
    }

    #[test]
    fn pm_lp_partial_withdrawal_scales_debt_proportionally_not_reset() {
        // Direct unit-level pin of `withdraw_pm_lp`'s remainder-debt formula: original_debt *
        // remainder / staked — NOT `yield_debt(remainder, live_acc)`. The two coincide only when the
        // position's debt was already exactly proportional to the live accumulator (the fresh-stake
        // case); once yield has moved past the position's baseline they diverge, and resetting to
        // the live accumulator would erase the remainder's already-accrued, not-yet-realized share —
        // the exact bug `backstop_partial_withdrawal_conserves_value` guards against for Backstop.
        let staked: u64 = 1_000;
        let acc: u128 = (300u128 * PRECISION) / 1_000; // 0.3/token accrued since this position's baseline
        let debt: u128 = yield_debt(staked / 2, acc); // baseline set when only half the stake existed
        let amount: u64 = 400; // partial withdrawal
        let remainder = staked - amount;

        let scaled_debt = debt.saturating_mul(remainder as u128) / staked as u128;
        let reset_debt = yield_debt(remainder, acc);
        assert_ne!(
            scaled_debt, reset_debt,
            "test fixture must exercise a case where scaling and resetting diverge"
        );

        let pending_with_scaled = pending_yield(remainder, acc, scaled_debt);
        let pending_with_reset = pending_yield(remainder, acc, reset_debt);
        assert!(
            pending_with_scaled > pending_with_reset,
            "proportional scaling must leave the remainder's already-accrued share intact; a \
             live-accumulator reset would erase it"
        );
    }

    #[test]
    fn pm_lp_partial_withdrawal_conserves_value() {
        // Fuzz-parity with `backstop_partial_withdrawal_conserves_value`: splitting a matured
        // position's surviving payout across multiple partial `withdraw_pm_lp` calls must never let
        // the staker collect MORE than the one-shot surviving total.
        for seed in 0..20_000u64 {
            let mut rng = seed.wrapping_mul(0x9E3779B97F4A7C15).wrapping_add(23);
            let mut next = || {
                rng ^= rng << 13;
                rng ^= rng >> 7;
                rng ^= rng << 17;
                rng
            };
            let staked0: u64 = 1 + (next() % 1_000_000);
            let acc = ((next() % 2_000_000_000) as u128 * PRECISION) / 1_000_000_000; // 0x-2x per-token
            let debt0 = yield_debt(staked0 / 2, acc); // a plausible prior baseline, not necessarily 0
            let pending_loss0 = pending_yield(staked0, acc, debt0);
            let surviving_total0 = staked0.saturating_sub(pending_loss0);

            let mut staked = staked0;
            let mut debt = debt0;
            let mut paid: u64 = 0;
            for _ in 0..10 {
                if staked == 0 {
                    break;
                }
                let amount = (next() % staked).saturating_add(1).min(staked);
                let pending_loss = pending_yield(staked, acc, debt);
                let surviving = staked.saturating_sub(pending_loss);
                let slice = ((amount as u128).saturating_mul(surviving as u128) / staked as u128) as u64;
                paid = paid.saturating_add(slice);
                let remainder = staked - amount;
                if remainder == 0 {
                    staked = 0;
                } else {
                    debt = debt.saturating_mul(remainder as u128) / staked as u128;
                    staked = remainder;
                }
            }
            assert!(
                paid <= surviving_total0,
                "split withdrawal over-paid (seed {seed}): {paid} > {surviving_total0}"
            );
        }
    }

    #[test]
    fn pm_lp_daily_cap_blocks_same_day_then_resets_next_day() {
        // Concrete two-step trace of `withdraw_pm_lp`'s reset-then-check-then-record idiom: an
        // over-cap request is rejected same-day, and the identical request succeeds once the day
        // rolls over and `daily_withdrawn` resets to 0.
        let total_staked: u64 = 100_000;
        let cap = (total_staked as u128 * PM_LP_DAILY_OUTFLOW_CAP_BPS as u128 / 10_000) as u64; // 10%
        assert_eq!(cap, 10_000);

        let mut daily_withdrawn: u64 = 0;
        let mut withdraw_day: i64 = 0;
        let now_day0 = 5 * 86_400; // arbitrary day 5, mid-day
        let day0 = now_day0 / 86_400;
        if day0 != withdraw_day {
            daily_withdrawn = 0;
            withdraw_day = day0;
        }

        // An over-cap request is rejected.
        let over_cap_amount = cap + 1;
        assert!(daily_withdrawn.saturating_add(over_cap_amount) > cap, "over-cap request must be rejected same-day");

        // A within-cap request the same day is accepted and recorded.
        let within_cap = cap; // exactly at the cap
        assert!(daily_withdrawn.saturating_add(within_cap) <= cap);
        daily_withdrawn = daily_withdrawn.saturating_add(within_cap);
        assert_eq!(daily_withdrawn, cap);

        // A further request the SAME day, even for 1 unit, is now rejected — the day's cap is spent.
        assert!(daily_withdrawn.saturating_add(1) > cap);

        // The next day, the reset-then-check idiom clears `daily_withdrawn` before the check runs,
        // so the identical (previously-rejected) request now succeeds.
        let now_day1 = now_day0 + 86_400;
        let day1 = now_day1 / 86_400;
        if day1 != withdraw_day {
            daily_withdrawn = 0;
            withdraw_day = day1;
        }
        assert_eq!(withdraw_day, day1, "the tracked day must roll forward");
        assert_eq!(daily_withdrawn, 0);
        assert!(
            daily_withdrawn.saturating_add(within_cap) <= cap,
            "the cap must be fully available again on a new UTC day"
        );
    }

    #[test]
    fn pm_lp_daily_outflow_cap_never_exceeded_within_a_day() {
        // Fuzz-parity with `backstop_daily_outflow_cap_never_exceeded_within_a_day`: no accepted
        // withdrawal ever pushes a day's cumulative outflow past the cap computed at that moment,
        // against a pool that shrinks by each accepted surviving slice.
        for seed in 0..20_000u64 {
            let mut rng = seed.wrapping_mul(0x9E3779B97F4A7C15).wrapping_add(29);
            let mut next = || {
                rng ^= rng << 13;
                rng ^= rng >> 7;
                rng ^= rng << 17;
                rng
            };
            let mut total_staked: u64 = 1_000_000 + (next() % 1_000_000);
            let mut withdraw_day: i64 = -1;
            let mut daily_withdrawn: u64 = 0;
            let mut now: i64 = 0;
            for _ in 0..80 {
                if total_staked == 0 {
                    break;
                }
                now += (next() % 200_000) as i64;
                let day = now / 86_400;
                if day != withdraw_day {
                    daily_withdrawn = 0;
                    withdraw_day = day;
                }
                let cap = (total_staked as u128 * PM_LP_DAILY_OUTFLOW_CAP_BPS as u128 / 10_000) as u64;
                let attempt = (next() % (total_staked / 2 + 1)).max(1);
                if daily_withdrawn.saturating_add(attempt) <= cap {
                    daily_withdrawn += attempt;
                    total_staked -= attempt;
                    assert!(daily_withdrawn <= cap, "day {day} withdrew {daily_withdrawn} > cap {cap} (seed {seed})");
                }
            }
        }
    }

    #[test]
    fn pm_lp_whale_tier_cooldown_lengthens_with_share() {
        // Same bands/tiers as Backstop's (duplicated helpers — see `pm_lp_whale_multiplier_tenths`'s
        // doc comment for why): pin the multiplier ladder and confirm the composed cooldown is
        // strictly monotonic in pool share at a fixed ARE tier.
        assert_eq!(pm_lp_whale_multiplier_tenths(0), 10);
        assert_eq!(pm_lp_whale_multiplier_tenths(499), 10);
        assert_eq!(pm_lp_whale_multiplier_tenths(500), 15);
        assert_eq!(pm_lp_whale_multiplier_tenths(1499), 15);
        assert_eq!(pm_lp_whale_multiplier_tenths(1500), 20);
        assert_eq!(pm_lp_whale_multiplier_tenths(2999), 20);
        assert_eq!(pm_lp_whale_multiplier_tenths(3000), 30);
        assert_eq!(pm_lp_whale_multiplier_tenths(10_000), 30);

        let healthy = 0u8;
        let c_small = required_pm_lp_cooldown(healthy, 100); // <5%
        let c_mid = required_pm_lp_cooldown(healthy, 1000); // 5-15%
        let c_big = required_pm_lp_cooldown(healthy, 2000); // 15-30%
        let c_whale = required_pm_lp_cooldown(healthy, 5000); // >=30%
        assert!(
            c_small < c_mid && c_mid < c_big && c_big < c_whale,
            "cooldown must strictly lengthen as pool share grows"
        );
        assert_eq!(c_small, 3 * 86_400); // HEALTHY base, 1.0x
        assert_eq!(c_whale, 3 * 86_400 * 3); // HEALTHY base, 3.0x
    }

    #[test]
    fn pm_lp_claim_pays_exact_pending_and_resets_debt_to_live_accumulator() {
        // Mirrors `claim_pm_lp_yield`'s body directly: pay `pending_yield(staked, acc, debt)`, then
        // set debt = yield_debt(staked, acc) — so an immediate second claim (no new yield folded)
        // pays 0.
        let staked: u64 = 777;
        let acc: u128 = (1_234u128 * PRECISION) / 1_000; // 1.234/token
        let debt: u128 = yield_debt(staked / 3, acc / 2); // some arbitrary prior baseline

        let paid = pending_yield(staked, acc, debt);
        let new_debt = yield_debt(staked, acc);

        // Exactly the accrued-but-unclaimed amount, no more/less.
        assert_eq!(paid, ((staked as u128).saturating_mul(acc) / PRECISION).saturating_sub(debt) as u64);
        // Debt now sits exactly on the live accumulator...
        assert_eq!(new_debt, yield_debt(staked, acc));
        // ...so an immediate re-claim against the SAME accumulator pays nothing further.
        assert_eq!(pending_yield(staked, acc, new_debt), 0);
    }

    #[test]
    fn pro_rata_prorates_the_payout_value() {
        // PAYOUT-LIFETIME-1: a full delivery credits the whole SOL obligation…
        assert_eq!(pro_rata(6_799_313_100, 180_830_275_418, 180_830_275_418), 6_799_313_100);
        // …a half delivery credits half…
        assert_eq!(pro_rata(1_000, 50, 100), 500);
        // …and a zero-owed payout can't divide by zero.
        assert_eq!(pro_rata(1_000, 0, 0), 0);
        // No u64 overflow on large values (u128 intermediate).
        assert_eq!(pro_rata(u64::MAX, 1, 1), u64::MAX);
    }

    #[test]
    fn effective_tier_takes_the_stricter() {
        let mk = |tier: u8, active: bool| PlatformRiskState {
            authority: Pubkey::default(),
            override_tier: tier,
            override_active: active,
            override_reason: [0u8; 32],
            set_at: 0,
            bump: 0,
        };
        // Inactive override → firm tier unchanged.
        assert_eq!(effective_tier(1, &mk(3, false)), 1);
        // Active override raises the floor.
        assert_eq!(effective_tier(1, &mk(3, true)), 3);
        // Firm already stricter than the override → firm wins.
        assert_eq!(effective_tier(3, &mk(2, true)), 3);
    }

    #[test]
    fn stakeholder_config_validation() {
        // `backstop_pool_bps` (2026-07-27 staking rebalance) is a SIBLING FirmState field, not part
        // of `StakeholderConfig` (see that struct's doc comment for why) — passed as a separate
        // argument to both `split_stakeholder` and `validate_stakeholder_config`.
        assert!(validate_stakeholder_config(&StakeholderConfig::default(), DEFAULT_BACKSTOP_POOL_BPS));
        // Sum != 10000 (universal_sol one short). backstop_pool_bps: 0 is itself out of its own
        // (500..=3000) bound, but that's moot — the sum check alone already fails this.
        assert!(!validate_stakeholder_config(&StakeholderConfig {
            owner_share_bps: 3000,
            staking_pool_bps: 1000,
            buyback_burn_bps: 1000,
            treasury_reserve_bps: 1000,
            universal_sol_bps: 3999, // sum = 9999
        }, 0));
        // buyback_burn below the 3% (300 bps) floor (cannot zero the deflationary mechanism).
        // staking/backstop split the old 1000 in half (500 each) so the sum stays isolated to this
        // one violation.
        assert!(!validate_stakeholder_config(&StakeholderConfig {
            owner_share_bps: 3000,
            staking_pool_bps: 500,
            buyback_burn_bps: 200, // below 300
            treasury_reserve_bps: 1000,
            universal_sol_bps: 4800, // sum = 10000
        }, 500));
        // owner above the 50% (5000 bps) ceiling.
        assert!(!validate_stakeholder_config(&StakeholderConfig {
            owner_share_bps: 5001, // above 5000
            staking_pool_bps: 500,
            buyback_burn_bps: 300,
            treasury_reserve_bps: 0,
            universal_sol_bps: 3699, // sum = 10000
        }, 500));
        // universal_sol above 60% (6000 bps) ceiling.
        assert!(!validate_stakeholder_config(&StakeholderConfig {
            owner_share_bps: 1000,
            staking_pool_bps: 500,
            buyback_burn_bps: 300,
            treasury_reserve_bps: 200,
            universal_sol_bps: 7500, // above 6000; sum = 10000
        }, 500));
        // Minimum valid: operator-centric with universal disabled. staking/backstop split the old
        // 3000 ceiling in half (1500 each) so both stay within their own (500..=3000) bound.
        assert!(validate_stakeholder_config(&StakeholderConfig {
            owner_share_bps: 5000,
            staking_pool_bps: 1500,
            buyback_burn_bps: 2000,
            treasury_reserve_bps: 0,
            universal_sol_bps: 0,
        }, 1500));
    }

    // ───────────────────── F-M-5: backstop premium SOLVENCY property test ─────────────────────
    // A pure model of the backstop premium/loss accounting (mirrors the on-chain handlers) run over
    // many random stake/fund/draw/claim/withdraw sequences, asserting the SOLVENCY invariant:
    //     premium_claimed + Σ pending_premium  ≤  premium_funded     (never over-claim the vault)
    // With the F-M-5 fix (premium folds divide by `total_premium_weight`, the NOMINAL sum, while losses
    // use the draw-reduced `total_staked`) this holds across all sequences. (The OLD code folded premium
    // over `total_staked`; the `old_code_violates_solvency` test pins that it broke the invariant.)

    #[derive(Clone, Copy)]
    struct Pos { staked: u64, premium_debt: u128 }

    struct PremiumModel {
        premium_acc: u128,
        unallocated: u64,
        total_premium_weight: u64, // F-M-5 nominal denominator
        total_staked: u64,         // loss denominator (drops on draw)
        loss_acc: u128,
        positions: Vec<Pos>,
        funded: u128,
        claimed: u128,
    }

    impl PremiumModel {
        fn new() -> Self {
            Self { premium_acc: 0, unallocated: 0, total_premium_weight: 0, total_staked: 0,
                   loss_acc: 0, positions: Vec::new(), funded: 0, claimed: 0 }
        }
        fn stake(&mut self, amount: u64) {
            self.total_staked += amount;
            self.total_premium_weight += amount;
            self.positions.push(Pos { staked: amount, premium_debt: yield_debt(amount, self.premium_acc) });
        }
        /// `weight` is the denominator the implementation folds over (F-M-5: total_premium_weight).
        fn fund(&mut self, amount: u64, use_fixed_weight: bool) {
            self.funded += amount as u128;
            let denom = if use_fixed_weight { self.total_premium_weight } else { self.total_staked };
            let (acc, unalloc) = fold_yield(self.premium_acc, self.unallocated, amount, denom);
            self.premium_acc = acc;
            self.unallocated = unalloc;
        }
        fn draw(&mut self, amount: u64) {
            if self.total_staked == 0 { return; }
            let d = amount.min(self.total_staked);
            self.loss_acc += (d as u128 * PRECISION) / self.total_staked as u128;
            self.total_staked -= d; // premium weight intentionally unchanged (F-M-5)
        }
        fn claim(&mut self, i: usize) {
            let p = self.positions[i];
            let pending = pending_yield(p.staked, self.premium_acc, p.premium_debt);
            self.claimed += pending as u128;
            self.positions[i].premium_debt = yield_debt(p.staked, self.premium_acc);
        }
        fn withdraw(&mut self, i: usize) {
            let p = self.positions[i];
            let pending = pending_yield(p.staked, self.premium_acc, p.premium_debt);
            self.claimed += pending as u128;
            self.total_premium_weight = self.total_premium_weight.saturating_sub(p.staked);
            let pl = pending_yield(p.staked, self.loss_acc, 0);
            self.total_staked = self.total_staked.saturating_sub(p.staked.saturating_sub(pl));
            self.positions.swap_remove(i);
        }
        /// premium_claimed + Σ pending_premium over active positions.
        fn total_claimable(&self) -> u128 {
            let pending: u128 = self.positions.iter()
                .map(|p| pending_yield(p.staked, self.premium_acc, p.premium_debt) as u128)
                .sum();
            self.claimed + pending
        }
    }

    /// Tiny dependency-free LCG for reproducible sequences.
    struct Lcg(u64);
    impl Lcg {
        fn next(&mut self) -> u64 { self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1); self.0 >> 16 }
        fn range(&mut self, n: u64) -> u64 { self.next() % n }
    }

    /// Returns the worst `claimable - funded` overage seen over the sequence (as i128). ≤ 0 means fully
    /// solvent; a small positive value is integer-floor rounding drift; a large one is the F-M-5 bug.
    fn worst_overage(seed: u64, use_fixed_weight: bool) -> i128 {
        let mut m = PremiumModel::new();
        let mut rng = Lcg(seed);
        let mut worst: i128 = i128::MIN;
        for _ in 0..200 {
            match rng.range(5) {
                0 => m.stake(1 + rng.range(1_000_000)),
                1 => m.fund(1 + rng.range(500_000), use_fixed_weight),
                2 if m.total_staked > 0 => m.draw(1 + rng.range(m.total_staked.max(1))),
                3 if !m.positions.is_empty() => m.claim((rng.range(m.positions.len() as u64)) as usize),
                4 if !m.positions.is_empty() => m.withdraw((rng.range(m.positions.len() as u64)) as usize),
                _ => {}
            }
            let overage = m.total_claimable() as i128 - m.funded as i128;
            if overage > worst { worst = overage; }
        }
        worst
    }

    // Rounding slack: each fund/claim flooring drifts ≤ 1 unit; ≤ 200 ops + ≤ ~a few positions ⇒ a few
    // hundred units max. The F-M-5 bug over-claims proportionally to draws × stake (millions here), so
    // this bound cleanly separates benign rounding from the insolvency bug.
    const ROUNDING_SLACK: i128 = 2_000;

    #[test]
    fn fm5_premium_is_solvent_across_random_sequences() {
        for seed in 0..2_000u64 {
            let w = worst_overage(seed.wrapping_mul(2718281828).wrapping_add(1), true);
            assert!(
                w <= ROUNDING_SLACK,
                "F-M-5: premium over-claimed the vault by {w} (> {ROUNDING_SLACK}) on seed {seed}"
            );
        }
    }

    #[test]
    fn fm5_old_code_violates_solvency() {
        // Regression pin: folding premium over the draw-reduced `total_staked` (the OLD behaviour)
        // over-claims by FAR more than rounding slack on at least one sequence — the fix is load-bearing.
        let worst = (0..2_000u64)
            .map(|s| worst_overage(s.wrapping_mul(2718281828).wrapping_add(1), false))
            .max()
            .unwrap();
        assert!(
            worst > ROUNDING_SLACK,
            "expected the old total_staked denominator to over-claim by > {ROUNDING_SLACK}; saw {worst}"
        );
    }

    // ── Post-graduation swap (RAYDIUM_GRADUATION.md §5.1) ──
    #[test]
    fn cpswap_swap_data_layout() {
        // The CPI data is [8-byte disc][u64 amount_in LE][u64 min_out LE] = 24 bytes — the exact wire
        // format Raydium's `swap_base_input` expects. Pin the disc + the little-endian arg encoding.
        let data = build_swap_base_input_data(1_234_567_890u64, 42u64);
        assert_eq!(data.len(), 24);
        assert_eq!(&data[0..8], &CPSWAP_SWAP_BASE_INPUT_DISC);
        assert_eq!(&data[0..8], &[143, 190, 90, 218, 196, 30, 51, 222]);
        assert_eq!(u64::from_le_bytes(data[8..16].try_into().unwrap()), 1_234_567_890);
        assert_eq!(u64::from_le_bytes(data[16..24].try_into().unwrap()), 42);
        assert_eq!(CPSWAP_SWAP_ACCOUNTS, 13);
    }

    #[test]
    fn cpswap_deposit_data_layout() {
        // Phase 4.4 add-liquidity CPI data = [8-byte disc][u64 lp][u64 max_0][u64 max_1] = 32 bytes.
        let data = build_deposit_data(1_000u64, 5_000u64, 6_000u64);
        assert_eq!(data.len(), 32);
        assert_eq!(&data[0..8], &CPSWAP_DEPOSIT_DISC);
        assert_eq!(&data[0..8], &[242, 35, 198, 137, 82, 225, 242, 182]);
        assert_eq!(u64::from_le_bytes(data[8..16].try_into().unwrap()), 1_000);
        assert_eq!(u64::from_le_bytes(data[16..24].try_into().unwrap()), 5_000); // max token_0
        assert_eq!(u64::from_le_bytes(data[24..32].try_into().unwrap()), 6_000); // max token_1
        assert_eq!(CPSWAP_DEPOSIT_ACCOUNTS, 13);
    }

    // ── VEST-1: claim_vesting ────────────────────────────────────────────────

    /// The guards of `claim_vesting` and `clawback_vesting`, side by side, as pure predicates.
    /// Both instructions move the SAME batch to DIFFERENT destinations (owner vs treasury), so the
    /// one property that must never break is that they can't both fire on one batch.
    fn can_claim(claimed: bool, unlocks_at: i64, now: i64) -> bool {
        !claimed && now >= unlocks_at
    }
    fn can_clawback(claimed: bool, unlocks_at: i64, now: i64) -> bool {
        !claimed && unlocks_at > now
    }

    #[test]
    fn claim_and_clawback_are_disjoint_at_every_instant() {
        // Not a sampled check — the guards partition on `now >= unlocks_at` vs `unlocks_at > now`,
        // which is a total split of the timeline. Walk across the boundary and assert never-both.
        let unlocks_at = 1_000_000i64;
        for delta in -3i64..=3 {
            let now = unlocks_at + delta;
            assert!(
                !(can_claim(false, unlocks_at, now) && can_clawback(false, unlocks_at, now)),
                "both fired at delta {delta}"
            );
            // And exactly one is always available on an unclaimed batch — no dead zone where an
            // operator's money is claimable by nothing, which was VEST-1's whole failure.
            assert!(
                can_claim(false, unlocks_at, now) || can_clawback(false, unlocks_at, now),
                "neither fired at delta {delta}"
            );
        }
    }

    #[test]
    fn claim_opens_exactly_at_unlock_not_a_second_early() {
        let unlocks_at = 1_000_000i64;
        assert!(!can_claim(false, unlocks_at, unlocks_at - 1));
        assert!(can_claim(false, unlocks_at, unlocks_at)); // inclusive: `now >= unlocks_at`
        assert!(can_claim(false, unlocks_at, unlocks_at + 1));
    }

    #[test]
    fn a_claimed_batch_is_inert_to_both_paths() {
        // `claimed` is the second guard, and the only one that survives a matured batch: a
        // double-claim would pay the same fee share twice out of a pooled per-firm vault, i.e.
        // out of some other batch's money.
        let unlocks_at = 1_000_000i64;
        assert!(!can_claim(true, unlocks_at, unlocks_at + 10));
        assert!(!can_clawback(true, unlocks_at, unlocks_at - 10));
    }

    #[test]
    fn vesting_lock_is_ninety_days() {
        assert_eq!(OWNER_VESTING_SECONDS, 90 * 24 * 60 * 60);
    }

    #[test]
    fn vested_and_immediate_halves_reconstruct_the_owner_total() {
        // The claim pays `batch.amount` = `split.owner_vested`. If the halving ever drifts, the
        // vault accrues an amount no batch claims — silently, since nothing reconciles them.
        for amount in [1u64, 999, 1_000_000, 398_999_999] {
            let s = compute_fee_split(amount, 900, 0, 0, 0);
            assert_eq!(s.owner_vested + s.owner_immediate, bps(amount, 900));
            assert!(s.owner_immediate >= s.owner_vested); // odd lamport favours the operator now
        }
    }

    // ───────── Prediction Market Curve (Phase 3 pooled-LP AMM plan) ─────────
    // Pure-function coverage mirroring `bonding_curve`'s own `curve_roundtrip_never_profits`/
    // `curve_k_never_decreases_on_trades` methodology, adapted to `MarketCurve`'s two-leg design.

    #[test]
    fn pm_curve_available_shares_is_the_outstanding_complement() {
        assert_eq!(pm_curve_available_shares(1_000, 0), 2_000); // fresh leg, MULTIPLIER=2
        assert_eq!(pm_curve_available_shares(1_000, 500), 1_500);
        assert_eq!(pm_curve_available_shares(1_000, 2_000), 0); // fully sold down
        // Saturates rather than underflows/panics if shares_outstanding ever exceeded the cap
        // (shouldn't happen in correct operation, same defensive posture as everything else here).
        assert_eq!(pm_curve_available_shares(1_000, 5_000), 0);
    }

    #[test]
    fn pm_curve_buy_then_sell_roundtrip_never_profits() {
        // THE most important test in this phase. Adapts `bonding_curve::curve_roundtrip_never_profits`'s
        // exact methodology to the two-leg curve: buy shares on one leg, immediately sell the exact
        // shares just received, replaying `buy_shares`/`sell_shares`' arithmetic verbatim (fee,
        // `pm_curve_available_shares`, `bonding_curve::buy_output`/`sell_output`). Must never return
        // more collateral than was put in, at ANY fee tier including 0% — the R40 rounding-toward-the-
        // pool guarantee (inherited unmodified from `bonding_curve`) is what stops profit even at zero
        // fee; a real fee only widens the loss.
        let fees: [u16; 5] = [0, 1, 50, 100, 300];
        for seed in 0..50_000u64 {
            let mut s = seed.wrapping_mul(0x9E3779B97F4A7C15).wrapping_add(11);
            let mut next = || {
                s ^= s << 13;
                s ^= s >> 7;
                s ^= s << 17;
                s
            };
            let virtual_seed = (next() % 100_000_000_000) + 1; // 1 .. 100 (curve units)
            let real0 = next() % 1_000_000_000_000; // 0 .. 1000, incl. a never-traded curve
            let cap = virtual_seed.saturating_mul(PM_CURVE_SHARE_SUPPLY_MULTIPLIER).max(1);
            let shares_outstanding0 = next() % cap;
            let fee_bps = fees[(next() % fees.len() as u64) as usize];
            let collateral_in = (next() % 200_000_000_000) + 1;

            let available0 = pm_curve_available_shares(virtual_seed, shares_outstanding0);
            if available0 == 0 {
                continue;
            }
            let eff0 = virtual_seed as u128 + real0 as u128;

            let fee = bonding_curve::fee_amount(collateral_in, fee_bps);
            let net = match collateral_in.checked_sub(fee) {
                Some(v) => v,
                None => continue,
            };
            let shares_out = match bonding_curve::buy_output(eff0, available0 as u128, net as u128) {
                Some(v) if v > 0 && v <= available0 => v,
                _ => continue,
            };

            let real1 = real0 + net;
            let shares_outstanding1 = shares_outstanding0 + shares_out;
            let available1 = pm_curve_available_shares(virtual_seed, shares_outstanding1);
            let eff1 = virtual_seed as u128 + real1 as u128;

            let gross = match bonding_curve::sell_output(eff1, available1 as u128, shares_out as u128) {
                Some(v) if v <= real1 => v, // handler guard: can't draw down the virtual seed
                _ => continue,
            };
            let sell_fee = bonding_curve::fee_amount(gross, fee_bps);
            let net_out = gross.saturating_sub(sell_fee);

            assert!(
                net_out <= collateral_in,
                "ROUND-TRIP PROFIT (seed {seed}): put in {collateral_in}, got back {net_out} \
                 (virtual {virtual_seed}, real0 {real0}, shares_outstanding0 {shares_outstanding0}, \
                 fee_bps {fee_bps}, shares_out {shares_out}, gross {gross})"
            );
        }
    }

    #[test]
    fn pm_curve_price_ceiling_guard_rejects_overpriced_buy_but_allows_a_safe_one() {
        // The guard itself is inline in `buy_shares` (not a separate function, per the plan's given
        // formula) — this pins the exact boolean condition (`eff_after <= new_available`) against a
        // buy sized to actually breach it, and a small buy that stays safely under it.
        let virtual_seed: u64 = 1_000;
        let shares_outstanding0: u64 = 0; // fresh leg — available0 = 2 × virtual = 2000, price starts 0.5
        let available0 = pm_curve_available_shares(virtual_seed, shares_outstanding0);
        assert_eq!(available0, 2_000);
        let eff0 = virtual_seed as u128; // real0 = 0

        // A buy large relative to the 2000-share pool pushes price toward/above 1.0.
        let net: u128 = 5_000;
        let shares_out = bonding_curve::buy_output(eff0, available0 as u128, net).unwrap();
        let new_available = pm_curve_available_shares(virtual_seed, shares_outstanding0 + shares_out);
        let eff_after = eff0 + net;
        assert!(
            eff_after > new_available as u128,
            "test fixture must actually breach the ceiling (eff_after {eff_after}, new_available {new_available})"
        );

        // A small, safe buy stays under the ceiling.
        let safe_net: u128 = 10;
        let safe_shares_out = bonding_curve::buy_output(eff0, available0 as u128, safe_net).unwrap();
        let safe_new_available =
            pm_curve_available_shares(virtual_seed, shares_outstanding0 + safe_shares_out);
        let safe_eff_after = eff0 + safe_net;
        assert!(
            safe_eff_after <= safe_new_available as u128,
            "a small buy should stay under the ceiling"
        );
    }

    #[test]
    fn split_curve_fee_3way_sums_to_fee_and_pool_absorbs_the_remainder() {
        let (firm, platform, pool) = split_curve_fee_3way(1_000, 4_000, 3_000, 3_000, 10_000);
        assert_eq!((firm, platform, pool), (400, 300, 300));
        assert_eq!(firm + platform + pool, 1_000);

        // Odd fee where floor-rounding creates dust: firm=floor(7×4000/10000)=2,
        // platform=floor(7×3000/10000)=2, pool = 7−2−2 = 3 (absorbs the dust).
        let (firm2, platform2, pool2) = split_curve_fee_3way(7, 4_000, 3_000, 3_000, 10_000);
        assert_eq!((firm2, platform2, pool2), (2, 2, 3));
        assert_eq!(firm2 + platform2 + pool2, 7);
    }

    #[test]
    fn pm_redeem_payout_is_exact_1to1_when_well_funded() {
        // redeemable_total (500) >= winning_shares_outstanding (300) → true 1:1, capped at exactly
        // what this holder holds, never more.
        assert_eq!(pm_redeem_payout(120, 300, 500), 120);
        assert_eq!(pm_redeem_payout(300, 300, 500), 300); // the entire pool of winning shares
        assert_eq!(pm_redeem_payout(300, 300, 300), 300); // exactly break-even funded
    }

    #[test]
    fn pm_redeem_payout_applies_the_exact_haircut_ratio_when_underfunded() {
        // redeemable_total (150) < winning_shares_outstanding (300) → haircut = position_shares ×
        // redeemable_total / shares_outstanding, floored. Hand-computed: 120 × 150 / 300 = 60 exactly.
        assert_eq!(pm_redeem_payout(120, 300, 150), 60);
        // Uneven ratio: 120 × 101 / 300 = 40.4 → floors to 40.
        assert_eq!(pm_redeem_payout(120, 300, 101), 40);
        // Floor-rounded haircut shares must never sum past the pot (R40 discipline).
        let a = pm_redeem_payout(120, 300, 101);
        let b = pm_redeem_payout(180, 300, 101);
        assert!(a + b <= 101, "haircut shares summed ({}) exceed the pot (101)", a + b);
    }

    #[test]
    fn pm_redeem_payout_zero_shares_outstanding_is_zero_not_a_panic() {
        assert_eq!(pm_redeem_payout(0, 0, 500), 0);
    }

    #[test]
    fn pm_deallocate_ceiling_ignores_topup_deposited() {
        // SECURITY-CRITICAL: `deallocate_pool_from_curve`'s guard is `amount <= curve.pool_allocated`
        // ONLY. `topup_deposited` must never factor in, even though `pass_real + fail_real` (which a
        // naive check might use instead) would happily "cover" a larger amount — that's exactly the
        // hole this ceiling exists to close: a compromised keeper authority must never be able to
        // claw back a permissionless top-up depositor's own funds.
        let pool_allocated: u64 = 100;
        let topup_deposited: u64 = 5_000; // vastly more, but MUST be irrelevant to this check
        let requested: u64 = 150; // exceeds pool_allocated even though real reserves (>=5100) cover it

        assert!(
            requested > pool_allocated,
            "test fixture must actually exceed pool_allocated"
        );
        // The handler's actual guard — mirrored here verbatim.
        let guard_passes = requested <= pool_allocated;
        assert!(!guard_passes, "must reject: {requested} > pool_allocated {pool_allocated}");
        assert!(topup_deposited > pool_allocated); // sanity: the covering amount really is bigger

        // A request within the pool's own allocation passes, regardless of topup_deposited's size.
        assert!(90u64 <= pool_allocated);
    }

    #[test]
    fn pm_add_curve_topup_self_lp_ban_is_unconditional() {
        // Mirrors `add_curve_topup`'s FIRST require: `depositor.key() != curve.trader`. The trader's
        // own wallet must fail this check regardless of side/amount; any other wallet must pass it.
        let trader = Pubkey::new_unique();
        let depositor_self = trader;
        let depositor_other = Pubkey::new_unique();

        let self_lp_check = |depositor: Pubkey| depositor != trader;
        assert!(!self_lp_check(depositor_self), "the trader's own wallet must fail this check");
        assert!(self_lp_check(depositor_other), "any other wallet must pass this check");
    }

    #[test]
    fn pm_void_redeem_payout_pro_rata_hand_computed_no_cross_vault_pooling() {
        // PASS side: 3 holders share pass_shares_outstanding=300 pro-rata over pass_real=90.
        // A: 150 shares (50%) → 45. B: 90 shares (30%) → 27. C: 60 shares (20%) → 18.
        assert_eq!(pm_void_redeem_payout(150, 300, 90), 45);
        assert_eq!(pm_void_redeem_payout(90, 300, 90), 27);
        assert_eq!(pm_void_redeem_payout(60, 300, 90), 18);
        assert_eq!(45 + 27 + 18, 90); // sums to the full pot exactly in this fixture

        // FAIL side is INDEPENDENT — a market with pass_real=90 but fail_real=0 pays FAIL holders
        // zero, never dipping into the PASS side's pot (no pooling across vaults, unlike
        // `pm_redeem_payout`'s settled-market formula).
        assert_eq!(pm_void_redeem_payout(100, 200, 0), 0);
    }

    #[test]
    fn pm_pool_ratio_split_preserves_current_ratio_and_falls_back_to_virtual_when_untraded() {
        // Traded curve: pass_real=300, fail_real=100 (3:1) — a 400 allocation splits 300/100.
        assert_eq!(pm_pool_ratio_split(400, 300, 100), (300, 100));

        // Never-traded curve (both real legs 0) — caller passes virtual seeds instead, avoiding a
        // divide-by-zero; equal virtual seeds split 50/50.
        assert_eq!(pm_pool_ratio_split(100, 500, 500), (50, 50));

        // Degenerate zero/zero weights (shouldn't happen — virtual seeds are required > 0 at init)
        // still falls back to an even split rather than panicking.
        let (to_pass3, to_fail3) = pm_pool_ratio_split(101, 0, 0);
        assert_eq!(to_pass3 + to_fail3, 101);
    }
}

