import { expect } from "chai";
import { SystemProgram } from "@solana/web3.js";
import {
  anchor,
  ata,
  bn,
  firma,
  fundedWallet,
  getProvider,
  Keypair,
  loadPrograms,
  mintSolTo,
  payerOf,
  type Programs,
  PublicKey,
  sol,
} from "./_env.js";
import { deployFirm, ensurePlatformBuyback, type FirmFixture } from "./_firm.js";
import * as pda from "./_pdas.js";

/**
 * §19/§25 stress: a payout the treasury can't satisfy in one daily-capped fill must
 * (a) deliver a partial amount, (b) trip the velocity breaker, and (c) auto-escalate the
 * risk tier one step immediately — and a second same-day fill must hit the daily cap.
 *
 * Numbers (tier 1, base units): a 10k SOL fee leaves treasury_gross = 55% = 5,500 SOL,
 * so the daily cap is 20% = 1,100 SOL. We owe the trader 50,000,000 $FIRMA — far more
 * than 1,100 SOL buys from the curve — so the first capped fill is necessarily partial.
 */
describe("Phase 10 — drawdown → partial fill → circuit breaker → tier escalation", () => {
  let provider: anchor.AnchorProvider;
  let programs: Programs;
  let fx: FirmFixture;
  let keeper: Keypair;
  let trader: Keypair;
  let challenge: PublicKey;
  let traderFirma: PublicKey;
  let ownerFirma: PublicKey;
  let stakingVault: PublicKey;
  let platformSol: PublicKey;

  const FEE = sol(10_000); // → treasury_gross 5,500 SOL → daily cap 1,100 SOL
  const OWED = firma(50_000_000); // unsatisfiable in one capped fill
  const CAP = sol(1_100); // == the daily cap

  before(async () => {
    provider = getProvider();
    programs = loadPrograms(provider);
    // Enforced 3% buyback routing → shared platform SOL + the canonical PDA vault.
    const buyback = await ensurePlatformBuyback(provider, programs);
    fx = await deployFirm(provider, programs, { tier: 1, solMint: buyback.solMint });
    // Settlement authority IS the firm's risk-engine authority (payout path binds
    // challenge.settlement_authority == firm.risk_engine_authority).
    keeper = fx.riskEngine;
    const payer = payerOf(provider);
    trader = await fundedWallet(provider);
    const traderSol = await mintSolTo(provider, payer, fx.solMint, trader.publicKey, FEE);
    // Funded phase (2): this flow settles a large payout, which only a funded challenge may owe.
    [challenge] = pda.challengePda(fx.firm, trader.publicKey, fx.tier, 2);

    const dpProfit = await ata(provider, payer, fx.solMint, Keypair.generate().publicKey);
    const dpTreasury = await ata(provider, payer, fx.solMint, Keypair.generate().publicKey);
    const dpropBuyback = buyback.solVault; // canonical PDA — enforced on-chain
    platformSol = await ata(provider, payer, fx.solMint, payer.publicKey);
    traderFirma = await ata(provider, payer, fx.firmaMint, trader.publicKey);
    ownerFirma = await ata(provider, payer, fx.firmaMint, fx.owner.publicKey);
    // staking_vault just needs to be a $FIRMA token account (constraint: token::mint).
    stakingVault = await ata(provider, payer, fx.firmaMint, Keypair.generate().publicKey);

    // Init the staking pool FIRST so the normal-staking 5% leg below routes into it (§19 DEC-1)
    // rather than the firm's own treasury — this file's numbers (`treasury_gross = 55%`, the
    // 1,100 SOL daily cap) are calibrated assuming the 5% leaves the treasury leg entirely, same
    // as the pre-DEC-1 legacy-vault routing did.
    await programs.firm.methods
      .initStakingPool()
      .accountsPartial({
        payer: payerOf(provider).publicKey,
        firmState: fx.firm,
        firmaMint: fx.firmaMint,
        solMint: fx.solMint,
      })
      .rpc();

    // Purchase → fund treasury → settle (large owed) → enqueue (under concentration guard).
    await programs.challenge.methods
      .purchaseChallenge(fx.tier, 2, rules(), false)
      .accountsPartial({
        trader: trader.publicKey,
        firm: fx.firm,
        settlementAuthority: keeper.publicKey,
        challenge,
        systemProgram: SystemProgram.programId,
      })
      .signers([trader, keeper])
      .rpc();
    await programs.firm.methods
      .payChallengeFee(bn(FEE))
      .accountsPartial({
        trader: trader.publicKey,
        traderSol,
        firmState: fx.firm,
        curve: fx.curve,
        curveSolVault: fx.curveSolVault,
        treasuryVault: fx.treasuryVault,
        ownerWalletSol: fx.ownerSol,
        dpProfitSol: dpProfit,
        dpTreasurySol: dpTreasury,
        dpropBuybackVault: dpropBuyback,
        referral: null,
        affiliateAccount: null,
        affiliatePoolVault: null,
        backstopPool: null,
        backstopPremiumVault: null,
        // §19 DEC-1: real staking-pool accounts (init'd above) — the normal-staking 5% routes
        // there, not the treasury, preserving this file's `treasury_gross = 55%` calibration.
        stakingPool: pda.stakingPoolPda(fx.firm)[0],
        solRewardVault: pda.stakingSolVaultPda(fx.firm)[0],
        stakerPosition: null,
        challenge,
        bondingCurveProgram: pda.PROGRAM_IDS.bondingCurve,
      })
      .signers([trader])
      .rpc();
    await programs.challenge.methods
      .settleChallenge(true, bn(0), bn(0), bn(OWED), { caution: {} })
      .accountsStrict({ authority: keeper.publicKey, challenge })
      .signers([keeper])
      .rpc();
    await programs.firm.methods
      .enqueuePayout(bn(sol(400)), 0, 0) // sol_at_settlement < 8% of treasury → no hold
      .accountsPartial({
        authority: keeper.publicKey,
        challenge,
        firmState: fx.firm,
        queuedPayout: pda.payoutPda(challenge)[0],
        systemProgram: SystemProgram.programId,
      })
      .signers([keeper])
      .rpc();
  });

  function processFill(solAmount: bigint) {
    return programs.firm.methods
      .processQueuedPayout(bn(solAmount), bn(0))
      .accountsPartial({
        authority: keeper.publicKey,
        challenge,
        firmState: fx.firm,
        queuedPayout: pda.payoutPda(challenge)[0],
        treasuryVault: fx.treasuryVault,
        curve: fx.curve,
        curveSolVault: fx.curveSolVault,
        curveFirmaVault: fx.curveFirmaVault,
        payoutFirmaVault: pda.payoutFirmaVaultPda(fx.firm)[0],
        firmaMint: fx.firmaMint,
        traderFirma,
        ownerFirma,
        stakingVault,
        platformSol,
        bondingCurveProgram: pda.PROGRAM_IDS.bondingCurve,
      })
      .signers([keeper])
      .rpc();
  }

  it("starts healthy-ish: CAUTION, breaker clear, nothing delivered", async () => {
    const s: any = await programs.firm.account.firmState.fetch(fx.firm);
    expect(s.riskTier).to.have.property("caution");
    expect(s.velocityBreakFlag).to.equal(false);
    const qp: any = await programs.firm.account.queuedPayout.fetch(pda.payoutPda(challenge)[0]);
    expect(qp.firmaAmountDelivered.toString()).to.equal("0");
    expect(qp.firmaAmountOwed.toString()).to.equal(OWED.toString());
  });

  it("a capped fill that can't satisfy the payout delivers partially", async () => {
    await processFill(CAP);
    const qp: any = await programs.firm.account.queuedPayout.fetch(pda.payoutPda(challenge)[0]);
    const delivered = BigInt(qp.firmaAmountDelivered.toString());
    expect(delivered > 0n).to.equal(true);
    expect(delivered < OWED).to.equal(true); // partial — payout still outstanding
  });

  it("trips the velocity breaker and auto-escalates one tier (CAUTION → WARNING)", async () => {
    const s: any = await programs.firm.account.firmState.fetch(fx.firm);
    expect(s.velocityBreakFlag).to.equal(true);
    expect(s.riskTier).to.have.property("warning"); // exactly one step, immediate
  });

  it("a second same-day fill is rejected by the 20% daily cap", async () => {
    let threw = "";
    try {
      await processFill(CAP);
    } catch (e: any) {
      threw = e.toString();
    }
    expect(threw).to.match(/DailyPayoutCapExceeded/);
  });
});

function rules() {
  return {
    profitTargetBps: 1000,
    maxDailyLossBps: 500,
    maxTotalDrawdownBps: 1000,
    isTrailingDrawdown: false,
    startingBalance: bn(sol(100_000)),
    minTradingDays: 1,
    maxTradingDays: 30,
    maxOpenPositions: 5,
    maxPositionSizeBps: 2000,
    maxLeverageBps: 10000,
    allowWeekendHolding: true,
    allowNewsTrading: true,
    baseSpreadBps: 2,
    dynamicSpread: false,
    simulateSlippage: false,
    minHoldTimeSeconds: 0,
    maxPriceAgeSeconds: 60,
    consistencyRuleBps: 0,
    maxSingleTradeProfitBps: 10000,
    dailyVarianceGate: false,
    traderSplitBps: 8000,
    stakeholderSplitBps: 2000,
  };
}
