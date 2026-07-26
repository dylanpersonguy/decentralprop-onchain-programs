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
  tokenBalance,
  sol,
} from "./_env.js";
import { deployFirm, ensurePlatformBuyback, type FirmFixture } from "./_firm.js";
import * as pda from "./_pdas.js";

// §17 fee split (tier 1 / Growth, owner 7.5%, LP 11% at zero depth) — used to assert exact routing.
const bps = (amount: bigint, b: bigint) => (amount * b) / 10_000n;

/** Minimal valid RulesSnapshot (camelCased IDL struct). */
const rules = (startingBalance: bigint) => ({
  profitTargetBps: 1000,
  maxDailyLossBps: 500,
  maxTotalDrawdownBps: 1000,
  isTrailingDrawdown: false,
  startingBalance: bn(startingBalance),
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
});

describe("Phase 10 — full challenge lifecycle (purchase → fee split → settle → payout → close)", () => {
  let provider: anchor.AnchorProvider;
  let programs: Programs;
  let fx: FirmFixture;
  let keeper: Keypair; // settlement authority
  let trader: Keypair;
  let traderSol: PublicKey;
  let challenge: PublicKey;
  let dpProfit: PublicKey;
  let dpTreasury: PublicKey;
  let dpropBuyback: PublicKey;
  let platformSol: PublicKey;

  const FEE = sol(100_000); // 100k SOL challenge fee → big treasury for clean assertions
  const OWED = firma(500); // trader-owed $FIRMA payout

  before(async () => {
    provider = getProvider();
    programs = loadPrograms(provider);
    // The 3% $DPROP buy-back leg is enforced into the canonical PDA vault, so this firm must use
    // the shared platform SOL mint and the buyback singleton must be initialised first.
    const buyback = await ensurePlatformBuyback(provider, programs);
    fx = await deployFirm(provider, programs, { tier: 1, solMint: buyback.solMint });
    // Settlement authority IS the firm's risk-engine authority (one platform authority). The
    // payout path binds challenge.settlement_authority == firm.risk_engine_authority, so a
    // self-set authority can never move firm funds.
    keeper = fx.riskEngine;
    const payer = payerOf(provider);
    trader = await fundedWallet(provider);
    traderSol = await mintSolTo(provider, payer, fx.solMint, trader.publicKey, FEE);
    dpProfit = await ata(provider, payer, fx.solMint, Keypair.generate().publicKey);
    dpTreasury = await ata(provider, payer, fx.solMint, Keypair.generate().publicKey);
    dpropBuyback = buyback.solVault; // canonical PDA — enforced on-chain, not an arbitrary ATA
    platformSol = await ata(provider, payer, fx.solMint, payer.publicKey);
    // Funded phase (2): this lifecycle settles a payout, which only a funded challenge may owe.
    [challenge] = pda.challengePda(fx.firm, trader.publicKey, fx.tier, 2);
  });

  it("purchase_challenge locks an immutable RulesSnapshot (status Active)", async () => {
    await programs.challenge.methods
      .purchaseChallenge(fx.tier, 2, rules(FEE), false)
      .accountsPartial({
        trader: trader.publicKey,
        firm: fx.firm,
        settlementAuthority: keeper.publicKey,
        challenge,
        systemProgram: SystemProgram.programId,
      })
      .signers([trader, keeper])
      .rpc();

    const c: any = await programs.challenge.account.challengeState.fetch(challenge);
    expect(c.trader.toBase58()).to.equal(trader.publicKey.toBase58());
    expect(c.firm.toBase58()).to.equal(fx.firm.toBase58());
    expect(c.settlementAuthority.toBase58()).to.equal(keeper.publicKey.toBase58());
    expect(c.status).to.have.property("active");
    expect(c.rulesSnapshot.profitTargetBps).to.equal(1000);
  });

  it("pay_challenge_fee routes the exact §17 split + keeps treasury in sync", async () => {
    // The $DPROP buy-back vault is the global canonical PDA (shared across all firms), so assert
    // the delta this fee contributes, not its absolute balance.
    const buybackBefore = BigInt((await tokenBalance(provider, dpropBuyback)).toString());
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
        // No referral / backstop in this test → optional accounts passed null (Anchor 0.31). The
        // affiliate carve is 0 (the 10% stays in the firm treasury). The staking pool isn't
        // init'd until later in this file (`initStakingPool` at line ~215), so `stakingPool: null`
        // (§19 DEC-1) means the normal-staking 5% stays in the firm's own treasury — asserted
        // below. `solRewardVault` is NOT optional on-chain (stack budget); reusing `treasuryVault`
        // as the inert placeholder, matching the SDK builder's convention.
        referral: null,
        affiliateAccount: null,
        affiliatePoolVault: null,
        backstopPool: null,
        backstopPremiumVault: null,
        stakingPool: null,
        solRewardVault: fx.treasuryVault,
        stakerPosition: null,
        challenge,
        bondingCurveProgram: pda.PROGRAM_IDS.bondingCurve,
      })
      .signers([trader])
      .rpc();

    const [insuranceVault] = pda.insuranceVaultPda(fx.firm);
    const [ownerVestingVault] = pda.ownerVestingVaultPda(fx.firm);
    expect((await tokenBalance(provider, dpProfit)).toString()).to.equal(bps(FEE, 800n).toString());
    expect((await tokenBalance(provider, dpTreasury)).toString()).to.equal(bps(FEE, 300n).toString());
    expect((await tokenBalance(provider, insuranceVault)).toString()).to.equal(
      bps(FEE, 200n).toString(),
    );
    // $DPROP buy-back 1% accumulator. The normal-staking 5% has no `stakingPool` here (not init'd
    // yet), so §19 DEC-1 folds it into the firm's own treasury instead — asserted via
    // `treasuryGross` below, which now INCLUDES that 5% rather than subtracting it.
    const buybackAfter = BigInt((await tokenBalance(provider, dpropBuyback)).toString());
    expect((buybackAfter - buybackBefore).toString()).to.equal(bps(FEE, 100n).toString());
    // owner 7.5% (tier 1 / Growth) split half immediate / half vested
    const ownerBps = 750n;
    expect((await tokenBalance(provider, fx.ownerSol)).toString()).to.equal(
      (bps(FEE, ownerBps) - bps(FEE, ownerBps) / 2n).toString(),
    );
    expect((await tokenBalance(provider, ownerVestingVault)).toString()).to.equal(
      (bps(FEE, ownerBps) / 2n).toString(),
    );
    // LP 11% (zero depth) routed into the curve (bonding-curve stage)
    const curve: any = await programs.bondingCurve.account.bondingCurve.fetch(fx.curve);
    expect(curve.realSol.toString()).to.equal(bps(FEE, 1100n).toString());
    // treasury gross = remainder (unreferred → no affiliate carve), vault == accounting field.
    // §19 DEC-1: normal-staking 5% is NOT subtracted — with no `stakingPool` passed, it stays in
    // the firm's own treasury instead of a separate vault.
    const treasuryGross =
      FEE -
      bps(FEE, 800n) -  // dp_profit 8%
      bps(FEE, 300n) -  // dp_treasury 3%
      bps(FEE, 200n) -  // insurance 2%
      bps(FEE, ownerBps) - // owner 7.5% (tier 1)
      bps(FEE, 1100n) - // LP 11%
      bps(FEE, 100n) -  // $DPROP buy-back 1%
      bps(FEE, 1000n) - // $DPROP staking 10%
      bps(FEE, 200n);   // loss-back 2%
    expect((await tokenBalance(provider, fx.treasuryVault)).toString()).to.equal(treasuryGross.toString());
    const state: any = await programs.firm.account.firmState.fetch(fx.firm);
    expect(state.treasurySol.toString()).to.equal(treasuryGross.toString());
  });

  it("settle_challenge records the outcome + owed payout (opens dispute window)", async () => {
    await programs.challenge.methods
      .settleChallenge(true, bn(0), bn(0), bn(OWED), { caution: {} })
      .accountsStrict({ authority: keeper.publicKey, challenge })
      .signers([keeper])
      .rpc();
    const c: any = await programs.challenge.account.challengeState.fetch(challenge);
    expect(c.status).to.have.property("passed");
    expect(c.payoutFirmaOwed.toString()).to.equal(OWED.toString());
  });

  it("enqueue_payout queues the passed challenge (under the concentration guard → no hold)", async () => {
    await programs.firm.methods
      .enqueuePayout(bn(sol(1000)), 0, 0)
      .accountsPartial({
        authority: keeper.publicKey,
        challenge,
        firmState: fx.firm,
        queuedPayout: pda.payoutPda(challenge)[0],
        systemProgram: SystemProgram.programId,
      })
      .signers([keeper])
      .rpc();
    const qp: any = await programs.firm.account.queuedPayout.fetch(pda.payoutPda(challenge)[0]);
    expect(qp.firmaAmountOwed.toString()).to.equal(OWED.toString());
    expect(qp.holdUntil.toString()).to.equal("0");
    expect(qp.settlementTier).to.equal(1); // Caution
  });

  it("process_queued_payout fully fills the trader leg from a treasury market-buy", async () => {
    // Init the staking pool so the stakeholder staking leg has a real vault.
    await programs.firm.methods
      .initStakingPool()
      .accountsPartial({
        payer: payerOf(provider).publicKey,
        firmState: fx.firm,
        firmaMint: fx.firmaMint,
        solMint: fx.solMint,
      })
      .rpc();

    const payer = payerOf(provider);
    const traderFirma = await ata(provider, payer, fx.firmaMint, trader.publicKey);
    const ownerFirma = await ata(provider, payer, fx.firmaMint, fx.owner.publicKey);
    const [stakingVault] = pda.stakingFirmaVaultPda(fx.firm);

    const treasuryBefore = await tokenBalance(provider, fx.treasuryVault);

    await programs.firm.methods
      .processQueuedPayout(bn(sol(1)), bn(0))
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

    const qp: any = await programs.firm.account.queuedPayout.fetch(pda.payoutPda(challenge)[0]);
    expect(qp.firmaAmountDelivered.toString()).to.equal(OWED.toString()); // fully filled
    expect((await tokenBalance(provider, traderFirma)).toString()).to.equal(OWED.toString());
    expect((await tokenBalance(provider, fx.treasuryVault)) < treasuryBefore).to.equal(true);
    // No circuit breaker on a successful full fill.
    const state: any = await programs.firm.account.firmState.fetch(fx.firm);
    expect(state.velocityBreakFlag).to.equal(false);
  });

  it("close_queued_payout reclaims rent once fully delivered", async () => {
    await programs.firm.methods
      .closeQueuedPayout()
      .accountsPartial({
        trader: trader.publicKey,
        challenge,
        queuedPayout: pda.payoutPda(challenge)[0],
      })
      .signers([trader])
      .rpc();
    const info = await provider.connection.getAccountInfo(pda.payoutPda(challenge)[0]);
    expect(info).to.equal(null); // closed
  });
});
