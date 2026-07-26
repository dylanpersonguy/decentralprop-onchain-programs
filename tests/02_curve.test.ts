import { expect } from "chai";
import {
  anchor,
  ata,
  bn,
  getProvider,
  loadPrograms,
  payerOf,
  type Programs,
  PublicKey,
  tokenBalance,
  sol,
} from "./_env.js";
import { CURVE_VIRTUAL_SOL, deployFirm, type FirmFixture, makeTrader } from "./_firm.js";
import * as pda from "./_pdas.js";

// TS mirrors of the on-chain §20 AMM math (asserted against live token movement).
const feeAmount = (amount: bigint, feeBps: bigint) => (amount * feeBps) / 10_000n;
const splitFee = (fee: bigint): [bigint, bigint] => {
  const platform = fee / 2n;
  return [fee - platform, platform]; // firm takes the rounding remainder
};
const buyOutput = (effSol: bigint, firmaReserve: bigint, netIn: bigint): bigint => {
  const k = effSol * firmaReserve;
  const newX = effSol + netIn;
  return firmaReserve - k / newX;
};

describe("Phase 10 — bonding curve trade (real SPL, §20 math)", () => {
  let provider: anchor.AnchorProvider;
  let programs: Programs;
  let fx: FirmFixture;
  let platformSol: PublicKey;

  before(async () => {
    provider = getProvider();
    programs = loadPrograms(provider);
    fx = await deployFirm(provider, programs, { tier: 1 });
    platformSol = await ata(provider, payerOf(provider), fx.solMint, payerOf(provider).publicKey);
  });

  it("buy: delivers exactly buy_output() $FIRMA and splits the 1% fee 50/50", async () => {
    const { trader, traderSol } = await makeTrader(provider, fx.solMint, sol(2000));
    const traderFirma = await ata(provider, payerOf(provider), fx.firmaMint, trader.publicKey);

    const solIn = sol(1000); // 1,000 SOL
    const fee = feeAmount(solIn, 100n);
    const net = solIn - fee;
    const [firmFee, platformFee] = splitFee(fee);
    const expectedFirmaOut = buyOutput(CURVE_VIRTUAL_SOL /* real=0 */, 180_000_000_000_000n, net);

    const traderSolBefore = await tokenBalance(provider, traderSol);
    const platformBefore = await tokenBalance(provider, platformSol);

    await programs.bondingCurve.methods
      .buy(bn(solIn), bn(0))
      .accountsPartial({
        trader: trader.publicKey,
        curve: fx.curve,
        solVault: fx.curveSolVault,
        firmaVault: fx.curveFirmaVault,
        traderSol,
        traderFirma,
        firmTreasurySol: fx.treasuryVault,
        platformSol,
      })
      .signers([trader])
      .rpc();

    expect((await tokenBalance(provider, traderFirma)).toString()).to.equal(
      expectedFirmaOut.toString(),
    );
    expect((traderSolBefore - (await tokenBalance(provider, traderSol))).toString()).to.equal(
      solIn.toString(),
    );
    expect((await tokenBalance(provider, fx.curveSolVault)).toString()).to.equal(net.toString());
    expect(((await tokenBalance(provider, platformSol)) - platformBefore).toString()).to.equal(
      platformFee.toString(),
    );
    expect((await tokenBalance(provider, fx.treasuryVault)).toString()).to.equal(firmFee.toString());

    const curve: any = await programs.bondingCurve.account.bondingCurve.fetch(fx.curve);
    expect(curve.realSol.toString()).to.equal(net.toString());
    expect(curve.firmaReserve.toString()).to.equal((180_000_000_000_000n - expectedFirmaOut).toString());
  });

  it("buy: slippage floor (min_firma_out too high) reverts", async () => {
    const { trader, traderSol } = await makeTrader(provider, fx.solMint, sol(2000));
    const traderFirma = await ata(provider, payerOf(provider), fx.firmaMint, trader.publicKey);
    let threw = false;
    try {
      await programs.bondingCurve.methods
        .buy(bn(sol(100)), bn(10_000_000_000_000_000n)) // impossibly high min out
        .accountsPartial({
          trader: trader.publicKey,
          curve: fx.curve,
          solVault: fx.curveSolVault,
          firmaVault: fx.curveFirmaVault,
          traderSol,
          traderFirma,
          firmTreasurySol: fx.treasuryVault,
          platformSol,
        })
        .signers([trader])
        .rpc();
    } catch {
      threw = true;
    }
    expect(threw).to.equal(true);
  });

  it("sell: round-trips $FIRMA back to SOL (virtual seed never withdrawn)", async () => {
    const { trader, traderSol } = await makeTrader(provider, fx.solMint, sol(2000));
    const traderFirma = await ata(provider, payerOf(provider), fx.firmaMint, trader.publicKey);

    await programs.bondingCurve.methods
      .buy(bn(sol(500)), bn(0))
      .accountsPartial({
        trader: trader.publicKey,
        curve: fx.curve,
        solVault: fx.curveSolVault,
        firmaVault: fx.curveFirmaVault,
        traderSol,
        traderFirma,
        firmTreasurySol: fx.treasuryVault,
        platformSol,
      })
      .signers([trader])
      .rpc();

    const firmaHeld = await tokenBalance(provider, traderFirma);
    expect(firmaHeld > 0n).to.equal(true);
    const solBeforeSell = await tokenBalance(provider, traderSol);

    await programs.bondingCurve.methods
      .sell(bn(firmaHeld), bn(0))
      .accountsPartial({
        trader: trader.publicKey,
        curve: fx.curve,
        solVault: fx.curveSolVault,
        firmaVault: fx.curveFirmaVault,
        traderSol,
        traderFirma,
        firmTreasurySol: fx.treasuryVault,
        platformSol,
      })
      .signers([trader])
      .rpc();

    // Sold everything back: FIRMA → 0, SOL recovered (minus the two 1% fees + curve slippage).
    expect((await tokenBalance(provider, traderFirma)).toString()).to.equal("0");
    expect((await tokenBalance(provider, traderSol)) > solBeforeSell).to.equal(true);
  });
});
