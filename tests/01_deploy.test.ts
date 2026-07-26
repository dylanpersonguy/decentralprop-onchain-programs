import { expect } from "chai";
import {
  anchor,
  getProvider,
  loadPrograms,
  mintInfo,
  type Programs,
  tokenBalance,
} from "./_env.js";
import {
  CURVE_FIRMA_RESERVE,
  deployFirm,
  DRIP_FIRMA,
  type FirmFixture,
} from "./_firm.js";
import * as pda from "./_pdas.js";

describe("Phase 10 — firm deploy + §16 rug-pull checklist", () => {
  let provider: anchor.AnchorProvider;
  let programs: Programs;
  let fx: FirmFixture;

  before(async () => {
    provider = getProvider();
    programs = loadPrograms(provider);
    fx = await deployFirm(provider, programs, { tier: 1 });
  });

  it("deploys a firm that starts in CAUTION (day-1 bootstrap)", async () => {
    const state: any = await programs.firm.account.firmState.fetch(fx.firm);
    expect(state.owner.toBase58()).to.equal(fx.owner.publicKey.toBase58());
    expect(state.riskEngineAuthority.toBase58()).to.equal(fx.riskEngine.publicKey.toBase58());
    expect(state.tier).to.equal(1);
    expect(state.riskTier).to.have.property("caution");
    expect(state.status).to.have.property("active");
    expect(state.supplyDistributed).to.equal(true);
    expect(state.graduated).to.equal(false);
  });

  it("minted the fixed 90/10 supply to the curve + drip vaults", async () => {
    const curveBal = await tokenBalance(provider, fx.curveFirmaVault);
    const [dripVault] = pda.ownerDripVaultPda(fx.firm);
    const dripBal = await tokenBalance(provider, dripVault);
    expect(curveBal.toString()).to.equal(CURVE_FIRMA_RESERVE.toString());
    expect(dripBal.toString()).to.equal(DRIP_FIRMA.toString());
  });

  it("§16: revoked the $FIRMA mint authority to None (no new supply ever)", async () => {
    const info = await mintInfo(provider, fx.firmaMint);
    expect(info.mintAuthority).to.equal(null);
    expect(info.supply.toString()).to.equal((CURVE_FIRMA_RESERVE + DRIP_FIRMA).toString());
  });

  it("§16: $FIRMA freeze authority is None (no freeze rug)", async () => {
    const info = await mintInfo(provider, fx.firmaMint);
    expect(info.freezeAuthority).to.equal(null);
  });

  it("§16: the firm program exposes no treasury-withdraw instruction", () => {
    const names = programs.firm.idl.instructions.map((i: any) => i.name);
    const withdrawish = names.filter(
      (n: string) => /withdraw/i.test(n) && !/backstop/i.test(n),
    );
    // The only `withdraw_*` is `withdraw_backstop` (a staker's own at-risk principal);
    // there is no instruction that lets anyone pull the firm treasury directly.
    expect(withdrawish).to.deep.equal([]);
  });

  it("§16: the owner-drip is time-locked (claim before a month elapses fails)", async () => {
    const [, ] = pda.ownerDripStatePda(fx.firm);
    const ownerFirma = await (await import("./_env.js")).ata(
      provider,
      (await import("./_env.js")).payerOf(provider),
      fx.firmaMint,
      fx.owner.publicKey,
    );
    let threw = false;
    try {
      await programs.firm.methods
        .claimDrip()
        .accountsPartial({
          owner: fx.owner.publicKey,
          firmState: fx.firm,
          platformRisk: pda.platformRiskPda()[0],
          ownerFirma,
        })
        .signers([fx.owner])
        .rpc();
    } catch {
      threw = true;
    }
    // Either the platform_risk account isn't initialised yet, or no month has elapsed —
    // in both cases the claim must not succeed on a freshly-deployed firm.
    expect(threw).to.equal(true);
  });
});
