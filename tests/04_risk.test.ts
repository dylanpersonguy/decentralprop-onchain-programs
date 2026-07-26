import { expect } from "chai";
import {
  anchor,
  getProvider,
  Keypair,
  loadPrograms,
  type Programs,
} from "./_env.js";
import { deployFirm, type FirmFixture } from "./_firm.js";
import * as pda from "./_pdas.js";

const T = {
  healthy: { healthy: {} },
  caution: { caution: {} },
  warning: { warning: {} },
  critical: { critical: {} },
};

/** Drive `update_risk_tier` as the firm's risk-engine authority. */
async function setTier(programs: Programs, fx: FirmFixture, tier: any, signer: Keypair) {
  await programs.firm.methods
    .updateRiskTier(tier)
    .accountsStrict({ authority: signer.publicKey, firmState: fx.firm })
    .signers([signer])
    .rpc();
}

describe("Phase 10 — §25 ARE risk-tier control surface guards", () => {
  let provider: anchor.AnchorProvider;
  let programs: Programs;
  let fx: FirmFixture;

  before(async () => {
    provider = getProvider();
    programs = loadPrograms(provider);
    fx = await deployFirm(provider, programs, { tier: 1 }); // starts in CAUTION
  });

  it("escalation is immediate, one step at a time (Caution → Warning → Critical)", async () => {
    await setTier(programs, fx, T.warning, fx.riskEngine);
    let s: any = await programs.firm.account.firmState.fetch(fx.firm);
    expect(s.riskTier).to.have.property("warning");

    await setTier(programs, fx, T.critical, fx.riskEngine);
    s = await programs.firm.account.firmState.fetch(fx.firm);
    expect(s.riskTier).to.have.property("critical");
  });

  it("rejects a jump of more than one tier (TierJumpTooLarge)", async () => {
    // From Critical, jumping straight to Healthy is a 3-step move.
    let threw = "";
    try {
      await setTier(programs, fx, T.healthy, fx.riskEngine);
    } catch (e: any) {
      threw = e.toString();
    }
    expect(threw).to.match(/TierJumpTooLarge/);
  });

  it("relaxation is time-locked (Critical → Warning is blocked immediately)", async () => {
    let threw = "";
    try {
      await setTier(programs, fx, T.warning, fx.riskEngine);
    } catch (e: any) {
      threw = e.toString();
    }
    expect(threw).to.match(/RelaxationTimelockActive/);
  });

  it("only the risk-engine authority may move the tier", async () => {
    const imposter = Keypair.generate();
    await provider.connection.confirmTransaction(
      await provider.connection.requestAirdrop(imposter.publicKey, 1_000_000_000),
    );
    let threw = "";
    try {
      // Even a valid one-step escalation fails for a non-authority signer.
      await programs.firm.methods
        .setVelocityBreak(true)
        .accountsStrict({ authority: imposter.publicKey, firmState: fx.firm })
        .signers([imposter])
        .rpc();
    } catch (e: any) {
      threw = e.toString();
    }
    expect(threw).to.match(/Unauthorized|ConstraintRaw|constraint/i);
  });

  it("the risk engine can trip + clear the velocity breaker", async () => {
    await programs.firm.methods
      .setVelocityBreak(true)
      .accountsStrict({ authority: fx.riskEngine.publicKey, firmState: fx.firm })
      .signers([fx.riskEngine])
      .rpc();
    let s: any = await programs.firm.account.firmState.fetch(fx.firm);
    expect(s.velocityBreakFlag).to.equal(true);

    await programs.firm.methods
      .setVelocityBreak(false)
      .accountsStrict({ authority: fx.riskEngine.publicKey, firmState: fx.firm })
      .signers([fx.riskEngine])
      .rpc();
    s = await programs.firm.account.firmState.fetch(fx.firm);
    expect(s.velocityBreakFlag).to.equal(false);
  });
});
