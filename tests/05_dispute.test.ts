import { createHash } from "node:crypto";
import { expect } from "chai";
import { SystemProgram } from "@solana/web3.js";
import {
  anchor,
  bn,
  firma,
  fundedWallet,
  getProvider,
  Keypair,
  loadPrograms,
  type Programs,
  PublicKey,
  sol,
} from "./_env.js";
import { deployFirm, type FirmFixture } from "./_firm.js";
import * as pda from "./_pdas.js";

// TS mirror of the dispute program's domain-separated SHA-256 Merkle hashing
// (`leaf:` / `node:`). The cross-language vector is already asserted in Rust; here we
// build a real proof off-chain and verify the on-chain program accepts it.
const sha = (s: string) => createHash("sha256").update(s).digest("hex");
const hashLeaf = (d: string) => sha(`leaf:${d}`);
const hashPair = (l: string, r: string) => sha(`node:${l}${r}`);

const STAKE = 2_000_000_000; // MIN_OPERATOR_STAKE_LAMPORTS (2 SOL)

describe("Phase 10 — dispute Merkle-proof verification + operator slash (§7)", () => {
  let provider: anchor.AnchorProvider;
  let programs: Programs;
  let fx: FirmFixture;
  let keeper: Keypair;
  let trader: Keypair;
  let challenge: PublicKey;

  // Hourly epoch bucket (epoch_start = epoch*3600); commit must land within 2h.
  const epoch = Math.floor(Date.now() / 1000 / 3600);
  // 2-leaf tree over tick hashes "t0","t1"; we dispute "t0".
  const leaf0 = hashLeaf("t0");
  const leaf1 = hashLeaf("t1");
  const root = hashPair(leaf0, leaf1);
  const rootBytes = Array.from(Buffer.from(root, "hex"));
  const goodProof = [{ sibling: leaf1, siblingOnRight: true }];
  const badProof = [{ sibling: leaf1, siblingOnRight: false }];

  before(async () => {
    provider = getProvider();
    programs = loadPrograms(provider);
    fx = await deployFirm(provider, programs, { tier: 1 });
    // Settlement authority IS the firm's risk-engine authority (payout path binds
    // challenge.settlement_authority == firm.risk_engine_authority).
    keeper = fx.riskEngine;
    trader = await fundedWallet(provider);
    [challenge] = pda.challengePda(fx.firm, trader.publicKey, fx.tier);

    // Purchase + settle a challenge so there is something to dispute.
    await programs.challenge.methods
      .purchaseChallenge(fx.tier, 0, minimalRules(), false)
      .accountsPartial({
        trader: trader.publicKey,
        firm: fx.firm,
        settlementAuthority: keeper.publicKey,
        challenge,
        systemProgram: SystemProgram.programId,
      })
      .signers([trader, keeper])
      .rpc();
    await programs.challenge.methods
      .settleChallenge(false, bn(0), bn(0), bn(firma(100)), { caution: {} })
      .accountsStrict({ authority: keeper.publicKey, challenge })
      .signers([keeper])
      .rpc();

    // Operator posts the dispute bond.
    await programs.dispute.methods
      .initOperatorStake(bn(STAKE))
      .accountsPartial({
        firmOwner: fx.owner.publicKey,
        firm: fx.firm,
        operatorStake: pda.operatorStakePda(fx.firm)[0],
        systemProgram: SystemProgram.programId,
      })
      .signers([fx.owner])
      .rpc();

    // Commit the batch root for the epoch (raw [u8;32] = the hex root's bytes).
    await programs.batch.methods
      .commitBatchRoot(bn(epoch), rootBytes, 2)
      .accountsPartial({
        committer: keeper.publicKey,
        firm: fx.firm,
        batchRoot: pda.batchPda(fx.firm, epoch)[0],
        systemProgram: SystemProgram.programId,
      })
      .signers([keeper])
      .rpc();
  });

  it("rejects an invalid Merkle proof (wrong sibling direction)", async () => {
    let threw = "";
    try {
      await programs.dispute.methods
        .openDispute(bn(epoch), "t0", badProof)
        .accountsPartial({
          trader: trader.publicKey,
          challenge,
          batchRoot: pda.batchPda(fx.firm, epoch)[0],
          dispute: pda.disputePda(challenge)[0],
          systemProgram: SystemProgram.programId,
        })
        .signers([trader])
        .rpc();
    } catch (e: any) {
      threw = e.toString();
    }
    expect(threw).to.match(/InvalidProof/);
    expect(await provider.connection.getAccountInfo(pda.disputePda(challenge)[0])).to.equal(null);
  });

  it("accepts a valid inclusion proof against the committed root", async () => {
    await programs.dispute.methods
      .openDispute(bn(epoch), "t0", goodProof)
      .accountsPartial({
        trader: trader.publicKey,
        challenge,
        batchRoot: pda.batchPda(fx.firm, epoch)[0],
        dispute: pda.disputePda(challenge)[0],
        systemProgram: SystemProgram.programId,
      })
      .signers([trader])
      .rpc();
    const d: any = await programs.dispute.account.disputeState.fetch(pda.disputePda(challenge)[0]);
    expect(d.status).to.have.property("open");
    expect(d.trader.toBase58()).to.equal(trader.publicKey.toBase58());
    expect(d.epoch.toString()).to.equal(epoch.toString());
  });

  it("resolve_dispute(upheld) slashes the full operator stake 50/50 (trader / DP fund)", async () => {
    const dpFund = Keypair.generate().publicKey;
    const traderLamportsBefore = await provider.connection.getBalance(trader.publicKey);

    await programs.dispute.methods
      .resolveDispute(true)
      .accountsPartial({
        authority: keeper.publicKey,
        challenge,
        dispute: pda.disputePda(challenge)[0],
        operatorStake: pda.operatorStakePda(fx.firm)[0],
        trader: trader.publicKey,
        dpDisputeFund: dpFund,
      })
      .signers([keeper])
      .rpc();

    const stake: any = await programs.dispute.account.operatorStake.fetch(
      pda.operatorStakePda(fx.firm)[0],
    );
    expect(stake.stakedLamports.toString()).to.equal("0");
    expect(stake.slashCount).to.equal(1);

    const d: any = await programs.dispute.account.disputeState.fetch(pda.disputePda(challenge)[0]);
    expect(d.status).to.have.property("resolvedUpheld");

    // Trader received ~half the slashed bond; DP fund received the other half.
    expect(await provider.connection.getBalance(trader.publicKey)).to.be.greaterThan(
      traderLamportsBefore,
    );
    expect(await provider.connection.getBalance(dpFund)).to.be.greaterThan(0);
  });
});

function minimalRules() {
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
