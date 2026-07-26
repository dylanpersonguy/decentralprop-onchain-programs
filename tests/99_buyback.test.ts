// Focused verification of the trustless $DPROP buyback-and-burn sink (§17): init → fund →
// execute (accounting) → burn. Independent of the lifecycle fixture so it isolates the new code.
import { expect } from "chai";
import { mintTo, getAccount, getMint } from "@solana/spl-token";
import {
  anchor,
  bn,
  getProvider,
  loadPrograms,
  payerOf,
  type Programs,
} from "./_env.js";
import { ensurePlatformBuyback } from "./_firm.js";
import * as pda from "./_pdas.js";

describe("§17 — $DPROP buyback-and-burn sink (trustless)", () => {
  let provider: anchor.AnchorProvider;
  let programs: Programs;
  let buyback: { solMint: any; dpropMint: any; solVault: any };

  before(async () => {
    provider = getProvider();
    programs = loadPrograms(provider);
    buyback = await ensurePlatformBuyback(provider, programs);
  });

  it("init creates PDA-owned SOL + $DPROP vaults (authority = buyback PDA, no admin)", async () => {
    const [buybackPda] = pda.dpropBuybackPda();
    const [solVault] = pda.dpropBuybackSolPda();
    const [dpropVault] = pda.dpropBuybackDpropPda();

    const state: any = await programs.firm.account.dpropBuyback.fetch(buybackPda);
    expect(state.solVault.toBase58()).to.equal(solVault.toBase58());
    expect(state.dpropVault.toBase58()).to.equal(dpropVault.toBase58());

    // The trustless property: both vaults are owned by the buyback PDA — no key can move them.
    const u = await getAccount(provider.connection, solVault);
    const d = await getAccount(provider.connection, dpropVault);
    expect(u.owner.toBase58()).to.equal(buybackPda.toBase58());
    expect(d.owner.toBase58()).to.equal(buybackPda.toBase58());
  });

  it("execute records the SOL spend (Raydium swap is the devnet boundary)", async () => {
    const payer = payerOf(provider);
    const [buybackPda] = pda.dpropBuybackPda();
    const [solVault] = pda.dpropBuybackSolPda();
    // Fund the buyback SOL accumulator (the PDA vault) directly, as the fee split would.
    await mintTo(provider.connection, payer, buyback.solMint, solVault, payer.publicKey, 1_000_000);

    const before: any = await programs.firm.account.dpropBuyback.fetch(buybackPda);
    await programs.firm.methods
      .executeDpropBuyback(bn(600_000n))
      .accountsPartial({
        cranker: payer.publicKey,
        dpropBuyback: buybackPda,
        solVault,
        dpropVault: pda.dpropBuybackDpropPda()[0],
      })
      .rpc();
    const after: any = await programs.firm.account.dpropBuyback.fetch(buybackPda);
    expect(BigInt(after.totalSolSpent.toString()) - BigInt(before.totalSolSpent.toString())).to.equal(
      600_000n,
    );
  });

  it("burn permanently removes $DPROP from the vault and bumps the deflation counter", async () => {
    const payer = payerOf(provider);
    const [buybackPda] = pda.dpropBuybackPda();
    const [dpropVault] = pda.dpropBuybackDpropPda();
    // Simulate $DPROP arriving from a swap: mint into the PDA vault (payer is the mint authority).
    await mintTo(provider.connection, payer, buyback.dpropMint, dpropVault, payer.publicKey, 5_000_000);

    const supplyBefore = (await getMint(provider.connection, buyback.dpropMint)).supply;
    const before: any = await programs.firm.account.dpropBuyback.fetch(buybackPda);

    await programs.firm.methods
      .burnDpropBuyback()
      .accountsPartial({
        cranker: payer.publicKey,
        dpropBuyback: buybackPda,
        dpropMint: buyback.dpropMint,
        dpropVault,
      })
      .rpc();

    const vault = await getAccount(provider.connection, dpropVault);
    const supplyAfter = (await getMint(provider.connection, buyback.dpropMint)).supply;
    const after: any = await programs.firm.account.dpropBuyback.fetch(buybackPda);

    expect(vault.amount).to.equal(0n); // the only exit is the incinerator
    expect(supplyBefore - supplyAfter).to.equal(5_000_000n); // supply truly reduced
    expect(
      BigInt(after.totalDpropBurned.toString()) - BigInt(before.totalDpropBurned.toString()),
    ).to.equal(5_000_000n);
  });
});
