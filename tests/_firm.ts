// Firm bootstrap fixture: runs the documented deploy sequence
//   deploy_firm → create_firma_mint → bonding_curve.initialize_curve → distribute_supply
// and returns every pubkey downstream tests need.
import { SystemProgram } from "@solana/web3.js";
import { getAccount } from "@solana/spl-token";
import {
  ata,
  bn,
  createSolMint,
  fundedWallet,
  Keypair,
  mintSolTo,
  payerOf,
  PublicKey,
  type Programs,
  anchor,
} from "./_env.js";
import * as pda from "./_pdas.js";

// §20 worked-example curve seed + a 200M $FIRMA fixed supply (90% curve / 10% drip).
export const CURVE_VIRTUAL_SOL = 4_000_000_000n; // 4,000 virtual SOL
export const CURVE_FIRMA_RESERVE = 180_000_000_000_000n; // 180M FIRMA
export const DRIP_FIRMA = 20_000_000_000_000n; // 20M FIRMA
export const TREASURY_FIRMA = 40_000_000_000_000n; // 40M FIRMA — minted Tier-2 reserve (RESERVE-2026-07-11)
export const GRADUATION_THRESHOLD = 69_000_000_000n; // 69k real SOL

export interface FirmFixture {
  owner: Keypair;
  riskEngine: Keypair;
  /** Independent platform guardian (co-signs drains / close). Stored at deploy. */
  guardian: Keypair;
  firm: PublicKey; // firm-state PDA
  solMint: PublicKey;
  firmaMint: PublicKey;
  treasuryVault: PublicKey;
  curve: PublicKey;
  curveFirmaVault: PublicKey;
  curveSolVault: PublicKey;
  ownerSol: PublicKey;
  tier: number;
}

/**
 * Deploy a fully-initialised firm (tokens minted, supply distributed, mint authority
 * revoked). The deployer (provider payer) funds the owner + risk-engine keypairs.
 */
export async function deployFirm(
  provider: anchor.AnchorProvider,
  programs: Programs,
  opts: { tier?: number; solMint?: PublicKey } = {},
): Promise<FirmFixture> {
  const tier = opts.tier ?? 1;
  const payer = payerOf(provider);
  const owner = await fundedWallet(provider);
  const riskEngine = await fundedWallet(provider);
  const guardian = await fundedWallet(provider);

  // Fee-paying tests must share ONE platform SOL mint (the global buyback vault holds a single
  // mint); pass `opts.solMint` from `ensurePlatformBuyback`. Other tests keep an isolated mint.
  const solMint = opts.solMint ?? (await createSolMint(provider, payer));
  const [firm] = pda.firmPda(owner.publicKey);
  const [firmaMint] = pda.firmaMintPda(firm);
  const [treasuryVault] = pda.treasuryVaultPda(firm);
  const [curve] = pda.bondingCurvePda(firm);
  const [curveFirmaVault] = pda.curveFirmaVaultPda(firm);
  const [curveSolVault] = pda.curveSolVaultPda(firm);

  // 1) deploy_firm — starts in CAUTION (day-1 bootstrap).
  await programs.firm.methods
    .deployFirm(tier)
    .accountsPartial({
      owner: owner.publicKey,
      riskEngineAuthority: riskEngine.publicKey,
      guardian: guardian.publicKey,
      firmState: firm,
      systemProgram: SystemProgram.programId,
    })
    .signers([owner])
    .rpc();

  // 2) create_firma_mint — mint + treasury/insurance/vesting/drip/staging vaults.
  await programs.firm.methods
    .createFirmaMint()
    .accountsPartial({ owner: owner.publicKey, firmState: firm, solMint })
    .signers([owner])
    .rpc();

  // 2b) init_loss_back_vault — PDA-owned SOL accumulator for the 2% loss-back leg. Required by
  // pay_challenge_fee (the leg routes here); the vault auto-resolves from ["loss_back_vault", firm].
  await programs.firm.methods
    .initLossBackVault()
    .accountsPartial({ payer: owner.publicKey, firmState: firm, solMint })
    .signers([owner])
    .rpc();

  // 3) initialize_curve — virtual-SOL-seeded AMM + its two vaults.
  await programs.bondingCurve.methods
    .initializeCurve(bn(CURVE_VIRTUAL_SOL), bn(CURVE_FIRMA_RESERVE), bn(GRADUATION_THRESHOLD))
    .accountsPartial({ payer: owner.publicKey, firm, solMint, firmaMint })
    .signers([owner])
    .rpc();

  // 4) distribute_supply — mint 70/10/20 (curve/drip/treasury) then revoke mint authority.
  await programs.firm.methods
    .distributeSupply(bn(CURVE_FIRMA_RESERVE), bn(DRIP_FIRMA), bn(TREASURY_FIRMA))
    .accountsPartial({
      firmState: firm,
      owner: owner.publicKey,
      firmaMint,
      curveFirmaVault,
    })
    .signers([owner])
    .rpc();

  const ownerSol = await ata(provider, payer, solMint, owner.publicKey);

  return {
    owner,
    riskEngine,
    guardian,
    firm,
    solMint,
    firmaMint,
    treasuryVault,
    curve,
    curveFirmaVault,
    curveSolVault,
    ownerSol,
    tier,
  };
}

let _platformBuyback: { solMint: PublicKey; dpropMint: PublicKey; solVault: PublicKey } | null =
  null;

/**
 * Stand up the global $DPROP buyback sink ONCE per test run (it is a one-shot singleton) plus a
 * shared platform SOL mint. Memoised, so every fee-paying firm routes its enforced 3% leg into
 * the same canonical `["dprop_buyback_sol"]` vault. Pass the returned `solMint` to `deployFirm`,
 * and `solVault` as `dpropBuybackVault` on `pay_challenge_fee`.
 */
export async function ensurePlatformBuyback(
  provider: anchor.AnchorProvider,
  programs: Programs,
): Promise<{ solMint: PublicKey; dpropMint: PublicKey; solVault: PublicKey }> {
  if (_platformBuyback) return _platformBuyback;
  // The buyback is a one-shot global singleton: if a prior run already created it (a non-reset
  // validator), reuse the mint it was initialised with rather than failing on re-init.
  const [buybackPda] = pda.dpropBuybackPda();
  const existing = await provider.connection.getAccountInfo(buybackPda);
  if (existing) {
    // Recover the mints from the vaults (the state PDA stores vault pubkeys, not the mints).
    const [solVault] = pda.dpropBuybackSolPda();
    const [dpropVault] = pda.dpropBuybackDpropPda();
    const u = await getAccount(provider.connection, solVault);
    const d = await getAccount(provider.connection, dpropVault);
    _platformBuyback = { solMint: u.mint, dpropMint: d.mint, solVault };
    return _platformBuyback;
  }
  const payer = payerOf(provider);
  const solMint = await createSolMint(provider, payer);
  const dpropMint = await createSolMint(provider, payer); // 6-dp stand-in for $DPROP
  await programs.firm.methods
    .initDpropBuyback()
    .accountsPartial({
      payer: payer.publicKey,
      dpropMint,
      solMint,
      dpropBuyback: pda.dpropBuybackPda()[0],
      solVault: pda.dpropBuybackSolPda()[0],
      dpropVault: pda.dpropBuybackDpropPda()[0],
    })
    .rpc();
  _platformBuyback = { solMint, dpropMint, solVault: pda.dpropBuybackSolPda()[0] };
  return _platformBuyback;
}

/** Create + fund a trader with SOL (returns the keypair + its SOL ATA). */
export async function makeTrader(
  provider: anchor.AnchorProvider,
  solMint: PublicKey,
  solAmount: bigint,
): Promise<{ trader: Keypair; traderSol: PublicKey }> {
  const payer = payerOf(provider);
  const trader = await fundedWallet(provider);
  const traderSol = await mintSolTo(provider, payer, solMint, trader.publicKey, solAmount);
  return { trader, traderSol };
}
