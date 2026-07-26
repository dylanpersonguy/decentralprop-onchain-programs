// Self-contained PDA derivations for the Phase-10 E2E suite. Ported from
// `@decentralprop/solana-client/src/pda.ts` so the onchain test package stays
// isolated from the npm workspace (the SDK is ESM + anchor-0.31-CJS and only loads
// cleanly under vitest, not raw node+tsx). Seeds mirror `onchain/README.md` exactly;
// the SDK's offline PDA tests already assert these byte-for-byte.
import { PublicKey } from "@solana/web3.js";
import BN from "bn.js";

/** Program ids = `declare_id!` of each program (also in `Anchor.toml`). */
export const PROGRAM_IDS = {
  batch: new PublicKey("29NK1pYubMLCRDi17YUGF3iMoFYyeYhxoSi6PakKdFLx"),
  firm: new PublicKey("4ZmeSsuMU38jnc42P53gjY8d1N6WPc3LUibiboKwMaEj"),
  challenge: new PublicKey("ENyhfPtpY1BPDFfdMmrUa4XJxuqXSeejgtGBHhhJsEBR"),
  dispute: new PublicKey("3BTD73nYinwAf3pWR1Fw5H9avyq7dYopVARkmYi9245H"),
  bondingCurve: new PublicKey("DeabUFkCGWWG9CHyDAeYMj9anLmguFacvBnMidpkkxBU"),
} as const;

type Pda = [PublicKey, number];
type U64 = BN | number | bigint;

const u64Le = (v: U64) => new BN(v.toString()).toArrayLike(Buffer, "le", 8);
const u8 = (v: number) => Buffer.from([v & 0xff]);

const at = (label: string, seeds: Buffer[], program: PublicKey): Pda =>
  PublicKey.findProgramAddressSync([Buffer.from(label), ...seeds], program);

// ── cross-program ──
export const firmPda = (owner: PublicKey): Pda => at("firm", [owner.toBuffer()], PROGRAM_IDS.firm);
export const challengePda = (
  firm: PublicKey,
  trader: PublicKey,
  tier: number,
  phase = 0,
  nonce: U64 = 0,
): Pda =>
  at(
    "challenge",
    [firm.toBuffer(), trader.toBuffer(), u8(tier), u8(phase), u64Le(nonce)],
    PROGRAM_IDS.challenge,
  );
export const batchPda = (firm: PublicKey, epoch: U64): Pda =>
  at("batch", [firm.toBuffer(), u64Le(epoch)], PROGRAM_IDS.batch);
export const disputePda = (challenge: PublicKey): Pda =>
  at("dispute", [challenge.toBuffer()], PROGRAM_IDS.dispute);
export const operatorStakePda = (firm: PublicKey): Pda =>
  at("operator_stake", [firm.toBuffer()], PROGRAM_IDS.dispute);
export const bondingCurvePda = (firm: PublicKey): Pda =>
  at("bonding_curve", [firm.toBuffer()], PROGRAM_IDS.bondingCurve);
export const curveSolVaultPda = (firm: PublicKey): Pda =>
  at("curve_sol", [firm.toBuffer()], PROGRAM_IDS.bondingCurve);
export const curveFirmaVaultPda = (firm: PublicKey): Pda =>
  at("curve_firma", [firm.toBuffer()], PROGRAM_IDS.bondingCurve);

// ── firm-program PDAs (seeded on the firm-state pubkey) ──
const f = (label: string, firm: PublicKey): Pda => at(label, [firm.toBuffer()], PROGRAM_IDS.firm);
export const firmaMintPda = (firm: PublicKey) => f("firma_mint", firm);
export const treasuryVaultPda = (firm: PublicKey) => f("treasury", firm);
export const ownerDripVaultPda = (firm: PublicKey) => f("owner_drip_vault", firm);
export const ownerDripStatePda = (firm: PublicKey) => f("owner_drip", firm);
export const insuranceFundPda = (firm: PublicKey) => f("insurance", firm);
export const insuranceVaultPda = (firm: PublicKey) => f("insurance_vault", firm);
export const ownerVestingVaultPda = (firm: PublicKey) => f("owner_vesting_vault", firm);
export const payoutFirmaVaultPda = (firm: PublicKey) => f("payout_firma_vault", firm);
export const stakingPoolPda = (firm: PublicKey) => f("staking_pool", firm);
export const stakeVaultPda = (firm: PublicKey) => f("stake_vault", firm);
export const stakingSolVaultPda = (firm: PublicKey) => f("staking_sol", firm);
export const stakingFirmaVaultPda = (firm: PublicKey) => f("staking_firma", firm);
export const backstopPoolPda = (firm: PublicKey) => f("backstop_pool", firm);
export const backstopEscrowVaultPda = (firm: PublicKey) => f("backstop_escrow", firm);
export const backstopPremiumVaultPda = (firm: PublicKey) => f("backstop_premium", firm);
export const platformRiskPda = (): Pda => at("platform_risk", [], PROGRAM_IDS.firm);

// Global $DPROP buyback-and-burn sink (§17).
export const dpropBuybackPda = (): Pda => at("dprop_buyback", [], PROGRAM_IDS.firm);
export const dpropBuybackSolPda = (): Pda => at("dprop_buyback_sol", [], PROGRAM_IDS.firm);
export const dpropBuybackDpropPda = (): Pda => at("dprop_buyback_dprop", [], PROGRAM_IDS.firm);

export const stakerPositionPda = (firm: PublicKey, staker: PublicKey): Pda =>
  at("staker", [firm.toBuffer(), staker.toBuffer()], PROGRAM_IDS.firm);
export const backstopPositionPda = (firm: PublicKey, staker: PublicKey): Pda =>
  at("backstop_pos", [firm.toBuffer(), staker.toBuffer()], PROGRAM_IDS.firm);
export const ownerVestingBatchPda = (challenge: PublicKey): Pda =>
  at("vesting", [challenge.toBuffer()], PROGRAM_IDS.firm);
export const payoutPda = (challenge: PublicKey): Pda =>
  at("payout", [challenge.toBuffer()], PROGRAM_IDS.firm);
export const disputePayoutRecordPda = (dispute: PublicKey): Pda =>
  at("dispute_payout", [dispute.toBuffer()], PROGRAM_IDS.firm);
