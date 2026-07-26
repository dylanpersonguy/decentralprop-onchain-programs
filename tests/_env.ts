// Shared E2E harness: provider, the five typed programs (loaded from `target/idl`),
// and SPL-token/airdrop utilities. Self-contained — no `@decentralprop/*` imports.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import * as anchor from "@coral-xyz/anchor";
import BN from "bn.js";
import {
  Connection,
  Keypair,
  LAMPORTS_PER_SOL,
  PublicKey,
  type Signer,
} from "@solana/web3.js";
import {
  createMint,
  getAccount,
  getAssociatedTokenAddressSync,
  getOrCreateAssociatedTokenAccount,
  mintTo,
  TOKEN_PROGRAM_ID,
} from "@solana/spl-token";

export { anchor, BN, PublicKey, Keypair, TOKEN_PROGRAM_ID };

const here = dirname(fileURLToPath(import.meta.url));
const idlDir = join(here, "..", "target", "idl");
const loadIdl = (name: string) =>
  JSON.parse(readFileSync(join(idlDir, `${name}.json`), "utf8"));

/** `anchor test` exports ANCHOR_PROVIDER_URL + ANCHOR_WALLET; fall back to localnet. */
export function getProvider(): anchor.AnchorProvider {
  if (!process.env.ANCHOR_PROVIDER_URL) {
    process.env.ANCHOR_PROVIDER_URL = "http://127.0.0.1:8899";
  }
  if (!process.env.ANCHOR_WALLET) {
    process.env.ANCHOR_WALLET = join(process.env.HOME ?? "", ".config/solana/id.json");
  }
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);
  return provider;
}

export interface Programs {
  batch: anchor.Program;
  firm: anchor.Program;
  challenge: anchor.Program;
  dispute: anchor.Program;
  bondingCurve: anchor.Program;
}

export function loadPrograms(provider: anchor.AnchorProvider): Programs {
  const P = (name: string) => new anchor.Program(loadIdl(name), provider);
  return {
    batch: P("batch"),
    firm: P("firm"),
    challenge: P("challenge"),
    dispute: P("dispute"),
    bondingCurve: P("bonding_curve"),
  };
}

/** The provider's funded payer keypair (from ANCHOR_WALLET). */
export function payerOf(provider: anchor.AnchorProvider): Keypair {
  return (provider.wallet as anchor.Wallet).payer;
}

/** Create + fund a fresh keypair with SOL via airdrop (for gas + rent). */
export async function fundedWallet(
  provider: anchor.AnchorProvider,
  sol = 5,
): Promise<Keypair> {
  const kp = Keypair.generate();
  const sig = await provider.connection.requestAirdrop(kp.publicKey, sol * LAMPORTS_PER_SOL);
  await confirm(provider.connection, sig);
  return kp;
}

export async function confirm(connection: Connection, sig: string): Promise<void> {
  const bh = await connection.getLatestBlockhash();
  await connection.confirmTransaction({ signature: sig, ...bh }, "confirmed");
}

/** Create a 6-decimal mock SOL mint (payer = mint authority). */
export async function createSolMint(
  provider: anchor.AnchorProvider,
  payer: Keypair,
): Promise<PublicKey> {
  return createMint(provider.connection, payer, payer.publicKey, null, 6);
}

/** Ensure `owner` has an ATA for `mint`, return its address. */
export async function ata(
  provider: anchor.AnchorProvider,
  payer: Keypair,
  mint: PublicKey,
  owner: PublicKey,
): Promise<PublicKey> {
  const acc = await getOrCreateAssociatedTokenAccount(
    provider.connection,
    payer,
    mint,
    owner,
    true, // allowOwnerOffCurve — owners may be PDAs in some flows
  );
  return acc.address;
}

/** Derive (without creating) the ATA address. */
export const ataAddr = (mint: PublicKey, owner: PublicKey): PublicKey =>
  getAssociatedTokenAddressSync(mint, owner, true);

/** Mint `amount` (base units) of `solMint` to `owner`'s ATA; returns the ATA. */
export async function mintSolTo(
  provider: anchor.AnchorProvider,
  payer: Keypair,
  solMint: PublicKey,
  owner: PublicKey,
  amount: bigint | number,
): Promise<PublicKey> {
  const account = await ata(provider, payer, solMint, owner);
  await mintTo(provider.connection, payer, solMint, account, payer, amount);
  return account;
}

/** Token-account balance in base units. */
export async function tokenBalance(
  provider: anchor.AnchorProvider,
  account: PublicKey,
): Promise<bigint> {
  const acc = await getAccount(provider.connection, account);
  return acc.amount;
}

/** Mint-supply + authority readout, for the §16 rug-pull checklist. */
export async function mintInfo(provider: anchor.AnchorProvider, mint: PublicKey) {
  const { getMint } = await import("@solana/spl-token");
  return getMint(provider.connection, mint);
}

/** `bn(x)` — u64/i64 args. */
export const bn = (v: bigint | number | string): BN => new BN(v.toString());

/** SOL scaled to 6 decimals. */
export const sol = (whole: number): bigint => BigInt(Math.round(whole * 1e6));

/** $FIRMA scaled to 6 decimals. */
export const firma = (whole: number): bigint => BigInt(Math.round(whole * 1e6));

export type { Signer };
