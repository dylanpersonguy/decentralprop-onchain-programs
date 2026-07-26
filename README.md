# DecentralProp — On-Chain Programs (Public Verification Mirror)

This is a **read-only source mirror** of DecentralProp's 5 Solana Anchor programs,
published for one purpose: [Solana verified builds](https://solana.com/developers/guides/advanced/verified-builds)
(`solana-verify`) and the explorer badges that depend on it (Solana Explorer, Solscan,
SolanaFM). Deployed program bytecode is already public and readable by anyone — this
repo lets you confirm that bytecode was actually compiled from this exact source,
instead of taking it on faith.

**What this repo is NOT:** the DecentralProp application — the trading-simulation
engine, risk engine, backend, and frontends are closed-source and live in a separate
private repository. Only the on-chain programs are mirrored here, generated from that
private repo's `onchain/` directory at each deploy.

## Programs

Program IDs are the program-keypair pubkeys, so they are identical across every
cluster (localnet/devnet/mainnet-beta):

| Program | Program ID | Purpose |
|---|---|---|
| `firm` | `4ZmeSsuMU38jnc42P53gjY8d1N6WPc3LUibiboKwMaEj` | Firm/challenge-fee economics, payouts, staking, autonomous risk-tier state |
| `batch` | `29NK1pYubMLCRDi17YUGF3iMoFYyeYhxoSi6PakKdFLx` | Append-only hourly Merkle-root commitments (trade-evidence anchoring) |
| `challenge` | `ENyhfPtpY1BPDFfdMmrUa4XJxuqXSeejgtGBHhhJsEBR` | Challenge lifecycle + immutable rule-snapshot + fraud-proof settlement |
| `dispute` | `3BTD73nYinwAf3pWR1Fw5H9avyq7dYopVARkmYi9245H` | On-chain Merkle-proof dispute verification + resolution |
| `bonding_curve` | `DeabUFkCGWWG9CHyDAeYMj9anLmguFacvBnMidpkkxBU` | Constant-product AMM for firm token launches, graduates to Raydium |

## Toolchain

Reproducing the exact deployed bytecode requires matching versions:

- Rust (host): cargo 1.93+
- Solana CLI: 2.2.4 (Agave)
- Anchor: 0.31.1
- `Cargo.lock` is committed and pinned — see the pins table below. Do not `cargo update`
  before verifying; the pinned versions are what was actually compiled.

## Verifying

```bash
cargo install solana-verify --locked

# Build deterministically and compare against on-chain bytecode for a given program + cluster:
solana-verify verify-from-repo \
  -u <mainnet-beta|devnet> \
  --program-id <PROGRAM_ID> \
  https://github.com/dylanpersonguy/decentralprop-onchain-programs \
  --commit-hash <COMMIT_SHA> \
  --library-name <program>

# The shared registry Explorer/Solscan/SolanaFM badges read from only accepts
# mainnet submissions — this step is a no-op on devnet/localnet:
solana-verify remote submit-job --program-id <PROGRAM_ID> --uploader <YOUR_PUBKEY>
```

Repeat per program (`firm`, `batch`, `challenge`, `dispute`, `bonding_curve`).

**⚠️ The deployed binary must itself have been built with `solana-verify build` (or
`anchor build --verifiable`), not a plain `anchor build`.** Two builds from identical
source are NOT guaranteed to be bit-for-bit identical across different host platforms/
toolchains — a native `anchor build` on macOS/arm64 reliably produces different bytes
than `solana-verify`'s own pinned Linux x86_64 Docker build, even with the exact same
`Cargo.lock`. This isn't a hypothetical: it's exactly what happened deploying these
programs from a plain `anchor build` — every verify came back a hash mismatch until
the affected program was rebuilt with `solana-verify build` and redeployed. If a
program you expect to verify cleanly doesn't, rebuild and redeploy it with:

```bash
solana-verify build <path-to-onchain-workspace> --library-name <program>
solana program deploy target/deploy/<program>.so --program-id <PROGRAM_ID> -u <cluster>
```

**`challenge` is a special case on devnet:** it runs an intentional `devnet-fast`
Cargo feature there (a 5-minute fraud-proof window instead of production's 72 hours),
so verifying it must build with the same feature the deployment actually used:

```bash
solana-verify verify-from-repo -u devnet --program-id <CHALLENGE_ID> \
  https://github.com/dylanpersonguy/decentralprop-onchain-programs \
  --commit-hash <COMMIT_SHA> --library-name challenge -- --features devnet-fast
```

Mainnet never runs `devnet-fast` — a plain verify (no extra features) is correct there.

## Staying in sync

This mirror is regenerated and pushed every time a program is rebuilt and redeployed.
If the commit here doesn't correspond to what's actually live on-chain, treat any
verification badge as stale until the mirror and the live deploy are back in sync.

## ⚠️ Dependency pins (required for the SBF build)

The Anchor 0.31.1 SBF toolchain ships an older Cargo (1.79) that cannot build crates
requiring `edition2024` or rustc ≥ 1.85. `Cargo.lock` pins the transitive dependency
tree down to versions that toolchain can build:

| Crate | Pinned to | Reason |
|---|---|---|
| `solana-program` | 2.2.1 | match the installed CLI; avoid 2.3.0 pulling newer crypto |
| `borsh` / `borsh-derive` | 1.5.5 / 1.5.7 | avoid `proc-macro-crate 3.5` → `toml_edit 0.25` |
| `proc-macro-crate` | 3.2.0 | older `toml_edit 0.22` |
| `blake3` | 1.5.5 | drops `digest 0.11` → `ctutils`/`cmov 0.5.4` (edition2024) |
| `indexmap` | 2.6.0 | ≥2.10 requires edition2024 |
| `zeroize` | 1.8.1 | 1.9.0 requires edition2024 |
| `zeroize_derive` | 1.4.2 | 1.5.0 requires edition2024 (pulled in by `anchor-spl`) |
| `unicode-segmentation` | 1.12.0 | 1.13.3 requires rustc 1.85 |

## Cross-program dependencies

`dispute` → `batch`, `challenge` (reads their PDAs). `firm` → `bonding_curve` (CPI),
`challenge`, `dispute` (cross-program reads). A change to a depended-on program's
account layout or instruction signature requires rebuilding the dependents — verify
all 5 together after any change, not just the one that changed.
