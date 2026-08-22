# Security Policy

DecentralProp is a decentralized prop-firm funding protocol on Solana. The 5 on-chain
programs (`firm`, `batch`, `challenge`, `dispute`, `bonding_curve`) move real SOL and
$FIRMA — a bug in any of them is a funds-at-risk issue, not a cosmetic one.

## Reporting a vulnerability

Email **info@decentralprop.com** with:

- Program(s) affected and the program ID(s) involved
- Steps to reproduce (a devnet transaction, PoC script, or failing test is ideal)
- Impact: what an attacker gains (drained funds, frozen state, bypassed check, etc.)

Please report privately and give us a reasonable window to ship a fix before any public
disclosure. We do not currently run a paid bug bounty.

## Scope

In scope: the 5 Anchor programs under `onchain/programs/`, and the `api-gateway` /
`are` (autonomous risk engine) code that constructs or signs transactions against them.

Out of scope: third-party dependencies (Solana runtime, SPL programs, Metaplex, Raydium),
and denial-of-service via resource exhaustion against public RPC infrastructure we don't
operate.

## Current status

The protocol is in active devnet development — see `master-docs/MASTER_LAUNCH_GATE.md`
and `master-docs/MASTER_SECURITY_AUDIT.md` for the current audit/launch-readiness state.
Nothing described here is a claim that mainnet is live or audited; check those docs for
the up-to-date picture.
