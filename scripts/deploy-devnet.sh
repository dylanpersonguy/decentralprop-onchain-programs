#!/usr/bin/env bash
# Deploy all five DecentralProp programs to devnet and re-sync the typed SDK IDLs.
# Idempotent: re-running upgrades the already-deployed programs (same program ids).
#
# Prereqs: a funded devnet keypair (≈ 8–10 SOL for five program deploys), the pinned
# Anchor 0.31.1 / Solana SBF toolchain (see onchain/README.md), and Cargo.lock committed.
#
# Usage:
#   ANCHOR_WALLET=~/.config/solana/devnet.json onchain/scripts/deploy-devnet.sh
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"   # onchain/
REPO="$(cd "$HERE/.." && pwd)"
WALLET="${ANCHOR_WALLET:-$HOME/.config/solana/id.json}"

# api.devnet.solana.com hard-429s a full 5-program deploy (each .so is ~700 buffer txs). Prefer the
# Helius endpoint pinned in repo .env.devnet-rpc; fall back to public devnet with a warning.
if [ -f "$REPO/.env.devnet-rpc" ] && grep -qE '^DEVNET_RPC_URL=' "$REPO/.env.devnet-rpc"; then
  RPC="$(grep -E '^DEVNET_RPC_URL=' "$REPO/.env.devnet-rpc" | cut -d= -f2-)"
else
  RPC="https://api.devnet.solana.com"
  echo "⚠ no .env.devnet-rpc found — using public devnet RPC, which rate-limits large program deploys."
fi

echo "▶ devnet deploy — wallet: $WALLET, rpc: ${RPC%%\?*}"
solana config set --url "$RPC" --keypair "$WALLET" >/dev/null

BAL="$(solana balance "$WALLET" | awk '{print $1}')"
echo "▶ balance: ${BAL} SOL"
awk "BEGIN{exit !(${BAL} >= 8)}" || {
  echo "✗ Need ≥ 8 SOL on devnet. Fund the wallet, e.g.:"
  echo "    solana airdrop 2 --url devnet   # (rate-limited; repeat or use a faucet)"
  exit 1
}

echo "▶ anchor build (SBF)…"
( cd "$HERE" && anchor build )

echo "▶ anchor deploy → devnet…"
( cd "$HERE" && anchor deploy --provider.cluster "$RPC" --provider.wallet "$WALLET" )

echo "▶ program ids (verify against Anchor.toml [programs.devnet]):"
( cd "$HERE" && anchor keys list )

echo "▶ publishing IDLs on-chain (init if new, upgrade if already there)…"
for PROGRAM in batch bonding_curve challenge dispute firm; do
  PROGRAM_ID="$(awk -v p="$PROGRAM" '$0 ~ "^"p" *=" {gsub(/[",]/,""); print $3}' "$HERE/Anchor.toml" | head -1)"
  IDL_PATH="$HERE/target/idl/${PROGRAM}.json"
  echo "  · $PROGRAM ($PROGRAM_ID)"
  if ( cd "$HERE" && anchor idl init -f "$IDL_PATH" "$PROGRAM_ID" --provider.cluster "$RPC" --provider.wallet "$WALLET" ) 2>/tmp/idl-init-err; then
    echo "    idl init ok"
  elif grep -qi "already in use\|already exists" /tmp/idl-init-err; then
    ( cd "$HERE" && anchor idl upgrade -f "$IDL_PATH" "$PROGRAM_ID" --provider.cluster "$RPC" --provider.wallet "$WALLET" )
    echo "    idl upgrade ok"
  else
    echo "    ✗ idl init failed:"; cat /tmp/idl-init-err; exit 1
  fi
done
rm -f /tmp/idl-init-err

echo "▶ re-sync typed IDLs into @decentralprop/solana-client…"
( cd "$REPO/packages/solana-client" && npm run copy:idl && npm run build )

echo "✓ devnet deploy complete."
echo "  Next: init platform state, set PYTH_FEEDS (devnet), point keepers/gateway/apps at devnet."
echo "  See onchain/DEVNET_DEPLOY.md."
