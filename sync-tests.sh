#!/bin/bash
# Syncs test files from btc-mapping-contract to all other UTXO mapping contracts.
# Only the Go module import path differs between chains.
set -euo pipefail

SRC="btc-mapping-contract"
CHAINS=(ltc-mapping-contract dash-mapping-contract doge-mapping-contract bch-mapping-contract)

# Files to sync from BTC → all others
FILES=(
  btctest_test.go
  mapping_test.go
  confirm_spend_test.go
  edge_cases_test.go
)

for chain in "${CHAINS[@]}"; do
  dst="$chain/tests/current"
  echo "=== Syncing to $chain ==="
  for file in "${FILES[@]}"; do
    src_file="$SRC/tests/current/$file"
    if [ ! -f "$src_file" ]; then
      echo "  SKIP $file (not found in source)"
      continue
    fi
    echo "  $file"
    sed "s|btc-mapping-contract|${chain}|g" "$src_file" > "$dst/$file"
  done
done

echo ""
echo "Done. Run 'make test' in each contract to verify."
