#!/bin/sh
# Endpoint coverage check for the Playit API inventory (no dependencies
# beyond POSIX sh, grep, sed, sort, comm).
#
# Compares paths called in packages/api_client/src/api.rs (generated
# client) against `POST /...` rows in docs/api-inventory.md (source of
# truth). Fails when a generated endpoint has no inventory row.
#
# Usage: sh tools/api-coverage.sh

set -u

REPO=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
API_RS="$REPO/packages/api_client/src/api.rs"
INVENTORY="$REPO/docs/api-inventory.md"

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT INT TERM

grep -o '\.client\.call\(_with_policy\)\?(caller, "[^"]*"' "$API_RS" \
  | sed 's/.*caller, "//; s/"$//' | sort -u > "$TMP/generated.txt"

grep -oE '`(GET|POST|PUT|PATCH|DELETE) /[^`]*`' "$INVENTORY" \
  | sed 's/^`//; s/`$//; s/^[^ ]* //' | sort -u > "$TMP/inventory.txt"

N_GEN=$(wc -l < "$TMP/generated.txt" | tr -d ' ')
N_INV=$(wc -l < "$TMP/inventory.txt" | tr -d ' ')
echo "generated endpoints (api.rs): $N_GEN"
echo "inventory rows: $N_INV"

comm -23 "$TMP/generated.txt" "$TMP/inventory.txt" > "$TMP/missing.txt"
if [ -s "$TMP/missing.txt" ]; then
  echo ""
  echo "generated endpoints missing from docs/api-inventory.md:"
  sed 's/^/  /' "$TMP/missing.txt"
  exit 1
fi

echo ""
echo "coverage OK"
