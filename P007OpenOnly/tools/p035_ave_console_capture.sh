#!/bin/bash
# Stream device syslog while P035 runs. Open+filter only. No poke.
set -euo pipefail

OUT="${1:-$HOME/Desktop/lumina_primitives/p035_ave_console.txt}"
mkdir -p "$(dirname "$OUT")"

echo "Waiting for a USB iPhone (idevice_id)..."
for i in $(seq 1 90); do
  if idevice_id -l 2>/dev/null | grep -q .; then
    break
  fi
  sleep 1
done

UDID="$(idevice_id -l 2>/dev/null | head -1)"
if [ -z "$UDID" ]; then
  echo "No device. Plug in the iPhone 12, unlock, tap Trust."
  exit 1
fi

TYPE="$(ideviceinfo -u "$UDID" -k ProductType 2>/dev/null || true)"
BUILD="$(ideviceinfo -u "$UDID" -k BuildVersion 2>/dev/null || true)"
echo "UDID=$UDID ProductType=$TYPE Build=$BUILD"
if [ "$TYPE" != "iPhone13,2" ] || [ "$BUILD" != "23F77" ]; then
  echo "STOP: want iPhone13,2 / 23F77. Do not mix XR / mini / iPad."
  exit 2
fi

echo "Streaming to $OUT"
echo "Tap More → 35 P035 once. Ctrl-C when the P035 log finishes."
echo "=== capture start $(date) $TYPE $BUILD ===" > "$OUT"
idevicesyslog -u "$UDID" 2>/dev/null | grep -E -i \
  'AppleAVE|AVE2|videotoolboxd|VideoToolbox|frame dimension|out of range|MBInput|CheckCapability|CalcBuf|Prepare' \
  | tee -a "$OUT"
