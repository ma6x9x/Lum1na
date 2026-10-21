#!/bin/bash
# logwatch.sh — the filtered live console (Mac-side, no bloat).
#
# Streams idevicesyslog and prints ONLY:
#   - the rig's kernel-side klog oracle lines (the aks/IOMFB/glyph klog
#     families the taps trigger), and
#   - your chosen extra patterns (pass as extra args).
# Everything else (the app's own NSLog spam, OS activity, etc.) is dropped.
#
# Usage:
#   ./tools/logwatch.sh                       # default filter set
#   ./tools/logwatch.sh 'PattOne' 'PattTwo'   # append your own EREs
#   ./tools/logwatch.sh -u <udid> 'Pattern'   # specific device
#
# Requires libimobiledevice (idevicesyslog) — installed on this Mac.

set -uo pipefail

UDID=""
if [ "${1:-}" = "-u" ]; then UDID="$2"; shift 2; fi

# ---- default filter: what actually matters to the hunt ----
DEFAULT_PATTERNS=(
  '%spid:%d'                       # the klog family format (kern klog prints)
  'aks[-_]'                        # aks-* boot-args / aks klog lines
  'AppleSEPKeyStore|AppleKeyStore'
  'IOMD|dmaCommand|IOMobileFramebuffer|IOMFB'
  'M2Scaler|IOSurface'
  'Sandbox|Seatbelt|cmrequest|CM_KERN'
  'Security: Process'              # the IOSurface warn-once oracle
  'unsupported request|invalid handle|unexpected session uid'
  'handle 0 requested|entitled:'
  'P007OpenOnly\['                 # the rig's own stdout lines (klog-side echo)
)
PAT=("${DEFAULT_PATTERNS[@]}")
[ $# -gt 0 ] && PAT+=("$@")

ERE=$(IFS='|'; echo "${PAT[*]}")
echo "[logwatch] filter: $ERE" >&2

if [ -n "$UDID" ]; then
  idevicesyslog -u "$UDID" 2>/dev/null | grep --line-buffered -E "$ERE"
else
  idevicesyslog 2>/dev/null | grep --line-buffered -E "$ERE"
fi