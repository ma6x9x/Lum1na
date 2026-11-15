#!/bin/zsh
# panic_pc.sh — panic-PC ingest, Mac side. The .ips NEVER leaves this
# machine: only a derived one-line row (this device's own panic VA) is
# pushed into Documents/panic_pc.txt, where the app's LabPanicSigDrain()
# scores it against the SKU's pinned unslid VAs and records sig-panic-va.
#
# usage: tools/panic_pc.sh /path/to/panic-full-*.ips [udid] [bundle]
#        defaults: UDID=17 (00008150-001225E03C47801C),
#                  bundle=com.ma6x9x.Lum1na.GLVKP6RZ39
# The panic VA used is the kernel's unslid-form PC found in the .ips JSON
# ("panicString" frame chain / "pc" fields). If KASLR is in play, pass the
# slide-adjusted address as the 4th arg (we never carry the corpus here).
set -u
IPS="$1"; UDID="${2:-00008150-001225E03C47801C}"
BUNDLE="${3:-com.ma6x9x.Lum1na.GLVKP6RZ39}"; MANUAL="${4:-}"
[ -r "$IPS" ] || { echo "no ips: $IPS"; exit 1; }

if [ -n "$MANUAL" ]; then PC="$MANUAL"; else
  PC=$(python3 - "$IPS" <<'PY'
import json, sys
try:
    d = json.load(open(sys.argv[1]))
    body = d.get("body", d)
    ps = body.get("panicString", "") or d.get("panicString", "")
    pc = None
    # kernel panic format: a kernel-frame line in panicString
    for line in ps.splitlines():
        t = line.split()
        for tok in t:
            if tok.startswith("0x") and len(tok) >= 10:
                v = int(tok, 16)
                if v > 0xffff000000000000:
                    pc = v  # keep the LAST such token (topmost frame = PC)
    if body.get("panicFlags") and body.get("pc") is not None:
        pc = int(body["pc"])
    print(f"0x{pc:x}" if pc else "")
except Exception:
    print("")
PY
)
fi
[ -n "$PC" ] || { echo "no VA found in $IPS (paste the addr manually as arg 4)"; exit 2; }
printf '%s\n' "$PC" | afcclient -u "$UDID" --documents "$BUNDLE" >/dev/null 2>&1 <<'EOF'
put /dev/stdin Documents/panic_pc.txt
exit
EOF
echo "pushed $PC -> Documents/panic_pc.txt on $UDID ($BUNDLE); next tap drains + scores it."
