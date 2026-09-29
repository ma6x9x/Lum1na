#!/usr/bin/env bash
# Lab IPSW markdown diff — same flags as blacktop/ipsw-diffs
#   .github/workflows/diff.yml  ("Download and diff")
#
# Default device is iPhone13,2 (T8101 / 23F77). blacktop CI defaults to
# iPhone18,1. Do not copy those VAs onto this board.
#
# Usage:
#   tools/ipsw-diff-lab.sh <prev.ipsw> <next.ipsw> [outdir]
#   tools/ipsw-diff-lab.sh --dl [--device iPhone13,2] [--os iOS] <prev_build> <next_build> [outdir]
#   tools/ipsw-diff-lab.sh --grep <diffdir>
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WATCHLIST="$ROOT/tools/ipsw-diff-watchlist.txt"
DEFAULT_DEVICE="iPhone13,2"
DEFAULT_OS="iOS"
DEFAULT_OUT="$ROOT/ipsw-diffs-out"

die() { echo "ipsw-diff-lab: $*" >&2; exit 1; }

need_ipsw() {
  command -v ipsw >/dev/null 2>&1 || die "ipsw not on PATH (https://github.com/blacktop/ipsw)"
}

# Kernel function names. Optional: skip --signatures if the clone is missing.
symbolicator_dir() {
  if [ -n "${SYMBOLICATOR:-}" ] && [ -d "$SYMBOLICATOR/kernel" ]; then
    echo "$SYMBOLICATOR/kernel"
    return
  fi
  local cache="${IPSW_SYMBOLICATOR:-$HOME/.cache/ipsw-symbolicator}"
  if [ ! -d "$cache/kernel" ]; then
    echo "cloning blacktop/symbolicator -> $cache" >&2
    git clone --quiet --depth 1 https://github.com/blacktop/symbolicator.git "$cache"
  fi
  if [ -d "$cache/kernel" ]; then
    echo "$cache/kernel"
  fi
}

run_diff() {
  local prev="$1" next="$2" out="$3"
  [ -f "$prev" ] || die "missing prev IPSW: $prev"
  [ -f "$next" ] || die "missing next IPSW: $next"
  mkdir -p "$out"
  local sig
  sig="$(symbolicator_dir || true)"
  local diff_args=(
    diff --output "$out"
    --markdown --fw --launchd --feat --strs --ent --files --starts
    --block-list "__TEXT.__info_plist"
    --block-list "__AUTH_CONST.__auth_ptr"
  )
  if [ -n "$sig" ]; then
    diff_args+=(--signatures "$sig")
  else
    echo "warning: no symbolicator/kernel; kernel functions will be unnamed" >&2
  fi
  echo "ipsw ${diff_args[*]} \\"
  echo "  $prev \\"
  echo "  $next"
  ipsw "${diff_args[@]}" "$prev" "$next"
  echo "wrote $out"
  grep_watchlist "$out"
}

grep_watchlist() {
  local dir="$1"
  [ -d "$dir" ] || die "not a directory: $dir"
  [ -f "$WATCHLIST" ] || die "missing $WATCHLIST"
  echo
  echo "== watchlist hits in $dir =="
  local pat
  while IFS= read -r pat; do
    [[ -z "$pat" || "$pat" == \#* ]] && continue
    local hits
    hits="$(grep -R -n -F -- "$pat" "$dir" 2>/dev/null | head -n 40 || true)"
    if [ -n "$hits" ]; then
      echo
      echo "-- $pat --"
      echo "$hits"
    fi
  done < "$WATCHLIST"
}

download_pair() {
  local os="$1" device="$2" prev_build="$3" next_build="$4" out="$5"
  need_ipsw
  local tmp="${IPSW_DL_DIR:-$DEFAULT_OUT/ipsw}"
  local prev_dir="$tmp/$device-$prev_build"
  local next_dir="$tmp/$device-$next_build"
  mkdir -p "$prev_dir" "$next_dir"
  echo "downloading $os $device $prev_build (large)"
  ipsw dl appledb --os "$os" --device "$device" --build "$prev_build" --output "$prev_dir" --confirm
  echo "downloading $os $device $next_build (large)"
  ipsw dl appledb --os "$os" --device "$device" --build "$next_build" --output "$next_dir" --confirm
  local prev_ipsw next_ipsw
  prev_ipsw="$(ls "$prev_dir"/*.ipsw | head -n 1)"
  next_ipsw="$(ls "$next_dir"/*.ipsw | head -n 1)"
  [ -n "$prev_ipsw" ] && [ -n "$next_ipsw" ] || die "ipsw download produced no .ipsw"
  run_diff "$prev_ipsw" "$next_ipsw" "$out"
}

usage() {
  cat <<'EOF'
Lab IPSW markdown diff — same flags as blacktop/ipsw-diffs
(.github/workflows/diff.yml). Default device iPhone13,2, not iPhone18,1.

  tools/ipsw-diff-lab.sh <prev.ipsw> <next.ipsw> [outdir]
  tools/ipsw-diff-lab.sh --dl [--device iPhone13,2] [--os iOS] <prev_build> <next_build> [outdir]
  tools/ipsw-diff-lab.sh --grep <diffdir>
EOF
  exit 2
}

mode=""
device="$DEFAULT_DEVICE"
os="$DEFAULT_OS"
args=()
while [ $# -gt 0 ]; do
  case "$1" in
    --dl) mode="dl"; shift ;;
    --grep) mode="grep"; shift ;;
    --device) device="${2:?}"; shift 2 ;;
    --os) os="${2:?}"; shift 2 ;;
    -h|--help) usage ;;
    --) shift; break ;;
    -*) die "unknown flag $1" ;;
    *) args+=("$1"); shift ;;
  esac
done
args+=("$@")

case "${mode:-diff}" in
  grep)
    [ "${#args[@]}" -eq 1 ] || die "--grep wants one diff directory"
    grep_watchlist "${args[0]}"
    ;;
  dl)
    [ "${#args[@]}" -ge 2 ] || die "--dl wants <prev_build> <next_build> [outdir]"
    prev_build="${args[0]}"
    next_build="${args[1]}"
    out="${args[2]:-$DEFAULT_OUT/${prev_build}_vs_${next_build}}"
    download_pair "$os" "$device" "$prev_build" "$next_build" "$out"
    ;;
  diff)
    [ "${#args[@]}" -ge 2 ] || usage
    prev="${args[0]}"
    next="${args[1]}"
    out="${args[2]:-$DEFAULT_OUT/$(basename "${prev%.ipsw}")_vs_$(basename "${next%.ipsw}")}"
    need_ipsw
    run_diff "$prev" "$next" "$out"
    ;;
esac
