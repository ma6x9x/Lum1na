#!/bin/bash
# build_ipa_local.sh — unsigned IPA builds on this Mac, no CI, no paid dev account.
# Usage:
#   tools/build_ipa_local.sh           -> both apps (main Lum1na + Lum1na-Debug rig)
#   tools/build_ipa_local.sh main      -> main app only
#   tools/build_ipa_local.sh debug     -> rig app only
# Output: ./artifacts/Lum1na-unsigned.ipa and ./artifacts/Lum1na-Debug-unsigned.ipa
# Sign/install with Sideloadly (free Apple ID). The IPA itself is unsigned.
set -euo pipefail
cd "$(dirname "$0")/.."
OUT=artifacts
XC=(xcodebuild -configuration Release -sdk iphoneos -destination 'generic/platform=iOS'
    CODE_SIGNING_ALLOWED=NO CODE_SIGNING_REQUIRED=NO CODE_SIGN_IDENTITY=""
    IPHONEOS_DEPLOYMENT_TARGET=17.0)
mkdir -p "$OUT"

build_one() { # name project-dir scheme pre-clean
  local NAME=$1 PROJ=$2 SCHEME=$3 PRE=$4
  echo "== building $NAME"
  if [ "$PRE" = "strip-nested" ]; then rm -rf P007OpenOnly; fi   # synchronized-root law
  local APP
  APP=$("${XC[@]}" -project "$PROJ" -scheme "$SCHEME" -showBuildSettings \
        2>/dev/null | awk -F' = ' '/ TARGET_BUILD_DIR/{print $2; exit}')
  local PNAME
  PNAME=$("${XC[@]}" -project "$PROJ" -scheme "$SCHEME" -showBuildSettings \
        2>/dev/null | awk -F' = ' '/ FULL_PRODUCT_NAME/{print $2; exit}')
  "${XC[@]}" -project "$PROJ" -scheme "$SCHEME" build
  local BUILT
  BUILT="${APP}/${PNAME}"
  test -d "$BUILT"
  local TMP="$OUT/.tmp-$NAME"
  rm -rf "$TMP" && mkdir -p "$TMP/Payload"
  cp -R "$BUILT" "$TMP/Payload/"
  (cd "$TMP" && zip -qry "../${NAME}.ipa" Payload)
  rm -rf "$TMP"
  echo "   -> $OUT/${NAME}.ipa"
}

WANT=${1:-both}
if [ "$WANT" = "main" ] || [ "$WANT" = "both" ]; then
  build_one "Lum1na-unsigned" Lum1na.xcodeproj Lum1na strip-nested
fi
if [ "$WANT" = "debug" ] || [ "$WANT" = "both" ]; then
  build_one "Lum1na-Debug-unsigned" P007OpenOnly/P007OpenOnly.xcodeproj "P007OpenOnly" keep
fi
echo DONE