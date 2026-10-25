#!/bin/bash
# build_ipa_local.sh — unsigned IPA builds on this Mac, no CI needed.
#   tools/build_ipa_local.sh [main|debug|both]
# Output: ./artifacts/Lum1na-unsigned.ipa / ./artifacts/Lum1na-Debug-unsigned.ipa
set -euo pipefail
cd "$(dirname "$0")/.."
OUT=artifacts; mkdir -p "$OUT"
XCARGS=(-configuration Release -sdk iphoneos -destination 'generic/platform=iOS'
        CODE_SIGNING_ALLOWED=NO CODE_SIGNING_REQUIRED=NO CODE_SIGN_IDENTITY=""
        IPHONEOS_DEPLOYMENT_TARGET=17.0)

build_one() { # name proj scheme ddsub
  local NAME=$1 PROJ=$2 SCHEME=$3 DD=$4 APPNAME=$5
  echo "== building $NAME"
  if [ "$PRE" = "strip-nested" ]; then rm -rf P007OpenOnly; fi
  xcodebuild "${XCARGS[@]}" -derivedDataPath "build/$DD" -project "$PROJ" -scheme "$SCHEME" build
  local BUILT="build/$DD/Build/Products/Release-iphoneos/$APPNAME"
  test -d "$BUILT"
  local TMP="$OUT/.tmp-$NAME"; rm -rf "$TMP"; mkdir -p "$TMP/Payload"
  cp -R "$BUILT" "$TMP/Payload/"
  (cd "$TMP" && zip -qry "../$NAME.ipa" Payload); rm -rf "$TMP"
  echo "   -> $OUT/$NAME.ipa"
}

WANT=${1:-both}; export PRE=
for arg in ${WANT//,/ }; do
  case $arg in
    main)  PRE=strip-nested build_one "Lum1na-unsigned" Lum1na.xcodeproj Lum1na main Lum1na.app ;;
    debug) build_one "Lum1na-Debug-unsigned" P007OpenOnly/P007OpenOnly.xcodeproj P007OpenOnly debug P007OpenOnly.app ;;
    both)  export PRE=strip-nested; build_one "Lum1na-unsigned" Lum1na.xcodeproj Lum1na main Lum1na.app; PRE=; build_one "Lum1na-Debug-unsigned" P007OpenOnly/P007OpenOnly.xcodeproj P007OpenOnly debug P007OpenOnly.app ;;
  esac
done
echo DONE
