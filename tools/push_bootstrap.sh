#!/bin/sh
# Download the Procursus bootstrap, decompress it on the Mac, and push
# bootstrap.tar into the Lum1na app's Documents (the app extracts it after
# elevate). Device must be unlocked; the app must have UIFileSharingEnabled.
#
# Usage: tools/push_bootstrap.sh <UDID> <BUNDLE_ID> [BOOTSTRAP_VERSION]
# Example:
#   tools/push_bootstrap.sh 00008030-... com.ma6x9x.Lum1na.A8686JM8XZ
set -e
UDID=${1:?usage: $0 <UDID> <BUNDLE_ID> [version]}
BUNDLE=${2:?usage: $0 <UDID> <BUNDLE_ID> [version]}
VER=${3:-1900}
TMP=${TMPDIR:-/tmp}
curl -L --fail -o "$TMP/bootstrap-$VER.tar.zst" \
  "https://apt.procurs.us/bootstraps/$VER/bootstrap-ssh-iphoneos-arm64.tar.zst"
zstd -d -f -o "$TMP/bootstrap.tar" "$TMP/bootstrap-$VER.tar.zst"
ls -lh "$TMP/bootstrap.tar"
afcclient -u "$UDID" --documents "$BUNDLE" put "$TMP/bootstrap.tar" bootstrap.tar
echo "pushed Documents/bootstrap.tar — run Full Chain; the app extracts it after elevate"
