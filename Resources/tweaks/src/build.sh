#!/bin/sh
# Build the SpringBoard post-respring LUM1NA plate as an arm64e dylib.
# Needs full Xcode (iPhoneOS SDK) and ldid. The IPA CI job does not run this.
set -e
cd "$(dirname "$0")"
SDK=$(xcrun --sdk iphoneos --show-sdk-path)
clang -dynamiclib -arch arm64e -miphoneos-version-min=17.0 \
  -isysroot "$SDK" -fobjc-arc \
  -framework UIKit -framework Foundation -framework QuartzCore \
  -o RespringLogo.dylib RespringLogo.m
if command -v ldid >/dev/null 2>&1; then
  ldid -S RespringLogo.dylib
else
  echo "warning: ldid not found; dylib is unsigned (TweakLoader may refuse it)" >&2
fi
echo "built $(pwd)/RespringLogo.dylib"
