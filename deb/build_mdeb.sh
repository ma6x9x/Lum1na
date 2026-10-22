#!/usr/bin/env bash
# Build pkg on the Xcode Mac (needs iOS SDK):
#   cd deb && ./build_mdeb.sh
# compile helper (host build script lives in CI as .yml addition; locally:
#   xcrun -sdk iphoneos clang -arch arm64 -mios-version-min=17.0 \
#     -fobjc-arc -framework Foundation -o Lum1naRoot/usr/libexec/lum1na-fkt \
#     lum1na-fkt.c.txt
#   ldid -S Lum1naRoot/usr/libexec/lum1na-fkt
#   dpkg-deb --root-owner-group --build Lum1naRoot ../com.ma6x9x.lum1naroot_0.0.1_iphoneos-arm64.deb
# Install on the 12 mini: scp to device, ssh root, dpkg -i (rootless prefix
# handled by Procursus dpkg; postinst runs the one-shot as root).
