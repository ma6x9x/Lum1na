# Respring logo tweak (SpringBoard plate)

`RespringLogo.m` shows the pink→violet LUM1NA plate for 2.4 s after
SpringBoard starts, guarded to `com.apple.springboard`. It is the
system-wide counterpart of the in-app `UI/RespringSplash.swift`.

Build (full Xcode, not the IPA job):

```sh
./build.sh
```

Deploy: copy `RespringLogo.dylib` into the app's `Documents/tweaks` before
the Full Chain. `ak_tryInject` stages `Documents/tweaks` for ElleKit
TweakLoader; the dylib only appears once the jailbreak injection is live.
Without a live injection it is inert.
