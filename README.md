<div align="center">

  <img src="docs/Lum1naLogo.JPG" alt="Lum1na logo" width="220" />

  <h1>Lum1na</h1>

  <p><strong>Research preview</strong> for hardware the developer owns. Kernel read/write is <em>not</em> obtained.</p>

  <p>
    <img alt="Visibility" src="https://img.shields.io/badge/visibility-public-brightgreen">
    <img alt="Platform" src="https://img.shields.io/badge/platform-iOS%20%7C%20iPadOS-lightgrey">
    <img alt="Status" src="https://img.shields.io/badge/status-research%20preview-orange">
  </p>

</div>

Authorized testing only. Do not use this against devices you do not own.

## What this repo is

A SwiftUI/ObjC iOS app: motherboard UI, P007-style per-tap console, `+tap` catalog, and `Documents/lum1na_board.json` for pins and heap-leak candidates.

It is **not** a jailbreak. `hasKread` stays false until a kread of a known kernel string works. Dopamine 3.0.10 does not port here by bumping versions (A12/A13 26.0–26.0.1 only).

## Targets

| SKU | OS | Offset table |
| --- | --- | --- |
| iPhone 12 family `iPhone13,*` A14 | 26.5 **23F77** | `A14_23F77` via `LabOff()` |
| iPad Pro 2018 `iPad8,*` A12X | 26.6 **23G71** | `A12X_23G71` |

SKU is `hw.machine` + `kern.osversion`, not `UIDevice` “26.5”.

## Where to read

| File | For |
| --- | --- |
| [`AGENTS.md`](AGENTS.md) | Compile contract (Xcode 16.4 IPA job) |
| [`docs/CHAIN.md`](docs/CHAIN.md) | Honest chain map |
| [`docs/BOARD.md`](docs/BOARD.md) | `lum1na_board.json` |
| [`docs/REPO_MAP.md`](docs/REPO_MAP.md) | What each button runs |
| [`docs/FUTURE.md`](docs/FUTURE.md) | Open vs closed classes |

Lab panic app (`P007OpenOnly`) and the long agent notebooks stay **off** this public tree.

## Build

IPA CI: unsigned `iphoneos` Release. Device install needs your signing team in Xcode.

```bash
open Lum1na.xcodeproj
```

Do not change race/UAF/OOB bodies, entitlements, or offset numbers without review. One failed tap does not close a class.
