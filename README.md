<div align="center">

  <img src="docs/Lum1naLogo.JPG" alt="Lum1na logo" width="220" />

  <h1>Lum1na</h1>

  <p><strong>Private developer beta</strong> — invite-only. Not a public release.</p>

  <p>
    <img alt="Visibility" src="https://img.shields.io/badge/visibility-private-red">
    <img alt="Platform" src="https://img.shields.io/badge/platform-iOS%20%7C%20iPadOS-lightgrey">
    <img alt="Status" src="https://img.shields.io/badge/status-trusted%20testers%20only-orange">
  </p>

</div>

Lum1na is a private research / jailbreak app project for devices you own and control. This repository stays **private**. Do not mirror, fork publicly, or redistribute builds without the owner’s explicit OK.

> Warning: Experimental. Only use on hardware you are legally allowed to modify. Trusted-developer testing only.

## Current focus

- iPhone 12 — iOS 26.5
- iPhone XR — iOS 18.7.5
- iPad Pro (A12X) — iPadOS 26.6

Confirm the exact build number on-device before each session.

## Repository layout

```text
Lum1na/
├── App/                 # SwiftUI entry + ContentView
├── Assets.xcassets/     # App icon / colors
├── Bootstrap/           # Bootstrap coordination protocols
├── Device/              # Device capability helpers
├── docs/                # Notes + logo asset
├── Exploit/             # Low-level research (do not “drive-by” edit)
├── KernelMap/           # Mapping / offset research
├── Lum1na.xcodeproj/    # Xcode project
├── Primitive/           # Primitive helpers
├── Resources/           # Bundled resources
├── Session/             # Session / logging helpers
├── Tests/               # Unit tests
├── UI/                  # Theme + console presentation
├── UITests/             # UI tests
├── .gitignore
└── README.md
```

## Polish policy

UI, docs, and project hygiene may change freely. **Do not change race triggers, KRW paths, leak implementations, or other exploit logic** under `Exploit/` unless the owner asks for that specifically.

## Build (Mac / Xcode)

1. Open `Lum1na.xcodeproj` in Xcode on a Mac.
2. Select your team / signing for a development device you control.
3. Product → Archive, then Distribute App → Ad Hoc or Development for trusted testers.
4. Keep `.ipa` / `.xcarchive` artifacts out of git (see `.gitignore`).

IPAs are produced on a Mac with your signing identity — not from this README’s host environment.

## Docs

See [`docs/development.md`](docs/development.md) for session logging expectations.
