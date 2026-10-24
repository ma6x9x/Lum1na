<div align="center">

  <img src="docs/Lum1naLogo.JPG" alt="Lum1na logo" width="220" />

  <h1>Lum1na</h1>

  <p><strong>Research preview</strong> for hardware the developer owns.</p>

  <p>
    <img alt="Platform" src="https://img.shields.io/badge/platform-iOS%20%7C%20iPadOS-lightgrey">
    <img alt="Status" src="https://img.shields.io/badge/status-research%20preview-orange">
  </p>

</div>

Authorized testing only. Do not use this against devices you do not own.

## What this repo is

A SwiftUI/ObjC iOS app: motherboard UI, per-tap console, a `+tap` probe catalog, and a local board store (`lum1na_board.json`) for lab telemetry. It is an instrument panel for hardware-level research on devices the developer owns — nothing more is claimed here.

## Building

Open the Xcode project and build against the bundled schemes, or use the repository CI workflows, which produce unsigned IPA artifacts that the developer signs on-device with a free Apple ID.

## Layout

| Path | Role |
| --- | --- |
| `App/`, `UI/` | SwiftUI front-end (home board, console, probe sheets) |
| `Exploit/` | Research tap sources (one `+tap` per instrument) |
| `Bootstrap/`, `Session/`, `Kernel/` | Staging, session logs, board state |
| `docs/` | Lab documentation |

See `AGENTS.md` for repo conventions.