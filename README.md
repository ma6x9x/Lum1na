<div align="center">

  <img src="docs/Lum1naLogo.JPG" alt="Lum1na logo" width="240" />

  # Lum1na

  Next Gen iOS research and jailbreak experimentation

  <p>
    <img alt="Status" src="https://img.shields.io/badge/status-early%20development-orange">
    <img alt="Platform" src="https://img.shields.io/badge/platform-iOS%20%7C%20iPadOS-lightgrey">
    <img alt="Focus" src="https://img.shields.io/badge/focus-experimental%20research-purple">
  </p>

</div>

Lum1na is an experimental research project focused on iOS and iPadOS jailbreak tooling, device capability checks, and low-level experimentation for A12/A12X-era devices.

This repository is intentionally structured as a clean, modular foundation so the app, jailbreak logic, kernel research, and test scaffolding can evolve without becoming a messy single-codebase project.

> Warning: This project is experimental and not production-ready. It is intended for authorized testing on devices you own and control. Do not run anything in this repo on a device that you cannot legally access or modify.

## Current focus

- iPhone 12 — iOS 26.5
- iPhone XR — iOS 18.7.5
- iPad Pro (A12X) — iPadOS 26.6

These targets are for development and testing only. Exact build numbers should be verified locally before each test session.

## Project goals

- Create a clean, original jailbreak app ecosystem
- Keep device-specific logic isolated and discoverable
- Build a modular structure for future research
- Maintain safe, testable code boundaries
- Avoid mixing research, UI, and exploitation work in one unstructured layer

## Repository layout

```text
Lum1na/
├── App/                     # Application source and entry points
├── Assets.xcassets/         # App icon, colors, and artwork
├── Bootstrap/               # Startup and bootstrap coordination
├── Device/                  # Device profile and capability checks
├── Docs/                    # Project notes and design docs
├── Exploit/                 # Research interfaces and exploit scaffolding
├── KernelMap/               # Kernel/build mapping research
├── Primitive/               # Primitive abstraction helpers
├── Resources/               # Compatibility and configuration resources
├── Session/                 # Session and log management
├── Tests/                   # Unit tests
├── UI/                      # Shared UI components and theme files
├── UITests/                 # UI automation tests
├── .gitignore
├── CONTRIBUTING.md
├── LICENSE
├── README.md
└── Lum1na.xcodeproj/        # Placeholder for the Xcode project
```
