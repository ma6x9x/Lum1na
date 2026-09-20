# Lum1na

Experimental iOS/iPadOS research project scaffold for Lum1na. The current layout is designed so the application files, research components, tests, and resources can be added incrementally.

## Development targets

- iPhone 12 — iOS 26.5, current test device
- iPhone XR — A12, planned iOS 18.7.5 port
- iPad Pro — A12X, planned iPadOS 26.6 port

Verify exact build numbers locally before recording results. Do not assume these devices share identical behavior.

## Layout

- `App/` — application entry point and views
- `Assets.xcassets/` — app assets
- `Bootstrap/` — startup coordination
- `Device/` — device and OS capability detection
- `Exploit/` — research interfaces and experimental implementations
- `KernelMap/` — version-specific kernel research data
- `Primitive/` — low-level primitive abstractions
- `Resources/` — compatibility and configuration resources
- `Session/` — logging and session state
- `UI/` — shared user-interface components
- `Tests/` — unit tests
- `UITests/` — UI tests

This repository contains an original scaffold only. Add your own app files and implementations under the appropriate directories. Do not commit private keys, signing certificates, provisioning profiles, proprietary SDK files, or data from devices you do not own.

## Safety

Maintain a verified backup and a known-good restore path before testing system-modifying software. Lum1na is experimental and is not production-ready.
