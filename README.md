<div align="center">

  <img src="docs/Lum1naLogo.JPG" alt="Lum1na logo" width="220" />

  <h1>Lum1na</h1>

  <p><strong>Open-source developer preview</strong> — available for public review and development.</p>

  <p>
    <img alt="Visibility" src="https://img.shields.io/badge/visibility-public-brightgreen">
    <img alt="Platform" src="https://img.shields.io/badge/platform-iOS%20%7C%20iPadOS-lightgrey">
    <img alt="Status" src="https://img.shields.io/badge/status-research%20preview-orange">
  </p>

</div>

Lum1na is an open-source SwiftUI/Objective-C iOS and iPadOS research application for hardware owned and controlled by the developer. It includes a visual SwiftUI interface, device/profile abstraction, experimental runtime components, and low-level research code.

> **Safety and scope:** This is experimental research software for authorized testing only. Use it only on hardware you are legally allowed to modify. Do not redistribute builds, publish the private research material, or use the software against devices or systems you do not own or have explicit permission to test.

## Repository snapshot

This README describes the repository tree inspected at commit `5fdc64af590f3f15e9e5c1a3f68671eed851ca6c` on the `main` branch. Agents must re-resolve the current `main` tip before starting later work.

## Stack

- **Languages:** Swift 5, Objective-C, Objective-C headers, C-compatible bridge declarations, YAML, JSON, XML/plist.
- **Platform/runtime:** iOS/iPadOS application, SwiftUI, Xcode project, deployment target iOS 16.0.
- **Frameworks:** SwiftUI, Foundation, Combine, CoreML, IOKit, IOSurface, VideoToolbox, ImageIO, CoreImage, pthread.
- **Build:** `Lum1na.xcodeproj`, shared `Lum1na` scheme, Xcode 16.4 in CI, unsigned `iphoneos` Release build for the IPA workflow.
- **No package manager:** There is no `Package.swift`, `Podfile`, or external dependency manifest in the current tree.

## Current focus

The README's device notes are research targets, not a guarantee of support. Confirm the exact hardware identifier, OS version, and build number before every session.

- iPhone 12 / A14 research targets (`iPhone13,*` identifiers in `Exploit/Bridges/ExploitManager.swift`).
- iPad Pro research targets, including A12X-family identifiers (`iPad8,*` and additional iPad identifiers in `Exploit/Bridges/ExploitManager.swift`).
- `KernelMap/LabOffsets.swift` currently contains lab tables tagged `A14_23F77` and `A12X_23G71`.

## Exact current file structure

The following is the complete tracked tree at the snapshot above. Xcode user-state files are listed because they exist in the repository tree, but they are generated/local state and are not valid [...] 

## Core code structure

### Application and UI

- `App/Lum1naApp.swift` is the `@main` SwiftUI entry point and presents `ContentView` in a `WindowGroup`.
- `App/ContentView.swift` owns the main screen. It observes `ExploitManager.shared`, renders stage buttons, drives the animated logo state, embeds `MatrixConsoleView`, and displays running/ready [...]

### Runtime and exploit bridge

`Exploit/Bridges/ExploitManager.swift` is the current UI-facing coordinator. Its important existing symbols are:

- `ConsoleLine`, `ExploitStage`, and `ExploitResult`.
- `DeviceUtils` for the supported-device identifier lists, current identifier, category, and expected kernel base.
- `ExploitManager`, a `@MainActor` singleton `ObservableObject` with `selectedStage`, `isRunning`, `lines`, `progress`, and `lastError`.
- `FusionChainDelegate`, which reports completion, failure, progress, and log messages.
- `FusionChain`, which currently attempts P009, then P052, then P039 and reports results to the delegate.
- The Swift extensions that call `P009Controller`, `P052Controller`, and `P039Controller` through `executeWithKbase(_:error:)`.

## Xcode and target integration

`Lum1na.xcodeproj/project.pbxproj` is authoritative for target membership and build settings. The project uses filesystem-synchronized source groups, so do not casually add duplicate PBX file references.

## Build and CI

### Local Mac build

Open the project in Xcode, select the `Lum1na` scheme and a development team/device you control, then build or archive. Signing is required for installation on a device.

```bash
open Lum1na.xcodeproj
# In Xcode: select the Lum1na scheme and an authorized development device.
# Product → Build, or Product → Archive for a signed distribution artifact.
```

## Policy

UI, documentation, and project hygiene may change with normal review. Do not change race triggers, kernel read/write paths, leak implementations, offsets, entitlements, or other low-level exploit code without careful review.
