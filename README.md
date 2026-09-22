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

Lum1na is a private SwiftUI/Objective-C iOS and iPadOS research application for hardware owned and controlled by the developer. It includes a visual SwiftUI interface, device/profile abstractions, low-level Objective-C research sources, exploit-to-Swift bridge code, kernel-map placeholders, and bundled Core ML resources.

> **Safety and scope:** This is experimental research software for authorized testing only. Use it only on hardware you are legally allowed to modify. Do not redistribute builds, publish the private repository, or invent/alter low-level exploit behavior without explicit authorization.

## Repository snapshot

This README describes the repository tree inspected at commit `5fdc64af590f3f15e9e5c1a3f68671eed851ca6c` on the `main` branch. Agents must re-resolve the current `main` tip before starting later work because the repository can change.

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

The following is the complete tracked tree at the snapshot above. Xcode user-state files are listed because they exist in the repository tree, but they are generated/local state and are not valid architectural source-of-truth.

```text
Lum1na/
├── .github/
│   └── workflows/
│       ├── build-ipa.yml
│       └── objective-c-xcode.yml
├── .gitignore
├── AGENTS.md
├── App/
│   ├── ContentView.swift
│   └── Lum1naApp.swift
├── Assets.xcassets/
│   ├── AppIcon.appiconset/
│   │   ├── AppIcon 2.JPG
│   │   ├── AppIcon 3.JPG
│   │   ├── Contents.json
│   │   └── Lum1naLogo.JPG
│   ├── Contents.json
│   └── README.md
├── Bootstrap/
│   └── BootstrapCoordinator.swift
├── Device/
│   ├── DeviceCapabilities.swift
│   ├── DeviceUtils.h
│   └── DeviceUtils.m
├── Exploit/
│   ├── ANE.h
│   ├── ANE.m
│   ├── AVERace.h
│   ├── AVERace.m
│   ├── Bridges/
│   │   ├── ExploitControllerAdapters.swift
│   │   ├── ExploitManager.swift
│   │   ├── FusionChainDelegate.h
│   │   ├── NativeLeakStubs.swift
│   │   └── cs_run.h
│   ├── CSKRW.h
│   ├── CSKRW.m
│   ├── ClearSword.m
│   ├── ExploitProvider.swift
│   ├── FusionChain.h
│   ├── FusionChain.m
│   ├── KASLRLeak.h
│   ├── KASLRLeak.m
│   ├── Lum1naKRW.h
│   ├── Lum1naKRW.m
│   ├── Momentarius.h
│   ├── Momentarius.m
│   ├── P009Controller.h
│   ├── P009Controller.m
│   ├── P009ReplaceBackingSmoke.h
│   ├── P009ReplaceBackingSmoke.m
│   ├── P039Controller.h
│   ├── P039Controller.m
│   ├── P052APFSNstream.h
│   ├── P052APFSNstream.m
│   ├── P052Controller.h
│   ├── P052Controller.m
│   ├── Persistence.h
│   ├── Persistence.m
│   └── UPLLeak.h
│   └── UPLLeak.m
├── KernelMap/
│   ├── KernelMapDescriptor.swift
│   ├── KernelRW.swift
│   └── LabOffsets.swift
├── Lum1na-Bridging-Header.h
├── Lum1na.entitlements
├── Lum1na.xcodeproj/
│   ├── README.md
│   ├── project.pbxproj
│   ├── project.xcworkspace/contents.xcworkspacedata
│   ├── project.xcworkspace/xcuserdata/kolby.xcuserdatad/UserInterfaceState.xcuserstate
│   ├── xcshareddata/xcschemes/Lum1na.xcscheme
│   └── xcuserdata/kolby.xcuserdatad/
│       ├── xcdebugger/Breakpoints_v2.xcbkptlist
│       └── xcschemes/xcschememanagement.plist
├── Lum1naTests/
│   └── Lum1naTests.swift
├── Primitive/
│   └── PrimitiveProvider.swift
├── README.md
├── Resources/
│   └── Compatibility.swift
├── Session/
│   ├── Logger.swift
│   └── SessionPhase.swift
├── Support/
│   └── IOSurfaceShim/IOSurface/IOSurface.h
├── UI/
│   ├── ConsoleLine.swift
│   ├── GlyphRainView.swift
│   ├── LiquidBubbleMotion.swift
│   ├── Lum1naTheme.swift
│   ├── MatrixConsoleView.swift
│   ├── RainbowWaveRibbon.swift
│   └── StarBeaconView.swift
├── UITests/
│   └── Lum1naUITests.swift
├── docs/
│   ├── Lum1naLogo.JPG
│   ├── PASTE_MAP.md
│   └── development.md
└── model/
    ├── XVRC27_254in_1out_addchain.mlmodelc/
    │   ├── analytics/coremldata.bin
    │   ├── coremldata.bin
    │   ├── metadata.json
    │   ├── model.espresso.net
    │   ├── model.espresso.shape
    │   ├── model.espresso.weights
    │   ├── model/coremldata.bin
    │   └── neural_network_optionals/coremldata.bin
    ├── model.mil
    ├── options.plist
    └── weights1.bin
```

> The tree above intentionally separates source, tests, project integration, docs, assets, and model resources. The compiled `.mlmodelc` contents are generated/binary model resources; do not hand-edit them.

## Core code structure

### Application and UI

- `App/Lum1naApp.swift` is the `@main` SwiftUI entry point and presents `ContentView` in a `WindowGroup`.
- `App/ContentView.swift` owns the main screen. It observes `ExploitManager.shared`, renders stage buttons, drives the animated logo state, embeds `MatrixConsoleView`, and displays running/ready state.
- `UI/StarBeaconView.swift` is the animated canvas-based hero beacon. It uses `Lum1naPalette` from `UI/Lum1naTheme.swift`.
- `UI/MatrixConsoleView.swift` observes the manager's console lines and renders the scrolling console plus matrix-rain background.
- `UI/Lum1naTheme.swift` defines `Lum1naPalette`, `LiquidGlassCard`, `LiquidGlassCapsuleButtonStyle`, and `LiquidGlassDisc`.
- `UI/ConsoleLine.swift`, `UI/GlyphRainView.swift`, `UI/LiquidBubbleMotion.swift`, and `UI/RainbowWaveRibbon.swift` provide UI models/effects used by the visual layer.

### Runtime and exploit bridge

`Exploit/Bridges/ExploitManager.swift` is the current UI-facing coordinator. Its important existing symbols are:

- `ConsoleLine`, `ExploitStage`, and `ExploitResult`.
- `DeviceUtils` for the supported-device identifier lists, current identifier, category, and expected kernel base.
- `ExploitManager`, a `@MainActor` singleton `ObservableObject` with `selectedStage`, `isRunning`, `lines`, `progress`, and `lastError`.
- `FusionChainDelegate`, which reports completion, failure, progress, and log messages.
- `FusionChain`, which currently attempts P009, then P052, then P039 and reports results to the delegate.
- The Swift extensions that call `P009Controller`, `P052Controller`, and `P039Controller` through `executeWithKbase(_:error:)`.

The Objective-C controller pairs are real current files: `P009Controller.h/.m`, `P052Controller.h/.m`, and `P039Controller.h/.m`. Do not invent replacement controller names or signatures. Inspect the corresponding headers and implementations before changing interop.

### Low-level layers

- `Exploit/*.h` and `Exploit/*.m` contain low-level research implementations and support code. Treat this directory as sensitive, hardware/build-specific code, not as a general-purpose API surface.
- `Exploit/Bridges/` contains Swift orchestration plus Objective-C/C bridge declarations.
- `Lum1na-Bridging-Header.h` currently imports `KASLRLeak.h`, `UPLLeak.h`, `CSKRW.h`, `ANE.h`, `Lum1naKRW.h`, `FusionChain.h`, `Bridges/FusionChainDelegate.h`, and `Bridges/cs_run.h`, all with the `Exploit/` prefix.
- `KernelMap/LabOffsets.swift` defines `LabOffTab`, `gA14`, `gA12X`, and `LabOff()`, which selects a table from the machine identifier.
- `KernelMap/KernelRW.swift` defines `KernelRW.shared`, `base`, `read64(at:)`, and `write64(at:value:)`. The current methods are placeholder implementations; do not describe them as functional kernel read/write primitives.
- `Primitive/PrimitiveProvider.swift` currently defines only `PrimitiveProvider.validate() throws`.
- `Exploit/ExploitProvider.swift` currently defines only `identifier` and `isSupported()`.
- `Bootstrap/BootstrapCoordinator.swift` currently defines only `validatePrerequisites()` and `prepare()`.
- `Device/DeviceCapabilities.swift` defines `DeviceProfile` and the `DeviceCapabilities.currentProfile()` protocol.
- `Session/SessionPhase.swift` defines `check`, `unsupported`, `hold`, `armed`, `running`, `done`, and `failed`.
- `Support/IOSurfaceShim/IOSurface/IOSurface.h` is a small SDK compatibility shim that imports `IOSurface/IOSurfaceRef.h`; the project adds `Support/IOSurfaceShim` to `HEADER_SEARCH_PATHS`.

## Xcode and target integration

`Lum1na.xcodeproj/project.pbxproj` is authoritative for target membership and build settings. The project uses filesystem-synchronized source groups, so do not casually add duplicate PBX file references. Confirm the project file and target membership before adding, moving, or renaming source files.

Current targets:

- `Lum1na` application target.
- `Lum1naTests` unit-test target.
- `Lum1naUITests` UI-test target.

The app target links CoreML, IOKit, IOSurface, VideoToolbox, ImageIO, CoreImage, and `libpthread`. It uses Swift 5, iOS 16.0, generated Info.plist settings, `Lum1na.entitlements`, and `Lum1na-Bridging-Header.h`.

The entitlements file currently includes elevated/private research entitlements such as task-port access, platform application, absolute-path access, selected IOKit user clients, and `get-task-allow`. Treat changes to it as security-sensitive and do not weaken or broaden access casually.

## Build and CI

### Local Mac build

Open the project in Xcode, select the `Lum1na` scheme and a development team/device you control, then build or archive. Signing is required for installation on a device.

```bash
open Lum1na.xcodeproj
# In Xcode: select the Lum1na scheme and an authorized development device.
# Product → Build, or Product → Archive for a signed distribution artifact.
```

### CI unsigned IPA workflow

`.github/workflows/build-ipa.yml` is manually dispatched. It runs on `macos-15`, selects Xcode 16.4, verifies selected Objective-C/Swift/bridge files, optionally rewrites `Exploit/Bridges/cs_run.h` import paths in the runner workspace, builds the `Lum1na` scheme in Release for `iphoneos` with signing disabled, and packages `Lum1na.ipa` as an artifact.

Equivalent core build command:

```bash
xcodebuild \
  -project Lum1na.xcodeproj \
  -scheme Lum1na \
  -configuration Release \
  -sdk iphoneos \
  -destination 'generic/platform=iOS' \
  CODE_SIGNING_ALLOWED=NO \
  CODE_SIGNING_REQUIRED=NO \
  CODE_SIGN_IDENTITY="" \
  build
```

Do not claim that a build or test passes unless it was actually run. Keep `.ipa`, `.xcarchive`, dSYM, DerivedData, signing material, and other build output out of commits.

## Documentation and history notes

- `AGENTS.md` is the detailed agent navigation and verification guide. Read it before making changes.
- `docs/development.md` requires recording device model, OS version/build, Xcode version, component tested, result, and recovery steps for experiments.
- `docs/PASTE_MAP.md` is a historical paste/migration note. It is not proof that a listed file is current; verify against the current tree first.
- `Assets.xcassets/README.md` explains the current app-logo asset situation.

## Copy/paste context for coding agents

Copy the block below into another coding agent before asking it to modify this repository:

```text
You are working in ma6x9x/Lum1na, a private SwiftUI iOS/iPadOS research app. Treat the repository at the current commit as the only source of truth. Before editing: read AGENTS.md and README.md, resolve the current main commit SHA, inspect the complete recursive tree at that SHA, and verify every path you touch exists there. Do not rely on remembered files or historical paste instructions.

Stack: Swift 5 + SwiftUI/Combine/Foundation, Objective-C/C bridge sources, Xcode project, iOS deployment target 16.0. No Swift Package Manager, CocoaPods, or external dependency manifest. The app target is Lum1na; test targets are Lum1naTests and Lum1naUITests. The shared scheme is Lum1na.

Main entry flow: App/Lum1naApp.swift (@main) presents App/ContentView.swift. ContentView observes Exploit/Bridges/ExploitManager.swift through ExploitManager.shared and renders stage controls plus UI/MatrixConsoleView.swift. UI/StarBeaconView.swift and UI/Lum1naTheme.swift contain the current beacon/theme design.

Current coordinator symbols: ConsoleLine, ExploitStage, ExploitResult, DeviceUtils, FusionChainDelegate, @MainActor ExploitManager, and @MainActor FusionChain are in Exploit/Bridges/ExploitManager.swift. FusionChain currently attempts P009, then P052, then P039. The controller bridge calls P009Controller, P052Controller, and P039Controller using executeWithKbase(_:error:); inspect the actual .h/.m files before changing this API.

Current important paths:
- App/Lum1naApp.swift, App/ContentView.swift
- UI/ConsoleLine.swift, UI/GlyphRainView.swift, UI/LiquidBubbleMotion.swift, UI/Lum1naTheme.swift, UI/MatrixConsoleView.swift, UI/RainbowWaveRibbon.swift, UI/StarBeaconView.swift
- Exploit/Bridges/ExploitManager.swift, Exploit/Bridges/ExploitControllerAdapters.swift, Exploit/Bridges/FusionChainDelegate.h, Exploit/Bridges/NativeLeakStubs.swift, Exploit/Bridges/cs_run.h
- Exploit/*.h and Exploit/*.m, including the P009/P052/P039 controller pairs
- KernelMap/KernelMapDescriptor.swift, KernelMap/KernelRW.swift, KernelMap/LabOffsets.swift
- Primitive/PrimitiveProvider.swift, Exploit/ExploitProvider.swift, Bootstrap/BootstrapCoordinator.swift
- Device/DeviceCapabilities.swift, Device/DeviceUtils.h, Device/DeviceUtils.m
- Session/Logger.swift, Session/SessionPhase.swift, Resources/Compatibility.swift
- Lum1na-Bridging-Header.h, Lum1na.entitlements, Lum1na.xcodeproj/project.pbxproj
- Support/IOSurfaceShim/IOSurface/IOSurface.h
- Lum1naTests/Lum1naTests.swift, UITests/Lum1naUITests.swift
- model/ (bundled Core ML resources), Assets.xcassets/, docs/

Interop rules: the bridging header currently imports Exploit/KASLRLeak.h, Exploit/UPLLeak.h, Exploit/CSKRW.h, Exploit/ANE.h, Exploit/Lum1naKRW.h, Exploit/FusionChain.h, Exploit/Bridges/FusionChainDelegate.h, and Exploit/Bridges/cs_run.h. Inspect the bridging header, the relevant .h/.m files, and project.pbxproj together before changing Swift/Objective-C interop. Do not invent controller names, methods, offsets, exploit behavior, or missing files. KernelMap/KernelRW.swift currently returns 0/no-op for its read64/write64 placeholders; do not call it a working implementation.

Project rules: project.pbxproj uses filesystem-synchronized source groups. Confirm target membership before adding/renaming files. Do not add duplicate PBX references. Keep generated Xcode user data, build output, archives, IPAs, signing material, and secrets out of commits. This is authorized private research software; do not broaden capabilities or modify low-level exploit logic unless the task explicitly authorizes that exact change. Run the narrowest relevant xcodebuild/test command available and report honestly whether it ran and passed.
```

## Policy

UI, documentation, and project hygiene may change with normal review. Do not change race triggers, kernel read/write paths, leak implementations, offsets, entitlements, or other low-level exploit logic unless the owner explicitly requests that specific change and the change is reviewed against the actual headers, implementations, target membership, and device/build assumptions.
