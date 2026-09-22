# AGENTS.md — Lum1na contributor and coding-agent guide

This is the operational guide for working in `ma6x9x/Lum1na`. Treat the repository at the pinned commit as the source of truth; do not rely on remembered file lists, old agent messages, or historical notes.

## 1. Start every task this way

1. Resolve the current `main` tip:
   `https://api.github.com/repos/ma6x9x/Lum1na/commits?sha=main&per_page=1`
2. Record the returned commit SHA.
3. Read the complete pinned tree:
   `https://api.github.com/repos/ma6x9x/Lum1na/git/trees/<SHA>?recursive=1`
4. Read relevant files from that same SHA only.
5. Before editing, confirm each exact path exists in the pinned tree.
6. After editing, re-check the diff and run the narrowest relevant validation available.

Current repository facts:

- Repository: `ma6x9x/Lum1na`
- Default branch: `main`
- Project: `Lum1na.xcodeproj`
- Shared scheme: `Lum1na`
- Primary CI workflow: `.github/workflows/build-ipa.yml`
- Current pinned tip used for this guide: `052d10ebedfc3ab3d16a2e18ab37a6493f373b5d`

The last item is only the revision used to write this document. Re-resolve `main` at the start of the next task.

## 2. Repository map

### App and UI

- `App/Lum1naApp.swift` — SwiftUI `@main` entry point.
- `App/ContentView.swift` — primary screen and stage controls.
- `UI/Lum1naViewModel.swift` — UI-facing state support.
- `UI/Lum1naTheme.swift` — palette and reusable visual styles.
- `UI/MatrixConsoleView.swift` — console presentation.
- `UI/ConsoleLine.swift` — console-line model.
- `UI/StarBeaconView.swift`, `UI/GlyphRainView.swift`, `UI/LiquidBubbleMotion.swift`, `UI/RainbowWaveRibbon.swift`, `UI/CentralHeapView.swift`, `UI/CircuitBackgroundView.swift`, `UI/HexagonBadgeView.swift`, `UI/ExploitStageSelector.swift` — visual components and effects.

### Runtime and support

- `Bootstrap/BootstrapCoordinator.swift` — bootstrap prerequisites and preparation.
- `Device/DeviceCapabilities.swift` — device profile protocol and model.
- `Device/DeviceUtils.swift` — device utility implementation currently present in the tree.
- `Resources/Compatibility.swift` — compatibility helpers.
- `Session/Logger.swift` and `Session/SessionPhase.swift` — session logging and phases.
- `Support/IOSurfaceShim/IOSurface/IOSurface.h` — SDK compatibility shim.

### Exploit and bridge code

Treat `Exploit/` as low-level, hardware/build-specific research code. Do not invent APIs, offsets, controller names, signatures, exploit behavior, or implementation status. Read a header and its implementation together before describing or changing behavior.

Important bridge files:

- `Exploit/Bridges/ExploitManager.swift` — `@MainActor` UI-facing coordinator.
- `Exploit/Bridges/ExploitControllerAdapters.swift` — Swift adapters for Objective-C controller methods.
- `Exploit/Bridges/FusionChainDelegate.h` — delegate declarations.
- `Exploit/Bridges/NativeLeakStubs.swift` — native-leak stubs.
- `Exploit/Bridges/cs_run.h` — C/Objective-C bridge declarations.

Important Objective-C pairs include:

- `Exploit/P009Controller.h` + `Exploit/P009Controller.m`
- `Exploit/P052Controller.h` + `Exploit/P052Controller.m`
- `Exploit/P039Controller.h` + `Exploit/P039Controller.m`
- `Exploit/ANE.h` + `Exploit/ANE.m`
- `Exploit/AVERace.h` + `Exploit/AVERace.m`
- `Exploit/CSKRW.h` + `Exploit/CSKRW.m`
- `Exploit/FusionChain.h` + `Exploit/FusionChain.m`
- `Exploit/KASLRLeak.h` + `Exploit/KASLRLeak.m`
- `Exploit/Lum1naKRW.h` + `Exploit/Lum1naKRW.m`
- `Exploit/Momentarius.h` + `Exploit/Momentarius.m`
- `Exploit/UPLLeak.h` + `Exploit/UPLLeak.m`

Additional probe, profile, APFS, JPEG UAF, Lockdownd, and persistence sources are present under `Exploit/`; verify their exact paths in the pinned tree before referencing them.

### Primitive and kernel-map layers

- `KernelMap/KernelMapDescriptor.swift`
- `KernelMap/KernelRW.swift`
- `KernelMap/LabOffsets.swift`
- `Primitive/PrimitiveProvider.swift`
- `Exploit/ExploitProvider.swift`

Do not describe placeholder methods as functional. In particular, inspect `KernelMap/KernelRW.swift` before making claims about kernel read/write capability.

### Tests and resources

- `Lum1naTests/Lum1naTests.swift` — unit tests.
- `UITests/Lum1naUITests.swift` — UI tests.
- `Assets.xcassets/` — app assets.
- `model/` — bundled Core ML resources, including compiled/generated model data.
- `docs/development.md` — experiment-record requirements.
- `docs/PASTE_MAP.md` — historical migration note, not proof of current files.

## 3. Swift/Objective-C interop checklist

The bridge is intentionally explicit. Current `Lum1na-Bridging-Header.h` imports:

```objc
#import "Exploit/KASLRLeak.h"
#import "Exploit/UPLLeak.h"
#import "Exploit/CSKRW.h"
#import "Exploit/ANE.h"
#import "Exploit/Lum1naKRW.h"
#import "Exploit/FusionChain.h"
#import "Exploit/Bridges/FusionChainDelegate.h"
#import "Exploit/Bridges/cs_run.h"
#import "Exploit/P009Controller.h"
#import "Exploit/P052Controller.h"
#import "Exploit/P039Controller.h"
```

Before diagnosing `cannot find ... in scope`, inspect all of the following at the same revision:

1. The relevant `.h` and `.m` files.
2. `Lum1na-Bridging-Header.h`.
3. `SWIFT_OBJC_BRIDGING_HEADER` in `Lum1na.xcodeproj/project.pbxproj`.
4. `Exploit/Bridges/ExploitControllerAdapters.swift`.
5. Target membership and filesystem-synchronized-group exceptions in `project.pbxproj`.

The Objective-C controller APIs are authoritative. Do not assume an Objective-C method can be represented as a Swift tuple-returning `@objc` protocol, and do not add duplicate declarations to make an error disappear.

The project uses `PBXFileSystemSynchronizedRootGroup`. Do not casually add PBX file references or manually duplicate source entries. Confirm the synchronized root and exception list before changing project structure.

## 4. Build and CI

The manually dispatched IPA workflow `.github/workflows/build-ipa.yml` currently:

1. Runs on `macos-15`.
2. Selects `/Applications/Xcode_16.4.app/Contents/Developer`.
3. Verifies selected source, header, bridge, and icon files.
4. May rewrite imports in `Exploit/Bridges/cs_run.h` in the CI checkout.
5. Applies a small SwiftUI compatibility replacement step in the CI checkout.
6. Builds the `Lum1na` scheme in `Release` for `iphoneos` with signing disabled.
7. Packages `Lum1na.app` as `Lum1na.ipa` and uploads it as `Lum1na-ipa`.

Equivalent core command:

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

Local device installation or archiving requires an authorized signing team/device. Do not claim a build or test passed unless it actually ran and passed. The Node 20 deprecation warning in Actions is not, by itself, a Swift compilation failure.

## 5. Change rules

- Read `README.md` and this file before editing.
- Prefer the smallest change that addresses the observed problem.
- Preserve public APIs unless the task explicitly requests an API change.
- For UI or project-layout changes, inspect the app entry point, `ContentView`, `ExploitManager`, affected UI components, bridging header, and `project.pbxproj` first.
- For interop changes, inspect headers, implementations, adapters, bridge imports, and target settings together.
- Keep generated Xcode user data, DerivedData, archives, dSYMs, IPAs, signing material, and secrets out of commits.
- Do not modify low-level exploit triggers, kernel read/write paths, offsets, or entitlements as a documentation/build-hygiene shortcut.
- Record experiments in `docs/development.md` with device model, OS version/build, Xcode version, component, result, and recovery steps.
- If a file is missing, report the exact pinned-tree lookup performed; never infer absence from an old README.
- If CI mutates files temporarily, do not copy those generated changes back into the repository without explicit justification.

## 6. Suggested investigation order

For a build failure:

1. Pin the revision and inspect the failing workflow.
2. Read the exact compiler error and identify the first real error.
3. Confirm the file exists and is in the intended target.
4. For Swift/Objective-C errors, follow the interop checklist above.
5. Reproduce with the narrowest `xcodebuild` command available.
6. Make one focused change, then rerun validation.

For a UI change:

1. `App/Lum1naApp.swift`
2. `App/ContentView.swift`
3. `Exploit/Bridges/ExploitManager.swift`
4. The affected UI component(s)
5. `UI/Lum1naTheme.swift`
6. `Lum1na-Bridging-Header.h` if bridge symbols are involved
7. `Lum1na.xcodeproj/project.pbxproj`

For low-level research code, stop and request clarification rather than guessing at missing primitives, offsets, devices, or exploit semantics.

## 7. Safety and scope

Lum1na is private experimental research software for hardware owned or controlled by the developer. Work only within authorized environments. Documentation, UI, tests, and project hygiene are ordinary maintenance areas; low-level exploit behavior and privileged entitlements require explicit scope and careful verification.
