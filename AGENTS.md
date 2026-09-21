# AGENTS.md — Lum1na repository guide

This file is the source-of-truth navigation guide for coding agents working in `ma6x9x/Lum1na`. Read it before inspecting or editing anything.

## Repository identity and freshness

- Repository: `ma6x9x/Lum1na`
- Default branch: `main`
- Repository URL: https://github.com/ma6x9x/Lum1na
- Build workflow: [`.github/workflows/build-ipa.yml`](.github/workflows/build-ipa.yml)
- Xcode project: [`Lum1na.xcodeproj`](Lum1na.xcodeproj)

Never rely on a remembered file list or an earlier agent response. At the start of every task:

1. Resolve the current tip of `main` from `https://api.github.com/repos/ma6x9x/Lum1na/commits?sha=main&per_page=1`.
2. Record that commit SHA.
3. Read the complete tree from `https://api.github.com/repos/ma6x9x/Lum1na/git/trees/<SHA>?recursive=1`.
4. Read all relevant files at that same SHA. Do not mix files from different revisions.
5. Before changing a file, confirm that its exact path exists in the pinned tree.

The latest inspected CI snapshot associated with the Build IPA failure was commit `98a3f2952bb4cd34c131220086f15fd78b3fb360`. That SHA is historical context only; agents must resolve the current `main` tip before working.

## Current source layout

### Application and UI

- `App/Lum1naApp.swift` — SwiftUI application entry point.
- `App/ContentView.swift` — primary application view.
- `UI/ConsoleLine.swift` — console line model.
- `UI/MatrixConsoleView.swift` — console presentation.
- `UI/GlyphRainView.swift` — glyph-rain animation.
- `UI/LiquidBubbleMotion.swift` — liquid bubble motion.
- `UI/Lum1naTheme.swift` — theme definitions.
- `UI/RainbowWaveRibbon.swift` — ribbon animation.
- `UI/StarBeaconView.swift` — star beacon view.

### Runtime coordination and support

- `Bootstrap/BootstrapCoordinator.swift` — bootstrap coordination.
- `Device/DeviceCapabilities.swift` — device capability logic.
- `Device/DeviceUtils.h` and `Device/DeviceUtils.m` — Objective-C device helpers.
- `Resources/Compatibility.swift` — compatibility helpers.
- `Session/Logger.swift` — session logging.
- `Session/SessionPhase.swift` — session state/phase definitions.
- `Support/IOSurfaceShim/IOSurface/IOSurface.h` — IOSurface shim declarations.

### Exploit and bridge sources

Treat this directory as low-level research code. Do not invent APIs, controller names, method signatures, exploit behavior, offsets, or missing files. Read the corresponding header and implementation together before making claims.

- `Exploit/ANE.h`, `Exploit/ANE.m`
- `Exploit/AVERace.h`, `Exploit/AVERace.m`
- `Exploit/CSKRW.h`, `Exploit/CSKRW.m`
- `Exploit/ClearSword.m`
- `Exploit/DeviceUtils.h`, `Exploit/DeviceUtils.m`
- `Exploit/FusionChain.h`, `Exploit/FusionChain.m`
- `Exploit/KASLRLeak.h`, `Exploit/KASLRLeak.m`
- `Exploit/Lum1naKRW.h`, `Exploit/Lum1naKRW.m`
- `Exploit/Momentarius.h`, `Exploit/Momentarius.m`
- `Exploit/P009Controller.h`, `Exploit/P009Controller.m`
- `Exploit/P039Controller.h`, `Exploit/P039Controller.m`
- `Exploit/P052Controller.h`, `Exploit/P052Controller.m`
- `Exploit/Persistence.h`, `Exploit/Persistence.m`
- `Exploit/UPLLeak.h`, `Exploit/UPLLeak.m`
- `Exploit/Bridges/ExploitManager.swift` — Swift orchestration and UI-facing bridge.
- `Exploit/Bridges/FusionChainDelegate.h` — FusionChain delegate declarations.
- `Exploit/Bridges/NativeLeakStubs.swift` — Swift native-leak stubs.
- `Exploit/Bridges/cs_run.h` — C/Objective-C bridge declarations.

The three controller pairs are real repository files:

- `Exploit/P009Controller.h` + `Exploit/P009Controller.m`
- `Exploit/P052Controller.h` + `Exploit/P052Controller.m`
- `Exploit/P039Controller.h` + `Exploit/P039Controller.m`

Do not report these controllers as absent without first checking the pinned tree and both files. Do not assume their Objective-C interfaces match a Swift tuple-returning protocol.

### Kernel map and primitive layers

- `KernelMap/KernelMapDescriptor.swift`
- `KernelMap/KernelRW.swift`
- `KernelMap/LabOffsets.swift`
- `Primitive/PrimitiveProvider.swift`
- `Exploit/ExploitProvider.swift`

### Project integration and interop

- `Lum1na.xcodeproj/project.pbxproj` — authoritative target membership and build settings.
- `Lum1na.xcodeproj/xcshareddata/xcschemes/Lum1na.xcscheme` — shared build scheme.
- `Lum1na-Bridging-Header.h` — current Swift/Objective-C bridge header.
- `Lum1na.entitlements` — app entitlements.

The current bridging header imports these paths:

```objc
#import "Exploit/KASLRLeak.h"
#import "Exploit/UPLLeak.h"
#import "Exploit/CSKRW.h"
#import "Exploit/ANE.h"
#import "Exploit/Lum1naKRW.h"
#import "Exploit/FusionChain.h"
#import "Exploit/Bridges/FusionChainDelegate.h"
#import "Exploit/Bridges/cs_run.h"
```

Before diagnosing a Swift `cannot find ... in scope` error, inspect both `Lum1na-Bridging-Header.h` and the `SWIFT_OBJC_BRIDGING_HEADER` setting in `Lum1na.xcodeproj/project.pbxproj`. Also inspect the controller headers and target membership. The CI file's existence check does not prove that a file is compiled or imported.

The project uses a filesystem-synchronized source group. Do not casually add duplicate PBX file references. Confirm target membership and the synchronized-group exception list in `project.pbxproj` first.

### Tests, resources, and documentation

- `Lum1naTests/Lum1naTests.swift` — unit tests.
- `UITests/Lum1naUITests.swift` — UI tests.
- `Assets.xcassets/` — app assets.
- `model/` — bundled Core ML model resources; treat compiled model files as binary/generated resources.
- `docs/development.md` — development and session notes.
- `docs/PASTE_MAP.md` — historical paste map; use it as a migration note, not as proof that a file is current.
- `README.md` — project scope, supported-device notes, layout, and safety/polish policy.

## Build and CI facts

The Build IPA workflow currently:

1. Runs on `macos-15`.
2. Selects `/Applications/Xcode_16.4.app/Contents/Developer`.
3. Verifies selected Objective-C source files exist.
4. Optionally rewrites imports in `Exploit/Bridges/cs_run.h`.
5. Builds `Lum1na.xcodeproj` using scheme `Lum1na`, configuration `Release`, and SDK `iphoneos`.
6. Disables code signing for the build.
7. Packages the resulting `Lum1na.app` into `Lum1na.ipa`.

The Node 20 deprecation message is a warning and is not the cause of Swift compilation failures.

For the CI failure that motivated this guide, the relevant errors were:

- A tuple return type in an `@objc` protocol cannot be represented in Objective-C.
- `P009Controller`, `P052Controller`, and `P039Controller` could not be found in Swift.

Agents must verify the actual current declarations before proposing a fix. Do not solve the first error by inventing a new controller API, and do not solve the second by adding duplicate headers without checking the existing bridging header and Xcode project settings.

## Editing and verification rules

1. Read this file and `README.md` before editing.
2. Pin all investigation to one resolved commit SHA.
3. Prefer the smallest change that addresses the observed error.
4. Preserve existing public APIs unless the task explicitly requests an API change.
5. For Objective-C/Swift interop, inspect `.h`, `.m`, the bridging header, and `project.pbxproj` together.
6. After source changes, run the narrowest relevant test or `xcodebuild` command available.
7. Do not claim a build passes unless the build actually ran and passed.
8. Do not treat historical notes in `docs/PASTE_MAP.md` or this file as newer than the pinned repository tree.
9. Never fabricate file contents, implementation status, commit SHAs, or test results.
10. Keep generated artifacts, `.ipa` files, archives, and Xcode user data out of commits.
