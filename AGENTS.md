# AGENTS.md — keep Lum1na compiling

Read this before editing. The IPA job (`.github/workflows/build-ipa.yml`) is the source of truth: **macos-15, Xcode 16.4, iOS 18.0 deployment, unsigned `iphoneos`**. If that job is red, the change is not done.

Re-resolve `main` at the start of a task. Do not trust this file’s remembered file list if it disagrees with the tree.

## Layout (current)

| Path | Role |
|---|---|
| `App/ContentView.swift` | Home: centered LUM1NA, motherboard, console, JAILBREAK |
| `App/Lum1naApp.swift` | `@main` |
| `UI/` | Theme, motherboard, glass, circuit background, console |
| `UI/LuminaGlass.swift` | Glass look via `ultraThinMaterial` (no `.glassEffect()` — Xcode 16.4 SDK) |
| `Exploit/Bridges/ExploitManager.swift` | Catalog, TAP, invoke `+tap` / `execute` |
| `Session/PersistentLogStore.swift` | POSIX + `F_FULLFSYNC`, `p011_tap_log.txt` |
| `Session/LabTime.swift` | `yyyy-MM-dd HH:mm:ss z` |
| `Exploit/LabRuntimeOffsets.*` | **Only** VA table. `LabOff()` |
| `Exploit/LabDeviceProfile.*` | SKU = `hw.machine` + `kern.osversion` |
| `Exploit/A14_23F77_LabOffsets.h` | Pins + `LabOff()` redirects |
| `Exploit/A12X_23G71_LabOffsets.h` | iPad 23G71 pins |
| `Lum1na-Bridging-Header.h` | iOS-safe Mach/IOKit + probe headers |
| `docs/FUTURE.md`, `docs/development.md` | Status / experiment log |

The project uses `PBXFileSystemSynchronizedRootGroup`. New files under the root are picked up automatically. Do not hand-edit pbx file lists unless you are changing **exceptions**.

Stale names (do **not** resurrect): FusionChain, KernelMap/LabOffsets.swift duplicate table, `AIOKqueueLeakController`, `Font.system(.caption, weight:, design:)` with weight before design.

## Compile landmines (already paid for)

1. **`Font.system` argument order**  
   Wrong: `.system(.caption, weight: .bold, design: .rounded)` — Xcode 16.4 matches `size:` and dies (`CGFloat has no member caption`).  
   Right: `.system(.caption, design: .rounded, weight: .bold)` **or** `.system(size: 12, weight: .bold, design: .rounded)`.

2. **No macOS-only headers**  
   Never `#import <mach/mach_vm.h>`, `IOKit/IOBSD.h`, `IOSurface/IOSurface.h`. IOSurface is `dlsym`. Mach via `<mach/mach.h>` + `<mach/vm_map.h>`.

3. **Do not duplicate `LabOff()` / `LabOffTab` in Swift.**  
   C table in `LabRuntimeOffsets.m` is the only VA source. Swift helpers: `labOffsetTag()` in `UI/LabOffsets.swift`.

4. **`stopUnlessA14_23F77:`**  
   P007 convention: **non-nil = STOP**. Probes do `if (stop) return stop`. Returning a sku string on success aborts every probe on a good 23F77 device.

5. **ObjC `NSString *` in Swift**  
   Interpolating an optional prints `Optional("…")`. Use `as String? ?? "?"`.

6. **Logging must stamp once**  
   `ConsoleLine.formatted` already has `yyyy-MM-dd HH:mm:ss z`. Never dump disk lines back through `log()` without `stripStamp`. Never dump `[RECOVER]` transcripts into the next session.  
   On-screen console is **P007 replace-on-tap**: `resetOnScreenLog()` at each `executeExploit` / `executeStage`. Do not append the previous probe. Disk TAP + `p0xx_*_log.txt` stay append-only.

7. **iOS 26 Liquid Glass API**  
   `.glassEffect()` / `.buttonStyle(.glass)` need Xcode 26. CI is 16.4. Use `luminaGlassCapsule()` / `luminaGlassRect()` only.

8. **Bridging header**  
   Only import headers that exist. NSClassFromString does not need a bridge import, but `LabOff()` / `LabDeviceProfile` do.

9. **Auto chain vs catalog**  
   JAILBREAK must not invoke process-killing probes. P051, P053, and unbounded P054 (4×500×30s unlink) jetsam'd the app. SANDBOX and DAEMON pads are HOLD. All-stages p054 is bounded (2s / 1 thread). Do not restore the storm loop.

## Probe wiring

New ObjC probe:

```objc
@interface P0XXThing : NSObject
+ (NSString *)tap;   // returns the log body
@end
```

Then:

1. Files under `Exploit/` (sync group).
2. Add the `.h` to `Lum1na-Bridging-Header.h` if Swift must see the type.
3. Catalog entry in `ExploitManager.catalog` with `controllerClass` **exactly** the ObjC class name.
4. Map `id` → Documents log filename in `PersistentLogStore.probeLogFiles`.
5. Log file: POSIX `open` / `write` / `F_FULLFSYNC`. Session banner `=== p0xx session <LabLocalMilitaryNow()> BUILD … ===`.

`invokeController` order: instance `execute`, then `tap` (instance then class). `+tap` returning `NSString` is the P007 shape.

## Offsets / SKU

- Active: `iPhone13,*` + **23F77** → table tag `A14_23F77`.
- Twin: `iPad8,*` + **23G71** → `A12X_23G71`.
- Detect with `kern.osversion`, never `UIDevice` `"26.5"`.
- Do not paste T8101 VAs onto T8020.
- `A14_23F77_*` names in probes follow `LabOff()` via redirects (queue size 0x410 vs 0x408).

## UI contract

- Centered **LUM1NA** at the top. No cloud wisps, glyph rain, or rainbow ribbon on the home screen.
- Motherboard: four-point star hub, energy to KERNEL / SANDBOX / DAEMON / PATCHSET. No center ring.
- Console: one monospaced stream of `ConsoleLine.formatted`. No second timestamp column.
- PATCHSET / JAILBREAK must not claim success if `kreadbuf` is missing.

## What not to change without an explicit ask

- Race / UAF / OOB / remaining-fire bodies in `Exploit/*.m`
- Offset numbers unless Ghidra + this SKU proved them
- Entitlements
- CI Xcode version
- `LAB_OFFSETS_NO_REDIRECT` spelling (`1`, not `NO_REDIRECT1`)

## Build check

```bash
xcodebuild -project Lum1na.xcodeproj -scheme Lum1na \
  -configuration Release -sdk iphoneos \
  -destination 'generic/platform=iOS' \
  CODE_SIGNING_ALLOWED=NO CODE_SIGNING_REQUIRED=NO CODE_SIGN_IDENTITY="" \
  build
```

The `objective-c-xcode.yml` workflow is historically red. **Lum1na Build** (IPA) is the gate.

## Honesty

Kernel read/write is **not** obtained. `Lum1naKRW` is a placeholder. One failed tap does not close a CVE class (`docs/FUTURE.md`, lab notes 89). Lab panic app is `~/Desktop/P007OpenOnly`. This repo is the public shell + catalog.
