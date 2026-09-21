# Lum1na — paste map (other-agent files)

Overwrite these paths with the files your other agent generated. Synced folder → no Xcode membership clicks.

| Your file | Paste over |
|-----------|------------|
| `Lum1naApp.swift` | `App/Lum1naApp.swift` |
| `ContentView.swift` | `App/ContentView.swift` |
| `ExploitManager.swift` | `Exploit/Bridges/ExploitManager.swift` |
| `MatrixConsoleView.swift` | `UI/MatrixConsoleView.swift` |
| `KASLRLeak.h` | `Exploit/KASLRLeak.h` |
| `KASLRLeak.m` | `Exploit/KASLRLeak.m` ← **you paste the real body** (stub is there now) |
| Bridging header | `Lum1na-Bridging-Header.h` (keep `#import "KASLRLeak.h"`) |
| `Lum1na.entitlements` | `Lum1na.entitlements` (paste your SideStore plist if you want) |

## After paste
1. Delete or empty `Exploit/Bridges/NativeLeakStubs.swift` if it still exists (Swift `KASLRLeak` enum clashes with ObjC class).
2. Confirm `Exploit/KASLRLeak.m` is **not** listed under `membershipExceptions` in `Lum1na.xcodeproj/project.pbxproj` (it must compile).
3. Still excluded on purpose: `ClearSword.m`, `Lum1naKRW.m`, `UPLLeak.m` (and old names if present).
4. Re-run **Build IPA**.

## Fixes already applied in stubs (keep if your paste is raw)
- `logoAnimation` naming consistent
- console gets manager via `ExploitManager.shared` (no missing `environmentObject`)
- `KASLRLeak.m` stub returns 0 until you paste real impl
