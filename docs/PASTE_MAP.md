# Lum1na — paste map

Overwrite these paths with your other agent's files:

| Your file | Paste over |
|-----------|------------|
| `Lum1naApp.swift` | `App/Lum1naApp.swift` |
| `ContentView.swift` | `App/ContentView.swift` |
| `ExploitManager.swift` | `Exploit/Bridges/ExploitManager.swift` |
| `MatrixConsoleView.swift` | `UI/MatrixConsoleView.swift` |
| `KASLRLeak.h` | `Exploit/KASLRLeak.h` |
| `KASLRLeak.m` | `Exploit/KASLRLeak.m` (**paste real body here** — stub only in repo) |
| Bridging header | keep `#import "KASLRLeak.h"` in `Lum1na-Bridging-Header.h` |
| Entitlements | `Lum1na.entitlements` |

`KASLRLeak.m` is **included** in the app target (not in membershipExceptions).
Still excluded: `ClearSword.m`, `Lum1naKRW.m`, `UPLLeak.m`.

After paste → push → re-run **Build IPA**.
