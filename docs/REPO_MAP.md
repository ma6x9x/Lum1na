# Lum1na repo map (what the app actually is)

IPA gate: GitHub **Lum1na Build** (`build-ipa.yml`, Xcode 16.4). Kernel read/write is **not** obtained.

## What you tap

| Control | What it runs | Crash history |
|---|---|---|
| JAILBREAK / Full Chain | KERNEL (AKS `execute` + P044 `execute`) → SANDBOX HOLD → DAEMON HOLD → PATCHSET HOLD | P051 then P053 then P054 killed the process. Auto chain no longer calls them. |
| KERNEL pad | same AKS + P044 | P044 `execute` completed in your 04:10 log |
| SANDBOX pad | HOLD log only | P051 gamed XPC, P053 NECP |
| DAEMON pad | HOLD log only | P054 4×500×30s unlink → **jetsam ~4s**, no `+tap` return |
| PATCHSET pad | HOLD: kreadbuf missing | used to lie “Chain complete!” |
| All stages | catalog `+tap` / `execute` by class name | ident / p010 / p032 / p046 are the safe ones. p017 can **panic**. p051/p053/p054 were process-kill. p054 tap is now 2s/1 thread. |
| Settings | Ident, copy TAP/console/recovery | should not crash |

If the console stops at `Invoking Foo...` and the app dies, that class is still inside `+tap`/`execute`. Documents may have `p0xx_*_log.txt` even when the UI never got the return string.

## Why P054 showed almost nothing

1. DAEMON TAP mapped recovery to `lum1na_console.log`, not `p054_reap_list_log.txt`.
2. `+tap` did not return (jetsam). UI only prints the NSString **after** tap returns.
3. Old tap: 4 pthreads × 500 files × 30s create/unlink. Watchdog/jetsam in ~4s.

Now: DAEMON pad HOLD; All-stages p054 is 1 thread × 50 files × 2s; recovery `DAEMON` → `p054_reap_list_log.txt`.

## Tree (current)

```
App/           ContentView, Lum1naApp
UI/            motherboard, glass, console, theme
Session/       PersistentLogStore, LabTime
Device/        DeviceUtils, DeviceCapabilities
Exploit/       probes + LabOff + LabDeviceProfile
Exploit/Bridges/ExploitManager.swift   catalog + invoke
docs/          FUTURE, development, this file
AGENTS.md      compile contract
```

Offsets: `LabRuntimeOffsets.m` only. SKU: `hw.machine` + `kern.osversion` **23F77**.

## Catalog (All stages)

Wired `+tap`: ident, p010, p017v2, p032–p034, p040–p042, p046, p050–p055.  
Wired `execute`: aks (`AKSExploitController`), p044, aio84530 (`CVE_2026_84530_KASLR`).  
On disk but **not** in the live catalog: P009/P035–P039/P052 controllers, CSKRW, AVERace, Lockdownd, Momentarius, Lum1naKRW placeholder.

## Agent rule

`AGENTS.md`. Do not put P051/P053/unbounded P054 back on JAILBREAK.
