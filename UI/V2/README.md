# Lum1na v2 UI shell

From-scratch SwiftUI chrome for the existing debugger app. Approved mockups live outside the repo (`lum1na-mockups/v2`).

## Tabs
- **Tests** — searchable grouped catalog (Probes / Taps / Chains / Kernel reads / Parked)
- **Chains** — real sequencers only (`FULL CHAIN`, `KERNEL`, `pathtest`, `krw`, `lightsword`, `swordchain`, `p044chain`)
- **Console** — CRT-first live `ExploitManager.lines`
- **Tools** — wired utilities only (export, hour logs, peek, SKU, board JSON, recovery, terminal)

## Hard rules
- Does **not** rewrite `Exploit/*.m/.h` attack bodies
- Views talk to `LuminaAppStore` → `ExploitManager` / board / LabLearn façades
- Dummy UI remains in-tree but is no longer the entry chrome
- AI model download is stubbed in Settings (follow-up)

## Entry
`App/ContentView.swift` → `LuminaRootView`
