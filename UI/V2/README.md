# Lum1na v2 shell

4-tab UI chrome on `redesign/lum1na-v2`:

- **Tests** — grouped catalog + honesty badges + glass search; Settings gear by title; Settings pushed from Tests
- **Chains** — live STEP/[chain] rung receipts, hold-to-reorder steps, violet Run pill
- **Console** — CRT-only structured stream (time / level / process[pid] / subsystem / message)
- **Tools** — wired utilities only; Export session shares

Pinned summary chip lives on the **root** overlay (every tab). Results are a **bottom-anchored** glass sheet with grabber; collapse moves toward the chip. Exploit/*.m/.h untouched.

## Console honesty (os_log)

Console merges:

1. **Run log** (`ExploitManager.lines`) — always attributed as `lum1na[<pid>]`. Never invents `kernel[0]` / `syslogd[1]` / other processes. A `[KERN]` tag in the message sets `isKernelTagged` for the kernel filter only.
2. **Own-process OSLogStore** (`OSLogStore(scope: .currentProcessIdentifier)`) via `AppOSLogBridge` — real `OSLogEntryLog` rows for this process only.

**Gap:** if OSLogStore throws or returns empty (privacy / entitlement), the UI shows `os_log: run-log only` and keeps the run log. We do **not** fabricate kernel/syslogd rows to fill the gap.

## Settings honesty

- **Auto-advance steps** is hidden until it can be wired into sequencer advance (`executeStage` is atomic; a UI-only toggle would be a façade).
- **Default level** floors Console severity (Debug / Info / Default / Error) across the merged stream.
- **Stop on failure** still paints remaining chain rungs as pending after a failed step.
