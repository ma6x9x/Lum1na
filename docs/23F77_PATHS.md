# 23F77 (A14 / iOS 26.5) kernel paths — map and implementation status

Target: iPhone 13,2 (iPhone 12), 23F77, Darwin 25.5.0.
Kexts: AppleH11ANEInterface 9.511.3, IOSurface 393.5.7, IOHIDFamily 2360.2.2,
AppleAVE2 905.36.1.

## ANE (H11ANE 9.511.3)

| Path | Reach | Status |
|---|---|---|
| 43748 P044 N=192 | sel2 SendRequest (0x948/0x28), table 0x820 | live 1-record OOB write; occupancy CLASS/PASS, not KRW |
| P099/P073 254 | second-table 254-in | standalone MAF, catalog-solo |
| P010/P063 disclose | P139 harvest | layout/heap kptr; not KRW |
| P113 DescForge | forged desc → recv oracle | conversion oracle, needs live lane |
| ProgramCreate | sel3, structIn 0x20, size field **0x35e18**, magic **0xac738** | handler `FUN_875887c`; needs a valid 0x35e18 program blob |
| CVE-2026-112696/84494 bounds-safety | ANE command parser | vulnerable 23F77 counterparts `0x87b9cf8` (iPad fixed `0x8776fdc`), `0x8754198` (`0x87111a0`), `0x8701b60` (`0x86be754`); caller parser `FUN_87b9408`; needs a program/command blob |

The fixed iPad 9.512.2 functions contain `cmp/b.hi`, `sxtw+csel` poison and
`umulh/cmp xzr` checks; 23F77 lacks them at the paired addresses. That is the
new ANE write class, but it is reached through the ANE program parser, not a
bare selector.

## AVE2 (AppleAVE2 905.36.1)

| Path | Reach | Status |
|---|---|---|
| Signed writer underwrite | sel5 Start (0x1a0b0/0x150) → SPS+0x1f8 → `0x835bc60` | writer and `_AVE_DLList_PushBack` sink present; writer is a separate IOMalloc, so the macOS embedded-list geometry does not transfer; input→SPS+0x1f8 field still unmapped |
| Surface pool | p149-style encode/Set/invalidate | queue_init `0x81f3058` (`stp x0,x0,[x0]`), same pattern as T8150; ctor/dtor/kfree mapping in progress |

## IOSurface (393.5.7, CVE-2026-112477)

The ready-byte gate (`ldrb [obj,#0xf1]; tbz; return 0xe00002d8`) added in
393.5.10/403.1 is absent. The vulnerable insert function and its selector are
not yet mapped on 23F77; this is the p154 race candidate.

## IOHIDFamily (2360.2.2, CVE-2026-112515)

The fixed 2360.40.13 index clamp (`cmp; b.ge; csel`) is absent. The 23F77
table-index function and event reach are not yet mapped; IOHID event
generation is app-reachable via the private IOHID APIs (p0xx probe needed).

Bench27 (iOS 27.0.1) located the fixed shape: 27.2 adds `cmp w8, w9; b.ge`
before `smull x8, w8, #0x14` on an array at `+0x38`, count at `+0x40`, magic
`" hid"`. Reachability stayed closed there because
`AppleMultitouchDeviceUserClient` refused every open type. A 23F77 scan for
either immediate encoding of the magic found nothing, so 26.5 builds the
comparison differently — the next step is a mnemonic-profile diff of
IOHIDFamily 23F77 vs 24B119, not a magic hunt.

**p162** now enumerates the HID service family on-device (`IOHIDDevice`,
`IOHIDEventService`, `IOHIDEventDriver`, `IOHIDInterface`, `IOHIDResource`,
`AppleMultitouchDevice`, fast-path client) and tries `IOServiceOpen` types 0–4,
read-only. Any open client is the entry point the 112515 lane needs.

First receipt (2026-11-09, 12/23F77 and 17/24A435):

- `AppleARMPMUPowerSensor` and `IOHIDEventDriver` open at **type 2**
  (`kr=0`) on both devices; types 0/1/3/4 return `0xe00002c2` (BadArgument).
- `AppleMultitouchDevice` refuses every type (`0xe00002c2`); on 24A435 the
  `AppleMultitouchDeviceUserClient` instance exists but returns
  `0xe00002c7` (Unsupported) for every type.
- `IOHIDDevice` instances (SPUHID/BTM) return `0xe00002e2` (NotPermitted)
  except one instance on 23F77, which returns `0xe00002c7`.
- `IOHIDInterface` is `0xe00002c7`; `IOHIDResource` is `0xe00002c2`.

p162 v2 reads `IOUserClientClass`/`IOClass`/`CFBundleIdentifier` for each
service class, so the next run names the type-2 user client.

**CLOSED (2026-11-09, IOHID agent 24A435→24B119):** the type-2 class for
`IOHIDEventDriver`/`AppleARMPMUPowerSensor` is
**`IOHIDEventServiceUserClient`** (registry personality at
`0xfffffe000b5b7e78`; class vtable `0xfffffe000831dc70`). Its selectors do
not reach the `HIDPreparsedData` table path. The `" hid"` magic is the
immediate `0x68696420` at `0xa0bc4a0`; the object is
`site.HIDPreparsedData` (`0xfffffe00083218c8`), table base `+0x38`, count
`+0x40`, stride `0x14`, index from the **descriptor** at `[obj+8]+0x30`.

- 27.0 vulnerable getter `0xa0bc4b0`/`0xa0bc6d0` does
  `ldr w8,[x11]` — a 4-byte **OOB read**, no store. 27.2 `0xa10b4dc` adds
  `ldr w9,[x20,#0x40]; cmp w8,w9; b.ge` (signed upper bound only).
  The batch twin `0xa0c17a8`/`0xa0c1894` is also read-only.
- The leaked dword is consumed **in-kernel** (it becomes the `x1` of a
  container lookup); neither getter copies it to userland.
- The index is parsed from a HID report descriptor at service init
  (`0xa10e74c` / `0xa10e908` / `0xa10f040`), i.e. device-side input, not a
  user-client value. The type-2 UC has no app-facing selector table for
  this path; the `[x16+0x118]` calls are container/property lookups, not
  table accessors.

**Verdict: 112515 is an internal OOB read only — not an app-reachable
leak, not a write, and not a KRW step.** The type-2 open is still useful
for anything that uses event-service vtable methods, but not for 112515.
If a user client is ever implicated in descriptor handling it would be
`IOHIDLibUserClient` (IOHIDDevice personality `0xb5b8220`), not the
event-service UC.

## Existing paths

- P027/AppleJPEG, P063/aio84530, P139/P010/P063 disclose, P113, P044 — already
  in the app.
- IOGPU/P110/P142/P143 are 24A435 lanes; 23F77 equivalents are not wired.

## Closest KRW routes

1. **AVE2 surface-pool (p149 port)** — a proven heap-write/dtor class on
   24A435; 23F77 has the same queue_init pattern at `0x81f3058`. Next: map
   ctor/dtor/kfree and port the P149 sequence.
2. **ANE P044 neighbor corruption** — a live OOB write into a kalloc.3072
   neighbor; needs a shaped neighbor whose pointer/length is corruptible.
3. **AVE2 SPS underwrite** — blocked on the iOS writer-buffer/list geometry.
4. **ANE 112696/84494** — fixed functions mapped, but requires an ANE program
   blob/parser path.

## Implementation changes

- `p153` now sends ProgramCreate size **0x35e18** on 26.x (23F77) and keeps
  0xd88 on 27.x, with structIn 0x20/0x28 per the dispatch table.
