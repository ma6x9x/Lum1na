# CaseStudies cross-ref — vschko intel → Lum1na wiring (2026-10-15)

Source: https://github.com/vschko/CaseStudies (public write-ups, pushed
2026-09-22, **no license file** — attribution-only credit; no code copied,
implementations in this repo are ours from the described recipes). Full
write-ups were mirrored to `/tmp/casestudies/` during the session; only the
distilled facts below belong in the repo.

## Why this matters on 26.5 (23F77 / iPhone13,*)

The hunt device runs **26.5.0 GM (xnu-12377.122.4)**. Several CVEs fixed in
26.5.2 / 26.6 are **still live** on that build. The repo now carries probes
for every one that is reachable from a stock sandbox.

| CVE / class | What it gives | Fixed in | Live on 23F77 26.5? | Lum1na |
|---|---|---|---|---|
| CVE-2026-84530 AIO kqueue `kqext_sdata` leak | heap KVA leak (GEN1, not kslide) | iOS 27 | **YES — LIVE-PROVEN** (p063 `sdata=0xffffffe16d5aaa40` stable across completion, 2026-10-15 11:31 EDT) | `CVE_2026_84530_KASLR.m`, catalog `p063` |
| CVE-2026-43748 ANE direct-path prewire OOB | controlled OOB write into kalloc.3072 (write-door candidate B) | 26.6 | **YES** (F77 `fill_cap=0`; ungroomed shape = panics #1–#3) | `P099AnePrewireGroom` (groomed, detection-only) + `ANE254ChainController` lane |
| CVE-2026-65371 IOConsoleSecurityInterest `gRegistryRoot` | **instance** KVA leak (heap 0xfffffe…, NOT a slide oracle) | 26.6 | **YES** | `P097ConsoleSecLeak` |
| M2ScalerCSC `get_iosaDiag` (sel 8) IOSurface KVA (maybe CVE-2026-64709) | IOSurface KVA leak | 26.6 (23G71 confirmed) | probable | `P098M2ScalerDiag` (honest shape) |
| CVE-2026-39868 DTrace lazy DOF corruption | panic primitive | 26.5.2 | yes, but needs UID-0 `/dev/dtrace` → **PARKED** on stock iOS | — |
| CVE-2026-65408 ANE integer overflow terminate | DoS only (FAR still unnamed as wrapping multiply) | — | reach proven, no write | `P071` (map only) |

## Panic #1–#3 re-attribution (supersedes "wedge→harvest")

The three hunt-device panics match **CVE-2026-43748 ungroomed**, not the
DarkSword harvest theory:

- pc in `ANE_ProgramCheckandPrewireBuffers_gated` region; faulting record
  stride **0xc0**; **x25 = FAR − 0xc00** (record 0xc0 crossing the 0x820
  table into the next kalloc.3072 chunk, 0x3e0 past table end).
- GZAlloc "wild deref missing or invalid metadata" = the OOB smash landing
  in gzalloc chunk headers instead of groomed data.
- The writeup's recipe explains every number: `MemoryMapRequest_gated`
  writes prewire records BEFORE the late `bufferCount < 0x80` check at
  **count_off +0x810**; `ProgramSendRequest` allows 0xff buffers → indices
  ≥ 0xc1 cross the chunk.
- Consequence: the ANE lane is **UNPARKED for groomed standalone taps
  only** (P099). Never in the JAILBREAK chain. AVE P087 zero-completions
  finding stands (that was a different lane).

## P046 pin consistency (LabOff vs writeup)

All agree on 23F77:
- `fill_cap=0` (F77) — the catalog `fill_cap=1 → SKIP` gate is bypassed by
  the **direct path** (`_ANEModel/_ANEClient doEvaluateDirectWithModel`).
- MemoryMap cmp `0x874c830`, count_off `+0x810` (= writeup bufferCount).
- ANE table `0x820`, next-chunk `0xc0`, `n>=0xc1` reaches NEXT 3072.
- Fill order PROVED: fill ALL records → mmap cmp #0x80 → IOFreeType.

**P046 park note `MIL _ANEModel CLOSED`** is respected: P099's primary
model loader is the **compiled espresso path** (bundled
`XVRC27_254in_1out_addchain.mlmodelc` through CoreML, P033-consistent);
`_ANEModel` MIL is only an honest secondary attempt.

## Groom design (P099, from the writeup's PoC recipe, implementation ours)

- Drain 2048 inline mach messages, then 2048 hole/victim **inline** pairs
  (payload 0xb80 → kalloc.3072), free holes → victims sit adjacent.
  **Inline on purpose**: P044 found "fat type-3 OOL is the conversion
  neighbor" — OOL descriptors would turn the OOB into descriptor
  tampering; inline payloads are diffable bytes.
- ONE evaluation (254-in addchain, expected y = Σ inputs).
- Scan up to 4 victims for payload diffs; first_diff/0x10 ≈ record index.
- Panic-safe: no loops, no unbounded allocation, board untouched.

## p063 / 84530 — no new probe needed

P096 was canceled: `CVE_2026_84530_KASLR.m` (catalog p063) already
implements the exact ABI (structs verified identical to xnu-12377:
`kevent_qos_s` 72B, `kevent_extinfo` 104B, sdata@72; PROC_PIDFDKQUEUE_EXTINFO=9,
EVFILT_AIO=−3). The 2026-10-15 11:31 EDT run **live-proved** the leak on
23F77 (stable aio_workq_entry `0xffffffe16d5aaa40`, filter −3, persists
post-completion). Heap ≠ commitSlide: pair with a WRITE door (P099 lane B)
before any AfterKread ingest.

## CVE-2026-65371 details (P097)

Leak = **instance** KVA of the kalloc'd 0x28 `gRegistryRoot` root, passed
as `context.argument` (type 0xe0000128, argSize 0) by
`IOService::updateConsoleUsers`. Ghidra (T8101 12377, kbase
0xfffffff007004000): `gRegistryRoot` VAR SLOT = **0xFFFFFFF00A934FF8**
(single WRITE in `getRegistryRoot` `FUN_fffffff00a4b0e5c`); row added to
`LabIntelOffsets.m`. Recipe: `IOServiceAddInterestNotification` on
IOPlatformExpertDevice ("IOConsoleSecurityInterest") + lock/unlock once +
CFRunLoop ≤45 s. This is a heap leak, NOT a slide oracle.

## Chain plan toward Beta-1 on 26.5 (honest state)

1. p063 (LIVE) gives a stable heap KVA anchor.
2. P099 (groomed, standalone) is the write-door candidate B — needs the
   victim-adjacent-chunk shape step before it is a real write primitive.
3. P044 fat-type-3 note stays for the conversion neighbor lane.
4. P033 espresso loading is the model path (MIL `_ANEModel` CLOSED).
5. `hasKread` stays NO until a door yields `kread32(kbase)==0xfeedfacf`.
   Board, AfterKread, basebin ingest all HOLD until then.
6. 39868 needs root `/dev/dtrace` — parked.

### Rig validation (iPhone 11, A13_22G100 — KRW PASS 2026-10-15 12:00 EDT)

The 18.6.2 rig now has **real kread+kwrite** (hasKread=YES hasKwrite=YES,
kslide=0x12f30000, kbase=0xfffffff019f34000; kread32(kbase)=0xfeedfacf and
kread64(kbase+8)=0xc00000002 self-tests PASS). That makes the vschko leaks
**value-verifiable on the rig** before any 26.5 write-door work:

- p063: tap on the rig, then kread at the leaked aio_workq_entry KVA —
  plausible kevent/AIO struct bytes = the "GEN1 leak" is a REAL kernel
  pointer, not a coincidence.
- P097: tap on the rig (lock/unlock once), kread the leaked
  gRegistryRoot instance — IORegistryEntry-shaped memory confirms it.
- P099 groomed shape: rig kwrite can pre-fill victim payloads with known
  bytes, making the OOB diff deterministic (not just magic-0xa5 scan).

AfterKread FIRE on the rig held honestly at every gate (pmap row missing;
AMFI UC 0xe00002e2 → TC skip; spawns EPERM because elevate held on
kernproc-underived). **Rig unlock path: tap P094 (kernproc derive,
A13_22G100 anchor 0x35CC000 head16) → board kernproc-proven row →
re-run PATCHSET — elevate then does uid0 → unsandbox → CS_PLATFORM and
the opainject/jbctl spawns stop dying EPERM.**