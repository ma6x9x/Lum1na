# Lum1na future map

This is the public-app companion to `~/Desktop/lumina_primitives/87_EXTERNAL_CONTEXT_NOTES.txt`. It is not a claim that KRW exists.

## Split

| Tree | Role |
| --- | --- |
| `P007OpenOnly` | Panic lab. Ident, probes, Documents logs |
| `Lum1na` (this repo) | Motherboard UI, P007-style logging, catalog of `+tap` probes |
| Dopamine 3.0.10 | Post-KRW BaseBin reference only. Supports 26.0–26.0.1 A12/A13. A12X iPad is A12 CPU (Vortex/Tempest) but 26.6 is past End; hop-1 dead since 26.1. Do not bump End. Catalog `dopaminecompat` is the honest diagnostic. |

## Proven on 23F77 (do not backtrack)

- SysMem MD `+0x90`, queue create `0x410`, leak `+0x558`
- fn4 `0xFFFFFFF0095C94AC`, getter `0xFFFFFFF0095E1BDC`
- ANE CheckandPrewire `0xFFFFFFF00874C070` (G71+ fill-capped)
- wvek `0xFFFFFFF009BD96D4` (26.7 adds `len <= 512`)
- icmp6filt `+0x148` unused until a real inpcb
- AKS user client **opens**. CVE-2026-65343 deserialize is a KASLR OOB read (ACM `declared_length`). Catalog `aks` tap is bounded ACM capture. Not KRW.
- CVE-2026-84530 class is public and live until iOS 27
- 2026-10-14 hunt evidence: T1's 254 addchain predict fails on 26.5 CoreML (`error -1` "invalid input data or broken/unsupported model", small 1-in/1-out works) — the 254 fire never runs, occupancy MISS ×4. T1 blocker until the addchain model is chunked or regenerated for 26.5. ClearSword (43520) is patched on 23F77 — cs2core establish now gates by build train (22A–22G / 23A only); ungated it jetsam'd the app ×5 in one day. Rapier died mid-race twice (~3s, 18:52/18:57) — check hunt panic-full logs for pc=cd8/d00 (HIT) vs cc8 (MISS). Two rig panics 16:40/16:44 decoded: ClearSword UAF tuition (stale VM-zone read far=0xffffffdc07557110; tagged-ptr deref far=0x00200000000000a8), an hour before the 17:35 commitSlide.
- 2026-10-14 hunt panic logs DECODED (5 kernel + 2 app, all 23F77/T8101, Fileset UUID 107196E1):
  - **17:55:33 — `[data.kalloc.3072]: element modified after free (off:0, val:0x000000c0000001e5, ptr:0xffffffe5c11a1c00)`** — the kernel zone monitor CAUGHT a write into a freed kalloc.3072 during the P044/T1 window (24 s after the 17:55 fire). off:0 = the freelist-next slot. This is kernel-confirmed proof the 43748/second-table OOB write FIRES — the miss is grooming (the element after the table was freed before the write), not the primitive. Next T1 move: hold the neighbor alive through the fire window instead of punching all 128 holes.
  - **18:15:51 — watchdogd 93 s / 18:48:06 — wifid 186 s** — cs2core resource starvation (22528 sockets + 8×128MiB remap), no kernel memory bug. Covered by the build-train gate (e8bea39). App-level twins: Lum1na 17:38 SIGABRT (self-abort in spray), 18:18 0x8BADF00D (main thread wedged past the 5 s exit watchdog).
  - **18:52:44 + 18:57:45 — IOGPU data aborts (the rapier deaths)**: identical backtrace under KernelCache slide (validated: caller `0xa5f74d4` = panic entry shim, frame `0x9e070e4` = panic() itself — both renamed in Ghidra). Faulting pc is in IOGPUFamily: panic #1 pc `0x95b7c84` inside a function that calls our `cve64788_IOGPU_raw_MD_get_plus90()` and dispatches `(**code**)(vtable+0xa8)`; #2 pc `0x9857cc8` (vtable+0x48). `far = 0x00200000000000a8 / 0x48` with `x16 = 0x0020000000000000` EXACTLY = the zone freelist/native-tag terminator → **an IOGPU object was freed while still referenced; its vtable slot was overwritten by the freelist encoding; the next GPU dispatch aborted**. Panic #2's boot ran ONLY rapier (fresh 18:53:37 reboot → rapier 18:57:20 → abort 18:57:45), so rapier's sel36 race corrupts IOGPU neighbors on its own. Same signature as the rig 16:44 panic (far …a8) — the A13 ClearSword run corrupted the same way. Rapier stays PARKED. Ghidra renames: `panic185244_pc_IOGPU_MD_vtable_plus_a8`, `panic_data_abort_entry_shim`, `panic_core`.
- PATH B 43748 kalloc.3072 **store** is live on 23F77 (FILL HIT). Conversion to kreadbuf is HOLD (type-1 payload-only, type-3 PACGA, second table ephemeral, icmp6filt wrong zone). Dual-wrap LightSword last-wire detach is GPU OOM (18:45). Home (`phys-map-1`): T1–T4 KRW theories, T5 PAC HOLD, T6 PPL map + AfterKread (inject still gated on hasKread), T7 PHYS MAP (registry + read-only MapMemory for Titan IORVBAR `0x206050000`; no `+0x34` fire). `DopaminePrimitives.h` is the credited gPrimitives contract. Hop-1/kfd bodies not copied.

## 23G71 A12X (T8020) — do not paste T8101

Unpatched: 64788 until 23G82; AKS 65343 until 23G83; aio84530 until 26.7/27; wvek BRK `len>0x210`.

Capped / FIXED: 43748 fill_cap; 64747 AVE mul; 64751 NECP flow UAF; CS hop-1 26.1. P044/P053/cscalib skip remaining-fire on those.

## Public write-ups worth keeping

- [CVE-2026-84530](https://github.com/vschko/CaseStudies/tree/main/CVE-2026-84530) — AIO kqueue `kn_sdata`
- [CVE-2026-43748](https://github.com/vschko/CaseStudies/tree/main/CVE-2026-43748) — ANE prewire table `0x80` vs `0xff`

FomoPeek/DarkSword local LPE stopped at iOS 26.1. Not this build.

## After kreadbuf (first tweak injection)

Dopamine 3.0.10 does not run on A14 23F77. Relaxin is a RootHide/ElleKit jailbreak on other SKUs. Lum1na reuses **names and layout**, not their KRW.

1. KRW self-test: `kread32(kbase) == MH_MAGIC_64`. Then AMFI UserClient loadTrustCache sel 2/7 + `pmap_cs_allow_invalid` + `pmap_load_trust_cache`
2. AfterKread stages bundled `Resources/basebin/basebin.tar` (Dopamine 3.0.10) plus `Relaxin.roothide` / `relaxin.tc` into `Documents/basebin`. Names: launchdhook, systemhook, dyldhook, watchdoghook, forkfix, opainject, libjailbreak, ElleKit-as-Substrate. Credit in `Resources/basebin/CREDITS.md`. Drop extra tweak dylibs into `Documents/tweaks`.
3. Package managers: Sileo first, Zebra second (`Resources/pkgman/*.deb` → `Documents/pkgman`). `dpkg -i` waits for Procursus bootstrap after KRW.
4. `opainject 1 launchdhook` then `jbctl respring`

Wired (2026-10-09): the JAILBREAK / FULL CHAIN flow drives this pipeline end to end via `Bootstrap/Lum1naBootstrap.swift` + the `Lum1naAfterKread` STAGE/FIRE split. Staging always runs (BaseBin.tar + debs into Documents); the gate, pmap_cs, AMFI trustcache, opainject, `dpkg -i`, and respring fire **only** on a passing self-test. Post-respring state is detected from the filesystem (jbroot dpkg + Sileo/Zebra bundles) and surfaces as `JAILBROKEN` in the device bar — detection, not a claim.

Wired (2026-10-14): **elevate step 0** added to AfterKread FIRE (`Kernel/Lum1naElevate.m`, Dopamine order: uid0 → P_SUGID → MAC label → env → CS_PLATFORM), driven by the new per-SKU struct-offset table `Kernel/Lum1naStructOffsets.m` (darwin-24.4+ ladder; P7-leak values cross-validated against Dopamine info.c, P7 VAs rejected via Ghidra). Root cause of the 17:50 rig run (KRW gate PASSED but `posix_spawn opainject rc=1 EPERM`, no respring) was this missing step. `kernproc` is 0 for every SKU until per-SKU Ghidra derivation lands, so elevate logs an honest HOLD and the pipeline degrades to pre-elevate behavior instead of writing to a wrong VA. Next: derive `kernproc`/allproc on 23F77 (cache already open in Ghidra), 22G100, 23G71.
5. A14 PPL — AMFI UC from this process after `hasKread`
6. Persist / tempRoot / boot-time auto-rejailbreak stay later — that is the novel Lum1na layer, after this injection basis works

## GOLDMINE 26.5 (keep unrun angles open)

Drop: `~/Library/Mobile Documents/com~apple~CloudDocs/Downloads/GOLDMINE 26.5/`
Lab note: `~/Desktop/lumina_primitives/88_GOLDMINE_26.5.txt`

- **84607** EncType-vs-session: `AVE_EncType_None < encType && encType < AVE_EncType_Max` landed in AppleAVE2 **905.36.1** (26.4 beta 2). 23F77 AVE is already 905.36.1 — the string is **present**, not a 27-only absence. That is a bounds assert, not a close of Close-vs-async. Do not remaining-fire. See `docs/IPSW_DIFFS.md`.
- **lockdownd** logic bugs are 26.5 userspace USB/pairing. `Exploit/Lockdownd/LockdowndFullChain` is a skeleton, not device-proven.
- **24A435 JPEG IOSurface UAR** is proven on iOS 27 GM (other silicon). Twin `structureInput+0x30` / `req+0x2b8` on T8101 before dropping JPEG.
- **IOMD `_dmaReferences` +0x34** is one-branch-bounded on 27; 23F77 unmapped.

One failed probe is not a closed class. Full reopen list: `~/Desktop/lumina_primitives/89_REOPEN_ONE_ANGLE.txt`.

## UI

Star is the motherboard hub (no center ring). Traces light to KERNEL / SANDBOX / DAEMON / PATCHSET. Nephew sketch: neon clouds, tagline, `iPhone 12  update:26.5` pill. Logging stays military local time + `F_FULLFSYNC`.

## Rig session 2026-10-12/13 (iPhone12,1 A13 22G100, Dopamine KRW)

- **ClearSword V23 phys_oob on the rig = first live OOB read oracle on A13 darwin 24.** Hop-1 race returned real foreign pages: 350+ hits, 5 mappings x 3 outer loops, every read success, no panic, no EINVAL (pre-26.1 kernel). Window content catalog: our own VM-cycler fills 0x41..0x50 ('H'/'M' pages, free pool self-poisoned), ANE perf JSON in kernel heap ("endance","NonEventVariables"), kernel __text pages, AMFI entitlement path strings (com.apple.mobile.CallExtension...), pointer tables (0x232b6xxxx and 0x19ece6240 clusters; one page of pid rows sharing 0x20c291fe8). NO inpcb content: no NECP exec-name string, no filter-default 0x0000ffffffffffff, so `find_and_corrupt_socket` never fired. Banner rule holds: Q0!=marker is NOT kread. hasKread=NO.
- **A13 pin wiring (lab app, Xcode rebuild pending):** `LabRuntimeOffsets` gA13 `socket_usecount` 0 -> 0x254 and gXR 0x23c -> 0x254. Ladder (libjailbreak info.c): darwin>=23.4 -> 0x254, overridden only at darwin>=25 -> 0x23c. Rig darwin 24.6.0 = 0x254; hunt 26.5 = 0x23c; gXR carrying the A14 number contradicted its own header comment ("XR was 0x254"). offsets_init now logs the real `LabOff()->tag` and gates on usecount==0; pe() banner prints the actual table tag; spray_socket logs the first SO_NECP_ATTRIBUTES setsockopt failure (the PCB identification depends on that string landing and the result was silently ignored). Upstream ClearSword resolves exactly three offsets (inpcb.socket 0x40, inpcb.icmp6filt 0x148 darwin>=23.1, socket.usecount) - lab port now ladder-faithful on all three per-SKU.
- **P066 rig:** AVE2 direct IOServiceOpen kr=0xe00002e2 (entitlement-gated as mobile); VTCompressionSession 128x128 full encode OK, session invalidated after complete - no in-flight Close-vs-async window on this SKU either. EncType class = reach only. PARK stands.
- **p080 y-craft127 v1:** ANE ENGAGED (delta 2.73 ms) on the 127-in All model with ALL-LIVE sids - the rig accepts and predicts the model the hunt rejects with 0x2/0x9. Read door closed (A y=inf, branch 4 unexpected, G scan hits=0); write door y=17 stable across B1-B3 but zero dereference evidence (capHit=0). The error echoes carry the real record sids but print to the Xcode console, not the disk log - next v must mirror them.
- **p074 consume v3:** All-real y=inf matches neither hypothesis (staging sum 6.59e4 / surface bytes 1.15e14); All-bogus also predicts OK (no abort/fallback timing signature); D1 scan 0 touched of 385. Discriminator inconclusive, arm-B needs Ghidra. Sharpest new lever: rig-accepts vs hunt-rejects means the 0x2/0x9 reject is SKU/ANE-firmware-specific, not model-intrinsic - the rig is the live control for that decode.
- **p022GC v41:** in-window no-file registration at 0x180000000 ACCEPTED, residency prot=5/5 depth=1 (v39 was prot=0/0), read still faults -> accepted but not instantiated. Container fd prot=RW -> EPERM MAC deny on any fd path (Ghidra mac_file_check_mmap 0xa5d79d8). Zero stores. Probe only.
- **p057 v6 on rig:** interpose hook never routes on this UC (hook_n=0, dyld4) -> synthetic path only; sel0/1 decl 0x28/0x100 kr=0x5 nonfill=0 kptrs=0 - no deserialize proof; need a real ACM on this AppleKeyStore conn. sel5 sweep / 163-sel / 0x800 stay parked.

## B1 unlock: verbatim ClearSword core lane (2026-10-13)

Beta 1 path #2 for real KRW, wired and CI-gated. The rig (iPhone12,1 A13 22G100,
Dopamine-jailbroken) runs Dopamine 3.0.10 whose ClearSword exploit provably works
on exactly this device/OS, so the core ships verbatim instead of re-derived:

- `Exploit/ClearSwordCore/` — upstream `exploit/*.c|*.h` copied byte-for-byte from
  Dopamine 3.0.11 (opa334, credited), then mechanically prefixed (`cs2_*`) to
  coexist with the lab's own ports. NO NECP sockopt addition (that was a lab
  invention), NO churn thread, NO VM cyclers: the five lab-port divergences that
  starved the OOB window are undone — 22,528-socket spray, per-mapping
  `surface_mlock` prefetch-wiring, full 8 x 128 MiB scan with unbounded outer
  retry, `highiest_success_idx + 100` read retries, upstream identification
  (`executable_name` memmem + filter-default marker) and the upstream iOS 17+
  textPtr ladder (pcbinfo → ipi_zone → kt_zv_name).
- Shim (`ClearSwordCore/common.h`): `koffsetof`/`kconstant` bridge to the
  libjailbreak info.c ladder; `socket.usecount` + `staticBase` come from the
  runtime table `LabOff()` (rig darwin 24.6: 0x254 / 0xfffffff007004000; iOS 26
  usecount 0x23c stays per-SKU). `walk_backtrace` (libjailbreak) stubbed.
- Lab-safety edits (marked `lab:` in source): time budget `cs2_expired()` guards
  on pe_v1's outer/seek loops + bounded kernel_base walk; pe_v1 failure is
  propagated (upstream ignored it); free-thread join before free on the cleanup
  path; worker mach_vm_map failure releases race_sync instead of leaving the
  main thread spinning; `return NULL` for the Xcode-16 int-to-pointer error.
- `Exploit/Lum1naCS2Core.{h,m}` — provider lane #2, contract identical to
  `Lum1naLibkrw`: Establish (run + kread8(kbase)==0x100000cfeedfacf self-test) →
  IsLive/Kbase/Kslide/KRead*/KWrite*. Durable log `cs2_core_log.txt`.
- Dispatch: `Lum1naBoard.commitSlide` and `Lum1naAfterKread` self-test/pmap
  lanes now pick SocketKRW → libkrw → ClearSword core. `KRWBridge` gained
  `Lum1naKRW_EstablishFromCS2Core` (slide = kbase − LabStaticBase()).
- Catalog tap `cs2core` ("B1 ClearSword core") → hasKread → PATCHSET gate opens.
  JAILBREAK does NOT auto-run the spray; it stays a deliberate one-tap per
  force-quit, same honesty shape as `krwlib`.
- `LabRuntimeOffsets.h` made C-safe (`__OBJC__` guard) with `LabSku` moved in as
  a plain C enum shared with `LabDeviceProfile.h` — pure C can now include the
  ladder without ObjC headers.

Success bar unchanged: hasKread flips only via `board.commitSlide` after the
magic self-test; JAILBROKEN only on real post-respring jbroot evidence.

## Rig session 2026-10-13 (afternoon, iPhone12,1 A13 22G100)

- **p083 staging:** 23/24 post-predict gap ids resolved via IOSurfaceLookup in
  OUR registry (16 KB espresso staging, ids 778-800). LUM1 0x4C554D31 fill of all
  hits → y2 == y_gate → NO EFFECT ON Y: staging surfaces are command/program-side,
  not the value source. Phase J re-lookup: ANE rewrote the first 2-byte fp header
  (u32@0 → 4c555ef8-shape) but LUM1 intact beyond → untouched by predict. The
  y-control hop stays the forged OUTPUT-record-sid route (Chain 2). Conversion bar
  untouched; hasKread=NO (this lane).
- **p019v2 iopl 64749 diagnostic:** every mismatch shape rejected on A13 22G100 —
  AllocSize < BPR*Height, multi-plane total > AllocSize, memory-entry vm_map size
  mismatch (kr=0x4), mlock 2-page overflow (errno 12). Non-page-aligned allocs
  (0x4001/0x7fff/0x5000) accepted and lock survived. The kernel catches all
  shapes; 64749 +0xc3 is not reachable via these surface params. NOT KRW,
  diagnostic only. (Log used box-drawing chars — ASCII-only rule reminder.)

- **2026-10-14 RIG PROOF (Beta 1, `cs2core` tap):** the verbatim ClearSword core
  ran the full chain on the rig (iPhone12,1 A13 22G100, 18.6.2): 22528-socket
  spray, first-mapping hit (pcb_start_offset 0x400), target corrupted at
  0xffffffe0cf174948, control_socket idx 0x1f7f, success_read_count 59,
  kbase 0xfffffff01c448000, slide 0x15444000, magic self-test PASS in
  1400 ms. First real KRW establishment in Lum1na. commitSlide refused on the
  same tap: board.krwContext was a stale/dead SocketKRW placeholder, so the
  kread of kbase+0x1c returned 0 through the socket lane and the ClearSword
  lane was never consulted. Fix: lane cascade in Lum1naBoard.commitSlide and
  Lum1naAfterKread (socket ctx -> libkrw -> cs2core, kread result decides, not
  the flag). Also: gA13_22G100 socket_usecount filled with the info.c ladder
  value 0x254 (darwin>=23.4; rig 24.6.0) -- the earlier 0 left so_count reads
  at socket+0, which bumped a refcount at the wrong offset and corrupted one
  live so_list.le_next; RIG MUST REBOOT before the next cs2core tap. Log sink
  format fixes (%@ -> %s, time via UTF8String) in Lum1naCS2Core.m. hasKread
  still NO until a rebooted rig re-taps and commitSlide passes; that is the
  honesty line, and it is one reboot away.

- **2026-10-14 INTEL DB (p093 `intel` tap, repo + P007):** merged offset
  database `Exploit/LabIntelOffsets.{h,m}` — PROVEN rows (our runs: LabOff
  tables, cs2core rig kbase/slide, P053/P063/P065/P069 pins), LADDER rows
  (Dopamine libjailbreak info.c branches, incl. socket.usecount 0x24c /
  0x254 / 0x23c per darwin), LEAD rows (DarkSword chain_loader_26.js
  __A14_A18_OFFSETS, unproven). Reference only: LabOff() stays the only
  resolver; the DB never feeds kread/kwrite. P093 cross-checks the ladder
  prediction for THIS device's kern.osrelease against LabOff() live
  (would have caught the usecount=0 rig bug). P091 `darksword` and
  P092 `liter8` static maps added; docs/DARKSWORD.md + docs/LITER8.md.

- **2026-10-14 RIG PANICS (2 kernel data aborts, both with Lum1na as the
  panicked task):** Panic 1 (16:40:11, boot slide 0x1544c000): SAME boot as
  the 16:29 cs2core run (kbase 0xfffffff01c448000 exact match; x1 even held
  kbase+0x1c, our version-string read target). Lum1na pid 321 RELAUNCH
  (1 thread, 0 pages) hit the abort at text+0xFA2848 dereferencing heap VA
  0xffffffdc07557110, 11 min after the usecount=0 wrong-offset corruption.
  This is the predicted so_list.le_next aftermath class: the reboot I
  advised would have prevented it if done before the device kept working.
  Panic 2 (16:44:29, NEW boot, slide 0x19a88000): DIFFERENT failure. Lum1na
  pid 416 ACTIVE (11 threads, 18702 pages, stackshot ok) mid-tap; pc
  IOGPUFamily+0xBE78 (kext 104.6.1 @ 0xfffffff023695200), AGXG12P 328.5 in
  backtrace; far 0x00200000000000a8 through x16=0x0020000000000000 with
  x17=0xcda1ffe048734b10 = FAILED PAC AUTH on kernel heap pointer
  0xffffffe048734b10 (raw in x0). A GPU-driver PAC-auth failure during an
  active tap is NOT the socket bug (different boot, different subsystem).
  Suspects: a GPU/ANE lane (p061/p066/p069/p055/ANE254) or a 23F77-pinned
  lane on the A13 rig. Which tap ran at 16:44 is the open attribution
  question; 16:44 console capture needed. No more rig taps until the repo
  app is rebuilt (usecount 0x254 + lane cascade) and panic 2 is pinned.

- **2026-10-14 PANIC 2 ATTRIBUTED: Rapier (CONFIRMED, console evidence).**
  The 16:44 console capture shows `TAP rapier 16:44:02`
  (rapier-v1.0-orderedstart mag=0 hold=0 45s, HIT pc=cd8/d00, calib ok
  conn=24071) then the panic at 16:44:29 — 27 s into the 45 s race window.
  Root cause of the run itself: the rig A13_22G100 table has sel36=0
  (unproven; Ident prints "QueueCreate sel=0 ... sel36=0") and Rapier
  fired anyway. Fix: Rapier.runWithLog now refuses when LabOff()->sel36
  == 0, logging the panic reference. Rule re-stated: a probe whose core
  offset is unproven on the runtime SKU must HOLD, not fire. Rapier stays
  untappable on the A13 rig until sel36 is proven for this SKU.

- **2026-10-14 COMMITSLIDE GATE ROOT CAUSE (fixed same day).** Three rig
  boots established ClearSword core KRW (slides 0x15444000 / 0x19a80000 /
  0x1d58c000; 1400 / 2218 / 878 ms; magic self-test PASS each time) and
  three times board.commitSlide refused with "kread kbase+0x1c=0x1b00000000
  (not a kernel VA)". The gate was our invention and unfalsifiable: in a
  Mach-O 64 kernel header, kbase+0x1c is reserved(u32) | first_LC.cmd(u32)
  << 32 — header data (0x1b00000000 on every device), never a pointer.
  Upstream has no such check; ClearSword poc.c identifies kbase by
  cs2_early_kread64(kbase)==0x100000cfeedfacf (magic+cputype) and
  cs2_early_kread64(kbase+8) in {0x200000000 arm64, 0xc00000002 arm64e
  iOS16+, 0xcc0000002 arm64e iOS19+}. The primitive SURVIVES the run:
  cs2_sockets_leak_forever() deliberately leaks the control/rw sockets and
  the provider's own post-run self-test passed (the ESTABLISHED line reads
  magic through it). Fix: commitSlide (Lum1naBoard) and ak_krwSelfTest
  (Lum1naAfterKread) now use the upstream criteria through the lane
  cascade. Expected next rig run: commitSlide OK kbase=0x... magic=
  0x100000cfeedfacf typeinfo=0x200000000 -> hasKread flips -> the
  AfterKread pipeline (AMFI/pmap/opainject/dpkg/respring) fires for the
  first time. Also fixed: [RECOVER] banner printed a double-encoded
  em-dash (mojibake) — now ASCII "--".

- **2026-10-14 17:35 CONFIRMED on the rig (build 98a2cb1): the gate fix
  flipped hasKread.** cs2core established a 4th time (kbase
  0xfffffff018128000, slide 0x11124000, 1103 ms, magic PASS) and the new
  upstream-criteria gate PASSED: "board committed hasKread via the
  ClearSword core lane" -> hasKread=YES hasKwrite=YES kslide=0x11124000
  kbase=0xfffffff018128000. "PATCHSET (JAILBREAK) now passes the KRW
  gate." First hasKread=YES in Lum1na. AfterKread pipeline next in the
  SAME session — the ClearSword primitive is process-local (leaked
  control/rw sockets die with the process), so the pipeline tap must run
  before any force-quit; respring will kill the app, and disk TAP logs
  are the record.

- **2026-10-14 HUNT DEVICE (iPhone13,2 A14 23F77 iOS 26.5) SESSION.**
  Four results, one parse bug (fixed), one display bug (fixed):
  1. **P044 aio84530 heap leak WORKS on A14 26.5**: stage 1
     `leak OK anchor=0xffffffe1a7988700 (heap, NOT slide)` — first live
     kernel-heap anchor on the hunt device. Anchor is session-local (heap
     VA, not a table offset), so no intel row; the leak lane is now
     PROVEN for A14_23F77 fill seeding.
  2. **P044 fire then death**: small predict OK, 254 addchain fired,
     CoreML prediction FAILED (-1, same as rig), then the app died in the
     kmsg harvest step (collect line never printed). No panic .ips yet —
     recovery packet needed. First A14 in-window death AFTER a successful
     leak; do not stack taps on hunt.
  3. **T4 krw4 dual-wrap on hunt reached real geometry**: victim/spy
     type=0x80 (rig never got past 0x0/0x11), alias LIVE spyConfirmed=1,
     detach victim kr=0x0, unpin ok, spy MD still wired, last-wire detach
     ok, blit = GPU OOM -> GART died with the last MD. REPRODUCES the
     18:45 seal on the hunt device: alias GART is not independent. T4
     stays sealed; dual-wrap type-0x80 geometry is now PROVEN reachable
     on A14_23F77.
  4. **cs2core DIED 3/3 on hunt with ZERO core logs** (16:57:12,
     17:01:50, 17:08:26 taps; next session 3-5 min later each time, no
     [cs2] line ever printed — death before or during spray setup; app
     jetsam vs panic unknown until a recovery packet lands). Catalog
     description now carries the warning. Do not re-tap cs2core on hunt
     without a fresh boot + recovery-packet capture.
  Fixes shipped with this entry: P093 ladder parse read kern.osrelease (a
  string node) into an int and returned -1 on every device — now
  strtol-parses the string (hunt will predict usecount 0x23c, matching
  LabOff A14 live). P044 stage statuses de-mojibaked to ASCII (the stage
  formatter path mangles non-ASCII; plain P06xLog lines render fine).

- **2026-10-14 EVENING THREE-DEVICE SESSION (12 mini / rig / hunt).**
  1. **12 mini (iPhone13,1 A14 21D50 17.3) — first real KRW through our
     pipeline, and the device was STOCK** (user correction: not
     Dopamine-jailbroken at test time, which makes the result stronger).
     cs2core fired on 21D50: control_socket idx 0x22a6, kbase
     0xfffffff00d56c000, slide 0x6568000 (page-aligned — static_base
     0xfffffff007004000 confirmed). Board hasKread/hasKwrite legitimately
     YES via the self-test gate. AfterKread FIRE reached staging + KRW
     self-test PASS + basebin.tc v1 loaded, then `posix_spawn opainject
     rc=1 (EPERM)` — sandbox wall. On a stock device there is no jbserver
     and no /var/jb, so krwlib "no provider found" is the correct honest
     result, not a bug. 509ms tap.
  2. **Rig (iPhone12,1 A13 22G100 18.6.2 Dopamine):** cs2core KRW stable
     across boots (slide changes per boot; board tracks it). The honesty
     gate caught a STALE slide: board said hasKread but kread32(kbase)=0 →
     "hasKread is a lie; refuse inject" → HOLD. krwlib on rig loads the
     provider but kbase rc=0 val=0 — root cause now PROVEN from source:
     libkrw wraps `jbclient_initialize_primitives()` whose first line is
     `if (getuid() != 0) return -1` (Dopamine libjailbreak/src/main.c) —
     sysinfo/physrw are Root-domain (euid==0 only). Our mobile app cannot
     pass; fixable only by becoming euid 0, which our own KRW enables.
  3. **Hunt (iPhone13,2 A14 23F77 26.5):** T1 leak OK (14 heap leaks on
     board), 254 addchain CoreML prediction FAILED (-1) again, LightSword
     spyConfirmed=1 but GART died with last MD (PARKED), Rapier panicked
     twice (18:52:24, 18:57:20) — stays parked. cs2core gate correctly
     skipped 26.5 (CVE-2025-43520 patched). See next entry for a new
     delayed panic.
  4. **krwlib on 12 mini: no code change.** On stock there is no provider
     to load; the search-path list already covers /var/jb Dopamine
     locations (verified against Dopamine Packages/libkrw-provider
     Makefile: installs to /var/jb/usr/lib/libkrw/libkrw-dopamine.dylib —
     first entry in our dlopen list).
  5. **Source-mined Beta 1 blueprint: docs/TIEIN.md** — Dopamine trust
     ladder (SYSTEMWIDE/PLATFORM/ROOT=euid0/DOPAMINE domains), the
     process_checkin setuid recipe (proc+svuid/svgid writes + ucred
     update), darwin23 ucred_rw mirror caveat, trustcache add is
     kwrite-only on an existing jb-tc (grow needs kalloc/kcall), Nugget's
     host-side SysContainerDomain traversal write into /var. Device
     ladders: rig = our KRW → self-elevate (uid0) → Dopamine Root domain
     unlocks → libkrw/opainject/dpkg live; 12 mini stock = P094 kernproc →
     P095 ucred ladder → elevate → unsandbox (MAC label slot) → exec-trust
     decision (static tc per lab notes 12/13/14 vs thread-hijack).

- **2026-10-14 20:30:21 HUNT DELAYED PANIC — `[data.kalloc.3072]: element
  modified after free (off:0, val:0x000000c000000174, sz:3072,
  ptr:0xffffffe0d4826800)`** (`panic-full-2026-10-14-203021.0002.ips`).
  Decode: T8101 xnu-12377.122.4, kernel slide 0xcca0000, text exec base
  0xfffffff016a4c000. Boot 20:13:31 → panic 20:30:21 (~17 min after boot).
  **Lum1na was alive at panic time (pid 587, uid 501): 38.4s user CPU,
  569,633 page faults — spray-probe profile, not idle.** Victim that
  tripped the poison check: `symptomsd` (pid 134) allocating from the
  recycled DATA kalloc.3072 element. Element content = (c0..d3 tag,
  0x100000001) pairs with 0xb9-0x1de values — shape consistent with a
  kmsg/port-descriptor table (symptomsd is a heavy kmsg consumer; our
  aio84530 lane touches this family — matches lab notes 106 P088
  kalloc-3072 triage and 135 P044 gzalloc-unified family). Backtrace =
  syscall path into zalloc poison check; panic caller 0xfffffff017289350
  = static text 0x83d350, reporter frame 0x83563c (map in Ghidra when
  convenient). Attribution:
  corruption landed in THIS boot session (kernel RAM does not survive
  the 20:13 reboot), i.e. a tap in the 20:13-20:30 window, then delayed
  payment minutes later — the remaining-fire pattern, NOT cross-boot
  persistence. Action: hunt fire lanes stay PARKED (existing warnings
  hold); one tap per boot on hunt; capture which tap ran 20:13-20:30 for
  the notes. Second panic 12 minutes later, same device, NEW boot
  (session EFBE32BD, boot ~20:30:4x, kernel slide 0x21360000, text exec
  base 0xfffffff02b10c000, same kernel UUID D5612296):

- **2026-10-14 20:42:43 HUNT PANIC #2 — Kernel data abort INSIDE Lum1na
  (pid 648)** (`panic-full-2026-10-14-204243.0002.ips`). esr 0x96000047
  (lower-EL data abort, write, translation fault L1) at pc
  0xfffffff029aa41fc (static __TEXT 0x17401fc; companion frames cluster
  at static 0x1739xxx-0x174cxxx — one driver region), FAR
  0xffffffe112900000 == x9, page-aligned, x25 = FAR−0xc00, x20/x26 =
  0xc0 — a 0xc0-stride entry walk whose write landed on an unmapped or
  dead translation. Panicked task = Lum1na itself (16 threads, 3.27s
  user CPU, 12k page faults — light profile vs panic #1's pid 587 at
  38.4s/569k). Panic-path static frames match panic #1 (0x530e4 entry,
  0x83563c reporter; #2 caller 0x8434d4). Interpretation: the dual-wrap
  / foreign-out write family firing synchronously through a dead
  mapping — the same "alias GART is not independent / GART died with
  the last MD" finding from the 18:4x session, now as a kernel data
  abort instead of GPU OOM. The 0xc0 stride matches the out-entry shape
  family (lab notes 120-125). Action: treat 20:30/20:42 as one incident
  pair — hunt write lanes (dual-wrap, foreign-out, 254 addchain fire)
  stay PARKED on 26.5; one tap per fresh boot; log which tap ran for
  attribution.
- **2026-10-14 21:52:08 HUNT PANIC #3 — AppleH11ANEInterface wild write,
  same static site as #2** (`panic-full-2026-10-14-215208.0002.ips`, hunt
  iPhone13,2 23F77, boot 2DACCFC7, slide 0x131f4000, text exec base
  0xfffffff01cfa0000). pc 0xfffffff01b9381fc = **static 0x17401fc — the
  exact pc of panic #2**; esr 0x96000047 write/translation L1; FAR
  0xffffffe98435c000 = x9, inside zalloc DATA submap (0xffffffe9826e0000
  base); x25 = FAR−0xc00 (object base 0xffffffe98435b400), x20/x26 = 0xc0
  stride — write at element +0xc00 of a 0xc0-stride walk. GZAlloc verdict:
  "**wild deref, missing or invalid metadata**", zid:0 <unknown>. Panicked
  task pid 368 **P007OpenOnly** (4220 pages, 15 threads). Backtrace kernel
  extension = **com.apple.driver.AppleH11ANEInterface(9.511.3)**
  @0xfffffff01b8ca3c0 (static rel 0x16C63C0..0x17B4F17); ANE-resident
  frames (static rel): crash 0x17401fc / ret 0x1740214 (same fn),
  callers 0x173FB2C, 0x173B020, 0x173633C, 0x172DDF0, 0x172DAF4,
  0x172D4FC, below 0x16D70D4; dispatch from 0x1d73a478/0x1d73aad0
  (IOService/IOUserClient path). ATTRIBUTION NOW SOLID: this is the ANE
  driver writing through a repurposed/dead object during the wedge→harvest
  sequence p087 v10 documents — NOT cs2 (cs2 ran 21:37 and its PCB domain
  panic would not recur at the identical static pc across boots/tap
  orders; #1/#2/#3 share the same site). Ghidra (xnu-12377.122.4 T8101
  project): ANE kext region around static 0x17401fc is NOT function-
  analyzed — needs a manual "Create Function" at the blob containing
  0xfffffff0087441fc to name the harvest fn; the ANE_AddClientForProgram
  fn (0x16EF624) IS analyzed and sits in the same kext. CC8-landing note
  (user): AGX cc8 panics are a different cluster; #1-#3 all land in ANE.
  Action: ANE/AVE hunt lanes stay PARKED on 23F77; the wedge finding
  (p087 v10: EncodeFrame accepted, ZERO completions in 30s even with one
  frame — session wedged from creation) means the trap needs no window:
  harvest runs downstream of any wedged session. Next Ghidra step: name
  0x17401fc fn + the 0xc0 array writer, then design a read-only probe
  that detects the wedge without feeding the harvest.

- **2026-10-14 21:37-21:46 hunt census + cs2 attempt (23F77)**:
  - **P090 census on 23F77 — LabKernelOffsets DB VALIDATED against the
    live resolver** (log p090_momentarius_log.txt): darwin 25.5 row prints
    proc.pid 0x60, proc_list 0x0/0x8, proc_ro 0x18, proc_ro.csflags 0x24,
    proc_ro.ucred 0x28, **proc_ro.task_tokens 0x0** (26.5 removed it —
    matches info.c:602 + our PROC_ROW_D25), ucred ladder
    0x18/0x1c/0x20/0x28/0x68/0x6c/label 0x78, task_token audit_token 0x8.
    **CORRECTION APPLIED BOTH REPOS: proc_flag 0x25C → 0x454** (DB +
    proc_iterate/proc_list_add decompile flag words at 0x458/0x45c/0x464).
  - **cs2-verbatim-v1 on 23F77**: RAN (non-A18 path): 0x5800 socket ports
    sprayed, pc_object 0xfd03, pc_address 0x4552a8000, 8×128MiB scan
    started (mappings 0-7 logged, then budget window). No verdict in the
    captured log; ~15 min later panic #3 fired at the ANE site (attribution
    above says NOT cs2, but the window overlaps — honest note: cs2 on
    26.5 A14 remains UNPROVEN, not refuted; one failed run ≠ class closed,
    lab notes 89 discipline).
  - `P007OpenOnly.diskwrites_resource` (bug 145, ~16.5 min runtime):
    app exceeded disk-write budget — per-line F_FULLFSYNC probe logs are
    the cost; keep one-tap-per-boot discipline (limits churn), no body
    changes. runningboardd/wifid 214117 = bug_type 409 system snapshots,
    not our crashes.

- **2026-10-14 26.5 A14 STATIC ANCHORS DERIVED (Ghidra, xnu-12377.122.4
  T8101, kbase static 0xfffffff007004000)** — Beta-1 groundwork for the
  hunt device; recorded in `LabIntelTab` as status GHIDRA:
  - **allproc head = 0xFFFFFFF00A900770** (delta from kbase **0x38FC770**).
    Proof: `proc_iterate` (kern_proc.c, identified via its assert string)
    walks `p = *(p)` from DAT_0a900770 with pid at p[0xc] = +0x60 and a
    second head DAT_0a900778 (zombproc, param_1 bit1); 14 xrefs include
    WRITEs from the fork/exit insert-remove path.
  - **proc_list_add (kern_fork) decompile-verbatim**: `elm->le_next =
    head; old_first->le_prev = &elm->le_next; head = elm; elm->le_prev =
    &head` → darwin-25 allproc is a **classic doubly-linked LIST with a
    one-pointer head** (le_prev of first member == &head) — p094 head8
    scan semantics; also proves le_next +0x0 / le_prev +0x8 / p_ppid +0x20
    (parent==kernproc → ppid 0) / proc_ro +0x18 with proc_ro->proc
    backref at ro+0x0.
  - **kernproc variable = 0xFFFFFFF007B6EB30** (`struct proc *kernproc`,
    static-init to &proc0; `in.c:471` assert "so != NULL || p ==
    kernproc" compares against DAT_7b6eb30; proc_list_add's
    `parent == kernproc` branch confirms; runtime value = &proc0).
    All kernproc xrefs are READs — static initializer only, no runtime
    writer.
  - p094 Path 2 extended per-tag (A13 22G100 0x35CC000 head16 / A14 23F77
    0x38FC770 head8); Path 3 gained zombproc + kernprocvar (deref→
    validate pid 0) semantics. Rows: allproc/zombproc/kernprocvar
    family "Ghidra T8101 12377". LabOff stays the only resolution source
    (AGENTS.md) — these are validation rows until a live lane CONFIRMs.

## 2026-10-15 — vschko/CaseStudies cross-ref + panic re-attribution

- Panics #1–#3 on the hunt 26.5 RE-ATTRIBUTED to CVE-2026-43748 ungroomed
  (x25 = FAR−0xc00, stride 0xc0, GZAlloc wild deref). ANE lane UNPARK for
  groomed standalone taps only (P099). "wedge→harvest" attribution retired;
  AVE P087 zero-completions finding stands.
- P096 canceled — p063 already implements 84530 AND live-proved it today
  (aio_workq_entry 0xffffffe16d5aaa40, filter −3, post-completion stable).
- New probes: P097 (65371 gRegistryRoot instance leak — heap, not slide),
  P098 (M2ScalerCSC sel-8 iosaDiag, honest shape), P099 (43748 groomed,
  espresso/CoreML primary per P046 MIL-CLOSED note, inline-mach groom).
- 43748 lane: write-door candidate B. Needs victim-adjacent chunk shaping
  before it is a real write primitive. Board/AfterKread stay HOLD.
- 39868 (DTrace DOF) parked: needs UID-0 /dev/dtrace on stock iOS.
  Details: docs/CASESTUDIES.md.

### 2026-10-15 12:00 EDT — A13_22G100 rig: KRW PASS + AfterKread FIRE holds

- P054 bounded tap (1 thread, 2s, 50 files): no panic. PATCHSET stage ran
  staging + AfterKread on the rig.
- KRW self-test PASS: hasKread=YES hasKwrite=YES leaks=5, kslide=0x12f30000,
  kbase=0xfffffff019f34000, kread32(kbase)=0xfeedfacf, kread64(+8)=0xc00000002.
- FIRE held honestly: pmap poke waits for leaks[] kind=pmap row; AMFI UC open
  0xe00002e2 -> loadTrustCache skip (selectors unproven on SKU); basebin.tc
  loaded (v1, 28 entries) but opainject/jbctl posix_spawn rc=1 EPERM —
  elevate held on kernproc-underived for A13_22G100.
- Rig unlock: tap P094 (A13 anchor 0x35CC000 head16) -> kernproc-proven row
  -> re-run PATCHSET. No code change needed (honest-gate design held).
- post-run state honest: "HOLD — no jbroot dpkg. Files present ≠ injection."

### 2026-10-15 — external intel pass (airlift/varik/AltDaemon/Nyxian)

- airlift (MIT): ATAirlock double-move path validation, paired-Mac file
  plant into /var/mobile app containers. OPEN TASK: check -[ATAirlock
  processCompletedAsset:] identifier validation on the 23F77 dyld cache.
  If the unchecked shape predates 27.0, airlift is a jailbreak-free
  staging channel on the hunt device. NOT a KRW door; do not claim 26.5
  support until run.
- varik.dev bounty workflow folded into the ios-xnu-hunt skill:
  Target Flags section in report template, flag-aware rubric money notes,
  tooling (ghidra-rpc/vphone-cli/ipsw) in rea.md, money loop + prompting
  ops in SKILL.md, new reference/patterns.md audit checklist.
- AltDaemon (rigs only, AGPL ports) and Nyxian (jailed IDE, signing
  keep-alive + on-device iteration) noted as distribution options.

### 2026-10-15 — cs2core bulk lane ungates P094 Path 2 (rig unlock)

- Lum1naKreadLane: cs2core now satisfies Lum1naLaneBuffered + KReadBuf
  (Lum1naCS2Core_KReadBuf existed; dispatcher never used it). P094 Path 2
  __DATA allproc scan now runs on cs2core-only devices (rig 22G100,
  12 mini 17.3) — runtime kernproc derivation WITHOUT the Ghidra pass.
  P007 lab lane mirrored with a chunked kread32 bulk adapter.
- docs/DEVICES.md: per-device lane matrix + completion bars. Nugget is
  explicitly NOT a 26.5 door (SparseRestore dead since 26.2 betas).

### 2026-10-15 — A13 22G100 Ghidra pass (T8030 xnu-11417.140.69)

- kernproc slot 0xfffffff007ade3a8 (in.c:0x476 assert + skywalk 0x37b
  + fork1 ppid readback — three independent compares).
- allproc 0xfffffff00a653cb8 8-byte LIST_HEAD, zombproc 0xfffffff00a653cc0
  (fork-register + exit1 LIST_INSERT_HEAD verbatim), initproc slot
  0xfffffff00a6542c0. Rows tagged Ghidra A13_22G100 in LabIntelTab.
- P094 Path 2 A13 scan fixed: delta 0x364FCB8 + head16=NO (P090 0x35CC000
  was __DATA base; the 16-byte queue shape could never match LIST_HEAD).
  Combined with the cs2core bulk lane, the rig now derives kernproc at
  runtime with static anchors to validate against. P007 copy mirrored.

### 2026-10-15 — rig panic #4: cs2core residue, NOT P094 (fix shipped)

- panic-full-2026-10-15-143657.0002.ips, bug_type 210:
  zone bound checks — 32 B write overflows 16 B object in
  kalloc.type.var1.16 @zalloc.c:1322. 32 = sizeof(icmp6_filter).
- Attribution: DEFERRED ClearSword corruption. cs2core corrupts
  inp->icmp6filter during KRW setup; ~40 s later the kernel touched the
  poisoned slot and Apple's zone bound checks caught it. P094 Path 2 is
  read-only; kernel reads cannot cause a write-overflow panic. Scan
  window was verified correct (kbase+0x364FCB8 == live allproc head).
- Lesson: cs2core lane has a ~40 s / one-tap reliability horizon on the
  rig. Order: relaunch -> cs2core -> IMMEDIATELY the one probe you need
  -> PATCHSET. No idle browsing between taps.
- P094 hardened: anchor ping (3 direct kreads, MATCH/MISMATCH evidence
  line) runs BEFORE the bulk sweep; A13 sweep cap cut 2 MB -> 512 KB.
  Next run settles window-vs-validation in milliseconds instead of
  silently sweeping under a dying kernel. P007 copy mirrored.
