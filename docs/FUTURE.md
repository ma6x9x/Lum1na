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

### 2026-10-15 — P094 LIST_INSERT_HEAD fix + chain rewiring (rig "all paths missed" root cause)

- ROOT CAUSE of the rig's repeated P094 "all paths missed": xnu
  proc_list_add is LIST_INSERT_HEAD(&allproc, p) verbatim (our own Ghidra
  fork-register decompile on both A13 22G100 and T8101 23F77). The head's
  FIRST member is the NEWEST proc; proc0 (pid 0, static, le_next=NULL)
  sits at the TAIL. P094 v1 assumed pid==0 AT the head and walked le_prev
  from self (TOWARD the head, away from proc0) — it could never match.
  Fixed: forward le_next walk to the pid-0 tail; head-shape validation is
  now first->le_prev == &head + valid proc at ANY pid; anchor ping
  short-circuits the sweep with a 3-kread fast path (fits the cs2core
  ~40 s horizon). Path 3 is SKU-filtered (wrong-SKU VAs can no longer
  false-CONFIRM). A13 LabIntel row renamed kernproc -> kernprocvar
  (0xFFFFFFF007ADE3A8 is a SLOT; isKv derefs once). BUILD tag
  p094-kernproc-v2-listhead. P007 mirror regenerated from official.
- proc_flag ladder fix (Lum1naStructOffsets): 0x25C -> 0x454 on the
  16.4+ rows (PROC_ROW A13/A12X/XR and PROC_ROW_D23 mini 17.3) per
  Dopamine info.c:390 (darwin >= 22.4.0). 0x25C was the pre-16.4 row.
  This is the P_SUGID bit elevate sets — wrong offset meant elevate's
  setuid prep silently wrote the wrong word on the rig.
- JAILBREAK chain rewiring (ExploitManager.executeKernelStage):
  SKU-aware. Hunt 26.5: T1 ANE 43748 then LightSword -> cs2core -> libkrw.
  Rig/mini/XR: skip T1 (43748 is a 26.5 door), lanes cs2core -> libkrw ->
  LightSword. After lanes, if hasKread && provenKernproc==0 the chain
  auto-fires P094 (read-only) so PATCHSET elevate stops HOLDing.
- Intel mined into LabIntelTab (~35 rows): Dopamine info.c 26.0+/26.4+/
  27.0+ struct ladder (LADDER), 24A435 A19 audit anchors (GHIDRA-EXT:
  ave2 signed-product loop 0xfffffff00886b170, iomd dmaReferences
  workers, decmpfs zlib guard, avd mvhevc index — reference-only until an
  A19 device exists, honesty rule), ncxcy lockdownd 26.5 userspace map
  (LEAD — host-side pairing logic bugs, NOT in-app KRW), vschko m2scaler
  get_iosaDiag sel=8 leak (PROVEN-EXT; hunt 26.5 affected, fixed 26.6).
- Honesty: lockdownd chain is USB/pairing/host-side (needs a Mac);
  documented as a Stage-0 entry/re-trigger vector, not an in-app door.
  KRW on 26.5 A14 is still NOT obtained.

### 2026-10-15 — P045 notes-export nugget: interleaved hole spray (parked)

- From the Sept 2026 p043-re notes export ("THE PANIC LOG IS A GOLDMINE"):
  the 43748 OOB panic (`data.kalloc.3072 element modified after free`,
  slot 0xC0) happened because P045 freed ALL holes — the OOB neighbor was
  a freed kmsg. Fix when the OOB experiment reopens: INTERLEAVED spray,
  free only even holes (A1 B1 A2 B2 ... free A's, keep B's live) so the
  OOB lands on a live neighbor ~50% of the time; silent corruption is
  observable by recv-ing the kmsg. KASLR comes free from that panic log
  (slide 0x0d0c4000 on that boot; unslide the backtrace LRs).
- Consistent verdict preserved: FKT dumps say 64788 is a KRW dead end on
  26.5 and 43748 OOB is the best/only path; missing piece = a Shape L
  victim in kalloc.3072, to be identified by scanning 21D50 with the 12
  mini's tfp0 then replicated on 23F77.
- No probe bodies touched (OOB bodies stay per AGENTS.md rule); the T1
  door is wired in the chain, P045 rework waits for an explicit ask.

### 2026-10-15 evening — 26.5 A14 (iPhone 12 / 23F77): controlled OOB ×2, GART catch-22, zalloc panic

- **P099 CONTROLLED OOB CONFIRMED twice on 23F77** (12:48:10 victim=2044,
  15:39:49 victim=2045, both `first_diff=0x0000`): the groomed inline-victim
  shape puts the 43748 addchain records at record index 0 of the adjacent
  kalloc.3072 chunk — 48 victim payloads overwritten with clean
  `{surfaceId, symbol, 0x100000001}` 16-byte records. The ANE OOB is now
  steerable on 26.5. This is the live KRW conversion entry for 26.5.
- **PANIC 2026-10-15 15:25:51 (panic-full .ips, iPhone13,2 23F77, slide
  0x1e8f4000)**: `[data.kalloc.3072]: element modified after free (off:0,
  val:0x000000c00000017e, sz:3072, ptr:0xffffffe0cfece800)` — the dumped
  element IS P099's record stream (symbols c0→d3 ascending, verbatim dump in
  the panic log). The 12:48 fire wrote into FREED victims; the element sat in
  a magazine freelist; ~26 s after the 15:25:25 p044chain tap a later
  **Lumina syscall alloc** drew it ("Panicked task … pid 1351: Lum1na",
  backtrace innermost 0xfffffff0070570e4 → zalloc check 0xfffffff007841350,
  exec slide 0x216a4000). Re-proves the parked interleaved-spray nugget:
  freed kalloc.3072 victims are lethal on darwin 25 — every fire into a freed
  element plants a future kernel panic in an innocent allocator.
- **Fix applied (P099 groom)**: interleaved hole free — only EVEN holes are
  recv'd/freed; ODD holes stay LIVE. Live victims are recv-able and observable,
  and the Beta-2 steering write must target a live element we own. Verdict
  text now carries the panic lesson. P044's punch-all has the same hazard when
  the 254 addchain ever fires on F77 (prediction currently fails — nothing
  written) — needs the same discipline before it is trusted in the chain.
- **LightSword stalepage (CVE-2026-64788) is DEAD on 26.5** — dual-wrap alias
  CONFIRMED (spyConfirmed=1, detach victim OK, unpin OK, "spy MD still wires
  after unpin — last GART live, not free"), but detaching the spy (the last
  wire) kills the GART: blit read = GPU OOM. `alias GART is not independent`:
  the wire pins the victim pages alive (no reuse), freeing the pages kills the
  only wire. Catch-22 proven at the log level — the stalepage window cannot
  contain kernel data on 26.5. Older trains unaffected.
- **Conversion machinery hardened for whichever lane lands the pair**:
  SocketKRW gained `Lum1naSocketKRW_Neutralize` (zero rw->filter through the
  smashed control channel BEFORE pcb teardown — Ghidra 23F77: rip6_detach /
  dgram teardown `kfree_type(icmp6_filter, *(inpcb+0x148))` when non-NULL);
  KRead/KWrite refuse after neutralize; Disarm neutralizes first. LightSword
  failure paths (rw-fd / Arm / verify / kbase-walk / commitSlide) now run
  `ls_teardown_defuse`: rw filter := NULL, then control filter := its
  pre-smash attach filter (saved in the hit struct) via the still-live GPU
  wire, then release. Success path needs no cleanup: Phase 11's refcount bump
  keeps both pcbs alive forever (sofree never hits zero → pr_detach never
  runs → no kfree_type on the smashed fields).
- **P043 (43724) v8 verdict**: all sweeps stay EINVAL(22). Ghidra: the wall
  is `mac_file_check_mmap` FUN_fffffff00a5d79d8 — a MAC policy aggregator
  (policy list DAT_fffffff007b6eb50, per-policy ops+0x20 → +0x120
  file_check_mmap; error ladder EAGAIN > EINVAL > ESRCH > ENOENT > EACCES >
  EPERM; panics "increased max protections" if a policy raises maxprot).
  So class 7 / action 0x12 routes through the MAC layer — the identity wall
  is cs/MAC on the vnode, not sf_flags or fd-open mode; the handler
  normalizes the denial to EINVAL. Policy chase recipe (DB has no names
  there): read DAT_fffffff007b6eb50 entries, each entry+0x20 = ops table,
  ops+0x120 = that policy's mmap check. iOS candidates: AMFI + Sandbox.
- **P069 (43684)**: mapping path exercised once on 23F77 — upl_validation
  ABSENT; increment is IOMD+0x68, not +0x34. Catalog note only.
- Honest state: KRW on 26.5 A14 still NOT obtained. The conversion is wired
  and now safe to arm; the missing piece is the Beta-2 LIVE-element steering
  write (mach-msg OOL/port pointer swap) built on the confirmed P099 shape.

### 2026-10-15 16:07–16:11 — 26.5 A14 tap batch on the fixed IPA: OOB #3, catch-22 re-proven ×3, ColdForge deputy survivors

- **The sideloaded IPA is the fixed build** — the P099 banner carries the
  interleaved verdict text and `holes-freed=1024 (interleaved: odd holes kept
  LIVE)` on-device, so 04a4c87 is what is running on the hunt device.
- **P099 v2 interleaved first live tap**: groom freed 1024/2048 (odd kept
  LIVE — the 15:25:51 panic fix is live). CONTROLLED OOB #3 confirmed
  (victim=2044, first_diff=0x0000, 48 payloads, records
  {surfaceId, symbol, 0x100000001}; surfaceIds vary per run). No panic in the
  window. Still Beta-1: detection only, the steering write is not built.
- **LightSword v2.1 re-tap**: spyConfirmed=1 → kill-shot miss again
  ("alias GART is not independent"). Failed PRE-smash (stale acquire), so the
  new teardown-defuse paths were never exercised — abort was clean, no crash,
  no dangling sockets.
- **LightSwordABC — second angle on the catch-22**: [B] detach-once = 0xe00002d5
  Busy (prior LightSword session left a wire); [C] detach+replace → blit
  first=0x00 (detach unmaps GART — blit is NOT a dangling-page read); [D]
  vm_remap alias → "not GPU-shared" (cpuShared=0). Three independent proofs
  that no alias/detach shape yields a post-detach GPU-visible read on 26.5.
- **ColdForge v1.4 (deputy lab) 16/16 SURVIVED**: post-free sel36 deref
  through freed IOGeneralMemoryDescriptor elements (cd8/d00 class) survived
  every attempt — confused-deputy UAF candidates on 26.5. Reach=0:
  IOSurfaceLookup(out) → NULL, consumers unreachable (p016 historic).
  **[debt] 16 extra taggedRetains in flight** on held GMDs — stabilize/
  teardown may free them late; a delayed zalloc-style panic after ColdForge
  taps would fit that debt. Operator note stands: cd8/d00 = RECLAIM HIT —
  file IPS + log if one lands, STOP tapping until then.
- **Beta-1 calibration (user's framing)**: the project is Beta-1 until a
  device is jailbroken from OUR app — post-respring evidence = jbroot + Sileo
  + Zebra installed by the bootstrap. Controlled-OOB confirmations, deputy
  survivors, and page-read oracles are lab evidence, not milestones. hasKread
  stays NO on 26.5; KRW still not obtained.

### 2026-10-15 ~16:50 — FomoPeek RE intel: DarkSwordStrategy confirms our kit lineage + sanitized bundle rebuilt CLEAN

Source: SlowMist/OKX joint disclosure (2026-09-21) + gm7.org full text + Threadlinqs TL-2026-2591 +
fullchain.sh finding. One card per skill discipline.

- **What shipped**: FomoPeek 1.1 (build 105, 09-09) / 1.2 (build 110, 09-12) App Store builds carried
  two non-business frameworks, `apptrace` (C2 comms) + `libapptracecore` (kernel attack + acquisition).
  1.3 (111, 09-17) removed both. ~$579,984 USDT traced to attacker address 0x6d37f2C5...5975f4BB.
- **The 8 strategy classes** (`libapptracecore`, all inherit `exploit::IExploitStrategy` /
  `KernelMachTaskExploitStrategyBase`, per-device support predicates, coverage windows tile
  iOS 12.0–18.7.2 + 26.0–26.1). Public reporting names exactly two: **CicutaVirosaStrategy**
  (iOS 12–14 era, single run >2 min — matches the KOL "stay 5–7 min on a real device" promo)
  and **DarkSwordStrategy (16.7–18.7.2 + 26.0–26.1)**. The other six are unnamed in public text.
- **Lineage confirmed**: DarkSwordStrategy IS the leaked DarkSword tool (SlowMist 03-25 warning,
  im23pds tweet) — the same codebase as our lab kit `research/p7-darksword-rce/` (WebKit RCE →
  sbx0 → sbx1 gpuFcall/PAC → pe_main inpcb corruption → kernel_base/slide → kread/kwrite via
  control-socket lane). Their declared window stops at 26.1; our kit's `rce_worker_26.5_fixed.js`
  + `sbx1_26.6.js` extend to 26.5/26.6 — exactly the hunt device build (23F77).
- **Native-layer strings (libapptracecore)**: tfp0 ("Creating safe tfp0" / "Updated port for tfp0!"),
  kread/kwrite ("found kread_sem_index"), exploit surfaces **IOSurfaceRootUserClient,
  IOSurfaceClient, IOAccelCommandQueue2, IOAccelSharedUserClient2** (our ColdForge/84530/43748
  family), PPL ("HSP4 patch exists./Applied HSP4 patch."), ucred (`KernelUcredStealer`,
  `RORestrictedUcredPatcher`, `RO2RestrictedUcredPatcher`, WeirdCsTrick), sandbox
  (`SandboxExtPatcher` → com.apple.app-sandbox.read-write), offset providers
  `kernel::OffsetProvideriOS12/13/14/15/15_2` + runtime computation with explicit **iOS 26** branch.
  Keychain parsers KeychainV3/V9/V11 + AppleKeyStore client = the theft half (we never copy).
- **C2/IOC**: deadbox `bitbucket[.]org/discordseven/text/raw/main/xxhVOn` (48B AES-128-CBC,
  key bc2c72b2…, IV 71ec8e39… → api-a95f0ed200f.assisaint[.]com); endpoints /api/device/{apps,
  config,report} + /api/upload/zip; collect_configs = 19 wallet/notes apps. All STRIPPED from our
  lane; host strings rewritten to 127.0.0.1:8081 / 192.168.1.2:8081.
- **Sample hashes (for later native RE)**: FomoPeek-1.2.ipa SHA-256
  48f9d5623af1518e774d57c41e6e0b915a7e9f896909bf596a9b27de5022911e; libapptracecore
  f0b3be01e8597f7f35ca36c009f68e7004527fe4a01d4349a01e211ca16de1e2; apptrace
  764663ff5c8bd1bdf33bbd1ec352ce262a4fe79695456f2612dc27c35840ab9d. Mirror (ipadump.com) is
  UDID-gated; MalwareBazaar/VT/archive.org do not yet host it. Native-side deep RE pending sample;
  otool/strings first, Ghidra import second (REA MCP stays read-only).
- **p7lab bundle rebuilt CLEAN (16:44–16:47)**: previous rce_loader.js PARSE FAIL was self-inflicted —
  the marker-blank pass turned `window.__LAB_X__` into dangling `window.` expressions. Rebuild keeps
  all `__LAB_*` markers as legitimate globals set by config.js (RECOMMENDED_WORKER →
  rce_worker_26.5_fixed.js, DELIVERY_HOST, DEVICE_UUID), URL rewrites + strip list + Cloudflare-beacon
  removal unchanged. pe_main amputation re-applied (both `__peStages` arrays emptied; kernel machinery
  pe_init/pe_v1/pe_v2 preserved; `__labKrwReport` scope-proof beacon + KRW self-test
  `early_kread64(kernel_base)===0x100000cfeedfacf…` wired at the mpd bridge). **All 8 chain-critical
  files JSC PARSE OK** (rce_loader, worker 26.5_fixed, sbx0_main_26, sbx1_main_26, pe_main, config,
  chain_loader_26, loader). Zero-external audit: CLEAN (36 files). serve_p7lab.py recreated (old copy
  was lost in the rebuild — localhost-only smoke log, no device beacons, was lost with it).
- **Server live**: :8081, sink verified (`LAB SERVER RESTART OK`). Device runbook unchanged: Safari →
  http://192.168.1.2:8081/index.html on the hunt device; watch fetch cascade then `PE ALIVE` +
  `KRW_OK/KRW_FAIL kb= slide=` beacons.
- **Honesty**: kernel r/w on 26.5 A14 is still not obtained by us or by anyone public; FomoPeek's
  declared window (26.0–26.1) does not prove 26.5. The marker test is a DARKSWORD.md §5 step-3
  experiment, not a KRW claim. hasKread stays NO; Beta-1 stays Beta-1 until jbroot + Sileo/Zebra
  from our bootstrap.

### 2026-10-15 ~17:10 — SwiftPeek × Lum1na: pre→post jailbreak continuity plan (user directive)

User: FomoPeek name-tie-in with **SwiftPeek** (`~/Projects/lumina/lumina-repo/SwiftPeek`, Theos
tweak + SPKit support library, docs/DEPENDENCY_PLAN.md). Use it / its logic to make the chain more
novel on modern iOS, as a dependency pre- and post-jailbreak.

- **Feasibility, honest split**:
  - *Pre-jailbreak*: NO exploit primitive comes from SwiftPeek (UI discovery is not kernel
    access — the KRW producer stays the DarkSword web lane + catalog doors). What IS usable now:
    the shipped SPKit pieces (runtime hygiene / sync-fsync trace / overlay hosting) already mirror
    our own PersistentLogStore discipline, and the SwiftUI discovery logic can run **in-process**.
  - *Post-jailbreak*: this is the goldmine. Lum1na's AfterKread pipeline already stages
    `Resources/tweaks/` and runs `dpkg -i` — SwiftPeek ships there as a `.deb` beside Sileo/Zebra.
    Per DEPENDENCY_PLAN shape 3 (`Depends:` shared dylib), SwiftPeek becomes the SwiftUI-era tweak
    support library (SPHostingViewsIn / SPSwiftTypeName / SPKOverlayWindow / control discovery),
    which no mainstream jailbreak ships out of the box today. That is the novelty claim.
- **Pre→post continuity (implemented this commit)**: `UI/PeekInspector.swift` + Settings
  "Peek UI Tree" — the in-app twin: walks Lum1na's own windows, finds UIHosting* views, names the
  SwiftUI rootView + one mirror level via public API only, logs through ExploitManager console.
  Same discovery shape as SwiftPeek's SPAttach/SPHostingViewsIn; pre-jailbreak it peeks our app,
  post-jailbreak the injected SwiftPeek peeks any app. API-identical-in-spirit so the code is
  transferable without rewiring.
- **Tasks queued (post-Beta-1, ordered by DEPENDENCY_PLAN dogfooding)**:
  1. Build SwiftPeek `.deb` on the Theos toolchain targeting 26.x and drop it into
     `Resources/tweaks/` (explicitFolder) — AfterKread installs it automatically; no pipeline
     changes needed.
  2. iOS 26 field re-dump: SwiftPeek's offline catalogs (MA-*.txt) are iOS 17.3-era; Liquid Glass
     changed Music/SpringBoard internals. First job after first jailbreak: re-run the dump tools
     on the hunt device at 26.5.
  3. Kill-switch exercise (SPKKillSwitchEngaged) on a lower-risk target before SpringBoard.
  4. Shape 3 (`Depends:`) only when third-party consumers or cross-tweak coordination force it —
     per the plan's own packaging table.
- **Naming**: FomoPeek / SwiftPeek / Lum1na-peek family branding stays cosmetic; the P075 census
  ("Peek" of the IOKit surface map) is coincidental naming alignment, not shared code with the
  hostile sample.
- **Honesty**: no SwiftPeek logic enters the exploit bodies (rule: race/UAF bodies untouched);
  PeekInspector is additive UI+console only. hasKread unchanged.

### 2026-10-15 ~17:35 — panic #5 (23F77): P044 v46 freed-element debt fired, ANE lane STOP; P075 first live census; p7 lane GO

Device log + `panic-full-2026-10-15-172914.0002.ips` (SHA-256 589fa3f1…, kept private — signature only here).

- **Panic**: `panic(cpu 4): [data.kalloc.3072]: element modified after free (off:0,
  val:0x000000c00000017e, sz:3072, ptr:0xffffffe0d971a800)` — 25–28 s after the 17:28:42 Full
  Chain, inside Lum1na's own syscall path (pid 805). Dumped element = the ANE prewire record
  stream `{surfaceId=0x17e, symbol=0xc0, 1, 1} {0xc4, 0xc1, 1, 1} …` — the P044 v46 fire's
  records (surfaceId ≠ the P099 tap's 0x17b), 48 records, exactly the 15:25:51 proof shape.
  Latency confirmed again: plant → ~25–30 s → zalloc catch.
- **What it proves**: the v46 interleaved groom ("odd holes kept LIVE") still fired into an
  element that was or became free — adjacent-element liveness at fire time is **not verifiable
  pre-fire on 23F77**. Occupancy MISS (stage 3 hits=0) + freed-element panic in the same session
  = groom redesign required, not a retry. ptr sits in the segregated `.DATA` zone; conversion
  HOLD unchanged (records still cannot carry pointer bits).
- **Operator rule (extended)**: an IPS for this class has landed → **STOP all kalloc.3072 /
  ANE fires (P044, P099, T1 chain, remaining-fire variants)** until a new groom design with
  verified-live adjacency exists. LightSword stays parked on its own kill-shot miss. Next
  progress on this class is Ghidra/design work, not taps.
- **P075 first live run (17:27:32)**: SKU gate pass; **IOSurfaceRootUserClient type 0
  kr=0x0 — OPEN** (FomoPeek surface 1 live on 23F77); IOSurfaceCreate/GetBaseAddress dlsym ok;
  **IOServiceMatching("IOAccelerator") = not found on 23F77** — census v2 must try
  AGXAccelerator / IOGPU / AppleAGXDevice before the AddClient pairs; cosmetic line-interleave
  in the double-open pair (P06xLog notify race), content unaffected.
- **p7 lane unaffected — GO**: the panic came from Lum1na's own process taps; the Safari/GPU
  web lane touches neither kalloc.3072 nor ANE, and a fresh post-reboot boot is the clean heap
  the test wants. Runbook: Safari → http://192.168.1.2:8081/index.html; watch serve log +
  `lab_log.txt` for the fetch cascade, `PE ALIVE`, then `KRW_OK/KRW_FAIL kb= slide=`.
- hasKread stays NO; Beta-1 stays Beta-1.

### 2026-10-15 ~18:05 — p7 DarkSword web lane: instrumented device test on 23F77 — NOT REPRODUCIBLE; lane closed pending a new bug

- **Setup**: p7lab bundle served from the Mac (LaunchAgent `:8081`), device Safari via
  Bonjour `http://Kolbys-iMac.local:8081` (bare-IP host is rewritten by the loader's
  `preferPublicHttps`; old `192.168.1.2` was also stale after DHCP moved the Mac to .236).
  Band override (`__LAB_BAND__`) feeds the loader a ghostwave/RESEARCH_HIGH research band
  that defeats its hardcoded ">26.3 patched" classifier — research-grade only.
- **Instrumentation made permanent** (both copies synced, parse-checked): stage1's 27-site
  telemetry redirected from the kit C2 (`mcp9.net` / `127.0.0.1:8081`) to the local lab log
  sink via the worker's `host`; `L=` grow-path discriminator added to `pv_oobread`; new
  `pv_warmup_done` beacon; worker progress beacons (aarw 50-try cadence, fallback result
  JSON); FALLBACK1 now calls `triggerStage1()` (full orchestrated sequence) instead of
  `establishPrimitives()` alone — the earlier "bare Error" was `TryAgainError` after 150
  silent catches in the worker's own try-loop.
- **Lane 1 — CVE-2025-43529 (aar/w UAF pair)**: 150/150 trigger tries, no 15.57 marker
  pair, across 4 runs → not reproducible.
- **Lane 2 — bug303879 (InBounds-OOB → fakeobj → scribble → LFH pair)**: the trigger
  executes but the stores never leave the array. Post-warmup beacon: `L=128` after 20000
  iterations AND after **140000 iterations (FTL tier pushed)** — JSC grew the array through
  the normal path; the bounds-check/grow elimination never engages at DFG or FTL on this
  build. Downstream all correctly dead: markers/spray `no_hits`, fakeobj stays
  `number:NaN`, contig/double pair never adjacent, LFH pair confusion 8/8 fail, kit's own
  `pv_layer1_check` honestly rejects the NaN-garbage addrof (`dom=7ff8 real=false`).
  Documented false positive: `pv_scribble_upgraded` passes on garbage addrof — weak check,
  never evidence by itself.
- **Verdict**: the web lane (kit-as-shipped, both CVE shapes) is **dead on
  iPhone13,2 / iOS 26.5 / 23F77**. One WebContent tab crash mid-run (18:01:40) was
  survivable and is not a panic. This does not claim the CVEs are fake — only that these
  trigger shapes do not produce the required JIT corruption on this device/build.
- **What stands**: the instrumented lab yields a one-reload verdict on any future
  build/device. Next options: a different 26.5 WebKit/JSC bug (out of kit scope), or the
  kit's `ios18` path on an actual 18.x device.
- hasKread stays NO; Beta-1 stays Beta-1; ANE/kalloc.3072 lane stays STOPPED (see above).

### 2026-10-15 ~18:10 — census repro across reboot + pre-panic log evidence; OPS: iOS 27.0.1 nag must be blocked

- **OPS WARNING**: `followupd` approved an **"Update to iOS 27.0.1"** banner (pending since
  Oct 13). Installing it kills the 23F77 lab target — pins, SKU gate, and the web-lane
  verdict above all become moot. Automatic Updates must be turned OFF; the device stays on
  26.5 / 23F77. Any 27.x testing is a fresh-lab decision, not an in-place update.
- **Census reproduced across reboot (18:05:42)**: IOSurfaceRootUserClient type 0 open
  `kr=0x0` again — FomoPeek surface 1 open is a stable 23F77 property, not a
  panic-transient. IOSurface dlopen/create/getBase ok; `IOAccelerator` still absent →
  census v2 service list (AGXAccelerator / IOGPU / AppleAGXDevice) stands. Cosmetic:
  first-open line printed garbled hex (`conn=0x22432b¿dN`) + one blank line (P06xLog
  notify interleave); double-open pair carried two distinct live conns.
- **Pre-panic timeline (completed by a second log paste)**: `ANECompilerService`
  compiled a `254in_1out_addchain` mlmodelc clone at 17:28:27, then Lum1na's ANE
  prewire attempts fired: **17:28:28** and **17:28:46** both hit
  `ANE_ProgramCheckandPrewireBuffers_gated: MemoryMapRequest for 255 buffers,
  result: 0xe00002c2` (**kIOReturnBadArgument** — code-name corrected in the P070
  card below; VMError is 0xe00002c8) with Lum1na programs open (229376 /
  344064 B wired); at **17:28:47.24** the GPU command buffer aborted
  (`kIOGPUCommandBufferCallbackErrorOutOfMemory`) with kernel faults
  `IOGPUMemory::prepare_memory_slow … prepare detached resource`; panic zalloc
  catch ~20–27 s later, then a clean gap to 17:30:51 (reboot). **Refinement of
  the panic-#5 analysis**: the freed kalloc.3072 element most plausibly
  originates in the *failed* 255-buffer prewire teardown path (255 × 12 B ≈ 3072
  — hypothesis, needs dump-tool/Ghidra confirmation), not a successful prewire.
  Any future groom design must target the map-failure window explicitly. ("XVRC27"
  clone name still to match against the note-139 dump-tool output.)
- Curiosity: `applekeystored` was sandbox-denied writing an xattr on the bundled
  `basebin/Relaxin.roothide` payload — harmless, file untouched; basebin survives
  install as expected. (The `modelmanagerd` "UAFAssetSet…" errors are Unified Asset
  Framework naming, not memory-safety signal.)
- Note: P075's built-in honesty line still names the web lane as "KRW producer
  candidate" — stale per the verdict above; next app build updates the string.
- hasKread stays NO; Beta-1 stays Beta-1; ANE lane STOPPED; web lane CLOSED (card above).

### P070 chain-sequencer v1 — reach census, 2-run repro (2026-10-15 18:15/18:16 EDT, note 142)
- First P070 evidence. Census + reach map only: no fire, no kwrite, one door TAP
  per force-quit. Two sessions 36 s apart (force-quit between) → same-boot repro
  of the reach map. IDENT identical both runs; **QueueCreate dual-oracle still LEFT**.
- Reach (IOServiceOpen, unprivileged, no fire): type=1 opens succeed on
  **H11ANEIn**, **H1xANELoadBalancer**, **IOGPU**; type=0 there returns
  `0xe00002c7` (**Unsupported** — a type gate, not an entitlement wall; matches
  the CHAIN.md P032/P044 record). **AppleKeyStore** and **AppleJPEGDriver** open
  type=0 (door C's AKS conn reachable). **AppleAVD** = `0xe00002c1`
  NotPrivileged both types; **AppleAVE2Driver** = `0xe00002e2` NotPermitted
  both. `agx` / `AppleH11ANEInterface` / `AppleAVE2` names not found. kr pattern
  deterministic across relaunch.
- **Code names verified against xnu IOReturn.h** (apple-oss-distributions,
  fetched this session): 0xe00002be NoResources · 0xe00002c1 NotPrivileged ·
  0xe00002c2 **BadArgument** · 0xe00002c7 Unsupported · 0xe00002c8 VMError ·
  0xe00002e2 NotPermitted. **Correction**: the panic-#5 255-buffer prewire
  failures (17:28:28 / 17:28:46, card above) were **kIOReturnBadArgument**, not
  VMError — argument/validity rejection of the map request, not VM pressure;
  the 17:28:47 GPU OOM command-buffer abort stands separately. The
  failed-teardown → freed kalloc.3072 hypothesis is unchanged (and slightly
  stronger: BadArgument fires after the record array is built). Three legacy
  debug strings in the repo label codes wrongly (`P032ANEOpenSmoke.m` /
  `LabIOGPUQueue.m`: 2c1 "Aborted"; `P010QueueLeak.m`: 2c7 "NotPrivileged") —
  cosmetic cleanup candidate, not done.
- Doors A–E unchanged with their nexts (A: shape-1 reclaim; B: named Shape L
  copyout dest; C: needs a WRITE-door pair; D: named client/flow reclaim;
  E: named +0x34 consumer). Nothing is one-tap-from-KRW. Persist VAs parked
  (AMFI UC 0xFFFFFFF008B673F8 … pmap_load_trust_cache 0xFFFFFFF00A60D8D0),
  AfterKread HOLD until commitSlide.
- State: hasKread NO / kslide 0 / kbase 0 (both sessions). Next per the TAP's
  own order: one door (P065 / P063 / P044) → force-quit; KREAD tap only after a
  door yields kread32. OPS standing: **disable iOS auto-update on the device**
  (27.0.1 nag, card above) — still unconfirmed done.

### A13 reference rig — FIRST hasKread=YES in project (Dopamine ClearSword core, public); P094 kernproc PROVEN; p095 walk bug + elevate visibility fixed (2026-10-15 evening, note 143)
- **Honesty**: the rig KRW is the **public Dopamine 3.0.11 ClearSword core**
  (Beta 1 path #2, verbatim) — it validates the post-KRW machinery, it is not a
  novel exploit. **Hunt (A14, 23F77) still hasKread NO**; ANE lane STOPPED; web
  lane CLOSED; doors A–E unchanged.
- **Milestone**: cs2core established KRW 3× on iPhone12,1 / 22G100 (slides
  0xec18000 then 0x79a4000; magic self-test kread32=0xfeedfacf /
  kread64=0xc00000002 PASS each time; commitSlide OK → hasKread=YES
  hasKwrite=YES). **P094 PROVEN** (read-only): sysctl anchor honestly masked
  (e_paddr=0), allproc head scan matched, kernproc-proven unslid
  0xffffffe624f996d8 recorded; LEADs kernprocvar + allproc CONFIRMED, zombproc
  honestly REFUTED; board leaks 6→9. Allproc is newest-first, **proc0 is the
  TAIL**.
- **p095 bug fixed**: its board fallback walked `le_next` FORWARD from proc0 —
  NULL at the tail — so it HOLDed with the stale "run p094 first" message
  minutes after p094 recorded the value. Fallback now walks `le_prev` backward
  (oldest→newest, same shape as Lum1naElevate) with exhausted-walk diagnostics.
- **AfterKread elevate visibility fixed**: `fire()` ran Lum1naElevate but
  appended its block to a string the `P06xLogDump` return path drops — every
  elevate HOLD/FAIL was invisible (explains FIRING → pmap line → EPERM with
  nothing between). Elevate lines now stream via `ak_log`. The installed rig
  IPA likely also predates the elevate lane — rebuild + reinstall required.
- Expected next wall (prediction): with elevate working, opainject spawn gets
  past EPERM, but exec may still SIGKILL on AMFI code signing — basebin.tc
  loads but the A13 AMFI loadTrustCache selectors are unproven. rc=0-then-die
  is progress, not failure; the follow-up is the A13 trustcache lane (Ghidra
  selectors, not guessed).
- State: rig hasKread YES (public core); Hunt hasKread NO / Beta-1. OPS
  standing: **disable iOS auto-update** — still unconfirmed done.

### Lum1na-Debug (P007 lab app) pushed to the repo + CI builds both IPAs (2026-10-15 late evening, note 144)
- The `P007OpenOnly` lab rig app (home-screen name **Lum1na-Debug**, bundle
  `ma6x9x.P007OpenOnly` so on-device container/logs survive reinstall) now
  lives in the repo at `P007OpenOnly/` with its own xcodeproj + shared scheme.
  New workflow job `build-debug` in `build-ipa.yml` produces
  **Lum1na-Debug-unsigned-ipa** alongside the Lum1na shell IPA — the only
  build path while the free dev account blocks local signing.
- **Offsets/VA/SKU sync**: its `LabRuntimeOffsets`, `LabDeviceProfile`, and
  `A14_23F77` / `A12X_23G71` pin headers were stale Desktop copies — replaced
  with the repo's current tables (A13_22G100 rig row, A14_21D50, XR_22H311,
  LabOffForSku/LabKernSlide/LabStaticBase/LabPmapCsAllowOff, amfi_external +
  amfi_loadtc VA fields). Repo headers keep the legacy `+sku` selector so all
  lab probe call sites compile unchanged. Rule recorded in AGENTS.md: tables
  are edited in `Exploit/` and re-copied into `P007OpenOnly/` — never diverge.
- **Unknown-device testing** (the point of the app): IDENT always prints
  (`hw.machine` + `kern.osversion`), "runtime profile always wins"; unknown
  SKUs get `LabSkuUnknown` / `_other` rows, kernel-VA probes HOLD honestly
  when `LabOff()` returns NULL, and IOKit/spray/CoreML primitives still fire —
  so a new device/OS can be probed for sticking primitives without a known
  offset row.
- CI note: pbxproj pins deployment target 18.5 (Desktop SDK); CI Xcode 16.4
  ships the 18.4 SDK, so the job overrides `IPHONEOS_DEPLOYMENT_TARGET=18.0`
  on the command line. Entitlements stay the free-account set the rig already
  proves works: `com.apple.developer.game-center` + `get-task-allow`.
- **SKU-gate bypass (compile-scoped)**: `LAB_DEBUG_APP=1` is defined only in
  the Lum1na-Debug pbxproj — `LabDeviceProfile stopUnlessA14_23F77:` returns
  nil in debug builds (primitives run on unknown machines) while the main
  Lum1na app keeps the gate. `+gateMode` prints which mode the build is in.
  Honest cost stated in code: kernel-VA probes still HOLD when `LabOff()` has
  no row — the bypass unblocks primitives, not kernel writes.
- **P100 AutoLearn v1 — the learner** (heuristic inference + oracle
  validation, not a trained model): deep IDENT sysctl sweep with honest
  denied-markers; **chip tag parsed from `kern.version`
  (`RELEASE_ARM64_Txxxx`)** with SoC-family map (this alone fixes
  "chip Unknown" IDENT rows); darwin-major → iOS family inference; ABI
  fingerprint (kinfo_proc len); IOKit door census (opens only, no selectors,
  type 0 + 1 on 10 services); IOSurface create smoke; classifier verdict
  (KNOWN / NEAREST-recognized-no-row / UNKNOWN class); **LEARN PACKET**
  block for copy-back + a JSON line appended to
  `Documents/lum1na_learn.json` (UIFileSharingEnabled → Finder/Files) +
  board recordEvent. One tap on any new device/OS emits everything we need
  to decide a new LabOff row.
- Same session: the lab copy of P095 got the le_prev backward-walk fix
  (repo commit 523367f shape) — lab board had `provenKernproc` but walked
  `le_next` from the allproc tail, same silent-HOLD bug.
