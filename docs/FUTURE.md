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
 - **2026-10-14 EVENING SESSION (17:35-18:00 EDT): FIRST hasKread=YES + four
  crash decodes + Full Chain HOLD fix.**
  1. **MILESTONE: hasKread flipped YES for the first time** — 4th cs2core
     establish on the rig (iPhone12,1 A13 22G100): kbase=0xfffffff018128000,
     slide=0x11124000, 1103 ms, magic PASS -> commitSlide -> KRW self-test
     gate PASSED. Build 98a2cb1. PATCHSET now passes the KRW gate.
  2. **Hunt panic 3 (17:38:29) DECODED — app SIGABRT, not kernel panic.**
     Faulting thread 6: pthread_kill -> abort -> __assert_rtn ->
     cs2_surface_mlock.cold.1. Root cause: ClearSwordCore mlock table cap is
     8 (wired mapping + 8 search mappings = 9 slots; verbatim munlock calls
     are commented out), the tap ran 3.5 min, scanned all 8 mappings, began
     a SECOND socket round, and the 9th mlock overflowed -> assert ->
     SIGABRT. Explains the earlier "zero logs" cs2core deaths on hunt:
     cs2_core_log.txt opened O_TRUNC per session, so every new tap erased
     the previous crash's evidence. Fixes: (a) cs2_surface_mlock now logs
     LOG_ERR("mlock table full ... untracked, continuing") and returns
     instead of aborting — surface still created, scan continues, exploit
     behavior unchanged; (b) cs2_core_log.txt opens O_APPEND so crash
     evidence survives relaunches.
  3. **Hunt panic 4 (17:38:29) DECODED — WLAN dext self-abort, not a kernel
     panic.** AppleBCMWLAN dext watchdog fired (IO80211DeadlockPolice
     handleDextWatchdogTimer -> panic -> abort) while the rest of the dext
     deadlocked on IORecursiveConditionLockLock (interrupt thread ->
     DispatchSync; command thread stuck in issueCommand/configureUpLinkOFDMA).
     Same bootSessionUUID and second as panic 3 — collateral from the cs2core
     spray window. Device did NOT reboot.
  4. **"Full Chain says complete but no respring" ROOT-CAUSED and fixed.**
     The chain's KERNEL stage never established the ClearSword core (lanes
     were T1 ANE WRITE -> LightSword -> libkrw only), and board.hasKread
     persists in the JSON across relaunches while the primitive is
     process-local. So after the 17:35 manual cs2core flip, FULL CHAIN ran
     with either (a) a persisted flag and a dead lane -> self-test SKIP ->
     HOLD, or (b) T1 spray disturbing the still-live lane -> self-test FAIL
     -> HOLD — while the KERNEL board legitimately showed COMPLETE on the
     persisted hasKread (AGENTS.md design). Fixes in ExploitManager:
     KERNEL stage gains B1 lane 4 (Lum1naKRW_EstablishFromCS2Core when
     nothing else landed KRW), and PATCHSET re-establishes the cs2core lane
     once when hasKread=YES but no lane is live in this process. The
     AfterKread self-test still decides — HOLD means HOLD.
