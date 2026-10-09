# Chain map (public)

This is not a claim of KRW. Pins are **unslid** per `LabOff()` (A14 23F77 T8101 / A12X 23G71 T8020).

## KRW theory buttons (home)

Seven isolated TAPs. Reboot + force-quit between T1–T4 and T7 GPU map. `ui-build phys-map-1`. Home is scaled down (star/pads clipped to the board; **JAILBREAK / ALL / COPY** on one row). Console glass is interactive. None of T1–T4 set `hasKread` from occupancy, `0xe00002be`, or blit `0x11`. PAC/PPL maps (T5/T6) do not skip kreadbuf. T7 is registry + read-only MapMemory.

| Button | Catalog | Theory |
| --- | --- | --- |
| **T1 ANE** | `krw` | 43748 store into next kalloc.3072. FILL HIT = write proof. |
| **T2 FACET** | `krw2` | 64788 1×65535 + Trap2 sel=3 oracle. |
| **T3 SOCK** | `krw3` | 43748 then icmp6filt. Expected SKIP. |
| **T4 LS** | `krw4` | Dual-wrap last-wire. 18:45 OOM sealed. |
| **T5 PAC** | `krw5` | Dopamine `badRecovery` / 65330 map. kcall after kread. Does not fire hop-1. |
| **T6 PPL** | `krw6` | Titan A14 / momentarius map. Always runs AfterKread; AMFI/opainject still HOLD without `hasKread`. |
| **T7 PHYS** | `krw7` | IOKit registry + read-only `IOConnectMapMemory` for A14 IORVBAR `0x206050000`. No DMA/`+0x34` fire, no Titan write. |

Credit: opa334 / Lars Fröder — Dopamine 3.0.10 (`primitives_external.h`, `DOJailbreaker.m`, Titan, momentarius, `physrw_pte.c`, `trustcache.c`). Copied into Lum1na: `Exploit/DopaminePrimitives.h` (vtable contract only). Hop-1 / kfd / multicast_bytecopy bodies stay in the Dopamine tree.

Solo `p044` / `staleentry` / `lightsword` stay All-stages. JAILBREAK is SANDBOX + T1 + AfterKread HOLD. CVE-2026-86950 stays parked.

Home also has **CHAINS** (`p070` census), **KREAD** (`kreadtest` commitSlide bar), **FILES** (`p072` parser census). Same processing contract as P007: TAP marker in `p011_tap_log.txt` before invoke, POSIX + `F_FULLFSYNC` probe logs, recover last TAP mapped log, `hasKread` only after `kread32(kbase)==MH_MAGIC_64`.

## P007 TAP-id parity (All-stages)

Port path after a primitive is proven on P007: copy `+tap` + catalog id + log name. Isolation: one TAP per force-quit.

| Id | Class | Log | Notes |
| --- | --- | --- | --- |
| `p063` | `CVE_2026_84530_KASLR` | `p84530_aio_kqueue_log.txt` | Alias of `aio84530`. HEAP, not kslide. |
| `p064` | `P064AVE84607Racer` | `p06x_P064_log.txt` | Close-vs-async PARK. **Not** the HT149041 map. |
| `ht149041` | `P064Ht149041ChainMap` | `p064_ht149041_chain_log.txt` | Print-only 26.7 map. P007 calls this `p064`. |
| `p065` | `P065FacetAOracle` | `p065_facet_a_log.txt` | 0xe00002be oracle. T2 `krw2` is the theory twin. |
| `p066` | `P066AveEncTypeMap` | `p066_ave_enctype_log.txt` | One 128x128 H.264. Distinct from `p061` dual-session. |
| `p067` | `P067AvdReach` | `p067_avd_reach_log.txt` | IOServiceOpen only. |
| `p068` | `P068ChrootPrivMap` | `p068_chroot_priv_log.txt` | errno MAP. |
| `p069` | `P069DmaCommandMap` | `p069_dma_command_log.txt` | One map. Local `mach_vm_map` prototype. |
| `p070` | `P070ChainSequencer` | `p070_chain_sequencer_log.txt` | Five doors + AMFI HOLD. |
| `p071` | `P071AneOverflowMap` | `p071_ane_overflow_log.txt` | DeviceOpen 0x68. Not 43748 fill. |
| `p072` | `P072FileParserMap` | `p072_file_parser_log.txt` | dlopen + 1x1 PNG. Not ACE. |
| `kreadtest` | `Lum1naKreadTest` | `lum1na_kread_test_log.txt` | FAIL unless armed kread returns `0xfeedfacf`. |

Lum1na `p057` is WVEK reach. P007 `p057` is AKS deserialize. Do not overwrite either.

## File-parser chain (P072)

Three slots. None of them is first KRW.

1. **In-app parse** of CG / ImageIO / SceneKit / JPEG / CoreMedia ACEs this IPA process. The app already owns that process. Cannot skip `commitSlide`.
2. **Daemon plant** (MobileBackup 84598, lockdownd, Photos) is sandbox-adjacent. PARK remaining-fire.
3. **AfterKread ingest** of board JSON + `basebin.tar` / `basebin.tc` is the jailbreak file mechanic. HOLD until `hasKread`.

P072 is print/dlopen census plus a 1x1 PNG we just encoded. No `trigger.pdf`. CVE-2026-86950 stays parked.

## Auto-filled board

On launch, `Kernel/Lum1naBoard` writes **Documents/`lum1na_board.json`** from `LabOff()`:

- identity: machine, `23F77`, table tag
- pins: fn4, wvek, AVE Close, ANE CheckandPrewire, SysMem `+0x90`, `SO_NECP`
- `kslide` / `hasKread` stay `0` / false until a proven kread

Heap hits from **aio84530** / **cskrw** append to `leaks[]` as `kind: heap`. Do not subtract `staticBase`.

View: Settings → Copy Kernel Board JSON, or All stages → Kernel board JSON.

## Proven facts (do not backtrack)

- P009 PathB = **F** (stale GPU), not W
- QueueCreate A14 `0x410` leak `+0x558`; A12X `0x408` / `+0x550`
- LightSword fd cap is `min(rlim, dtablesize)` (23F77 live: rlim 65535, dtablesize **10240**). v1.7 used rlim as room so punch-after-hole never ran.
- CS hop 1 `cluster_*_contig` **EINVAL** unless `UPL_PHYS_CONTIG` (26.1)
- P052 nstream **EFBIG 27** already on 26.5 — a different 84523 guess than wvek. Do not remaining-fire.
- CVE-2026-84530 AIO `kqext_sdata` class live until **26.7/27**
- wvek: `apfs_aks_create_wvek` `0xFFFFFFF009BD96D4`; F77 `len>0x210` is **BRK**, 26.7 adds `len<=512`
- AKS UC **opens** (live P057). CVE-2026-65343 is an OOB **read** (KASLR) via ACM deserialize. Catalog `aks` tap is ACM capture (`aks-capture-v4`), not the 163-selector crash. Fingerprint: sel0/1 empty; sel2–4,6–7 `0xe00002c2` BadArgument; **sel5 `0xe00002c1` NotPrivileged** (privilege, not size — more insz will not deserialize). Sibling leak of aio84530. Does not replace 43748 fill (`surfaceId` is u32). Not KRW.

## 23G71 A12X iPad (T8020) — dual-SKU gates

SKU is `hw.machine` + `kern.osversion`: iPad8,* + 23G71. Runtime `LabOff()` is the pin table. Do not paste T8101 VAs onto T8020. Do not bump Dopamine 3.0.10 `End` 26.0.1 → 26.6.

**Unpatched on 23G71 (run these):** 64788 LightSword until 23G82 — live detach is `0xe00002e2` NotPermitted (sandbox; abort after first, do not spin 24×); AKS 65343 until 23G83; aio84530 until 26.7/27; wvek create BRK if `len>0x210` (`FUN_fffffff009ab24c0`).

**Patched / capped (skip remaining-fire):** 64747 AVE mul FIXED; 64751 NECP flow UAF FIXED (`necp_client_add_flow FUN_fffffff009f965a8`) — P053 keeps PHASE 1 socket reach, skips PHASE 2 race; 43748 CheckandPrewire fill_cap (`FUN_fffffff008701990`, `>=0x80` → `0xe00002c2`) — P044 / p044chain SKIP 254 fire; CS hop-1 `cluster_*_contig` EINVAL 0x16 unless `UPL_PHYS_CONTIG` since 26.1 (`write FUN_fffffff009e6b2b0` / `read FUN_fffffff009e711f0`) — cscalib/cskrw SKIP.

QueueCreate A12X `0x408` / leak `+0x550`. A14 `0x410` on this iPad is `0xe00002c2`. Catalog `dopaminecompat` is an honest CPU/OS vs End=26.0.1 diagnostic (Vortex/Tempest = A12 hardware). hop-1 is already dead on 26.6.

## Open (one failed tap ≠ closed)

AVE EncType / Close-async; JPEG `+0x30` teardown; NECP add/flow dest; 64788 other reclaim; IOMD `+0x34`; lockdownd USB from a Mac.

P044 43748 (All-stages, isolate: one tap per force-quit): P032 live path is `H11ANEIn` **type=1** (type=0 `0xe00002c7` Unsupported; `AppleH11ANEInterface` not found). 23F77 DirectPath TABLE 0: DeviceOpen `stIn=stOut=0x68`, Prepare sel 4 `0x38`, Send sel 2/19 `scIn=1 stIn=0x948 stOut=0x28`. WeightBufs `{ptr, 0xA60}` / 88-byte DeviceOpen is `0xe00002c2` on this UC (v34/v35 live). Program from bundled `XVRC27_254in_1out_addchain.mlmodelc`. Open + 255 surfaces + handle + Prepare happen **before** the 3072 spray; punch n-2 then immediate send (v34 created surfaces after the punch and overflow record 192 landed in a freed neighbor). Direct uses **real IOSurface IDs** (count_gate lookup). `aio84530` is the later Arm/vtable seed, not a Direct surfaceId. If sel 2 misses, fire already-loaded CoreML (v35 skip-CoreML-if-opened was hits=0). `hasKread` only after `commitSlide`.

Live 2026-10-02 (iPhone13,2 23F77):
- P044 v34/v35: Direct sel 2 `0xe00002c2`, hits=0. v35 skipped CoreML because Direct opened.
- P044 v36: DeviceOpen `0x68` OK. Prepare sel 4 `0xe00002c2`. Bind aborted. CoreML async + `harvestKmsgs=NO` → t+0s hits=0. Regression vs P007 v18 (spray hole+victim → sync `predictionFromFeatures` → recv victims).
- LightSword v1.8 Full Chain: REPLACE_OK, blit zeros or live `0xA5` new MD, kptrs=0 after 24 attempts (empty GART / new MD, not inpcb). v1.10 aborts on first detach `0xe00002e2` **and** first GART-zero / A5-full with kptrs=0. v2.0: `0xe00002d5` is **Busy** (not ExclusiveAccess); read path is spy alias B after detaching A. Replace-on-A stays off the read path until D/lsabc proves spy keeps 0x11. Metal type 0x80 length stays `0x1000`.
- BadQuery consume `-4`. SANDBOX still the app container.
- PATCHSET HOLD. Not a jailbreak.
- v37 restores P007 fire: punch even simple kmsgs, sync XVRC27, harvest kmsgs. Direct sel 2 still tried after DeviceOpen. Live 12:49 FILL HIT simple[511]/[509]; krw SKIP (icmp6filt wrong zone).
- v38: keep even-simple punch + sync CoreML occupancy. Interleave fat type-3 OOL (`n=128` descriptors, kdata `0x824` in kalloc.3072). Do not punch OOL (v36 12:43 MAF). Recv of smashed type-3 can panic — isolate one tap per force-quit. P010 QueueCreate word1 is CommandQueue+0x558 userspace, 0 kptrs. P053 flow_add×close hits=0 (dest is NECP client).
- AKS 13:28 / 13:56 / 14:05 / 14:19: `se_ok=YES` `capture_done=0` `hook_n=0`. sel0/1 `kr=0` empty; sel2–4,6–7 `0xe00002c2` BadArgument; **sel5 `0xe00002c1` NotPrivileged**. 2c1 is privilege, not a new leak. Getting past 2c2 is in-process ACM on our AppleKeyStore conn, not a size sweep and not a 163-sel crash. AKS complements aio84530 as KASLR; it cannot replace 43748 fill.
- v39 live iPad 14:12: aio84530 heap `0xffffffe016645000`, fill_cap SKIP, `anchor=YES`.
- v39 live A14 14:21 p044chain: FILL HIT simple[509] 16-byte records; fat OOL mut=0; krw SKIP icmp6filt. Direct sel2 `0xe00002c2`, CoreML -1.
- v40: spray simples → punch evens → fat type-3 OOL **into the holes** (14:21 / 15:24 / 15:32 FILL HIT simple[509] extra; 128 fat OOL into 256 even holes; table neighbored the live odd extra). v41: simples stay live; fat type-3 **last**; punch even fat OOL. IPS 16:51/16:54/16:57 `[data.kalloc.3072] MAF` off:0 val=`0xc0<<32|surfaceId` (overflow into a **free** 3072; SpringBoard/ReportCrash/cloudd). IPS 17:39 / 17:56:30 CheckandPrewire+0x18c unslid `0x874c1fc` x20=0xc0 GZAlloc at table+0xc00 (last 3072 on a 16KB DATA page, off 0x3400). v42 punched fat OOL: 17:57:54 harvest mut=0 (live type-3 were not the neighbor); CoreML error -1 still filled. Delayed MAF 17:58:46 `[data.kalloc.16384]` accountsd and 18:08:27 `[data.kalloc.3072]` routined — punching fat type-3 frees 3072 kdata **and** 16KB OOL copies, so page-end overflow MAFs those 16384s in other processes. v43: consecutive **simple 0x820 hole + fat type-3 victim**, punch simples only. Live 18:26 harvested 68 intact fats then IOGPU mutex (255 surfaces). IPS 18:41 ReportCrash / 18:43 `ind`: 3072 MAF at **interior** slots (table page+0x400/+0x1000, neighbor FREE). v44: live simple **guard + hole + fat victim** sandwich (64 triples), punch holes only, **CoreML-only fire** (skip Direct 255-surface). Live 5/5 FILL HIT **guard extra**, fat mut=0. v45: same sandwich but **guards are fat type-3** (the proven +0xc00 neighbor); harvest `guardfat` first. Look for `guardfat MUTATED` / `FAT OOL MUTATED`. Addchain fire stays; `XVRC27_254in_passthrough.mlmodelc` is bundled HOLD (do not swap until conversion). v45 live: 21:40 mut=0; 21:44 rapportd 3072 MAF (hole-next-to-hole); 21:47 Lum1na `IPC kmsg header signature mismatch` `@ipc_kmsg.c:460` id=`0x5030B435` (our fat index 1) — type-3 recv after neighbor+0 fill is PACGA-fatal. v46: 128 consecutive simple holes, punch all, **small 1-in/1-out table first** (LIFO) then 254 addchain. `P044_SMALL_TABLE_DELAY_MS` 0 or 30000. Do not recv fat OOL. Neighbor is a second MemoryMap table.
- LightSword A14 14:18: REPLACE_OK, zeros, one A5-full new MD, jetsam ~attempt 16. A12X 14:04: detach `0xe00002e2` ×24 — v1.10 aborts on first NotPermitted and first empty blit.
- AfterKread live iPad listed `App.app/basebin.tar` then claimed missing `Resources/basebin` — lookup now includes app-root Copy Bundle Resources. A14 15:25 AfterKread staged `basebin.tar` (27 files) + Sileo/Zebra; AMFI type=0 `0xe00002e2`; HOLD (`hasKread=NO`).
- Nyxian / Procursus-Jailed is a userspace companion QA host. Do not embed. CVE-2026-86950 CoreGraphics stays parked (userspace ACE in our process is not KRW).

## Untried reach (in All stages)

- **p058** AppleJPEGDriver open (24A435 `+0x30` class)
- **p061** H264+HEVC VT sessions (84607 EncType; 23F77 AVE 905.36.1 already has EncType_Max — do not expect ABSENT)
- **p057** wvek AKS/MobileKeyBag
- **p065–p072 / ht149041 / kreadtest** P007-parity MAP/reach/oracle/census. Isolate one TAP per force-quit.
- **afterkread** constellation: AMFI UC open + 23F77 pins. Dopamine 3 / Relaxin-RootHide names (`basebin.tc`, launchdhook, systemhook, ElleKit TweakLoader). HOLD until `hasKread`

## After kread (HOLD until `commitSlide`)

Dopamine 3.0.10 BaseBin names + Relaxin/RootHide (ElleKit as CydiaSubstrate, `Relaxin.roothide` marker, `basebin.tc`, `basebin.tar`). IPA ships `Resources/basebin/` (tar + tc + licenses) and `Resources/pkgman/` (`sileo.deb` first, `zebra.deb` second). Those payload folders are Xcode folder references so `.deb` (`ar`) is not passed to `ld`. AfterKread copies/extracts into `Documents/basebin` and `Documents/pkgman` even on HOLD. Files present is inventory, not injection. Credit: opa334 / Dopamine MIT, Relaxin/ElleKit, opainject, Sileo Team, Zebra — see `Resources/basebin/CREDITS.md`. Not copied: kfd, ClearSword, physrw, Fugu14 kcall, bootstrap zst.

KRW self-test (must pass before inject): `kread32(kbase) == MH_MAGIC_64` and `kbase+0x1c` is a kernel VA. Heap leaks and blit `0xA5` fail this test.

1. `pmap_cs_allow_invalid` `*(pmap+0xca)=1`
2. AMFI UC loadTrustCache sel 2/7 of `Documents/basebin/basebin.tc`
3. trustcache `launchdhook` / `systemhook` / `dyldhook` / `watchdoghook` / `forkfix`
4. inject via `opainject 1 launchdhook` + ElleKit `TweakLoader` of `Documents/tweaks/*.dylib`
5. `dpkg -i` Sileo, then Zebra (needs Procursus `dpkg`; debs stay staged until then)
6. respring: `jbctl respring` (sbreload / `backboardd` SIGTERM)

A14 is **PPL**, not momentarius. Drop files into the app container, then re-tap **afterkread** after `hasKread`. Persist / tempRoot / boot-time auto-rejailbreak stay later (novel Lum1na, not a Dopamine copy). See All stages → After-kread plan.

Full Chain order: SANDBOX BadQuery → KERNEL LightSword → AfterKread. P044 stays All-stages. Auto chain skips P051/P053/P054. Parked All-stages: ColdForge, Rapier, p055, p058 JPEG open, p056/p061 AVE reach, Anvil open-only, P064AVE84607Racer remaining-fire, P065–P072 (invoke solo).

## Not in this repo

Full `lumina_primitives/` notebooks, P007 panic lab, GOLDMINE PoC trees. Those are local. Publishing them would duplicate remaining-fire detail that does not belong on a public README.
