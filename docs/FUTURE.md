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
