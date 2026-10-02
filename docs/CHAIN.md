# Chain map (public)

This is not a claim of KRW. Pins are **unslid** 23F77 T8101 unless noted.

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
- P052 nstream **EFBIG 27** already on 26.5
- CVE-2026-84530 AIO `kqext_sdata` class live until **26.7/27**
- wvek: `apfs_aks_create_wvek` `0xFFFFFFF009BD96D4`; F77 `len>0x210` is **BRK**, 26.7 adds `len<=512`
- AKS UC **opens**; deserialize length sweep not implemented

## Open (one failed tap ≠ closed)

AVE EncType / Close-async; JPEG `+0x30` teardown; NECP add/flow dest; 64788 other reclaim; IOMD `+0x34`; lockdownd USB from a Mac.

P044 43748 (All-stages, isolate: one tap per force-quit): P032 live path is `H11ANEIn` **type=1** (type=0 `0xe00002c7` Unsupported; `AppleH11ANEInterface` not found). 23F77 DirectPath TABLE 0: DeviceOpen `stIn=stOut=0x68`, Prepare sel 4 `0x38`, Send sel 2/19 `scIn=1 stIn=0x948 stOut=0x28`. WeightBufs `{ptr, 0xA60}` / 88-byte DeviceOpen is `0xe00002c2` on this UC (v34/v35 live). Program from bundled `XVRC27_254in_1out_addchain.mlmodelc`. Open + 255 surfaces + handle + Prepare happen **before** the 3072 spray; punch n-2 then immediate send (v34 created surfaces after the punch and overflow record 192 landed in a freed neighbor). Direct uses **real IOSurface IDs** (count_gate lookup). `aio84530` is the later Arm/vtable seed, not a Direct surfaceId. If sel 2 misses, fire already-loaded CoreML (v35 skip-CoreML-if-opened was hits=0). `hasKread` only after `commitSlide`.

Live 2026-10-02 (iPhone13,2 23F77):
- P044 v34/v35: Direct sel 2 `0xe00002c2`, hits=0. v35 skipped CoreML because Direct opened.
- P044 v36: DeviceOpen `0x68` OK. Prepare sel 4 `0xe00002c2`. Bind aborted. CoreML async + `harvestKmsgs=NO` → t+0s hits=0. Regression vs P007 v18 (spray hole+victim → sync `predictionFromFeatures` → recv victims).
- LightSword v1.8 Full Chain: REPLACE_OK, blit zeros or live `0xA5` new MD, kptrs=0 after 24 attempts (empty GART / new MD, not inpcb).
- BadQuery consume `-4`. SANDBOX still the app container.
- PATCHSET HOLD. Not a jailbreak.
- v37 restores P007 fire: punch even simple kmsgs, sync XVRC27, harvest kmsgs. Direct sel 2 still tried after DeviceOpen.

## Untried reach (in All stages)

- **p058** AppleJPEGDriver open (24A435 `+0x30` class)
- **p061** H264+HEVC VT sessions (84607 EncType; 23F77 AVE 905.36.1 already has EncType_Max — do not expect ABSENT)
- **p057** wvek AKS/MobileKeyBag
- **afterkread** constellation: AMFI UC open + 23F77 pins. Dopamine 3 / Relaxin-RootHide names (`basebin.tc`, launchdhook, systemhook, ElleKit TweakLoader). HOLD until `hasKread`

## After kread (HOLD until `commitSlide`)

Dopamine 3.0.10 BaseBin names + Relaxin/RootHide (ElleKit as CydiaSubstrate, `Relaxin.roothide` marker, `basebin.tc`, `basebin.tar`):

1. `pmap_cs_allow_invalid` `*(pmap+0xca)=1`
2. AMFI UC loadTrustCache sel 2/7 of `Documents/basebin/basebin.tc`
3. trustcache `launchdhook` / `systemhook` / `dyldhook` / `watchdoghook` / `forkfix`
4. inject via `opainject` + ElleKit `TweakLoader` of `Documents/tweaks/*.dylib`

A14 is **PPL**, not momentarius. Drop files into the app container, then re-tap **afterkread** after `hasKread`. Persist / tempRoot / boot-time auto-rejailbreak stay later (novel Lum1na, not a Dopamine copy). See All stages → After-kread plan.

Full Chain order: SANDBOX BadQuery → KERNEL LightSword → AfterKread. P044 stays All-stages. Auto chain skips P051/P053/P054. Parked All-stages: ColdForge, Rapier, p055, p058 JPEG open, p056/p061 AVE reach, Anvil open-only.

## Not in this repo

Full `lumina_primitives/` notebooks, P007 panic lab, GOLDMINE PoC trees. Those are local. Publishing them would duplicate remaining-fire detail that does not belong on a public README.
