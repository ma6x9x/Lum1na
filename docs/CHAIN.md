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

## Untried reach (in All stages)

- **p058** AppleJPEGDriver open (24A435 `+0x30` class)
- **p061** H264+HEVC VT sessions (84607 EncType; 23F77 AVE 905.36.1 already has EncType_Max — do not expect ABSENT)
- **p057** wvek AKS/MobileKeyBag
- **afterkread** constellation: AMFI UC open + 23F77 pins. Dopamine BaseBin names (`basebin.tc`, launchdhook, dyldhook, hookd). HOLD until `hasKread`

## After kread (HOLD)

AMFI loadTrustCache sel 2/7, `pmap_cs_allow_invalid` `*(pmap+0xca)=1`, then trustcache of tweak dylibs. A14 is **PPL**, not momentarius. Persist/tempRoot stay later. See All stages → After-kread plan.

## Not in this repo

Full `lumina_primitives/` notebooks, P007 panic lab, GOLDMINE PoC trees. Those are local. Publishing them would duplicate remaining-fire detail that does not belong on a public README.
