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
- PATH B 43748 kalloc.3072 conversion is sealed on 23F77 (type-1 payload-only, type-3 PACGA, second ANE table ephemeral). KRW TEST is PATH A LightSword v2.1 spy.

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
