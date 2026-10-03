# Third-party BaseBin payloads (credit)

Lum1na stages these files for the first post-KRW tweak-injection slot
(`Kernel/Lum1naAfterKread`). They are **not** a jailbreak on A14 23F77 by
themselves. AMFI UserClient loadTrustCache sel 2/7 and
`pmap_cs_allow_invalid` stay compiled and unfired until
`Lum1naBoard.hasKread` after `commitSlide`.

Do not treat dropping these files as proof of injection.

## Dopamine 3.0.10 — opa334 (Lars Fröder)

- Upstream: https://github.com/opa334/Dopamine
- License: MIT (`LICENSE_Dopamine.md`)
- IPA payload used here: `basebin.tar`, `basebin.tc`
- Names AfterKread consumes after extract: `launchdhook.dylib`,
  `systemhook.dylib`, `dyldhook`, `watchdoghook.dylib`, `forkfix.dylib`,
  `opainject`, `libjailbreak.dylib`, `jbctl`, `hookd`, ElleKit shipped as
  `fallback/CydiaSubstrate.framework/CydiaSubstrate`
- Covers iOS 26.0–26.0.1 on A12/A13. Does not run on A14 23F77 by bumping
  End versions.
- **Copied (contract only):** `Exploit/DopaminePrimitives.h` — `gPrimitives`
  vtable from `BaseBin/libjailbreak/src/primitives_external.h` (kreadbuf /
  kwritebuf / kcall / kmap). No exploit body.
- Home T5 PAC / T6 PPL dump the after-kread order from `DOJailbreaker.m`
  (PAC badRecovery → PPL Titan/momentarius/dmaFail → physrw_pte → uid0 →
  trustcache → opainject). T6 runs `Lum1naAfterKread` which still HOLDs
  AMFI/opainject until `hasKread`.
- Home T7 PHYS MAP credits Titan `iorvbar = 0x206050000` (A14) and walks
  IOKit registry / read-only `IOConnectMapMemory`. Titan GPU ROP / PTE
  write is not copied. IOMD `dmaCommandOperation +0x34` is logged, unfired.
- **Not copied:** kfd, ClearSword, physrw, Fugu14 kcall, `bootstrap_*.tar.zst`,
  momentarius / Titan / dmaFail / multicast_bytecopy / weightBufs bodies.

## Relaxin 0.5.4 — RootHide / ElleKit

- Marker: `Relaxin.roothide`
- Trust cache twin: `relaxin.tc`
- ElleKit-as-CydiaSubstrate lives inside the Dopamine `basebin.tar` fallback
  (same layout Relaxin ships). `LICENSE_ElleKit.md` from the Dopamine IPA.

## opainject

- `LICENSE_opainject.md` from the Dopamine IPA.

## Sileo (first package manager)

- Deb: `Resources/pkgman/sileo.deb` (from the Dopamine 3.0.10 IPA).
- License: `Resources/pkgman/LICENSE_Sileo.md` (Sileo Team).
- AfterKread stages it to `Documents/pkgman/sileo.deb`. `dpkg -i` waits for
  KRW self-test + Procursus `dpkg`. Files present ≠ Sileo running.

## Zebra (second package manager)

- Deb: `Resources/pkgman/zebra.deb` (from the Dopamine 3.0.10 IPA).
- License: `Resources/pkgman/LICENSE_Zebra.md` (GPL-3).
- Same staging / same dpkg gate as Sileo. Sileo is installed first.

## CVE-2026-65343 (AppleKeyStore deserialize — KASLR leak)

Discovered by **Drinor Selmanaj** (Sentry) and **Surya Narayan Kushwaha**
(Apple advisory for iOS 26.6.1 / 23G83). Impact is an OOB **read** of
adjacent kernel heap via `_LibSer_SEPControl_Deserialize` trusting
`declared_length`. That is KASLR, not KRW. Lum1na’s `aks` tap ports the
DYLD_INTERPOSE ACM-capture approach, bounded to the captured selector
(the 163-selector remaining-fire previously crashed this lab device).
