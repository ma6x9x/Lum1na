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
- **Not copied:** kfd, ClearSword, physrw, Fugu14 kcall, `bootstrap_*.tar.zst`,
  momentarius / Titan.

## Relaxin 0.5.4 — RootHide / ElleKit

- Marker: `Relaxin.roothide`
- Trust cache twin: `relaxin.tc`
- ElleKit-as-CydiaSubstrate lives inside the Dopamine `basebin.tar` fallback
  (same layout Relaxin ships). `LICENSE_ElleKit.md` from the Dopamine IPA.

## opainject

- `LICENSE_opainject.md` from the Dopamine IPA.

## CVE-2026-65343 (AppleKeyStore deserialize — KASLR leak)

Discovered by **Drinor Selmanaj** (Sentry) and **Surya Narayan Kushwaha**
(Apple advisory for iOS 26.6.1 / 23G83). Impact is an OOB **read** of
adjacent kernel heap via `_LibSer_SEPControl_Deserialize` trusting
`declared_length`. That is KASLR, not KRW. Lum1na’s `aks` tap ports the
DYLD_INTERPOSE ACM-capture approach, bounded to the captured selector
(the 163-selector remaining-fire previously crashed this lab device).
