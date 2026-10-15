# Device matrix — Beta 1 lanes per device (2026-10-15)

Rule: the app detects `hw.machine` + `kern.osversion` (never UIDevice
marketing strings) and picks lanes from this table. `hasKread` is per-SKU
honest — it flips only on a passing magic self-test on THAT device.

| Device | SKU / build | KRW lane | State | Beta-1 path |
|---|---|---|---|---|
| iPhone 11 | iPhone12,1 A13 / 22G100 (18.6.2) | cs2core (ClearSword core, Dopamine 3.0.11 verbatim); libkrw when Dopamine is active | **KRW PASS** (2026-10-15 12:00, kslide 0x12f30000) | P094 (Path 2 ungated 10-15 via cs2core bulk lane) → kernproc-proven row → PATCHSET: elevate uid0 → unsandbox → CS_PLATFORM → pmap_cs → AMFI TC → opainject launchdhook → Sileo → Zebra → respring |
| iPhone 12 mini | iPhone13,1 A14 / 17.3 | cs2core (proven) | KRW YES | Same PATCHSET pipeline; struct rows for 17.3 need the per-SKU Ghidra pass if P094 Path 2 misses (no scan delta pinned yet) |
| iPhone 12 | iPhone13,2 A14 / 23F77 (26.5 GM) | none yet | **hasKread=NO** | Four live doors (docs/CASESTUDIES.md): p063 84530 heap leak (LIVE-PROVEN), P099 43748 groomed write-door candidate, P097 65371 gRegistryRoot leak, P098 M2Scaler diag. hasKread stays NO until a door yields `kread32(kbase)==0xfeedfacf` |

## Vendored jailbreak stack (what fires after hasKread)

- **Dopamine 3.0.10/3.0.11** (opa334, MIT): basebin.tc v1, jbctl,
  launchdhook/systemhook/watchdoghook/dyldhook/forkfix dylibs, hookd,
  opainject, libjailbreak.dylib, TweakLoader + **ElleKit**
  (Relaxin-RootHide build), CydiaSubstrate. Staged to Documents/basebin
  by the PATCHSET stage; `dpkg -i` Sileo then Zebra (Dopamine order).
- **Relaxin / ElleKit** (RootHide/Évelyne Bélanger, BSD-style): tweak
  injection substrate consumed by launchdhook after opainject.
- **Procursus** (0BSD): dpkg/apt userland installed post-elevate.
- **Nugget (misakaX family)**: NOT in the 26.5 path — SparseRestore was
  patched in 26.2 betas; Nugget remains a feature-flag tool for the
  jb'd rigs (17.3/18.6.2), not a jailbreak door. Honest: it adds nothing
  to KRW on any device here.
- **AltDaemon** (rig-only): keeps the IPA signed on jailbroken devices.
- **Nyxian** (stock devices): jailed on-device iteration + signing
  keep-alive; distribution option, not an exploit lane.

## What "complete" means per device (honest bar)

1. **iPhone 11 (rig)**: one P094 tap → one PATCHSET run → post-respring
   jbroot evidence (jbroot dpkg + Sileo/Zebra present). That is the first
   full end-to-end Beta-1 completion. Remaining code work: none known —
   the 10-15 FIRE held only on kernproc-underived, and P094 Path 2 now
   has a bulk lane.
2. **12 mini**: same pipeline once P094 proves kernproc (scan delta for
   17.3 unpinned — Path 3 LEADs + Ghidra pass as fallback).
3. **iPhone 12 26.5**: the long pole. Order of work: P099 victim-diff
   detection → shape the adjacent kalloc.3072 chunk with a known object →
   steer a corrupted field → first kread32(kbase) → then the same
   PATCHSET pipeline as the rig. P046 pins and the CASESTUDIES chain
   plan govern; JAILBREAK never auto-invokes P099.

## Honesty

- hasKread/hasKwrite are per-device flags. Rig YES does not imply hunt YES.
- "Files present ≠ injection" — PATCHSET reports JAILBROKEN only on real
  post-respring evidence (AGENTS.md UI contract).
- P099 is STANDALONE ONLY (real OOB; never in the JAILBREAK chain).
