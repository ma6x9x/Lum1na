# CREDITS & LICENSES

Everything Lum1na borrows, with upstream, license (verified against the
GitHub API 2026-10-14), and exactly what we take. Licenses for the staged
payloads also live next to the files: `Resources/basebin/CREDITS.md`,
`Resources/basebin/LICENSE_Dopamine.md` (MIT),
`Resources/basebin/LICENSE_ElleKit.md` (© Évelyne Bélanger, BSD-style),
`Resources/basebin/LICENSE_opainject.md` (MIT).

| Upstream | License | We take |
|---|---|---|
| opa334/Dopamine | MIT | see below |
| leminlimez/Nugget | AGPL-3.0 | design reference only |
| ProcursusTeam/Procursus | 0BSD | staging pattern |
| Sileo/Sileo | BSD-4-Clause | staged `sileo.deb` |
| zbrateam/Zebra | GPL-3.0 | staged `zebra.deb` |
| ElleKit (Évelyne Bélanger) | BSD-style | inside Dopamine basebin fallback |
| opainject (opa334) | MIT | inside Dopamine basebin |

## opa334 (Lars Fröder) — Dopamine — MIT

https://github.com/opa334/Dopamine

- **libkrw plugin ABI** (`krw_initializer`, `krw_kread/kwrite/kbase`) —
  the interface our lane glue implements/consumes
  (`P007KreadLane.m` P090 pattern; `docs/TIEIN.md`).
- **libjailbreak `info.c` struct-offset ladder** (MIT, (c) Lars Fröder) —
  transcribed into the per-darwin PROC_ROW tables
  (`Kernel/Lum1naStructOffsets.m`, P007 `LabKernelOffsets.*`): proc/proc_ro/
  ucred ladder, the 24.4.0 proc_ro +0x8 shift, task_tokens 0x40→0x48→removed.
- **`dopamine_get_root` recipe** (`jbdomain_dopamine.c`): direct uid/gid
  writes on ucred cr_posix — the basis of our elevate step 4
  (`Kernel/Lum1naElevate.m`), plus the task_tokens audit_token fix from
  `proc_ucred_update_content` (`libjailbreak/src/util.c`) which we added as
  elevate step 4b.
- **Trust-ladder domain rules** (`jbdomain_systemwide/root/dopamine.c`) —
  documented in `docs/TIEIN.md`, used to design the check-in sequence.
- **Staged payload** `basebin.tar`/`basebin.tc` (Dopamine 3.0.10 IPA) —
  details and per-component credits in `Resources/basebin/CREDITS.md`.
- **Titan iorvbar intel** (A14 `0x206050000`) credited as received via the
  Dopamine tree; see `Resources/basebin/CREDITS.md` Home T7 note.

## leminlimez — Nugget — AGPL-3.0

https://github.com/leminlimez/Nugget

- Host-side SparseRestore mechanics reference only (`SysContainerDomain-../
  ..` traversal write with owner/group/mode, `concat_exploit_file` order).
- **No Nugget code is copied or distributed.** Nugget does nothing on-device
  (AMFI blocks exec of staged files) — our use is staging-order knowledge
  recorded in `docs/TIEIN.md`. If code derived from Nugget is ever shipped,
  AGPL-3.0 applies.

## ProcursusTeam — Procursus — 0BSD

https://github.com/ProcursusTeam/Procursus

- Bootstrap/dpkg staging pattern (dpkg + basebin layout, `/var/jb` prefix
  discipline) referenced by the AfterKread pipeline.

## Sileo — BSD-4-Clause

https://github.com/Sileo/Sileo — staged as `Resources/pkgman/sileo.deb`
(same .deb Dopamine ships). BSD-4-Clause keeps the UC advertising clause;
the license text rides with the package.

## Zebra — GPL-3.0

https://github.com/zbrateam/Zebra — staged as `Resources/pkgman/zebra.deb`.
Binary redistribution of the unmodified deb with this pointer satisfies
GPL-3.0 §6 for the binary; upstream source at the link above.

## ElleKit — Évelyne Bélanger — BSD-style

Shipped inside the Dopamine `basebin.tar` fallback
(`CydiaSubstrate.framework`). License staged at
`Resources/basebin/LICENSE_ElleKit.md`.

## Apple — XNU

All kernel VAs/offsets in `LabIntelTab`/`LabOff` marked GHIDRA/PROVEN are
**our own derivations** (Ghidra on the exact decrypted build, e.g. T8101
xnu-12377.122.4 for A14 26.5 — see `docs/TIEIN.md`), not copied XNU source.
XNU itself is APSL 2.0 and is not distributed here.

## DarkSword / GhostWave P7 kit — **NOT credited (hostile)**

Leaked kit; claims used only as untrusted LEAD rows, several refuted by our
Ghidra work. Policy: `docs/DARKSWORD.md`. Its name belongs in the refutation
log, not in credits.

## Lum1na original work

ClearSword (cs2) primitives, all P0xx probes, the LabOff/LabIntel tables,
Lum1naBoard, the elevate pipeline: authored in this repo
(ma6x9x/Lum1na). No exploit bodies are taken from any upstream above.
## vschko — CaseStudies write-ups (no license file)

Public write-ups (CVE-2026-84530, CVE-2026-43748, CVE-2026-65371,
CVE-2026-39868, M2Scaler diag, others): used as technical REFERENCES for
recipes and fix-version mapping. **No code copied** — all probe
implementations in this repo are ours. The repo ships no LICENSE file, so
attribution-only credit is given here. See docs/CASESTUDIES.md.
