# Third-party vendored code — verbatim, credited

Lum1na vendors upstream files **unmodified** under their own licenses. Each
directory carries its upstream license/provenance; nothing here was written
by Lum1na.

## Vendor/worse_query — forcequitOS/worse_query (GPL-3.0-or-later)
- Files: `pathleak.h`, `pathleak.m`, `worse_query.h`, `worse_query.m`,
  `fallback_query.h`, `fallback_query.m` (copied verbatim from the
  worse_query sources as shipped inside git.jbjflab.top/admin/filza27.2 v27.2.0).
- Author: Taj C (forcequit), 2026. In-file GPL-3 headers preserved byte-exact.
- Used by: P164 (directory enumeration fallback when `opendir` is denied).

## Vendor/filza27.2 — git.jbjflab.top/admin/filza27.2 (lab-internal)
- Files: `MCMBridge.h`, `MCMBridge.m` (verbatim).
- Upstream lineage: forcequitOS/worse_query + 0xjohnnydev/FilzaSlop (Filza heritage);
  MHA-C2/-C12/-C13 proofs (24A5390f archive).
- License: unlicensed in the repo — **lab-internal origin on our own git
  server**, operator-authorized 2026-11-11. The GPL-credited classes used by
  Lum1na remain governed by their upstream terms.

## Dopamine (opa334/Dopamine) — MIT
- Lum1na's post-KRW ladder (libkrw-first path in `KRWBridge` / `DopamineCompa`,
  Elevate/Bootstrap order: uid0 -> unsandbox -> CS_PLATFORM -> pmap_cs -> AMFI
  trustcache -> opainject -> dpkg) follows the Dopamine design. Verbatim
  Dopamine file vendoring slot reserved; MIT terms apply when files land.
