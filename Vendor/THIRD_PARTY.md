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

## Build note (Vendor/, Lum1na target)
Everything under `Vendor/` is compiled/bundled by the Lum1na target. Keep
file basenames unique inside the tree — the synchronized root copies
non-source files into the app bundle and Xcode fails on duplicate output
names (the two CMakeLists.txt and two README.md were removed for this).

## Vendor/darksword provenance notes
- `kpf/` (patchfinder) was NOT vendored: it imports opa334/xpf (MIT) which
  itself needs ChOma + img4lib — three more trees for a module the Lum1na
  chain never calls. The vendored kexploit/ is self-contained. Vendor xpf
  + ChOma when a patchfinder integration actually lands.
- Entry point: `int kexploit_opa334(void)`; on success `g_kernel_base`/
  `g_kernel_slide` are live and krw/m (`kreadbuf/kwritebuf/kread64/...`)
  works on the phys lane; `kutils`: proc_self/proc_find(_by_name).
- The socket lane matches ClearSword/CS2 (inpcb/icmp6filt/ipi_zone/
  so_usecount); offsets.m derives per-train values by hex-pattern search
  for iOS 17.x–26.x, includes the 26.x kbase magic `0xCC0000002`, receipt
  on iPhone14,6 iOS 26.0.
- Lum1na integration (our code): `Exploit/DarkswordBridge.{h,m}` externs +
  `Kernel/Lum1naDarkswordLane.{h,m}` lane (cascade slot 4). Slide is
  recomputed against OUR LabStaticBase — the vendored g_kernel_slide
  subtracts only the A14 link base.

## External reference pulls (Vendor/external — NOT built into the app)

- **brotli-111497** (`MchinaMd57764/CVE-2026-111497-PoC`, MIT): Brotli
  BlockSwitch OOB-write trigger generator + decode harness (userspace
  libcompression/CFNetwork layer; vulnerable on 24A446/24B119/24C5037i,
  patched 27.2.1/24B156 — our 24A435 and 23F77 trains predate the fix;
  verify per-firmware before relying on it). Userspace primitive only.
- **henge-jit** (`ammaarreshi/WindowsiOS`, GPL-2.0-or-later, adapted from
  `Leviidev/Henge` + `Leviidev/Husk`; StikDebug/StikJIT lineage):
  dual-mapped RX/RW JIT substrate for iOS 17–27 including 26/27 TXM
  (`winios_jit.c`), and the `henge-jit.js` page-blessing protocol notes.
  Value: executable memory without a jailbreak (CS_DEBUGGED ledger-exempt
  path) — payload staging / post-KRW codegen candidate.
- **terminal-worse** (`git.jbjflab.top/admin/terminal_worse`, GPL-3.0;
  a-Shell BSD-2, worse_query GPL-3 by Taj C/forcequitOS, badshell,
  pathleak): full a-Shell 2.3.2 + worse_query integration tested on
  24A446/27.0.1 (`TerminalSBX.m`) — reference for our terminal lane.
