# Lum1na jailbreak port (Dopamine-derived, different chain)

Status: **wired, unverified on device**. The 2026-11-01/02 iPhone 11 panics
were decoded; the ClearSword deviations that could mis-target are reverted,
and the post-KRW chain now locates our `proc` without `allproc`/`kernproc`.

## Chain (our app, no Dopamine daemon)

```
1. ClearSword KRW          Exploit/ClearSwordCore (Dopamine 3.0.12 bodies)
                           gate: viability train + ONE attempt per boot
2. self-proc locate        Kernel/Lum1naProcFind.m
                           mach_port_kobject(task_self) -> task_t
                           scan task for bsd_info (pid + proc_ro validate)
                           NO allproc, NO kernproc, NO XPF
3. elevate                 Kernel/Lum1naElevate.m (existing, now unblocked)
                           uid/gid 0, audit token, label unsandbox,
                           CS_PLATFORM_BINARY, verified with getuid/csops
4. jbroot install          Kernel/Lum1naAfterKread.m ak_installJbroot()
                           /var/jb/basebin/* from Resources/basebin/basebin.tar
5. trustcache              AMFI UC selectors 2/7 (existing ak_openAMFI path)
6. inject                  opainject 1 launchdhook.dylib (from /var/jb/basebin)
7. pkgman / respring       dpkg -i sileo/zebra; jbctl respring (+ LUM1NA plate)
```

## What is copied from Dopamine (MIT / Dopamine license)

- `Exploit/ClearSwordCore/*`: ClearSword exploit bodies (Dopamine 3.0.12).
  Lab bridge only: `cs2_log`, LabOff-driven `socket.usecount`/`staticBase`/
  `socket.proto`, deadline, one-tap gate.
- `Kernel/Lum1naStructOffsets.m`: proc/proc_ro/ucred/task ladder values from
  `libjailbreak/src/info.c` (darwin 23.1–23.3 and 24.4+ branches).
- Elevate semantics (uid fields, audit token, `mac_label_set` slot+1, csops
  verify) from Dopamine `libjailbreak/src/kernel.c` / `DOJailbreaker`.
- `/var/jb/basebin` layout from Dopamine's rootless basebin.

## What is deliberately different (novel)

- No `ksymbol(allproc)` and no XPF. The task kobject gives `task_t`; the
  `bsd_info` scan gives `proc_t`. This works without a patchfinder and without
  the kernelcache symbol table.
- No `jbserver`/`launchdhook` root daemon for elevate. Kernel writes happen
  in-process with the live ClearSword/libkrw lane.
- Trustcache goes through the AMFI user client (selectors 2/7) instead of
  editing the PPL trustcache linked list (which needs `ppl_trust_cache_rt`).
- Respring logo is an in-app plate (UI/RespringSplash.swift) with a 1.5 s
  pre-respring hold; a SpringBoard dylib is only needed for a system-wide
  overlay after injection lands.

## Gaps / honesty

- **Procursus bootstrap is not in the repo.** `basebin.tar` is the basebin
  only (jbctl/opainject/launchdhook/ElleKit), not dpkg/shells. `dpkg -i` will
  HOLD until a Procursus bootstrap payload is staged. `Resources/pkgman` has
  the Sileo/Zebra debs, not the bootstrap.
- AMFI selectors 2/7 are proven on 23F77 and assumed kext-global for A13
  18.6.2 / A14 17.3. A refusal is logged, never silent.
- `pmap_cs_allow_off` stays 0 on the rigs, so the fire logs the pmap poke as
  SKIPPED; the trustcache path is the intended code-validity route.
- One-tap guard is per app container. Lum1na and Lum1na-Debug cannot see
  each other's attempt; do not run both KERNEL taps in one boot.
- `mach_port_kobject` can be refused on hardened ports. If so, elevate HOLDs
  with the locator reason; P094/kernproc remains the fallback.

## iPhone 11 panic decode (2026-11-01/02, 18.6.2 22G100)

- Device is **18.6.2 / 22G100**, not 18.7.1 (BuildVersion read over USB).
- `panic-full-2026-11-01-224302` and `-11-02-182738`: unexpected fault in
  kernel static region, panicked task `P007OpenOnly`, pc (unslid)
  `0xfffffff0070158d0` — execution reached non-exec text.
- `panic-full-2026-11-02-185702`: `zone bound checks ... length 32 overflows
  object ... size 984 in zone [socket]`, panicked task `Lum1na`.
- All three share the same unslid CS2/socket backtrace. The 2026-10-24
  gencnt self-calibration is the likely mis-target: a wrong `socket_pcb_ids`
  entry can make `find_and_corrupt` accept a different inpcb. Reverted to
  Dopamine's fixed blob+0x110. Also restored multi-pass retry and added the
  per-boot one-tap gate.

## Test receipts added for the next build

- `P156ProcLocate` (debug app, tap `p156`): calls `mach_port_kobject` on the
  task and thread ports, logs type/kaddr, and when a KRW lane is live scans
  the task struct for `bsd_info` (pid + proc_ro validate). This is the
  standalone receipt for the symbol-free locator before running Full Chain.
- `p153` (24A435): table-driven sizes — send `0xc50`/out `0x40`, create
  struct `0x28`, map `0x828`, stale-service retry, knob source. Use
  `p153_force=1` + `p153_map=1`/`p153_create=1`/`p153_send=1` on a fresh
  boot; DeviceOpen 0x88 success is the receipt, not KRW.
- `Resources/tweaks/src/RespringLogo.m` + `build.sh`: SpringBoard post-respring
  LUM1NA plate. Build with full Xcode (`-arch arm64e`, ldid), drop the dylib
  in `Documents/tweaks`; it is inert until TweakLoader injects it.
- `UIFileSharingEnabled` on the main app: `afcclient --documents
  com.ma6x9x.Lum1na.<team>` can pull Documents logs after reinstall.
