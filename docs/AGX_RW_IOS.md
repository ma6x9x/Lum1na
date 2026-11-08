# AGX-RW-iOS-PoC (0xjohnnydev) — integration notes

Repo: `https://github.com/0xjohnnydev/AGX-RW-iOS-PoC` — **AGPL-3.0**.
Tested only on `iPhone17,1-4` (A18 Pro) / iOS 18.6.2 (22G100). It is GFX
virtual R/W (AGX firmware), not physical memory or an SPTM bypass.

## What is in it

- `src/*` is ClearSword `pe_v3` (A18 path from kolbicz/Cyanide) plus AGX
  firmware command R/W (`agx.m`), `kmem.c` object traversal, `krw.c`, and
  `persistence.m` wrapping a vendored `libsrd.a` that parks KRW in launchd.
- AGX constants are **G17P-specific**: vtables `0xfffffff007c4…`, firmware
  `0xfffffc0000…`, `STATIC_RIPCBINFO 0xfffffff00ae6a790`. None of these apply
  to G13/G16/G11 (our A13/A14/T8150/A12X); a port needs per-SoC RE.

## What we integrated (22G100 offsets, proven on the same Darwin 24.6)

The iPhone 11 is also 18.6.2 / 22G100, so these struct offsets transfer:

```text
inpcb.inp_socket              0x40
socket.so_background_thread   0x2B0
thread.t_ro                   0x3F0
thread_ro.proc                0x18
proc_ro.task                  0x8
task.map                      0x28
vm_map.pmap                   0x40
```

- `Kernel/Lum1naStructOffsets`: the A13_22G100 row now carries this ladder.
- `ClearSword` `spray_socket` wraps socket() in
  `pthread_set_qos_class_self_np(BACKGROUND/USER_INITIATED)` so
  `so_background_thread` points at the tap thread (the repo's trick).
- `Lum1naFindSelfProcViaSocket` (`Kernel/Lum1naProcFind`): pcb → socket →
  so_background_thread → thread_ro → proc, with a safe XPACI-only-if-needed
  strip. Elevate tries this first when the CS2 lane is live, then the
  `mach_port_kobject` fallback.
- Elevate now prints a read-only `proc_ro → task → map → pmap` receipt; no
  pmap write yet.

## What is not ported

- **AGX firmware R/W** itself: requires the G13/G16/G11 vtables, firmware
  VA ranges, `ripcbinfo` static address, and DropMDSID/command-ring profiles.
  The code is structured per-target, so adding a SoC is a profile + RE task.
- **`libsrd.a` launchd KRW persistence**: the core is a binary vendor lib
  (unknown license). The design is: transfer the control/rw socket fds to a
  launchd-injected helper (SCM_RIGHTS or fileport) and keep a relay thread
  alive; the app reconnects after a crash/relaunch. Our own version would
  need a `KRWRelay.dylib` + opainject into launchd + a socket protocol.
- **pe_v3**: the A18 reoccupation path. The 22G100 A13/A14 lane is the OG
  EFAULT `pe_v1` we already run; pe_v3 is not needed unless the OG lane fails.

## License

The repo is AGPL-3.0. We copied **offset facts and the traversal method**,
not code, and did not vendor `libsrd.a`. If any AGPL source is ever copied
into Lum1na, the app distribution must comply with AGPL-3.0.
