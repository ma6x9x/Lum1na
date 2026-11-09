# Sandbox / IOSurface adjacency repos (2026-11-08)

Three new repos reviewed statically; none is a kernel R/W primitive.

## Rust505/iosurface-adjacent-oob (SurfHeist, MIT)

- Creates 50 16 KB IOSurfaces, finds a pair with `base[i+1]-base[i] == 0x4000`
  and no guard page, then writes past surface A into surface B and reads past
  surface B.
- The OOB write is **user-VA adjacency between two app-owned surfaces**, not a
  kernel write. The "kernel heap-like" read is unverified on stock iOS and was
  observed only in a `newjail` environment.
- Integrated as **p159** (read-only): adjacency discovery + a bounded read of
  the window past surface B; counts kernel-pointer-like and poison-like
  qwords. No OOB writes.

## sasobhabha/Gester (KAMUI, MIT)

- Partial **sandbox escape** using MCM `container_query`:
  - class 13 + `partDomain` traversal (works on 27.0.x, patched on 27.2);
  - class 7 app-group part-directory symlink (27.2, needs an app group);
  - class 2 staged/subpath symlink (no app group; may kill the app).
- Gives a sandbox extension for a chosen MCM container path (MobileGestalt,
  SystemGroup, app data, PosterBoard), not root and not kernel.
- Integrated as **p160** (read-only): loads the MCM client, tries the class-13
  traversal against the kernelcache, `/var/jb`, MG cache, app-data and
  InternalDaemon roots, and reports token/open results. No file is modified.
  A kernelcache dump to Documents is opt-in via
  `Documents/lum1na_dump_kernelcache`.

## forcequitOS/worse_query (GPLv3)

- Sandbox escape for iOS 26.0–26.7.2 / 27.2; accesses app/system containers and
  system-group paths. It explicitly says it is not relevant to a jailbreak.
- GPLv3: **do not copy** into Lum1na. The p160 probe reimplements the documented
  MCM query technique from KAMUI (MIT), not worse_query code.
- `pathleak` (fsgetpath inode brute force) is a path-enumeration helper; useful
  only after a token exists.

## Why this could matter

- If p160's class-13 traversal works on the 17 (27.0) / 12 (26.5) / iPad
  (26.7.1), it gives **read access to the kernelcache** without KRW — exact
  offsets for Ghidra — and read access to SystemGroup/MobileGestalt
  containers. It does not give kernel read/write.
- p159 tests whether the IOSurface adjacency is real on stock; if it is, it
  is a surface-layout/heap-disclosure tool, not a KRW primitive.

## First device receipts (2026-11-08)

### p159 IOSurface adjacency
- **12 / 23F77**: adjacency real (idx=1, delta 0x4000). The read window is
  mapped (no fault), 194 non-zero qwords, 36 values whose top bits are 0xffff
  — but they are **tags/tagged pointers** (`0xffffffa6…`, `0xffffe6a9…`,
  `0xffffffdc0a…`), below the XNU zone map. Refined classifier treats them as
  non-kernel. No kernel-heap leak.
- **17 / 24A435**: adjacency real (idx=3). 679 non-zero, 226 top-0xffff values
  (`0xffffe383…`, `0xfffffffffe900600`, `0xfffffffff46e0100`) — again outside
  the canonical kernel ranges. No kernel-heap leak.
- Verdict: SurfHeist adjacency is real on stock, but the OOB window is mapped
  **user VA**; the OOB write is surface A → surface B. It is not a kernel
  primitive on these devices.

### p160 MCM class-13 traversal
- **12 / 23F77**: MCM loads. `kernelcache` and `/var/jb` return posix=1
  (EPERM); MG cache posix=2 (ENOENT); app-data and InternalDaemon roots return
  the **raw traversal path** but `handle=-5` (no token) and `open=0`.
- **17 / 24A435**: no result and no token for any target (posix=0).
- Verdict: class-13 is not issuing a sandbox extension on either device.
  `p160` now also tries the class-2 staged/subpath-symlink variants (no
  app-group required); re-tap is needed.

### p160 class-2 results + parent fallback (2026-11-08 23:21)

- **12 / 23F77**: class-2 staged and subpath both `posix=2 (ENOENT)`. The
  subpath query had a domain bug (`leaf` instead of `leaf_link`), fixed in
  `0fb526a`.
- **17 / 24A435**: class-2 `posix=0`, no result and no token.
- No token = no sandbox extension. `obj=…` on the 12 app-data rows is the raw
  traversal path, not a resolved container path.
- Added the **class-2 parent fallback** (KAMUI): opt-in via
  `Documents/lum1na_class2_parent`. It moves `Library` aside, symlinks
  `Library/Caches` to the target, queries class 2 part 3 with an empty domain,
  then restores. A guard file (`lum1na_class2_parent_guard`) is written first;
  if the app is killed mid-move, the next launch restores `Library.p160bak`, so
  repeated taps cannot loop.
- Moving `Library` can kill the app on some builds: one tap, fresh boot, and
  check the log before the next tap.

### Entitlement reality (why Sideloadly cannot just grant these)

- `container_query` **class 7** (app group) needs a **provisioned app group**
  in the code signature. `com.apple.security.application-groups` in this app
  is currently an **integer** (`1`, from the p117 experiment), not an array,
  so class 7 is unavailable even before provisioning.
- Sideloadly/AltStore sign with a **development certificate + provisioning
  profile**. AMFI honors only the entitlements listed in that profile; a free
  profile cannot provision an app group (paid-account capability). Private
  entitlements (`platform-application`, `no-sandbox`, `task_for_pid-allow`)
  are stripped or rejected.
- `ldid`/AppSync/TrollStore can embed arbitrary entitlements, but on stock iOS
  AMFI rejects private/platform ones — they work only on a jailbroken device
  with AMFI relaxed/trustcache, or with a platform-signed binary. This is why
  the app's `platform-application`/`no-sandbox` set only takes effect on the
  Dopamine-jailed 11/mini under ldid.
- Therefore class-7 is a **paid-account or jailbroken-device** path, not a
  free-sideload path. The class-2 parent fallback is the only no-entitlement
  variant, and it is now testable.
