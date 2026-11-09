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
