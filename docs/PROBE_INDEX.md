# Probe number index (P150–P169)

Numbers are **reserved by design**, not allocated sequentially. A number is
added to the app only when its trigger/selector/shape is mapped and its
safety class is known; a reserved number may stay unbuilt for months. Do not
add a placeholder tap that does nothing.

| # | Lane | State |
|---|---|---|
| P150 | ANE user-client reach (H11ANEIn / H16) | implemented, invoked by other probes |
| P151 | ANE DeviceOpen census | implemented, invoked by other probes |
| P152 | IOSurface foreign lookup gate | implemented, invoked by other probes |
| P153 | ANE selector/class probe | implemented, invoked by other probes |
| **P154** | **IOSurface notification-listener ready-byte race (CVE-2026-112477)** | **reserved — mapped 2026-11-09, not built.** 23F77 add `0x986ba54`, remove `0x986bb98`, teardown `0x986e1fc`; 27.2 `+0xf1` gate `0x9be5210` / mark `0x9be5494`. Needs a PANIC-POSSIBLE race runner (sel 0x11 + `IOServiceClose`). Primitive is DoS/type-confusion + second-order lck_mtx UAF on 23F77. |
| **P155** | **iPad A12X read/corrupt candidate** | **reserved, not built** — needs the 23H30/26.7.1 A12X offset table and a mapped primitive; p017 is FORBIDDEN on the iPad. |
| P156 | symbol-free self-proc locator | implemented |
| P157 | AVE2 writer reach + type sweep | implemented (v2, SKU-aware selectors) |
| **P158** | **AVE2 Prepare blob fill (gates/SPS/fill)** | **reserved, not built** — the direct AVE2 UC is `0xe00002e2` on stock; build only if the p157 type sweep 0–5 opens a type. |
| P159 | IOSurface user-VA adjacency | implemented; user-VA only, not KRW |
| P160 | worse_query/class-7 sandbox escape + pathleak | implemented; absorbed the pathleak helper |
| **P161** | **AppleSEPKeyStore test-UC type sweep** | **implemented v2** — `P161SEPKeyStoreTestUC`, log `p161_sepks_testuc_log.txt`. v1 on the 17/24A435 opened types **0–23 all OK**, every child `AppleKeyStoreUserClient`, no Test class; v1 stopped at the 24-open cap and hid children past the first 16. v2 tests **0–32** and diffs child registry-entry IDs before/after each open, logging `connClass` and only the new children. No selectors, no writes. PANIC-POSSIBLE — one tap per force-quit. |
| P162 | IOHID user-client reach (CVE-2026-112515 lane) | implemented; CVE closed as internal OOB read |
| **P163** | **Descriptor-Port Confusion (DPC) translation oracle** | **implemented v1; userland forge NEGATIVE** — `P163DescOOLOracle`, log `p163_desc_ool_log.txt`. 17/24A435 (2026-11-09): control sends/recvs 16 port descs (type=0); every forge case sends/recvs 0 but the received descriptor is normalized to `name=0, type=0, disp=0` — the userland type word is validated/normalized and never reaches the OOL copy engine. The DPC still needs a kernel write to the kernel-resident descriptor (p073 record smash or a kw provider). PANIC-POSSIBLE — one tap per force-quit. |

## Why gaps exist

- **P154** was named in `docs/IPSW_DIFFS.md` when the 27.2 IOSurface diff
  first showed the ready-byte guard. The vulnerable insert function and its
  selector were not mapped until the 2026-11-09 23F77 diff (add/remove/
  teardown + selectors 0x11/0x12), so a blind race probe was not written.
  It is now buildable.
- **P155** is the iPad's read/corrupt lane; it cannot be written until the
  23H30/26.7.1 A12X cache is mapped and the `A12X_23G71` table is replaced.
- **P158** was the AVE2 blob-fill idea. The gates/SPS/fill fields are mapped,
  but the direct UC never opens on stock devices; the VT path clamps the
  dangerous fields. Build only on a type-open receipt.
- **P161/P163** were never allocated. P161 is now the AppleSEPKeyStore
  test-UC type sweep (closed after v2: 33/33 types flat). P163 is the DPC
  translation oracle (userland forge normalized to a null port; needs a
  kernel-resident type smash). The Scaler idea under P163 stays closed for
  23F77 (histogram self-test, not the 27.2 queue code); the 27.0 sel8 read
  is p114.
- **P084 v7 is closed on the fleet.** 12/23F77 (2026-11-09): the D2
  2,048-surface IOSurface spray found `signature_surfaces=0` and
  `weak_surfaces=0`; C3 0/0 and the 60s watch 0. The free/reclaim did not
  occur on A14. T8150 is structurally dead (SPTM `cpt_mapcnt` has no silent
  u16 wrap). Do not spend more boots on the pmap-tte lane.
- **P073 desc-smash on the 12 is a type-forge bar, not a kread.** The fill
  record sets the desc `{type=1, disp=0}`, but the OOL address is
  `sid | (flags<<32)` and the 43748 `flags` is the record index (6..15), so
  it is a user VA; the port pointer is overwritten. p073 v9's
  `vmread(addr)` is a userland read and a mapped user page can fake
  `kernelRange=YES`. Next: scan the received message body, and find either
  a user-controlled +4 u32 (kernel high half) or a 4/8-byte type-only write
  at `desc+8` that preserves `desc+0..7`. Design: `docs/KRW_THEORY.md` §2.1.
- **P116 v2 (TOCTOU) is the pre-KRW daemon-deputy enabler.** Path read,
  directory listing, and a read-write probe restricted to `/var/mobile`
  (default `/var/mobile/Library/Caches/p116_rw_probe.txt`);
  `Documents/p116_path.txt`, `p116_dir.txt`, `p116_rw_path.txt`. Tokens are
  never logged. It is a deterministic **userland** sandbox escape, not uid0
  and not kread32. Theory D (P116 rw -> privileged daemon cache -> AVE2/ANE
  entitlement) is in `docs/KRW_THEORY.md` §10.
- P150–P153 exist in `LuminaTAP.swift` but are invoked by other probes rather
  than as TapDirectory rows; the visible tap list only shows wired rows.
