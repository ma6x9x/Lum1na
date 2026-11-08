# External research triage (2026-11-08)

Sources reviewed statically (not executed):

- `0xjohnnydev/AGX-RW-macOS-PoC` — AGX firmware R/W on macOS 27.0.1
  (26A434), M4/M5. **No LICENSE file.** Read-only reference.
- `dawgyg/AppleResearch` — raw macOS research dump: fuzzers and ~100
  submission packages. **No LICENSE file.** Read-only reference; do not
  vendor their code without permission.

## Highest-value finding: AppleAVE2 signed writer underwrite

The macOS report
`submission_packages/_PENDING_APPLEAVE2_HEVC_SIGNED_COUNT_LIST_TAIL_WRITE_26A5421a_20260827.zip`
describes an unprivileged `AppleAVE2Driver` selector-5 `Start` HEVC SPS
bit-count underwrite. The writer checks `index < capacity` but not
`index >= 0`; a negative signed index reaches before the writer buffer. The
forged embedded command list is then consumed by selector-7 `Process` →
command 8 → `_AVE_DLList_PushBack`, which only NULL-checks head/tail and does
`str x1,[x8]` — an eight-byte store to an attacker-selected kernel address
(value = a valid kernel command node).

Static confirmation on the iOS/iPadOS binaries (capstone, 2026-11-08):

| Build | Signed writer underwrite | PushBack `str x1,[x8]` |
|---|---|---|
| 21D50 (17.3, A14 mini) | present (9 signed `strb` sites) | not matched (older layout) |
| 22G100 (18.6.2, A13) | present (9) | not matched |
| 23F77 (26.5, A14) | present (9) | **present** (`0xfffffff0081f3520`) |
| 24A435 (27.0, T8150) | **writer clamped** (`cmp/csel lt`) | present |
| 24B119 (27.2, A14) | **writer clamped** (`cmp/csel lt` before `asr`) | **present** (`0xfffffff0083bd224`) |
| iPad 23H24 (26.7) | present (9) | present |
| iPad 23H128 (26.7.2) | present (9) | present |

The count-add site is present on 26.5 (`ldr w8,[x20,#0x1f8]; add w2,w8,#4;
bl WriteU`) and on 27.0/27.2 (`[x20,#0x1f4]`). Both 27.x writers clamp the
negative position, so the underwrite is fixed there; the PushBack sink is
still unfixed. **The 26.5 A14 build is the best port target: writer and sink
both present, and it is the main 12 rig.**

This is the first app-reachable write primitive found that is independent of
the CS2 socket race. It is **not yet a working iOS write**: the macOS request
geometry (client+0x280 list, client+0x2648 writer buffer, request +0x487c →
SPS +0x1f4, 0x12c18 selector-5 input) must be re-derived for each iOS build.

## Added probe

`P157AVEWriterReach` (debug tap `p157`): opens `AppleAVE2Driver` type 1 and
walks the macOS selector chain with **zeroed** buffers. Default is
`Open` only; `p157_prepare=1`, `p157_config=1`, `p157_start=1`,
`p157_process=1` step through the rest. Start writes a **nonnegative** count
(`p157_count` default 0 → +4), so it is a reach test, not the underwrite.
All of Prepare/Config/Start/Process are PANIC-POSSIBLE; one tap per boot.

## Other AppleResearch items worth porting (not yet integrated)

- `_PENDING_APPLEJPEG_OOB` / `applejpeg_oob_20260614` — JPEG decode OOB
  (iOS p027 already exercises AppleJPEG).
- `applemultitouch_reporter_uaf_26A5421a_*` — IOHID/multitouch reporter UAF
  (iOS reachable via IOKit; pairs with the 112515 diff).
- `io80211_anqp_nai_realm_oob_read_CONFIRMED` — Wi-Fi ANQP parser OOB read
  (iOS IO80211 present; fuzzer source in `fuzzers/io80211`).
- `_PENDING_cfnetwork_ftp_shortline_oob` — CFNetwork parser OOB (iOS
  CFNetwork present).
- APFS keybag / btree compact / xattr UAF packages — APFS exists on iOS;
  reachability from an app needs a disk-image or container path.
- `_PENDING_nfs_kauth_acl_inherit_toctou`, NFS rpcsecgss UAF — NFS client is
  present but mounts are restricted on iOS.
- `_PENDING_APPLEUSBSERIAL_SEL1_*` — USB serial UC; iOS needs an external
  accessory session.
- AppleRAID / UDF / HFS / exFAT / CD9660 / DiskImages2 OOBs — iOS can mount
  some disk images via private DiskImages2; lower priority.
- Fuzzers `fuzzers/opack`, `cfnetwork_pac`, `iokit`, `caf`, `nfs`, `kflag`,
  `io80211` — source is macOS-shaped; useful as input corpora, not
  drop-in iOS probes.

## AGX-RW (macOS) assessment

The AGX PoC is MacBook Neo-only for the DropMDSID write/auth-call/PAC-reuse
modes; read is profiled for M4/M5. The README explicitly says it is GFX
virtual R/W, not standalone KRW or an SPTM bypass. No matching primitive was
found on M2/M3/M4 base. There is **no evidence** the same DropMDSID path
exists in the iOS AGX firmware for T8150/T8027; porting would first require
matching the AGX firmware command path on the iOS kext, so this stays
reference-only for now.

## Ghidra static proof (23F77, 26.5, A14)

`WriteBits` at `0xfffffff00835bc60` decompiles to:

```c
iVar1 = *(int *)(writer + 0xc);              /* signed bit/byte position */
if (*(int *)(writer + 0x14) <= iVar1)        /* only index < capacity */
    return 0xfffffc05;
*(int *)(writer + 0xc) = iVar1 + 1;
*(char *)(*(long *)(writer + 0x20) + (long)iVar1) = (char)uVar3;  /* sxtw */
```

There is no `iVar1 >= 0` check, so a negative position passes and the
`(long)` cast sign-extends it before the store — exactly the macOS root
cause, on iOS 26.5.

`_AVE_DLList_PushBack` at `0xfffffff0081f3520` decompiles to the same
NULL-only checks and `*plVar1 = param_2;` store, confirming the consumer.
The macOS client geometry (list/writer offsets) is the remaining port gap.
