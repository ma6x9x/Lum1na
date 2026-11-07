# IPSW diffs (lab method)

Kernel read/write is **not** obtained. These notes are size + CString maps, not a KRW, not a fire list.

Public source: [blacktop/ipsw-diffs](https://github.com/blacktop/ipsw-diffs). Adopt the **method**, not the default device.

## Method (copy this)

blacktop’s CI (`.github/workflows/diff.yml`) does:

```text
ipsw dl appledb --os iOS --device DEVICE --build BUILD --output DIR --confirm
ipsw diff --output OUT \
  --markdown --fw --launchd --feat --strs --ent --files --starts \
  --signatures symbolicator/kernel \
  --block-list __TEXT.__info_plist \
  --block-list __AUTH_CONST.__auth_ptr \
  PREV.ipsw NEXT.ipsw
```

Layout of each pair:

```text
VERSION_BUILD_vs_VERSION_BUILD/
  README.md          # KC version, NEW/Removed/Updated kexts, DSC, entitlements
  KEXTS/             # function-size + CStrings
  DYLIBS/ MACHOS/ FIRMWARE/ IBOOT/ FEATURES/ FILES/
  Entitlements.md Sandbox.md
```

Cron only diffs **forward inside one major** (26.x vs 26.x). Cross-major (23F77 → 27, 23F77 → 26.6) is a manual `workflow_dispatch` / `just diff-build`.

Lab wrapper: `tools/ipsw-diff-lab.sh` (same flags). Default device is **iPhone13,2**, not blacktop’s **iPhone18,1**.

## Device warning (do not skip)

blacktop’s iOS matrix is `iPhone18,1` (T8150 / AGXG18P / AppleH16ANE / AVE H18). Lab SKUs are:

| Lab | Device | Build | SoC |
| --- | --- | --- | --- |
| Active | iPhone13,2 | 23F77 | T8101 / A14 |
| Twin | iPad8,* | 23G71 | T8027 / A12X |

Same *build number* can still be a different kext (H16 vs H11 ANE, T8150 vs T8101 IOGPU). **Do not paste iPhone18,1 VAs onto T8101.** Use blacktop markdown to see *which strings/sizes moved*, then confirm on the Ghidra 23F77 XNU / kext for this board.

## Pairs that matter for 23F77

All links are `main` on ipsw-diffs.

| Pair | Why |
| --- | --- |
| [26.5 23F77 vs 26.6 beta 1 23G5028e](https://github.com/blacktop/ipsw-diffs/tree/main/26_5_23F77_vs_26_6_23G5028e) | First step toward the A12X 23G71 twin. 18 updated kexts. |
| [26.6 beta 1 23G5028e vs beta 2 23G5043d](https://github.com/blacktop/ipsw-diffs/tree/main/26_6_23G5028e_vs_26_6_23G5043d) | **IOGPU replace-backing ownership.** |
| [26.6 beta 5 23G5065a vs 26.6 23G71](https://github.com/blacktop/ipsw-diffs/tree/main/26_6_23G5065a_vs_26_6_23G71) | Twin RC. IOGPU data-only. |
| [26.5 23F77 vs 27.0 beta 1 24A5355q](https://github.com/blacktop/ipsw-diffs/tree/main/26_5_23F77_vs_27_0_24A5355q) | What 27 patched. 297 kexts. |
| [26.5 23F77 vs 26.5.1 23F81](https://github.com/blacktop/ipsw-diffs/tree/main/26_5_23F77_vs_26_5_1_23F81) | KC identical. iBoot only. |
| [26.7 23H24 vs 26.7.1 23H30](https://github.com/blacktop/ipsw-diffs/tree/main/26_7_23H24_vs_26_7_1_23H30) | CoreGraphics only. KC skipped. |
| [26.4 beta 1 23E5207q vs beta 2 23E5218e](https://github.com/blacktop/ipsw-diffs/tree/main/26_4_23E5207q__vs_26_4_23E5218e) | AVE EncType / in-buf offset strings. |

## Findings (string/size only)

### IOGPU / 64788 / P009 replace

23F77 IOGPUFamily is **130.14**. Live LightSword is still acquire → replace 0x20000 → spray → blit.

| Build | IOGPU | What moved |
| --- | --- | --- |
| 23F77 | 130.14 | baseline |
| 23G5028e | 130.16.2 | only `IOGPUDevice::create_resource_iosurface` 1152 → 1160 (+8 TEXT) |
| 23G5043d | 130.16.3 | **ownership check** |
| 23G71 | 130.16.3 (data rebuild) | same as late 26.6 |
| 24A5355q | 162.5 | GART reclaim timers + more |

**26.6 beta 2** added:

- `IOGPUResource::owns_replaceable_backing() const`
- `IOGPUSysMemory::replace_backing_bytes_locked`
- `IOGPUSysMemory::replace_backing_ranges_locked`
- `"resource does not own its backing (resType=0x%x…)"`

and dropped the unlocked `replace_backing_bytes` / `replace_backing_ranges` virtual names plus `"Attempting to detach memory for invalid resource type"`.

That is the first public string-level close of the dangling-GART *replace* class — **after** 23F77, **before** 23G71. The iPad twin may already refuse P009 replace. Do not assume LightSword’s replace needle is the same on 23G71.

**27** added `iogpu_gart_interval_ms` / `iogpu_gart_timeout_ms` and `GARTReclaimInterval` / `GARTReclaimTimeout`. That is reclaim *timing*, on top of the 26.6 ownership check. Mapping-valid asserts for `wireRange` also show up there.

23F77 vs 26.6 beta 1 does **not** list AppleAVE2, AppleJPEGDriver, or ANE in updated kexts. Those were unchanged on that pair.

### AVE EncType (84607)

`AVE_EncType_None < encType && encType < AVE_EncType_Max` (plus `AVE_ClientType_*` and `offset + size <= pInBuf/pOutBuf->iSize`) landed in AppleAVE2 **905.36.1** on **26.4 beta 2** (23E5218e).

23F77 AVE in the blacktop 23F77 vs 27 pair is already **905.36.1**. The EncType string is **present on 23F77**, not a 27-only guard. 27 bumps AVE to 912.89.1 with more logging/index checks. That does not reopen remaining-fire. P061 stay reach-only.

### JPEG (24A435 class)

23F77 AppleJPEGDriver **7.7.9** → 27 **8.1.0**. New reject strings:

- crop offset vs MCU / pixels
- `elementCount` vs `partialDecodeFakeHeader` capacity
- `newHeaderSize` vs `MARKERRAM_MEM_SIZE` and 12-byte multiple
- `startOfRawBitStream >= sourceSurface allocSize`

Timeout-cleanup strings drop. P058 stays **open-only**. Do not ioctl-teardown.

### AMFI (after-kread only)

23F77 AMFI **1045.120.5**, TEXT 0x283c8, `copyTrustCacheFromInputArguments`, `performCommandV2`, string `personalized.trust-cache`.

27 AMFI **1166.0.0** replaces that with `copyBytesFromInputArguments` / `performCommandV3`, adds `_check_cdhash_in_trustcache`, `cdhash-full`, PQC strings, `"input too large"`. The 23F77 AfterKread plan (UC loadTrustCache sel 2/7) is for **this** AMFI. Do not retarget it from 27 names. HOLD until `hasKread`.

23F77 → 26.6 beta 1 AMFI is date + three daemon names removed. TEXT size unchanged.

### ANE

23F77 vs 27 lists **AppleH16ANEInterface** 9.511.3 → 10.13.20 (3577 → 4838 functions). That is iPhone18,1 silicon. A14 23F77 uses **AppleH11ANEInterface**. There is no H11 file in that pair. Do not copy H16 timeout/scheduler strings onto T8101. 254 stays unfired.

### Kernel / sandbox / APFS (23F77 → 26.6 beta 1)

| | 23F77 | 23G5028e |
| --- | --- | --- |
| XNU | 25.5.0 `12377.122.4~1` | 25.6.0 `12377.160.49.0.1~39` |
| sandbox | 2680.120.12 | 2680.160.3 (`com.apple.private.security.revoke`) |
| APFS | 2811.120.14.0.1 | 2811.160.3 (version strings only) |

Kernel CStrings on that pair include NECP caps (`necp_client_add cannot add more clients`, `max_flows_per_client`). That is iPhone18,1 XNU. Confirm on T8101 Ghidra before calling P053 closed. One failed tap is still not a close.

23F77 vs 23F81: **kernelcache functionally identical**. iBoot `mBoot-18000.120.36` → `18000.122.1`.

### CoreGraphics (CVE-2026-86950)

23H24 vs 23H30: KC identical, KEXT skipped, iBoot identical. Only dylib updated among Frameworks: CoreGraphics 1965.6.5 → 1965.6.6.

```text
_aa_moveto     344 → 488
_aa_lineto     452 → 652
_aa_clip_edge  648 → 1120
_aa_clipping   480 → 712
_aa_rectat     656 → 884
_aa_quadto     968 → 1076
_aa_cubeto    1252 → 1344
_aa_close      276 → 264
```

Userspace path-rasterizer OOB / file ACE. Not XNU, not AMFI, not pmap_cs, not tempRoot. Do not put a CG/PDF probe on KERNEL or persist.

### Firmware / iBoot

23F77 vs 26.6 beta 1 firmware on blacktop is T8150 (`sptm.t8150`, `agx_a000`, `AppleAVE2FW_H18`). Useless as T8101 pins. iBoot versions are comparable as *labels* only.

## What this does not change

- KERNEL head is LightSword (replace 0x20000 then spray then blit). No inpcb yet, `hasKread` false.
- Do not remaining-fire P027, 254, 84607 Close-vs-async, JPEG +0x30, hop-1, CG ACE.
- P044 frozen.
- AfterKread AMFI/pmap_cs HOLD.

## Local commands

Need `ipsw` (this machine has 3.1.706). Optional: [blacktop/symbolicator](https://github.com/blacktop/symbolicator) for named kernel functions.

```bash
# Two IPSWs you already have (preferred):
./tools/ipsw-diff-lab.sh /path/iPhone13,2_23F77.ipsw /path/iPhone13,2_23H24.ipsw

# Download then diff (many GB; iPhone13,2):
./tools/ipsw-diff-lab.sh --dl 23F77 23H24

# Twin iPad:
./tools/ipsw-diff-lab.sh --dl --device iPad8,1 --os iPadOS 23G71 23G82

# Grep a pair (blacktop clone or local out dir):
./tools/ipsw-diff-lab.sh --grep ipsw-diffs-out/26_5_23F77_vs_…
```

Watchlist is `tools/ipsw-diff-watchlist.txt`. Output goes to `ipsw-diffs-out/` (gitignored).

Confirm every interesting string on the **T8101 23F77** binary in Ghidra before changing a probe.

## 2026-11-07 — 27.0 (24A435) vs 27.2 (24B119) kext isolation

Kernelcaches: 24A435 release (iPhone18,2) and 24B119 release (iPhone18,2).
`ipsw kernel extract` + `kextdiff2.py`/global similarity pairing.

### IOSurface — CVE-2026-112477 fix, exact
- IOSurface kext has only 3 B-only functions.
- Fixed `0xfffffe000a3944c0` (A 24A435 `0xfffffe000a3460f0`): after the lock,
  the new check is
  `ldrb w8,[x21,#0xf1] ; tbz w8,#0,#+0x10 ; add w20,w20,#0x1b ; b return`
  with `w20` seeded `0xe00002bd`, so the not-ready return is **0xe00002d8**.
  The vulnerable build goes straight to the list insert
  (`stp x8,x21,[x24,#0x50]` under `[x19+0x188]`).
- The other two B-only functions set/clear the ready byte (`strb` at +0xf1):
  the fix adds a ready flag and gates the insert on it. This is the p154 race.

### IOHIDFamily — CVE-2026-112515 candidate
- B `0xfffffe000a15ec54` (A `0xfffffe000a10fb20`): fixed adds
  `cmp w21,w0 ; b.hs` immediately after the count call, before using `w21`
  as the table index. The vulnerable build only checks `cbz w0`. The index
  path then calls a virtual `[x16+0x118]` accessor with `x1 = w21`.
- 45/44 B/A-only functions; most other diffs are codegen shifts (`and/cmp`
  refcount sequences repeated across many functions).

### ANE — CVE-2026-112696 / 84494 status
- AppleH16ANEInterface 10.19.6 → 10.102.4 (278 B-only functions; big version
  jump, noisy).
- Prewire `ANE_ProgramCheckAndPrewireBuffers` A `0x8c16a84` ~ B `0x8cc7634`
  (r=0.93, 448→449 insns). B saves `x0` in `x20` and adds one state gate
  (`ldrb/tbz` class) but the caller fence `0x8c14310` ~ B `0x8cc4fb4` is
  **byte-identical** (r=1.00, no added check). The dispatcher `0x8cb0ee0` ~
  B `0x8cb0378` is also identical.
- The exact 112696/84494 OOB-write check still needs the full `ipsw diff`
  run (24A435↔24B119, in progress); the prewire gate is the best candidate
  but not proven from this pairing alone.

### AVE2 iPad — CVE-2026-112466 (already isolated)
- iPad 905.41.1 → 905.43.1 added the `sub/ubfiz/cmp/csel` index bounds check
  before the `ldp` at the vulnerable `add w26,sxtw #4 ; ldp [x8,#-8]` site.
  This remains the iPad's read/corrupt candidate; p155 not built (needs the
  iPad VT encode path; p017 stays forbidden).
