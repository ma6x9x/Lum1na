# 27.0 hunt — 2026-11-09 (T8150 24A435 / 24A437)

Target: iPhone18,2 A19 Pro, iOS 27.0. Ghidra program: 24A437; AppleAVE2 is
byte-identical between 24A435 and 24A437 (0 changed functions), and the
kernelcache is the same train. Static base `0xfffffe0007004000`.

Tools: Ghidra MCP (`[::1]:8080`), `ipsw kernel sym` with the blacktop
signatures, `ipsw kernel extract`, capstone 5.0.7, mnemonic-profile diffs.

## AVE2 (AppleAVE2 913.43.1)

### P149 gates — why frames=0

Both P149 callers return 0 (success) silently when a gate fails:

| Gate | Field | Value |
|---|---|---|
| Open done | `ctx+0x274` | set by `FUN_87955f4` after IOOpen |
| Config | `ctx+0x1f60` | `blob+0x420` = Prepare in **+0x758** / Start in **+0x760**, must be ≥1 |
| Pipeline mode | `pipeline+0x18` | mode 2 iff `(*(u8*)(ctx+0x1f39)>>2)&1`; `ctx+0x1f39 = blob+0x3f9` = Prepare in **+0x731** / Start in **+0x739** |

`FUN_879054c` copies `ctx+0x1b40 <- settings, 0x5c0`, which maps those
fields. The direct UC Prepare (selector 3) can set them; VT must serialize
them from its session spec. Current VT session does not.

**VT fix (2026-11-09, ave.videoencoder analysis):** the blobs are built in
`/System/Library/VideoCodecs/ave.videoencoder`, not VideoToolbox. The AVE
plugin's **SuggestedLookAheadFrameCount** setter (VT key CFString content
`"LookAheadFrames"`) writes Gate1 (`settings+0x420`) and Gate2
(`settings+0x3f9` bit2) **together**; values **1..20** pass, default 0
fails. P149 now sets `"LookAheadFrames"` = 1 before Prepare. Other
properties (NumberOfTemporalLayers -> session+0x12438, EncoderUsage,
MaxKeyFrameInterval, BaseLayerFrameRate, ExpectedFrameRate,
SourceFrameCount) do **not** touch these fields; MaxFrameDelayCount has a
getter only.

### The NTL=16463 write is a bounded DPB fill

- Store: `0xfffffe000883979c` `str w24,[x10,x9,lsl#2]` in `FUN_8839554`
  (HEVC PSGen/DPB init).
- Loop A: base `ctx+0x4678`, count `ctx+0x3760`, index 0..count, value
  `w24 = min(GOP_CLAMP16, max(CalcMaxDpbSize,1)-1)` → **0..16**, never
  negative.
- Count lever: `FUN_88b9a08` sets `ctx+0x3760 = u32(ctx+0x2050)-1`;
  `ctx+0x2050 = Prepare input+0x848` (Start +0x850). The direct UC can
  write 16463 there; the arithmetic would put the last store at
  `ctx+0x147b0`. **VT cannot:** the AVE plugin's field C
  (`settings+0x510` = input+0x848) is default/forced **1** (AllowFrame
  Reordering=false forces 1, Validate sets 1); no VT property writes an
  arbitrary value, and 16463/16462 are absent as client data. Number of
  TemporalLayers maps to session+0x12438, not this field. So the p142
  NTL=16463 panic is **not** reachable through this fill on the VT path;
  it must be another site/path (needs reconciliation). The fill remains
  direct-UC-only.
- Loop B (HEVC_SPS delta-POC): layer 0 base `ctx+0x6424`, count
  `ctx+0x6230`; layer 1 base `ctx+0x8098`, count `ctx+0x7ea4` (Prepare
  input+0x62fc).
- In-object, the only kernel pointers above the bases are the three SOT
  pool slots at 0x147b0/b8/c0; a 0..16 value there is a fault, not
  control. Layer 1 can write past the `_S_AVE_Client` object (size
  0x147c8) into neighbouring clients with the same small value; that is
  cross-session corruption, not a pointer forge.
- **Verdict: the DPB fill is not a direct KRW primitive.** Fields
  0x63e8/0x6414/0x641c/0x6c90/0x6c94 are later-read scalars that can be
  zeroed/shrunk, but no field was found where a small value yields a
  bigger read/write.
- Reachability of the HEVC branch: subtype `ctx+0x270==2` and
  `ctx+0x1f64 == 0x14` (RCMode); our RCMode=20 forces it.

### Signed writer (SPS bit count)

- `HEVC_SPS::Write_seq_parameter_set_rbsp` `0x88e4c2c` calls
  `FUN_88b9670(writer, value, *(int*)(sps+0x1f4)+4)`.
- Real writer `0x88b94f8`: bitpos +8, capacity +0x10, accumulator +0x14,
  buffer +0x18, flag +0x820. Byte index = `(bitpos-8)>>3` (signed);
  capacity check is upper-bound only; `strb` at a negative index passes.
- 27.2 `0x88f39a4` is **also unclamped**; the `cmp/csel` is division
  rounding, not a lower bound. The 27.2 SPS caller `0x891f68c` passes
  `sps+0x1f4+4` with no check.
- Input mapping: Prepare settings = input+0x338; `AVE_Client_Verify`
  copies settings+0x4348 -> client+0x6228 (0x38e8); `AVE_PSGen::Init`
  memcpy's client+0x6228 -> HEVC_SPS (0x1c74). Therefore
  **Prepare input+0x4874 -> HEVC_SPS+0x1f4** (layer 0; layer 1 +0x64e8).
  The field is `log2_max_pic_order_cnt_lsb_minus4`; a negative value
  (e.g. -12 -> bit count -8) triggers the underwrite.
- Reachability: the direct UC Prepare is the natural path but
  `IOServiceOpen` is `0xe00002e2` for type 1. VT does not help: the AVE
  plugin's private `log2_max_minus4` setter accepts only unsigned <12 and
  stores **value+1 (1..12)**; negatives/≥12 are rejected. The negative
  SPS field is therefore **not reachable through VT**. Direct UC only.
- Direct-open receipt (p148, 12/23F77): types 0/1/2 all return
  `0xe00002e2`; `IOServiceMatching("AppleAVE2")` finds no service. The
  P157 sweep now covers types 0-5; if none open, the direct UC path is
  closed on that build and VT is the only AVE2 route.

### Zones

`AVE_SurfacePool` 0x98, `S_AVE_SurfacePool_Entry` 0x20/entry (backing,
count 10 = 0x140), `_S_AVE_Client` 0x147c8, `AVE_Pipeline` 0x50,
`AVE_MD_SVE` 0x1c1d0 / `AVE_MD_LAGOP` 0x19590, `AVE_SyntaxWriter` 0x828.
Kernel-pipe/kalloc_data sprays cannot groom these typed zones.

## ANE (AppleH16ANEInterface 10.19.6)

- `ANEDriver::newUserClient 0x8c096f0`: types 1/4 -> DirectPathClient
  (init 0x8caf080, skips the entitlement check); all other types ->
  H11ANEInUserClient (init 0x8caede8, tests
  `com.apple.ane.iokit-user-access`). Stock app: **only 1/4 open**.
  The 0xe00002c7 is realized by `mov w0,#0x2c7; movk w0,#0xe000; ret`
  stubs (e.g. 0x8cae834), not device state.
- ProgramCreate (sel2), GetProgramOutput (sel8), and the argsOutput
  failure leak are therefore unreachable; no other service/type reaches
  H11ANEInUserClient (`ANEClientHints` needs
  `com.apple.private.ane.allow-set-client-hints`, 0xe00002c1).
- Reachable DirectPath: sel2 ProgramSendRequest (0xc50/0x40), sel3
  OutputSetEnqueue, sel4 InputsReady, sel5 MemoryMapRequest (0x828), sel6
  Unmap, sel7 SessionHint, sel8 Chaining, sel9/10 mutable weights.
- Readouts: sel7 SessionHint copies fixed page counts/status; sel5 echoes
  the user's own +0x818; sel2's async 0x40 completion is unproven. No
  kread32-style copyout.
- The unchecked `surfaceId*0x68` oracle in `FUN_8c52f34` needs the
  program-object base VA, which is not leakable; not practical.
- Prewire TOCTOU on `+0x20/+0x81c`: conditional — IOConnectCallStructMethod
  normally passes a kernel copy of structureInput, so the counts are
  immutable; the mapped-user-buffer case belongs to the unreachable
  ProgramCreate class. Unproven.
- **Verdict: the ANE UC read half is effectively empty on stock. The
  proven ANE write lane remains p044/AVE2 chosen writes.**

## IOHID 112515 — CLOSED

Type-2 class is `IOHIDEventServiceUserClient` (personality
`0xfffffe000b5b7e78`). The `" hid"` table object is
`site.HIDPreparsedData` (`0xfffffe00083218c8`), base +0x38, count +0x40,
stride 0x14, index from the descriptor at `[obj+8]+0x30`. Both getters
are `ldr` only; the leaked dword is consumed in-kernel; no copyout.
27.2 adds a signed upper-bound check. Not app-reachable, not a write.

## Static diffs (27.0/24A437 -> 27.2/24B119)

| Kext | Changed | Notes |
|---|---|---|
| AppleAVE2 | 18 | none on the P149 pool path except settings copier 0x879054c; per-subtype inits 0x8863b6c/0x874cdd4/0x87cae10 are codec ctors |
| AppleH16ANEInterface | 256 | no fix in prewire/ProgramCreate/processRequest; 0x8c15480 pairing was false (real 27.2 request_prep 0x8cc61b4) |
| AppleM2ScalerCSCDriver | 77 | top 0x9108d04, 0x91073c0; guard candidate 0x91413b8 |
| IOSurface | 2 | 0xa3460f0, 0xa34b2dc (p154 ready-byte candidates) |

## SPTM / MIE on T8150 (24A435/24A437)

Core kernel is byte-identical between 24A435 and 24A437 (md5 match), so the
Ghidra addresses apply to both.

### SPTM

- The kernel→EL2 gate is a custom trap, **`.inst 0xd4e00000`** (undefined
  in ARM ARM; Ghidra prints "bad instruction"), one per call, **174 sites**
  / 51 wrappers, selector in `x16`. Enter `FUN_ab48018` saves x0-x7/x16,
  bumps `tpidr_el1+0x1c0`, spins on `s3_6_c15_c8_0`; exit `FUN_ab48084`.
  SPTM-present flag `DAT_7ef9380`; gate sites e.g. `0xb41b44c` (sel0),
  `0xb41b488` (sel1), `0xb41b4c4` (sel2).
- Shadow state in `__DATA_CONST` (RO after boot): `7ef92d0` enabled,
  `7ef92d8/e0` range list, `7ef9310` per-page metadata, `7ef9318`
  entry-type table, `7ef9338` range table. Range/pointer lookups tag-check
  and force tag **0xc8a2**.
- Mediates page tables/PTE state (`pmap_tt_deallocate 0xad34020`,
  `sptm_get_table_mapping_count 0xb41b080`), page retype/lifecycle
  (`sptm_check_inflight`, sel50), **DART/SMMU** (`sptm_gen3dart_*`),
  and the trustcache/SART ranges (`kern_trustcache` resolves via
  `0xb41ab4c`, tag 0xc8a2).
- **A kernel data write cannot edit page tables, DART tables, text
  permissions, or the trustcache.** No writable SPTM config register,
  call-gate pointer, or permissive selector was found. Do not claim an
  SPTM bypass.

### MIE / MTE

- MTE enabled at boot in `arm_init 0xb4346f0` (`s3_4_c15_c9_6` bit setup,
  `cntkctl_el1 |= 3`).
- Tag-check faults are fatal: ESR EC 0x25 → panic
  `"Kernel tag check fault (expected tagged address...)"` at `0xad54d28`.
- `kalloc_type` zidx validation on free at `0xb42dfe0`; double-free
  detection at `0xb42e498`.
- **CPU writes are tag-checked**: OOB within the same allocation/tag works;
  crossing into a differently tagged neighbour panics. DMA bypasses CPU
  MTE, but its reach is the IOVA→PA mappings the driver installed, and
  those DART tables are SPTM-mediated.

### Post-KRW requirements

| Step | From a kernel data write under SPTM/MIE |
|---|---|
| (a) Patch kernel text | **No** — RX, SPTM owns PTEs, DART cannot map text PA |
| (b) Trustcache / AMFI | **No, not directly** — SPTM range table + SART; runtime caches are tagged kalloc_type |
| (c) `pmap_cs` / CS flags | **Name absent**; config is const/RO; `code_signing_configuration`, `disable_code_signing_feature` exports only |
| (d) kernproc / ucred | **Yes in principle** — heap data, but writes must use correctly tagged kernel pointers |
| (e) launchd / opainject | **Split** — task/cred edits are data-only; mapping unsigned/exec pages still hits pmap_cs + trustcache |

### DART / DMA verdict (2026-11-09)

Both AVE2 and ANE DMA reach **only IOSurface backing**, not kernel
objects:

- `IOUAT::map FUN_b3c5688` builds the segment array from
  `IOMemoryDescriptor::getPhysicalSegment` (vtable +0x90); the PA always
  comes from the IOMD, never from a client field. `pmap_iommu_map_internal
  FUN_ad43c18` → SPTM callgates → AppleT8110DART `FUN_ad6c0b8`.
- `FUN_ad6c0b8` filters only PA < dart+0xaa8 and IOVA < per-SID limit
  (16K pages << 14); page-table refcount on an unmanaged page hard-panics
  (`FUN_ad4451c`, "unmanaged page", `0x7063622`). No user/kernel PA split
  exists in the mapper because every PA is an IOMD segment.
- AVE2 surfaces: global IOSurface lookup (`FUN_a344130` / policy
  `FUN_a343de8`); the client supplies sids/symbols/sizes, never a PA.
- ANE: `ANE_ProgramCheckAndPrewireBuffers` resolves sids via
  `FUN_8d31f9c`/`FUN_8d32494`; the plane check `FUN_8c1cae8` compares
  plane count/size against the surface (`surface+0x98`, plane array
  `+0x180` stride 0x38, size +0x28) and rejects mismatches/undersize.
  DMA length is confined to the surface's own plane.
- Tag-bypass candidates: the prewire record table (kalloc, CPU-only), the
  IOSurface object (kalloc, not backing), the IOSurface backing (already
  user-writable), the AVE2 command IOMD (user-writable), shared events
  (kernel-mediated). **None gives a DMA-to-kernel-object path.**
- A hypothetical kernel-PA mapping needs an IOMD whose page list contains
  a kernel PA — no user-reachable constructor — plus SPTM accepting a
  non-managed page, which the refcount path panics on.

Ranked next: data-only ucred/task edits through correctly tagged
pointers; target task `cs_blob`/AMFI decision state for unsigned code;
treat page tables, text, trustcache and DART tables as SPTM-gated until a
real gate bypass exists. The DMA tag-bypass route is closed.

## Next (17)

1. **p157 type sweep 0-5** (now coded, SKU-aware selectors). 24A435:
   0 Open / 2 Config / 3 Prepare (0x12c08) / 4 Start (0x12c18), count
   +0x12c10; 23F77: 1/3/4/5 with 0x1a0a0/0x1a0b0 and count +0x1a0a8.
   Each selector is knob-overridable. If any AVE2 type opens, the direct
   UC path unlocks the Prepare blob gates and the signed writer. If none
   open, the VT blob mapping is the only route.
2. **p149 v4.2 LookAheadFrames test** (VT path): `LookAheadFrames=1`
   should satisfy the P149 gates and materialize the pool; read
   `[2a] lookahead st` and `[2e] frames`. This does **not** unlock the
   16463 fill or the negative writer (both direct-UC-only).
3. If a type opens, build a blob-filling probe: Prepare in+0x758 ≥1,
   in+0x731 bit2 set, in+0x848 = chosen N, in+0x4874 negative.
4. SPTM/MIE: no bypass; DMA is surface-only. New lanes must be new bugs
   (Scaler/IOSurface 27.2 diffs) or a real SPTM gate bypass.

## M2Scaler sel8 static map (24A435, 2026-11-09)

The 17's best remaining **read** lead is the M2Scaler sel8 copyout, not the
fenced 43748 prewire. Static decode (capstone over
`kernelcache.research.iPhone18,2`; flat delta `fileoff = low32(va) - 0x7004000`):

- Dispatch table `0xfffffe00080efcd8`, stride `0x30`, 12 rows. Row 8 =
  `0xfffffe00080efe58`, handler `0xfffffe000909b3e0` (flags `0x3`, in-size
  descriptor `0xfffffe0007004008` = 8 bytes).
- Handler `0x909b3e0`:
  - rejects `*(u32*)(this+0x15c) != 0`, null input, or `inputSize != 8`;
  - `x0 = *(u64*)input` (the caller's 8-byte value);
  - global `*(u32*)(0xfffffe000b8f5460 + 0x48)` is a record/queue count;
    `stride = (count > 0x100 ? 0x200 : 0x40) + count`;
  - allocation size = `count_or_512 * 0x7c + 0x20`;
  - `bl 0xfffffe00091862f8` with `(input_u64, size, 1, *(this+0x130))`;
  - then `x0 = *(this+0x100)`, `x1 = buffer`, `bl 0xfffffe00090e3414`
    (the serializer that fills the 0x7c-stride records), release via
    `vtable+0x28`, return status.
- Matches the device contract: first record's `rec+0x18` is **our** input
  u64; the later records are kernel-refilled. The record copy
  (`0x90e36e4`) sends every pointer field through `0x9186b48`, whose target
  `0xac91568` is the `VM_KERNEL_ADDRPERM` canonicalizer/permuter (kernel
  range table `0x7ef7f58`, `addr + vm_kernel_addrperm`). **The disclosure is
  permuted kernel addresses, not raw pointers.** It is a slide/pointer-
  obfuscation leak, not an arbitrary kread: the low offset survives, but
  the permutation constant must be solved before the value is dereferenceable.
  Do not bill p114's sel8 output as a kread.
- The 27.2 sel8 check pattern (`085c41b9 28060035`) is absent from 24B119,
  so the handler changed after 27.0. Treat the lane as 24A435/27.0-only
  until a 24B119/24C diff proves otherwise.
- Next static step (needs a T8150/24A435 Ghidra program; the current bridge
  is A14/23F77): decompile `0x91862f8` (allocator/descriptor),
  `0x90e3414` / `0x90e3468` (serializer/action), and the globals at
  `0xb8f5460` / `0xb8f4510`; enumerate the 0x7c record fields and classify
  each as scalar, permuted pointer, or our-input echo. Then p114 can use
  the records as a slide oracle rather than pretending they are a read.
- 43748 status on the 17: the 257/300-in models are already generated
  (`tools/make_257in_addchain.py`, `make_300in_addchain.py`) and wired in
  P073, but the prewire caller still fences in+out to 255 records. The
  >254 model is necessary but not sufficient; do not remaining-fire it.
- **27.3b1 (24C5037i) diff plan:** when the IPSW lands, extract
  `kernelcache.research.iPhone18,2` and diff (a) the M2Scaler sel8
  handler/permuter, (b) the ANE prewire caller fence, (c) AVE2, and
  (d) SPTM/MIE. Treat it as a **patched reference**, not a target: the 17
  stays on 27.0 and the 12 on 26.5. A lane that is live on 27.0 and changed
  in 27.3b1 is a priority; one present in both is deliberate behavior.



