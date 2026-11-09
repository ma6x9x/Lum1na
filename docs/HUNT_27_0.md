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

### The NTL=16463 write is a bounded DPB fill

- Store: `0xfffffe000883979c` `str w24,[x10,x9,lsl#2]` in `FUN_8839554`
  (HEVC PSGen/DPB init).
- Loop A: base `ctx+0x4678`, count `ctx+0x3760`, index 0..count, value
  `w24 = min(GOP_CLAMP16, max(CalcMaxDpbSize,1)-1)` → **0..16**, never
  negative.
- Count lever: `FUN_88b9a08` sets `ctx+0x3760 = u32(ctx+0x2050)-1`;
  `ctx+0x2050 = Prepare input+0x848` (Start +0x850). So "Set 16463" =
  input+0x848 = 16463 → 16462 stores, last at
  `ctx+0x4678+16462*4 = ctx+0x147b0` (SOT pool slot low half).
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
  `IOServiceOpen` is `0xe00002e2` for type 1. VT composes the SPS from
  session properties; a negative VT-provided value is unproven.

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
- ProgramCreate (sel2), GetProgramOutput (sel8), and the argsOutput
  failure leak are therefore unreachable; `0xe00002c7` is the entitlement
  stub, not device state.
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

## Next (17)

1. **p157 type sweep 0-5** (now coded, SKU-aware selectors). If any
   AVE2 type opens, the direct UC path unlocks the Prepare blob gates and
   the signed writer. If none open, the VT blob mapping is the only route.
2. If a type opens, build a blob-filling probe: Prepare in+0x758 ≥1,
   in+0x731 bit2 set, in+0x848 = chosen N, in+0x4874 negative.
3. SPTM/MIE mapping pending (post-KRW path).
