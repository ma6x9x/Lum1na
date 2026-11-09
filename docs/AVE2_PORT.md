# AppleAVE2 writer-underwrite port (iOS)

Target: **23F77 (26.5, A14, the 12)** — writer and PushBack sink both present.
Source: `dawgyg/AppleResearch` macOS 26A5421a report + Ghidra on 23F77.

## iOS user-client dispatch (23F77 AVE2 905.36.1)

Table at `0xfffffff007bfec88`, 0x18-byte entries, PAC-signed fn; real target =
`0xfffffff007004000 + (raw & 0xffffffff)`. Nine entries starting at selector 3:

| Selector | Handler | structIn | structOut |
|---|---|---:|---:|
| 3 Config | `0x83692b0` | `0x38` | `0x20` |
| 4 Prepare | `0x8369b6c` | **`0x1a0a0`** | `0x20` |
| 5 Start | `0x836a640` | **`0x1a0b0`** | **`0x150`** |
| 6..11 Process | `0x836b158` … `0x836d9d0` | `0x30` | `0x20` |

The macOS request sizes (`0x12c08`/`0x12c18`) do **not** transfer; iOS uses
the larger 0x1a0a0/0x1a0b0 buffers.

## Start path (Ghidra)

```
0x836a640 Start handler
  checks input>=0x1a0b0, output>=0x150
  -> 0x836ac4c (checks client+0xd8/+0x100/+0x160)
     -> 0x824a808(ctx=[UC+0x160],
                  input+0x18, [input+0x28], [input+0x1a0a8],
                  input+0x22c, input+0x340, input+0x2c)
```

- The writer/pipeline is `ctx + 0x2d0`; `0x824a808` calls
  `0x835011c(*(ctx+0x2d0), input+0x1a0a8)` — the request's last 8 bytes are
  the **field pointer** for the syntax writer (the macOS `+0x487c` analog).
- The signed writer is `0x835bc60`: it checks only `capacity <= position`;
  a negative position passes and sign-extends into `strb` (Ghidra proof in
  `APPLE_RESEARCH_TRIAGE.md`).
- `_AVE_DLList_PushBack` is `0x81f3504` (the arbiter of the final
  `str x1,[x8]`).

## p157 reach test

`p157` now defaults to the iOS shapes: sel4 `0x1a0a0`, sel5 `0x1a0b0`,
`p157_count_off=0x1a0a8`, sel3 `0x38`, sel7 `0x30`. Open/Prepare/Config are
opt-in, Start/Process are opt-in and PANIC-POSSIBLE. With a zeroed Start
buffer the count field is 0 (positive), so the probe is a **reach** test, not
the underwrite.

## Remaining geometry

The macOS client list offset (`client+0x280`) and writer buffer base
(`client+0x2648`) are not yet mapped on iOS. The next Ghidra pass:
`FUN_824a808` → `FUN_835011c` for the writer object/buffer, and
`FUN_824e014` / `FUN_837b838` (Process command path) for the list pointer
that reaches `0x81f3504`. Once mapped, the request field at `0x1a0a8` can be
set to the negative count and the forged list can target a chosen VA.

## SPS count chain (Ghidra, continued)

```
0x82eda2c (SPS/layer generator)
  param_1+0x10 = layer count (1 or 2)
  param_1+0x18 = SPS-id source
  param_1+0x20 + layer*8 = SPS object pointer
  param_1+0x48 = per-layer array
  -> 0x837f2d0(sps_obj, param_1+0x18, param_1+0x48, layer, ...)
     allocates the syntax writer, seeds *(sps+8), *(sps+0x1c0)
     -> 0x837f6fc(sps_obj, layer_array, writer)   HEVC SPS writer
```

The vulnerable call is inside `0x837f6fc`:

```c
thunk_0x835bc60(writer,
                layer_array[i + 0x169c],
                *(int *)(sps_obj + 0x1f8) + 4);   /* signed count */
```

`0x835bc60` checks only `capacity <= position`; a negative SPS+0x1f8 value
passes and sign-extends into the byte store. So the chain is:

```
Start input (0x1a0b0)
  -> ctx = [UC+0x160]
  -> ctx+0x20/0x28 SPS object(s)
  -> SPS+0x1f8 count
  -> WriteBits underwrite
```

Remaining: the input offset that populates **SPS+0x1f8**. The macOS request
used +0x487c -> SPS+0x1f4; iOS has the count one field later at +0x1f8, so
the input field is likely one 4-byte slot later in the parsed SPS payload.
The next pass is the SPS parser (`0x82ee3fc` / `0x82eda2c` caller) to map
that input slot.

## SOLVED: input offset -> HEVC_SPS+0x1f8 (2026-11-09)

The 23F77 kernelcache was symbolicated with the blacktop/symbolicator
signatures (`ipsw kernel sym ... --signatures ...`) — 73.3% match. Names:

| Address | Symbol |
|---|---|
| `0x836a640` | `AppleAVE2UserClient::IO_Start` |
| `0x836ac4c` | `AppleAVE2UserClient::Start` |
| `0x837f6fc` | `HEVC_SPS::seq_parameter_set_rbsp(HEVC_RPS*, AVE_SyntaxWriter*)` |
| `0x837f2d0` | `HEVC_SPS::Generate(HEVC_VPS*, HEVC_RPS*, int, int, _S_AVE_PSContext*)` |
| `0x82eda2c` | `AVE_PSGen::GenerateSPS(_S_AVE_PSContext*)` |
| `0x82ec254` | `AVE_PSGen::Init(unsigned long long, void*, _E_AVE_EncType, int, int)` |
| `0x8338a70` | `AVE_MD_SVE::InitComponents()` |
| `0x8249ddc` | `AVE_Client_Prepare(...)` |
| `0x8244850` | `AVE_Client_Verify(_S_AVE_Client*, bool, SessionSettings_UserKernel_Data*)` |
| `0x837f124` | `HEVC_SPS` constructor (`memcpy(dst, src, 0x1e7c)`) |
| `0x835bc60` | `AVE_SyntaxWriter` WriteBits (nearest symbol `AVE_IOP_GetCurrTime_Aio`) |

### The chain

```
IO_Prepare  -> AVE_Client_Prepare(ctx, in+0x18, in+0x228, in+0x338, in+0x28)
  AVE_Client_Verify(client, 1, in+0x338):
      HEVC (client+0x3cac == 2):
        client+0x5c28 <- in+0x338+0x3398   (0x2fcc)
        client+0x8bf4 <- in+0x338+0x6364   (0x3cf8)
        client+0xc8ec <- in+0x338+0xa05c   (0x4b40)
        client+0x11430 <- in+0x338+0xeba0  (0x53f0)
        client+0x16820 <- in+0x338+0x13f90 (0x5dd8)
  AVE_PSGen::Init:
      HEVC_SPS layer 0 = ctor(heap, client+0x8bf4)
      HEVC_SPS layer 1 = ctor(heap, client+0x8bf4+0x1e7c)
      ctor = memcpy(sps, src, 0x1e7c), then zeroes sps+0x1c74..0x1e78
```

`HEVC_SPS::Generate` / `Init` never write +0x1f8, so it stays the value
copied by the constructor. Therefore:

**Prepare input +0x6894  ->  HEVC_SPS+0x1f8**

(`0x338 + 0x6364 + 0x1f8 = 0x6894`.) Layer 1 is `+0x1e7c` later in the
client copy: Prepare input +0x6894+0x1e7c = **+0x8710**.

### Writer reachability (important)

- `AVE_SyntaxWriter` is heap-allocated per `HEVC_SPS::Generate` and its
  position +0xc is zeroed by the constructor `0x835bb0c`, so a negative
  SPS+0x1f8 does not seed a negative byte position directly. On 23F77 a
  negative count makes WriteBits take the signed-compare branch and move the
  **bit accumulator +8** negative; it returns without a store. The macOS
  underwrite story is not yet reproduced by this call on 23F77.
- The iOS Prepare input is large enough to reach the field, so the remaining
  work is the writer-position path (which helper turns a negative count into
  a negative +0xc), not the input mapping.

### IOServiceOpen gate (blocking)

`p157` on the 12 (23F77, free-signed) gets
`AppleAVE2Driver type=1 kr=0xe00002e2 (kIOReturnNotPermitted) conn=0`.
`AppleAVE2Driver::newUserClient` (0x8378ac0) creates the UC and calls
`AppleAVE2UserClient::Init` (0x836f528), which calls the base
`initWithTask` vtable slot (+0x550); the permission check lives there.
The app's entitlements file lists `AppleAVE2UserClient` under
`com.apple.security.exception.iokit-user-client-class`, but free signing
strips that private exception entitlement, so stock iOS refuses the open.
**The AVE2 lane is therefore not reachable on the stock 12.** It can only
be exercised on the ldid/Dopamine rigs (11 22G100, mini 21D50), where the
writer exists but the PushBack sink was not matched.

## 27.0 T8150 (24A435/24A437): writer is UNCLAMPED, input mapped

24A435 and 24A437 AppleAVE2 are byte-identical (0 changed functions in the
mnemonic diff), so the 24A437 Ghidra project is valid for the 17.

Symbols on 24A435 (from `ipsw kernel sym` + the 27.0 signature set):

| Address | Symbol |
|---|---|
| `0x88e4c2c` | `HEVC_SPS::Write_seq_parameter_set_rbsp(HEVC_RPS*, AVE_SyntaxWriter*)` |
| `0x88b9670` | wrapper: `(writer, value, count)` → `0x88b94f8` |
| `0x88b94f8` | real WriteBits |
| `0x8839554` | `AVE_PSGen::Init(...)` |
| `0x88e45f4` | `HEVC_SPS` ctor: `memcpy(sps, src, 0x1c74)` |
| `0x88e4618` | `HEVC_SPS::Init` (writes +0x1fc/+0x218, never +0x1f4) |
| `0x879054c` | `AVE_Client_Verify` |
| `0x88d46d4` | `AppleAVE2UserClient::Prepare` |

**The writer has no lower-bound check.** 24A435 `0x88b94f8`:

```c
bitpos = *(int *)(writer + 8);              /* signed */
index  = (bitpos - 8) >> 3;                 /* arithmetic shift */
if (*(int *)(writer + 0x10) <= index)       /* upper bound only */
    return 0xfffffc05;
*(char *)(*(long *)(writer + 0x18) + index) = byte;   /* sxtw */
```

A negative bit position gives a negative byte index, passes the capacity
check, and lands before the buffer at `writer+0x18`.

**Correction (2026-11-09):** 27.2 does **not** clamp either. The 24B119
real WriteBits `0x88f39a4` has the same shape; its `cmp/csel` is
`(bitpos<0 ? bitpos+7 : bitpos) >> 3` rounding, not a lower bound. The
27.2 SPS caller `0x891f68c` does `ldr w8,[x20,#0x1f4]; add w2,w8,#4;
bl 0x88f3b1c` with no check. The old "27.x clamps" note was a misread.

### Input mapping (27.0)

```
IO_Prepare: AVE_Client_Prepare(ctx, in+0x18, in+0x228, in+0x338, in+0x28)
  settings = in+0x338
AVE_Client_Verify (encType 2):
  client+0x6228 <- settings+0x4348   (0x38e8)
  client+0x9b10 <- settings+0x7c30   (0x4300)
  client+0x3758 <- settings+0x1878   (0x2ad0)
  client+0xde10 <- settings+0xbf30   (0xbc8)
  client+0xe9d8 <- settings+0xcaf8   (0x5dd8)
AVE_PSGen::Init:
  HEVC_SPS layer 0 = ctor(heap, client+0x6228)       memcpy 0x1c74
  HEVC_SPS layer 1 = ctor(heap, client+0x6228+0x1c74)
```

`HEVC_SPS::Init`/`Generate` never rewrite +0x1f4, so:

**Prepare input +0x4874  →  HEVC_SPS+0x1f4** (layer 0)
layer 1 at **+0x64e8** (`+0x1c74` later).

This matches the macOS PoC's `request+0x487c → SPS+0x1f4` within 8 bytes.

### Remaining reachability question

The direct UC Prepare is denied (`IOServiceOpen` 0xe00002e2). Through
VideoToolbox, VT builds `settings` from session properties. The open
question is **which VT property maps to `settings+0x4348+0x1f4`**, and
whether it accepts a negative value. If it does, the underwrite is live on
the 17 through the VT path. Candidate properties: MaxFrameDelayCount /
AllowFrameReordering / NumberOfTemporalLayers / ExpectedFrameRate; the
field is in the SPS RBSP path, not the temporal-layer fill.
