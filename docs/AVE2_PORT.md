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
