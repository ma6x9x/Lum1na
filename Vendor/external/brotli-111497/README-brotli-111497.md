# CVE-2026-111497: Brotli BlockSwitch OOB Write — PoC

Reproducer for the Brotli decoder out-of-bounds write tracked as **CVE-2026-111497**, fixed by Apple in iOS 27.2.1. Apple's security advisory lists **no external researcher credit** for this issue (internally discovered).

The same underlying Brotli library flaw was fixed upstream in Google Brotli **1.2.1** ([GHSA-9v8h-qqgm-4m35](https://github.com/google/brotli/security/advisories/GHSA-9v8h-qqgm-4m35), commit `0ed4268a`, affecting Brotli 1.0.3–1.2.0). Apple's fix is a backport of the upstream change. This repository provides a trigger generator and a two-stage decode harness used to reproduce the issue against Apple's bundled `libcompression` Brotli decoder on macOS and iOS — including the CFNetwork `Content-Encoding: br` response-decoding path on iOS 27.0.1.

## Root cause

BlockSwitch commands are accepted for the literal, command and distance block categories even when `num_block_types < 2`. A crafted second-stage stream then supplies block-switch values that corrupt the decoder's output position tracking, and the fast-path backward-reference copy in `ProcessCommandsInternal` performs an out-of-bounds `memmove16`/copy relative to the output ring buffer:

```
dst = ringbuffer + pos   (pos = attacker-corrupted int32)
src = ringbuffer content (attacker-controlled decoded data)
len = attacker-influenced copy length
```

Upstream 1.2.1 rejects these BlockSwitch commands with `BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH` (-17). Vulnerable builds return success and continue decoding with the corrupted state.

## Apple patch diff (iOS 27.2 24B119 → iOS 27.2.1 24B156)

Instruction-level diff of Apple's bundled `libcompression` Brotli decoder:

- The six BlockSwitch functions (fast/safe × literal/command/distance) each grow by 12 bytes. Before applying a block switch they now load `num_block_types[i]` (struct offsets `0x11c` / `0x120` / `0x124`), compare it against 2, and fail with the new error code **-17** (`BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH`) when fewer than two block types are defined.
- Vulnerable builds instead return success (`mov w0, #0`), which the callers misinterpret as "needs more input" — this is what lets the corrupted state persist instead of aborting the stream.
- `BrotliDecoderErrorString` grows by 36 bytes (error table extended to 34 entries) and gains the new `"BLOCK_SWITCH"` string; `ProcessCommands` grows by 76 bytes and `SafeProcessCommands` shrinks by 20 bytes.
- The patched code is an exact backport of upstream commit `0ed4268a` (Brotli 1.2.1).

Verified across firmwares by disassembling the extracted `libcompression.dylib` from each DSC: 24A446 (27.0.1) vulnerable, 24B119 (27.2) vulnerable, 24B156 (27.2.1) patched, 24C5037i (27.3 beta 1) still vulnerable.

## Files

| File | Purpose |
|---|---|
| `gen_trigger.c` | Two-stage trigger generator (`wbits body d15 d19 d23 b7 out_prefix`) |
| `decode_harness.c` | Decode harness feeding stage 1 in 64 KiB chunks, then stage 2 |
| `trigger_w13_first.bin` | Sample stage 1 (window bits 13, ~23 MB) |
| `trigger_w13_second.bin` | Sample stage 2 (127 bytes) |

## Build

Against a brotli **1.2.0** source tree built with AddressSanitizer:

```sh
cc -fsanitize=address -g -O1 decode_harness.c \
   -I /path/to/brotli-1.2.0/c/include \
   /path/to/brotli-1.2.0/build/libbrotlidec.a \
   /path/to/brotli-1.2.0/build/libbrotlicommon.a \
   -o decode_harness
```

## Reproduce

```sh
./decode_harness trigger_w13_first.bin trigger_w13_second.bin
```

Expected: AddressSanitizer reports an invalid write in `memmove16` (decode.c), called from `ProcessCommandsInternal` — the corrupted `pos` makes `dst = ringbuffer + pos` point outside the ring-buffer allocation.

For the crash to fire, the two stages must arrive as **separate decoder inputs**: stage 1 is fully consumed first (decoder parks waiting for more input), stage 2 then drives the corrupted block-switch path. Concatenating both stages into a single buffer does **not** crash. This mirrors network delivery, where the two parts of the response body arrive in separate chunks — which is why the issue is reachable through HTTP `Content-Encoding: br` decoding.

Also reproduced on real devices: iOS 27.0.1 (24A446) through the system network stack (CFNetwork → `libcompression`) when a URL session receives a `Content-Encoding: br` response.

## Affected / fixed

| Component | Status |
|---|---|
| Google Brotli 1.0.3 – 1.2.0 | Vulnerable |
| Google Brotli 1.2.1 | Fixed (upstream commit `0ed4268a`) |
| Apple libcompression (iOS 27.0.1 / 24A446) | Vulnerable |
| Apple libcompression (iOS 27.2 / 24B119) | Vulnerable |
| Apple libcompression (iOS 27.2.1 / 24B156) | Fixed |
| Apple libcompression (iOS 27.3 beta 1 / 24C5037i) | Vulnerable |

## Disclaimer

For security research and education only. This is a memory-corruption reproducer (crash / OOB write demonstration), not a weaponized exploit.
