# DarkSword (GhostWave / P7) integration

Source: `research/p7-darksword-rce` (leaked kit, hostile - handle as
untrusted data). Claimed coverage iOS 18.4 - 26.5. This file is the
Lum1na integration record: chain map, newest module inventory, sanitization
contract, and the payload-adapter slot. Lum1na has NOT executed any of it.
The hunt device (iPhone 12, A14, 23F77, 26.5) is the intended target; the
rig (iPhone 11, 22G100, 18.6.2) is technically in the claimed range too but
already has KRW via cs2core and must not be gambled on Safari RCEs.

## 1. Chain map (three stages before kernel)

1. **RCE (WebKit/JSC)**: CVE-2025-43529-26 family. Per-version workers:
   `rce_worker_18.4/18.5/18.6/18.7/26.x/26.3/26.5.js` and
   `rce_worker_26.5_fixed.js` (140 KB, the newest fixed build). b3/DFG
   butterfly tricks. In-browser, same-process.
2. **sbx0 (sandbox escape to GPU process)**: CVE-2025-43518-26 family.
   `sbx0_main*.js`, `sbx0_main_26.js`, `sbx0_26.js`,
   `sbx0_26x_agx_offsets.js` (AGX offset table for the 26.x line). dyld4
   shared-cache + IPC escape, WebContent -> GPU Process.
3. **sbx1 (GPU-process r/w + PAC)**: `gpuRead64` (26 hits), `gpuWrite64`
   (26), `gpuFcall` (20), `gpuPacia` (18), `gpuPacib` (18) across the kit.
   Version files `sbx1_18.5/18.6/26.0/26.4.js` plus
   `sbx1_main/sbx1_main_new/sbx1_main_26/sbx1_built.js` (2.75 MB built
   bundle). PACIA/PACIB forging via the GPU context.
4. **LPE slot**: `${{LPE_64BITE}}` template interpolation in
   `sbx1_main*.js`. This is a JS payload slot that receives the gpu*
   primitives and is supposed to convert GPU-process r/w into KERNEL r/w.
   The kit ships no LPE payload - the slot is empty. That emptiness is the
   whole integration question (section 5).

New modules noted this pass (2026-10-14):

- `MigFilterBypassThread.js` (101 KB, webpack, `src/libs/Chain/Chain.js`) -
  MIG filter bypass thread, part of the sbx machinery.
- `variantD_26.js` - obfuscator.io string-array packed variant (a0_0xf3da
  table). Do not trust; unpack before reading.
- `pe_main.js` / `pe_worker.js` / `pe_worker_body.js` / `pe_vm.js` -
  post-exploitation main/worker/VM (870/800/896 KB).
- `chain_loader_26.js` / `loader_26_deploy.js` - 26.x chain loader with the
  offset table below.
- `c2_bootstrap.js` (114 KB) + `c2_agent.js` (235 KB) - HOSTILE.

## 2. The A14-A18 offset table (chain_loader_26.js) - LEADS, unproven

`__A14_A18_OFFSETS.ios18` claims, per its own comment, authoritative
disassembly evidence for A14/A15/A16/A17 Pro:

```
kernel_base  0xfffffff007004000   (matches our LabStaticBase for A14 23F77)
kernproc     0xfffffff007d2c258
current_proc 0xfffffff009e646d4
proc_find    0xfffffff00a2bbd44
proc_rele    0xfffffff0083a01e0
copyin       0xfffffff009daecb0
structs: proc_p_ucred 0x28  proc_p_pid 0x60   proc_p_task 0x08
         proc_p_csflags 0x24 ucred_cr_uid 0x18 ucred_cr_ruid 0x1c
         task_map 0x28  task_itk_space ...
```

Status for Lum1na: LEADS ONLY. These are another kit's claims. The
kernel_base matching our own static base is encouraging; every VA and
struct offset still needs our own Ghidra proof on the 23F77 kernelcache
before it enters the LabOff table. Cross-check queue: proc_p_csflags 0x24
and ucred_cr_uid 0x18 against the Dopamine info.c ladder we already use.

## 3. Delivery + LAB markers (templating inventory)

The kit is template-instrumented (found markers, hit counts):
`__LAB_ENC_PASS__` (15), `__LAB_DEVICE_UUID__` (8), `__LAB_FORCE_IOS__` (4),
`__LAB_FALLBACK_WORKERS__` (4), `__LAB_EXFIL_DOMAIN__` (4),
`__LAB_DELIVERY_HOST__` (4), `__LAB_EXFIL__` (3),
`__LAB_RECOMMENDED_WORKER__` (2), `__LAB_BAND__` (2).

Delivery supports a local web server via `__LAB_DELIVERY_HOST__`: serve the
sanitized chain from the Mac (or the lab app), open the page in Safari on
the target, the chain selects the worker by the device's iOS version
(`__LAB_FORCE_IOS__` can pin it).

## 4. Sanitization contract (mandatory before any lab use)

Strip outright (hostile / exfil):

- `keychain_copier.js`
- `photos_upload_v1.js`
- `telegram_v1.js`, `session_telegram.js`, `session_whatsapp.js`
- `c2_agent.js`, `c2_bootstrap.js`, `c2_probe.js`
- `channel_crypto_min.js`
- `pe_dbg_tcp.js` (debug beacon - audit before keeping)

Replace: `__LAB_EXFIL_DOMAIN__` -> local no-op sink;
`__LAB_DEVICE_UUID__` -> fixed lab string; `__LAB_EXFIL__` -> strip calls;
`__LAB_ENC_PASS__` -> lab-only value. Any unpacked `variantD_26.js` counts
as new untrusted input until audited.

Verification before first fire: the sanitized page must make ZERO non-local
network requests. Assert by serving from a host that only answers the local
interface and watching the Mac's server log.

## 5. The payload-adapter slot (open integration question)

The `{{LPE_64BITE}}` slot contract, as far as the kit shows: a JS payload
running in the sbx1 (GPU process) context, handed gpuRead64/gpuWrite64/
gpuFcall/gpuPacia/gpuPacib, expected to produce kernel read/write.

Our assets do NOT drop into it as-is:

- cs2core (ClearSword) is native C, in-app, socket UAF. It cannot run
  inside a JS-only RCE context.
- The sbx1 context is a GPU process: it can create sockets, but cs2's
  spray/UAF choreography (22528 sockets, ICMPv6 corruption, PCB scan) has
  never been exercised from that sandbox, and the GPU process may have
  socket quota/entitlement differences.
- The honest path: re-express the ClearSword socket-UAF as a JS LPE payload
  that uses the sbx1 primitives only for glue (if at all), OR use gpuFcall
  to reach a kernel function that mangles the inpcb path. Both are
  unproven. This is the recorded open question.

Integration plan staged in Lum1na (public shell keeps the MAP only):

1. p091 `darksword` tap: prints this chain map + the on-device worker
   selection for the rig/hunt osversion. Static, fires nothing.
2. Sanitized bundle: kept OUT of the repo (hostile provenance). The lab
   keeps it in `research/p7-darksword-rce` on disk only.
3. Marker test on the hunt device: serve sanitized page locally, Safari
   26.5, verify the chain reports sbx1 r/w with a benign marker write
   (e.g. read a known AGX struct) - no exfil, no LPE slot filled.
4. Only after 3 passes: prototype a minimal JS LPE payload against the
   slot, starting from the LEADS table in section 2.

## 6. Honesty lines

- DarkSword is a spyware kit first. Every module is untrusted until read.
- No LPE payload ships with it; kernel r/w via DarkSword on 26.5 is NOT
  established by anyone, including us.
- The kit claiming 18.4-26.5 does not mean our SKUs; workers are per-build.
- One failed tap does not close a CVE class; the same stays true for
  DarkSword claims we have not reproduced.