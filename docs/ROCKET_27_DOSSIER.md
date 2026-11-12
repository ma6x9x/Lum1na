# Rocket / TTBR1 alias window — 17 (T8150, 24A435, xnu-13432.2.10~2)

Derived 2026-11-12 from the exact on-disk cache (Ghidra bridge program
"Darwin Kernel Version 27.0.0 … xnu-13432.2.10~2/RELEASE_ARM64_T8150").
This cache is NOT fully stripped: 167 named functions incl. the IOGPU UC,
IOUAT, AGX and the entire ANE stack. All addresses below are 24A435 VAs.

## User-client submit door
- `IOGPUDeviceUC_getTargetAndMethodForIndex` @ 0xa024d94
  - uc+0x100 bit0 must be set, else 0xe00002d8
  - selector > 0x37 → delegate method table via PTR_0x82fea78+0x550
  - dispatch tables live at 0x82f6708 / 0x82f6c48 (IOExternalMethodDispatch)
- `IOGPUDeviceUC_s_submit_command_buffers` @ 0xa02299c (selector 0x24)
  - structIn @ args+0x20: {u32 resourceId @+0, u64 count @+0x10, u64 cmdArgSize @+0x18}
  - no-OOL path: *(args+0x28)==4, scalarIn @0x30, structInSize @0x38
  - channel = FUN(uc+0x120, resourceId)          (owner table)
  - structInSize must equal count*cmdArgSize
  - cmdArgSize must equal *(chanState+0x260), chanState = [chan+0x530]
  - engine call: IOGPU_submit_state_loop(chan, cmdbufs, count, cmdArgSize, &out)
- `IOGPU_submit_state_loop` @ 0xa051654
  - state gate FUN_0a050604(chan[0xa6], chan); needs chan[0x85]&[0x91] live (real queue)
  - per-command FUN_0a051968(chan, entry); entry flag @ cmd+0x20
  - writes last state to *(chan[0xa6]+0x2e0)
- `IOGPUDeviceUC_QueueCreate` @ 0xa021ee8 = device-config getter (fields off [uc+0xf8])
- `IOGPUDeviceUC_sel26_single_resource` @ 0xa022c2c
- `IOGPUDeviceUC_deviceUserClientStart` @ 0xa024974

## Alias window (SPTM-era "MIT"/TTBR1 shared L2)
- `FUN_b3c31a0` = **IOUAT entry** (IOUnifiedAddressTranslator)
  - "gfx-shared-region-size" (u64), "gfx-shared-region-base" (ASC carveout)
  - "gfx-shared-l2-region-base" = **TTBR1 shared L2 table**  ← the alias table
  - "gpu-region-base" (TTBAT), "gfx-handoff-base" (GPU handoff region)
  - stores: DAT_b7b2c38 = shm base, DAT_b7b2c40 = TTBR1 L2, DAT_b7b2c50 = handoff
  - state object locks: PPL state lock, release thread lock, TTBR1 state lock
- `FUN_b3c507c` = IOUAT bring-up gating
  - DT `/arm-io/sgx`, props "gpu_iouat", `/chosen/gpu-iouat`, "iouat_debug"
  - mode globals DAT_b844290/…a80/…a90; calls FUN_ad6aca4 (DART shared-mode)
  - strings: "UAT SHARED_MODE_TTBR1", "ttbrIdx < 2"
- Region getters: FUN_b3c361c (u64 prop), FUN_b3c3764 (region base, logs
  "IOUAT %s:%d: *** Attempting to map %s", page-alignment + size checks)
- gfx keys seen: gfx-shared-region-base/size, gfx-shared-l2-region-base,
  gfx-handoff-base, gpu-region-base, gfx-tvm, gfx1-tvm, GFX_TVM/GFX1_TVM,
  GFX[1..4]-SRAM, /arm-io/gfx-asc, AGXGFXDVAccessor ("GFXDVA")

## ANE Stage-B (bonus, same cache)
- `ANE_find_task_from_pid` @ 0x8cb3288: pid 0 or proc_find miss → NULL → 2f0
- `ANE_stageb_pid_borrow(memdesc, pid)`: find_task → entitlement compare
  (`0x1a < (flags & 0xffff)` class) → "Cannot find task from the given pid"
- Full ANE stack named: ProgramSendRequest_UC, DoProgramCreate_UC,
  MemoryMapRequest_UC, record_clamp_attach, request_prep, dispatch_prep

## Remaining gaps (next decompiles)
1. IOExternalMethodArguments slot layout on 27.x — resolve from p143 v5
   device census rows (two candidate layouts).
2. Channel creation/configuration selector map (the dispatch arrays at
   0x82f6708/0x82f6c48 cannot be dumped via the bridge; use xrefs from
   handler addresses + p143 rows).
3. How a userland map op reaches IOUAT TTBR1 insertion (AGX map selectors →
   IOGPU memory descriptors → DVA → IOUAT) — the actual alias write.
4. cmdbufArgSize config write at chanState+0x260 (config selector).
