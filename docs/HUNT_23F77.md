# 23F77 hunt — 2026-11-09 (iPhone 12, A14/T8101, iOS 26.5)

Kernel: xnu-12377.122.4~1 RELEASE_ARM64_T8101; flat law
`fileoff = VA - 0x7004000` for `__TEXT_EXEC`, `__DATA_CONST`, `__PPLTEXT`,
`__PPLDATA`. Ghidra: 23F77, base `0xfffffff007004000`.

## A14 protections — PPL + CTRR, no SPTM, no MIE

- **No SPTM.** No `__SPTM` segment; `sptm_gen3dart_*` are panic stubs
  (`0xa5f7be8`, "Unsupported function"). T8101 board config defines
  XNU_MONITOR/PMAP_CS without CONFIG_SPTM.
- **PPL is the protector.** `__PPLTEXT` 0xfffffff00a604000 (RX),
  `__PPLDATA_CONST` 0xfffffff007b8c000 (R),
  `__PPLDATA` 0xfffffff00a874000 (RW). PPL call gates, `pmap_ppl_*`,
  `MARK_AS_PMAP_DATA/TEXT`, "UAT PPL".
- **No MIE/MTE.** No `mteinfo`; the heap mitigation is kalloc_type + GZ
  (`zone_element_bounds_check`, `zone_require`).
- Kernel text is never writable (`ml_unsafe_kernel_text()` false; CTRR
  backstop); kernel_pmap W/X rejected ("PMAP_CS: attempted to allow W/X
  mappings on kernel_pmap").
- Trustcache and `pmap_cs` are PPL-resident (`ppl_trust_cache_rt`,
  `pmap_lookup_in_*_ppl`, `PMAP_CS_PPL_MONITOR`); kernel-side
  `__pmap_cs_runtime_*` are panic stubs.
- `kernproc` is `SECURITY_READ_ONLY_LATE` at `0xfffffff007b6eb30`
  (__DATA_CONST); the proc/ucred objects it points to are ordinary RW
  kernel heap. PPL does not protect them, but our lanes cannot address
  them.

**A kernel data write can change regular kernel data (kalloc data,
__DATA, proc/ucred, writable function tables) given a leak+address. It
cannot change text, PPL/PPLDATA, trustcache, page tables, IOMMU/DART
tables, or pmap_cs state.**

## ANE DART/UAT on A14

- `ANEHWDevice::dartMapMemoryDescriptor 0x876bbdc` takes an
  `IOMemoryDescriptor*`, gets an IODMACommand, `setMemoryDescriptor`
  (+0x88), `genIOVMSegments` (+0xb8), stores the IOVA.
- `IODARTMapper::iovmMapMemory 0x953e0d0` builds `{iova, pa = seg &
  ~0x3fff, len, 0}` from `getPhysicalSegment` (vtable +0x90).
- UAT is PPL-owned (`IOUnifiedAddressTranslator::init 0xa58aa14`,
  `ppl_iommu_state`, map gate `0x9f59f24`); DART page tables are PPL state
  (`AppleT8020DART::getPagetableMemory 0x8f16230`).
- Client supplies **sid/symbol/offset/size only**; the PA comes from the
  IOSurface's IOMD. `ANE_MemoryMapRequest_gated 0x874c7f4` resolves the
  sid via the global IOSurface lookup `0x9867c18`, checks owner/token,
  plane count and per-plane size, then DART-maps. DMA is confined to the
  surface planes.

## p044 on 23F77 — element-contained

- Gate `ANE_ProgramSendRequestInitialChecksAndLookups_gated 0x8745ed8`
  requires exact per-procedure counts and total <0x100.
- Writer `ANE_ProgramCheckandPrewireBuffers_gated 0x874c070`: object from
  kalloc_type view `0x7cc91d8`, `kt_size=0x820`, flags
  SHARED_ACCT|DATA_ONLY -> **data.kalloc.3072**, element 0xC00.
- Layout `{records[128] @0, stride 0x10; +0x800 programHandle; +0x808
  xid; +0x810 count; +0x814}`, alloc 0x820.
- Client args: in-count +0x1c, sids +0x20 (255), per-buffer u8 +0x41c,
  out-count +0x51c.
- **128 records = 0x800 (object); 192 = 0xC00 (element).** N=192 exactly
  fills the element; >192 crosses it and GZ panics. Records 128/129 are
  overwritten by the object's own metadata; 130..191 sit in element
  slack. Same-zone self-corruption only — no victim object, no read.
- Chosen-content 512 B: an output record names a sid; the ANE inference
  writes the output into that IOSurface plane backing (foreign if the
  lookup allows). Surface-granular; not kernel memory.

## Post-write verdict

| Step | On A14 26.5 from a kernel data write |
|---|---|
| Kernel text | No — PPL-owned PTEs, CTRR, PMAP_CS |
| Trustcache / AMFI | No — PPL data/lookup, entitlement-gated load |
| `pmap_cs` / CS fields | No — PPL-resident |
| kernproc / ucred | Yes in principle (RW heap), but no address lane |
| Page tables / DART | No — PPL-owned |

**No path from p044/AVE2 to `kread32(kbase)==0xfeedfacf`.** Closest read
doors are new bugs: ANE ProgramCreate argsOutput double-fetch/leak
(entitlement-gated on stock), programCreateParamsMapping parser, or a
kernel consumer of a client-writable IOSurface. AVE2's signed writer is
not reproduced on 23F77 (only the +8 bit-accumulator path; VT negative is
unproven pending the 26.5 ave.videoencoder analysis), and the direct UC
open is 0xe00002e2.

## Static diff 23F77 -> 24B119 (A14, 26.5 -> 27.2)

Kext versions: AVE2 905.36.1->913.64.1; AppleH11ANEInterface 9.511.3->
10.102.4; IOSurface 393.5.7->403.1; M2Scaler 265.0.0->265.0.0 (code
changed); IOHIDFamily 2.0.0->2.0.0 (code changed).

**AVE2 writer: nothing was clamped.** 23F77 SPS call `0x837fc3c ldr
w8,[x20,#0x1f8]; add w2,w8,#4; bl 0x835bdb8 -> 0x835bc60`. 27.2 A14 call
`0x857ac2c [x20,#0x1f4]; ... -> 0x854ef44`. The 23F77 writer has a
separate zeroed byte cursor at +0xc (signed cap check), so a negative SPS
count only moves the +8 bit accumulator; the 27.x writer computes
`(bitpos-8)>>3` and underflows. **Do not claim the P149 underwrite as a
26.5 bug;** it is a 27.x writer shape. The field moved +0x1f8 -> +0x1f4
but is unvalidated on both.

**23F77 fill loops (AVE_PSGen::Init 0x82ec254):** PS block base
`client+0x6144`, count `+0x5c34`; SPS L0 base `client+0x8df4`, count
`+0x8c00`; L1 base `client+0xac70`, count `+0xaa7c`. Blob offsets
(settings = Prepare in+0x338): PS `in+0x3bec/+0x36dc`; SPS L0
`in+0x689c/+0x66a8`; L1 `in+0x8718/+0x8524`. The value is encoder-derived
and bounded. The loop is `base[i*4] = value` for i<count, so a count above
the struct/client capacity is a heap OOB small-value write (a huge count
is a long loop/panic), not a writer underwrite.

**26.5 VT plugin is clamped.** The 26.5 encoder is
`/System/Library/Video/Plug-Ins/AppleVideoEncoder.bundle/AppleVideoEncoder`
(not the 27.0 VideoCodecs/ave.videoencoder). HEVC_SPS L0 = instance+0x5eac;
SPS+0x1f8 = instance+0x60a4, SPS+0xc = instance+0x5eb8.
- `log2_max_minus4`: `cmp w8,#0xc; b.hs` rejects unsigned >=12 (and
  negatives); stores value+1 (1..12) at 0x60a4.
- `LookAheadFrames`: negative rejected, 0..20 accepted (clamped to 20).
- `NumberOfTemporalLayers`: no setter upper bound, but the encoder core
  caps effective layers to 3/4 and writes SPS+0xc only for value >=2,
  value-1 <=3 (`0x106a98-0x106ab8`). Negative impossible.
So the VT path cannot deliver a negative SPS count or a chosen fill
index. The direct-UC type sweep (types 0-5; p148 0/1/2 = 2e2, 3-5
untested) remains the only AVE2 route on 23F77.

**Top 3 27.2 fixes still live on 26.5 (ranked by app reach):**

1. **IOSurface ready-byte listener race (p154).** 23F77 add
   `0x986ba54`, remove `0x986bb98`, teardown `0x986e1fc`; **no +0xf1 byte
   exists anywhere in the 23F77 kext.** Teardown clears +0xf0, removes
   the listener from `+0x440` (count `+0x408`), then notifies, with no
   mark preventing a concurrent re-add. 27.2 adds the +0xf1 gate
   (`0x9be5210`, returns 0xe00002d8), mark (`0x9be5494`) and teardown
   (`0x9bea414`). App reach: IOSurfaceRoot/shared-event listeners, no
   entitlement. Race class -> stale/UAF listener.
2. **M2Scaler — premise false; not a 23F77 memory-corruption lane.** The
   23F77 `0x8a2e57c` is a **histogram self-test** ("HistogramBinMode"),
   not the 24B119 `0x8dc40ac` per-stream scaler window/tile prepare; the
   static-diff pairing was a same-size mispair. The real 24B119 histogram
   twin is the function containing `0x8cf5334`. The 27.2 `+0x1414` active
   bitmap, HAL state fields, and queue-depth/backpressure/stale-flush
   logic have **no 23F77 counterpart** (exhaustive scan: no
   `[xN,#0x1414]`, no new strings). The older 23F77 enqueue `FUN_8acf088`
   is a different HW-FIFO bitmap with a `0x1e` slot cap, driven by the
   internal request path, not a client index. Reachable Scaler paths:
   sel6 histogram (`0xFA8` struct, count 2..1000, sid0/sid1, `+0xFA4`
   bit0; 0x620 kernel stack buffer; an engine-length overflow would be a
   canary panic with kernel-set length/source) and sel11 `0x288` kernel
   copyout (disclosure). No queue/arena primitive.
3. **IOHID 112515 bit-range check.** 23F77 matcher `0x9671ebc` (caller
   `0x969ac4c`) lacks the 27.2 checks at `0x99c9a74-0x99c9b4c` against
   the element bit-size/offset fields (+0x138/+0x110) and the +0x108/
   +0x110 equality checks. App reach is weaker (HID/peripheral event
   path); still an internal read, not a copyout.

### p154 in detail (23F77)

- UC is `IOSurfaceRootUserClient`, 0x148 B, type-isolated kalloc_type
  (`site.IOSurfaceRootUserClient`, flags 0x61); +0xd8 lock, +0xe8 root,
  +0xf0 armed byte, +0xf8 task, +0x108/+0x110/+0x118 surface array/count/
  token. Root is 0x4b8 B; notification node is `IOSurfaceNotifyRequest`
  0x60 B (links +0/8, port word +0x10, ids +0x18/+0x20, refcon +0x50,
  UC +0x58).
- Teardown `0x986e1fc`: if +0xf0, clear +0xf0; remove_map
  `0x986bb98`; clear surface owners; purge listeners `0x98699f4`
  (root+0x148 lock, unlink nodes with [node+0x58]==UC, release +0x10,
  free node); then super::free `0x986e280`.
- **Race:** a concurrent sel-0x11 insert (`0x986978c`) that takes
  root+0x148 after the purge's unlock and before super::free links a node
  with +0x58 = the dying UC. The UC is freed; the node survives (a second
  teardown cannot run because +0xf0 was cleared). A later surface
  use-count→0 notify `0x9858bc0 → 0x9869984 → 0x98722dc` locks the stale
  UC+0xd8 and reads the stale +0x108/+0x110/+0x118.
- 27.2 fix: detach sets `+0xf1` under the list lock
  (`0x9be5494`), add gate returns `0xe00002d8` if set (`0x9be5210`).
  23F77 has no +0xf1 byte.
- App reach: selector 0x11 (add) / 0x12 (remove), 0x18-byte struct,
  normal TABLE1, entitlement token 0. Trigger with
  `IOSurfaceDecrementUseCount`/last unlock.
- **Primitive:** stale-pointer UAF of the UC, not a refcount underflow.
  The node holds no retain; use is a read of the freed lock/array/token.
  The UC zone is type-isolated, so generic kalloc sprays cannot land;
  the only same-zone object is another IOSurfaceRootUserClient. Net:
  DoS/type-confusion, **not a self-contained KRW ladder**. The window is
  narrow (one lock interval at the tail of free) and requires
  IOServiceClose to overlap an in-flight method; validate on-device.
- **Follow-up (+0xd8 lifetime):** UC+0xd8 is a dedicated `lck_mtx_t`
  allocated at `0x986dcd4` from the lck_mtx zone and freed in the UC
  dealloc path (`0x986de80` → `0x986e024` free → `0x986e030` zero). The
  escaped node therefore produces a **second-order mutex-state UAF**
  (owner/waiters/interlock/ext; `lck_mtx_lock 0x9e1e8b0/0x9e1e8d8`), not
  just an array read. But the lck_mtx zone is kernel-initialized, so no
  arbitrary bytes; the effect is lock-state corruption/deadlock/panic
  (or ext deref) when the slot is recycled by another lock. If the UC
  slot is reclaimed by a new UC, +0xd8 is that UC's valid lock and the
  mutex UAF does not occur.
- **Escaped node:** the +0x10 port ref leaks at purge; a later UC at the
  same address triggers a duplicate-registration DoS/oracle
  (`0xe00002c9`); the node is freed once when a UC at that address is
  destroyed; no write path, no double-free. It is a permanent notify
  hook into the recycled slot.
- **No same-zone reclaim:** the UC's type string occurs only at site 32
  (`0x7f360b0`, 0x148, flags 0x61); no other record shares it, so only
  another IOSurfaceRootUserClient can reclaim it. Bound remains
  UAF/type-confusion + second-order lck_mtx UAF, DoS-grade.

Pending: M2Scaler PoC-shape agent (AVE2 VT/writer complete; p154 mapped).

## P073 desc-smash on 23F77 (design, not a kread yet)

- p073 v7g: 16 port descs extend the kmsg desc block to `body+0xC4`; the
  OOB record stream lands `body+0x64..0xC4` and overwrites descs 6..15.
- Fill record `{sid u32, flags u32, tail 0x1000000001}` → desc
  `{name=sid, pad=flags, type u16=0x0001 (OOL), disp u16=0}`. Clean port
  desc is `{type=0, disp=0x11}`.
- OOL address = `sid | (flags<<32)`. The 43748 `flags` is the **record
  index** (6..15 at the desc block), so the address is a **user VA**, not
  the kernel port pointer; the record also overwrites the port pointer.
- `p073_ool_probe`'s `vmread(addr)` is a userland read; a `kernelRange=YES`
  in a mapped user page is a false positive. Scan the **received message
  body** for the real OOL copy.
- To make it a kread: (a) find a +4 u32 that is user-controlled and set it
  to a kernel high half (0xfffffe00 / 0xfffffff0), or (b) find a 4/8-byte
  type-only write at `desc+8` that preserves the port pointer at `desc+0..7`.
  Full design: `docs/KRW_THEORY.md` §2.1.
