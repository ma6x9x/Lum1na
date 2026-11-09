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

**Top 3 27.2 fixes still live on 26.5 (ranked by app reach):**

1. **IOSurface ready-byte listener race (p154).** 23F77 add
   `0x986ba54`, remove `0x986bb98`, teardown `0x986e1fc`; **no +0xf1 byte
   exists anywhere in the 23F77 kext.** Teardown clears +0xf0, removes
   the listener from `+0x440` (count `+0x408`), then notifies, with no
   mark preventing a concurrent re-add. 27.2 adds the +0xf1 gate
   (`0x9be5210`, returns 0xe00002d8), mark (`0x9be5494`) and teardown
   (`0x9bea414`). App reach: IOSurfaceRoot/shared-event listeners, no
   entitlement. Race class -> stale/UAF listener.
2. **M2Scaler submit/queue guards.** 23F77 `0x8a2e57c` (453 insn);
   27.2 `0x8dc40ac` adds an entry active-bitmap gate on service+0x1414
   (`0x8dc40b0-0x8dc40b8`, returns 5), window/clamp checks
   (`0x8dc4600-0x8dc4678`), and queue-depth/backpressure/stale-flush
   strings. 23F77 has no `+0x1414` field and none of those checks. App
   reach: the Scaler UC opens with no entitlement; types {6,7,8,11} and
   selectors 6/7/8/11 are reachable.
3. **IOHID 112515 bit-range check.** 23F77 matcher `0x9671ebc` (caller
   `0x969ac4c`) lacks the 27.2 checks at `0x99c9a74-0x99c9b4c` against
   the element bit-size/offset fields (+0x138/+0x110) and the +0x108/
   +0x110 equality checks. App reach is weaker (HID/peripheral event
   path); still an internal read, not a copyout.

Pending: 23F77 AVE2 VT/writer (26.5 ave.videoencoder clamps) and the
IOSurface/Scaler PoC-shape agents.
