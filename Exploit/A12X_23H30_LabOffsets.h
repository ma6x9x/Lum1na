// A12X_23H30_LabOffsets.h — iPad Pro A12X (T8027/T8020 tag) / iPadOS 26.7.1, 23H30.
// Supersedes the FIELD#-only row for the 23H30 SKU. PROVEN pins only — every
// value below was located by signature in the 23H30 binary (findings file:
// PINS-23H30-iPad8_5.md, cross-checked against ios-xnu-hunt findings when the
// companion decode lands). UNDERIVED stays absent — never paste T8150/24B156
// or 23G71 unslid VAs onto this build.
//
// PROVEN (2026-11-20, Ghidra 12.1.2, com.apple.kernel fileset entry,
//         xnu-12377.162.13.700.38~2, Darwin 25.6.0):
//   STATIC_BASE 0xfffffff007004000 — outer fileset __TEXT vmaddr (the classic
//     A12-era base; NOT the T8150 0xFFFFFE00... space).
//   KERNPROC 0xfffffff007b6ece0 — ~894 ADRP+LDR refs; the "p != kernproc"
//     assert (skywalk_kill_process 0xfffffff00a266b60) and both "so != NULL
//     || p == kernproc" sites; sole STR at task_init 0xfffffff009d26460.
//
// ANE = AppleH11ANEInterface (NOT H16; the gated-method entry VAs are pinned
// below for RE — the H11 LAYOUT constants are UNDERIVED: no 0x10b0 u32 in the
// H11 __kalloc_type; 0x18a8 appears but is NOT sealed as the map-object size
// without store-block RE). M2 validator entry VAs pinned for the diff lane.
// The ANE fill/table fields stay 0/1 (ane_fill_cap) — 43748 is patched in the
// 26.6+ trains; these VAs are RE targets, not lane activations.
//
// PENDING (companion decode, in flight): the cs2-chain struct pins (socket
// so_proto/so_pcb/so_usecount, inpcb le_next/pcbinfo/socket/gencnt/icmp6filt,
// inpcbinfo.ipi_zone, kalloc_type_view name, protosw.input) and the
// momentarius anchor row (vm_map.pmap with the 26.4+ hdr movement, task.map,
// IOMachPort.object, ipc_port.kobject, ipc_space.table, IOSurface ranges).
// cs2/copy27 on this SKU HOLDs until those land (the kernel-VA-probe law).
//
#ifndef A12X_23H30_LabOffsets_h
#define A12X_23H30_LabOffsets_h

/* ---- kernel symbol layer (PROVEN) ---- */
#define A12X_23H30_STATIC_BASE       0xFFFFFFF007004000ULL
#define A12X_23H30_KERNPROC          0xFFFFFFF007B6ECE0ULL

/* ---- ANE AppleH11ANEInterface entry VAs (PROVEN; RE-ready, not lane-ready) ---- */
#define A12X_23H30_ANE_MEMORYMAP_GATED        0xFFFFFFF008702380ULL  /* impl */
#define A12X_23H30_ANE_MEMORYMAP_GATED_UC     0xFFFFFFF0086A8A00ULL  /* wrapper */
#define A12X_23H30_ANE_CHECKANDPREWIRE_GATED  0xFFFFFFF008701AB0ULL
#define A12X_23H30_ANE_MEMORYUNMAP_GATED      0xFFFFFFF00870589CULL  /* impl */
#define A12X_23H30_ANE_MEMORYUNMAP_GATED_UC   0xFFFFFFF0086A8C48ULL  /* wrapper */
#define A12X_23H30_ANE_PROGRAMCREATE_GATED    0xFFFFFFF0086EFF90ULL

/* ---- AppleM2ScalerCSCDriver 265.0.0 validator entry VAs (PROVEN) ---- */
#define A12X_23H30_M2_VALIDATE_MACROBLOCK     0xFFFFFFF008A17F6CULL
#define A12X_23H30_M2_VALIDATE_ADDRFMT        0xFFFFFFF00896803CULL
#define A12X_23H30_M2_VALIDATE_COMPTILE       0xFFFFFFF00896BF34ULL
#define A12X_23H30_M2_VALIDATE_DIMENSIONS     0xFFFFFFF008995FBCULL
#define A12X_23H30_M2_CHECK_ABERRANT          0xFFFFFFF008A2155CULL
#define A12X_23H30_M2_MAP_API_PARAMS          0xFFFFFFF008A284D4ULL

#endif /* A12X_23H30_LabOffsets_h */
