// A12X_23H30_LabOffsets.h — iPad Pro A12X/A12Z (iPad8,*) / iPadOS 26.7.1 (23H30).
// UUID 24528F5B-614D-FED3-F58D-4A0ABE751057, xnu-12377.162.13.700.38~2,
// Darwin 25.6.0. Classic 0xfffffff0... VA space; AppleH11ANEInterface (not H16).
//
// Evidence (every row VA+insn cited):
//   findings/2026-11-20_a12x_23h30_pin_table.md (the companion decode — the
//   cs2-chain FIELD#s, the momentarius anchor row, the kernel symbols, the
//   IOGPU/IOSurface selector map) + PINS-23H30-iPad8_5.md (the OffsetHunter
//   pass — kernproc cross-verified at the same VA by both decodes).
// Twin law: 23G71/23F77 numbers were NEVER pasted; every FIELD# below is
// re-proved from kc23H30 bytes. Unslid VAs are 23H30-only.
//
// NOT re-derived on 23H30 (23G71 VAs do NOT transfer; cut per-row before use):
//   ANE CheckandPrewire/MemoryMap/alloc-type-desc layouts, AVE
//   ClientClose/SendAsync/EncType, AKS wvek overflow, AMFI
//   externalMethod/LoadTrustCache, pmap_cs_allow_invalid, IOGPU RAW_MD getter
//   (+0x90 FIELD# unverified), SYSMEM_MD_OFF 0x90, GMD_ELEMSZ 0xb0.
// 43748 patched in the 26.6+ trains. 64788 Facet A dead (fixed 23G82).
// PPL-only AfterKread (HOLD) — the momentarius port is the PPL stage.
//
#ifndef A12X_23H30_LabOffsets_h
#define A12X_23H30_LabOffsets_h

#define A12X_23H30_STATIC_BASE             0xFFFFFFF007004000ULL
#define A12X_23H30_KTEXT                   0xFFFFFFF009C90000ULL /* __TEXT_EXEC,__text 0x84194c */
#define A12X_23H30_ENTRY                   0xFFFFFFF009C98588ULL

/* ---- CS2 chain FIELD#s (all CONFIRMED identical to 23F77 on this build) ---- */
#define A12X_23H30_SO_PROTO                0x20u   /* in_pcballoc 0xfffffff00a030264 -> pr_mem_acct 0xa0 */
#define A12X_23H30_SO_PCB                  0x18u
#define A12X_23H30_SO_FAMILY               0x08u   /* AF_INET6 0x1e gate @ 0xfffffff00a030348 */
#define A12X_23H30_SOCKET_USECOUNT         0x23c   /* 336 text refs (23F77: 330) */
#define A12X_23H30_INPCB_LE_NEXT           0x20u
#define A12X_23H30_INPCB_LE_PREV           0x28u
#define A12X_23H30_INPCB_PCBINFO           0x38u   /* STP pair @ 0xfffffff00a0302e0 */
#define A12X_23H30_INPCB_SOCKET            0x40u
#define A12X_23H30_INPCB_GENCNT            0x78u
#define A12X_23H30_INPCB_ICMP6FILT         0x148u  /* rip6_attach str @ 0xfffffff00a12cf54 */
#define A12X_23H30_INPCB_NECP_ATTRS        0x178u  /* 0x178..0x198; resolver 0x200/0x208 */
#define A12X_23H30_INPCBINFO_IPI_ZONE      0x68u   /* kalloc_type_view* (NOT plain zone) */
#define A12X_23H30_PROTOSW_INPUT           0x28u   /* ip dispatch ldr @ 0xfffffff00a045a90 */
#define A12X_23H30_KTVIEW_NAME             0x10u   /* zv_name static cstring ptr */
#define A12X_23H30_KTVIEW_SIZE             0x2cu   /* inpcb kt_size 0x400 sanity read */

/* ---- kernel symbols ---- */
#define A12X_23H30_KERNPROC                0xFFFFFFF007B6ECE0ULL  /* both decodes agree (884 refs) */
#define A12X_23H30_KALLOC_TYPE             0xFFFFFFF009CEFF70ULL
#define A12X_23H30_KFREE_TYPE              0xFFFFFFF009D5C5A8ULL
#define A12X_23H30_KALLOC_DATA             0xFFFFFFF009CEF4C0ULL
#define A12X_23H30_KFREE_DATA              0xFFFFFFF009CEFDA4ULL
#define A12X_23H30_NECP_SET_SOCKET_ATTR    0xFFFFFFF009FA5A04ULL
#define A12X_23H30_IN_PCBALLOC             0xFFFFFFF00A030248ULL
#define A12X_23H30_UDBINFO                 0xFFFFFFF00A7A8790ULL   /* ipi_zone slot = +0x68 */
#define A12X_23H30_IP_PROTOX               0xFFFFFFF00A79C870ULL
#define A12X_23H30_INPCB_KT_VIEW           0xFFFFFFF007B78A70ULL   /* udp lane */
#define A12X_23H30_ICMP6FILT_KT_VIEW       0xFFFFFFF007B79030ULL   /* kt_size 0x20 */

/* ---- momentarius anchor row (the port's three edits are now concrete) ---- */
#define A12X_23H30_TASK_MAP                0x28u   /* PAC'd (0x5ef8); "task->map" */
#define A12X_23H30_VM_MAP_HDR              0x18u   /* 26.4+ move VERIFIED; first 0x18/last 0x20 */
#define A12X_23H30_VM_MAP_MIN              0x28u   /* was 0x20 pre-26.4 */
#define A12X_23H30_VM_MAP_MAX              0x30u   /* was 0x28 pre-26.4 */
#define A12X_23H30_VM_MAP_PMAP             0x58u   /* PAC'd (0x250c); vendored +0x40 is STALE */
#define A12X_23H30_VM_MAP_PAGESHIFT        0x44u   /* u16 = 14 on this 16K A12X */
#define A12X_23H30_KERNEL_MAP              0xFFFFFFF007B6B3D0ULL
/* 26.x fd layout: filedesc INLINED into proc — old proc.fd=0xE0/ofiles_start=0x20 STALE */
#define A12X_23H30_PROC_FD_BOUND           0xE4u   /* int; fd must be < this */
#define A12X_23H30_PROC_OFILES             0xF8u   /* fileproc** — PAC'd (div 0xac9d) */
#define A12X_23H30_PROC_OFILEFLAGS         0x100u  /* uint8_t* per-fd flags */
#define A12X_23H30_FILEPROC_GLOB           0x10u   /* PAC'd */
#define A12X_23H30_FILEGLOB_OPS            0x28u
#define A12X_23H30_FILEGLOB_DATA           0x38u   /* PAC'd */
#define A12X_23H30_PIPEPAIR_BUF_KVA        0x10u   /* PAC'd (0xab80); size u32 @ +0xc; sizeof 0x168 */
#define A12X_23H30_IOMACHPORT_OBJECT       0x20u   /* PAC'd (0xba96); sizeof(IOMachPort) 0x28 */
#define A12X_23H30_IPC_PORT_KOBJECT        0x50u   /* PAC'd (0x5a^kotype, addr-div port+0x50) */
#define A12X_23H30_IPC_SPACE_TABLE         0x48u   /* PAC'd (0xb8b5); ipc_entry 0x20 */
#define A12X_23H30_IOSURFACE_MD            0x30u   /* plain ptr; thunk @ 0xfffffff009722470 */
#define A12X_23H30_GVIRTBASE               0xFFFFFFF007B29D28ULL
#define A12X_23H30_GPHYSBASE               0xFFFFFFF007B2BD28ULL
#define A12X_23H30_GPHYSSIZE               0xFFFFFFF007AD67F0ULL
#define A12X_23H30_GPHYSEND                0xFFFFFFF007AF8020ULL
#define A12X_23H30_CPU_TTEP                0xFFFFFFF007AF8010ULL
#define A12X_23H30_PHYSWALK                0xFFFFFFF009E37144ULL /* phystokv w/ bounds panic */
#define A12X_23H30_GFX_ASC_RVBAR           0x206050000ULL /* DeviceTree/hw — NOT in kc (verified absent) */

/* ---- IOGPU copy27 lane (selector map CONFIRMED == 23G71 on this build) ---- */
#define A12X_23H30_IOGPU_UC_DEVICE         0x120u  /* 23G71 prior, not re-proven */
#define A12X_23H30_IOGPU_QUEUE_CREATE_SEL  6u
#define A12X_23H30_IOGPU_QUEUE_CREATE_SIZE 0x408u /* == expected && >= 0x408 (0xfffffff0094aa8ec) */
#define A12X_23H30_IOGPU_QUEUE_DESTROY_SEL 7u
#define A12X_23H30_IOGPU_QUEUE_SUBMIT_SEL  25u
#define A12X_23H30_IOGPU_QUEUE_SUBMIT_SCIN 4u
#define A12X_23H30_IOGPU_QUEUE_SUBMIT_SCOUT 1u
#define A12X_23H30_IOGPU_SEL36             36
#define A12X_23H30_IOGPU_SEL36_SCIN        3
#define A12X_23H30_IOGPU_SEL36_SCOUT       1
#define A12X_23H30_IOGPU_NEWCMDQ           0xFFFFFFF0094AA7ECULL
#define A12X_23H30_IOGPU_SUBMIT            0xFFFFFFF0094AAF04ULL
/* A12-family word1 leak prior +0x550 (XR 22H311; A14 0x558). Calibrate from
   word1 after sel=6 SUCCESS; do not chase PAC/slide if word1 is small. */
#define A12X_23H30_IOGPU_QUEUE_LEAK        0x550u

/* ---- kext band ---- */
#define A12X_23H30_IOSURFACE_UC_SELCOUNT   60u     /* table A 0xfffffff007f25768 (B: ...260c8) */
#define A12X_23H30_IOSURFACE_SEL17         0xFFFFFFF009740CECULL /* register_node; 24B; 0xe00002c2 */
#define A12X_23H30_IOSURFACE_REGNODE       0xFFFFFFF00973D9B0ULL
#define A12X_23H30_IOMFB_UC_SELCOUNT       59u     /* sel 81 OOR -> clean no-op on T8027 */

/* ---- ANE H11 entry VAs (OffsetHunter pass — RE-ready, layout UNDERIVED) ---- */
#define A12X_23H30_ANE_MEMORYMAP_GATED        0xFFFFFFF008702380ULL  /* impl */
#define A12X_23H30_ANE_MEMORYMAP_GATED_UC     0xFFFFFFF0086A8A00ULL  /* wrapper */
#define A12X_23H30_ANE_CHECKANDPREWIRE_GATED  0xFFFFFFF008701AB0ULL
#define A12X_23H30_ANE_MEMORYUNMAP_GATED      0xFFFFFFF00870589CULL  /* impl */
#define A12X_23H30_ANE_MEMORYUNMAP_GATED_UC   0xFFFFFFF0086A8C48ULL  /* wrapper */
#define A12X_23H30_ANE_PROGRAMCREATE_GATED    0xFFFFFFF0086EFF90ULL

/* ---- AppleM2ScalerCSCDriver 265.0.0 validator entry VAs (OffsetHunter pass) ---- */
#define A12X_23H30_M2_VALIDATE_MACROBLOCK     0xFFFFFFF008A17F6CULL
#define A12X_23H30_M2_VALIDATE_ADDRFMT        0xFFFFFFF00896803CULL
#define A12X_23H30_M2_VALIDATE_COMPTILE       0xFFFFFFF00896BF34ULL
#define A12X_23H30_M2_VALIDATE_DIMENSIONS     0xFFFFFFF008995FBCULL
#define A12X_23H30_M2_CHECK_ABERRANT          0xFFFFFFF008A2155CULL
#define A12X_23H30_M2_MAP_API_PARAMS          0xFFFFFFF008A284D4ULL

/* UNPROVEN on 23H30 (runtime p090 v2): allproc, pidhash(+mask),
   IOMemoryDescriptor field set (keep the audit's numbers), IOMFB sel
   12/4/19 semantics, IOGPU +0x550. */

#endif /* A12X_23H30_LabOffsets_h */
