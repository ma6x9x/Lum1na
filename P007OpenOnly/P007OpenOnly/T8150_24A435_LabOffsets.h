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
/* NOTE 232 (2026-10-21): the 0x…8C16A88 pin was STALE for the fresh 24A437
   cache — real CheckandPrewire = 0xFFFFFE0008C5C3E4, re-anchored via the
   klog string xref ("[ERROR] %s: %s: MemoryMapRequest for %u buffers,
   result: %d" @ 0xfffffe0007436a72 ← param in the writer). */
#define T8150_24A435_ANE_CHECKANDPREWIRE    0xFFFFFE0008C5C3E4ULL
#define T8150_24A435_ANE_MAPLOCKED          0xFFFFFE0008C17190ULL
#define T8150_24A435_ANE_MAPREQUEST         0xFFFFFE0008C19708ULL
#define T8150_24A435_ANE_MAPALLOC           0xFFFFFE0008C0D324ULL
#define T8150_24A435_ANE_ALLOC_SIZE         0x10B8u
#define T8150_24A435_ANE_ALLOC_CLEAR        0x10A0u
#define T8150_24A435_ANE_RECORD_OFF         0x90u
/* Trailer at +0x1080 (beta-4 decompile; 0x90+255*16). 254-in = 255 records = in-bounds. */
#define T8150_24A435_ANE_TRAILER_OFF        0x1080u
#define T8150_24A435_ANE_TABLE_ENTRIES      255u

#endif /* T8150_24A435_LabOffsets_h */
