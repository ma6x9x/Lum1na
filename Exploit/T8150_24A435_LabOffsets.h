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

#endif /* T8150_24A435_LabOffsets_h */
