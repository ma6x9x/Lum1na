//
//  P078AneYcraft3.h
//  P007OpenOnly
//
//  P078 — 43748 y-craft on a 3-INPUT model (all-valid input records).
//
//  Ghidra-locked mechanics (cve43748_ANE_MemoryMapRequest_gated @ 23F77,
//  decompile bee5f818, 2026-10-09):
//    - Request entries are {sid=field[0], symbolIndex=field[1], type=field[3]}
//      (1=input, 2=output). The surface fetch is keyed by THE ENTRY'S sid
//      (FUN_fffffff0087b1af0 cache -> FUN_fffffff009867f18(dev+0x3c0, sid)).
//    - FIRST BAD RECORD ABORTS THE WHOLE REQUEST ("Input IOSurface for
//      surface-Id: %d is nullptr" -> 0xe00002c2). P077's crafts both died at
//      their bad INPUT records — the output record was never reached, so the
//      y-craft was NOT disproven, only blocked at the front door.
//    - The output record is processed by the SAME pattern: fetch by the
//      output entry's sid. P073 proved the client fill reads STAGED INPUT
//      CONTENT into the entry sids; the output entry sid is hypothesized to
//      be the OUTPUT staging content = the PREVIOUS PREDICT'S Y.
//
//  P078 uses XVRC27_3in_1out so ALL input records can be valid:
//    find live sids (a,b,c) with a+b+c == sid_C (repeats allowed).
//    Craft-A (value-decode world): x = (a, b, c) -> y == sid_C exactly.
//      Next predict: output entry sid = fp16_value(staged y) = sid_C
//      -> capture surface fetched + wired -> ANE writes into it.
//    Craft-B (raw-bits world): x = (a*2^-24, b*2^-24, c*2^-24) — fp16
//      subnormals whose BITS are a, b, c -> y bits == sid_C. Requires
//      a,b,c <= 1023 (subnormal mantissa max 0x3FF).
//
//  Oracles:
//    capture bytes != 0x53          -> WRITE DOOR (own target this tap).
//    y == 0.0 after a valid-input craft -> the ANE RAN and read OUR wired
//                                     surfaces (fp32 1.0 bytes = fp16 0.0)
//                                     = READ DOOR + buffer-cache HIT proof.
//    y == 3.0                       -> ANE read our surfaces as fp32.
//    y == sid_C / vB exact          -> CPU fallback (request aborted or
//                                     never reached the ANE).
//  Interpretation: capture touched = wire + compute both fired. Capture
//  untouched with y==0.0 = ANE ran but output entry sid != staged content.
//  Capture untouched with y==sid_C = aborted before compute (output entry
//  sid garbage or entry not staged-content-derived).
//
//  Honesty: own surfaces only; foreign sids are Stage B. Conversion bar
//  (desc_type_forged OR (body_forged AND kptr)) untouched. hasKread=NO
//  hasKwrite=NO. ONE TAP per force-quit. Per-line POSIX write+F_FULLFSYNC.
//

#import <Foundation/Foundation.h>

@interface P078AneYcraft3 : NSObject
+ (NSString *)tap;
@end