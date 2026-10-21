//
//  P106JPEGTeardownOracle.h
//  The P058-extension (note 234): the +0x30==0 early-teardown two-call oracle.
//
//  Ghidra 23F77: AppleJPEGDriver_startDecoder (0x8b78fc) tests the input
//  struct's +0x30 (u32 idx 0xc = the input-surface pair) == 0 → the
//  early-teardown branch, which STILL dispatches the decoder work with
//  different pool data (the "both branches dispatch" shape). The request
//  object = IOMallocType(&DAT_7d16a70) — the JPEG view's static decode:
//  **site.JpegRequest, element 0x458 (1112 B), ktflag 0x64** (guarded-zone
//  family — NOT the ANE record-area's 0x6c KT_DATA_ONLY), typecode
//  1122211111111122.
//  Field map (u32-index → req field): [0]+0x2ac [2]+0x2b0 [3]+0x324
//  [5]+0x65/0x66(dup,byte+0x28) [9]req0x6a [0x12]+0x438 [0x13]+0x37c;
//  +0x344 = subsampling FSM (unknown-mode aborts cleanly).
//
//  Oracle: sel5 (the decode request) round 1 with the struct's +0x30=0
//  (surface omitted) vs round 2 (control, +0x30 still 0 but repeated
//  completion) — request shapes + outSc/outsz census + verdicts.
//  Bounded: 2 requests, no fuzz, no fires. hasKread unchanged.
//

#import <Foundation/Foundation.h>

@interface P106JPEGTeardownOracle : NSObject
+ (NSString *)tap;
@end