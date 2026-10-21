//
//  P107AveWrapDims.h
//  AVE2 int32-wrap-dims probe (notes 233/240 — the p066-followup).
//
//  Static (23F77): AVE_CalcBufSizeOfCodedData 0x8216170; its multiply
//  helper AVE_MulDimsBitDepth 0x8240968 = plain int32 w*h*(bytes+pad>>3)
//  with ZERO overflow checks; the caller's `iVar3 * 10` wraps too. The
//  wrap -> undersized coded-data allocation -> the encoder writes
//  compressed output past it = userland-triggered kernel heap overflow
//  with frame content (the advisory 65410/84616 family's shape).
//  128x128 (p066's tap) stays in-range by design.
//
//  This tap: VTCompressionSessionCreate at 16384x16384 (the wrap dims —
//  w*h*10 > 2^31) vs 16384x8192 (control, no wrap). ONE encode attempt on
//  the wrap session only; NO fuzz; PANIC POSSIBLE (fresh boot, isolate).
//  hasKread unchanged.
//

#import <Foundation/Foundation.h>

@interface P107AveWrapDims : NSObject
+ (NSString *)tap;
@end