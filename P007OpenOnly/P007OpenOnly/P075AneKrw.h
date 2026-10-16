//
//  P075AneKrw.h
//  P007OpenOnly
//
//  CVE-2026-43748 KRW probe v1 (SAFE stage — every target is our own surface).
//
//  Mechanism (Ghidra, 23F77): CheckandPrewire fills {sid, symbol, flags}
//  records where sid = the STAGED INPUT CONTENT (the 43748 type confusion —
//  P073 proved armed x values appear 1:1 as record sids). Count = inputs +
//  output (128-in failed = 129 > 0x80; 127-in passed = 128). The OUTPUT
//  record's sid = the output staging surface's recycled CONTENT — garbage so
//  far, which is why every consume aborted at the output record and CoreML
//  fell back to CPU (v2 y=inf, v3 arm C; InitialChecks only rejects sid==0).
//
//  P075 grooms the IOSurface allocator with u32 = our capture surface's id,
//  fills the 127 input surfaces with fp32 1.0, then predicts XVRC27_127in:
//    y == 127.0 (exact)      -> ANE read OUR surface bytes (consume feeds
//                               the compute) — kernel cross-process READ door
//    y == fp16 staging sum   -> compute reads staging; wiring unused
//    y == inf / fallback sum -> output record still aborts (groom missed)
//    capture surface bytes changed -> ANE WROTE through the groomed output
//                               record — kernel WRITE primitive (own target)
//  No overflow anywhere (128 records = 0x800 < 0xC00). Foreign sids are NOT
//  used in this build (own surfaces only) — Stage B gates on these results.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface P075AneKrw : NSObject
+ (NSString *)tap NS_SWIFT_NAME(tap());
@end

NS_ASSUME_NONNULL_END