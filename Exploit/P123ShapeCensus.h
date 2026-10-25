//
//  P123ShapeCensus.h — the Shape-L census (measure-then-replicate instrument).
//  Vehicle law: the MAIN app + libkrw on the 12 mini (A14/17.3, Dopamine) —
//  the only A14-family lane with LIVE KRW, so kalloc.3072 victims are
//  MEASURED kernel-side, not guessed. Every value this tap prints feeds the
//  groom construction on the hunt 12 (23F77) / 17 (24A435).
//  The 43748 record-OOB fingerprint law: records = {sid u32}{flags=u8 0xcN
//  band}{tail u64 0x1000000001} landing at victim+0 in kalloc.3072 chunks.
#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface P123ShapeCensus : NSObject
+ (NSString *)tap;
@end

NS_ASSUME_NONNULL_END