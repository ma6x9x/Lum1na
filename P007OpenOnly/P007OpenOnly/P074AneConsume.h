//
//  P074AneConsume.h
//  P007OpenOnly
//
//  CVE-2026-43748 consume probe v3: compute-units timing discriminator on
//  the 127-in addchain. Three arms, fresh (sid,symbolIndex) windows each:
//    A cpuOnly real sids  -> pure-CPU y/t baseline
//    B All real sids      -> y oracle (staging sum vs surface-byte sum) + t
//    C All bogus sid      -> kernel-abort + CPU-fallback detector + t
//  H1 = kernel attempted every predict (v1 consumed real sids; v2 control
//  y=inf was a fallback). H2 = pure CPU, kernel never attempted.
//  Timing deltas vs A decide. y == surface-byte sum on B = consume PROVEN.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface P074AneConsume : NSObject
+ (NSString *)tap NS_SWIFT_NAME(tap());
@end

NS_ASSUME_NONNULL_END