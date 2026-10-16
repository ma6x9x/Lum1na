#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/// CVE-2026-43748 occupancy write (254-in addchain → kalloc.3072).
/// Conversion PASSES only on forged descriptors / non-fill kptrs.
/// Occupancy HIT is not hasKread. Fat type-3 recv after fire is sealed.
@interface P044AksKaslrReach : NSObject
+ (NSString *)tap NS_SWIFT_NAME(tap());
@end

NS_ASSUME_NONNULL_END
