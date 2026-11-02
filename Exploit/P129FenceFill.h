//
//  P129FenceFill.h — fence churn x the ANE fill battery, concurrent. p129.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface P129FenceFill : NSObject
/// The LAST cell in the fence co-driver grid. p127 (fence alone) and
/// p128 (fence x IOGPU-queue churn) are completed falsifications; the
/// twice-aborted 0x984faf8 append (2/2, abort PC 0x984fcc8, OUR fill-
/// staging sids in x5) actually fired while the 43748 fill battery was
/// live. This tap = thread A (p127/p128 fence churn + recycle) racing
/// thread B (the REAL P044 fill engine — mlmodel compile + ember/grammar
/// rounds, invoked as its one tap). Bounded wall clock. PANIC-POSSIBLE;
/// one tap per force-quit. Stage 3 = the honest KRW self-test.
+ (NSString *)tap;
@end

NS_ASSUME_NONNULL_END