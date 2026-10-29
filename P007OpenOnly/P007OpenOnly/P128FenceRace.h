//
//  P128FenceRace.h — fence churn x IOGPU queue churn, concurrent. p128.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface P128FenceRace : NSObject
/// The co-driver race: the 2/2 fence-append aborts (note 288/289, OUR
/// sids in x5) happened with fence teardown concurrent with allocator
/// churn. p127 established fence churn ALONE is clean (3x ~21k commits,
/// 3x ~670 recycles, zero panics). This tap reproduces the CO-DRIVER
/// condition: thread A = IOSurface-backed Metal blit churn + surface
/// recycle (the fence teardown/drain/append path), thread B = P040-ABI
/// IOGPU QueueCreate/destroy ping-pong at full rate. Bounded wall clock;
/// PANIC-POSSIBLE; one tap per force-quit. Stage 3 = the honest KRW
/// self-test (kread32 receipt only).
+ (NSString *)tap;
@end

NS_ASSUME_NONNULL_END