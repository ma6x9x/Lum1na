//
//  P127FencePress.h — the fence-list pressure + KRW self-test. p127.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface P127FencePress : NSObject
/// The 0x984faf8 fence-append lane as a device test (23F77/26.5, the 12).
/// Stage 0 = gate + ident. Stage 1 = dlsym fence census (userspace fence
/// exports). Stage 2 = IOSurface-backed Metal blit churn on OUR sids with
/// periodic surface recycle (drain-walker 0x985c5fc + append 0x984faf8
/// regrowth exercised at rate; the twice-aborted fence-list range checks
/// now in the hot path). Stage 3 = the honest KRW SELF-TEST via the
/// P007KreadLane pickers (kread32(kbase)==0xfeedfacf). PANIC-POSSIBLE;
/// one tap per force-quit.
+ (NSString *)tap;
@end

NS_ASSUME_NONNULL_END