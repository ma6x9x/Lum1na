//
//  P145Composition.h — the COMPOSITION probe (p142 stage9 fill session
//  INSIDE the live p027-class spray + the overshoot discriminator). p145.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface P145Composition : NSObject
/// The COMPOSITION row: the p142 stage9 AVE2 temporal-layers fill
/// session (EncoderUsage=1, RCMode-20 refused-allowed, RealTime=FALSE,
/// HEVC 1280x720, 4-frame battery, then invalidate) composed INSIDE a
/// LIVE spray — stage 1 = 64 IOSurface-backed Metal buffers (0x4000
/// class, marker 0x41) plus a separate 16-surface marker group
/// (marker 0x53), created, filled and HELD for the whole tap; stage 2
/// = the fill session on a second thread while the spray stays live;
/// stage 3 = the overshoot DISCRIMINATOR: every held allocation's
/// bytes scanned against its own fill marker (0x41-group and
/// 0x53-group separately); a foreign-value byte = the OVERSHOOT
/// RECEIPT row (counts + byte class only, never a raw dump).
/// The count knob = Documents/p142_layers.txt; the composition's
/// DEFAULT 8 = an in-bounds count for the composition row.
/// HONESTY: PANIC-POSSIBLE badge; composition forbids the panic
/// counts (16462/163/16464-class) — the guard SKIPS those with the
/// honest line; a foreign-value row = receipt-class evidence of a
/// write we did not author, NEVER a KRW claim; hasKread stays
/// kread32-gated. One tap per force-quit.
+ (NSString *)tap;
@end

NS_ASSUME_NONNULL_END