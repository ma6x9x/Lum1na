//
//  P136RouteC.h — ROUTE C: fence churn × the stale-GVA reclaim kick. p136.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface P136RouteC : NSObject
/// Route C = the aimable-write experiment: the b1b2 engine (getter-pinned
/// GVA/LEN/OFF record law) holds a kernel-side GPU mapping bound to OUR
/// pages; phase2 drops Metal and sprays 0x4000-class pages (0xCC marker);
/// phase3 fires the latched kick; phase4 verifies which page reclaimed
/// the block. This probe runs ALL FOUR phases with the p127 fence churn
/// thread LIVE for the whole session (the third reclaim window meets
/// the delayed-abort condition). Oracles: any phase4 non-own reclaim =
/// the stale GVA maps a non-our page = the aimable-write candidate
/// LIVE; a 0x984fcc8-band panic = the fence window on top. PANIC-
/// POSSIBLE; one tap per force-quit; honest tail.
+ (NSString *)tap;
@end

NS_ASSUME_NONNULL_END