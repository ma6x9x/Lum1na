//
//  P119StaleUpl.h — the T020 stale-UPL port (note 282, reopen #3 of note 283). p119.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface P119StaleUpl : NSObject
/// Stage0 wire×replace calibrate → Stage1 re-ordered race (detach-idle →
/// wirer commit → replace) → Stage2 staging oracle → Stage3 reclaim-spray
/// physical-reuse receipt. PANIC-POSSIBLE; one tap per force-quit.
+ (NSString *)tap;
@end

NS_ASSUME_NONNULL_END