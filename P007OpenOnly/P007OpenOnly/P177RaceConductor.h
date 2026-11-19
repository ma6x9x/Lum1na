//
//  P177RaceConductor.h — the concurrent-race conductor for the LightSword lane. p177.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface P177RaceConductor : NSObject
/// The user's reproducible law on 24B156: OOB reads fire ONLY when the cskrw
/// (V23) lane and cs2 run simultaneously — the second concurrent racer doubles
/// the window density. This probe wires that INTO the chain instead of being
/// a manual double-tap:
///   1. IOSurfaceRoot open + the OG window objects (the anon/small/big surfaces
///      + the pc memory object), additive — existing race bodies untouched.
///   2. A SECOND race worker (the OG mach_vm_map FIXED|OVERWRITE loop, additive
///      code in this file) runs at the V23 cadence while the cs2 core scan runs.
///   3. cs2_run() itself (unchanged) with the concurrent flag set — the
///      free_thread/churn already live pre-spray.
/// Receipts: the cs2 chain rungs in cs2_krw_log.txt with [churn]/[lswarm]/[chain].
/// PANIC-POSSIBLE (race + window). One tap per force-quit, fresh boot law.
+ (NSString *)tap;
@end

NS_ASSUME_NONNULL_END
