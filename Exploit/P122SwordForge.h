//
//  P122SwordForge.h — the combined 64788-class KRW test harness.
//  Unique build law (2026-10-25): one tap = one chain attempt:
//    [freer P009] -> [same-CPU magazine reclaim] -> [sel36 freed-slot read]
//    -> [assign_shared_ptr consumer via our own surface] -> honest KRW gate.
//  Honesty: no kread claim without a copyout of kernel bytes we did not write.
#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface P122SwordForge : NSObject
/// Runs the combined chain once. Returns the full log body.
+ (NSString *)tap;
@end

NS_ASSUME_NONNULL_END