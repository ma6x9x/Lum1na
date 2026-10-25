#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/// LightSwordKRW — v1 harness weld (2026-10-24).
/// The calib's PROVEN race stack (5 WRONG crossings on 24A435 tonight, never
/// wedged) driving cs2's socket payload: fileport icmpv6 spray + gencnt
/// identity, live inpcb churn during races, and cs2_find_and_corrupt parsing
/// every capture for our own pcb; on a hit the cs2 socket aperture machinery
/// takes over. KRW gate unchanged: kread32(kbase)==0xfeedfacf + typeinfo →
/// commitSlide → board.
///
/// Honesty: every stage prints PASS/FAIL. Zero captures = honest exhaustion
/// (one tap per fresh boot). No spin, ever (fire #3/#4 law).
@interface LightSwordKRW : NSObject
+ (NSString *)runSelfTest;
@end

NS_ASSUME_NONNULL_END