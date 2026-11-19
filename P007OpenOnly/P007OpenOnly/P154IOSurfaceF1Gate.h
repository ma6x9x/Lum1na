//
//  P154IOSurfaceF1Gate.h — the IOSurface +0xf1 claim-gate residual classification. p154.
//  (the handoff priority-(3) tap; murk-sus 27.2 law: dereg-before-unlink reorder)
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface P154IOSurfaceF1Gate : NSObject
/// The 27.2 claim-gate law as a classification tap (murk-sus §27.2 + our +0xf0/+0xf1 map):
///   1. IOSurfaceRoot open (p018 door 1).
///   2. sel-17 register ladder x4 (24-B struct variants — our p168 shapes).
///   3. dup-check (2c9 = owner HIT — the 27.2 reorder makes fan-out cleanup unconditional).
///   4. sel-18 dereg then re-register on the SAME connection (murk §15: legal on 27.x).
///   5. verdict vs the 24B156 law: 2c2-on-caps = gate law; 2c9 dup = fan-out live;
///      anything else = residual surface to quote.
/// READ-ONLY classification; no dangle stage on 24B156 (fan-out patched per +0xf1 law);
/// hasKread law intact. PANIC-POSSIBLE badge (sel-17 register is a kernel call).
+ (NSString *)tap;
@end

NS_ASSUME_NONNULL_END
