//  P113DescForgeControl.h — A13 KRW control experiment (user request 2026-10-24).
//  With cs2core KRW live: build ONE port-kind kmsg carrying the P113 marker,
//  kernel-scan for its kdata address (content signature), kwrite-FORGE
//  desc0's {type,disposition} words by hand, then recv — kernel-verified
//  conversion bar: body_forged AND kptr without needing the ANE landing.
//  If the forged desc produces the port-confusion door here, the ANE's
//  natural fill only owes the 12 its landing geometry.
@interface P113DescForgeControl : NSObject
+ (NSString *)tap;
@end
