//
//  P168Iosurface112477.h — 112477 sel-17 registration-shape classification
//  probe (+ explicit-arm dangle stage). p168.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface P168Iosurface112477 : NSObject
/// Ladder (classification, not an exploit):
///   1. open IOSurfaceRootUserClient (type 0), create 2 surfaces (framework).
///   2. sel-17 register: struct variants, dup-check (expect 2c9 on repeat),
///      sel-18 dereg (expect 0 then 2c2-class when gone).
///   3. ARM-GATED dangle stage (Documents/p168_dangle_arm.txt must exist):
///      register -> IOServiceClose BEFORE CFRelease -> drop last ref of the
///      OTHER surface -> the 0x9869984 fan-out derefs the freed client at
///      owner+0xd8. PANIC-POSSIBLE — this is THE 112477 device trigger, so
///      it stays behind the explicit arm file like lswkrw_arm.txt.
///   Behavior codes only; no kernel writes; one tap per boot.
+ (NSString *)tap;
@end

NS_ASSUME_NONNULL_END
