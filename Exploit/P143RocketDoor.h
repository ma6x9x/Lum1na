//
//  P143RocketDoor.h — the ROCKET SUBMIT DOOR on the 17 (24A435). p143.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface P143RocketDoor : NSObject
/// The Rocket submit door, device row (the state-band derivation landed
/// statically: the record array = {ptr +8 value +0x10 valid} @0x18 stride
/// at PP+0x48; owner=UC+0x120; submitObject=UC-adjacent 0x28; the door =
/// UC sel 0x24 = fn 0xa02299c reading [uc+0x120] then FUN(owner,resourceId)).
/// Stage 1 = the IOGPU UC open (type 0/1, the 2c7 exclusivity census).
/// Stage 2 = the sel-0x24 call with the REAL owner + a REAL live
/// resource id (the Rocket battery class: resource from our own surface
/// family) — the honest rows: kr + out scalars.
/// Stage 3 = the state census: sel 0x24's out + the readback trio's [..]
/// class rows (the +8/+0xc values) = the submit landed's class.
/// PANIC-POSSIBLE (the door = a real kernel state machine); one tap.
/// hasKread stays kread32-gated; commitSlide never from these rows.
+ (NSString *)tap;
@end

NS_ASSUME_NONNULL_END