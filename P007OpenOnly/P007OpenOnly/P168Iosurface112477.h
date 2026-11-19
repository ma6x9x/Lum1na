//
//  P168Iosurface112477.h — 112477 sel-17 registration-shape classification
//  probe (+ explicit-arm dangle stage). p168.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface P168Iosurface112477 : NSObject
/// V2 (2026-11-19, Rust505/Kimi cross-ref fusion):
///   1. open IOSurfaceRootUserClient (type 0), create 2 surfaces (framework).
///   2. [A] calling-contract calib: sel17 is ASYNC-ONLY (sync = 2c2 forever).
///      [B] sticky ladder: reg -> dup(2c9) -> dereg -> re-reg (2D8 = the
///      27.2-era sticky gate LIVE receipt; 0 = pre-27.2 shape).
///      [E] SIBLING stale-read oracle: reg->dereg frees the node, async
///      groom (256 kernel-held buffers, sz sweep 24..96) recycles the slot,
///      a fresh SIBLING connection's reg reads the groomed bytes
///      (dup 2c9 -> not-2c9 = STALE-READ). Behavior codes only.
///   3. ARM-GATED dangle stage (Documents/p168_dangle_arm.txt must exist):
///      register -> IOServiceClose BEFORE CFRelease -> drop last ref of the
///      OTHER surface -> the 0x9869984 fan-out derefs the freed client at
///      owner+0xd8. PANIC-POSSIBLE — this is THE 112477 device trigger, so
///      it stays behind the explicit arm file like lswkrw_arm.txt.
///   Behavior codes only; no kernel writes; one tap per boot.
+ (NSString *)tap;
@end

NS_ASSUME_NONNULL_END
