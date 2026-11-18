//
//  P170T8150Composite.h — the 17 Pro Max composite KRW chain (one boot). p170.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface P170T8150Composite : NSObject
/// T8150-only sequencer (note-271 composite, PLAN B):
///   [BOOT LEARN] P139BootIntel   — leaks + per-boot state harvest
///   [LEAK]      P114SurfaceLeak — sel-8 serializer KVA disclosure
///   [CLAIM]     P110SurfaceSwapClaim — 112477 claim race, leak-gate PAIRED
///   [WRITE]     P142AVETemporal — ONLY if Documents/p142_layers.txt exists
///                              (knob law: the file sets the layer count;
///                               16463 = the 112705 panic attestation)
///   [GATE]      board kread32 honesty check (hasKread flips ONLY there)
/// P143 RocketDoor stays catalog-solo (T1 law — never remaining-fired).
/// Log: Documents/p170_t8150_log.txt, F_FULLFSYNC per line (panic-surviving).
/// PANIC-POSSIBLE (P110/P142 stages). One tap per force-quit.
+ (NSString *)tap;
@end

NS_ASSUME_NONNULL_END
