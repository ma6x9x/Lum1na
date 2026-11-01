//
//  P147Lifecycle.h — the LIFECYCLE probe (the stale-slot UAF's
//  teardown-cycle battery INSIDE the live p027-class spray + the
//  discriminator). p147.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface P147Lifecycle : NSObject
/// The LIFECYCLE row: the 16463-class stale-slot UAF's userland
/// precondition driven at rate — 64 IOSurface-backed Metal buffers
/// (0x4000 class, marker 0x41) plus a separate 16-surface marker group
/// (marker 0x53) created, filled and HELD for the whole tap, then N
/// fast create→prepare→encode→complete→invalidate CYCLES of a
/// VTCompressionSession (HEVC 1280x720, the stage9 property pack
/// VERBATIM: EncoderUsage=1, RCMode-20, RealTime=FALSE) on a worker
/// pthread — one honest row per cycle (cycle#, create st, prepare st,
/// encode st, elapsed ms) — then the DISCRIMINATOR: every held
/// allocation's bytes scanned against its own fill marker;
/// a foreign-value byte = receipt-class evidence of a write we did
/// not author (counts + byte class only, never a raw dump).
/// The knob = the cycle count (Documents/p147_cycles.txt, decimal,
/// default 24, cap 200); the temporal-layers property is RETIRED on
/// this lane (it appears NOWHERE in this probe).
/// HONESTY: PANIC-POSSIBLE badge (the teardown chase class); a
/// foreign-value row = receipt-class evidence, NEVER a KRW claim;
/// hasKread stays kread32-gated. One tap per force-quit.
+ (NSString *)tap;
@end

NS_ASSUME_NONNULL_END