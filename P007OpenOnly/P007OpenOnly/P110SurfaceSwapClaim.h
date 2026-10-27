//
//  P110SurfaceSwapClaim.h
//  Lum1na-Debug (P007 rig)
//
//  CVE-2026-112477 — IOSurface zero-lock swap-claim probe (design 270).
//
//  The claim law (note 270, byte-verified on 23F77 T8101 + 24A435 T8150):
//  the IOSurface detach-then-set (23F77 0xfffffff00985fbb8 / 24A435
//  0xa33ac74) releases the old client (vtbl+0xe0) then swaps [obj+0x30]
//  via the PAC setter (0x9857c88-class) with ZERO locks between. The
//  freed client slot is claimable ONLY by a genuine live IOSurface-class
//  object — the vtable-pointer autda modifier is bound to the object
//  address (0xcda1 law), so attacker content NEVER passes auth; a
//  genuine reclaim dispatches the vt+0x48 consumer body (0x985b178-class:
//  ++[p+0xc], ++[p+0x10], [this+0x3c0]|=0x1c — 24A435 +0x3d0, bit10 same).
//  The Family-B far 0x0020000000000048 / x16 0x0020000000000000 IS the
//  autda auth-fail poison = the fleet's attested window-win/slot-lost class.
//
//  Probe shape (D-thread): sibling IOSurface sessions; after a session
//  owner dies, prefill(6)+2 same-CPU pop of sibling clients through the
//  IOSurfaceRoot sMethods row-0 attach chain (23F77 0xfffffff007f33888 /
//  24A435 0xfffffe000837fa10 — the +0x30 value is ALWAYS kernel-sourced;
//  user influence = WHICH sibling session + WHEN its owner dies).
//  64 rounds. dlsym-only IOSurface APIs (no <IOSurface/IOSurface.h>);
//  mach via <mach/mach.h>. Bounded, one tap, fsync log, honest verdicts.
//
//  v2 LEAK-GATE: the claim stage is now PAIRED with the M2ScalerCSCDriver
//  selector-8 leak (the derived law: {u64} 8-byte input; out = the
//  activity-queue serializer's records, stride 0x7c, rec+0x18 = raw
//  first-event qword passthrough with no auth = the IOSurface-KVA
//  disclosure class — likely CVE-2026-64709; rec+0x30 = the +0x30-class
//  client-ptr field = the claim law's own [surface+0x30] shape). Per
//  round: a pre-window sel-8 snapshot (its record count rides the IN
//  FLIGHT stamp), and on a claim-won round a pre/post leak DIFF — the
//  +0x30-class KV changes = the claim-corruption observable (proxy-class:
//  names the objects, proves the corruption CLASS, no kread claim).
//  Leaked KVs print labeled LAW: KVA DISCLOSURE CLASS — not kread;
//  hasKread=NO until a kread32-class receipt exists. Shape mismatch
//  (kext drift) = honest hexdump + HOLD the pairing. The 6-arm bandit
//  adds leakgate-on / leakgate-off (does leak-gating change the claim
//  rate?). The (b) catch stays the sigaction law.
//
//  Three-outcome law per round (note 270 §4):
//    (a) clean-no-anomaly     = window lost (honest print)
//    (b) Family-B-shaped fault(SIGBUS/EFAULT-class on the alias path, or
//        the fleet's on-device panic later with the in-flight round
//        fsync-marked) = window won, free slot (honest print)
//    (c) claim won = silent clean + proxy-class readback evidence
//        (flags 0x1c-class law proxy via property/mapping readback +
//        client-slot alias detection via IOSurface identity checks)
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface P110SurfaceSwapClaim : NSObject
+ (NSString *)tap;   // returns the log body
@end

NS_ASSUME_NONNULL_END