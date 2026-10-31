//
//  P140GroundTruth.h — the MINI GROUND-TRUTH VERIFIER. p140.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface P140GroundTruth : NSObject
/// The 21-D50 cross-reference rig (Dopamine). The user's insight: a
/// jailbroken device lets us ANSWER the 2c2-class questions by kernel
/// READ instead of by port-guessing.
///   A. RECIPT — the lane's kread32(kbase)==0xfeedfacf receipt (legal
///      hasKread on THIS rig only; the board on the hunt stays gated).
///   B. THE MD OBJECT, READ DIRECTLY — IOSurfaceCreateMachPort port →
///      mach_port_kobject → the kernel object kaddr → kread the p138
///      oracle slots ([+0x98] gate, [+0x34] u16 dmaref) AND the 21-D50
///      twin-class slot (+0x80 per the FKT dump FIELD# law). The p138
///      op-channel census (all 2c2) is answered WITHOUT asking the port:
///      the object's own fields become kernel-read truth. Class/field
///      reads only — 23F77 pins never transfer to 21D50.
///   C. THE OFFSET LEDGER STATUS — prints the A14_21-D50 DERIVED rows with
///      their og-source law (Dopamine info.c darwin-23.3 usecount=0x24c),
///      each still DERIVED (not read-verified; the inpcb walk = v2).
/// Writes p140_groundtruth.txt. READ-ONLY (no ladder, no wrap path).
+ (NSString *)tap;
@end

NS_ASSUME_NONNULL_END