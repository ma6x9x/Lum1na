//
//  P142AVETemporal.h — the AVE2 TEMPORAL-LAYERS KNOB (CVE-2026-112705). p142.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface P142AVETemporal : NSObject
/// The PUBLIC vector, borrowed with attribution: MMdAS's independent
/// reproduction of CVE-2026-112705 (originally the Calif/Chollima
/// discovery, repo MchinaMd57764/AVETemporalPoC): VideoToolbox
/// compression session with NumberOfTemporalLayers = 16463 (16462
/// survives) + first encode => AppleAVE2 kernel OOB WRITE panic at
/// +0xDA78, far=0x59 / x0=0x100000059 — the fault address's high word
/// SCALES with the layer count (N=16464 => 0x100000001-class) = a
/// COUNT-SCALED, fixed-offset fill = the lab's own fill-store
/// conversion class (the p088/p112 geometry), now with a LIVE knob.
///
/// Fleet run: the knob = Documents/p142_layers.txt (a decimal value;
/// default = the 16462/16463/16464 truth battery). Each value = a
/// SEPARATE tap (one encode per run, boot-clean law). Panic-possible
/// BY DESIGN = the count-law receipt; the fleet's 12 (23F77, AVE2
/// 913.43-class = pre-27.2-fix) is the likely-live device and the
/// 17 (24A435) is the sibling-class control.
///
/// v6 sequence: Prepare with N=8 first (real Surface Pool), then Set
/// the overshoot count, then encode. v5 set-then-Prepare is the this=1
/// / FAR=0x59 path. Conversion TAP is catalog p149 (kernel pipes).
///
/// HONESTY: this is a kernel-state WRITE probe (the count knob), not
/// a read; hasKread stays kread32-gated; one value per tap.
+ (NSString *)tap;
@end

NS_ASSUME_NONNULL_END