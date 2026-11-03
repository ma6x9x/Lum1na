//
//  P149T8150Krw.h — the 17 conversion TAP. p149.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface P149T8150Krw : NSObject
/// T8150 24A435 conversion fire. AppleAVE2 913.43.1 Surface-Pool
/// constructor/destructor (unslid FUN_fffffe0008840f78 /
/// FUN_fffffe0008840fec) both call queue_init at this+0x58
/// (FUN_fffffe000872b180 = stp x0,x0,[x0]; the Nov 1 panic PC +0xDA78).
/// this=1 is a failed alloc (FAR=0x59). Conversion: Encode >=1 frame
/// at N=8 so FUN_fffffe0008790cec stores a heap this at ctx+0x147b0,
/// then Set NumberOfTemporalLayers=16463 (re-init live pool), encode,
/// invalidate. Destructor then kfree(this+0x50, count<<5). Kernel pipe
/// spray is the readable neighbor (not Metal 0x4000). Scan for marker
/// mismatch / kernel VA / queue-init triplet (three equal kptrs + 0).
/// hasKread only after kread32(kbase)==0xfeedfacf. PANIC-POSSIBLE.
+ (NSString *)tap;
@end

NS_ASSUME_NONNULL_END
