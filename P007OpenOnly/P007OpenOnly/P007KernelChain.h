//
//  P007KernelChain.h
//  Lum1na-Debug (P007 rig)
//
//  KERNEL hot button. Same SKU doors as public KRWChainController:
//  hunt 12 23F77: P139 harvest (P063 + P010 disclose) → P044 N=192
//  LIVE 1-record OOB → Arm HOLD until rw_inpcb → kread32.
//  P099/P073 254 remaining-fire SKIP (MAF into FREE kalloc.3072).
//  Occupancy CLASS is not hasKread. T8150 fires P149.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface P007KernelChain : NSObject
+ (NSString *)tap;
@end

NS_ASSUME_NONNULL_END
