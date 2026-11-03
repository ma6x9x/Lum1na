//
//  P007KernelChain.h
//  Lum1na-Debug (P007 rig)
//
//  KERNEL hot button. Same SKU doors as public KRWChainController:
//  P139 harvest (no 150s lock) + hunt P044 / 17 P114 + kread32.
//  Occupancy CLASS is not hasKread. No P110/P142/P143/P054 auto.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface P007KernelChain : NSObject
+ (NSString *)tap;
@end

NS_ASSUME_NONNULL_END
