//
//  P172M2ContractSweep.h — M2ScalerCSC 24A435 queue-contract census. p172.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface P172M2ContractSweep : NSObject
/// The p170 run isolated the blocker: QueueCreate sel=6 {1000, sids,
/// flags} returned 0xe00002c2 on 24A435 and sel-8 returned 0xe00002bf —
/// the v5 contract was attested on 23F77/24A5390f, NEVER on 24A435.
/// THIS tap sweeps the contract matrix (bounded, one tap):
///   sel 5..8 × struct sizes {8,16,0x408,0x410,0xfa8} × word0 variants
///   {0, count, 0x3e8} logging kr / outLen / first qword; then the sel-8
///   readers with in-size {8,16} after the best QueueCreate hit.
/// All calls go to OUR live surfaces only; read-only classification except
/// the (bounded) queue attempts. PANIC-POSSIBLE badge per contract law.
+ (NSString *)tap;
@end

NS_ASSUME_NONNULL_END
