//
//  P109AneSelSweep.h
//  ANE request-type/sel sweep with the kernel's own Stage-B oracle:
//  any request reaching Stage-B (FUN_8739b14) returns kr=0xe00002f0
//  "Cannot find task from the given pid" for our DEADBEEF pid pattern.
//  Bounded census: sels 0..63 x 2 struct sizes x 2 open types x
//  H11ANEIn + H1xANELoadBalancer. NO valid program fire.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface P109AneSelSweep : NSObject
+ (NSString *)tap NS_SWIFT_NAME(tap());
@end

NS_ASSUME_NONNULL_END