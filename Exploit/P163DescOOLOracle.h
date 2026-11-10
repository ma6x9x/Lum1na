//
//  P163DescOOLOracle.h
//  DPC first step: can a userland port descriptor whose `type` word is
//  forged to OOL be sent and received without the validator normalizing it?
//  No kw provider, no kernel writes, no selectors. PANIC-POSSIBLE.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface P163DescOOLOracle : NSObject
+ (NSString *)tap;
@end

NS_ASSUME_NONNULL_END
