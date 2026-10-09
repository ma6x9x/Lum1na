//
//  P070ChainSequencer.h
//  Multi-door KRW chain map + IOService reach census + AfterKread HOLD.
//  Does not fire 254, Facet plant, Close-vs-async, or AMFI kwrite.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface P070ChainSequencer : NSObject
+ (NSString *)tap NS_SWIFT_NAME(tap());
@end

NS_ASSUME_NONNULL_END
