//
//  P067AvdReach.h
//  CVE-2026-65407 AppleAVD UAF class — IOServiceOpen reach only.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface P067AvdReach : NSObject
+ (NSString *)tap NS_SWIFT_NAME(tap());
@end

NS_ASSUME_NONNULL_END
