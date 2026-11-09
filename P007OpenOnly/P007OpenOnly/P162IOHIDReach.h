//
//  P162IOHIDReach.h
//  P007OpenOnly
//
//  Read-only reach probe for the IOHIDFamily user clients (CVE-2026-112515
//  lane). Enumerates HID services and attempts IOServiceOpen for types 0..4.
//  No external method is invoked; nothing is written.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface P162IOHIDReach : NSObject
+ (NSString *)tap;
@end

NS_ASSUME_NONNULL_END
