//
//  P071AneOverflowMap.h
//  CVE-2026-65408 ANE integer-overflow class — MAP only.
//  Distinct from CVE-2026-43748 CheckandPrewire fill.
//  DeviceOpen 0x68, no ProgramSendRequest, no huge n.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface P071AneOverflowMap : NSObject
+ (NSString *)tap NS_SWIFT_NAME(tap());
@end

NS_ASSUME_NONNULL_END
