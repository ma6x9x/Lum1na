//
//  P101DmaCommandFire.h
//  CVE-2026-43684 dmaCommandOperation REUSE fire. Separate TAP from T7.
//  Live 23F77 field is IOMD+0x68 (pre-26 name +0x34). One setup + one reuse.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface P101DmaCommandFire : NSObject
+ (NSString *)tap NS_SWIFT_NAME(tap());
@end

NS_ASSUME_NONNULL_END
