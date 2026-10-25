//
//  P068ChrootPrivMap.h
//  CVE-2026-43689 app→root permissions class. chroot/seteuid MAP, no jail_priv fire.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface P068ChrootPrivMap : NSObject
+ (NSString *)tap NS_SWIFT_NAME(tap());
@end

NS_ASSUME_NONNULL_END
