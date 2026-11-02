//
//  P120NewResourceDoor.h — the 64788 new-resource DOOR probe. p120.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface P120NewResourceDoor : NSObject
/// 23F77 device-conn sel8 (s_new_resource, variable struct) / sel9 (delete)
/// / sel36 (fn4 ANE-buffer gate oracle) — resType-0 calibrate, then the
/// oversized-IOSurface-class create-fail-after-insert ladder + post-fail
/// leftover-id sweep. Bounded; panic-possible.
+ (NSString *)tap;
@end

NS_ASSUME_NONNULL_END