#import <Foundation/Foundation.h>

/// Post-KRW slots. Named after what Dopamine's BaseBin *does* after
/// kreadbuf exists (trust cache, cs_allow_invalid, userspace reboot).
/// None of these run until Lum1naBoard.hasKread is true.
@interface Lum1naAfterKread : NSObject
+ (NSString *)tap;
+ (NSString *)plan;
@end
