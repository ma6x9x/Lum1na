#import <Foundation/Foundation.h>

/// Post-KRW slots. Named after Dopamine 3.0.10 BaseBin and Relaxin/RootHide
/// (trust cache, cs_allow_invalid, ellekit tweak load). None of these run
/// until Lum1naBoard.hasKread is true. Persist/tempRoot stay HOLD.
@interface Lum1naAfterKread : NSObject
+ (NSString *)tap;
+ (NSString *)plan;
@end
