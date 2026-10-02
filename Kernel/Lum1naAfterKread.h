#import <Foundation/Foundation.h>

/// Post-KRW slots. Named after Dopamine 3.0.10 BaseBin and Relaxin/RootHide
/// (trust cache, cs_allow_invalid, ellekit tweak load, Sileo then Zebra).
/// KRW self-test (kread32(kbase)==MH_MAGIC_64) must pass. Persist/tempRoot HOLD.
@interface Lum1naAfterKread : NSObject
+ (NSString *)tap;
+ (NSString *)plan;
@end
