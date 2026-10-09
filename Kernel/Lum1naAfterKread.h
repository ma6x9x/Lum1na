#import <Foundation/Foundation.h>

/// Post-KRW slots. Named after Dopamine 3.0.10 BaseBin and Relaxin/RootHide
/// (trust cache, cs_allow_invalid, ellekit tweak load, Sileo then Zebra).
/// KRW self-test (kread32(kbase)==MH_MAGIC_64) must pass. Persist/tempRoot HOLD.
@interface Lum1naAfterKread : NSObject
+ (NSString *)tap;
+ (NSString *)plan;
/// STAGE phase only: extract basebin.tar into Documents/basebin and copy
/// the Sileo/Zebra debs into Documents/pkgman. No gates, no fires.
+ (NSString *)stageOnly;
/// FIRE phase: KRW self-test gate (kread32(kbase)==MH_MAGIC_64 and
/// kbase+0x1c is a kernel VA), then pmap_cs / AMFI trustcache /
/// opainject launchdhook / dpkg -i Sileo then Zebra / jbctl respring.
/// Returns HOLD text without firing when the gate fails.
+ (NSString *)fire;
@end
