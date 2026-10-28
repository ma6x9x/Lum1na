//
//  P118BootLearn.h — the BOOT-LEARNER slice (note 281): p090's resolver
//  in-process → boot_learning/<bootId>/offsets.json + the entitlement echo.
//
#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface P118BootLearn : NSObject
/// One tap = one training event: DERIVE (LabKernelOffsets → per-boot
/// offsets.json), ECHO (the entitlement map), the bandit ledger joins by
/// its own bootId. READ-ONLY.
+ (NSString *)tap;
@end

NS_ASSUME_NONNULL_END
