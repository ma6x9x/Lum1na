//
//  P117EntEcho.h — the AMFI entitlement-echo probe (kernel's own SecTask view). p117.
//
#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface P117EntEcho : NSObject
/// Prints the kernel's OWN view of the rig's declared entitlements
/// (SecTaskCopyValueForEntitlement per key, CF type + value). NIL =
/// stripped by free-profile AMFI enforcement = the corresponding
/// kernel-side crash-experiment on that key is VOID. Read-only.
+ (NSString *)tap;
@end

NS_ASSUME_NONNULL_END
