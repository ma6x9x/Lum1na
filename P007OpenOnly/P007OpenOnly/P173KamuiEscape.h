//
//  P173KamuiEscape.h — containermanagerd part-directory symlink escape (27.2.1). p173.
//  Technique + engine port: murk-sus / KAMUI (MIT) — credit murk-sus.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface P173KamuiEscape : NSObject
/// Murk-sus KAMUI engine (MIT, credit murk-sus): the app-group PART DIRECTORY
/// is not validated by MCM — only partDomain is. Symlink <group>/Library/Caches
/// → target, run the class-7 container query with flags 0x8100000000
/// (extension type 3 = R/W), consume the token, restore the part dir.
/// Multi-strategy per their BQEscape: class-7 symlink (27.2 primary) →
/// class-13 direct (MG caches) → class-12 geod. Dynamic group read via
/// SecTaskCopyValueForEntitlement ("com.apple.security.application-groups").
/// Receipts: sandbox extension for an out-of-container path + the MobileGestalt
/// cache reachable = userspace sandbox-escape class (not KRW, never hasKread).
/// PANIC-FREE by design (userspace file ops only); one tap per force-quit.
+ (NSString *)tap;
@end

NS_ASSUME_NONNULL_END
