//
//  P175KamuiCensus.h — the KAMUI MCM census (no escape fire). p175.
//  Companion census to p173: murk-sus §2 fsgetpath law — credit murk-sus.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface P175KamuiCensus : NSObject
/// murk's fsgetpath census law, run through OUR dynamic app-group read:
///   - the app-group container path (dynamic entitlement read; no hardcode)
///   - the part-dir enumeration (root / user-managed / Preferences / Caches /
///     Documents / tmp / SystemData — the 27.2 class-2 mapping)
///   - which part dirs exist + writable + rename-EPERM receipts (murk §4 law:
///     renames are EPERM from the app's own data container)
///   - the class-13 direct MG-caches query WITHOUT any query mutation (token = NULL
///     expected on 27.2 = traversal-dead receipt)
/// READ-ONLY; PANIC-FREE; log p175_kamui_census_log.txt.
+ (NSString *)tap;
@end

NS_ASSUME_NONNULL_END
