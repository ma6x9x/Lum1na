//
//  P065FacetAOracle.h
//  CVE-2026-64788 Facet A — 1x65535 plant + Trap2 sel=3 oracle.
//  0xe00002be = Call1 UAF confirm. Spray zeros skip Call2/Call3.
//  Not kreadbuf. Not hasKread.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface P065FacetAOracle : NSObject
+ (NSString *)tap NS_SWIFT_NAME(tap());
@end

NS_ASSUME_NONNULL_END
