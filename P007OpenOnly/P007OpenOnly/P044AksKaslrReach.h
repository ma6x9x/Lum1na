#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/// CVE-2026-43748 occupancy write (CheckandPrewire 0x820 table OOB).
/// v73 sprays msgh_size=0x7FC kdata=0x820 (P034 class). Default N=191
/// in-bounds; Documents/p044_req_in.txt=192 is 1-record OOB.
/// Conversion PASSES only on forged descriptors / (body_forged AND kptr).
/// Occupancy HIT is not hasKread. Do not remaining-fire 254.
@interface P044AksKaslrReach : NSObject
+ (NSString *)tap NS_SWIFT_NAME(tap());
@end

NS_ASSUME_NONNULL_END
