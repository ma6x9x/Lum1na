#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/// CVE-2026-65343 KASLR sibling (AKS ACM deserialize OOB read).
/// Feeder is megafunction sel 16 (P104 ungated; 23F77 jumptable
/// 0xfffffff008d9f868 → FUN_8d8ca10 → aks_sep_req_prepare_output_ool).
/// Sel 0/1 are ungated no-ops — they never reach ACMDeserialize.
/// Bounded: declared_length 0x28 then 0x100 on the feeder only.
/// Not the ByteV0rtex 163-selector 0x800 crash sweep. Not sel5.
/// A leaked kptr is KASLR, not hasKread / not kreadbuf.
@interface P057AksDeserialize : NSObject
+ (NSString *)tap NS_SWIFT_NAME(tap());
@end

NS_ASSUME_NONNULL_END
