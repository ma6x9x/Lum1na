//
//  P126DecmpfsLeak.h — kernel heap disclosure via the crafted decmpfs
//  chunked xattr (CVE-2026-113910 port). p126.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface P126DecmpfsLeak : NSObject
/// Craft a com.apple.decmpfs chunked-zlib xattr whose chunks UNDER-PRODUCE
/// vs the chunk table, read the file back, scan the decoded bytes for
/// kernel-space pointers (>= 0xFFFFFFE000000000). READ-ONLY class; a
/// kernel-content read from a free app = a KASLR-class receipt.
+ (NSString *)tap;
@end

NS_ASSUME_NONNULL_END