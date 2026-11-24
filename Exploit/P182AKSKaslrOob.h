//
//  P182AKSKaslrOob.h — CVE-2026-65343 AKS OOB read -> KASLR (read-only).
//  p182 v1. Byte-proven live on 23F77 (findings 2026-11-24).
//

#import <Foundation/Foundation.h>

@interface P182AKSKaslrOob : NSObject
+ (NSString *)tap;
@end
