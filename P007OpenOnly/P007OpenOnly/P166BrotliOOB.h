//
//  P166BrotliOOB.h
//  P007OpenOnly
//
//  CVE-2026-111497 fingerprint — Brotli BlockSwitch OOB window in
//  libcompression (userspace only; NO kernel, NO panic risk).
//  Technique + trigger generator: MchinaMd57764/CVE-2026-111497-PoC (MIT).
//  Trigger pair is pushed by tools/brotli_trigger.sh into Documents
//  (brotli_first.bin / brotli_second.bin) — stage1 must arrive in separate
//  chunks before stage2 (network-delivery shape).
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface P166BrotliOOB : NSObject
+ (NSString *)tap;
@end

NS_ASSUME_NONNULL_END
