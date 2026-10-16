//
//  P099AnePrewireGroom.h
//  Lum1na
//
//  CVE-2026-43748 — ANE direct-path prewire OOB write probe (groomed).
//
//  Public writeup + iOS PoC recipe: vschko/CaseStudies
//  (CVE-2026-43748). Fixed in *OS 26.6 -> LIVE on 23F77 (26.5.0).
//  Our panic-full #1-#3 signatures (0xc0-stride wild writes into
//  data.kalloc.3072 next-chunk) match this bug's prewire loop: the
//  descriptor table is 0x820 bytes (0x80 x 0x10 entries) but the request
//  allows up to 0xff buffers; record 0xc0 lands at +0xc00 = next chunk.
//
//  Flow (bounded, one evaluation, no storm loop):
//    1. load bundled 254-input MIL model via private ANE API
//    2. drain kalloc.3072 + spray inline mach-msg hole/victim pairs,
//       free holes (groom so the OOB lands in a freed victim, not
//       gzalloc metadata -> panic-safe by design)
//    3. doEvaluateDirectWithModel (direct path skips the late
//       bufferCount<0x80 gate that ANE254ChainController saw as
//       fill_cap=1 / 0xe00002c2)
//    4. scan victims for payload diffs = controlled OOB detection
//
//  PANIC RISK: accepted per lab protocol (groomed path). This probe fires
//  a real OOB write — STANDALONE TAP ONLY, never in the JAILBREAK chain
//  (AGENTS.md rule 9). Zero entitlements expected (direct path is
//  reachable from a sandboxed process per the writeup).
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface P099AnePrewireGroom : NSObject
+ (NSString *)tap;
@end

NS_ASSUME_NONNULL_END