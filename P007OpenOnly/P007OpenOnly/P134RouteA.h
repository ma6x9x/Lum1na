//
//  P134RouteA.h — ROUTE A: the engine-armed K2K fill disclosure. p134.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface P134RouteA : NSObject

/// The K2K-context-reuse route (the 2026-10-30 static decode): the
/// M2ScalerCSC sel-6 row-6 body is a two-state machine — ARMED branch
/// (UC+0x154 != 0) executes the FILL and writes kernel-side results INTO
/// the caller's 0xfa8 struct: the count at +0x0 and record-array
/// pointers at +0x608/+0x60c/+0x610 (full-width kernel KVAs, not the
/// truncated p010 cursor). If the ENGINE (VideoToolbox/AVE scale
/// machinery, the K2K caller) arms the state on a UC we hold, a plain
/// userland row-6 send returns kernel-chosen pointers = the full-width
/// KVA disclosure route. This probe runs the engine battery BETWEEN two
/// row-6 sends on the SAME connection and scans every response for
/// kernel-range qwords (the disclosure law: 0xffffff-band, printed
/// verbatim; echo-filtered). Tags = REAL live surfaces only (the
/// mismatched-sid PANIC law). PANIC-POSSIBLE (the armed fill writes
/// kernel data into our struct by design); one tap per force-quit.
+ (NSString *)tap;

@end

NS_ASSUME_NONNULL_END