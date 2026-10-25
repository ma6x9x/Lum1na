//
//  P087ReclaimObserver.h
//  CVE-2026-84607 reclaim observer (P087).
//
//  Ladder per 101ap: the AVE2 UC's async waiter ("client") is allocated per
//  session from a kalloc-type zone (alloc site DAT_007c00890, free site
//  DAT_007c008d0) and stopAsync has a DOUBLE-FREE window (re-reads +0x160
//  after a re-entrant virtual call +0x548). Same-type allocator = new VT
//  sessions. sendAsyncResult64 builds a kernel mach message from the
//  UC+0x118 saved rights/descriptors and sends it to the waiter's port.
//
//  P087: run one compact race wave -> IMMEDIATELY spawn refill sessions
//  (their waiters land in any double-freed slot) -> keep them encoding ->
//  drain all completions with per-session attribution -> flag anomalies:
//    - completions for already-invalidated sessions (late)
//    - PTS values outside a session's submitted range (cross-waiter leak)
//    - duplicate PTS on one session (same result delivered twice)
//  Evidence of cross-waiter confusion = the reclaim ladder is live.
//
//  HONESTY: anomalies are evidence, not KRW. commitSlide stays gated.
//

#import <Foundation/Foundation.h>

@interface P087ReclaimObserver : NSObject
+ (NSString *)tap;
@end