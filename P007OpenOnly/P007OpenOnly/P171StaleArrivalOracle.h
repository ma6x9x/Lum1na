//
//  P171StaleArrivalOracle.h — stale-arrival socket-slot oracle (read-only). p171.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface P171StaleArrivalOracle : NSObject
/// Reclaim-shape receipt for the cs2 "window-only hits, no pcb pair" question.
/// Borrowed concept (Tims-Cooked harness receipts, 109-hit/335-dgram law;
/// their own conclusion = cross-type reclaim structurally blocked — we measure
/// whether ANY foreign dgram lands on OUR never-sent listeners):
///   batches of UDP listeners (never sent to) + a UDP create/close churn thread
///   (same typed zone recycle) + a self-dgram control (must hit).
/// A dgram received on a listener we never sent to/from = the slot carried
/// live queue state from a previous incarnation (or foreign prober — logged,
/// classified, not disambiguated).
/// PANIC-FREE: socket/bind/recv syscalls only; NO kernel writes, NO OOB.
/// Log: Documents/p171_oracle_log.txt, F_FULLFSYNC per line. One tap.
+ (NSString *)tap;
@end

NS_ASSUME_NONNULL_END
