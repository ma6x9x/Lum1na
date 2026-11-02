//
//  P130FenceSecondTable.h — fence churn x the p073 landing engine. p130.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface P130FenceSecondTable : NSObject
/// The FUSION tap: p127/p128/p129 falsified fence churn against every
/// reproducible pair EXCEPT the one that actually aborted 2/2 (0x984fcc8,
/// OUR fill-staging sids in x5) — a RECORD WRITE THAT LANDS. Only p073
/// produces landings (positioned 0x820 prefill neighbors + 254-in
/// post-marshal fires; translation-bar signal on the 23H30 iPad).
/// Thread A = p127 fence churn (+recycle); thread B =
/// [P073AneSecondTable tap] serialized, its own dial/log/bandit
/// untouched. This pair reproduces the HISTORICAL condition: fence
/// teardown concurrent with a landing record write. PANIC-POSSIBLE; one
/// tap per force-quit; honest stage-3 KRW self-test. NOT a conversion
/// claim on its own.
+ (NSString *)tap;
@end

NS_ASSUME_NONNULL_END