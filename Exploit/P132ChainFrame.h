//
//  P132ChainFrame.h — the staged chain frame (the full picture). p132.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface P132ChainFrame : NSObject
/// The 2026-10-29 unlock: the receipts INTERLOCK, and running the lanes
/// apart loses the picture (the 20:20 abort happened where fence churn,
/// the record machinery, and the PAC walk met — not in any single lane).
/// P132 = the STAGED CHAIN in one session, reusing each primitive at the
/// step the chain needs:
///   stage ANCHOR  [P063AioKqueueLeak tap]     — the slide-tracker KVA family
///              (+0xC0 law = the anchor the later stages reuse in printouts).
///   stage FENCE   our p127 fence churn thread STARTS (recycle@8) and runs
///              for the whole session — the 20:20 delayed-abort condition.
///   stage WRITE   [P112CGShading tap] with p112_chosen.txt seeded =1.0
///              (v1.2 single-row mode) — the value-controlled shading write
///              RECEIPT taken while fences churn (the co-driver pair).
///   stage LAND    [P073AneSecondTable tap] ONLY if Documents/p132_land.txt
///              exists (the landing engine is the heaviest stage; flag it
///              on the boots you want the record-lane landing attempted).
///   stage GATE    the honest KRW self-test (kread32(kbase)==0xfeedfacf via
///              the lane pickers) + the board print. Nothing claims KRW
///              without it. The late watcher (45s) catches delayed
///              landings before the end.
/// Each invoked tap keeps its own log file and honesty; P132 records the
/// cross-stage summary. One tap per force-quit. PANIC-POSSIBLE.
+ (NSString *)tap;

@end

NS_ASSUME_NONNULL_END