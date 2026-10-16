//
//  P088AneWriteHop.h — forged OUTPUT-record write hop (102 Chain 2 Step 2).
//
//  v4 (runs 2–4 calibration): there IS no run "direction" — the sentinel
//  run is not index-contiguous. The fill-hit index MEASURES the physical
//  pair instead: hit at run[h] with A-hole at run[a] proves
//  X_h == X_a + 0xC00 exactly. Round 0..1 measures (calA, calB); later
//  rounds free X_calB first (B pops it = the chunk A's fill lands in) and
//  X_calA last (A pops it = top). Run 4: pair (14 -> 16) reproduced 4/4
//  rounds on one boot; pairs are boot-specific (23:51 boot measured 14->11).
//  When hit == hB: ADJACENCY CORRECT — only the [fill->map] window race
//  remains. Race inversion (A first, B volley) and note-105 staging-band
//  gap-scan unchanged. B = XVRC27_3in127ops_1out: OUTPUT record @0x30 =
//  A's spilled record 195.
//

#import <Foundation/Foundation.h>

@interface P088AneWriteHop : NSObject
+ (NSString *)tap;   // P007 convention: returns the log body
@end