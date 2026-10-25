//
//  P079AneYcraftPad.h
//  P007OpenOnly
//
//  P079 — 43748 y-craft, P078 crafts on an ANE-SCHEDULED 3-in model.
//
//  P078 lesson: XVRC27_3in_1out (3 bare adds) never got ANE-specialized —
//  predicts ran 0.1-0.6ms pure CPU, no kernel request was ever sent, so
//  the y-craft was UNTESTED (not disproven). The 127-in chain IS ANE-
//  scheduled (4-5ms predicts, +2-3ms kernel trip per 101c).
//
//  Fix: XVRC27_3in127ops_1out — 3 inputs (all-valid-record constraint kept)
//  padded to 126 elementwise ops with cancel pairs (LINEAR alpha=-1 negate
//  of x_000, then re-add): (t + (-x0)) + x0 == t EXACTLY in fp16 for our
//  integers <= 2048 (craft-A) and subnormals (craft-B). Verified numerically:
//  craft-A y==695.0, craft-B y==695*2^-24 exact, integers never round.
//
//  NEW: ANE-engagement detector BEFORE the crafts — min-of-20 steady-state
//  predict time on All vs CpuOnly for the same input. engaged =
//  (minAll > minCpu + 1.0ms) [v3 measured +2-3ms kernel trip]. If NOT
//  engaged, the verdict says so explicitly: no door, y-craft untested,
//  model still CPU-only — this is NOT a theory failure.
//
//  Ghidra mechanics unchanged (MemoryMapRequest_gated bee5f818): entry
//  sid = field[0]; FIRST BAD RECORD ABORTS; output record reached only
//  when all input records are valid; output entry sid hypothesized =
//  previous predict's y (staged content, P073 fill + P074 garbage).
//
//  Oracles (engaged case only): capture bytes != 0x53 = WRITE DOOR (own
//  target); y==0.0/3.0 on crafts = ANE read OUR wired surfaces = READ
//  DOOR; y==sid_C/vB = fallback/aborted. hasKread=NO hasKwrite=NO.
//  Conversion bar untouched. ONE TAP per force-quit. F_FULLFSYNC per line.
//

#import <Foundation/Foundation.h>

@interface P079AneYcraftPad : NSObject
+ (NSString *)tap;
@end