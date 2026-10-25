//
//  P080AneYcraft127.h
//
//  P080 — 43748 y-craft on the PROVEN-engaged 127-input models, with all
//  127 input records pointing at LIVE armed IOSurfaces.
//
//  Cross-referenced evidence that reshaped this probe:
//   - P044 v28 log (2026-10-09 14:08): 254-in addchain fires CheckandPrewire
//     OOB fingerprints [u32 surface][0xcN][1][1] — the ANE record path is
//     real on 23F77. Engagement confirmed for 254-in and 127-in.
//   - P079 espresso.net diff: layer count is NOT the specialization driver.
//     XVRC27_3in127ops_1out (~127 layers) never sent a kernel request while
//     the 126-layer 127-in chain did. The driver is the number of model
//     INPUTS (few inputs -> espresso inlines, no IOSurface DMA, no request).
//   - Ghidra bee5f818 (MemoryMapRequest_gated): FIRST bad input record
//     aborts the whole request (0xe00002c2). P077's crafts aborted exactly
//     there (craft-A echo "x_1=394 not live" also proved record sid ==
//     int(x_i): the client fill writes the input VALUE into entry field[0]).
//   - P033 precedent: MLComputePlan loadContentsOfURL is proven API here.
//
//  P080 feeds x_i = sids[i] (live armed surfaces) so the input loop passes
//  for the first time, then:
//   - Model A (XVRC27_127in_1out, existing): READ-DOOR differential.
//     Contents staged 0.0 -> y==0.0 means the ANE reads OUR wired surfaces
//     (content flows from the fetched surface). y==fp16 serial sum of sids
//     means the client copies x VALUES into its own staging instead.
//   - Model B (XVRC27_127inmin_1out, new): WRITE DOOR.
//     y = MIN(sum, x_000) == x_000 == sids[0] exactly (fold-proof: 126
//     strictly positive terms keep sum > x_000). predict1 sets prev y =
//     sids[0]; predict2's output record sid = prev y = OUR surface 0 ->
//     ANE writes into it -> capture scan.
//
//  PANIC POSSIBLE: the successful input-loop path (128 records fetched,
//  wired, dartMapped) has never run before on this device. Every log line
//  is POSIX write + F_FULLFSYNC so a panic still leaves the trail.
//  One TAP per force-quit. Fresh boot between taps.
//
//  Honesty: hasKread=NO hasKwrite=NO. Conversion bar
//  (desc_type_forged OR (body_forged AND kptr)) untouched. A capture hit
//  here is an OWN-surface write through the ANE request path — Stage B
//  (foreign sid) is the next step, not a claim of KRW.

#import <Foundation/Foundation.h>

@interface P080AneYcraft127 : NSObject
+ (NSString *)tap;
@end