//
//  P081AneForeignProbe.h
//
//  P081 — three questions P080 left open, one tap:
//
//  1. THE +~60 BIAS: P080's ANE y = exact_sum + ~60 (33120 vs 33064;
//     32800 vs 32738), deterministic, sid-tracking, on the fp16 grid,
//     unexplained by serial/tree/fp32 sims. Phase E runs ALL 127 inputs
//     = sid0 (every partial sum exact fp16 while < 2048/4096): a faithful
//     evaluator returns EXACTLY fp16(127*sid0); y-expected = k*sid0 if k
//     inputs are double-counted. Logs ALL 412 sids for offline sims.
//
//  2. FOREIGN-SID FETCH (Stage B decider): P080 proved record sid ==
//     int(x_i) client-controlled and the fetch passes for owned sids.
//     If the registry fetch is GLOBAL, x_i = a FOREIGN sid maps another
//     process's surface into the ANE request path. Gap capture during
//     creation: IOSurface ids consumed BETWEEN two consecutive creates
//     belong to other processes (backboardd et al create every frame)
//     and are almost certainly still live. Feed the freshest gap sids.
//     No-abort => cross-process fetch CONFIRMED (Stage B premise alive).
//     "surface-Id: %d is nullptr" => per-task scope, Stage B dead here.
//     Control first: x_126 = a live armed sid must pass.
//
//  3. STAGING GAPS: P080 proved the output record sid = espresso's own
//     staging surface (live, in-process, invisible). After model load +
//     predicts, extra id consumption shows up as fresh gaps — those are
//     espresso staging candidates. Logged for the IOSurfaceLookup /
//     content-injection experiment (next probe).
//
//  PANIC POSSIBLE: Phase F asks the kernel to fetch a surface owned by
//  another process. Per-line F_FULLFSYNC keeps the trail.
//
//  Honesty: hasKread=NO hasKwrite=NO. Conversion bar untouched. A
//  foreign fetch would be a MAPPING, not yet a write; the write hop is
//  the 43748 record-forgery chain (notes 102).

#import <Foundation/Foundation.h>

@interface P081AneForeignProbe : NSObject
+ (NSString *)tap;
@end