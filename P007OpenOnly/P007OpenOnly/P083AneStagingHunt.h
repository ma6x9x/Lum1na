//
//  P083AneStagingHunt.h
//
//  P083 — staging hunt + injection. p082 Phase L found the espresso
//  staging pool: 15/24 post-predict gap ids resolved via IOSurfaceLookup
//  in OUR registry, 16 KB each, readable, distinct u32@0 fingerprints.
//  The other 9 (foreign-taken) missed — per-task registry vs the ANE's
//  global fetch, both now proven independently.
//
//  One tap, four phases:
//    H. HUNT: capture fresh gap ids, IOSurfaceLookup each, fingerprint
//       u32@0 of every hit (our-task staging candidates only).
//    I. INJECT: fill EVERY hit surface with the LUM1 pattern, then
//       repeat the gate predict. y2 != y_gate => staging IS the value
//       source => in-process y-control primitive (write staging ->
//       control what the ANE computes and writes). y2 == y_gate =>
//       those surfaces are command/program buffers, values flow another
//       way. Own-registry writes only — no foreign targets.
//    J. JUSTICE (classification): re-lookup, dump first 32 bytes:
//         ascending sid sequence            -> input staging
//         y encodings (u32/fp16/fp32)       -> output staging
//         LUM1 pattern intact               -> untouched by predict
//         changed, neither                  -> dump for twin naming
//       The surface carrying y is THE output record target for the
//       Chain 2 sid forgery.
//  PANIC POSSIBLE (staging surfaces are ANE-mapped during predicts).
//

#import <Foundation/Foundation.h>

@interface P083AneStagingHunt : NSObject
+ (NSString *)tap;
@end