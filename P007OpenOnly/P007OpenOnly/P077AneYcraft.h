//
//  P077AneYcraft.h
//  P007OpenOnly
//
//  P077 — 43748 "y-craft" write-door probe.
//
//  Core idea (from the P075 v2 miss + Ghidra): if the kernel record fill
//  reads the OUTPUT staging content as the output IOSurface id, then the
//  sid it sees is the PREVIOUS PREDICT'S Y — because each predict writes
//  its y into the output staging. We control y exactly. So we craft y to
//  BE our capture surface's id and let the next predict wire the capture
//  surface as the ANE program's output buffer. No allocator groom at all.
//
//  Two decode worlds are covered in one tap:
//    Craft-B (raw-bits world): x = 126 zeros + x_126 = fp16 value whose
//      BIT PATTERN == sid_C. Predict B1 -> y == v. B2's output staging
//      holds fp16 bits sid_C -> output record sid = sid_C.
//    Craft-A (value-decode world): x_0 = in[0].sid, x_1 = sid_C - in[0].sid
//      (fp16-exact: ~130 < 2048), rest 0. Predict A1 -> y == sid_C exactly.
//      A2's output record sid = (int)fp16_value(staged y) = sid_C.
//
//  Oracles:
//    capture bytes != 0x53        -> ANE DMA WROTE the wired output record
//                                    = kernel-mediated WRITE (own target).
//    y == 127.0                   -> ANE read ALL 127 input surfaces (fp32
//                                    1.0 content) = READ door.
//    y == 1.0 (craft-A only)      -> ANE read exactly the WIRED inputs
//                                    (skip-and-continue proof + read door).
//    y == crafted value, capture
//    untouched                    -> output sid not staging-content, or
//                                    request aborts on first bad record.
//
//  Honesty: every target here is OUR surface. Foreign sids are Stage B and
//  gated on a positive result. Conversion bar untouched. hasKread=NO
//  hasKwrite=NO. Risk note: skipped input records may leave ANE input
//  IOVAs unmapped; a dart fault is possible on the lab device. ONE TAP
//  per force-quit. Per-line POSIX write + F_FULLFSYNC.
//

#import <Foundation/Foundation.h>

@interface P077AneYcraft : NSObject
+ (NSString *)tap;
@end