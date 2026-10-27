//
//  P112CGShading.h
//  Lum1na-Debug (P007 rig)
//
//  CVE-2026-112611 — CoreGraphics Type-5 (lattice Gouraud) shading OOB oracle,
//  in-process port of the vendored public generator
//  (ios-xnu-hunt/jb-sources/cve-112611-cg-shading/poc/make_poc_shading.py).
//
//  Site law (analysis/CVE-2026-112611_type5_shading.md, both-side 24A435 vs
//  24B115 disasm): a /ShadingType 5 dict with /ColorSpace nc components and a
//  /Function whose /Range output dimension R != nc lets _cg_shading_type5_draw
//  write R attacker-chosen doubles into the nc-slot color area (record+0x20) of
//  a 72-byte stack-VLA mesh record. For R=136 the last record's writes run
//  past the VLA into spilled live state (triangle count + mesh pointer), so
//  the runaway loop dereferences the SMASHED pointer = the bit pattern of the
//  attacker-chosen /C0 double. Fixed in 27.2 (24B115) by a parse-time gate in
//  _CGPDFShadingType5Init (range_dim == nc && nc <= 4, "CG-SEC-187882049" log);
//  draw code unchanged (gate-only fix).
//
//  On-device proof (analysis/on-device-proof.md): deterministic EXC_BAD_ACCESS
//  SIGSEGV at 0x3ff000000000001c = 1.0-bits (0x3FF0000000000000) + 0x1c
//  structural offset, inside cg_shading_type5_draw, via op_sh page render.
//
//  Probe shape (p072/P076 sibling class, CoreGraphics public import):
//    1. control PDF (R=nc=1, in-bounds) through the same in-process render
//       path (CGPDFDocumentCreateWithProvider -> CGContextDrawPDFPage) —
//       proves the harness; survives on every build.
//    2. the oracle PDF built AT TAP TIME in-process, /Range R=136, with the
//       CHOSEN-DOUBLE KNOB (/C0 = /C1 = the chosen value): a VALUE-CONTROL
//       sweep of 4 chosen doubles max per tap (1.0, 2.0, 4.0, 8.0). Each
//       render is marked IN FLIGHT (fsync'd) BEFORE it runs, with that
//       value's IEEE-754 bit pattern and the expected far class printed —
//       if the render kills the process, the log already names the round
//       and the expected far (one tap per force-quit law).
//
//  THREE-OUTCOME HONEST LAW (p110/p072 class):
//    (a) render survived = no in-process fault (on a PATCHED build / the 27.2
//        parse-time gate this is the EXPECTED outcome; the CG-SEC-187882049
//        unified-log line is the fixed-build receipt, not readable in-app).
//    (b) in-process fault = SIGSEGV/SIGBUS-class catch in the async-signal-
//        safe handler (P110SurfaceSwapClaim sigaction law): prints far +
//        the chosen-double bit pattern relationship BEFORE dying. The
//        fault address's upper bits == the chosen double's bit pattern is
//        the ONLY primitive claim (value-control evidence, no success).
//    (c) survive-with-anomaly = honest print; no user-observable CG security
//        log exists in-app for outcome (c) — stated openly.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface P112CGShading : NSObject
+ (NSString *)tap;   // returns the log body
@end

NS_ASSUME_NONNULL_END