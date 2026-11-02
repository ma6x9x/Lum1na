//
//  P007KreadLane.m
//  P007OpenOnly
//
//  libkrw glue is the P090 transcription (Dopamine 3.x provider paths,
//  krw_initializer ABI). Board fallback composes kread64 from two kread32
//  calls (little-endian) and offers NO buffered read and NO writes — the
//  probes log that honestly instead of pretending.
//

#import "P007KreadLane.h"
#import "P007Board.h"

#import <dlfcn.h>

#pragma mark - libkrw plugin ABI (Dopamine BaseBin _external/include/libkrw)

typedef int (*krw_kbase_func_t)(uint64_t *addr);
typedef int (*krw_kread_func_t)(uint64_t from, void *to, size_t len);
typedef int (*krw_kwrite_func_t)(void *from, uint64_t to, size_t len);

struct p007_krw_handlers_s {
    uint64_t version;
    krw_kbase_func_t kbase;
    krw_kread_func_t kread;
    krw_kwrite_func_t kwrite;
    uint64_t kmalloc;
    uint64_t kdealloc;
    uint64_t kcall;
    uint64_t physread;
    uint64_t physwrite;
};
typedef int (*krw_plugin_initializer_t)(struct p007_krw_handlers_s *handlers);

#pragma mark - lazy libkrw init (P090 pattern)

static krw_kread_func_t  g_kread  = NULL;
static krw_kwrite_func_t g_kwrite = NULL;
static krw_kbase_func_t  g_kbaseF = NULL;
static uint64_t g_kbase = 0;
static BOOL g_libkrwTried = NO;

static void P007LaneInitLibkrw(void) {
    @synchronized ([P007Board class]) {
        if (g_libkrwTried) return;
        g_libkrwTried = YES;

        const char *candidates[] = {
            "/var/jb/usr/lib/libkrw/libkrw-dopamine.dylib",   /* Dopamine 3.x */
            "/var/jb/usr/lib/libkrw.dylib",
            "/var/jb/usr/lib/libkrw/libkrw.dylib",
            "/var/jb/basebin/libkrw.dylib",
            "libkrw.dylib",                                    /* already loaded */
        };
        void *h = NULL;
        for (NSUInteger i = 0; i < sizeof(candidates) / sizeof(candidates[0]); i++) {
            h = dlopen(candidates[i], RTLD_NOW);
            if (h) break;
        }
        if (!h) return; /* honest miss: no provider (stock device) */

        krw_plugin_initializer_t init = (krw_plugin_initializer_t)dlsym(h, "krw_initializer");
        if (!init) return;

        struct p007_krw_handlers_s handlers;
        memset(&handlers, 0, sizeof(handlers));
        if (init(&handlers) != 0 || !handlers.kread || !handlers.kbase) return;

        uint64_t kb = 0;
        if (handlers.kbase(&kb) != 0 || kb < 0xfffff00000000000ULL) return;
        uint32_t magic = 0;
        if (handlers.kread(kb, &magic, sizeof(magic)) != 0 || magic != 0xfeedfacfULL) return;

        /* sanity passed: kernel Mach-O header read through the provider */
        g_kbase  = kb;
        g_kread  = handlers.kread;
        g_kwrite = handlers.kwrite;
        g_kbaseF = handlers.kbase;
    }
}

#pragma mark - board fallback lane

static P007Kread32Fn LaneBoardKread32(void) {
    P007Board *b = [P007Board shared];
    if (!b.hasKread) return NULL;   /* commitSlide gate — record, not license */
    return [b kread32Fn];
}

#pragma mark - API

bool P007LaneLive(void) {
    P007LaneInitLibkrw();
    return g_kread != NULL || LaneBoardKread32() != NULL;
}

const char *P007LaneName(void) {
    P007LaneInitLibkrw();
    if (g_kread) return "libkrw";
    if (LaneBoardKread32()) return "board-kread32";
    return "none";
}

bool P007LaneBuffered(void) {
    P007LaneInitLibkrw();
    return g_kread != NULL || LaneBoardKread32() != NULL;
}

uint64_t P007LaneSlide(void) {
    P007Board *b = [P007Board shared];
    if (b.kslide) return b.kslide;
    P007LaneInitLibkrw();
    if (g_kread) return g_kbase - b.staticBase;   /* provider ground truth */
    return 0;
}

uint64_t P007LaneKbase(void) {
    P007LaneInitLibkrw();
    return g_kbase;
}

uint64_t P007LaneKRead64(uint64_t a) {
    P007LaneInitLibkrw();
    if (g_kread) {
        uint64_t v = 0;
        return g_kread(a, &v, sizeof(v)) == 0 ? v : 0;
    }
    P007Kread32Fn f = LaneBoardKread32();
    if (f) {
        BOOL okLo = NO, okHi = NO;
        uint32_t lo = f(a, &okLo);
        uint32_t hi = f(a + 4, &okHi);
        if (okLo && okHi) return ((uint64_t)hi << 32) | lo;   /* little-endian */
    }
    return 0;
}

uint32_t P007LaneKRead32(uint64_t a) {
    P007LaneInitLibkrw();
    if (g_kread) {
        uint32_t v = 0;
        return g_kread(a, &v, sizeof(v)) == 0 ? v : 0;
    }
    P007Kread32Fn f = LaneBoardKread32();
    if (f) {
        BOOL ok = NO;
        uint32_t v = f(a, &ok);
        return ok ? v : 0;
    }
    return 0;
}

bool P007LaneKWrite64(uint64_t a, uint64_t v) {
    P007LaneInitLibkrw();
    if (g_kwrite) return g_kwrite(&v, a, sizeof(v)) == 0;
    return false;   /* board-kread32 lane is read-only */
}

bool P007LaneKWrite32(uint64_t a, uint32_t v) {
    P007LaneInitLibkrw();
    if (g_kwrite) return g_kwrite(&v, a, sizeof(v)) == 0;
    return false;   /* board-kread32 lane is read-only */
}

ssize_t P007LaneKReadBuf(uint64_t kaddr, void *buf, size_t len) {
    if (!buf || !len) return -1;
    P007LaneInitLibkrw();
    if (g_kread) return g_kread(kaddr, buf, len) == 0 ? (ssize_t)len : (ssize_t)-1;
    /* board-kread32 lane: honest chunked bulk (2 x kread32 per qword).
       Slow on MB windows — P094's cap stays the discipline. */
    P007Kread32Fn f = LaneBoardKread32();
    if (f) {
        uint8_t *out = (uint8_t *)buf;
        for (size_t o = 0; o + 4 <= len; o += 4) {
            BOOL ok = NO;
            uint32_t v = f(kaddr + o, &ok);
            if (!ok) return o ? (ssize_t)o : (ssize_t)-1;
            memcpy(out + o, &v, 4);
        }
        return (ssize_t)(len & ~(size_t)3);
    }
    return -1;
}