//
//  P090MomentariusTest.m
//  P007OpenOnly - momentarius census v1 (p090-census-v1)
//
//  READ-ONLY kernel instrument for a device that already has KRW
//  (rig iPhone 11 = iPhone12,1 A13 22G100, Dopamine 3.0.10 libkrw).
//  Purpose: validate the LabKernelOffsets DB (Dopamine 3.0.11 info.c
//  transcription, MIT (c) Lars Froeder) against the LIVE kernel, and
//  census the two anchors the v2 momentarius port needs:
//    - kernel version string VA (confirms kbase -> static VA mapping)
//    - allproc queue head (proc walk anchor, pid==0 self-check)
//
//  __DATA scan provenance: delta 0x35CC000 derived from OUR decrypted
//  22G100 kernelcache segment map (Ghidra: __TEXT 0xfffffff007004000,
//  __DATA 0x00a5d0000). It is A13-22G100-specific and gated below.
//  A14 26.5 gets its own delta from the Ghidra A14 project; never reuse
//  this number on another SKU.
//
//  Honest prereq report at the end: DB fields that need runtime
//  derivation (v2): task.itk_space, task.bsd_info, IOSurface ranges/
//  rangeCount, proc struct size, vm_map->pmap (+0x40 momentarius hardcode).
//

#import "P090MomentariusTest.h"
#import "LabDeviceProfile.h"
#import "LabKernelOffsets.h"
#import "LabLocalTime.h"
#import "P007Board.h"

#import <dlfcn.h>
#import <fcntl.h>
#import <string.h>
#import <unistd.h>
#import <sys/stat.h>

#define P090_BUILD @"p090-momentarius-census-v3"

// ---- libkrw plugin ABI (Dopamine BaseBin/_external/include/libkrw) ----
typedef int (*krw_kbase_func_t)(uint64_t *addr);
typedef int (*krw_kread_func_t)(uint64_t from, void *to, size_t len);
typedef int (*krw_kwrite_func_t)(void *from, uint64_t to, size_t len);
struct p090_krw_handlers_s {
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
typedef int (*krw_plugin_initializer_t)(struct p090_krw_handlers_s *handlers);

// ---- v2 provider chain (2026-10-25: the mini's 21D50 route) — cs2core FIRST;
// libkrw stays the fallback. The mobile-uid law (libkrw kbase=0 for this app)
// is why the core lane leads now. Same __has_include guard as rig P113 —
// the rig tree may carry no Lum1naCS2Core header. ----
#if __has_include("Lum1naCS2Core.h")
#import "Lum1naCS2Core.h"
#define P090_HAS_CS2CORE 1
#endif
#ifdef P090_HAS_CS2CORE
static int p090_rd_cs2(uint64_t a, void *b, size_t n) { return Lum1naCS2Core_KReadBuf(a, b, n) ? 0 : -1; }
static int p090_kb_cs2(uint64_t *out) { *out = Lum1naCS2Core_Kbase(); return *out ? 0 : -1; }
#endif

static int g_p090_fd = -1;
static NSMutableString *g_p090_buf;

// ---- v2 rig provider: the ARM's OWN live context (same-boot law). The rig
// tree carries the core under ClearSword/cs2/ — after a passing CS2Runner
// fire this boot, cs2_ctx.kernel_base is the kbase and cs2_kreadbuf is the
// reader. (cs2_kreadbuf: 0=success — the inverted-BOOL trap, twice-learned.) ----
#include "ClearSword/cs2/poc.h"
#include "ClearSword/cs2/krw.h"
static int p090_rd_arm(uint64_t a, void *b, size_t n) { return (cs2_kreadbuf(a, b, n) == 0) ? 0 : -1; }
static int p090_kb_arm(uint64_t *out) { *out = cs2_ctx.kernel_base; return *out ? 0 : -1; }

static void p090_log(NSString *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    NSString *line = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    NSString *out = [line hasSuffix:@"\n"] ? line : [line stringByAppendingString:@"\n"];
    @synchronized ([P090MomentariusTest class]) {
        if (g_p090_buf) [g_p090_buf appendString:out];
        if (g_p090_fd >= 0) {
            const char *s = out.UTF8String;
            if (s) {
                write(g_p090_fd, s, strlen(s));
                fcntl(g_p090_fd, F_FULLFSYNC);   /* panic-surviving flush per line */
            }
        }
    }
}

static void p090_finish(void) {
    if (g_p090_fd >= 0) { fcntl(g_p090_fd, F_FULLFSYNC); close(g_p090_fd); g_p090_fd = -1; }
}

// ---- scan window constants (A13 22G100 only - see file header) ----
static const uint64_t kP090_DataDelta = 0x35CC000ULL;   /* __DATA VA - kbase */
static const uint64_t kP090_ScanCap   = 0x200000ULL;    /* 2 MB window cap   */
static const uint64_t kP090_Chunk     = 0x10000ULL;     /* 64 KB per kread   */

static BOOL p090_looks_kernel(uint64_t v) {
    return (v >= 0xffffffe000000000ULL) && (v <= 0xffffffffffffff00ULL);
}

@implementation P090MomentariusTest

+ (NSString *)tap {
    return [self run];
}

+ (NSString *)run {
    g_p090_buf = [NSMutableString string];
    NSString *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    NSString *path = [docs stringByAppendingPathComponent:@"p090_momentarius_log.txt"];
    g_p090_fd = open(path.fileSystemRepresentation, O_CREAT | O_WRONLY | O_TRUNC, 0644);

    p090_log(@"=== p090 session %@ BUILD %@ ===", LabLocalMilitaryNow(), P090_BUILD);
    p090_log(@"momentarius census v1: LabKernelOffsets DB vs LIVE kernel.");
    p090_log(@"DB source: Dopamine 3.0.11 info.c transcription (MIT, (c) Lars Froeder).");
    p090_log(@"READ-ONLY. No kernel writes. No KRW claimed. Panic risk from");
    p090_log(@"candidate dereference during allproc heuristic is accepted.");
    p090_log(@"Device: %@ | %@", [LabDeviceProfile machine], [LabDeviceProfile osversion]);
    p090_log(@"%@", [P007Board shared].kreadSignal);

    // ---- Step 1: resolve the offsets DB for THIS device ----
    LabKernelOffsets ko;
    BOOL ok = LabKernelOffsetsResolveRunning(&ko);
    if (!ok) {
        p090_log(@"[-] LabKernelOffsetsResolveRunning FAILED (uname/sysctl).");
        p090_log(@"[-] Census cannot proceed without the DB.");
        [[P007Board shared] recordEvent:@"p090_session" kind:@"fail"
                                 detail:@"resolve failed" source:@"p090"];
        NSString *ret = g_p090_buf; g_p090_buf = nil; p090_finish(); return ret;
    }
    p090_log(@"[*] Step 1: LabKernelOffsets resolved for %@ %@ (xnu parse from kern.version).",
             [LabDeviceProfile machine], [LabDeviceProfile osversion]);
    // Full table: one line per field. Runtime fields print "= 0x0 (runtime)".
    NSString *table = LabKernelOffsetsDescription(&ko);
    for (NSString *lineObj in [table componentsSeparatedByString:@"\n"]) {
        if (lineObj.length) p090_log(@"    %@", lineObj);
    }
    [[P007Board shared] recordEvent:@"p090_resolve" kind:@"info"
                             detail:[NSString stringWithFormat:@"pid=0x%llx svuid=0x%llx ipc_table=0x%llx",
                                     ko.proc_pid, ko.proc_svuid, ko.ipc_space_table]
                             source:@"p090"];

    // ---- Step 2: KRW provider glue — v2: cs2core FIRST (the mobile-uid law
    // kills libkrw's kbase on this app), then libkrw as the FKT fallback. ----
    krw_kbase_func_t f_kbase = NULL;
    krw_kread_func_t f_kread = NULL;
    int rc = 0;   /* hoisted (v2b): the libkrw branch owns the old decl */

#ifdef P090_HAS_CS2CORE
    if (Lum1naCS2Core_IsLive()) {
        f_kbase = p090_kb_cs2;
        f_kread = p090_rd_cs2;
        p090_log(@"[+] krw via cs2core (in-process — the mini-proven route)");
    }
#endif
    /* v2c: the ARM's own live ctx (same-boot law) — after a passing CS2Runner
       fire this boot, cs2_ctx is the provider (23:03 mini run's path). */
    if (!f_kread && cs2_ctx.kernel_base != 0) {
        f_kbase = p090_kb_arm;
        f_kread = p090_rd_arm;
        p090_log(@"[+] krw via the cs2 ARM ctx (same-boot: kernel_base=0x%llx)", cs2_ctx.kernel_base);
    }
    if (!f_kread) {
    p090_log(@"[*] Step 2: libkrw glue.");
    const char *candidates[] = {
        "/var/jb/usr/lib/libkrw/libkrw-dopamine.dylib",   /* Dopamine 3.x */
        "/var/jb/usr/lib/libkrw.dylib",
        "/var/jb/usr/lib/libkrw/libkrw.dylib",
        "/var/jb/basebin/libkrw.dylib",
        "libkrw.dylib",                                    /* already loaded */
    };
    void *h = NULL;
    const char *opened = NULL;
    for (NSUInteger i = 0; i < sizeof(candidates) / sizeof(candidates[0]); i++) {
        h = dlopen(candidates[i], RTLD_NOW);
        if (h) { opened = candidates[i]; break; }
        const char *e = dlerror();
        p090_log(@"[-] dlopen %s -> %s", candidates[i], e ? e : "(no dlerror)");
    }
    if (!h) {
        p090_log(@"[-] No libkrw provider loadable (expected on NON-jailbroken devices).");
        p090_log(@"[-] This is an HONEST miss, not a failure: census part 1 (DB print)");
        p090_log(@"[-] still validated the resolver on this device. KRW sections skip.");
        [[P007Board shared] recordEvent:@"p090_libkrw" kind:@"miss"
                                 detail:@"no provider" source:@"p090"];
        p090_log(@"[*] Prereq report (v2 tasks): task.itk_space, task.bsd_info,");
        p090_log(@"[*] IOSurface ranges/rangeCount, proc struct size, vm_map->pmap:");
        p090_log(@"[*] all runtime-derivation, none hardcodable. momentarius port = v2.");
        NSString *ret = g_p090_buf; g_p090_buf = nil; p090_finish(); return ret;
    }
    p090_log(@"[+] dlopen: %s", opened);

    krw_plugin_initializer_t init = (krw_plugin_initializer_t)dlsym(h, "krw_initializer");
    if (!init) {
        p090_log(@"[-] dlsym krw_initializer FAILED: %s", dlerror());
        NSString *ret = g_p090_buf; g_p090_buf = nil; p090_finish(); return ret;
    }
    struct p090_krw_handlers_s handlers;
    memset(&handlers, 0, sizeof(handlers));
    rc = init(&handlers);
    if (rc != 0 || !handlers.kread || !handlers.kbase) {
        p090_log(@"[-] krw_initializer rc=%d kread=%p kbase=%p -> no usable primitives.",
                 rc, (void *)handlers.kread, (void *)handlers.kbase);
        NSString *ret = g_p090_buf; g_p090_buf = nil; p090_finish(); return ret;
    }
    p090_log(@"[+] krw_initializer rc=0 handlers v=%llu kbase=%p kread=%p",
             (unsigned long long)handlers.version, (void *)handlers.kbase, (void *)handlers.kread);
    f_kbase = handlers.kbase;
    f_kread = handlers.kread;
    }   /* end of the libkrw-glue fallback branch */
    uint64_t kbase = 0;
    rc = f_kbase(&kbase);
    if (rc != 0 || kbase < 0xfffff00000000000ULL) {
        p090_log(@"[-] kbase rc=%d val=0x%llx -> implausible, aborting KRW section.",
                 rc, (unsigned long long)kbase);
        NSString *ret = g_p090_buf; g_p090_buf = nil; p090_finish(); return ret;
    }
    uint32_t magic = 0;
    rc = f_kread(kbase, &magic, sizeof(magic));
    if (rc != 0 || magic != 0xfeedfacfULL) {
        p090_log(@"[-] kread32(kbase) rc=%d val=0x%x (expect 0xfeedfacf) -> aborting.",
                 rc, (unsigned int)magic);
        NSString *ret = g_p090_buf; g_p090_buf = nil; p090_finish(); return ret;
    }
    p090_log(@"[+] KRW SANITY PASS: kbase=0x%llx kread32=0xfeedfacf (kernel Mach-O header).",
             (unsigned long long)kbase);
    [[P007Board shared] recordEvent:@"p090_krw" kind:@"info"
                             detail:[NSString stringWithFormat:@"kbase=0x%llx", (unsigned long long)kbase]
                             source:@"p090"];

    // ---- Step 3: per-build FILESET windows (v3) — deltas = unslid segment
    // VA − staticBase, derived from each build's decrypted kernelcache via
    // `ipsw macho info` (UUID-matched to the device's own panic headers).
    // Reads stay INSIDE the fileset's mapped segments = the six-panic-law
    // safe habitat. 22G100 = the A13 on-device-proven delta (its constants).
    // 21D50 cache UUID 2BD6A021… 23F77 cache UUID 107196E1… ----
    NSString *mach = [LabDeviceProfile machine];
    NSString *osv  = [LabDeviceProfile osversion];
    struct { uint64_t delta; uint64_t cap; const char *tag; } wins[4];
    uint32_t nW = 0;
    {
        /* A13 22G100 — the original proven window (device-validated). */
        BOOL a13 = ([mach isEqualToString:@"iPhone12,1"] && [osv isEqualToString:@"22G100"]);
        /* A14 21D50 (mini/12 17.3) — dc 0x1870000/0x4C8000, d 0x32A0000/0x210000. */
        BOOL a14_21d = ([mach hasPrefix:@"iPhone13,"] && [osv isEqualToString:@"21D50"]);
        /* A14 23F77 (hunt 12 26.5) — dc 0xA80000/0x544000, d 0x3870000/0x240000. */
        BOOL a14_23f77 = ([mach hasPrefix:@"iPhone13,"] && [osv isEqualToString:@"23F77"]);
        if (a13) {
            wins[nW].delta = kP090_DataDelta; wins[nW].cap = kP090_ScanCap;
            wins[nW].tag = "a13-22g100-proven"; nW++;
        }
        if (a14_21d) {
            wins[nW].delta = 0x1870000ULL; wins[nW].cap = 0x4C8000ULL;
            wins[nW].tag = "a14-21d50-data-const"; nW++;
            wins[nW].delta = 0x32A0000ULL; wins[nW].cap = 0x210000ULL;
            wins[nW].tag = "a14-21d50-data"; nW++;
        }
        if (a14_23f77) {
            wins[nW].delta = 0xA80000ULL; wins[nW].cap = 0x544000ULL;
            wins[nW].tag = "a14-23f77-data-const"; nW++;
            wins[nW].delta = 0x3870000ULL; wins[nW].cap = 0x240000ULL;
            wins[nW].tag = "a14-23f77-data"; nW++;
        }
    }
    if (nW == 0) {
        p090_log(@"[-] __DATA scan gated: no per-build window row for %@ %@ yet.",
                 mach, osv);
        p090_log(@"[-] This build gets its own deltas from its decrypted kernelcache first (twin law).");
        p090_log(@"[*] Prereq report: scan deltas for this build = v2 task.");
        NSString *ret = g_p090_buf; g_p090_buf = nil; p090_finish(); return ret;
    }
    p090_log(@"[*] Step 3: __DATA windows for %@ %@ — %u window(s).", mach, osv, nW);

    const char *needle = "Darwin Kernel Version";
    const size_t needleLen = strlen(needle);
    uint64_t versionVA = 0;
    uint64_t allprocHead = 0;
    uint32_t proc0Pid = 0;
    NSMutableArray *procPids = [NSMutableArray array];
    uint64_t candidateCount = 0;

    uint8_t *chunk = malloc(kP090_Chunk);
    if (!chunk) {
        p090_log(@"[-] malloc chunk failed.");
        NSString *ret = g_p090_buf; g_p090_buf = nil; p090_finish(); return ret;
    }
    uint64_t windowBase = 0, capNow = 0;
    const char *wTag = "";
    for (uint32_t wi2 = 0; wi2 < nW && !(allprocHead && versionVA); wi2++) {
        windowBase = kbase + wins[wi2].delta;
        capNow = wins[wi2].cap;
        wTag = wins[wi2].tag;
        p090_log(@"[*] window[%u] %s = kbase + 0x%llx, cap 0x%llx",
                 wi2, wTag, wins[wi2].delta, wins[wi2].cap);
    for (uint64_t off = 0; off < capNow && !allprocHead; off += kP090_Chunk) {
        size_t chunkLen = kP090_Chunk;
        if (windowBase + off + chunkLen > windowBase + capNow) {
            chunkLen = capNow - off;
        }
        rc = f_kread(windowBase + off, chunk, chunkLen);
        if (rc != 0) {
            p090_log(@"[-] chunk kread rc=%d at +0x%llx - window ends here.",
                     rc, (unsigned long long)off);
            break;
        }
        // version string search
        if (versionVA == 0) {
            for (size_t i = 0; i + needleLen < chunkLen; i++) {
                if (memcmp(chunk + i, needle, needleLen) == 0) {
                    versionVA = windowBase + off + i;
                    break;
                }
            }
        }
        // allproc queue-head heuristic: two adjacent qwords, both kernel
        // ptrs; element0->prev == head and element0->pid == 0.
        for (uint64_t i = 0; i + 16 <= chunkLen && !allprocHead; i += 8) {
            uint64_t nxt, prv;
            memcpy(&nxt, chunk + i, 8);
            memcpy(&prv, chunk + i + 8, 8);
            if (!p090_looks_kernel(nxt) || !p090_looks_kernel(prv)) continue;
            if (nxt == prv || nxt == (windowBase + off + i)) continue;
            candidateCount++;
            uint64_t headVA = windowBase + off + i;
            uint64_t prevBack = 0;
            if (f_kread(nxt + ko.proc_list_prev, &prevBack, 8) != 0) continue;
            if (prevBack != headVA) continue;
            uint32_t pid = 0;
            if (f_kread(nxt + ko.proc_pid, &pid, 4) != 0) continue;
            if (pid != 0) continue;
            // forward-edge check: head->prev->next == head
            uint64_t lastNext = 0;
            if (f_kread(prv + ko.proc_list_next, &lastNext, 8) != 0) continue;
            if (lastNext != headVA) continue;
            allprocHead = headVA;
            proc0Pid = pid;
            // walk a few elements for pid plausibility (0, 1, ...)
            uint64_t cur = nxt;
            for (int k = 0; k < 5; k++) {
                uint32_t p = 0;
                if (f_kread(cur + ko.proc_pid, &p, 4) != 0) break;
                [procPids addObject:[NSNumber numberWithUnsignedInt:p]];
                uint64_t nextEl = 0;
                if (f_kread(cur + ko.proc_list_next, &nextEl, 8) != 0) break;
                if (nextEl == headVA || !p090_looks_kernel(nextEl)) break;
                cur = nextEl;
            }
            if (allprocHead && versionVA) break;   /* v3: window loop satisfied */
        }
    }
    }   /* v3: per-window outer loop */
    free(chunk);

    if (versionVA) {
        p090_log(@"[+] version string at 0x%llx (kbase + 0x%llx).",
                 (unsigned long long)versionVA,
                 (unsigned long long)(versionVA - kbase));
        [[P007Board shared] recordCandidate:versionVA kind:@"version_string" source:@"p090"];
    } else {
        p090_log(@"[-] version string NOT found in window (mapping or delta suspect).");
    }

    if (allprocHead) {
        p090_log(@"[+] allproc CANDIDATE at 0x%llx (kbase + 0x%llx): first el prev==head,", 
                 (unsigned long long)allprocHead,
                 (unsigned long long)(allprocHead - kbase));
        p090_log(@"[+]   first el pid==%u, prev->next==head. pid walk: %@",
                 (unsigned int)proc0Pid, [procPids componentsJoinedByString:@","]);
        [[P007Board shared] recordCandidate:allprocHead kind:@"allproc" source:@"p090"];
        [[P007Board shared] recordEvent:@"p090_allproc" kind:@"info"
                                 detail:[NSString stringWithFormat:@"head=0x%llx pids=%@",
                                         (unsigned long long)allprocHead,
                                         [procPids componentsJoinedByString:@","]]
                                 source:@"p090"];
    } else {
        p090_log(@"[-] allproc candidate NOT found in %llu heuristic probes.",
                 (unsigned long long)candidateCount);
        p090_log(@"[-] Honest: heuristic can miss (allproc may sit past the cap or");
        p090_log(@"[-] in a section our delta does not cover). v2 widens window.");
    }

    // ---- prereq report ----
    p090_log(@"[*] Census v1 complete. v2 queue: momentarius port (pmap via vm_map+0x40,");
    p090_log(@"[*] DCP MMIO 0x206050000 via IOSurface physmap) + runtime derivation of");
    p090_log(@"[*] itk_space / bsd_info / IOSurface ranges / proc struct size.");
    [[P007Board shared] recordEvent:@"p090_session" kind:@"info"
                             detail:[NSString stringWithFormat:@"ver=%@ allproc=%@",
                                     versionVA ? @"found" : @"miss",
                                     allprocHead ? @"found" : @"miss"]
                             source:@"p090"];

    NSString *ret = g_p090_buf; g_p090_buf = nil; p090_finish(); return ret;
}

@end