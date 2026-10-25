/*
 * p062_neon_mac.c — Mac arm64 fast-path for the P062 NEON exception channel.
 *
 * Same questions as the iOS TAP:
 *   (a) does the exception message contain ARM_NEON_STATE64 (flavor 17)?
 *   (b) do the 64 magic qwords round-trip?
 *   (c) thread_get_state / set_state persist across resume?
 *
 *   clang -O0 -g -o /tmp/p062_neon_mac tools/p062_neon_mac.c
 *   /tmp/p062_neon_mac          # NOT under lldb — lldb steals brk #0
 *
 * arm64 macOS only. Not KRW. Not hasKread.
 */

#if !defined(__arm64__)
#include <stdio.h>
int main(void)
{
    fprintf(stderr,
            "p062_neon_mac: this Mac is not arm64.\n"
            "The NEON exception channel is AArch64 xnu. Run this file on Apple Silicon,\n"
            "or tap P062 on the A14 23F77 phone (not under lldb).\n");
    return 2;
}
#else

#include <mach/mach.h>
#include <mach/exception_types.h>
#include <mach/arm/thread_status.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>

#ifndef ARM_NEON_STATE64
#define ARM_NEON_STATE64 17
#endif

#define P062_NEON_QWORDS 64
#define P062_MAGIC_A 0x4142434445464748ULL
#define P062_MAGIC_B 0x5152535455565758ULL

static volatile mach_port_t g_excPort = MACH_PORT_NULL;
static volatile thread_act_t g_workerThread = MACH_PORT_NULL;
static volatile int g_excReceived = 0;
static int g_neonFlavorSeen = 0;
static uint32_t g_neonCountSeen = 0;
static uint64_t g_neonSeen[P062_NEON_QWORDS];
static int g_neonMatchCount = 0;
static int g_p1_pass = 0;
static int g_p2_pass = 0;

static volatile int g_p2_ready = 0;
static volatile uint64_t g_p2_obs = 0;
static volatile int g_p2_quit = 0;

static uint64_t expect_q(int q)
{
    return (q & 1) ? (P062_MAGIC_B + (uint64_t)q)
                   : (P062_MAGIC_A + (uint64_t)q);
}

static void fill_and_brk(void)
{
    uint64_t v0[P062_NEON_QWORDS] __attribute__((aligned(16)));
    for (int i = 0; i < P062_NEON_QWORDS; i++)
        v0[i] = expect_q(i);
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

static void *worker_fn(void *arg)
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
        fprintf(stderr, "[P1] thread_set_exception_ports kr=0x%x\n", kr);
        return NULL;
    }
    fill_and_brk();
    fprintf(stderr, "[P1] worker returned from brk\n");
    return NULL;
}

static void parse_msg(mach_msg_header_t *mh, uint8_t *msgbuf)
{
    printf("[P1] msgh_id=%d size=%u bits=0x%x\n",
           mh->msgh_id, mh->msgh_size, mh->msgh_bits);
    if (mh->msgh_size < sizeof(mach_msg_header_t) + 8)
        return;
    uint32_t *words = (uint32_t *)(msgbuf + sizeof(mach_msg_header_t));
    uint32_t nwords = (mh->msgh_size - (uint32_t)sizeof(mach_msg_header_t)) / 4;
    uint32_t dump_n = nwords < 16 ? nwords : 16;
    printf("[P1] body u32s:");
    for (uint32_t i = 0; i < dump_n; i++)
        printf(" %08x", words[i]);
    printf("\n");

    for (uint32_t i = 0; i + 1 < nwords; i++) {
        if (words[i] != (uint32_t)ARM_NEON_STATE64)
            continue;
        uint32_t cnt = words[i + 1];
        if (cnt < 64 || cnt > 160 || (i + 2 + cnt) > nwords)
            continue;
        g_neonFlavorSeen = 1;
        g_neonCountSeen = cnt;
        uint64_t *st = (uint64_t *)&words[i + 2];
        uint32_t nq = cnt / 2;
        if (nq > P062_NEON_QWORDS)
            nq = P062_NEON_QWORDS;
        for (uint32_t q = 0; q < nq; q++)
            g_neonSeen[q] = st[q];
        break;
    }

    if (g_neonFlavorSeen) {
        int match = 0;
        for (int q = 0; q < P062_NEON_QWORDS; q++) {
            if (g_neonSeen[q] == expect_q(q))
                match++;
        }
        g_neonMatchCount = match;
        printf("[P1] flavor 17 at count=%u (ARM_NEON_STATE64_COUNT=%u) match=%d/%d "
               "V0=0x%016llx 0x%016llx\n",
               g_neonCountSeen, (unsigned)ARM_NEON_STATE64_COUNT,
               match, P062_NEON_QWORDS, g_neonSeen[0], g_neonSeen[1]);
        if (match >= 28)
            g_p1_pass = 1;
    } else {
        printf("[P1] ARM_NEON_STATE64 NOT found (%u words, flavor %d, COUNT %u)\n",
               nwords, ARM_NEON_STATE64, (unsigned)ARM_NEON_STATE64_COUNT);
    }
}

static void *handler_fn(void *arg)
{
    (void)arg;
    uint8_t msgbuf[0x2000];
    memset(msgbuf, 0, sizeof(msgbuf));
    mach_msg_header_t *mh = (mach_msg_header_t *)msgbuf;
    kern_return_t kr = mach_msg(mh, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0,
                                sizeof(msgbuf), g_excPort, 5000, MACH_PORT_NULL);
    if (kr != MACH_MSG_SUCCESS) {
        fprintf(stderr, "[P1] mach_msg kr=0x%x\n", kr);
        return NULL;
    }
    g_excReceived = 1;
    parse_msg(mh, msgbuf);
    if (g_workerThread != MACH_PORT_NULL)
        thread_terminate(g_workerThread);
    return NULL;
}

static void *p2_worker(void *arg)
{
    (void)arg;
    g_p2_ready = 1;
    uint64_t v0[2] __attribute__((aligned(16)));
    while (!g_p2_quit) {
        __asm__ volatile("stp q0, q1, [%0]\n" : : "r"(v0) : "memory");
        g_p2_obs = v0[0];
        usleep(1000);
    }
    return NULL;
}

static void phase2(void)
{
    pthread_t th;
    g_p2_quit = 0;
    g_p2_ready = 0;
    g_p2_obs = 0;
    pthread_create(&th, NULL, p2_worker, NULL);
    while (!g_p2_ready)
        usleep(1000);

    thread_act_t target = pthread_mach_thread_np(th);
    kern_return_t kr = thread_suspend(target);
    printf("[P2] suspend kr=0x%x\n", kr);

    arm_neon_state64_t neon;
    memset(&neon, 0, sizeof(neon));
    mach_msg_type_number_t cnt = ARM_NEON_STATE64_COUNT;
    kr = thread_get_state(target, ARM_NEON_STATE64, (thread_state_t)&neon, &cnt);
    if (kr != KERN_SUCCESS) {
        printf("[P2] get_state kr=0x%x FAIL\n", kr);
        thread_resume(target);
        g_p2_quit = 1;
        pthread_join(th, NULL);
        return;
    }
    printf("[P2] get_state OK count=%u\n", cnt);

    uint64_t newV0[2] = { 0xDEADC0DEDEADC0DEULL, 0xCAFEBABECAFEBABEULL };
    memcpy(&neon.__v[0], newV0, sizeof(newV0));
    kr = thread_set_state(target, ARM_NEON_STATE64,
                          (thread_state_t)&neon, ARM_NEON_STATE64_COUNT);
    printf("[P2] set_state kr=0x%x\n", kr);
    thread_resume(target);
    usleep(50000);
    printf("[P2] observed V0=0x%016llx want 0xDEADC0DEDEADC0DE\n", g_p2_obs);
    if (g_p2_obs == 0xDEADC0DEDEADC0DEULL)
        g_p2_pass = 1;
    g_p2_quit = 1;
    pthread_join(th, NULL);
}

int main(void)
{
    printf("p062_neon_mac  ARM_NEON_STATE64=%d COUNT=%u sizeof=%zu (want 17 / 132 / 528)\n",
           ARM_NEON_STATE64, (unsigned)ARM_NEON_STATE64_COUNT,
           sizeof(arm_neon_state64_t));
    printf("NOT under lldb. Not KRW. Not hasKread.\n");

    kern_return_t kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE,
                                          (mach_port_t *)&g_excPort);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "port alloc kr=0x%x\n", kr);
        return 1;
    }
    kr = mach_port_insert_right(mach_task_self(), g_excPort, g_excPort,
                                MACH_MSG_TYPE_MAKE_SEND);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "insert send kr=0x%x\n", kr);
        return 1;
    }

    pthread_t h, w;
    pthread_create(&h, NULL, handler_fn, NULL);
    usleep(50000);
    pthread_create(&w, NULL, worker_fn, NULL);

    for (int i = 0; i < 100 && !g_excReceived; i++)
        usleep(50000);
    if (g_workerThread != MACH_PORT_NULL)
        thread_terminate(g_workerThread);
    pthread_join(w, NULL);
    if (!g_excReceived && g_excPort != MACH_PORT_NULL) {
        mach_port_destroy(mach_task_self(), g_excPort);
        g_excPort = MACH_PORT_NULL;
    }
    pthread_join(h, NULL);
    if (g_excPort != MACH_PORT_NULL) {
        mach_port_destroy(mach_task_self(), g_excPort);
        g_excPort = MACH_PORT_NULL;
    }

    phase2();

    printf("\n=== VERDICT ===\n");
    printf("(a) flavor ARM_NEON_STATE64 found: %s (count=%u)\n",
           g_neonFlavorSeen ? "PASS" : "FAIL", g_neonCountSeen);
    printf("(b) magic qword match: %s (%d/%d, need >= 28)\n",
           g_p1_pass ? "PASS" : "FAIL", g_neonMatchCount, P062_NEON_QWORDS);
    printf("(c) get_state/set_state roundtrip: %s\n",
           g_p2_pass ? "PASS" : "FAIL");
    return (g_p1_pass && g_p2_pass) ? 0 : 1;
}
#endif /* __arm64__ */
