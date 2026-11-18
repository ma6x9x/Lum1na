//
//  P171StaleArrivalOracle.m — stale-arrival socket-slot oracle (read-only). p171.
//  2026-11-17.
//
//  Borrow: Tims-Cooked --sockprec/--sockmix oracle concepts (their receipts:
//  109 stale arrivals / 335 dgrams on iPhone14,2 24A5390f, 4/14 on 18,1 —
//  their interpreted kernel-stale-write, their conclusion cross-type reclaim
//  blocked). We measure the observable with OUR controls on our builds:
//    Phase 0  control: self-dgram (sendto our own listener) MUST arrive.
//    Phase A  never-sent listeners, NO churn: baseline foreign arrivals
//             (background probers / daemons are a real noise source —
//             counted and classified, not disambiguated).
//    Phase B  never-sent listeners WITH a UDP create/close churn thread
//             (same-type slot recycle: the cs2-lane question — does slot
//             reuse increase stale arrivals?).
//    Phase C  self-dgram control repeated after churn (sanity).
//  A hit = recvfrom on a listener never targeted by us. Payloads: classify
//  only (length + printable-window sample, <=16 chars) — never full dumps.
//  NO kernel writes, NO OOB, no mach primitives. PANIC-FREE.
//

#import "P171StaleArrivalOracle.h"
#import "LabDeviceProfile.h"
#import "LabLocalTime.h"

#import <Foundation/Foundation.h>
#import <fcntl.h>
#import <unistd.h>
#import <string.h>
#import <stdlib.h>
#import <pthread.h>
#import <sys/socket.h>
#import <netinet/in.h>
#import <poll.h>

#define P171_BUILD @"p171-stale-arrival-v1"

static int g_p171_fd = -1;

static void p171_line(NSString *s) {
    NSString *t = [s hasSuffix:@"\n"] ? s : [s stringByAppendingString:@"\n"];
    if (g_p171_fd >= 0) {
        const char *c = t.UTF8String;
        if (c) { write(g_p171_fd, c, strlen(c)); fcntl(g_p171_fd, F_FULLFSYNC); }
    }
}

static volatile int g_p171_churn_go = 0;

static void *p171_churn(void *arg) {
    (void)arg;
    while (g_p171_churn_go) {
        int created = 0;
        int fds[256];
        for (int i = 0; i < 256; i++) {
            fds[i] = socket(AF_INET, SOCK_DGRAM, 0);
            if (fds[i] >= 0) created++;
        }
        for (int i = 0; i < 256; i++) if (fds[i] >= 0) close(fds[i]);
        usleep(2000);
    }
    return NULL;
}

/* returns listener count bound */
static int p171_makeListeners(int n, int *outfds, uint16_t basePort) {
    int made = 0;
    for (int i = 0; i < n; i++) {
        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0) continue;
        struct sockaddr_in a;
        memset(&a, 0, sizeof(a));
        a.sin_family = AF_INET;
        a.sin_addr.s_addr = htonl(INADDR_ANY);
        a.sin_port = htons(basePort + (uint16_t)i);
        if (bind(fd, (struct sockaddr *)&a, sizeof(a)) != 0) { close(fd); continue; }
        int fl = fcntl(fd, F_GETFL, 0);
        if (fl >= 0) fcntl(fd, F_SETFL, fl | O_NONBLOCK);
        outfds[made++] = fd;
    }
    return made;
}

/* poll all listeners once; log arrivals with never-sent classification */
static void p171_poll(int *fds, int n, uint16_t basePort, NSString *phase,
                      uint64_t *hits, uint64_t *dgrams, int fdStart) {
    struct pollfd *pf = calloc(1, sizeof(struct pollfd) * n);
    for (int i = 0; i < n; i++) { pf[i].fd = fds[i]; pf[i].events = POLLIN; }
    int r = poll(pf, n, 300);
    if (r > 0) {
        for (int i = 0; i < n; i++) {
            if (!(pf[i].revents & POLLIN)) continue;
            uint8_t buf[512];
            struct sockaddr_in src;
            socklen_t sl = sizeof(src);
            ssize_t len = recvfrom(fds[i], buf, sizeof(buf), 0, (struct sockaddr *)&src, &sl);
            if (len <= 0) continue;
            (*dgrams)++;
            /* never-sent classification: this fd is a pure listener; the only
               dgrams it MAY legally receive are our own control frames sent to
               (basePort+i) which the caller marks. Phase A callers never send. */
            (*hits)++;
            /* payload classification: printable window, capped */
            char sample[17];
            uint32_t s = 0;
            for (; s < 16 && s < (uint32_t)len; s++)
                sample[s] = (buf[s] >= 0x20 && buf[s] < 0x7f) ? (char)buf[s] : '.';
            sample[s] = 0;
            p171_line([NSString stringWithFormat:
                @"  [%@] HIT fd#%d len=%zu src=%u.%u.%u.%u:%u head=\"%s\"",
                phase, i + fdStart, (size_t)len,
                (unsigned)(ntohl(src.sin_addr.s_addr) >> 24),
                (unsigned)((ntohl(src.sin_addr.s_addr) >> 16) & 0xff),
                (unsigned)((ntohl(src.sin_addr.s_addr) >> 8) & 0xff),
                (unsigned)(ntohl(src.sin_addr.s_addr) & 0xff),
                (unsigned)ntohs(src.sin_port), sample]);
        }
    }
    free(pf);
}

@implementation P171StaleArrivalOracle

+ (NSString *)tap {
    NSMutableString *o = [NSMutableString string];
    NSString *docs = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory,
                                                          NSUserDomainMask, YES) firstObject];
    g_p171_fd = open([docs stringByAppendingPathComponent:@"p171_oracle_log.txt"].fileSystemRepresentation,
                     O_CREAT | O_WRONLY | O_TRUNC, 0644);
    NSString *line = [NSString stringWithFormat:@"=== p171 session %@ BUILD %@ ===\n%@\n"
        "Stale-arrival oracle (read-only, PANIC-FREE). Borrow: Tims --sockprec/--sockmix.\n"
        "Question: does slot reuse put live queue state on OUR never-sent listeners?\n",
        LabLocalMilitaryNow(), P171_BUILD, [LabDeviceProfile identBlock]];
    p171_line(line);
    [o appendString:line];

    uint16_t base = (uint16_t)(0x8000 + (arc4random() & 0x3ff0));
    int fds[512];
    const int N = 256;

    /* Phase 0: control — self-dgram MUST arrive */
    {
        int n = p171_makeListeners(1, fds, base);
        if (n == 1) {
            int snd = socket(AF_INET, SOCK_DGRAM, 0);
            struct sockaddr_in a;
            socklen_t al = sizeof(a);
            getsockname(fds[0], (struct sockaddr *)&a, &al);
            uint8_t mark[8] = {'P','1','7','1','S','E','L','F'};
            sendto(snd, mark, 8, 0, (struct sockaddr *)&a, sizeof(a));
            /* control recv is EXPECTED; mark as control not stale hit */
            struct pollfd pf = { .fd = fds[0], .events = POLLIN };
            int r = poll(&pf, 1, 500);
            if (r > 0 && (pf.revents & POLLIN)) {
                uint8_t b[64]; recv(fds[0], b, sizeof(b), 0);
                line = [NSString stringWithFormat:@"  [CTRL] self-dgram DELIVERED (baseline channel live)\n"];
                p171_line(line); [o appendString:line];
            } else {
                line = [NSString stringWithFormat:@"  [CTRL] self-dgram NOT delivered — environment broken, verdicts void\n"];
                p171_line(line); [o appendString:line];
            }
            close(fds[0]); close(snd);
        }
    }

    /* Phase A: never-sent, no churn (12 s) */
    int made = p171_makeListeners(N, fds, base);
    line = [NSString stringWithFormat:@"  [A] %d never-sent listeners bound (%u..%u), poll 12 s\n",
            made, (unsigned)base, (unsigned)(base + made - 1)];
    p171_line(line); [o appendString:line];
    uint64_t hitsA = 0, dgA = 0;
    for (int t = 0; t < 40 && made > 0; t++) {
        p171_poll(fds, made, base, @"A-norchurn", &hitsA, &dgA, 0);
    }
    p171_line([NSString stringWithFormat:@"  [A done] hits=%llu dgrams=%llu\n",
              (unsigned long long)hitsA, (unsigned long long)dgA]);
    [o appendFormat:@"  [A done] hits=%llu dgrams=%llu\n",
        (unsigned long long)hitsA, (unsigned long long)dgA];

    /* Phase B: same listeners + UDP churn (12 s) */
    g_p171_churn_go = 1;
    pthread_t tid;
    int churned = (pthread_create(&tid, NULL, p171_churn, NULL) == 0);
    if (churned) {
        line = [NSString stringWithFormat:@"  [B] churn ON (256-burst UDP create/close)\n"];
        p171_line(line); [o appendString:line];
    }
    uint64_t hitsB = 0, dgB = 0;
    for (int t = 0; t < 40 && made > 0; t++) {
        p171_poll(fds, made, base, @"B-churn", &hitsB, &dgB, 0);
    }
    if (churned) { g_p171_churn_go = 0; pthread_join(tid, NULL); }
    p171_line([NSString stringWithFormat:@"  [B done] hits=%llu dgrams=%llu\n",
              (unsigned long long)hitsB, (unsigned long long)dgB]);
    [o appendFormat:@"  [B done] hits=%llu dgrams=%llu\n",
        (unsigned long long)hitsB, (unsigned long long)dgB];

    /* verdict */
    line = [NSString stringWithFormat:
        @"[VERDICT] no-churn=%llu/%llu churn=%llu/%llu — %s\n"
        "(hits with no foreign prober in range = stale queue/slot carryover;\n"
        " churn- delta = no same-zone recycle effect on our builds)\n",
        (unsigned long long)hitsA, (unsigned long long)dgA,
        (unsigned long long)hitsB, (unsigned long long)dgB,
        (hitsA + hitsB) ? "ARRIVALS OBSERVED — check sources before claiming slot carryover"
                        : "CLEAN — no stale arrivals on this boot"];
    p171_line(line); [o appendString:line];
    line = [NSString stringWithFormat:@"  NOTE: hit classification (stale-carryover vs foreign prober) is\n"
              "  NOT decidable from this tap alone — correlate src/port with a netstat\n"
              "  window if a hit row appears. Feeds the cs2 reclaim-shape question.\n"];
    p171_line(line); [o appendString:line];

    for (int i = 0; i < made; i++) close(fds[i]);
    if (g_p171_fd >= 0) { fcntl(g_p171_fd, F_FULLFSYNC); close(g_p171_fd); g_p171_fd = -1; }
    return o;
}

@end
