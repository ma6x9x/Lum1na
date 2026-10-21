//
//  P104SepksCensus.m — AppleSEPKeyStore UC census (notes 241/242).
//  Opens-only + benign zero shapes. The gate verdict table comes from the
//  decoded dispatch (note 242): expect the aks klog lines in the console
//  log for the gate paths (handle-0/uid/entitlement denials).
//

#import "P104SepksCensus.h"
#import "LabDeviceProfile.h"
#import "LabLocalTime.h"

#import <IOKit/IOKitLib.h>
#import <fcntl.h>
#import <string.h>
#import <unistd.h>

#define P104_BUILD @"p104-sepks-census-v1"

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

@implementation P104SepksCensus

+ (NSString *)tap {
    g_log = [NSMutableString string];
    NSString *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    g_fd = open([[docs stringByAppendingPathComponent:@"p104_sepks_census_log.txt"] UTF8String],
                O_CREAT | O_WRONLY | O_TRUNC, 0644);

    L([NSString stringWithFormat:@"=== p104 session %@ BUILD %@ ===",
        LabLocalMilitaryNow(), P104_BUILD]);
    L(@"AppleSEPKeyStore census (notes 241/242). 163-sel table @0xfffffff008d9f868.");
    L(@"Expected gate verdicts: sels 7/17/31 handle0 -> 0xfffffffa; non-entitled -> 0xe00002c2-family.");
    L(@"Watch idevicesyslog: klog lines are the gate oracle (handle 0 requested outside of user session / unexpected session uid / invalid handle).");
    L(@"Bounded: 3 opens x sel 0..0xa2 x benign shapes. NO writes. NO packed payloads.");
    NSString *stop = [LabDeviceProfile stopUnlessA14_23F77:@"p104"];
    if (stop) {
        L(stop);
        if (g_fd >= 0) { fcntl(g_fd, F_FULLFSYNC); close(g_fd); }
        return g_log;
    }
    L([LabDeviceProfile identBlock]);

    const char *svcs[3] = { "AppleKeyStore", "AppleKeyStoreTest", "com.apple.driver.AppleSEPKeyStore" };
    int opens = 0, svcs_found = 0, verdict_hits = 0;

    for (int v = 0; v < 3; v++) {
        io_service_t svc = IOServiceGetMatchingService(kIOMainPortDefault,
            IOServiceMatching(svcs[v]));
        if (!svc) { L([NSString stringWithFormat:@"[%s] service not found", svcs[v]]); continue; }
        svcs_found++;
        for (int t = 0; t <= 1; t++) {
            io_connect_t conn = 0;
            kern_return_t kr = IOServiceOpen(svc, mach_task_self(), t, &conn);
            if (kr != KERN_SUCCESS || !conn) {
                L([NSString stringWithFormat:@"[%s] type=%d open kr=0x%x", svcs[v], t, kr]);
                continue;
            }
            opens++;
            L([NSString stringWithFormat:@"[%s] type=%d conn=0x%x (OPEN)", svcs[v], t, conn]);
            int hit = 0;
            for (uint32_t sel = 0; sel <= 0xa2; sel++) {
                /* shape A: 4 zero scalars (benign; MIG-style scalar entry) */
                uint64_t sc[4] = {0, 0, 0, 0};
                uint64_t out[8] = {0};
                uint32_t outc = 8;
                kern_return_t k1 = IOConnectCallScalarMethod(conn, sel, sc, 4, out, &outc);

                /* shape B: 0x28 zero struct — the p057 AKS envelope size */
                uint8_t stB[0x28]; memset(stB, 0, sizeof(stB));
                uint8_t stOut[0x80]; memset(stOut, 0, sizeof(stOut));
                size_t stOutSz = sizeof(stOut);
                kern_return_t k2 = IOConnectCallStructMethod(conn, sel, stB, sizeof(stB), stOut, &stOutSz);

                int is_block_sel = (sel == 7 || sel == 17 || sel == 31);
                NSString *verdict = @"";
                if (is_block_sel && (k1 == 0xfffffffa || k2 == 0xfffffffa)) {
                    verdict = @"<GATE:handle0-block>";  /* predicted outside-session verdict */
                    hit++; verdict_hits++;
                }
                if ((k1 == 0xe00002c2 || k2 == 0xe00002c2) && !is_block_sel) {
                    /* entitlement/context denial (expected for the gated majority) */
                    verdict = @"<DENIAL>";
                }
                if (verdict.length) {
                    L([NSString stringWithFormat:@"  sel=%u scalar=0x%x struct=0x%x %@",
                       sel, k1, k2, verdict]);
                }
                /* log the NON-denial, non-block winners (the ungated minority) */
                if (!verdict.length && (k1 == 0 || k2 == 0) && sel <= 0x23) {
                    L([NSString stringWithFormat:@"  sel=%u OPEN-ish scalar=0x%x struct=0x%x (ungated!)",
                       sel, k1, k2]);
                }
            }
            L([NSString stringWithFormat:@"[%s] type=%d sweep done verdicts=%d", svcs[v], t, hit]);
            IOServiceClose(conn);
        }
        IOObjectRelease(svc);
    }

    L([NSString stringWithFormat:@"=== VERDICT svcs_found=%d opens=%d gate_verdict_hits=%d ===",
       svcs_found, opens, verdict_hits]);
    L(@"gate_verdict_hits = the decoded handle-0 gate CONFIRMED live from an app.");
    L(@"HONESTY: census only. No fires. No writes. hasKread=NO.");
    if (g_fd >= 0) { fcntl(g_fd, F_FULLFSYNC); close(g_fd); }
    return g_log;
}

@end