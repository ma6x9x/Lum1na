//
//  P086IomdDmaFingerprint.m — bounded UC sweep for the 43684 DMA-command
//  path (see .h for the fingerprint). Discovery only: no dmaCommand setup,
//  no teardown race, no unbounded counters.
//

#import "P086IomdDmaFingerprint.h"
#import "LabDeviceProfile.h"
#import "LabLocalTime.h"

#import <IOKit/IOKitLib.h>
#import <fcntl.h>
#import <string.h>
#import <unistd.h>

#define P086_BUILD @"p086-iomd-dma-fingerprint-v2"

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

@implementation P086IomdDmaFingerprint

+ (NSString *)tap {
    g_log = [NSMutableString string];
    NSString *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    g_fd = open([[docs stringByAppendingPathComponent:@"p086_iomd_dma_fingerprint_log.txt"] UTF8String],
                O_CREAT | O_WRONLY | O_TRUNC, 0644);

    L([NSString stringWithFormat:@"=== p086 session %@ BUILD %@ ===",
        LabLocalMilitaryNow(), P086_BUILD]);
    L(@"43684 dmaCommandOperation fingerprint sweep. Fingerprint (Ghidra 23F77):");
    L(@"  0xe00002d8 reuse-addr/len mismatch | 0xe00002d0 alignment | 0xe00002db length-over-MD");
    L(@"Bounded: 3 UCs x sel 0..40 x 3 shapes, zero/short args. NO fires.");
    L(@"Dual SKU: A14 23F77 and A12X 23G71. Fingerprint codes are xnu-class, not T8101 VAs.");
    NSString *stop = [LabDeviceProfile stopUnlessA14_23F77:@"p086"];
    if (stop) {
        L(stop);
        if (g_fd >= 0) { fcntl(g_fd, F_FULLFSYNC); close(g_fd); }
        return g_log;
    }
    L([LabDeviceProfile identBlock]);

    /* v2 (2026-10-19): these are IOServiceMatching REGISTRY CLASS names,
       not kext bundle ids. p038 proved AppleM2ScalerCSCDriver opens type 0
       and 1 on 23F77 (kr=0x0); P066 proved AppleAVE2Driver matches. The old
       IOSurfaceAcceleratorClient / AppleAVE2 strings never matched, which
       pinned fingerprint_hits=0 structurally instead of empirically. */
    const char *svcs[3] = { "AppleM2ScalerCSCDriver", "IOGPU", "AppleAVE2Driver" };
    int fingerprints = 0;

    for (int v = 0; v < 3; v++) {
        io_service_t svc = IOServiceGetMatchingService(kIOMainPortDefault,
            IOServiceMatching(svcs[v]));
        if (!svc) { L([NSString stringWithFormat:@"[%s] service not found", svcs[v]]); continue; }
        for (int t = 0; t <= 1; t++) {
            io_connect_t conn = 0;
            kern_return_t kr = IOServiceOpen(svc, mach_task_self(), t, &conn);
            if (kr != KERN_SUCCESS || !conn) {
                L([NSString stringWithFormat:@"[%s] type=%d open kr=0x%x", svcs[v], t, kr]);
                continue;
            }
            L([NSString stringWithFormat:@"[%s] type=%d conn=0x%x", svcs[v], t, conn]);
            int hits = 0;
            for (uint32_t sel = 0; sel <= 40; sel++) {
                /* shape A: scalars only */
                uint64_t scA[4] = {0, 0, 0, 0};
                uint32_t scAcnt = 4;
                uint64_t scOut[8] = {0};
                uint32_t scOutCnt = 8;
                kr = IOConnectCallScalarMethod(conn, sel, scA, scAcnt, scOut, &scOutCnt);
                if (kr == 0xe00002d8u || kr == 0xe00002d0u || kr == 0xe00002dbu) {
                    hits++; fingerprints++;
                    L([NSString stringWithFormat:@"  *** FP [%s] type=%d sel=%u scalars kr=0x%x ***",
                        svcs[v], t, sel, kr]);
                }
                /* shape B: short struct (28B — the ACM/AVE-ish shape) */
                uint8_t stB[28]; memset(stB, 0, sizeof(stB));
                uint8_t stOutB[256]; size_t stOutSz = sizeof(stOutB);
                kr = IOConnectCallStructMethod(conn, sel, stB, sizeof(stB), stOutB, &stOutSz);
                if (kr == 0xe00002d8u || kr == 0xe00002d0u || kr == 0xe00002dbu) {
                    hits++; fingerprints++;
                    L([NSString stringWithFormat:@"  *** FP [%s] type=%d sel=%u struct28 kr=0x%x ***",
                        svcs[v], t, sel, kr]);
                }
                /* shape C: struct with an offset/length pair (dmaCommand shape) */
                uint8_t stC[32]; memset(stC, 0, sizeof(stC));
                uint64_t a0 = 0, a1 = 0x1000;   /* addr=0 len=0x1000: length-over-MD probe */
                memcpy(stC, &a0, 8); memcpy(stC + 8, &a1, 8);
                size_t stOutSzC = sizeof(stOutB);
                kr = IOConnectCallStructMethod(conn, sel, stC, sizeof(stC), stOutB, &stOutSzC);
                if (kr == 0xe00002d8u || kr == 0xe00002d0u || kr == 0xe00002dbu) {
                    hits++; fingerprints++;
                    L([NSString stringWithFormat:@"  *** FP [%s] type=%d sel=%u struct32offlen kr=0x%x ***",
                        svcs[v], t, sel, kr]);
                }
            }
            L([NSString stringWithFormat:@"[%s] type=%d sweep done hits=%d", svcs[v], t, hits]);
            IOServiceClose(conn);
        }
        IOObjectRelease(svc);
    }

    L([NSString stringWithFormat:@"=== VERDICT fingerprint_hits=%d ===", fingerprints]);
    L(@"A hit = the 43684 DMA-command path via this UC+selector. P087 fire map targets it.");
    L(@"HONESTY: discovery only. No fires. hasKread=NO.");
    if (g_fd >= 0) { fcntl(g_fd, F_FULLFSYNC); close(g_fd); }
    return g_log;
}

@end