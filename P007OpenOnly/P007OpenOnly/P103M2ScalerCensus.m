//
//  P103M2ScalerCensus.m — M2ScalerCSCDriver opens-only sel census
//  (notes 228/238/240). Discovery only: no transforms, no counter setups,
//  no dmaCommand paths. Bounded sweep.
//

#import "P103M2ScalerCensus.h"
#import "LabDeviceProfile.h"
#import "LabLocalTime.h"

#import <IOKit/IOKitLib.h>
#import <fcntl.h>
#import <string.h>
#import <unistd.h>

#define P103_BUILD @"p103-m2scaler-census-v1"

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

@implementation P103M2ScalerCensus

+ (NSString *)tap {
    g_log = [NSMutableString string];
    NSString *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    g_fd = open([[docs stringByAppendingPathComponent:@"p103_m2scaler_census_log.txt"] UTF8String],
                O_CREAT | O_WRONLY | O_TRUNC, 0644);

    L([NSString stringWithFormat:@"=== p103 session %@ BUILD %@ ===",
        LabLocalMilitaryNow(), P103_BUILD]);
    L(@"M2ScalerCSCDriver user_* census (note 238). Targets:");
    L(@"  sel=11 semantics (p101's permissive mapper), the K2U/K2K boundary denials,");
    L(@"  and the iosaDiag (sel 8, p097/p098 leak-window) kr shape.");
    L(@"Bounded: 2 opens x sel 0..40 x benign shapes. NO transforms. NO fires.");
    NSString *stop = [LabDeviceProfile stopUnlessA14_23F77:@"p103"];
    if (stop) {
        L(stop);
        if (g_fd >= 0) { fcntl(g_fd, F_FULLFSYNC); close(g_fd); }
        return g_log;
    }
    L([LabDeviceProfile identBlock]);

    /* p066-pooled lesson (note 234): log the census kr verdicts per sel —
       "plain-SUCCESS" is NOT a fire; the census classifies RESPONSE SHAPES. */
    const char *svc = "AppleM2ScalerCSCDriver";
    int opens = 0, odd = 0;

    /* the pool's decoded method order for the verdict columns (note 238):
       the UC's method table order maps roughly to sels — kept as labels. */
    const char *labels[] = {
        "0:?", "1:?", "2:?", "3:?", "4:?", "5:?", "6:?", "7:?",
        "8:iosaDiag?", "9:?", "10:?", "11:permissive?", "12:?", "13:?",
        "14:?", "15:?", "16:?", "17:?", "18:?", "19:?", "20:?", "21:?",
        "22:?", "23:?", "24:?", "25:?", "26:?", "27:?", "28:?", "29:?",
        "30:?", "31:?", "32:?", "33:?", "34:?", "35:?", "36:?", "37:?",
        "38:?", "39:?", "40:?"
    };

    for (int t = 0; t <= 1; t++) {
        io_service_t s = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching(svc));
        if (!s) { L([NSString stringWithFormat:@"[%s] service not found", svc]); continue; }
        io_connect_t conn = 0;
        kern_return_t kr = IOServiceOpen(s, mach_task_self(), t, &conn);
        if (kr != KERN_SUCCESS || !conn) {
            L([NSString stringWithFormat:@"[%s] type=%d open kr=0x%x", svc, t, kr]);
            IOObjectRelease(s);
            continue;
        }
        opens++;
        L([NSString stringWithFormat:@"[%s] type=%d conn=0x%x (OPEN)", svc, t, conn]);
        for (uint32_t sel = 0; sel <= 40; sel++) {
            uint64_t sc[4] = {0, 0, 0, 0};
            uint64_t out[8] = {0};
            uint32_t outc = 8;
            kern_return_t k1 = IOConnectCallScalarMethod(conn, sel, sc, 4, out, &outc);
            uint8_t st[28]; memset(st, 0, sizeof(st));
            uint8_t stOut[256]; memset(stOut, 0, sizeof(stOut));
            size_t stOutSz = sizeof(stOut);
            kern_return_t k2 = IOConnectCallStructMethod(conn, sel, st, sizeof(st), stOut, &stOutSz);

            NSMutableArray *odds = [NSMutableArray array];
            /* the boundary/context denials + the non-standard kr classes */
            if (k1 != 0xe00002c2 && k1 != 0 && k1 != 0xe00002bc)
                [odds addObject:[NSString stringWithFormat:@"SCALAR-ODD 0x%x", k1]];
            if (k2 != 0xe00002c2 && k2 != 0 && k2 != 0xe00002bc)
                [odds addObject:[NSString stringWithFormat:@"STRUCT-ODD 0x%x", k2]];
            if (odds.count) {
                L([NSString stringWithFormat:@"  sel=%u %s %@ (type=%d)",
                   sel, labels[sel], [odds componentsJoinedByString:@", "], t]);
                odd++;
            }
        }
        L([NSString stringWithFormat:@"[%s] type=%d sweep done odd=%d", svc, t, odd]);
        IOServiceClose(conn);
        IOObjectRelease(s);
    }

    L([NSString stringWithFormat:@"=== VERDICT opens=%d odd_verdicts=%d ===", opens, odd]);
    L(@"Odd verdicts = the sel's RESPONSE SHAPE (boundary denial vs permissive mapper vs diag read).");
    L(@"P101's sel=11 + the P097/P098 leak-window sels get their exact semantics from this map.");
    L(@"HONESTY: census only. NO fires. hasKread=NO.");
    if (g_fd >= 0) { fcntl(g_fd, F_FULLFSYNC); close(g_fd); }
    return g_log;
}

@end