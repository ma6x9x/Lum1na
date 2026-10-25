//
//  P108DiskImagesCensus.m — DiskImages2 + KDI UserClient census (note 255).
//  Question: is the disk-image attach door (AppleDiskImages2's UC, incl.
//  KDIDiskImageNubUserClient's registration home) reachable from a sandboxed
//  app? Opens-only + sel sweep, benign shapes, NO transforms, NO fires.
//  Note-255 verdict: the KDI kext itself = stubs (readBytes/writeBytes =
//  kIOReturnUnsupported); the UC surface lives behind the controller plate.
//

#import "P108DiskImagesCensus.h"
#import "LabDeviceProfile.h"
#import "LabLocalTime.h"

#import <IOKit/IOKitLib.h>
#import <fcntl.h>
#import <string.h>
#import <stdarg.h>
#import <unistd.h>

#define P108_BUILD @"p108-diskimages-regwalk-v2"

static NSMutableString *g_log = nil;
static int g_fd = -1;
static void Lv(NSString *s) {
    if (!g_log) return;
    NSString *out = [s hasSuffix:@"\n"] ? s : [s stringByAppendingString:@"\n"];
    [g_log appendString:out];
    if (g_fd >= 0) {
        const char *p = out.UTF8String;
        if (p) { write(g_fd, p, strlen(p)); fcntl(g_fd, F_FULLFSYNC); }
    }
}
static void L(NSString *fmt, ...) NS_FORMAT_FUNCTION(1,2);
static void L(NSString *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    Lv(s);
}

@implementation P108DiskImagesCensus

+ (NSString *)tap {
    g_log = [NSMutableString string];
    NSString *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    g_fd = open([[docs stringByAppendingPathComponent:@"p108_diskimages_census_log.txt"] UTF8String],
                O_CREAT | O_WRONLY | O_TRUNC, 0644);

    L([NSString stringWithFormat:@"=== p108 session %@ BUILD %@ ===",
        LabLocalMilitaryNow(), P108_BUILD]);
    L(@"AppleDiskImages2 / KDI UC census (note 255). The disk-image attach door:");
    L(@"open + sel sweep, types 0/1, benign shapes. NO attach calls, NO images.");
    L([LabDeviceProfile identBlock]);

    /* service names = the controller plate + any KDI class the IORegistry
       exposes directly. Matching is honest (absence = a result). */
    /* v2: plane-wide registry walk FIRST - the four legacy names returned
       "service not found" on every device (v1). On modern iOS the disk-image
       driver may surface under an entirely different class name, or only
       while an image is attached. Absence = a MEASURED result. */
    {
        mach_port_t mp = kIOMainPortDefault;
        io_iterator_t it = 0;
        kern_return_t wkr = IORegistryCreateIterator(mp, "IOService", 0, &it);
        L(@"[regwalk] IOService-plane iterator kr=0x%x", (unsigned)wkr);
        int hits = 0;
        if (wkr == KERN_SUCCESS && it) {
            io_object_t obj;
            while ((obj = IOIteratorNext(it))) {
                io_name_t cls = {0}, nam = {0};
                IOObjectGetClass(obj, cls);
                IORegistryEntryGetName(obj, nam);
                if (strcasestr(cls, "Disk") || strcasestr(nam, "Disk") ||
                    strcasestr(cls, "HDIX") || strcasestr(nam, "HDIX") ||
                    strcasestr(cls, "Image") || strcasestr(nam, "Image") ||
                    strcasestr(cls, "Digi")  || strcasestr(nam, "Digi")) {
                    L(@"[regwalk] HIT class=%s name=%s", cls, nam);
                    hits++;
                }
                IOObjectRelease(obj);
                if (hits > 40) break;
            }
            IOObjectRelease(it);
        }
        L(@"[regwalk] done hits=%d (plane-wide Disk/HDIX/Image/Digi)", hits);
    }

    const char *svcs[] = {
        "AppleDiskImages2",
        "AppleDiskImages2DiskImageController",
        "IOHDIXHDDriveInKernel",
        "KDIDiskImageNubUserClient",
    };

    for (size_t si = 0; si < sizeof(svcs)/sizeof(svcs[0]); si++) {
        const char *svc = svcs[si];
        io_service_t s = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching(svc));
        if (!s) {
            L([NSString stringWithFormat:@"[%s] service not found", svc]);
            continue;
        }
        L([NSString stringWithFormat:@"[%s] FOUND", svc]);
        for (int t = 0; t <= 1; t++) {
            io_connect_t conn = 0;
            kern_return_t kr = IOServiceOpen(s, mach_task_self(), t, &conn);
            if (kr != KERN_SUCCESS || !conn) {
                L([NSString stringWithFormat:@"  type=%d open kr=0x%x (denied or wrong type)", t, kr]);
                continue;
            }
            L([NSString stringWithFormat:@"  type=%d conn=0x%x (OPEN)", t, conn]);
            for (uint32_t sel = 0; sel <= 24; sel++) {
                uint64_t sc[4] = {0, 0, 0, 0};
                uint64_t out[8] = {0};
                uint32_t outc = 8;
                kern_return_t k1 = IOConnectCallScalarMethod(conn, sel, sc, 4, out, &outc);
                uint8_t st[28]; memset(st, 0, sizeof(st));
                uint8_t stOut[256]; memset(stOut, 0, sizeof(stOut));
                size_t stOutSz = sizeof(stOut);
                kern_return_t k2 = IOConnectCallStructMethod(conn, sel, st, sizeof(st), stOut, &stOutSz);

                NSMutableArray *odds = [NSMutableArray array];
                if (k1 != 0xe00002c2 && k1 != 0 && k1 != 0xe00002bc)
                    [odds addObject:[NSString stringWithFormat:@"SCALAR-ODD 0x%x", k1]];
                if (k2 != 0xe00002c2 && k2 != 0 && k2 != 0xe00002bc)
                    [odds addObject:[NSString stringWithFormat:@"STRUCT-ODD 0x%x", k2]];
                if (odds.count)
                    L([NSString stringWithFormat:@"  sel=%u %@ (type=%d)", sel, [odds componentsJoinedByString:@", "], t]);
            }
            L([NSString stringWithFormat:@"  type=%d sweep done", t]);
            IOServiceClose(conn);
        }
        IOObjectRelease(s);
    }

    L(@"=== VERDICT ===");
    L(@"opens>0 = the attach door is app-reachable (then the file-parse surface");
    L(@" = the UDIF/KernelBacked parsers via the controller). Denials = the");
    L(@" attach path stays root/entitlement-gated — the kext remains a pool");
    L(@" lever only. hasKread=NO. Census only, no attaches fired.");
    if (g_fd >= 0) { fcntl(g_fd, F_FULLFSYNC); close(g_fd); }
    return g_log;
}

@end