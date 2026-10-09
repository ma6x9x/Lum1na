//
//  P071AneOverflowMap.m
//  CVE-2026-65408 ANE integer-overflow MAP. DeviceOpen only.
//  23F77 MemoryMapRequest_gated @ 0xfffffff00874c7f4
//    outputBuffersMappingInfo = kalloc_data(view 0x7cc5a58, n_out*0xc00)
//    n_out comes from program +0xa00 (uint, zero-extended to 64-bit * 0xc00).
//  User count param_2[0x204] already FAIL 0xe00002c2 if > 0x80.
//  43748 is the 0xff-vs-0x80 fill. This TAP does not fire either.
//

#import "P071AneOverflowMap.h"
#import "LabDeviceProfile.h"
#import "LabLocalTime.h"

#import <IOKit/IOKitLib.h>
#import <fcntl.h>
#import <string.h>
#import <unistd.h>

#define P071_BUILD @"p071-ane-overflow-map-v1"
#define P071_SEL_DEVICEOPEN 0
#define P071_DEVICEOPEN_SZ 0x68

@implementation P071AneOverflowMap

+ (NSString *)tap {
    NSMutableString *log = [NSMutableString string];
    NSString *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    int fd = open([[docs stringByAppendingPathComponent:@"p071_ane_overflow_log.txt"] UTF8String],
                  O_CREAT | O_WRONLY | O_TRUNC, 0644);
    void (^L)(NSString *) = ^(NSString *s) {
        NSString *out = [s hasSuffix:@"\n"] ? s : [s stringByAppendingString:@"\n"];
        [log appendString:out];
        if (fd >= 0) { const char *p = out.UTF8String; if (p) write(fd, p, strlen(p)); }
    };

    L([NSString stringWithFormat:@"=== p071 session %@ BUILD %@ ===", LabLocalMilitaryNow(), P071_BUILD]);
    L(@"CVE-2026-65408 ANE integer overflow terminate. NOT 43748 fill.");
    L(@"MemoryMapRequest_gated 0xfffffff00874c7f4  CheckandPrewire 0xfffffff00874c070");
    L(@"Theory: n_outputs at procedure+0xa00 * 0xc00 kalloc_data. 64-bit multiply,");
    L(@"uint n_out zero-extended so wrap is not 32-bit. User count capped 0x80.");
    L(@"This TAP: H11ANEIn type=1 + DeviceOpen 0x68. No ProgramSendRequest. No huge n.");
    NSString *stop = [LabDeviceProfile stopUnlessA14_23F77:@"p071"];
    if (stop) {
        L(stop);
        if (fd >= 0) { fcntl(fd, F_FULLFSYNC); close(fd); }
        return log;
    }

    io_service_t svc = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("H11ANEIn"));
    L([NSString stringWithFormat:@"H11ANEIn service=%u", (unsigned)svc]);
    if (!svc) {
        L(@"[-] H11ANEIn missing. 65408 still MAP via CoreML path, unfired.");
        if (fd >= 0) { fcntl(fd, F_FULLFSYNC); close(fd); }
        return log;
    }

    for (uint32_t t = 0; t < 2; t++) {
        io_connect_t conn = 0;
        kern_return_t kr = IOServiceOpen(svc, mach_task_self(), t, &conn);
        L([NSString stringWithFormat:@"IOServiceOpen type=%u kr=0x%x conn=0x%x",
           t, (unsigned)kr, (unsigned)conn]);
        if (kr != 0 || !conn) continue;

        uint8_t stIn[P071_DEVICEOPEN_SZ];
        uint8_t stOut[P071_DEVICEOPEN_SZ];
        memset(stIn, 0, sizeof(stIn));
        memset(stOut, 0, sizeof(stOut));
        size_t outSz = sizeof(stOut);
        kr = IOConnectCallStructMethod(conn, P071_SEL_DEVICEOPEN, stIn, sizeof(stIn), stOut, &outSz);
        L([NSString stringWithFormat:@"  DeviceOpen sel=0 stIn=0x68 kr=0x%x outSz=%zu",
           (unsigned)kr, outSz]);
        L(@"  STOP. No sel2/19 ProgramSendRequest. No 254-input. No crafted n_out.");
        IOServiceClose(conn);
    }
    IOObjectRelease(svc);

    L(@"=== VERDICT === 65408 dest still unnamed as a wrapping multiply.");
    L(@"Live multiply in MemoryMap is 64-bit (uint n_out * 0xc00). 43748 fill is separate.");
    L(@"hasKread=NO. Isolation: force-quit before CONV/P044.");
    if (fd >= 0) { fcntl(fd, F_FULLFSYNC); close(fd); }
    return log;
}

@end
