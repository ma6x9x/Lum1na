//
//  P067AvdReach.m
//  CVE-2026-65407 AppleAVD UAF — IOServiceOpen reach. No decoder bitstream fire.
//

#import "P067AvdReach.h"
#import "LabDeviceProfile.h"
#import "LabLocalTime.h"

#import <IOKit/IOKitLib.h>
#import <fcntl.h>
#import <unistd.h>

#define P067_BUILD @"p067-avd-reach-v1"

@implementation P067AvdReach

+ (NSString *)tap {
    NSMutableString *log = [NSMutableString string];
    NSString *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    int fd = open([[docs stringByAppendingPathComponent:@"p067_avd_reach_log.txt"] UTF8String],
                  O_CREAT | O_WRONLY | O_TRUNC, 0644);
    void (^L)(NSString *) = ^(NSString *s) {
        NSString *out = [s hasSuffix:@"\n"] ? s : [s stringByAppendingString:@"\n"];
        [log appendString:out];
        if (fd >= 0) { const char *p = out.UTF8String; if (p) write(fd, p, strlen(p)); }
    };
    L([NSString stringWithFormat:@"=== p067 session %@ BUILD %@ ===", LabLocalMilitaryNow(), P067_BUILD]);
    L(@"CVE-2026-65407 AppleAVD UAF terminate. cve65407_AVD_session_stats_bound 0xfffffff008193944");
    L(@"client id cap 0x3f; complete-session frees 0xa0 kalloc_data. OPEN types 0..3.");
    L(@"No compressed bitstream, no remaining-fire.");
    NSString *stop = [LabDeviceProfile stopUnlessA14_23F77:@"p067"];
    if (stop) {
        L(stop);
        if (fd >= 0) { fcntl(fd, F_FULLFSYNC); close(fd); }
        return log;
    }

    const char *names[] = { "AppleAVD", "AppleAVDUserClient", "IODPAudio", NULL };
    for (int n = 0; names[n]; n++) {
        io_service_t svc = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching(names[n]));
        L([NSString stringWithFormat:@"service %s = %u", names[n], (unsigned)svc]);
        if (!svc) continue;
        for (uint32_t t = 0; t < 4; t++) {
            io_connect_t conn = 0;
            kern_return_t kr = IOServiceOpen(svc, mach_task_self(), t, &conn);
            L([NSString stringWithFormat:@"  type=%u kr=0x%x conn=0x%x", t, (unsigned)kr, (unsigned)conn]);
            if (conn) IOServiceClose(conn);
        }
        IOObjectRelease(svc);
    }
    L(@"=== VERDICT === reach MAP. UAF dest still unnamed. hasKread=NO.");
    if (fd >= 0) { fcntl(fd, F_FULLFSYNC); close(fd); }
    return log;
}

@end
