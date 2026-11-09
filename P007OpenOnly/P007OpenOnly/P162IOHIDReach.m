//
//  P162IOHIDReach.m
//  P007OpenOnly
//
//  Bench27 (SKVLENT/iOS27-Research-Exploits) closed the IOHID 112515 path at
//  AppleMultitouchDeviceUserClient: every open type returned NotPermitted.
//  This probe checks the whole HID service family on our builds — the index
//  bug's table object carries a " hid" magic, and any open client is a
//  candidate entry point. Read-only: IOServiceOpen only, no selectors.
//

#import "P162IOHIDReach.h"
#import "LabDeviceProfile.h"
#import "LabLocalTime.h"

#import <Foundation/Foundation.h>
#import <IOKit/IOKitLib.h>
#import <mach/mach.h>

#define P162_BUILD @"p162-iohid-reach-v1"

@implementation P162IOHIDReach

+ (NSString *)classOf:(io_object_t)obj {
    io_name_t name;
    if (IOObjectGetClass(obj, name) == KERN_SUCCESS) {
        return [NSString stringWithUTF8String:name];
    }
    return @"?";
}

+ (NSString *)tap {
    NSMutableString *o = [NSMutableString string];
    [o appendFormat:@"=== p162 session %@ BUILD %@ ===\n",
        LabLocalMilitaryNow(), P162_BUILD];
    [o appendString:[LabDeviceProfile identBlock]];
    [o appendString:@"  [law] read-only open probe for the CVE-2026-112515 lane. "
                     @"No external method is called. Bench27 measured AppleMultitouchDevice "
                     @"refusing every type on 27.0.1; this checks the wider HID family on this build.\n"];

    NSArray<NSString *> *classes = @[
        @"IOHIDDevice",
        @"IOHIDEventService",
        @"IOHIDEventDriver",
        @"IOHIDInterface",
        @"IOHIDResource",
        @"AppleMultitouchDevice",
        @"AppleMultitouchDeviceUserClient",
        @"IOHIDEventServiceFastPathUserClient",
    ];

    int totalServices = 0, totalOpens = 0;
    for (NSString *cls in classes) {
        CFMutableDictionaryRef match = IOServiceMatching(cls.UTF8String);
        if (!match) {
            [o appendFormat:@"  [%@] no matching dictionary\n", cls];
            continue;
        }
        io_iterator_t it = 0;
        kern_return_t mkr = IOServiceGetMatchingServices(kIOMainPortDefault, match, &it);
        if (mkr != KERN_SUCCESS) {
            [o appendFormat:@"  [%@] match kr=0x%x\n", cls, mkr];
            continue;
        }
        int n = 0;
        io_object_t svc = 0;
        while ((svc = IOIteratorNext(it)) != 0) {
            n++;
            NSString *real = [self classOf:svc];
            NSMutableString *line = [NSMutableString stringWithFormat:
                @"  [%@] inst=%d class=%@", cls, n, real];
            for (uint32_t type = 0; type <= 4; type++) {
                io_connect_t conn = 0;
                kern_return_t kr = IOServiceOpen(svc, mach_task_self(), type, &conn);
                [line appendFormat:@" t%u=0x%x%@", type, kr,
                    (kr == KERN_SUCCESS ? @"(OPEN)" : @"")];
                if (kr == KERN_SUCCESS) {
                    totalOpens++;
                    if (conn) IOServiceClose(conn);
                }
            }
            [o appendFormat:@"%@\n", line];
            totalServices++;
            if (n >= 8) {
                [o appendString:@"  [cap] stopped after 8 instances of this class\n"];
                IOObjectRelease(svc);
                break;
            }
            IOObjectRelease(svc);
        }
        IOObjectRelease(it);
        if (n == 0) [o appendFormat:@"  [%@] no instances\n", cls];
    }

    [o appendFormat:@"  [res] classes=%lu services=%d openOK=%d\n",
        (unsigned long)classes.count, totalServices, totalOpens];
    [o appendString:@"  [verdict] open-OK clients above are the only app-reachable HID entry points; "
                       @"0x(e00002c7)=Unsupported, 0x(e00002c1)=NotPrivileged, "
                       @"0x(e00002e2)=NotPermitted. An open client still needs a selector shape "
                       @"before it can reach the 112515 index path; do not call selectors blind.\n"];
    [o appendFormat:@"=== p162 end %@ ===\n", LabLocalMilitaryNow()];
    return o;
}

@end
