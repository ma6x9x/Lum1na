//
//  P161SEPKeyStoreTestUC.m
//  P161 — AppleSEPKeyStore test-UC type sweep.
//
//  Static backing (23F77 A14):
//    AppleKeyStoreTest          registered by the production ctor 0x8d8838c
//    AppleKeyStoreTestUserClient registered at 0x8d883e0 (name 0x75c6453)
//    AppleKeyStoreUserClient    production UC (name 0x75c92eb)
//  P104 opens the KeyStore services with types 0+1 and sweeps the 163
//  selectors. This probe is the missing first half: which IOServiceOpen
//  *type* instantiates the test UC? It opens types 0..32, reads the service
//  and child classes, and flags any "Test" user client. No selector is
//  called. PANIC-POSSIBLE: an unknown type can assert; one tap per boot.
//

#import "P161SEPKeyStoreTestUC.h"
#import "LabDeviceProfile.h"
#import "LabLocalTime.h"

#import <Foundation/Foundation.h>
#import <IOKit/IOKitLib.h>
#import <mach/mach.h>
#import <fcntl.h>
#import <string.h>
#import <unistd.h>

#define P161_BUILD @"p161-sepks-testuc-v1"
#define P161_TYPES 32

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

@implementation P161SEPKeyStoreTestUC

+ (NSString *)classOf:(io_object_t)obj {
    io_name_t name;
    if (IOObjectGetClass(obj, name) == KERN_SUCCESS) {
        return [NSString stringWithUTF8String:name];
    }
    return @"?";
}

+ (NSString *)property:(NSString *)key of:(io_object_t)obj {
    CFTypeRef v = IORegistryEntryCreateCFProperty(
        obj, (__bridge CFStringRef)key, kCFAllocatorDefault, 0);
    if (!v) return nil;
    NSString *s = nil;
    if (CFGetTypeID(v) == CFStringGetTypeID()) {
        s = [NSString stringWithString:(__bridge NSString *)v];
    }
    CFRelease(v);
    return s;
}

/// User clients are registry children of the provider. Listing them after
/// each open is how a type-selected test class becomes visible without
/// calling any selector.
+ (NSArray<NSString *> *)childClasses:(io_service_t)svc {
    NSMutableArray<NSString *> *out = [NSMutableArray array];
    io_iterator_t it = 0;
    if (IORegistryEntryGetChildIterator(svc, kIOServicePlane, &it) != KERN_SUCCESS) {
        return out;
    }
    io_object_t child = 0;
    while ((child = IOIteratorNext(it)) != 0) {
        NSString *cls = [self classOf:child];
        if (cls.length) [out addObject:cls];
        IOObjectRelease(child);
        if (out.count >= 16) break;
    }
    IOObjectRelease(it);
    return out;
}

+ (BOOL)looksTest:(NSString *)s {
    return s.length && [s rangeOfString:@"Test" options:NSCaseInsensitiveSearch].location != NSNotFound;
}

+ (NSString *)join:(NSArray<NSString *> *)a {
    return a.count ? [a componentsJoinedByString:@","] : @"(none)";
}

+ (NSString *)tap {
    g_log = [NSMutableString string];
    NSString *docs = NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    g_fd = open([[docs stringByAppendingPathComponent:@"p161_sepks_testuc_log.txt"] UTF8String],
                O_CREAT | O_WRONLY | O_TRUNC, 0644);

    L([NSString stringWithFormat:@"=== p161 session %@ BUILD %@ ===",
        LabLocalMilitaryNow(), P161_BUILD]);
    L(@"AppleSEPKeyStore test-UC type sweep. Static: AppleKeyStoreTestUserClient "
      @"is registered in the production ctor (0x8d8838c -> 0x8d883e0).");
    L(@"Opens types 0..32; reads service IOUserClientClass/IOClass/bundle and the "
      @"provider's registry children after each open. NO selectors. NO writes.");
    L(@"PANIC-POSSIBLE: an unknown user-client type can assert. One tap per force-quit.");
    L([LabDeviceProfile identBlock]);

    NSArray<NSString *> *services = @[
        @"AppleKeyStore",
        @"AppleKeyStoreTest",
        @"AppleSEPKeyStore",
        @"AppleSEPKeyStoreTest",
        @"com.apple.driver.AppleSEPKeyStore",
    ];

    int servicesFound = 0, opens = 0, testHits = 0, instances = 0;
    NSMutableSet<NSString *> *openTypes = [NSMutableSet set];

    for (NSString *name in services) {
        CFMutableDictionaryRef match = IOServiceMatching(name.UTF8String);
        if (!match) {
            L([NSString stringWithFormat:@"[%@] no matching dictionary", name]);
            continue;
        }
        io_service_t svc = IOServiceGetMatchingService(kIOMainPortDefault, match);
        if (!svc) {
            L([NSString stringWithFormat:@"[%@] service not found", name]);
            continue;
        }
        servicesFound++;

        NSString *svcClass = [self classOf:svc];
        NSString *ucClass = [self property:@"IOUserClientClass" of:svc];
        NSString *ioClass = [self property:@"IOClass" of:svc];
        NSString *bundle = [self property:@"CFBundleIdentifier" of:svc];
        L([NSString stringWithFormat:@"[%@] class=%@ IOUserClientClass=%@ IOClass=%@ bundle=%@",
            name, svcClass, ucClass ?: @"(null)", ioClass ?: @"(null)", bundle ?: @"(null)"]);
        if ([self looksTest:ucClass]) {
            L([NSString stringWithFormat:@"  TEST-UC? class property: %@", ucClass]);
            testHits++;
        }

        NSArray<NSString *> *before = [self childClasses:svc];
        L([NSString stringWithFormat:@"  children(before)=%@", [self join:before]]);
        for (NSString *c in before) {
            if ([self looksTest:c]) {
                L([NSString stringWithFormat:@"  TEST-UC? child(before): %@", c]);
                testHits++;
            }
        }

        for (uint32_t type = 0; type <= P161_TYPES; type++) {
            io_connect_t conn = 0;
            kern_return_t kr = IOServiceOpen(svc, mach_task_self(), type, &conn);
            BOOL opened = (kr == KERN_SUCCESS && conn != 0);
            [openTypes addObject:[NSString stringWithFormat:@"%@:%u=0x%x", name, type, kr]];
            if (!opened) {
                L([NSString stringWithFormat:@"  %@ type=%u kr=0x%x", name, type, kr]);
                continue;
            }

            opens++;
            instances++;
            NSArray<NSString *> *after = [self childClasses:svc];
            L([NSString stringWithFormat:@"  %@ type=%u conn=0x%x (OPEN) children(after)=%@",
                name, type, conn, [self join:after]]);
            for (NSString *c in after) {
                if ([self looksTest:c]) {
                    L([NSString stringWithFormat:@"    TEST-UC? child(after): %@", c]);
                    testHits++;
                }
            }
            IOServiceClose(conn);
            if (instances >= 24) {
                L(@"  [cap] stopped after 24 successful opens");
                break;
            }
        }

        IOObjectRelease(svc);
    }

    L([NSString stringWithFormat:@"=== VERDICT services_found=%d opens=%d test_hits=%d ===",
        servicesFound, opens, testHits]);
    if (testHits > 0) {
        L(@"TEST-UC VISIBLE. Next: a selector probe against the type/child above; "
          @"do not call the 163-sel sweep on it until the class is confirmed.");
    } else {
        L(@"No test-class child seen. Either no type selects it, the class is not "
          @"a registry child, or the driver does not register it on this SKU.");
    }
    L(@"HONESTY: open/property census only. No external method, no writes, hasKread=NO.");
    if (g_fd >= 0) { fcntl(g_fd, F_FULLFSYNC); close(g_fd); }
    return g_log;
}

@end
