//
//  P141UsbStockholm.m — the USB/Stockholm REACHABILITY ORACLE. p141.
//  Lum1na-Debug (P007 rig). iOS kernel research (Lum1na).
//
//  Laws honored tonight: dlsym IOKit only; the local MachPortKObject
//  prototype (P069 no-header law); one open per lane; the census = 4
//  scalar rows, bounded 16 sels; close after. The mini's CLI rows are
//  recorded in NOTES_MINI_CROSSREF_21D50.md — this tap = the fleet's
//  in-app comparison rows (the 23F77 row the tethered question needs).
//

#import "P141UsbStockholm.h"
#import "LabDeviceProfile.h"
#import "LabLocalTime.h"
#import "LabBandit.h"

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

#define P141_BUILD @"p141-usbstockholm-v1"

typedef io_object_t p_ioservice_t; typedef io_object_t p_iosvc_t;
typedef io_object_t p_iosvc_m;
typedef CFMutableDictionaryRef (*IOServiceMatching_t)(const char *);
typedef p_iosvc_t (*GetSVC_t)(mach_port_t, CFDictionaryRef);
typedef kern_return_t (*IOOpen_t)(p_iosvc_m, task_port_t, uint32_t, p_iosvc_m *);
typedef IOReturn (*IOClose_t)(p_iosvc_m);
typedef void (*IORel_t)(mach_port_t);
typedef kern_return_t (*IOConnectCallMethod_t)(
    mach_port_t, uint32_t, const uint64_t *, uint32_t, const void *, size_t,
    uint64_t *, uint32_t *, void *, size_t *);
typedef kern_return_t (*IOGetClass_t)(p_iosvc_m, io_name_t);

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
static NSString *P141R(void) { NSString *r = [g_buf copy]; g_buf = nil; return r; }

static void p141_bandit(const char *outcome) {
    static const char *arms[1] = { "main" };
    LabBanditSeedRow sr = { "main", "ok", 0 };
    char attr[288];
    LabBanditRegister("p141", arms, 1, &sr, 0, "p141 reachability oracle",
                      "ok", "survived", attr, sizeof attr);
    LabBanditRecord("p141", 0, outcome);
}

static void p141_census(IOConnectCallMethod_t call, mach_port_t conn) {
    for (uint32_t s = 0; s <= 15; s++) {
        uint64_t out[4]; memset(out, 0, sizeof out);
        uint32_t nout = 4;
        kern_return_t kr = call(conn, s, NULL, 0, NULL, 0, out, &nout,
                                NULL, NULL);
        Lf(@"      sel %2u kr=0x%08x out0=0x%llx out1=0x%llx", s, (unsigned)kr,
           (unsigned long long)out[0], (unsigned long long)out[1]);
    }
}

@implementation P141UsbStockholm

+ (NSString *)tap {
    g_buf = [NSMutableString string];
    NSString *docs = [NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    g_fd = open([[docs stringByAppendingPathComponent:@"p141_oracle_log.txt"]
                 UTF8String], O_CREAT | O_TRUNC | O_WRONLY, 0644);

    Lf(@"=== p141 session %@ BUILD %@ ===", LabLocalMilitaryNow(), P141_BUILD);
    Lf(@"%@", [LabDeviceProfile identBlock]);
    L(@"[oracle law] SKU-FREE: IDENT always prints; both lanes run per");
    L(@"  device. One IOServiceOpen per lane; bounded 16-sel census; close");
    L(@"  after. USB wedge risk accepted (reconnect possible). Any kr row =");
    L(@"  reachability census ONLY (no kernel claim; hasKread stays gated).");
    L(@"[mini's CLI rows recorded]: USB match=OK in-app, open=2e2 owner-held");
    L(@"  on 21-D50 root+app; IOSurfaceRoot root-CLI = 2e2/2c7 (context law).");

    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    if (!iokit) { L(@"[-] STOP dlopen"); p141_bandit("nodlopen"); return P141R(); }
    IOServiceMatching_t pM = dlsym(iokit, "IOServiceMatching");
    GetSVC_t pG = dlsym(iokit, "IOServiceGetMatchingService");
    IOOpen_t pO = dlsym(iokit, "IOServiceOpen");
    IOClose_t pC = dlsym(iokit, "IOServiceClose");
    IORel_t pR = dlsym(iokit, "IOObjectRelease");
    IOConnectCallMethod_t call = dlsym(iokit, "IOConnectCallMethod");
    IOGetClass_t pCls = dlsym(iokit, "IOObjectGetClass");
    if (!pM || !pG || !pO || !pR || !call || !pCls) {
        L(@"[-] STOP dlsym"); p141_bandit("nodlsym"); return P141R();
    }

    const char *lanes[] = { "IOUSBDeviceInterface", "AppleStockholmControl" };
    for (int li = 0; li < 2; li++) {
        Lf(@"=== LANE %d: match '%s' ===", li + 1, lanes[li]);
        CFMutableDictionaryRef md = pM(lanes[li]);
        if (!md) { L(@"  NO match dictionary"); continue; }
        p_ioservice_t svc = pG(kIOMasterPortDefault, md);
        if (!svc || svc >= 0xffffff00) {
            L(@"  NO SERVICE visible from this app (the in-app reachability row)"); continue;
        }
        char nm[128]; memset(nm, 0, sizeof nm);
        kern_return_t ckr = pCls(svc, nm);
        Lf(@"  svc=0x%08x class=%s (getClass kr=0x%x)", svc,
           ckr == 0 ? nm : "?", (unsigned)ckr);
        for (uint32_t t = 0; t < 2; t++) {
            p_ioservice_t conn = 0;
            kern_return_t okr = pO(svc, mach_task_self(), t, &conn);
            Lf(@"    open t%u kr=0x%08x conn=0x%08x", t, (unsigned)okr,
               (unsigned)conn);
            if (okr == 0 && conn) {
                L(@"      *** THE OPEN LANED — census ***");
                p141_census(call, conn);
                kern_return_t c2 = pC ? pC(conn) : 0;
                Lf(@"      IOServiceClose kr=0x%08x", (unsigned)c2);
                pR(conn);
            }
        }
        pR(svc);
    }

    L(@"[honesty] census rows = the per-device reachability law (any");
    L(@"  kr==0 = the lane opens in-app = the fleet comparison row the");
    L(@"  tethered question needs; 2e2 = owner-held; 2c2 = the silent wall).");
    p141_bandit("ran");
    Lf(@"=== p141 end %@ ===", LabLocalMilitaryNow());
    return P141R();
}

@end