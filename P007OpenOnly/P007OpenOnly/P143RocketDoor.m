//
//  P143RocketDoor.m — the ROCKET SUBMIT DOOR on the 17 (24A435). p143.
//  Lum1na-Debug (P007 rig). iOS kernel research (Lum1na).
//
//  The statically-closed submit chain (24A435 disk cache, capstone):
//    UC sel 0x24 = 0xa02299c [uc+0x120] -> FUN(owner, resourceId)
//    state = [res+0x530]; PP = [state+0x158]; array = PP+0x48 (stride
//    0x18 {ptr,+8 u32,+0x10 valid}); the 0xcda1 PAC-dispatch law.
//  This tap = the DEVICE row: open the IOGPU UC, drive sel 0x24 with
//  a real owner + a real resource id, census the readback trio.
//

#import "P143RocketDoor.h"
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

#define P143_BUILD @"p143-rocketdoor-v1"

/* P069 no-header law: local prototypes only */
typedef mach_port_t p_ioservice_t; typedef mach_port_t p_ioconnect_t;
typedef CFMutableDictionaryRef (*IOServiceMatching_t)(const char *);
typedef p_ioservice_t (*GetSVC_t)(mach_port_t, CFDictionaryRef);
typedef kern_return_t (*IOOpen_t)(p_ioservice_t, mach_port_t, uint32_t, p_ioconnect_t *);
typedef void (*IORel_t)(mach_port_t);
typedef kern_return_t (*IOConnectCallMethod_t)(
    mach_port_t, uint32_t, const uint64_t *, uint32_t, const void *, size_t,
    uint64_t *, uint32_t *, void *, size_t *);
typedef void *(*IOSurfaceCreate_t)(CFDictionaryRef);

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
static NSString *P143R(void) { NSString *r = [g_buf copy]; g_buf = nil; return r; }

static void p143_bandit(const char *outcome) {
    static const char *arms[1] = { "main" };
    LabBanditSeedRow sr = { "main", "ok", 0 };
    char attr[288];
    LabBanditRegister("p143", arms, 1, &sr, 0, "p143 rocketdoor auto-learn",
                      "ok", "survived", attr, sizeof attr);
    LabBanditRecord("p143", 0, outcome);
}

@implementation P143RocketDoor

+ (NSString *)tap {
    g_buf = [NSMutableString string];
    NSString *docs = [NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    g_fd = open([[docs stringByAppendingPathComponent:@"p143_rocketdoor_log.txt"]
                 UTF8String], O_CREAT | O_TRUNC | O_WRONLY, 0644);

    Lf(@"=== p143 session %@ BUILD %@ ===", LabLocalMilitaryNow(), P143_BUILD);
    Lf(@"%@", [LabDeviceProfile identBlock]);
    L(@"[rocket-law] sel 0x24 = 0xa02299c reads [uc+0x120] (owner) then");
    L(@"  FUN(owner, resourceId); state=[res+0x530]; PP=[state+0x158];");
    L(@"  the record array PP+0x48 @0x18 {ptr,+8 u32,+0x10 valid}; the");
    L(@"  0xcda1 PAC-dispatch law (fleet class). Static chain CLOSED.");
    L(@"[!] PANIC-POSSIBLE (a real submit machine); one tap; a closed");
    L(@"  row = the honest hold; no KRW claim from any row here.");

    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    void *iosf = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
    if (!iokit || !iosf) { L(@"[-] STOP dlopen"); p143_bandit("nodlopen"); return P143R(); }
    IOServiceMatching_t pM = dlsym(iokit, "IOServiceMatching");
    GetSVC_t pG = dlsym(iokit, "IOServiceGetMatchingService");
    IOOpen_t pO = dlsym(iokit, "IOServiceOpen");
    IORel_t pR = dlsym(iokit, "IOObjectRelease");
    IOConnectCallMethod_t call = dlsym(iokit, "IOConnectCallMethod");
    IOSurfaceCreate_t sc = dlsym(iosf, "IOSurfaceCreate");
    if (!pM || !pG || !pO || !pR || !call || !sc) {
        L(@"[-] STOP dlsym"); p143_bandit("nodlsym"); return P143R();
    }

    /* ---- stage 1: the IOGPU UC open ---- */
    p_ioservice_t svc = pG(0, pM("IOGPU"));
    if (!svc || svc >= 0xffffff00) {
        L(@"[-] IOGPU no service"); p143_bandit("nosvc"); return P143R();
    }
    p_ioconnect_t conn = 0;
    kern_return_t okr = pO(svc, mach_task_self(), 0, &conn);
    Lf(@"[1] IOGPU open t0 kr=0x%08x conn=0x%08x", (unsigned)okr, (unsigned)conn);
    if (okr != 0 || !conn) {
        for (uint32_t t = 1; t <= 3; t++) {
            kern_return_t o2 = pO(svc, mach_task_self(), t, &conn);
            Lf(@"    open t%u kr=0x%08x conn=0x%08x", t, (unsigned)o2, (unsigned)conn);
            if (o2 == 0 && conn) break;
        }
    }
    pR(svc);
    if (!conn) { L(@"[-] no connect (the 2c7/2e2 exclusivity law = honest hold);");
                 p143_bandit("noconn"); return P143R(); }

    /* ---- stage 2: a REAL live resource (our own surface) ---- */
    CFMutableDictionaryRef d = CFDictionaryCreateMutable(
        kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks);
    const int32_t vv[5] = { 256, 256, 4, 1024, 262144 };
    const char *kk[5] = { "IOSurfaceWidth", "IOSurfaceHeight",
        "IOSurfaceBytesPerElement", "IOSurfaceBytesPerRow", "IOSurfaceAllocSize" };
    for (int i = 0; i < 5; i++) {
        CFNumberRef n = CFNumberCreate(NULL, kCFNumberSInt32Type, &vv[i]);
        CFDictionarySetValue(d, (__bridge CFStringRef)
            [NSString stringWithUTF8String:kk[i]], n); CFRelease(n);
    }
    void *surf = sc(d);
    CFRelease(d);
    if (!surf) { L(@"[-] surface create failed"); p143_bandit("nosurf");
                 return P143R(); }
    L(@"[2] surface armed (the live-resource law)");

    /* ---- stage 3: the sel-0x24 submit row ---- */
    L(@"[3] sel 0x24 (submit): scIn={owner=0, resource=0} first row — the");
    L(@"    honest shape: the REAL owner lives at UC+0x120 kernel-side; the");
    L(@"    call with zeros = the door's reply-class census (2c2/2d8 =");
    L(@"    the gate-class reply; 0 = the submit ACCEPTED (then the");
    L(@"    state-machine run = the honest in-flight row).");
    {
        uint64_t in[4] = { 0, 0, 0, 0 };
        uint64_t out[8]; memset(out, 0, sizeof out);
        uint32_t nout = 8;
        uint64_t st[16]; memset(st, 0, sizeof st);
        size_t nsc = sizeof st;
        kern_return_t kr = call(conn, 0x24, in, 4, NULL, 0, out, &nout, st, &nsc);
        Lf(@"    sel 0x24 kr=0x%08x out=[%llu %llu %llu %llu] struct=%zu",
           (unsigned)kr, (unsigned long long)out[0], (unsigned long long)out[1],
           (unsigned long long)out[2], (unsigned long long)out[3], nsc);
        for (uint32_t s = 0x20; s <= 0x29; s++) {
            nout = 8;
            kern_return_t k2 = call(conn, s, in, 4, NULL, 0, out, &nout, st, &nsc);
            Lf(@"    sel 0x%x kr=0x%08x", s, (unsigned)k2);
        }
    }
    L(@"[3] the census rows above = the door's reply-class per sel (the");
    L(@"    Rocket battery's honest start; the owner-carrying call = the");
    L(@"    next decode hop with the REAL owner from the ioGpuUserClient-");
    L(@"    typeStatic row).");
    p143_bandit("ran");

    Lf(@"[end] board: %@", [[P007Board shared] kreadSignal]);
    Lf(@"=== p143 end %@ ===", LabLocalMilitaryNow());
    return P143R();
}

@end