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

#define P143_BUILD @"p143-rocketdoor-v2-ownerlaw"

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

    /* ---- stage 3: the OWNER-LAW census (the decode-correction batch) --
       24A435 decode: the owner = minted at OPEN time by
       deviceUserClientStart (0xa024970; vt+0x588 blraa with the task
       token from [uc+0xd8]) — NO userland selector writes [uc+0x120].
       The submit fn = row 0x19 (0xa02299c; the pinned 0x24 = off by
       11 rows, fn VA right, index wrong), kind=4, checkIn=variable,
       out=1; NO entitlement check in the row (size/overflow asserts
       only). [uc+0x103] = the gpu-restricted table-choice bit.
       CENSUS: rows 0x17..0x1B + the owner-reader row 0x37 (cin=0). */
    L(@"[3] the owner-law census on the LIVE open: submit-row 0x19 +");
    L(@"    the neighbors + the owner-getter 0x37 (cin=0/out=scalar).");
    {
        uint64_t inB[4] = { 0, 0, 0, 0 };
        uint64_t outB[8]; memset(outB, 0, sizeof outB);
        uint32_t nout = 8;
        uint64_t stB[16]; memset(stB, 0, sizeof stB);
        size_t nsc = sizeof stB;
        for (uint32_t s = 0x17; s <= 0x1B; s++) {
            nout = 8; nsc = sizeof stB;
            kern_return_t k2 = call(conn, s, inB, 4, NULL, 0, outB, &nout, stB, &nsc);
            Lf(@"    sel 0x%x kr=0x%08x out0=0x%llx out1=0x%llx struct=%zu",
               s, (unsigned)k2, (unsigned long long)outB[0],
               (unsigned long long)outB[1], nsc);
        }
        nout = 4; nsc = sizeof stB;
        kern_return_t k37 = call(conn, 0x37, NULL, 0, NULL, 0, outB, &nout, stB, &nsc);
        Lf(@"    sel 0x37 (owner-reader row; [owner+0xfc] bit0's vt chain)"
           @" kr=0x%08x out0=0x%llx struct=%zu",
           (unsigned)k37, (unsigned long long)outB[0], nsc);
    }
    L(@"[3] the door's real gate = the INPUT shape: kind=4 + variable");
    L(@"    struct-in (the cmdBufArgSize/total-overflow assert laws = the");
    L(@"    struct-carrying call = v3's row; the empty-in = the census).");
    p143_bandit("ran");

    Lf(@"[end] board: %@", [[P007Board shared] kreadSignal]);
    Lf(@"=== p143 end %@ ===", LabLocalMilitaryNow());
    return P143R();
}

@end