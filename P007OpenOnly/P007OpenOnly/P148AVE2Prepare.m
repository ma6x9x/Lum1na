//
//  P148AVE2Prepare.m — the AVE2 IO_Prepare BLOB-first intake calibration. p148.
//  Lum1na-Debug (P007 rig). iOS kernel research (Lum1na).
//
//  The params-blob decode's verbatim law (2026-11-01, 23F77+24A435 caches):
//    cfg = the userland's struct-in blob pointer read DIRECTLY (no remap)
//    -> cfg+0x55c == structIn+0x55c. The count = sSessionCfg.sEnc.sAlgCfg.
//    sGOP.iNumOfTemporalLayer; +0x560 = its duplicate (0x88ba790 copies
//    +0x560 -> +0x55c). The pool-init count-copy itself = UNBOUNDED (no
//    capacity check); the walls = the three upstream validators:
//      (i)   the [0,8] CheckInfo assert   = LOG-GATED (weakest)
//      (ii)  the D5 verifier 0x873358c    = HARD 0xe00002bc
//            (num_ref_frame vs profile-class clamp16 @0x88ba5dc; <2 needs
//            the long-term flag = the [ctx+0x14]-bit0 skip-door candidate)
//      (iii) the DPB-size clamp           = HARD
//  This tap = the INTAKE CALIBRATION only (the lawful envelope rows):
//  the kr verdicts name WHICH wall fires on the sparse zeroed blob and
//  where the state machine gates. NO overshoot values (a >8 knob =
//  OUT-LAW, refused in-app; the 16463-class = the panic row, guarded).
//  The overshoot build waits on the sGOP-neighbor field laws (no-guess).
//

#import "P148AVE2Prepare.h"
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

#define P148_BUILD       @"p148-ave2blob-v1"
#define P148_PREPARE_ROW 3
#define P148_OPEN_ROW    0
#define P148_CONFIG_ROW  2
#define P148_BLOB        0x12c08ULL   /* IO_Prepare structIn (the row law) */
#define P148_GOP_OFF     0x55c        /* sGOP.iNumOfTemporalLayer (verbatim) */
#define P148_MAX_LAWFUL  8            /* the [0,8] assert's boundary (i) */

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
static NSString *P148R(void) { NSString *r = [g_buf copy]; g_buf = nil; return r; }

static void p148_bandit(const char *outcome) {
    static const char *arms[1] = { "main" };
    LabBanditSeedRow sr = { "main", "ok", 0 };
    char attr[288];
    LabBanditRegister("p148", arms, 1, &sr, 0, "p148 aveblob auto-learn",
                      "ok", "survived", attr, sizeof attr);
    LabBanditRecord("p148", 0, outcome);
}

/* the kr classifier: each hard label = one of the envelope's own rows */
static NSString *P148Classify(kern_return_t kr) {
    if (kr == 0) {
        return @"ACCEPTED (the intake landed — the calibration class; the "
               @"kernel landing at ctx+0xb60 is NOT provable from this lane)";
    }
    if (kr == 0xe00002bc) {
        return @"THE D5 VERIFIER ROW (hard wall (ii) fired UPSTREAM of any "
               @"fill — the envelope's order proof on-device)";
    }
    if (kr == 0xe00002c2) {
        return @"shape/state refusal (2c2 — the sparse blob or the state "
               @"gate rejected it; the honest null row)";
    }
    return [NSString stringWithFormat:@"state/gate kr (unclassified — "
            @"the honest per-row print)"];
}

@implementation P148AVE2Prepare

+ (NSString *)tap {
    g_buf = [NSMutableString string];
    NSString *docs = [NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    g_fd = open([[docs stringByAppendingPathComponent:@"p148_aveblob_log.txt"]
                 UTF8String], O_CREAT | O_TRUNC | O_WRONLY, 0644);

    Lf(@"=== p148 session %@ BUILD %@ ===", LabLocalMilitaryNow(), P148_BUILD);
    Lf(@"%@", [LabDeviceProfile identBlock]);
    L(@"[law] the params-blob decode's VERBATIM intake: cfg+0x55c ==");
    L(@"  structIn+0x55c (NO remap) — sGOP.iNumOfTemporalLayer inside the");
    L(@"  0x12c08 IO_Prepare blob; +0x560 = its duplicate. The count-copy");
    L(@"  itself = UNBOUNDED; the walls = (i) the [0,8] assert (log-gated),");
    L(@"  (ii) the D5 verifier 0x873358c (HARD 0xe00002bc), (iii) the DPB");
    L(@"  clamp16 (HARD). This tap fires ONLY the lawful in-bounds ladder");
    L(@"  {0,2,4,8} + a p148_gop.txt knob IF it is in [0,8] — the v1 goal");
    L(@"  = WHICH wall fires first on the sparse zeroed blob, on-device.");
    L(@"[!] PANIC-POSSIBLE (a real encoder state machine at the DPB");
    L(@"    intake); one tap per force-quit.");
    L(@"[-] GUARDS: values >8 = OUT-LAW (REFUSED in-app). The >16-clamp");
    L(@"    and the unbounded copy NEVER fire from this tap (the panic");
    L(@"    class). hasKread stays kread32-gated; a 0-kr row = ACCEPTED");
    L(@"    (state-manipulation class, NOT a KRW claim).");
    L(@"[reach] the direct-UC open = the 2bd/2e2 exclusivity class on");
    L(@"    this fleet (p144's law) — a refusal row = the honest HOLD");
    L(@"    (the blob arm stays the decoder's; no VT-composed blob is");
    L(@"    built here — the property path is p142/p145's lawful lane).");

    /* ---- stage 1: the open census (p144's shape verbatim) ---- */
    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    if (!iokit) { L(@"[-] STOP dlopen"); p148_bandit("nodlopen"); return P148R(); }
    IOServiceMatching_t pM = dlsym(iokit, "IOServiceMatching");
    GetSVC_t pG = dlsym(iokit, "IOServiceGetMatchingService");
    IOOpen_t pO = dlsym(iokit, "IOServiceOpen");
    IORel_t pR = dlsym(iokit, "IOObjectRelease");
    IOConnectCallMethod_t call = dlsym(iokit, "IOConnectCallMethod");
    if (!pM || !pG || !pO || !pR || !call) {
        L(@"[-] STOP dlsym"); p148_bandit("nodlsym"); return P148R();
    }

    const char *names[2] = { "AppleAVE2Driver", "AppleAVE2" };
    p_ioconnect_t conn = 0;
    for (int i = 0; i < 2; i++) {
        p_ioservice_t svc = pG(0, pM(names[i]));
        if (!svc || svc >= 0xffffff00) { Lf(@"  match '%s' -> NO SERVICE", names[i]); continue; }
        for (uint32_t t = 0; t <= 2; t++) {
            p_ioconnect_t c = 0;
            kern_return_t okr = pO(svc, mach_task_self(), t, &c);
            Lf(@"[1] %s open t%u kr=0x%08x conn=0x%08x", names[i], t,
               (unsigned)okr, (unsigned)c);
            if (okr == 0 && c) { conn = c; break; }
        }
        pR(svc);
        if (conn) break;
    }
    if (!conn) {
        L(@"[-] no connect (the 2bd/2e2 exclusivity law = the honest reach");
        L(@"    row) — the blob arm HOLDs; no row fired beyond the open.");
        p148_bandit("noconn");
        Lf(@"[end] board: %@", [[P007Board shared] kreadSignal]);
        Lf(@"=== p148 end %@ ===", LabLocalMilitaryNow());
        return P148R();
    }

    /* ---- stage 2: row0 IO_Open (the state-machine law, zero shape) ---- */
    {
        static uint8_t ob[0x768]; memset(ob, 0, sizeof ob);
        uint8_t sob[0x38]; memset(sob, 0, sizeof sob);
        size_t osc = sizeof sob;
        uint64_t out[2]; memset(out, 0, sizeof out); uint32_t nout = 2;
        kern_return_t kr = call(conn, P148_OPEN_ROW, NULL, 0,
                                ob, sizeof ob, out, &nout, sob, &osc);
        Lf(@"[2] IO_Open kr=0x%08x out=[%llu %llu] (0 = the session state open)",
           (unsigned)kr, (unsigned long long)out[0], (unsigned long long)out[1]);
        if (kr != 0) {
            L(@"    non-zero open — the state machine's gate row; the ladder");
            L(@"    STILL runs below (the per-row kr print = the calibration).");
        }
    }

    /* ---- stage 3: row2 IO_Config, the ZERO-SHAPE lawful pass ---- */
    {
        uint8_t cfg[0x38]; memset(cfg, 0, sizeof cfg);
        uint8_t sob[0x20]; memset(sob, 0, sizeof sob); size_t osc = sizeof sob;
        uint64_t out[2]; memset(out, 0, sizeof out); uint32_t nout = 2;
        kern_return_t kr = call(conn, P148_CONFIG_ROW, NULL, 0,
                                cfg, sizeof cfg, out, &nout, sob, &osc);
        Lf(@"[3] IO_Config (mask=0 zero shape) kr=0x%08x", (unsigned)kr);
    }

    /* ---- stage 4: the row3 ladder (blob-first, +0x55c only) ---- */
    /* the knob: Documents/p148_gop.txt (lawful gate below) */
    long knob = -1;
    NSString *kline = [NSString stringWithContentsOfFile:
        [docs stringByAppendingPathComponent:@"p148_gop.txt"]
        encoding:NSUTF8StringEncoding error:nil];
    if (kline) {
        long v = strtol(kline.UTF8String, NULL, 10);
        if (v >= 0 && v <= P148_MAX_LAWFUL) knob = v;
        else Lf(@"[*] knob p148_gop.txt=%@ OUT-LAW (>8 class) — NOT fired "
                @"(the honest guard)", kline);
    }

    long vals[8]; int nv = 0;
    vals[nv++] = 0;   /* the [0,8] assert's lower edge (the log-gate probe) */
    vals[nv++] = 2;   /* the D5's in-bounds minimum class */
    vals[nv++] = 4;
    vals[nv++] = 8;   /* the assert's upper edge */
    if (knob >= 0 && knob != 0 && knob != 2 && knob != 4 && knob != 8)
        vals[nv++] = knob;

    for (int vi = 0; vi < nv; vi++) {
        static uint8_t blob[0x12c08];
        memset(blob, 0, sizeof blob);
        *(uint32_t *)(blob + P148_GOP_OFF) = (uint32_t)vals[vi];  /* THE ONLY set field */
        uint8_t sob[0x20]; memset(sob, 0, sizeof sob); size_t osc = sizeof sob;
        uint64_t out[2]; memset(out, 0, sizeof out); uint32_t nout = 2;
        kern_return_t kr = call(conn, P148_PREPARE_ROW, NULL, 0,
                                blob, (size_t)P148_BLOB, out, &nout, sob, &osc);
        Lf(@"[4] IO_Prepare blob 0x12c08 with +0x55c=%ld kr=0x%08x out0=0x%llx"
           @" — %@ (mandatory honesty: a 0-kr ACCEPTED row = the calibration's"
           @" state-manipulation class, NEVER a KRW claim)", vals[vi],
           (unsigned)kr, (unsigned long long)out[0], P148Classify(kr));
        if (kr == 0) break;   /* an accepted row ends the ladder (calibration met) */
    }

    L(@"[4] honest v1 scope: the sparse zeroed blob is EXPECTED to meet the");
    L(@"    D5 wall (num_ref_frame=0; the <2-long-term door = the next");
    L(@"    decode's field). The rows above = the wall ORDER + the kr shapes");
    L(@"    the overshoot build must lawfully traverse (sGOP-neighbor field");
    L(@"    laws from the decode notes, never invented).");

    Lf(@"[end] board: %@", [[P007Board shared] kreadSignal]);
    p148_bandit("ran");
    Lf(@"=== p148 end %@ ===", LabLocalMilitaryNow());
    return P148R();
}

@end