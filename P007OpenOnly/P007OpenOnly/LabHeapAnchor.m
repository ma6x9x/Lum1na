//
//  LabHeapAnchor.m — same-boot REAL heap-anchor loader (2026-11-19)
//
//  Reads the board store's leaks[] (kind=heap) and returns the freshest
//  entry whose timestamp falls inside THIS boot (kern.boottime). Provenance
//  is the board receipt itself — nothing here invents or derives a value.
//
#import "LabHeapAnchor.h"
#import "P159IOSurfaceAdjacency.h"
#import <Foundation/Foundation.h>
#import <sys/sysctl.h>

static uint64_t labha_boot_secs(void) {
    struct timeval tv;
    size_t len = sizeof(tv);
    if (sysctlbyname("kern.boottime", &tv, &len, NULL, 0) != 0) return 0;
    return (uint64_t)tv.tv_sec;
}

uint64_t LabHeapAnchorSameBoot(void) {
    uint64_t out[1] = {0};
    LabHeapAnchorsSameBoot(1, out);
    return out[0];
}

int LabHeapAnchorsSameBoot(int max, uint64_t *out) {
    if (!out || max <= 0) return 0;
    int written = 0;
    NSArray *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    if (docs.count == 0) return 0;
    NSString *dir = docs.firstObject;

    uint64_t boot = labha_boot_secs();
    if (boot == 0) return 0;

    NSDateFormatter *df = [[NSDateFormatter alloc] init];
    df.locale = [NSLocale localeWithLocaleIdentifier:@"en_US_POSIX"];
    df.dateFormat = @"yyyy-MM-dd HH:mm:ss z";   /* LabTime / board stamp */

    /* gather (value, date) pairs from both board stores, same-boot only */
    NSMutableArray<NSDictionary *> *cands = [NSMutableArray array];
    for (NSString *name in @[@"lum1na_board.json", @"p007_board.json"]) {
        NSString *path = [dir stringByAppendingPathComponent:name];
        NSDictionary *board = [NSJSONSerialization JSONObjectWithData:
                                [NSData dataWithContentsOfFile:path]
                                options:0 error:nil];
        if (![board isKindOfClass:[NSDictionary class]]) continue;
        for (NSDictionary *e in (board[@"leaks"] ?: @[])) {
            if (![e isKindOfClass:[NSDictionary class]]) continue;
            if (![e[@"kind"] isKindOfClass:[NSString class]] ||
                ![[e valueForKey:@"kind"] isEqualToString:@"heap"]) continue;
            NSString *vaStr = ([e[@"va"] isKindOfClass:[NSString class]]) ? e[@"va"] : nil;
            if (![vaStr hasPrefix:@"0x"]) continue;
            uint64_t va = strtoull(vaStr.UTF8String, NULL, 16);
            /* shape gate: kernel-pointer band only, and never a static */
            if (va == 0 || (va >> 48) != 0xffffULL) continue;
            if (va == 0xfffffe0007004000ULL) continue;   /* static_base, not heap */
            /* same-boot provenance: the leak's own stamp must postdate boot */
            NSString *ts = ([e[@"time"] isKindOfClass:[NSString class]]) ? e[@"time"] : nil;
            NSDate *t = ts ? [df dateFromString:ts] : nil;
            if (!t) continue;
            if ([t timeIntervalSince1970] < (NSTimeInterval)boot - 1) continue;  /* clock skew slack */
            [cands addObject:@{ @"va": @(va), @"t": t }];
        }
    }
    /* freshest first, distinct values only */
    [cands sortUsingComparator:^NSComparisonResult(NSDictionary *a, NSDictionary *b) {
        return [(NSDate *)b[@"t"] compare:(NSDate *)a[@"t"]];
    }];
    for (NSDictionary *c in cands) {
        uint64_t va = [c[@"va"] unsignedLongLongValue];
        BOOL dup = NO;
        for (int i = 0; i < written; i++) if (out[i] == va) { dup = YES; break; }
        if (dup) continue;
        out[written++] = va;
        if (written >= max) break;
    }
    return written;
}

int LabHeapAnchorHarvestIfThin(int want) {
    uint64_t buf[8];
    int have = LabHeapAnchorsSameBoot(8, buf);
    if (have >= want) return have;
    /* thin: run ONE P159 harvest tap (self-bounded rounds; records every
       distinct canonical kptr to the board). Read-only, never blocks. */
    (void)[P159IOSurfaceAdjacency tap];
    return LabHeapAnchorsSameBoot(8, buf);
}
