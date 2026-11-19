//
//  LabHeapAnchor.m — same-boot REAL heap-anchor loader (2026-11-19)
//
//  Reads the board store's leaks[] (kind=heap) and returns the freshest
//  entry whose timestamp falls inside THIS boot (kern.boottime). Provenance
//  is the board receipt itself — nothing here invents or derives a value.
//
#import "LabHeapAnchor.h"
#import <Foundation/Foundation.h>
#import <sys/sysctl.h>

static uint64_t labha_boot_secs(void) {
    struct timeval tv;
    size_t len = sizeof(tv);
    if (sysctlbyname("kern.boottime", &tv, &len, NULL, 0) != 0) return 0;
    return (uint64_t)tv.tv_sec;
}

uint64_t LabHeapAnchorSameBoot(void) {
    NSArray *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    if (docs.count == 0) return 0;
    NSString *dir = docs.firstObject;

    uint64_t boot = labha_boot_secs();
    if (boot == 0) return 0;

    NSDateFormatter *df = [[NSDateFormatter alloc] init];
    df.locale = [NSLocale localeWithLocaleIdentifier:@"en_US_POSIX"];
    df.dateFormat = @"yyyy-MM-dd HH:mm:ss z";   /* LabTime / board stamp */

    uint64_t best = 0;
    NSDate *bestDate = nil;

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
            if (!bestDate || [t compare:bestDate] == NSOrderedDescending) {
                bestDate = t;
                best = va;
            }
        }
    }
    return best;
}
