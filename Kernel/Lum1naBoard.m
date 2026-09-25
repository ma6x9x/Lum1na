#import "Lum1naBoard.h"
#import "LabDeviceProfile.h"
#import "LabRuntimeOffsets.h"
#import "LabLocalTime.h"
#import <sys/sysctl.h>


static NSString *boardPath(void) {
    NSString *docs = [NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    return [docs stringByAppendingPathComponent:@"lum1na_board.json"];
}

@implementation Lum1naBoard {
    NSMutableDictionary *_d;
    // Dedupe guard: one record per (va,kind,source) per app session.
    // A fresh process start resets this, so a re-tap in a later session
    // still records. Prevents the aio84530 poll-loop pattern from
    // writing 66 identical rows (11:50 run).
    NSMutableSet *_recordedKeys;
    NSString *_session;
}

+ (instancetype)shared {
    static Lum1naBoard *g;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ g = [Lum1naBoard new]; });
    return g;
}

- (instancetype)init {
    self = [super init];
    if (!self) return self;
    NSData *data = [NSData dataWithContentsOfFile:boardPath()];
    if (data) {
        _d = [[NSJSONSerialization JSONObjectWithData:data options:NSJSONReadingMutableContainers error:nil] mutableCopy];
    }
    if (!_d) _d = [NSMutableDictionary dictionary];
    if (!_d[@"leaks"]) _d[@"leaks"] = [NSMutableArray array];
    _recordedKeys = [NSMutableSet set];
    _session = [NSString stringWithFormat:@"s-%@-%u",
                LabLocalMilitaryNow() ?: @"?", arc4random()];
    [self refreshIdentity];
    return self;
}

- (void)refreshIdentity {
    const LabOffTab *off = LabOff();
    _d[@"machine"] = [LabDeviceProfile machine] ?: @"?";
    _d[@"osversion"] = [LabDeviceProfile osversion] ?: @"?";
    _d[@"skuTag"] = (off && off->tag) ? [NSString stringWithUTF8String:off->tag] : @"NULL";
    _d[@"staticBase"] = [NSString stringWithFormat:@"0x%llx", off ? off->static_base : 0xFFFFFFF007004000ULL];
    if (!_d[@"hasKread"]) _d[@"hasKread"] = @NO;
    if (!_d[@"hasKwrite"]) _d[@"hasKwrite"] = @NO;
    if (!_d[@"kslide"]) _d[@"kslide"] = @"0x0";
    if (!_d[@"kbase"]) _d[@"kbase"] = @"0x0";
    NSMutableDictionary *pins = [NSMutableDictionary dictionary];
    if (off) {
        pins[@"fn4"] = [NSString stringWithFormat:@"0x%llx", off->fn4];
        pins[@"wvek"] = [NSString stringWithFormat:@"0x%llx", off->aks_wvek_overflow];
        pins[@"ave_close"] = [NSString stringWithFormat:@"0x%llx", off->ave_close];
        pins[@"ane_checkandprewire"] = [NSString stringWithFormat:@"0x%llx", off->ane_checkandprewire];
        pins[@"sysmem_md"] = [NSString stringWithFormat:@"0x%x", off->sysmem_md];
        pins[@"so_necp"] = [NSString stringWithFormat:@"0x%x", off->so_necp];
    }
    _d[@"pins"] = pins;
    _d[@"updated"] = LabLocalMilitaryNow();
    [self persist];
}

- (void)persist {
    NSError *err = nil;
    NSData *data = [NSJSONSerialization dataWithJSONObject:_d options:NSJSONWritingPrettyPrinted error:&err];
    if (data) [data writeToFile:boardPath() atomically:YES];
}

- (NSString *)machine { return _d[@"machine"]; }
- (NSString *)osversion { return _d[@"osversion"]; }
- (NSString *)skuTag { return _d[@"skuTag"]; }
- (uint64_t)staticBase { return strtoull([_d[@"staticBase"] UTF8String], NULL, 16); }
- (uint64_t)kslide { return strtoull([_d[@"kslide"] UTF8String], NULL, 16); }
- (uint64_t)kbase { return strtoull([_d[@"kbase"] UTF8String], NULL, 16); }
- (BOOL)hasKread { return [_d[@"hasKread"] boolValue]; }
- (BOOL)hasKwrite { return [_d[@"hasKwrite"] boolValue]; }
- (NSArray *)leaks { return _d[@"leaks"]; }

- (void)recordHeapLeak:(uint64_t)va source:(NSString *)source {
    [self recordCandidate:va kind:@"heap" source:source];
}

- (void)recordCandidate:(uint64_t)va kind:(NSString *)kind source:(NSString *)source {
    if (va < 0xffff000000000000ULL) return;

    // v2: dedupe within this session — same (va,kind,source) recorded once
    // per app launch. Cross-session and cross-source records are unaffected
    // (aio84530 and p044 hitting the same region = two entries, which is
    // the correlation signal we want on the board).
    NSString *key = [NSString stringWithFormat:@"0x%llx|%@|%@", va, kind ?: @"", source ?: @""];
    if ([_recordedKeys containsObject:key]) return;
    [_recordedKeys addObject:key];

    NSMutableArray *leaks = _d[@"leaks"];
    if (![leaks isKindOfClass:[NSMutableArray class]]) {
        leaks = [leaks mutableCopy] ?: [NSMutableArray array];
        _d[@"leaks"] = leaks;
    }
    [leaks addObject:@{
        @"va": [NSString stringWithFormat:@"0x%llx", va],
        @"kind": kind ?: @"unknown",
        @"source": source ?: @"?",
        @"time": LabLocalMilitaryNow() ?: @""
    }];
    if (leaks.count > 64) {
        [leaks removeObjectsInRange:NSMakeRange(0, leaks.count - 64)];
    }
    [self persist];
}

- (BOOL)commitSlide:(uint64_t)slide reason:(NSString *)reason {
    (void)slide;
    (void)reason;
    /* Refuse until a kread of a known kernel string succeeds.
       Heap-static subtract is not a slide. */
    return NO;
}

- (NSString *)jsonDump {
    NSData *data = [NSJSONSerialization dataWithJSONObject:_d options:NSJSONWritingPrettyPrinted error:nil];
    return data ? [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding] : @"{}";
}

- (void)resetLeaks {
    _d[@"leaks"] = [NSMutableArray array];
    _d[@"kslide"] = @"0x0";
    _d[@"kbase"] = @"0x0";
    _d[@"hasKread"] = @NO;
    _d[@"hasKwrite"] = @NO;
    [_recordedKeys removeAllObjects];
    [self persist];
}

+ (NSString *)tap {
    Lum1naBoard *b = [Lum1naBoard shared];
    [b refreshIdentity];
    return [NSString stringWithFormat:
            @"=== lum1na board %@ ===\n"
            @"Documents/lum1na_board.json\n"
            @"hasKread=%@ hasKwrite=%@ leaks=%lu\n"
            @"kslide=%@ kbase=%@\n\n%@\n",
            LabLocalMilitaryNow(),
            b.hasKread ? @"YES" : @"NO",
            b.hasKwrite ? @"YES" : @"NO",
            (unsigned long)b.leaks.count,
            b.kslide ? [NSString stringWithFormat:@"0x%llx", b.kslide] : @"0",
            b.kbase ? [NSString stringWithFormat:@"0x%llx", b.kbase] : @"0",
            [b jsonDump]];
}

@end
