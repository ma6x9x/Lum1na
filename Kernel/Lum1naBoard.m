//
//  Lum1naBoard.m
//  Lum1na
//
//  Durable jailbreak-state file (Documents/lum1na_board.json).
//  v2: launch-path hardened — nil-guarded inserts, exception-safe JSON,
//      self-healing corrupt store, thread-safe mutators.
//      Launch path: ExploitManager.init → shared → jsonDump — NOTHING in
//      this file may throw or crash.
//

#import "Lum1naBoard.h"
#import "LabDeviceProfile.h"
#import "LabRuntimeOffsets.h"
#import "LabLocalTime.h"
#import "P06xLog.h"
#import <fcntl.h>
#import <string.h>
#import <sys/sysctl.h>
#import <unistd.h>

#define MH_MAGIC_64_BOARD 0xfeedfacfu

// Forward declare SocketKRW function for commitSlide.
// NOTE: actual signature takes Lum1naSocketKRWContext* — void* is ABI-compatible.
uint64_t Lum1naSocketKRW_kread64(void *ctx, uint64_t kaddr);

static NSString *boardPath(void) {
    NSString *docs = [NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    if (!docs) docs = NSTemporaryDirectory();
    return [docs stringByAppendingPathComponent:@"lum1na_board.json"];
}

/// Nil-safe insert: NSNull stand-in so a nil value can never throw.
static inline void boardSet(NSMutableDictionary *d, NSString *key, id val) {
    d[key] = val ?: [NSNull null];
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

    // Exception-safe load: a corrupt board.json must never kill launch.
    @try {
        NSData *data = [NSData dataWithContentsOfFile:boardPath()];
        if (data) {
            id obj = [NSJSONSerialization JSONObjectWithData:data
                                                     options:NSJSONReadingMutableContainers
                                                       error:nil];
            if ([obj isKindOfClass:[NSMutableDictionary class]]) {
                _d = obj;
            } else if (obj) {
                _d = [obj mutableCopy];
            }
        }
    } @catch (__unused NSException *ex) {
        _d = nil;
    }

    if (![_d isKindOfClass:[NSMutableDictionary class]]) {
        // Self-heal: park the corrupt file, start clean
        NSString *p = boardPath();
        NSString *parked = [p stringByAppendingString:@".corrupt"];
        [[NSFileManager defaultManager] removeItemAtPath:parked error:nil];
        [[NSFileManager defaultManager] moveItemAtPath:p toPath:parked error:nil];
        _d = [NSMutableDictionary dictionary];
    }
    if (![_d[@"leaks"] isKindOfClass:[NSArray class]]) {
        _d[@"leaks"] = [NSMutableArray array];
    }

    // Live KRW flags are PER-RUN: KRW dies with the process, so a persisted
    // hasKread=YES is a record, not a license. Restore slide/base as info;
    // require fresh verification for the live flags.
    _kslide = strtoull([[_d[@"kslide"] description] UTF8String] ?: "0x0", NULL, 16);
    _kbase  = strtoull([[_d[@"kbase"]  description] UTF8String] ?: "0x0", NULL, 16);
    _hasKread = NO;
    _hasKwrite = NO;
    if ([_d[@"hasKread"] boolValue]) {
        NSLog(@"[board] note: store claims hasKread=YES from prior run — requires re-verify this run");
    }

    [self compactLeaks];
    [self refreshIdentity];
    return self;
}

- (void)compactLeaks {
    @synchronized (self) {
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
            NSString *va = [e[@"va"] isKindOfClass:[NSString class]] ? e[@"va"] : @"";
            NSString *kind = [e[@"kind"] isKindOfClass:[NSString class]] ? e[@"kind"] : @"heap";
            NSString *src = [e[@"source"] isKindOfClass:[NSString class]] ? e[@"source"] : @"?";
            NSString *key = [NSString stringWithFormat:@"%@|%@", va, kind];
            NSNumber *idx = index[key];
            NSInteger add = [e[@"hits"] respondsToSelector:@selector(integerValue)] ? [e[@"hits"] integerValue] : 1;
            if (add < 1) add = 1;
            if (idx) {
                NSMutableDictionary *ex = [out[idx.unsignedIntegerValue] mutableCopy];
                if (!ex) continue;
                NSInteger hits = [ex[@"hits"] respondsToSelector:@selector(integerValue)] ? [ex[@"hits"] integerValue] : 1;
                if (hits < 1) hits = 1;
                ex[@"hits"] = @(hits + add);
                NSString *seen = [e[@"lastSeen"] isKindOfClass:[NSString class]] ? e[@"lastSeen"] : e[@"time"];
                if ([seen isKindOfClass:[NSString class]] && seen.length) ex[@"lastSeen"] = seen;
                NSMutableArray *sources = [[ex[@"sources"] isKindOfClass:[NSArray class]] ? ex[@"sources"] : nil mutableCopy]
                                          ?: [NSMutableArray array];
                NSString *first = [ex[@"source"] isKindOfClass:[NSString class]] ? ex[@"source"] : nil;
                if (first.length && ![sources containsObject:first]) [sources addObject:first];
                if (src.length && ![sources containsObject:src]) [sources addObject:src];
                if (sources.count > 1) ex[@"sources"] = sources;
                out[idx.unsignedIntegerValue] = ex;
            } else {
                NSMutableDictionary *ex = [e mutableCopy] ?: [NSMutableDictionary dictionary];
                if ([ex[@"hits"] respondsToSelector:@selector(integerValue)] && [ex[@"hits"] integerValue] < 1)
                    ex[@"hits"] = @(add);
                else if (!ex[@"hits"])
                    ex[@"hits"] = @(add);
                if (!ex[@"lastSeen"]) boardSet(ex, @"lastSeen", e[@"time"] ?: @"");
                index[key] = @(out.count);
                [out addObject:ex];
            }
        }
        if (out.count > 64) {
            [out removeObjectsInRange:NSMakeRange(0, out.count - 64)];
        }
        _d[@"leaks"] = out;
    }
}

- (void)refreshIdentity {
    @synchronized (self) {
        const LabOffTab *off = LabOff();
        boardSet(_d, @"machine", [LabDeviceProfile machine] ?: @"?");
        boardSet(_d, @"osversion", [LabDeviceProfile osversion] ?: @"?");
        boardSet(_d, @"skuTag", (off && off->tag) ? [NSString stringWithUTF8String:off->tag] : @"NULL");
        boardSet(_d, @"staticBase",
                 [NSString stringWithFormat:@"0x%llx", off ? off->static_base : 0xFFFFFFF007004000ULL]);
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
            pins[@"amfi_external"] = [NSString stringWithFormat:@"0x%llx", off->amfi_external];
            pins[@"amfi_loadtc"] = [NSString stringWithFormat:@"0x%llx", off->amfi_loadtc];
            pins[@"pmap_cs_allow"] = [NSString stringWithFormat:@"0x%llx", off->pmap_cs_allow];
            pins[@"pmap_cs_allow_off"] = [NSString stringWithFormat:@"0x%x", off->pmap_cs_allow_off];
            pins[@"owns_replaceable"] = @(off->owns_replaceable);
        }
        _d[@"pins"] = pins;
        boardSet(_d, @"updated", LabLocalMilitaryNow() ?: @"?");   // ← nil-guarded now
        [self persist];
    }
}

- (void)persist {
    @synchronized (self) {
        @try {
            NSError *err = nil;
            NSData *data = [NSJSONSerialization dataWithJSONObject:_d
                                                           options:NSJSONWritingPrettyPrinted
                                                             error:&err];
            if (data) [data writeToFile:boardPath() atomically:YES];
        } @catch (NSException *ex) {
            NSLog(@"[board] persist skipped: %@", ex.name);
        }
    }
}

- (NSString *)machine { NSString *v = _d[@"machine"]; return [v isKindOfClass:[NSString class]] ? v : @"?"; }
- (NSString *)osversion { NSString *v = _d[@"osversion"]; return [v isKindOfClass:[NSString class]] ? v : @"?"; }
- (NSString *)skuTag { NSString *v = _d[@"skuTag"]; return [v isKindOfClass:[NSString class]] ? v : @"?"; }
- (NSString *)sku { return [self skuTag]; }

- (uint64_t)staticBase {
    const char *s = [[_d[@"staticBase"] description] UTF8String];
    return s ? strtoull(s, NULL, 16) : 0xFFFFFFF007004000ULL;
}
- (uint64_t)kslide { return _kslide; }
- (uint64_t)kbase { return _kbase; }
- (BOOL)hasKread { return _hasKread; }
- (BOOL)hasKwrite { return _hasKwrite; }
- (NSArray *)leaks { NSArray *l = _d[@"leaks"]; return [l isKindOfClass:[NSArray class]] ? l : @[]; }

- (void)recordHeapLeak:(uint64_t)va source:(NSString *)source {
    [self recordCandidate:va kind:@"heap" source:source];
}

- (void)recordCandidate:(uint64_t)va kind:(NSString *)kind source:(NSString *)source {
    if (va < 0xffff000000000000ULL) return;
    @synchronized (self) {
        NSMutableArray *leaks = [_d[@"leaks"] isKindOfClass:[NSMutableArray class]] ? _d[@"leaks"] : nil;
        if (!leaks) {
            leaks = [[_d[@"leaks"] isKindOfClass:[NSArray class]] ? _d[@"leaks"] : @[] mutableCopy]
                    ?: [NSMutableArray array];
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
            NSInteger hits = [ex[@"hits"] respondsToSelector:@selector(integerValue)] ? [ex[@"hits"] integerValue] : 1;
            if (hits < 1) hits = 1;
            ex[@"hits"] = @(hits + 1);
            ex[@"lastSeen"] = now;
            if (![ex[@"source"] isEqualToString:src]) {
                NSMutableArray *sources = [[ex[@"sources"] isKindOfClass:[NSArray class]] ? ex[@"sources"] : nil mutableCopy]
                                          ?: [NSMutableArray array];
                NSString *first = [ex[@"source"] isKindOfClass:[NSString class]] ? ex[@"source"] : nil;
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
}

- (void)recordEvent:(NSString *)event
               kind:(NSString *)kind
             detail:(NSString *)detail
             source:(NSString *)source {
    if (event.length == 0) return;
    @synchronized (self) {
        NSMutableArray *leaks = [_d[@"leaks"] isKindOfClass:[NSMutableArray class]] ? _d[@"leaks"] : nil;
        if (!leaks) {
            leaks = [[_d[@"leaks"] isKindOfClass:[NSArray class]] ? _d[@"leaks"] : @[] mutableCopy]
                    ?: [NSMutableArray array];
            _d[@"leaks"] = leaks;
        }
        NSString *k = kind.length ? kind : @"event";
        NSString *src = source.length ? source : @"?";
        NSString *now = LabLocalMilitaryNow() ?: @"";

        for (NSUInteger i = 0; i < leaks.count; i++) {
            NSDictionary *e = leaks[i];
            if (![e isKindOfClass:[NSDictionary class]]) continue;
            if (![e[@"va"] isEqualToString:event]) continue;
            if (![e[@"kind"] isEqualToString:k]) continue;
            NSMutableDictionary *ex = [e mutableCopy];
            NSInteger hits = [ex[@"hits"] respondsToSelector:@selector(integerValue)]
                ? [ex[@"hits"] integerValue] : 1;
            if (hits < 1) hits = 1;
            ex[@"hits"] = @(hits + 1);
            ex[@"lastSeen"] = now;
            if (detail.length) boardSet(ex, @"detail", detail);
            if (![ex[@"source"] isEqualToString:src]) {
                NSMutableArray *sources = [[ex[@"sources"] isKindOfClass:[NSArray class]]
                    ? ex[@"sources"] : nil mutableCopy] ?: [NSMutableArray array];
                NSString *first = [ex[@"source"] isKindOfClass:[NSString class]]
                    ? ex[@"source"] : nil;
                if (first.length && ![sources containsObject:first]) [sources addObject:first];
                if (![sources containsObject:src]) [sources addObject:src];
                ex[@"sources"] = sources;
            }
            leaks[i] = ex;
            [self persist];
            return;
        }

        NSMutableDictionary *row = [NSMutableDictionary dictionary];
        boardSet(row, @"va", event);
        boardSet(row, @"kind", k);
        boardSet(row, @"source", src);
        boardSet(row, @"time", now);
        boardSet(row, @"lastSeen", now);
        row[@"hits"] = @1;
        if (detail.length) boardSet(row, @"detail", detail);
        [leaks addObject:row];
        if (leaks.count > 64) {
            [leaks removeObjectsInRange:NSMakeRange(0, leaks.count - 64)];
        }
        [self persist];
    }
}

- (BOOL)commitSlide:(uint64_t)slide reason:(NSString *)reason {
    @synchronized (self) {
        P06xLogF(@"board", @"commitSlide 0x%016llx reason=%@", slide, reason ?: @"?");

        if (slide > 0x100000000) {
            P06xLog(@"board", @"commitSlide FAIL slide out of range");
            return NO;
        }
        if (!_krwContext) {
            P06xLog(@"board", @"commitSlide FAIL no KRW context");
            return NO;
        }

        uint64_t kbase = LabStaticBase() + slide;

        // Live kread of kbase+0x1c must look like a kernel VA (pointer, not Darwin version text).
        uint64_t version_ptr = kbase + 0x1c;
        uint64_t version_str = Lum1naSocketKRW_kread64(_krwContext, version_ptr);
        if (version_str < 0xFFFFFF8000000000ULL) {
            P06xLogF(@"board", @"commitSlide FAIL kread kbase+0x1c=0x%llx (not a kernel VA)", version_str);
            return NO;
        }

        _kslide = slide;
        _kbase = kbase;
        _hasKread = YES;
        _hasKwrite = YES;

        P06xLogF(@"board", @"commitSlide OK kbase=0x%016llx kread(kbase+0x1c)=0x%llx", _kbase, version_str);

        _d[@"kslide"] = [NSString stringWithFormat:@"0x%llx", _kslide];
        _d[@"kbase"] = [NSString stringWithFormat:@"0x%llx", _kbase];
        _d[@"hasKread"] = @YES;
        _d[@"hasKwrite"] = @YES;
        [self persist];
        [self recordEvent:@"commitSlide"
                     kind:@"kread"
                   detail:[NSString stringWithFormat:@"kbase=0x%llx", _kbase]
                   source:@"board"];
        return YES;
    }
}

- (NSString *)kreadSignal {
    return [NSString stringWithFormat:@"hasKread=%@ hasKwrite=%@ kslide=0x%llx kbase=0x%llx",
            _hasKread ? @"YES" : @"NO",
            _hasKwrite ? @"YES" : @"NO",
            (unsigned long long)_kslide,
            (unsigned long long)_kbase];
}

- (NSString *)jsonDump {
    @synchronized (self) {
        @try {
            NSData *data = [NSJSONSerialization dataWithJSONObject:_d
                                                           options:NSJSONWritingPrettyPrinted
                                                             error:nil];
            if (data) return [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
        } @catch (__unused NSException *ex) {}
        return @"{}";
    }
}

- (void)resetLeaks {
    @synchronized (self) {
        _d[@"leaks"] = [NSMutableArray array];
        _kslide = 0; _kbase = 0;
        _hasKread = NO; _hasKwrite = NO;
        _d[@"kslide"] = @"0x0";
        _d[@"kbase"] = @"0x0";
        _d[@"hasKread"] = @NO;
        _d[@"hasKwrite"] = @NO;
        [self persist];
    }
}

+ (NSString *)tap {
    Lum1naBoard *b = [Lum1naBoard shared];
    [b compactLeaks];
    [b refreshIdentity];
    NSUInteger hits = 0;
    for (NSDictionary *e in b.leaks) {
        if (![e isKindOfClass:[NSDictionary class]]) continue;
        NSInteger n = [e[@"hits"] respondsToSelector:@selector(integerValue)] ? [e[@"hits"] integerValue] : 1;
        hits += (n < 1) ? 1 : (NSUInteger)n;
    }
    return [NSString stringWithFormat:
            @"=== lum1na board %@ ===\n"
            @"Documents/lum1na_board.json\n"
            @"%@ unique=%lu hits=%lu\n"
            @"commitSlide needs kread32(kbase)==MH_MAGIC_64. Heap/panic PC never sets slide.\n\n%@\n",
            LabLocalMilitaryNow() ?: @"?",
            b.kreadSignal,
            (unsigned long)b.leaks.count,
            (unsigned long)hits,
            [b jsonDump]];
}

+ (NSString *)tapKreadTest {
    Lum1naBoard *b = [Lum1naBoard shared];
    [b refreshIdentity];

    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"=== lum1na kread test %@ ===\n", LabLocalMilitaryNow() ?: @"?"];
    [out appendString:@"Bar: kread32(kbase)==0xfeedfacf then commitSlide.\n"];
    [out appendString:@"P044 occupancy, IPS KernelCache slide, and heap leaks do not pass.\n"];
    [out appendString:[LabDeviceProfile identBlock]];
    [out appendFormat:@"%@\n", b.kreadSignal];
    [out appendFormat:@"krwContext=%@ hasKread=%@\n",
         b.krwContext ? @"YES" : @"NO",
         b.hasKread ? @"YES" : @"NO"];
    [out appendFormat:@"staticBase=0x%llx\n", (unsigned long long)b.staticBase];

    if (!b.krwContext) {
        [out appendString:@"\nKREAD FAIL — no KRW context this process.\n"];
        [out appendString:@"43748 fill writes {surfaceId, 0xcN, 1, 1} into kalloc.3072 extra.\n"];
        [out appendString:@"Recv of that extra is occupancy read-back. Type-3 recv after fire is PACGA-fatal.\n"];
        [out appendString:@"Facet A 0xe00002be is Call1 UAF oracle, not kreadbuf.\n"];
        [out appendString:@"Shape L unnamed. MemoryMap restores +0x810 then cmp count,#0x80.\n"];
        [out appendString:@"Register kread only from a copyout of kernel bytes you did not write.\n"];
    } else {
        uint64_t kbase = b.staticBase;
        uint64_t mag64 = Lum1naSocketKRW_kread64(b.krwContext, kbase);
        uint32_t mag = (uint32_t)mag64;
        [out appendFormat:@"kread64(staticBase=0x%llx) mag=0x%x (want 0xfeedfacf)\n",
            (unsigned long long)kbase, mag];
        if (mag == MH_MAGIC_64_BOARD) {
            [out appendString:@"KREAD primitive reads MH_MAGIC_64 at staticBase.\n"];
            [out appendString:@"commitSlide still needs the live slide (nonzero) plus kbase+0x1c kernel VA.\n"];
        } else {
            [out appendString:@"KREAD FAIL — armed kread did not return MH_MAGIC_64 at staticBase.\n"];
        }
        [out appendFormat:@"%@\n", b.kreadSignal];
    }

    NSString *docs = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    if (docs) {
        NSString *path = [docs stringByAppendingPathComponent:@"lum1na_kread_test_log.txt"];
        int fd = open(path.fileSystemRepresentation, O_CREAT | O_WRONLY | O_TRUNC, 0644);
        if (fd >= 0) {
            const char *s = out.UTF8String;
            size_t n = s ? strlen(s) : 0;
            while (n) {
                ssize_t w = write(fd, s, n);
                if (w <= 0) break;
                s += w;
                n -= (size_t)w;
            }
            fcntl(fd, F_FULLFSYNC);
            close(fd);
        }
    }
    return out;
}

@end

