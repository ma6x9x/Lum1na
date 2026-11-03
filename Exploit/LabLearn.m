//
//  LabLearn.m — per-SKU overlay. Atomic write + F_FULLFSYNC.
//

#import "LabLearn.h"
#import "LabDeviceProfile.h"
#import "LabLocalTime.h"
#import "LabRuntimeOffsets.h"
#import "lumina_core.h"

#import <fcntl.h>
#import <stdlib.h>
#import <unistd.h>

#define LEARN_FILE @"lab_learn.json"

@implementation LabLearn

static NSString *g_pendingArm;

+ (NSString *)learnPath {
    NSString *docs = [NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    return [docs stringByAppendingPathComponent:LEARN_FILE];
}

+ (NSMutableDictionary *)loadDoc {
    NSData *d = [NSData dataWithContentsOfFile:[self learnPath]];
    id j = d ? [NSJSONSerialization JSONObjectWithData:d options:0 error:nil] : nil;
    if ([j isKindOfClass:[NSDictionary class]])
        return [j mutableCopy];
    return [NSMutableDictionary dictionary];
}

+ (void)saveDoc:(NSDictionary *)doc {
    NSData *out = [NSJSONSerialization dataWithJSONObject:doc
                                                  options:NSJSONWritingSortedKeys
                                                    error:nil];
    if (!out) return;
    NSString *path = [self learnPath];
    if (![out writeToFile:path options:NSDataWritingAtomic error:nil]) return;
    int fd = open(path.fileSystemRepresentation, O_RDONLY);
    if (fd >= 0) { (void)fcntl(fd, F_FULLFSYNC); (void)close(fd); }
}

+ (NSString *)skuKey {
    NSString *s = [LabDeviceProfile skuName];
    return s.length ? s : @"Unknown";
}

+ (NSDictionary *)row {
    NSDictionary *doc = [self loadDoc];
    NSDictionary *skus = doc[@"skus"];
    NSDictionary *row = [skus isKindOfClass:[NSDictionary class]] ? skus[[self skuKey]] : nil;
    return [row isKindOfClass:[NSDictionary class]] ? row : @{};
}

+ (void)setPendingArm:(NSString *)arm {
    g_pendingArm = arm.length ? [arm copy] : nil;
}

+ (NSString *)pendingArm {
    return g_pendingArm;
}

+ (NSString *)aneModel {
    NSString *arm = g_pendingArm;
    const char *mapped = lumina_ane_model_for_arm(arm.UTF8String);
    if (mapped) return @(mapped);
    NSDictionary *row = [self row];
    NSString *learned = row[@"ane_model"];
    if ([learned isKindOfClass:[NSString class]] && learned.length)
        return learned;
    LabSku sku = [LabDeviceProfile detectedSku];
    /* 12 mini 21D50: 43748 is not live. Smaller in-bounds 127-in for CLASS/FIELD. */
    if (sku == LabSkuA14_21D50)
        return @"XVRC27_127inmin_1out";
    return nil;
}

+ (uint32_t)aneReqIn {
    NSString *arm = g_pendingArm;
    uint32_t mapped = lumina_ane_req_in_for_arm(arm.UTF8String);
    if (mapped) return mapped;
    NSDictionary *row = [self row];
    NSNumber *n = row[@"req_in"];
    if ([n isKindOfClass:[NSNumber class]]) {
        uint32_t v = n.unsignedIntValue;
        if (v >= 2 && v <= 4096 && v != 254u) return v;
    }
    LabSku sku = [LabDeviceProfile detectedSku];
    if (sku == LabSkuA14_21D50) return 127u;
    return 0;
}

+ (BOOL)conversionConfirmed {
    NSString *c = [self row][@"conversion"];
    return [c isKindOfClass:[NSString class]] && [c isEqualToString:@"YES"];
}

+ (BOOL)magicConfirmed {
    NSString *m = [self row][@"magic"];
    return [m isKindOfClass:[NSString class]] && [m isEqualToString:@"PASS"];
}

+ (void)recordOccupancy:(BOOL)occ
             conversion:(BOOL)conv
                  magic:(BOOL)magic
                   heap:(uint64_t)heap
                  model:(NSString *)model
                  reqIn:(uint32_t)reqIn
                 source:(NSString *)source {
    NSMutableDictionary *doc = [self loadDoc];
    NSMutableDictionary *skus = [doc[@"skus"] isKindOfClass:[NSDictionary class]]
        ? [doc[@"skus"] mutableCopy]
        : [NSMutableDictionary dictionary];
    NSString *key = [self skuKey];
    NSMutableDictionary *row = [skus[key] isKindOfClass:[NSDictionary class]]
        ? [skus[key] mutableCopy]
        : [NSMutableDictionary dictionary];
    row[@"ts"] = LabLocalMilitaryNow() ?: @"?";
    row[@"source"] = source ?: @"?";
    row[@"occupancy"] = occ ? @"YES" : @"NO";
    row[@"conversion"] = conv ? @"YES" : @"NO";
    row[@"magic"] = magic ? @"PASS" : @"FAIL";
    if (model.length) row[@"ane_model"] = model;
    if (reqIn >= 2 && reqIn != 254u) row[@"req_in"] = @(reqIn);
    if (heap >= 0xffff000000000000ULL)
        row[@"heap"] = [NSString stringWithFormat:@"0x%llx", (unsigned long long)heap];
    if (g_pendingArm.length) row[@"last_arm"] = g_pendingArm;
    const LabOffTab *off = LabOff();
    if (off && off->tag)
        row[@"table"] = [NSString stringWithUTF8String:off->tag];
    skus[key] = row;
    doc[@"skus"] = skus;
    [self saveDoc:doc];
}

+ (void)ingestIdent:(NSString *)ident {
    if (!ident.length) return;
    NSMutableDictionary *doc = [self loadDoc];
    NSMutableDictionary *skus = [doc[@"skus"] isKindOfClass:[NSDictionary class]]
        ? [doc[@"skus"] mutableCopy]
        : [NSMutableDictionary dictionary];
    NSString *key = [self skuKey];
    NSMutableDictionary *row = [skus[key] isKindOfClass:[NSDictionary class]]
        ? [skus[key] mutableCopy]
        : [NSMutableDictionary dictionary];
    row[@"ident"] = ident;
    row[@"ident_ts"] = LabLocalMilitaryNow() ?: @"?";
    skus[key] = row;
    doc[@"skus"] = skus;
    [self saveDoc:doc];
}

+ (void)ingestBootIntel {
    NSString *docs = [NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    if (!docs.length) return;
    NSString *path = [docs stringByAppendingPathComponent:@"p139_boot_intel.txt"];
    NSString *txt = [NSString stringWithContentsOfFile:path
                                              encoding:NSUTF8StringEncoding
                                                 error:nil];
    if (!txt.length) return;
    NSMutableDictionary *doc = [self loadDoc];
    NSMutableDictionary *skus = [doc[@"skus"] isKindOfClass:[NSDictionary class]]
        ? [doc[@"skus"] mutableCopy]
        : [NSMutableDictionary dictionary];
    NSString *key = [self skuKey];
    NSMutableDictionary *row = [skus[key] isKindOfClass:[NSDictionary class]]
        ? [skus[key] mutableCopy]
        : [NSMutableDictionary dictionary];
    NSUInteger cap = MIN(txt.length, (NSUInteger)4096);
    row[@"p139"] = [txt substringToIndex:cap];
    row[@"p139_ts"] = LabLocalMilitaryNow() ?: @"?";
    NSRegularExpression *re =
        [NSRegularExpression regularExpressionWithPattern:@"0x[fF]{6,}[0-9a-fA-F]+"
                                                  options:0 error:nil];
    NSTextCheckingResult *m = [re firstMatchInString:txt options:0
                                               range:NSMakeRange(0, txt.length)];
    if (m) {
        NSString *hex = [txt substringWithRange:m.range];
        unsigned long long v = strtoull(hex.UTF8String, NULL, 16);
        if (lumina_kptr_zone((uint64_t)v))
            row[@"p139_heap"] = hex;
    }
    skus[key] = row;
    doc[@"skus"] = skus;
    [self saveDoc:doc];
}

+ (void)recordPath:(NSString *)pathId
            result:(NSString *)result
          evidence:(NSString *)evidence {
    if (!pathId.length) return;
    NSMutableDictionary *doc = [self loadDoc];
    NSMutableDictionary *skus = [doc[@"skus"] isKindOfClass:[NSDictionary class]]
        ? [doc[@"skus"] mutableCopy]
        : [NSMutableDictionary dictionary];
    NSString *key = [self skuKey];
    NSMutableDictionary *row = [skus[key] isKindOfClass:[NSDictionary class]]
        ? [skus[key] mutableCopy]
        : [NSMutableDictionary dictionary];
    NSMutableDictionary *paths = [row[@"paths"] isKindOfClass:[NSDictionary class]]
        ? [row[@"paths"] mutableCopy]
        : [NSMutableDictionary dictionary];
    NSString *ev = evidence ?: @"";
    if (ev.length > 160) ev = [ev substringToIndex:160];
    paths[pathId] = @{
        @"result": result.length ? result : @"HOLD",
        @"evidence": ev,
        @"ts": LabLocalMilitaryNow() ?: @"?",
    };
    row[@"paths"] = paths;
    row[@"path_ts"] = LabLocalMilitaryNow() ?: @"?";
    skus[key] = row;
    doc[@"skus"] = skus;
    [self saveDoc:doc];
}

+ (NSDictionary *)pathResults {
    id p = [self row][@"paths"];
    return [p isKindOfClass:[NSDictionary class]] ? p : @{};
}

@end
