//
//  LabPathTest.m
//
//  Honest per-path oracles. hasKread still only kread32(kbase)==0xfeedfacf.
//

#import "LabPathTest.h"
#import "LabDeviceProfile.h"
#import "LabLearn.h"
#import "LabLocalTime.h"
#import "P007Board.h"
#import "P007KreadLane.h"
#import "P139BootIntel.h"
#import "P114SurfaceLeak.h"
#import "ClearSword/CS2Runner.h"
#import "lumina_core.h"

#include <stdlib.h>
#include <string.h>

#define PATH_BUILD @"t8150-krw-3"

@implementation LabPathTest

static void path_log(void (^logger)(NSString *), NSMutableString *out, NSString *line) {
    if (line.length == 0) return;
    [out appendFormat:@"%@\n", line];
    if (logger) logger(line);
}

static int path_int_after(NSString *s, const char *key) {
    if (!s.length || !key) return -1;
    NSString *needle = [NSString stringWithFormat:@"%s=", key];
    NSRange r = [s rangeOfString:needle];
    if (r.location == NSNotFound) return -1;
    const char *p = s.UTF8String + r.location + needle.length;
    return (int)strtol(p, NULL, 10);
}

+ (NSString *)scoreLog:(NSString *)log forPath:(NSString *)pathId {
    if (!log.length || !pathId.length) return @"HOLD";
    if ([pathId isEqualToString:@"occ"]) {
        if ([log containsString:@"occupancy=YES"]) return @"PASS";
        if ([log containsString:@"occupancy=NO"]) return @"FAIL";
        return @"HOLD";
    }
    if ([pathId isEqualToString:@"conv"]) {
        if ([log containsString:@"conversion=YES"] ||
            [log containsString:@"desc_type_forged=1"] ||
            ([log containsString:@"body_forged=1"] && [log containsString:@"kptr=1"]))
            return @"PASS";
        if ([log containsString:@"conversion=NO"] ||
            [log containsString:@"not-confirmed"])
            return @"FAIL";
        return @"HOLD";
    }
    if ([pathId isEqualToString:@"p010"]) {
        if ([log containsString:@"SUCCESS"] && [log containsString:@"word1"])
            return @"PASS";
        return @"FAIL";
    }
    if ([pathId isEqualToString:@"p114"]) {
        int kq = path_int_after(log, "kernel_range_q");
        int nq = path_int_after(log, "nonzero_q");
        if (kq > 0) return @"PASS";
        if (nq > 0) return @"REACH";
        if ([log containsString:@"0xe00002bf"] || [log containsString:@"kr=0xe00002bf"])
            return @"REACH";
        return @"FAIL";
    }
    if ([pathId isEqualToString:@"p139"]) {
        if ([log containsString:@"0xffffff"] || [log containsString:@"p139_heap"] ||
            [log containsString:@"SLIDE-TRIANGULATION"] || [log containsString:@"dossier"])
            return @"PASS";
        if (log.length > 80) return @"REACH";
        return @"FAIL";
    }
    if ([pathId isEqualToString:@"kread"]) {
        if ([log containsString:@"hasKread=YES"] ||
            [log containsString:@"KREAD primitive reads MH_MAGIC"])
            return @"PASS";
        if ([log containsString:@"KREAD FAIL"] || [log containsString:@"no KRW context"] ||
            [log containsString:@"hasKread=NO"])
            return @"FAIL";
        return @"HOLD";
    }
    if ([pathId isEqualToString:@"p143"]) {
        if ([log containsString:@"qid="] && [log containsString:@"kr=0x00000000"])
            return @"REACH";
        return @"HOLD";
    }
    if ([pathId isEqualToString:@"p110"]) {
        if ([log containsString:@"claim won"] || [log containsString:@"claim-won"])
            return @"PASS";
        if ([log containsString:@"family-b"] || [log containsString:@"Family-B"] ||
            [log containsString:@"died mid-round"])
            return @"REACH";
        return @"HOLD";
    }
    if ([pathId isEqualToString:@"p142"]) {
        if ([log containsString:@"session still alive after corruption"] ||
            [log containsString:@"CORRUPTION DETECTED"])
            return @"PASS";
        if ([log containsString:@"panic"] || [log containsString:@"0xDA78"] ||
            [log containsString:@"OOB WRITE"])
            return @"REACH";
        return @"HOLD";
    }
    if ([pathId isEqualToString:@"p149"]) {
        if ([log containsString:@"hasKread=YES"] ||
            [log containsString:@"KRW SELF-TEST READ: PASS"])
            return @"PASS";
        if ([log containsString:@"PIPE-HIT"] ||
            [log containsString:@"QUEUE-INIT"] ||
            [log containsString:@"conversion_receipt=YES"])
            return @"REACH";
        if ([log containsString:@"hasKread=NO"] ||
            [log containsString:@"KRW SELF-TEST READ: FAIL"])
            return @"FAIL";
        return @"HOLD";
    }
    return @"HOLD";
}

+ (NSString *)tap {
    NSMutableString *acc = [NSMutableString string];
    (void)[self runWithLog:^(NSString *msg) {
        if (msg.length) [acc appendFormat:@"%@\n", msg];
    }];
    return acc;
}

+ (BOOL)runWithLog:(void (^)(NSString *msg))logger {
    NSMutableString *out = [NSMutableString string];
    void (^L)(NSString *) = ^(NSString *line) { path_log(logger, out, line); };

    LabSku sku = [LabDeviceProfile detectedSku];
    NSString *skuName = [LabDeviceProfile skuName];
    L([NSString stringWithFormat:@"=== PATH TEST %@ BUILD %@ ===",
       LabLocalMilitaryNow() ?: @"?", PATH_BUILD]);
    L([NSString stringWithFormat:@"[*] sku=%@  hasKread still kread32(kbase)==0xfeedfacf",
       skuName]);
    L(@"[*] Occupancy / P110 / P143 are catalog-solo. P149 is KERNEL conversion on T8150. Hunt/17 PATHS is harvest-only. 12 mini PATHS establishes CS2/libkrw.");
    int coreSt = lumina_core_selftest();
    L([NSString stringWithFormat:@"[*] lumina_core %s selftest=%d",
       lumina_core_version(), coreSt]);

    NSDictionary *prev = [LabLearn pathResults];
    L(@"=== SCORECARD (last stored) ===");
    if (sku == LabSkuA14_23F77) {
        L(@"  occ     tap=p044/krw   bar=occupancy=YES");
        L(@"  conv    tap=p044/p113  bar=desc_type_forged OR (body_forged AND kptr)");
        L(@"  p010    tap=p010/p139  bar=QueueCreate SUCCESS + word1 band");
        L(@"  p114    tap=p114       bar=kernel_range_q>0 (disclosure, not kread)");
        L(@"  p139    tap=p139       bar=dossier + heap-shaped kptr");
        L(@"  kread   tap=kreadtest  bar=kread32(kbase)==0xfeedfacf");
        L(@"  p143    tap=p143       ISOLATED (17 door). Do not stack on P044.");
    } else if (sku == LabSkuT8150_24A435 || sku == LabSkuT8150_other) {
        L(@"  p139    tap=p139/krw   bar=dossier + heap-shaped kptr");
        L(@"  p114    tap=p114/krw   bar=sel-8 serializer kernel_range_q>0 or 2bf REACH");
        L(@"  kread   tap=kreadtest  bar=kread32(kbase)==0xfeedfacf");
        L(@"  p143    tap=p143       ISOLATED rocket submit. One TAP after reboot.");
        L(@"  p110    tap=p110       ISOLATED race. Family-B = window-won/slot-lost, not kread.");
        L(@"  p142    tap=p142       write. v6 Prepare-first then overshoot. Conversion is p149.");
        L(@"  p149    tap=p149/krw   17 conversion. PASS = kread32(kbase)==0xfeedfacf. REACH = PIPE-HIT.");
        L(@"  occ     SKIP           43748 clamp-CLOSED (table 0x10b8, 255 in-bounds)");
        L(@"  formula leak(P114) → write(P149=P142 prepare-then-overshoot + pipes) → kread32 → sptm(HOLD)");
    } else if (sku == LabSkuA14_21D50) {
        L(@"  kread   tap=kreadtest/libkrw/cs2  bar=kread32(kbase)==0xfeedfacf");
        L(@"  ane127  tap=conv       CLASS/FIELD in-bounds. 43748 not live.");
    } else if (sku == LabSkuA13_22G100) {
        L(@"  kread   tap=cs2core    bar=hasKread=YES via CS2");
    } else {
        L(@"  unknown SKU — Ident first. Public HOLD remaining-fire.");
    }
    if ([prev isKindOfClass:[NSDictionary class]] && prev.count) {
        L(@"=== LAST RESULTS ===");
        for (NSString *k in [[prev allKeys] sortedArrayUsingSelector:@selector(compare:)]) {
            id row = prev[k];
            if (![row isKindOfClass:[NSDictionary class]]) continue;
            L([NSString stringWithFormat:@"  %-6@  %@  %@  %@",
               k, row[@"result"] ?: @"?", row[@"ts"] ?: @"?", row[@"evidence"] ?: @""]);
        }
    }

    BOOL ran = NO;
    if (sku == LabSkuT8150_24A435 || sku == LabSkuT8150_other) {
        L(@"=== RUN 17 PAIR (READ-ONLY): P139 + P114 ===");
        NSString *p139 = nil;
        @try { p139 = [P139BootIntel tap]; }
        @catch (NSException *e) { L([NSString stringWithFormat:@"[-] p139 %@", e.name]); }
        [LabLearn ingestBootIntel];
        NSString *r139 = [self scoreLog:p139 forPath:@"p139"];
        if ([[LabLearn row][@"p139_heap"] isKindOfClass:[NSString class]]) r139 = @"PASS";
        [LabLearn recordPath:@"p139" result:r139
                   evidence:r139.length ? r139 : @"p139"];
        L([NSString stringWithFormat:@"PATH_TEST id=p139 class=harvest sku=%@ result=%@",
           skuName, r139]);
        ran = YES;

        NSString *p114 = nil;
        @try { p114 = [P114SurfaceLeak tap]; }
        @catch (NSException *e) { L([NSString stringWithFormat:@"[-] p114 %@", e.name]); }
        NSString *r114 = [self scoreLog:p114 forPath:@"p114"];
        int kq = path_int_after(p114 ?: @"", "kernel_range_q");
        [LabLearn recordPath:@"p114" result:r114
                   evidence:[NSString stringWithFormat:@"kernel_range_q=%d", kq]];
        L([NSString stringWithFormat:@"PATH_TEST id=p114 class=disclosure sku=%@ result=%@ kernel_range_q=%d",
           skuName, r114, kq]);
    } else if (sku == LabSkuA14_23F77) {
        L(@"=== RUN HUNT READ-ONLY: P139 (includes P010) ===");
        L(@"[*] Occupancy test is KERNEL / catalog p044. One TAP after reboot, Game Mode ON.");
        NSString *p139 = nil;
        @try { p139 = [P139BootIntel tap]; }
        @catch (NSException *e) { L([NSString stringWithFormat:@"[-] p139 %@", e.name]); }
        [LabLearn ingestBootIntel];
        NSString *r139 = [self scoreLog:p139 forPath:@"p139"];
        if ([[LabLearn row][@"p139_heap"] isKindOfClass:[NSString class]]) r139 = @"PASS";
        [LabLearn recordPath:@"p139" result:r139 evidence:@"p139"];
        L([NSString stringWithFormat:@"PATH_TEST id=p139 class=harvest sku=%@ result=%@",
           skuName, r139]);
        NSString *r010 = [self scoreLog:p139 forPath:@"p010"];
        [LabLearn recordPath:@"p010" result:r010 evidence:@"via p139"];
        L([NSString stringWithFormat:@"PATH_TEST id=p010 class=trunc-kva sku=%@ result=%@",
           skuName, r010]);
        ran = YES;
    } else {
        L(@"[*] No extra harvest TAP on this SKU. kreadtest still runs.");
    }

    L(@"=== RUN kread32 GATE ===");
    if ((sku == LabSkuA14_21D50 || sku == LabSkuA13_22G100) &&
        ![P007Board shared].hasKread) {
        L(@"[*] 12 mini / A13: CS2 then libkrw before kreadtest");
        NSString *cs = nil;
        @try { cs = [CS2Runner runUpstream]; }
        @catch (NSException *e) { L([NSString stringWithFormat:@"[-] cs2 %@", e.name]); }
        if (![P007Board shared].hasKread) {
            bool armed = P007LaneArmBoard();
            L([NSString stringWithFormat:@"[*] libkrw P007LaneArmBoard %@",
               armed ? @"YES" : @"miss"]);
        }
        (void)cs;
    }
    NSString *kt = nil;
    @try { kt = [P007Board tapKreadTest]; }
    @catch (NSException *e) { L([NSString stringWithFormat:@"[-] kreadtest %@", e.name]); }
    NSString *rk = [self scoreLog:kt forPath:@"kread"];
    [LabLearn recordPath:@"kread" result:rk evidence:@"tapKreadTest"];
    L([NSString stringWithFormat:@"PATH_TEST id=kread class=krw sku=%@ result=%@",
       skuName, rk]);
    P007Board *b = [P007Board shared];
    L([NSString stringWithFormat:@"[*] board hasKread=%@ kbase=0x%llx",
       b.hasKread ? @"YES" : @"NO", (unsigned long long)b.kbase]);

    L(@"=== PATH TEST END ===");
    L(@"[*] Next hunt occupancy: reboot, Game Mode ON, LPM off, one KERNEL.");
    L(@"[*] Next 17 submit: reboot, catalog p143 alone. Not this TAP.");
    return ran || b.hasKread;
}

@end
