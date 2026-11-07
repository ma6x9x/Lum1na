#import <UIKit/UIKit.h>
#import <QuartzCore/QuartzCore.h>
//
//  LabDeviceProfile.m
//  Lum1na
//

#import "LabDeviceProfile.h"
#import "LabRuntimeOffsets.h"
#import "LabLocalTime.h"
#import <sys/utsname.h>
#import <sys/sysctl.h>
#import <stdlib.h>
#import <string.h>
#import <notify.h>
#if __has_include(<os/proc.h>)
#import <os/proc.h>
#endif

static NSString *lp_sysctl(const char *name) {
    size_t n = 0;
    if (sysctlbyname(name, NULL, &n, NULL, 0) != 0 || n == 0) return @"?";
    char *b = calloc(1, n + 1);
    if (!b) return @"?";
    sysctlbyname(name, b, &n, NULL, 0);
    NSString *s = [NSString stringWithUTF8String:b];
    free(b);
    return s ?: @"?";
}

LabSku LabDeviceProfile_sku(void) {
    return [LabDeviceProfile detectedSku];
}

const char *LabDeviceProfile_sku_string(LabSku sku) {
    switch (sku) {
        case LabSkuA12X_23G71: return "A12X_23G71";
        case LabSkuA12X_other: return "A12X_other";
        case LabSkuA12X_23H30: return "A12X_23H30";
        case LabSkuXR_22H311:  return "XR_22H311";
        case LabSkuA13_22G100:    return "A13_22G100";
        case LabSkuA13_19F77:     return "A13_19F77";
        case LabSkuA13_other:  return "A13_other";
        case LabSkuA14_23F77:  return "A14_23F77";
        case LabSkuA14_21D50:  return "A14_21D50";
        case LabSkuA14_other:  return "A14_other";
        case LabSkuT8150_24A435: return "T8150_24A435";
        case LabSkuT8150_other:  return "T8150_other";
        default:               return "Unknown";
    }
}

@implementation LabDeviceProfile

#pragma mark - Core Detection

+ (NSString *)machine {
    return lp_sysctl("hw.machine");
}

+ (NSString *)osversion {
    return lp_sysctl("kern.osversion");
}

+ (NSString *)skuString {
    LabSku sku = [self detectedSku];
    switch (sku) {
        case LabSkuA14_23F77: return @"A14_23F77";
        case LabSkuA14_21D50: return @"A14_21D50";
        case LabSkuA14_other: return @"A14_other";
        case LabSkuA12X_23G71: return @"A12X_23G71";
        case LabSkuA12X_other: return @"A12X_other";
        case LabSkuA12X_23H30: return @"A12X_23H30";
        case LabSkuXR_22H311: return @"XR_22H311";
        case LabSkuA13_22G100: return @"A13_22G100";
        case LabSkuA13_19F77:  return @"A13_19F77";
        case LabSkuA13_other: return @"A13_other";
        case LabSkuT8150_24A435: return @"T8150_24A435";
        case LabSkuT8150_other: return @"T8150_other";
        default: return @"Unknown";
    }
}

+ (LabSku)detectedSku {
    NSString *m = [self machine];
    NSString *v = [self osversion];
    BOOL a14 = [m hasPrefix:@"iPhone13,"];
    BOOL a12x = [m hasPrefix:@"iPad8,"];
    BOOL xr = [m hasPrefix:@"iPhone11,8"] || [m hasPrefix:@"iPhone11,2"]
           || [m hasPrefix:@"iPhone11,4"] || [m hasPrefix:@"iPhone11,6"];
    BOOL a13 = [m hasPrefix:@"iPhone12,"];
    BOOL i182 = [m isEqualToString:@"iPhone18,2"];
    if (i182 && [v isEqualToString:@"24A435"]) return LabSkuT8150_24A435;
    if (i182 && [v hasPrefix:@"24A"]) return LabSkuT8150_other;
    if (a14 && [v isEqualToString:@"23F77"]) return LabSkuA14_23F77;
    if (a14 && [v hasPrefix:@"21D"]) return LabSkuA14_21D50; /* 17.3.x — 12 mini */
    if (a14) return LabSkuA14_other;
    if (a12x && [v isEqualToString:@"23G71"]) return LabSkuA12X_23G71;
    if (a12x && [v isEqualToString:@"23H30"]) return LabSkuA12X_23H30;
    if (a12x) return LabSkuA12X_other;
    if (xr) return LabSkuXR_22H311;
    /* Any A13 on the 18.x train uses the reference-rig harness row.
       22G = 18.6.x (proven rig); 22H = 18.7.x (iPhone 11). The info.c
       ladder is the same generation; CS2 stays train/rev-gated so a
       patched 22H never fires the heavy spray. Without this mapping the
       iPhone 11 fell through to LabSkuA13_other -> LabOff()==NULL, so
       every KERNEL step that reads the table aborted before the door. */
    if (a13 && [v hasPrefix:@"22"]) return LabSkuA13_22G100;
    if (a13 && [v isEqualToString:@"19F77"]) return LabSkuA13_19F77;
    if (a13) return LabSkuA13_other;
    return LabSkuUnknown;
}

+ (LabSku)sku {
    return [self detectedSku];
}

+ (NSString *)skuName {
    switch ([self detectedSku]) {
        case LabSkuA14_23F77:  return @"iPhone13,* A14 / 23F77";
        case LabSkuA14_21D50:  return @"iPhone13,* A14 / 21D* (17.3.x) — 12 mini, Dopamine rootless";
        case LabSkuA14_other:  return @"iPhone13,* A14 / not 23F77 or 21D*";
        case LabSkuA12X_23G71: return @"iPad8,* A12X / 23G71";
        case LabSkuA12X_other: return @"iPad8,* A12X / not 23G71 or 23H30 — FIELD# only";
        case LabSkuA12X_23H30: return @"iPad8,* A12X / 23H30 — iPadOS 26.7.1 FIELD# only, PPL";
        case LabSkuXR_22H311:  return @"XR A12 / 18.7.x — momentarius-ready";
        case LabSkuA13_22G100:    return @"iPhone12,* A13 / 22x build (18.x) — reference rig; 22H 18.7.x harness";
        case LabSkuA13_19F77:     return @"iPhone12,5 A13 / 19F77 — usbliter8 tethered rig (15.5 stock)";
        case LabSkuA13_other:  return @"iPhone12,* A13 / not 18.x";
        case LabSkuT8150_24A435: return @"iPhone18,2 T8150 / 24A435 — 17 Pro Max iOS 27.0";
        case LabSkuT8150_other:  return @"iPhone18,2 T8150 / 24A* sibling — static_base only";
        default:               return @"unknown";
    }
}

+ (BOOL)isTargetSku {
    return [self detectedSku] == LabSkuA14_23F77;
}

+ (BOOL)isA14_23F77 {
    return [self detectedSku] == LabSkuA14_23F77;
}

- (BOOL)isA14_23F77 {
    return [LabDeviceProfile detectedSku] == LabSkuA14_23F77;
}

+ (NSString *)kernelVersion {
    struct utsname u;
    uname(&u);
    return [NSString stringWithFormat:@"%s", u.release];
}

#pragma mark - Patch Oracle Utilities

+ (NSString *)stopUnlessA14_23F77:(NSString *)probe {
    /* P007 convention: non-nil means STOP. Probes do `if (stop) return stop`.
       Only unknown machines are blocked; SKU table still follows LabOff().

       LAB_DEBUG_APP builds (Lum1na-Debug lab app) return nil — primitives run
       on UNKNOWN machines. That is the point of the debug app: probe a new
       device/OS, see what sticks. Honest cost: kernel-VA probes still HOLD
       when LabOff() has no row for the SKU, and any unknown-SKU kernel write
       is a guess — AutoLearn (p100) exists to produce the learning packet
       that becomes a new table row instead of guessing. */
#if defined(LAB_DEBUG_APP) && LAB_DEBUG_APP
    return nil;
#else
    if ([self detectedSku] == LabSkuUnknown) {
        return [NSString stringWithFormat:@"STOP %@ — unknown machine.\n%@\n",
                probe ?: @"probe", [self identBlock]];
    }
    return nil;
#endif
}

+ (NSString *)gateMode {
    /* What the SKU gate will do on this build — AutoLearn/IDENT print it. */
#if defined(LAB_DEBUG_APP) && LAB_DEBUG_APP
    return @"DISABLED (LAB_DEBUG_APP) — primitives run on unknown machines";
#else
    return @"active (unknown machines STOP)";
#endif
}

+ (BOOL)isExactOraclePair {
    LabSku s = [self detectedSku];
    return s == LabSkuA14_23F77 || s == LabSkuA12X_23G71;
}

+ (uint32_t)queueCreateSel {
    const LabOffTab *o = LabOff();
    return o ? o->queue_create_sel : 6u;
}
+ (uint32_t)queueDestroySel {
    const LabOffTab *o = LabOff();
    return o ? o->queue_destroy_sel : 7u;
}
+ (uint32_t)queueSubmitSel {
    const LabOffTab *o = LabOff();
    return o ? o->submit_sel : 25u;
}
+ (uint32_t)queueCreateSize {
    const LabOffTab *o = LabOff();
    return o ? o->queue_create_size : 0x410u;
}
+ (uint32_t)queueLeakOff {
    const LabOffTab *o = LabOff();
    return o ? o->queue_leak : 0x558u;
}
+ (uint32_t)sysmemMdOff {
    const LabOffTab *o = LabOff();
    return o ? (uint32_t)o->sysmem_md : 0x90u;
}
+ (uint32_t)sel36 {
    const LabOffTab *o = LabOff();
    return o ? o->sel36 : 36u;
}
+ (NSArray<NSNumber *> *)queueCreateSizeSweep {
    uint32_t sz = [self queueCreateSize];
    return @[ @(sz), @(0x408u), @(0x410u) ];
}

+ (NSString *)expectQueueCreate {
    const LabOffTab *o = LabOff();
    if (!o || !o->queue_create_sel)
        return @"QueueCreate (NO SKU LAW ROW — no QueueCreate lane values for this table; honest hold)";
    return [NSString stringWithFormat:@"QueueCreate sel=%u size=0x%x leak=+0x%x",
            [self queueCreateSel], [self queueCreateSize], [self queueLeakOff]];
}
+ (NSString *)expectP010LastRef { return @"P010 last-ref: word1 small int; K-"; }
+ (NSString *)expectNecpReach { return @"NECP SO_NECP=0x1109 TLV=7; 84561/84507 map"; }
+ (NSString *)expectAVEOpen { return @"AVE Open; 84607 Close/async lock gap"; }
+ (NSString *)expect64788 { return @"64788 getter +0x90 naked; cd8 not KRW"; }
+ (NSString *)oracleTable { return @"oracle: LEFT=runtime sku; do not paste iPad VAs\n"; }
+ (BOOL)aneFillCapped {
    const LabOffTab *o = LabOff();
    return o && o->ane_fill_cap;
}
+ (BOOL)aneTableIsA14_0x820 {
    const LabOffTab *o = LabOff();
    return o && o->ane_table_size == 0x820u;
}

+ (BOOL)skuIsA12X {
    return LabSkuIsA12X([self detectedSku]);
}

+ (NSString *)armDump {
    NSMutableString *s = [NSMutableString string];
    const LabOffTab *off = LabOff();
    LabSku sku = [self detectedSku];
    [s appendString:@"=== ARM (LabOff static_base + FIELD# + unslid VAs) ===\n"];
    [s appendFormat:@"sku=%@ table=%s\n",
     [self skuString], (off && off->tag) ? off->tag : "NULL"];
    if (!off) {
        [s appendString:@"LabOff NULL — unslid VAs HOLD. Debugger still fires EXPECT-BAD.\n"];
        return s;
    }
    [s appendFormat:@"static_base=0x%llx (link base; live kbase = static_base+slide after commitSlide)\n",
     (unsigned long long)off->static_base];
    [s appendFormat:@"QueueCreate sel=%u size=0x%x leak=+0x%x destroy=%u submit=%u MD+0x%x sel36=%u\n",
     off->queue_create_sel, off->queue_create_size, off->queue_leak,
     off->queue_destroy_sel, off->submit_sel, off->sysmem_md, off->sel36];
    [s appendFormat:@"socket_usecount=+0x%x so_necp=0x%x icmp6filt=+0x148 (xnu FIELD#)\n",
     off->socket_usecount, off->so_necp];
    [s appendFormat:@"pmap_cs_allow_off=+0x%x owns_replaceable=%u fill_cap=%u table_size=0x%x\n",
     off->pmap_cs_allow_off, off->owns_replaceable, off->ane_fill_cap, off->ane_table_size];
    [s appendFormat:@"unslid CheckandPrewire=0x%llx AMFI_loadtc=0x%llx fn4=0x%llx getter=0x%llx\n",
     (unsigned long long)off->ane_checkandprewire,
     (unsigned long long)off->amfi_loadtc,
     (unsigned long long)off->fn4,
     (unsigned long long)off->getter];
    if (off->ane_checkandprewire == 0)
        [s appendString:@"unslid VA 0 = HOLD that poke (no kslide+wrong-KC smash).\n"];
    if (LabSkuIsA12X(sku) && sku != LabSkuA12X_23G71)
        [s appendString:@"A12X FIELD# row: 23G71 unslid VAs not pasted. 43748/254 SKIP. P010/P063 harvest live kptrs.\n"];
    return s;
}

+ (NSString *)beta1Matrix {
    NSMutableString *s = [NSMutableString string];
    const LabOffTab *off = LabOff();
    LabSku sku = [self detectedSku];
    [s appendString:@"=== BETA-1 SKU MATRIX ===\n"];
    [s appendFormat:@"sku=%@ table=%s fill_cap=%u owns_replaceable=%u\n",
     [self skuString],
     (off && off->tag) ? off->tag : "NULL",
     off ? off->ane_fill_cap : 0u,
     off ? off->owns_replaceable : 0u];
    [s appendString:@"hasKread flips only after SocketKRW.Arm then kread32(kbase)==0xfeedfacf on THIS sku.\n"];
    [s appendString:@"A12X phys_oob READ and A14 43748 WRITE are independent first doors. AfterKread HOLD.\n"];
    [s appendString:@"Study/port from Dopamine: gPrimitives vtable + End/CPUFAMILY SKU gate + AfterKread pipeline. hop-1/kfd bodies stay in the Dopamine tree.\n"];
    switch (sku) {
        case LabSkuA14_23F77:
            [s appendString:@"A14 23F77 first door: KERNEL T1 sequencer (P044 N=192 conversion bar; P139; P113; kread32).\n"];
            [s appendString:@"  conversion = desc_type_forged OR (body_forged AND kptr). Neighbor = live same-type ANE table or named Shape L.\n"];
            [s appendString:@"  KERNEL locks oob192 until conversion CONFIRMED. Game Overlay ON + LPM off raises adjacency odds.\n"];
            [s appendString:@"  hop-1 cluster_*_contig SKIP (EINVAL since 26.1). CS2 fail-graceful. P044 254 remaining-fire CLOSED.\n"];
            [s appendString:@"  Hot: T1 SKU door, pathtest, conv, KREAD, CHAINS.\n"];
            break;
        case LabSkuA12X_23G71:
            [s appendString:@"A12X 23G71 first door: 64788 Facet A (live until 23G82) + aio84530 HEAP leak.\n"];
            [s appendString:@"  43748 254-in SKIP (fill_cap >=0x80 -> 0xe00002c2). T1/P044/P099 skip.\n"];
            [s appendString:@"  hop-1 SKIP. CS2 phys_oob READ scan with kbase=0 is setup until pcb_start_offset + magic.\n"];
            [s appendString:@"  LightSword detach expect 0xe00002e2 abort-after-first. Momentarius needs kreadbuf first.\n"];
            [s appendString:@"  Hot: T2 Facet A, aio84530, KREAD, CHAINS. CS2 honesty last.\n"];
            break;
        case LabSkuA12X_23H30:
            [s appendString:@"A12X 23H30 iPadOS 26.7.1. PPL-only (no SPTM) AfterKread. First KRW is still disclose→convert→Arm→kread32.\n"];
            [s appendString:@"  FIELD# only: queue 0x408 leak=+0x550 static_base=0xfffffff007004000 icmp6filt=+0x148. 23G71 unslid VAs HOLD.\n"];
            [s appendString:@"  43748 patched in 26.6. SKIP P044/P099/P073 254. 64788 Facet A patched 23G82 — P065 EXPECT-BAD oracle.\n"];
            [s appendString:@"  First doors: P010 QueueCreate copyout + P063 aio HEAP (via P139). CS2 phys_oob READ scan kbase=0 is setup.\n"];
            [s appendString:@"  hop-1 EINVAL since 26.1. Do not fuse iPad READ with iPhone 43748 WRITE.\n"];
            [s appendString:@"  Hot: KERNEL (P139 harvest), P010, P063, P065 oracle, CS2, KREAD.\n"];
            break;
        case LabSkuA12X_other:
            [s appendString:@"A12X_other iPad8,* not 23G71/23H30. FIELD# only — 23G71 unslid VAs HOLD.\n"];
            [s appendString:@"  SKIP 254 remaining-fire. Ident + P010/P063 harvest. CS2 kbase=0 is setup.\n"];
            break;
        case LabSkuA13_22G100:
            [s appendString:@"A13 22G100 rig: CS2 KRW proven. Introspection harness. Separate from hunt A14/A12X.\n"];
            [s appendString:@"  Hot: cs2core, KREAD, CHAINS.\n"];
            break;
        case LabSkuA14_21D50:
            [s appendString:@"A14 21D50 12 mini: Dopamine rootless / CS2. Twin CLASS/FIELD only. Smaller 127-in ANE (43748 not live). Keep 21D50 VAs off 23F77.\n"];
            break;
        case LabSkuT8150_24A435:
            [s appendString:@"T8150 24A435 iPhone18,2 17 Pro Max. static_base=0xfffffe0007004000. ANE table 0x10b8 record+0x90.\n"];
            [s appendString:@"  KERNEL T1 = P139 harvest + P114 sel-8 serializer + kread32. Isolated p110/p142/p143.\n"];
            [s appendString:@"  SKIPS T8101 0x820/254, CS2 hop-1, LightSword (IOGPU pins 0). SPTM.\n"];
            [s appendString:@"  TAP pathtest for the scorecard. Probe app fires every TAP. iPhone18,1/18,3 unknown.\n"];
            break;
        case LabSkuT8150_other:
            [s appendString:@"T8150_other iPhone18,2 24A* sibling. static_base only. Public Lum1na SKIPS T8101 geometry.\n"];
            break;
        default:
            [s appendString:@"Unknown SKU: Ident first. Public Lum1na STOPs kernel remaining-fire. Use Lum1na-Debug to probe.\n"];
            break;
    }
    return s;
}

+ (NSString *)proveMatrix {
    NSMutableString *s = [NSMutableString string];
    [s appendString:[self beta1Matrix]];
    [s appendString:@"prove matrix:\n"
                    @"  hasKread=NO until commitSlide kread32(kbase)==MH_MAGIC_64 on THIS sku\n"
                    @"  LIVE A14: KERNEL T1 sequencer (P044 N=192 + P139 + P113 + kread32); P057 65343 KASLR sel16; P099 254 occupancy isolated; 64788 Facet A P065 0x2be oracle; P063 aio84530 HEAP\n"
                    @"  LIVE T8150: KERNEL T1 P139 + P114 serializer + kread32. Isolated p110/p142/p143. 43748 clamp-CLOSED. LightSword SKIP.\n"
                    @"  LIVE 12 mini 21D50: 127-in in-bounds ANE (43748 not live); CS2/libkrw KRW; kread32\n"
                    @"  LIVE A12X 23G71: P065 Facet A; P063 aio84530 HEAP; P057 sel16; CS2 phys_oob READ scan; P034 occupancy class; KREAD; P070 census. 254 SKIP.\n"
                    @"  LIVE A12X 23H30: FIELD# only (queue 0x408/+0x550, static_base). P139 harvest P010+P063. P065 EXPECT-BAD. CS2 kbase=0 setup. 43748/254 SKIP. PPL AfterKread.\n"
                    @"  CLOSED: 84523 sandbox (P057/P051/P052); P045 recv; LightSword last-wire GPU OOM; type-3 PACGA; hop-1 since 26.1; 43748 254 on fill_cap\n"
                    @"  PARKED: 28968 reap fire; 163-sel; 0x800; AfterKread persist; 86950 CG; file-ACE payloads (P072 is census)\n"
                    @"  NOTE: Lum1na catalog p064 = AVE racer. HT149041 print map id = ht149041. P007 p064 = that map.\n"];
    return s;
}
+ (NSString *)slideDestMap { return @"43724 pager dest unnamed; #536=22\n"; }
+ (NSString *)writeClassMap { return @"W not found this factory. F≠W. 84607 AVE race class.\n"; }

+ (NSString *)identBlock {
    const LabOffTab *off = LabOff();
    NSMutableString *out = [NSMutableString string];
    struct utsname u;
    uname(&u);
    [out appendFormat:@"=== IDENT %@ ===\n", LabLocalMilitaryNow()];
    [out appendFormat:@"machine        %@\n", [self machine]];
    [out appendFormat:@"osversion      %@\n", [self osversion]];
    [out appendFormat:@"release        %s\n", u.release];
    [out appendFormat:@"sku            %@\n", [self skuName]];
    [out appendFormat:@"offset table   %s\n", off ? off->tag : "NULL"];
    if (off && off->queue_create_sel) {
        [out appendFormat:@"QueueCreate    sel=%u size=0x%x leak=+0x%x destroy=%u submit=%u MD+0x%x sel36=%u\n",
             [self queueCreateSel], [self queueCreateSize], [self queueLeakOff],
             [self queueDestroySel], [self queueSubmitSel], [self sysmemMdOff], [self sel36]];
    } else {
        [out appendString:@"QueueCreate    (NO SKU LAW ROW — this table has no QueueCreate lane values;"
                          @" zeros = honest, not decoded. The 17's queue door = the IOGPU RocketDoor lane)\n"];
    }
    [out appendString:[self armDump]];
    switch ([self detectedSku]) {
        case LabSkuA14_23F77:
            [out appendString:@"TRACK: iPhone13 A14 23F77 ACTIVE. First door=KERNEL T1 (P044 N=192 + P139 + P113 + kread32). Home KERNEL pad / PATHS button. Catalog p097 is lock/unlock solo. hop-1 SKIP.\n"];
            break;
        case LabSkuA14_21D50:
            [out appendString:@"TRACK: 12 mini 21D50. Twin CLASS/FIELD only. Keep 21D50 VAs off 23F77.\n"];
            break;
        case LabSkuA14_other:
            [out appendFormat:@"TRACK: A14 osversion=%@ NOT 23F77.\n", [self osversion]];
            break;
        case LabSkuA12X_23G71:
            [out appendString:@"TRACK: iPad A12X 23G71. First door=64788 Facet A + aio84530 HEAP. 254 SKIP fill_cap. hop-1 SKIP. CS2 kbase=0 is setup.\n"];
            break;
        case LabSkuA12X_23H30:
            [out appendString:@"TRACK: iPad A12X 23H30 (26.7.1). FIELD# only. PPL AfterKread. SKIP 43748/254. Facet A EXPECT-BAD. First door=P010+P063 harvest. CS2 kbase=0 is setup.\n"];
            break;
        case LabSkuA12X_other:
            [out appendFormat:@"TRACK: iPad A12X osversion=%@ FIELD# only. 23G71 unslid VAs HOLD. SKIP 254.\n", [self osversion]];
            break;
        case LabSkuXR_22H311:
            [out appendString:@"TRACK: XR A12 18.7.x — momentarius-ready (ladder row).\n"];
            break;
        case LabSkuA13_22G100:
            [out appendString:@"TRACK: iPhone12 A13 22G100 rig. CS2 KRW proven. Separate from hunt A14/A12X.\n"];
            break;
        case LabSkuA13_other:
            [out appendFormat:@"TRACK: iPhone12 A13 osversion=%@.\n", [self osversion]];
            break;
        case LabSkuT8150_24A435:
            [out appendString:@"TRACK: iPhone18,2 T8150 24A435 (17 Pro Max). KERNEL pair = P139 harvest + P114 sel-8 serializer + kread32. Home KERNEL pad / PATHS button. Isolated: p110 leak-on, p143 RocketDoor. Catalog p097 lock/unlock solo. Never paste T8101/T8027 VAs.\n"];
            break;
        default:
            [out appendString:@"TRACK: unknown — paste Ident before panic tests.\n"];
            break;
    }
    [out appendString:@"Runtime profile always wins.\n"];
    [self beginHuntGroom];
    [out appendString:[self gameModeLine]];
    return out;
}

+ (NSString *)patchOracleMap {
    NSMutableString *map = [NSMutableString string];
    [map appendString:@"=== Patch Oracle Map ===\n"];
    [map appendFormat:@"Machine: %@\n", [self machine]];
    [map appendFormat:@"osversion: %@\n", [self osversion]];
    [map appendFormat:@"SKU: %@\n", [self skuString]];
    [map appendFormat:@"Target: %@\n", [self isTargetSku] ? @"YES" : @"NO"];
    [map appendFormat:@"Kernel: %@\n", [self kernelVersion]];
    // P007 lab oracle text (26.7 HT149041 guard map vs 23F77).
    [map appendString:@"26.7 HT149041 guards ABSENT on 23F77: EncType mismatch, "
     "necp underflow, upl_validation, reap free-entry, chroot entitlement, "
     "bpf attach policy. aio_workq_entry live @ 0xa285e94. See P064.\n"];
    return map;
}

#pragma mark - P009 Support

+ (NSString *)banner {
    return [NSString stringWithFormat:@"=== %@ ===", [self identBlock]];
}

+ (NSString *)expectP009PathB {
    return @"P009 PathB REPLACE_OK F (stale GPU) not W";
}


/* Ported from rig LabDeviceProfile (Route-A/KRW chain parity — 2026-10-24). */
static id g_huntGroomActivity = nil;
static CADisplayLink *g_huntDisplayLink = nil;
+ (void)huntGroomTick:(CADisplayLink *)dl { /* keep main thread hot; no-op body */ (void)dl; }
+ (void)beginHuntGroom {
    if (!g_huntGroomActivity) {
        NSActivityOptions opts = NSActivityUserInitiated | NSActivityLatencyCritical;
        g_huntGroomActivity = [[NSProcessInfo processInfo] beginActivityWithOptions:opts
                                                                            reason:@"Lum1na hunt Game Mode groom"];
    }
    void (^setIdleAndLink)(void) = ^{
        UIApplication.sharedApplication.idleTimerDisabled = YES;
        if (!g_huntDisplayLink) {
            g_huntDisplayLink = [CADisplayLink displayLinkWithTarget:self selector:@selector(huntGroomTick:)];
            CAFrameRateRange r = {80.f, 120.f, 120.f};
            g_huntDisplayLink.preferredFrameRateRange = r;
            [g_huntDisplayLink addToRunLoop:[NSRunLoop mainRunLoop] forMode:NSRunLoopCommonModes];
        }
    };
    if ([NSThread isMainThread]) setIdleAndLink();
    else dispatch_sync(dispatch_get_main_queue(), setIdleAndLink);
}
+ (void)stampLastTap:(NSString *)tapId {
    NSUserDefaults *d = [NSUserDefaults standardUserDefaults];
    [d setObject:[NSDate date] forKey:[NSString stringWithFormat:@"labTapStamp_%@", tapId]];
}
+ (NSString *)huntTapWarn:(NSString *)thisTap {
    NSUserDefaults *d = [NSUserDefaults standardUserDefaults];
    NSString *prev = [d objectForKey:[NSString stringWithFormat:@"labTapStamp_%@", thisTap]];
    NSMutableString *w = [NSMutableString string];
    if (prev) [w appendFormat:@"[!] %@ ran earlier this boot - one tap per force-quit", thisTap];
    NSProcessInfo *pi = NSProcessInfo.processInfo;
    if (pi.isLowPowerModeEnabled)
        [w appendString:w.length ? @" LPM=1" : @"[!] LPM=1 (conversion odds LOW)"];
    if ((long)pi.thermalState >= 2)
        [w appendFormat:@"%@thermal=%ld", w.length ? @" " : @"[!] ", (long)pi.thermalState];
    [self stampLastTap:thisTap];
    return w.length ? w : nil;
}
+ (NSString *)gameModeLine {
    NSDictionary *info = NSBundle.mainBundle.infoDictionary;
    id gc = info[@"GCSupportsGameMode"];
    id ls = info[@"LSSupportsGameMode"];
    NSString *cat = info[@"LSApplicationCategoryType"] ?: @"-";
    int gcB = [gc respondsToSelector:@selector(boolValue)] ? [gc boolValue] : 0;
    int lsB = [ls respondsToSelector:@selector(boolValue)] ? [ls boolValue] : 0;
    NSMutableString *n = [NSMutableString string];
    uint64_t anyOn = 0;
    static const char *names[] = {
        "com.apple.gamepolicyd.game-mode-enabled",
        "com.apple.gamepolicyd.gamemode",
        "com.apple.gamepolicy.gameMode",
        "com.apple.gamepolicyd.gameModeDidChange",
        "com.apple.runningboard.gameMode",
        NULL
    };
    for (int i = 0; names[i]; i++) {
        int token = 0;
        uint64_t st = 0;
        if (notify_register_check(names[i], &token) == NOTIFY_STATUS_OK) {
            notify_get_state(token, &st);
            notify_cancel(token);
            [n appendFormat:@" %s=%llu", names[i], (unsigned long long)st];
            anyOn |= st;
        }
    }
    NSProcessInfo *pi = NSProcessInfo.processInfo;
    size_t avail = 0;
#if __has_include(<os/proc.h>)
    avail = os_proc_available_memory();
#endif
    __block BOOL idle = NO;
    void (^readIdle)(void) = ^{
        idle = UIApplication.sharedApplication.idleTimerDisabled;
    };
    if ([NSThread isMainThread]) readIdle();
    else dispatch_sync(dispatch_get_main_queue(), readIdle);
    NSMutableString *s = [NSMutableString stringWithFormat:
            @"GAME_MODE_PLIST GCSupports=%d LSSupports=%d category=%@\n"
            @"GAME_MODE_NOTIFY%@\n"
            @"GAME_MODE_GROOM activity=%d idle=%d thermal=%ld LPM=%d avail=%zu displaylink=%d\n",
            gcB, lsB, cat,
            n.length ? n : @" none",
            g_huntGroomActivity != nil, idle ? 1 : 0,
            (long)pi.thermalState, pi.isLowPowerModeEnabled ? 1 : 0, avail,
            g_huntDisplayLink != nil];
    if (!anyOn) [s appendString:@"GAME_MODE_HOLD\n"];
    return s;
}

@end