//
//  P070ChainSequencer.m
//  Five independent KRW doors + persist-after-kread. Reach census only.
//

#import "P070ChainSequencer.h"
#import "LabDeviceProfile.h"
#import "LabLocalTime.h"
#import "P007Board.h"

#import <IOKit/IOKitLib.h>
#import <fcntl.h>
#import <unistd.h>

#define P070_BUILD @"p070-chain-sequencer-v2-sku"

static void p070_svc(void (^L)(NSString *), const char *name) {
    io_service_t s = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching(name));
    L([NSString stringWithFormat:@"  %-28s service=%u", name, (unsigned)s]);
    if (!s) return;
    io_connect_t c = 0;
    kern_return_t kr = IOServiceOpen(s, mach_task_self(), 0, &c);
    L([NSString stringWithFormat:@"    open type=0 kr=0x%x conn=0x%x", (unsigned)kr, (unsigned)c]);
    if (kr != 0) {
        kr = IOServiceOpen(s, mach_task_self(), 1, &c);
        L([NSString stringWithFormat:@"    open type=1 kr=0x%x conn=0x%x", (unsigned)kr, (unsigned)c]);
    }
    if (c) IOServiceClose(c);
    IOObjectRelease(s);
}

@implementation P070ChainSequencer

+ (NSString *)tap {
    NSMutableString *log = [NSMutableString string];
    NSString *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    int fd = open([[docs stringByAppendingPathComponent:@"p070_chain_sequencer_log.txt"] UTF8String],
                  O_CREAT | O_WRONLY | O_TRUNC, 0644);
    void (^L)(NSString *) = ^(NSString *s) {
        NSString *out = [s hasSuffix:@"\n"] ? s : [s stringByAppendingString:@"\n"];
        [log appendString:out];
        if (fd >= 0) { const char *p = out.UTF8String; if (p) write(fd, p, strlen(p)); }
    };
    L([NSString stringWithFormat:@"=== p070 session %@ BUILD %@ ===", LabLocalMilitaryNow(), P070_BUILD]);
    L(@"Isolation: one door TAP per force-quit. This TAP is census + map only.");
    L([P007Board shared].kreadSignal);
    NSString *stop = [LabDeviceProfile stopUnlessA14_23F77:@"p070"];
    if (stop) {
        L(stop);
        if (fd >= 0) { fcntl(fd, F_FULLFSYNC); close(fd); }
        return log;
    }
    L([LabDeviceProfile identBlock]);
    L([LabDeviceProfile beta1Matrix]);

    L(@"=== FIVE INDEPENDENT KRW DOORS (SKU-honest) ===");
    L(@"A  64788 Facet A     P065  plant 1x65535 + Trap2 sel=3. 0xe00002be oracle.");
    L(@"                     LIVE on A12X 23G71 until 23G82. Shape-1 reclaim still required.");
    L(@"B  43748 occupancy   P044/P099  CheckandPrewire 16B records into kalloc.3072.");
    L(@"                     A14: P099 254-in occupancy HIT. A12X: fill_cap EXPECT-BAD (probe fires). T8150: 0x10b8 EXPECT-BAD.");
    L(@"                     Next: named Shape L copyout dest. Fat type-3 recv sealed PACGA.");
    L(@"C  84530 + 65343     P063/P057  heap sdata + AKS sel16 feeder. GEN1 leak, not kslide.");
    L(@"                     Next: pair with a WRITE door (A or B). Heap ≠ commitSlide.");
    L(@"D  84507/84561 NECP  P053  add/add_flow. 26.7 underflow strings ABSENT.");
    L(@"                     Next: named reclaim object in the client/flow zone.");
    L(@"E  43684 IOMD        P069/P055  makeMapping + dmaCommandOperation.");
    L(@"                     Next: named +0x34 consumer. One map done; no unbounded inc.");
    L(@"CS2 hop-1           phys_oob READ scan. Proven KRW on A13 22G100. EINVAL since 26.1 on hunt SKUs.");
    L(@"Siblings (reach, not first KRW): 84607 EncType P066, 65407 AVD P067, 43689 P068, 65408 P071.");
    L(@"File-parser slot (not a KRW door): P072 print/dlopen census. In-app ACE = this process.");
    L(@"  Daemon plant PARK (84598). AfterKread board/basebin ingest HOLD until commitSlide.");

    L(@"=== REACH CENSUS (IOServiceOpen, no fire) ===");
    p070_svc(L, "H11ANEIn");
    p070_svc(L, "H1xANELoadBalancer");
    p070_svc(L, "AppleAVE2Driver");
    p070_svc(L, "AppleAVE2");
    p070_svc(L, "AppleAVD");
    p070_svc(L, "AppleJPEGDriver");
    p070_svc(L, "AppleKeyStore");
    p070_svc(L, "IOGPU");
    p070_svc(L, "agx");
    p070_svc(L, "AppleH11ANEInterface");

    L(@"=== PERSIST (AfterKread HOLD) ===");
    L(@"Semi-untether after commitSlide kread32(kbase)==0xfeedfacf:");
    {
        const LabOffTab *off = LabOff();
        if (off) {
            L([NSString stringWithFormat:@"  table %s AMFI external=0x%llx loadtc=0x%llx sel %u/%u",
               off->tag ? off->tag : "?",
               (unsigned long long)off->amfi_external,
               (unsigned long long)off->amfi_loadtc,
               off->amfi_sel_copy, off->amfi_sel_manifest]);
            L([NSString stringWithFormat:@"  pmap_cs_allow=0x%llx +0x%x  pmap_load_tc=0x%llx",
               (unsigned long long)off->pmap_cs_allow,
               off->pmap_cs_allow_off,
               (unsigned long long)off->pmap_load_tc]);
        } else {
            L(@"  persist VAs HOLD (LabOff NULL)");
        }
    }
    L(@"Same-process AMFI UC + board JSON + userspace reboot. No iBoot, no NVRAM,");
    L(@"no launchdhook, no firmware write this pass. This TAP does not kwrite.");
    L(@"=== ORDER ===");
    if ([LabDeviceProfile sku] == LabSkuA12X_23G71) {
        L(@"A12X: 1 Ident  2 P070 census  3 P065 or P063  4 force-quit  5 KREAD after kread32");
        L(@"254 EXPECT-BAD on probe (public SKIP). hop-1 SKIP. CS2 is a READ scan until magic.");
    } else if ([LabDeviceProfile sku] == LabSkuA14_23F77) {
        L(@"A14: 1 Ident  2 P070 census  3 P099 occupancy or P044 1-rec OOB  4 force-quit");
        L(@"5 conversion (live ANE neighbor / Shape L)  6 SocketKRW.Arm  7 KREAD magic");
    } else if ([LabDeviceProfile sku] == LabSkuT8150_24A435 ||
               [LabDeviceProfile sku] == LabSkuT8150_other) {
        L(@"T8150: 1 Ident  2 P070 census  3 P100 / ANE 0x10b8 map. static_base=0xfffffe0007004000");
        L(@"A14 0x820/254 EXPECT-BAD on probe. Public SKIPS. hop-1 SKIP. CS2 READ scan.");
    } else {
        L(@"1 Ident  2 P070 census  3 one SKU door  4 force-quit  5 KREAD after kread32");
        L(@"Probe fires EXPECT-BAD. Public STOPs remaining-fire on unknown.");
    }
    L(@"hasKread stays NO until MH_MAGIC_64.");
    if (fd >= 0) { fcntl(fd, F_FULLFSYNC); close(fd); }
    return log;
}

@end
