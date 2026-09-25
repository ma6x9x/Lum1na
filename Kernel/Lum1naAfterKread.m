#import "Lum1naAfterKread.h"
#import "Lum1naBoard.h"
#import "LabLocalTime.h"
#import "LabRuntimeOffsets.h"
#import <IOKit/IOKitLib.h>
#import <string.h>

@implementation Lum1naAfterKread

+ (NSString *)plan {
    const LabOffTab *off = LabOff();
    const char *tag = (off && off->tag) ? off->tag : "?";
    NSMutableString *s = [NSMutableString string];
    [s appendString:
     @"LUM1NA CONSTELLATION (not /var/jb, not Dopamine BaseBin, not Relaxin):\n"
     @"  After kreadbuf of a KNOWN kernel string → board.commitSlide.\n"
     @"  Persist is the board + AMFI trust cache reloaded in THIS app each\n"
     @"  userspace reboot. No second root, no launchdhook clone, no momentarius.\n"];
    if (off && off->tag && strcmp(off->tag, "A12X_23G71") == 0) {
        [s appendString:@"A12X 23G71 = no SPTM. momentarius is PPL-on-KRW, not a kernel slot.\n"];
        [s appendFormat:@"T8020 pins (unslid) tag %s:\n", tag];
        [s appendString:@"  AMFIUserClient_externalMethod  0xFFFFFFF008B3FFE8\n"];
        [s appendString:@"  loadTrustCache                 0xFFFFFFF008B40088  sel 2 / 7\n"];
        [s appendString:@"  pmap_cs_allow_invalid_internal 0xFFFFFFF00A4DA8FC\n"];
        [s appendString:@"  pmap_load_trust_cache          (cstring absent — not pinned)\n"];
        [s appendFormat:@"  aks_wvek                       0x%llx\n", off->aks_wvek_overflow];
    } else {
        [s appendString:@"A14 = PPL. pmap_cs_allow_invalid + AMFI UC sel 2/7 from the same process.\n"];
        [s appendFormat:@"23F77 pins (unslid) tag %s:\n", tag];
        [s appendString:@"  AMFIUserClient_externalMethod  0xFFFFFFF008B673F8\n"];
        [s appendString:@"  loadTrustCache                 0xFFFFFFF008B67498  sel 2 / 7\n"];
        [s appendString:@"  pmap_cs_allow_invalid_internal 0xFFFFFFF00A610458  *(pmap+0xca)=1\n"];
        [s appendString:@"  pmap_load_trust_cache          0xFFFFFFF00A60D8D0\n"];
    }
    return s;
}

+ (NSString *)tap {
    Lum1naBoard *b = [Lum1naBoard shared];
    [b refreshIdentity];
    NSMutableString *s = [NSMutableString string];
    [s appendFormat:@"=== constellation %@ ===\n", LabLocalMilitaryNow()];
    [s appendFormat:@"hasKread=%@ leaks=%lu sku=%@\n",
         b.hasKread ? @"YES" : @"NO", (unsigned long)b.leaks.count, b.skuTag];
    [s appendString:[self plan]];

    io_service_t amfi = IOServiceGetMatchingService(
        kIOMainPortDefault, IOServiceMatching("AppleMobileFileIntegrity"));
    [s appendFormat:@"[*] AppleMobileFileIntegrity service=%u\n", amfi];
    if (amfi) {
        io_connect_t conn = MACH_PORT_NULL;
        kern_return_t kr = IOServiceOpen(amfi, mach_task_self(), 0, &conn);
        [s appendFormat:@"[*] AMFI IOServiceOpen kr=0x%x conn=%u (expect 0xe00002c1/2c7 without kwrite)\n",
             kr, conn];
        if (kr == KERN_SUCCESS && conn) IOServiceClose(conn);
        IOObjectRelease(amfi);
    }

    if (!b.hasKread) {
        [s appendString:@"HOLD: no kreadbuf. AMFI sel 2/7 and pmap_cs not invoked.\n"];
        [s appendString:@"That is the point: glue is compiled, fire waits for the board.\n"];
    }
    return s;
}

@end
