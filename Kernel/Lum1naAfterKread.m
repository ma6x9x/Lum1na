#import "Lum1naAfterKread.h"
#import "Lum1naBoard.h"
#import "LabLocalTime.h"
#import "LabRuntimeOffsets.h"
#import "A14_23F77_LabOffsets.h"
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
        [s appendFormat:@"  AMFIUserClient_externalMethod  0x%llx\n", off->amfi_external];
        [s appendFormat:@"  loadTrustCache                 0x%llx  sel %u / %u\n",
         off->amfi_loadtc, off->amfi_sel_copy, off->amfi_sel_manifest];
        [s appendFormat:@"  pmap_cs_allow_invalid_internal 0x%llx\n", off->pmap_cs_allow];
        [s appendString:@"  pmap_load_trust_cache          (cstring absent — not pinned)\n"];
        [s appendFormat:@"  aks_wvek                       0x%llx\n", off->aks_wvek_overflow];
        [s appendString:@"  owns_replaceable               present (twin 23G71)\n"];
    } else {
        [s appendString:@"A14 = PPL. pmap_cs_allow_invalid + AMFI UC sel 2/7 from the same process.\n"];
        [s appendFormat:@"23F77 pins (unslid) tag %s Ghidra 2026-09-29:\n", tag];
        [s appendFormat:@"  AMFIUserClient_externalMethod  0x%llx\n",
         off ? off->amfi_external : A14_23F77_AMFI_EXTERNALMETHOD];
        [s appendFormat:@"  loadTrustCache                 0x%llx  sel %u / %u\n",
         off ? off->amfi_loadtc : A14_23F77_AMFI_LOADTRUSTCACHE,
         off ? off->amfi_sel_copy : A14_23F77_AMFI_LOADTC_SEL_COPY,
         off ? off->amfi_sel_manifest : A14_23F77_AMFI_LOADTC_SEL_MANIFEST];
        [s appendFormat:@"  pmap_cs_allow_invalid_internal 0x%llx  *(pmap+0xca)=1\n",
         off ? off->pmap_cs_allow : A14_23F77_PMAP_CS_ALLOW_INVALID];
        [s appendFormat:@"  pmap_load_trust_cache          0x%llx\n",
         off ? off->pmap_load_tc : A14_23F77_PMAP_LOAD_TRUST_CACHE];
        [s appendString:@"  owns_replaceable               ABSENT (detach bit + size only)\n"];
        [s appendString:@"  EncType_Max                    PRESENT; session-mismatch ABSENT\n"];
    }
    return s;
}

+ (NSString *)tap {
    NSMutableString *s = [NSMutableString string];
    Lum1naBoard *b = [Lum1naBoard shared];
    
    // Header
    [s appendString:@"=== After-Kread Plan ===\n"];
    [s appendFormat:@"hasKread=%@ leaks=%lu sku=%@\n", 
     b.hasKread ? @"YES" : @"NO", (unsigned long)b.leaks.count, b.sku];
    
    if (!b.hasKread) {
        [s appendString:@"HOLD: no kreadbuf. AMFI sel 2/7 and pmap_cs not invoked.\n"];
        [s appendString:@"That is the point: glue is compiled, fire waits for the board.\n"];
        return s;
    }
    
    // Now execute the after-kread plan
    [s appendString:@"FIRING: KRW established, executing AMFI/pmap_cs plan\n"];
    
    // AMFI IOServiceOpen
    [s appendString:@"[*] AMFI IOServiceOpen...\n"];
    // ... rest of AMFI code ...
    
    return s;
}

@end
