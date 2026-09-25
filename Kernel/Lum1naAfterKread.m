#import "Lum1naAfterKread.h"
#import "Lum1naBoard.h"
#import "LabLocalTime.h"

@implementation Lum1naAfterKread

+ (NSString *)plan {
    return @"post-kread (A14 PPL, not momentarius, not Dopamine End-bump):\n"
           @"  1. kreadbuf of a known kernel string → commit slide\n"
           @"  2. AMFI UserClient loadTrustCache sel 2/7\n"
           @"  3. pmap_cs_allow_invalid (pmap+0xca class)\n"
           @"  4. pmap_load_trust_cache\n"
           @"  5. userspace reboot + bootstrap (jbserver-shaped, Lum1na-owned)\n"
           @"Dopamine 3.0.10 KRW (ClearSword/kfd) is A12/A13 26.0.0.1. Do not copy.\n";
}

+ (NSString *)tap {
    Lum1naBoard *b = [Lum1naBoard shared];
    NSMutableString *s = [NSMutableString string];
    [s appendFormat:@"=== after-kread %@ ===\n", LabLocalMilitaryNow()];
    [s appendFormat:@"hasKread=%@ leaks=%lu\n", b.hasKread ? @"YES" : @"NO", (unsigned long)b.leaks.count];
    [s appendString:[self plan]];
    if (!b.hasKread) {
        [s appendString:@"HOLD: board has no proven kreadbuf. Slots not invoked.\n"];
    }
    return s;
}

@end
