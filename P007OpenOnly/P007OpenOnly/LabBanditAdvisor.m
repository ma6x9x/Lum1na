//
//  LabBanditAdvisor.m — v3 individual-test-mode advisor (the Swift face).
//  Lum1na. iOS kernel research.
//

#import "LabBanditAdvisor.h"
#import "LabBandit.h"

@implementation LabBanditAdvisor

+ (NSString *)adviceForCatalogId:(NSString *)catalogId {
    if (catalogId.length == 0) return @"";
    const char *dom = catalogId.UTF8String;
    char buf[256];
    buf[0] = '\0';
    int idx = LabBanditRecommendInput(dom, buf, (int)sizeof buf);
    (void)idx;   /* the index is for future input-knob wiring; today we
                    print the advisory line only */
    if (buf[0] == '\0') return @"";
    return [NSString stringWithFormat:
        @"[bandit-v3] %s -> %@", dom,
        [NSString stringWithUTF8String:buf] ?: @""];
}

@end
