//
//  LabBanditAdvisor.m — v3 individual-test-mode advisor (the Swift face).
//  Lum1na. iOS kernel research.
//

#import "LabBanditAdvisor.h"
#import "LabBandit.h"
#import "LabKnob.h"

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
    // surface the operator's knob on the same advisory line (one place,
    // every tap): probes still read their own knob files; this is display
    char knob[128];
    if (LabKnobRead(dom, knob, (int)sizeof knob) == 1)
        return [NSString stringWithFormat:
            @"[bandit-v3] %s knob=%@ | %@", dom,
            [NSString stringWithUTF8String:knob] ?: @"?",
            [NSString stringWithUTF8String:buf] ?: @""];
    return [NSString stringWithFormat:
        @"[bandit-v3] %s -> %@", dom,
        [NSString stringWithUTF8String:buf] ?: @""];
}

@end
