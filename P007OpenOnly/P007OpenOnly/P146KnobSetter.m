//
//  P146KnobSetter.m — the in-app KNOB FILE SETTER. p146.
//  Lum1na-Debug (P007 rig). iOS kernel research (Lum1na).
//
//  The afc-bypass law: the Documents channel can wedge per device /
//  session (the ApplicationLookupFailed / Permission-denied classes
//  2026-11-01); the app writes its own flags at runtime (the p131
//  stage-3 class), so the tap set = a file utility: p146_set.txt
//  (the ladder) -> p142_layers.txt (the knob), verified by readback.
//

#import "P146KnobSetter.h"
#import "LabDeviceProfile.h"
#import "LabLocalTime.h"

#import <Foundation/Foundation.h>

#define P146_BUILD @"p146-knobsetter-v1"

@implementation P146KnobSetter

+ (NSString *)tap {
    NSMutableString *out = [NSMutableString string];
    NSString *docs = [NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    [out appendFormat:@"=== p146 session %@ BUILD %@ ===\n",
        LabLocalMilitaryNow(), P146_BUILD];
    [out appendString:[LabDeviceProfile identBlock]];

    /* the ladder source */
    NSString *sets = [docs stringByAppendingPathComponent:@"p146_set.txt"];
    NSString *knob  = [docs stringByAppendingPathComponent:@"p142_layers.txt"];
    long layers = 18;   /* the first overshoot-tap default */
    NSString *setLine = [NSString stringWithContentsOfFile:sets
        encoding:NSUTF8StringEncoding error:nil];
    if (setLine) {
        long v = strtol(setLine.UTF8String, NULL, 10);
        if (v > 0) layers = v;
    }
    [out appendFormat:@"[*] ladder: %@ -> layers=%ld\n",
        setLine ? @"p146_set.txt" : @"(absent; the 18 default)", layers];

    /* the write + the readback verify */
    NSString *val = [NSString stringWithFormat:@"%ld\n", layers];
    BOOL ok = [val writeToFile:knob atomically:YES
                       encoding:NSUTF8StringEncoding error:nil];
    NSString *rb = [NSString stringWithContentsOfFile:knob
        encoding:NSUTF8StringEncoding error:nil];
    long rbv = rb ? strtol(rb.UTF8String, NULL, 10) : -1;
    [out appendFormat:@"[%@] p142_layers.txt written=%d readback=%ld\n",
        (rbv == layers) ? @"VERIFY" : @"MISMATCH", ok, rbv];

    /* the other composition flags' presence (the tap order's state) */
    NSArray *flags = @[ @"p131_stage3.txt", @"p132_land.txt",
                        @"lswkrw_arm.txt", @"p084_mode_massunmap.txt" ];
    for (NSString *f in flags) {
        BOOL present = [[NSFileManager defaultManager]
            fileExistsAtPath:[docs stringByAppendingPathComponent:f]];
        [out appendFormat:@"  flag %@ = %@\n", f, present ? @"SET" : @"-"];
    }

    [out appendFormat:@"=== p146 end %@ ===\n", LabLocalMilitaryNow()];
    return out;
}

@end