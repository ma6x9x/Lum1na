//
//  P146KnobSetter.m — the in-app KNOB FILE SETTER. p146 v2.
//  Lum1na-Debug (P007 rig). iOS kernel research (Lum1na).
//
//  The afc-bypass law: the Documents channel can wedge per device /
//  session (the ApplicationLookupFailed / Permission-denied classes
//  2026-11-01); the app writes its own flags at runtime (the p131
//  stage-3 class), so the tap set = a file utility. v2: the ladder is
//  LINE-PER-KNOB — p146_set.txt's lines feed ALL the composition knobs
//    line 1 -> p142_layers.txt  (the p142/p145 fill-session knob;
//              single-line legacy = this knob only)
//    line 2 -> p147_cycles.txt  (the p147 teardown battery knob)
//    line 3 -> p148_gop.txt     (the p148 blob tap's lawful [0,8] knob)
//  Absent lines = each knob's own default (18/24/2). Every write gets
//  the readback VERIFY row. No IOKit, no Metal, no state.
//

#import "P146KnobSetter.h"
#import "LabDeviceProfile.h"
#import "LabLocalTime.h"

#import <Foundation/Foundation.h>

#define P146_BUILD @"p146-knobsetter-v2"

@implementation P146KnobSetter

+ (NSString *)tap {
    NSMutableString *out = [NSMutableString string];
    NSString *docs = [NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    [out appendFormat:@"=== p146 session %@ BUILD %@ ===\n",
        LabLocalMilitaryNow(), P146_BUILD];
    [out appendString:[LabDeviceProfile identBlock]];

    /* the ladder source: line-per-knob (single line = the legacy p142 row) */
    NSString *sets = [docs stringByAppendingPathComponent:@"p146_set.txt"];
    NSArray *lines = [NSArray array];
    if ([NSFileManager.defaultManager fileExistsAtPath:sets]) {
        NSString *s = [NSString stringWithContentsOfFile:sets
            encoding:NSUTF8StringEncoding error:nil];
        lines = [s componentsSeparatedByCharactersInSet:
            [NSCharacterSet newlineCharacterSet]];
    }

    /* {ladder-index (1-based), knob file, default} */
    struct { int line; NSString *file; long def; } rows[3] = {
        { 1, @"p142_layers.txt", 18 },
        { 2, @"p147_cycles.txt", 24 },
        { 3, @"p148_gop.txt",    2  },
    };
    long got[3] = { -1, -1, -1 };

    [out appendFormat:@"[*] ladder: %@%@ (%@)\n",
        lines.count ? lines[0] : @"(absent)",
        lines.count > 1 ? [NSString stringWithFormat:@", %@",
            [lines[1] length] ? lines[1] : @"-"] : @"",
        @"line-per-knob; single line = the legacy p142 row; absent = defaults"];

    for (int i = 0; i < 3; i++) {
        long val = rows[i].def;
        BOOL fromLadder = NO;
        if (lines.count >= (NSUInteger)rows[i].line) {
            NSString *ln = [lines[rows[i].line - 1]
                stringByTrimmingCharactersInSet:
                [NSCharacterSet whitespaceCharacterSet]];
            if ([ln length]) {
                long v = strtol(ln.UTF8String, NULL, 10);
                if (v > 0) { val = v; fromLadder = YES; }
            }
        }
        NSString *knob = [docs stringByAppendingPathComponent:rows[i].file];
        NSString *sval = [NSString stringWithFormat:@"%ld\n", val];
        BOOL ok = [sval writeToFile:knob atomically:YES
                            encoding:NSUTF8StringEncoding error:nil];
        NSString *rb = [NSString stringWithContentsOfFile:knob
            encoding:NSUTF8StringEncoding error:nil];
        long rbv = rb ? strtol(rb.UTF8String, NULL, 10) : -1;
        [out appendFormat:@"[%@] line%d -> %@ written=%d readback=%ld"
            @" (%@ %@)\n",
            (rbv == val) ? @"VERIFY" : @"MISMATCH", rows[i].line,
            rows[i].file, ok, rbv,
            fromLadder ? @"from ladder" : @"DEFAULT",
            val == rows[i].def && !fromLadder ? @"value" : @""];
        got[i] = rbv;
    }

    /* the other composition flags' presence (the tap order's state) */
    NSArray *flags = @[ @"p131_stage3.txt", @"p132_land.txt",
                        @"lswkrw_arm.txt", @"p084_mode_massunmap.txt" ];
    for (NSString *f in flags) {
        BOOL present = [[NSFileManager defaultManager]
            fileExistsAtPath:[docs stringByAppendingPathComponent:f]];
        [out appendFormat:@"  flag %@ = %@\n", f, present ? @"SET" : @"-"];
    }

    [out appendFormat:@"[end-state] p142=%ld p147=%ld p148=%ld\n",
        got[0], got[1], got[2]];
    [out appendFormat:@"=== p146 end %@ ===\n", LabLocalMilitaryNow()];
    return out;
}

@end