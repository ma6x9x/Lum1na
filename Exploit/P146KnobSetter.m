//
//  P146KnobSetter.m — the in-app KNOB FILE SETTER. p146 v2.
//  Lum1na-Debug (P007 rig). iOS kernel research (Lum1na).
//
//  The afc-bypass law: the Documents channel can wedge per device /
//  session (the ApplicationLookupFailed / Permission-denied classes
//  2026-11-01); the app writes its own flags at runtime (the p131
//  stage-3 class), so the tap set = a file utility. v2: the ladder is
//  LINE-PER-KNOB — p146_set.txt's lines feed ALL the composition knobs
//    line 1 -> p142_layers.txt  (the p142/p145/p149 overshoot knob;
//              single-line legacy = this knob only)
//    line 2 -> p147_cycles.txt  (the p147 teardown battery knob)
//    line 3 -> p148_gop.txt     (the p148 blob tap's lawful [0,8] knob)
//    line 4 -> p142_pre.txt     (Prepare-first count, lawful [1,8])
//  Absent lines = each knob's own default (16463/24/2/8). Every write
//  gets the readback VERIFY row. No IOKit, no Metal, no state.
//

#import "P146KnobSetter.h"
#import "LabDeviceProfile.h"
#import "LabLocalTime.h"

#import <Foundation/Foundation.h>

#define P146_BUILD @"p146-knobsetter-v4"

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
    struct { int line; NSString *file; long def; } rows[4] = {
        { 1, @"p142_layers.txt", 16463 },
        { 2, @"p147_cycles.txt", 24 },
        { 3, @"p148_gop.txt",    2  },
        { 4, @"p142_pre.txt",    8  },
    };
    long got[4] = { -1, -1, -1, -1 };

    [out appendFormat:@"[*] ladder: %@%@ (%@)\n",
        lines.count ? lines[0] : @"(absent)",
        lines.count > 1 ? [NSString stringWithFormat:@", %@",
            [lines[1] length] ? lines[1] : @"-"] : @"",
        @"line-per-knob; single line = the legacy p142 row; absent = defaults"];

    for (int i = 0; i < 4; i++) {
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
        /* line 1 leftover 18 (09:06 / 09:55 HOLD) cannot hit the 16463 OOB */
        if (i == 0 && val > 0 && val < 16462) {
            [out appendFormat:@"[heal] line1 %ld is in-bounds leftover — writing 16463\n",
                val];
            val = 16463;
            fromLadder = NO;
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

    /* v3.2: the P044 v47 knobs (no-push law): p044_model.txt = the
       passthrough marshal class (the post-marshal fill), p044_req_in.txt =
       192 (the 1-record OOB). ABSENT = write the defaults. p044_target.txt
       stays the census's OWN pick (absent = honest census law). */
    NSString *modelPath = [docs stringByAppendingPathComponent:@"p044_model.txt"];
    if (![NSFileManager.defaultManager fileExistsAtPath:modelPath]) {
        BOOL ok = [@"XVRC27_127in_copyout\n" writeToFile:modelPath
                       atomically:YES encoding:NSUTF8StringEncoding error:nil];
        [out appendFormat:@"[%@] p044_model.txt auto-written = XVRC27_127in_copyout (the in-bounds chosen-write; the 21:26 kernel line: sid-validation gates the OOB — the v61c census target rides the OUTPUT record)\n",
            ok ? @"VERIFY" : @"FAILED"];
    } else {
        NSString *cur = [NSString stringWithContentsOfFile:modelPath
                            encoding:NSUTF8StringEncoding error:nil] ?: @"";
        [out appendFormat:@"[kept] p044_model.txt = %@\n",
            [cur stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]]];
    }
    NSString *reqPath = [docs stringByAppendingPathComponent:@"p044_req_in.txt"];
    if (![NSFileManager.defaultManager fileExistsAtPath:reqPath]) {
        BOOL ok = [@"127\n" writeToFile:reqPath atomically:YES
                        encoding:NSUTF8StringEncoding error:nil];
        [out appendFormat:@"[%@] p044_req_in.txt auto-written = 127 (in-bounds; all sids resolve -> inference RUNS; the copyout model = chosen tiles)\n",
            ok ? @"VERIFY" : @"FAILED"];
    }

    /* the other composition flags' presence (the tap order's state) */
    NSArray *flags = @[ @"p131_stage3.txt", @"p132_land.txt",
                        @"lswkrw_arm.txt", @"p084_mode_massunmap.txt" ];
    for (NSString *f in flags) {
        BOOL present = [[NSFileManager defaultManager]
            fileExistsAtPath:[docs stringByAppendingPathComponent:f]];
        [out appendFormat:@"  flag %@ = %@\n", f, present ? @"SET" : @"-"];
    }

    [out appendFormat:@"[end-state] p142=%ld p147=%ld p148=%ld pre=%ld\n",
        got[0], got[1], got[2], got[3]];
    [out appendFormat:@"=== p146 end %@ ===\n", LabLocalMilitaryNow()];
    return out;
}

@end