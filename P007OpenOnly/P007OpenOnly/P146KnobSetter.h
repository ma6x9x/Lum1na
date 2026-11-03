//
//  P146KnobSetter.h — the in-app KNOB FILE SETTER. p146.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface P146KnobSetter : NSObject
/// Reads the ladder from Documents/p146_set.txt (line-per-knob: line 1 =
/// p142_layers.txt, line 2 = p147_cycles.txt, line 3 = p148_gop.txt,
/// line 4 = p142_pre.txt; single line = the legacy p142 row; absent =
/// defaults 16463/24/2/8), writes
/// each knob file, reads them back, prints the VERIFY rows — the
/// afc-bypass law (the Documents channel on a given device can be
/// wedged; the app writes its own flags at runtime = the same class
/// p131's stage-3 flag uses). Also prints the current values of the
/// other composition flags (p131_stage3.txt, lswkrw_arm.txt presence).
/// HONESTY: no IOKit, no Metal, no state — a file utility between taps.
+ (NSString *)tap;
@end

NS_ASSUME_NONNULL_END