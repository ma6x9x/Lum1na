//
//  P148AVE2Prepare.h — the AVE2 IO_Prepare BLOB-first intake calibration. p148.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface P148AVE2Prepare : NSObject
/// Direct-UC blob census on 24A435: IOServiceOpen AppleAVE2* (type 0..2)
/// -> row0 IO_Open (0x768) -> row2 IO_Config (zero-shape lawful pass) ->
/// row3 IO_Prepare ladder with a ZEROED 0x12c08 blob whose ONLY user set
/// field = the u32 at +0x55c (sGOP.iNumOfTemporalLayer — the params-blob
/// decode's VERBATIM intake, cfg+0x55c == structIn+0x55c, no remap).
/// Ladder {0,2,4,8} + the Documents/p148_gop.txt knob IF in [0,8].
/// Values >8 are OUT-LAW (the [0,8] assert's boundary; the >16 clamp and
/// the unbounded count-copy = HARD/panic-class — never fired here).
/// kr classified per row: 0 = accepted; 0xe00002bc = the D5 verifier row;
/// 2c2 = shape/state refusal. HONESTY: a clean row = the calibration's
/// intake-accepted class (kernel landing unprovable from this lane);
/// hasKread stays kread32-gated. PANIC-POSSIBLE; one tap per force-quit.
+ (NSString *)tap;
@end

NS_ASSUME_NONNULL_END