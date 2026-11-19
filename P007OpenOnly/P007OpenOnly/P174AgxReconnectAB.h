//
//  P174AgxReconnectAB.h — the AGX reconnect-hang A/B attribution probe. p174.
//  Technique: murk-sus / natsuk1 (RECONNECT_HANG.md) — credit murk-sus.
//  Their repo's own missing control: F1 surface vs NORMAL surface, same loop.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface P174AgxReconnectAB : NSObject
/// murk-sus's missing A/B: 17 cycles of IOServiceOpen(AGX*, type=1) → sel8
/// type-0x82 (sid) → IOServiceClose, measured SEPARATELY for the F1 surface
/// and a NORMAL surface. Their 24B115 receipt: cycle 18 hangs (F1). Our run:
/// (a) attribution — does the F1 seed cause the hang on 24B156/T8150?
/// (b) receipts — hang point, per-cycle kr/out.
/// The 18th open for each leg is attempted LAST (so a hang leaves the log
/// full); the cycle-18 attempt itself is the receipt boundary. PANIC: HANG
/// class (device stays responsive; the app is expected to be killed).
/// hasKread law intact. One tap per force-quit.
+ (NSString *)tap;
@end

NS_ASSUME_NONNULL_END
