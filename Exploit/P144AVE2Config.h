//
//  P144AVE2Config.h — the AVE2 IO_Config MASK INTAKE (row 2). p144.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface P144AVE2Config : NSObject
/// The agent-decoded knob, device row: AppleAVE2UserClient:
///   row 2 "IO_Config" (fn 0x88d3804, Config 0x88d3b90): structIn =
///   EXACTLY 0x38 bytes, structOut = 0x20; the u64 at structIn+0x30 =
///   the RAW MASK stored UNVALIDATED into [session+0x110]; [0x118..
///   0x140] then zeroed. State-machine gate: IO_Open (row 0, structIn
///   0x768/out 0x38) FIRST ("m_pcIODrv != null && no notification port").
///   NO entitlement strings anywhere in the row region.
/// The mask's consumer = the encode-loop's map step (chk 0x8879dc8;
/// per-surface mapper 0x87734f0 ANDs the full-FF mask) → the write-
/// through mapper 0x87a4b4c (id*8 slots, *(u64*)(*(slot)+0x20) |= bit,
/// no bound) — the AIMABLE-WRITE cluster's userland arm.
/// Stage 1 = the open census (the type-0/1 rows; the 2bd/2e2 law = the
///   honest reach row per device).
/// Stage 2 (if a connect lands) = the IO_Open + IO_Config census with
///   the smallest real mask (0x1 = bit0 only) — the intake's reply rows.
/// HONESTY: census-class rows only; a 0-kr row = the intake ACCEPTED
///   (state-manipulation class), never a read claim; hasKread stays
///   kread32-gated. PANIC-POSSIBLE (a real submit machine); one tap.
+ (NSString *)tap;
@end

NS_ASSUME_NONNULL_END