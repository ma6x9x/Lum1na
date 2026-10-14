//
//  Lum1naElevate.h
//  Lum1na
//
//  Post-KRW elevate step: uid0 -> unsandbox (MAC label slot) ->
//  CS_PLATFORM_BINARY, Dopamine 3 DOJailbreaker.elevatePrivileges order,
//  driven through whichever KRW lane is live (SocketKRW / libkrw /
//  ClearSword core). Runs AFTER the AfterKread self-test gate passes and
//  BEFORE pmap/AMFI/inject — the rig transcript 2026-10-14 17:51 showed
//  every spawn die EPERM without it (AMFI 0xe00002e2, opainject rc=1).
//
//  HONESTY: this is NOT DarkSword code. Only the P7 kit's leaked struct
//  offset claims were used, and only after they matched the Dopamine
//  info.c darwin-24.4+ ladder exactly. No kit modules, no delivery, no
//  payload. Safe variant: Dopamine-order privilege elevation only.
//
//  Gate of its own: needs LabProcOff()->kernproc (per-SKU VA, Ghidra-
//  derived). 0 = HOLD with a logged reason; the pipeline continues to
//  AMFI as before (no regression, no pretending).
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface Lum1naElevate : NSObject

/// Runs the elevate sequence. Returns the log body (appended to the
/// AfterKread FIRE transcript by the caller).
+ (NSString *)runElevate;

@end

NS_ASSUME_NONNULL_END
