//
//  P097ConsoleSecLeak.h
//  Lum1na
//
//  CVE-2026-65371 — gRegistryRoot instance KVA disclosure through
//  IOService::updateConsoleUsers console-security interest notifications.
//
//  Public writeup: vschko/CaseStudies (github.com/vschko/CaseStudies).
//  Fixed in *OS 26.6 -> LIVE on 23F77 (26.5.0) and older (since xnu-1699).
//
//  Mechanics: updateConsoleUsers builds a MessageClientsContext with
//  context.argument = gRegistryRoot INSTANCE (kalloc'd 0x28 IORegistryEntry
//  root) and context.argSize = 0; the zero-size branch of the Mach send
//  passes the pointer ITSELF as messageArgument[0] to the user notifier.
//
//  IMPORTANT: the leaked value is the HEAP instance (0xfffffe... region),
//  NOT a static __DATA pointer — a leak primitive, NOT a slide oracle.
//  The static VARIABLE slot for T8101 12377 is intel row "gRegistryRoot"
//  (0xFFFFFFF00A934FF8) for later kread validation.
//
//  READ-ONLY. Registers one IOConsoleSecurityInterest notifier on
//  IOPlatformExpertDevice, waits for a lock/unlock trigger. No user client,
//  no kernel writes. Standalone tap, never in the JAILBREAK chain.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface P097ConsoleSecLeak : NSObject
+ (NSString *)tap;
@end

NS_ASSUME_NONNULL_END