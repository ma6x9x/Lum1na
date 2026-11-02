//
//  P135RouteB.h — ROUTE B: taming the NQ NULL-ctx window. p135.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/// The NQ NULL-ctx route: the ×5-reproducing IOGPU notification-queue
/// crash (DispatchAvailableCompletionNotifications derefs ctx+0x10 with
/// ctx==NULL on the LEGIT path — far 0x10 every time) is a WINDOWED
/// NULL. Route B = the first-ever tame attempt, OUR bug: groom the
/// freed-ctx block with CHOSEN content (patterned vm pages at the zone
/// head), then fire the p027 NQ trap twice and compare signatures:
///   far 0x10 again        = the window stayed NULL (law, honest)
///   far in our pattern    = THE NULL WAS TAMED — ctx+0x10 read our
///                           content = a KERNEL READ AT A CHOSEN SLOT
///   new far / different signature = the walk shape moved (map data)
/// Signature comparison runs against the fleet's standing 0x10 corpus.
/// PANIC-POSSIBLE BY DESIGN; one tap per force-quit; hasKread NO.
@interface P135RouteB : NSObject
/// NQ NULL-ctx window groom; mechanics in the .m header.
+ (NSString *)tap;

@end

NS_ASSUME_NONNULL_END