//
//  P131QuickLookDetour.h — the QuickLook detour (stage 2 of the calif
//  chain). p131.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface P131QuickLookDetour : NSObject
/// The calif-chain STAGE-2 harness: the 86950 trigger PDF does not stop
/// at in-process parse — thumbnails/previews hand the SAME content to
/// quicklookd (a daemon). p131 runs the p076 crafted content through the
/// QuickLook route and records which process actually parsed it:
///   stage 0  gate + ident + honesty (stage-2 harness; no SpringBoard
///            claims — the status-bar artifact was THEIR demo's end-state)
///   stage 1  CONTROL: benign PDF via CGPDFDocument in-process + QL thumb
///            (isolates the trigger variable, proves the QL path works)
///   stage 2  TRIGGER-QL: bundled p076_trigger.pdf -> QLThumbnailGenerator
///            (daemon handoff). Our callback error = what the app saw.
///            A quicklookd crash log with the glyph path = the DAEMON
///            receipt (user pulls it from crash logs afterwards).
///   stage 3  TRIGGER-ImageIO in-process control (p076 replica, bounded)
///            so the daemon/in-process difference is attributable.
/// READ-ONLY apart from the parse work. PANIC-POSSIBLE (crafted content
/// is deliberately bug-shaped); one tap per force-quit. hasKread/NO.
+ (NSString *)tap;
@end

NS_ASSUME_NONNULL_END