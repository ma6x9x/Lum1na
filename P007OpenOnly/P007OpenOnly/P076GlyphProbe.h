//
//  P076GlyphProbe.h
//  P007OpenOnly
//
//  CVE-2026-86950 "Great Glyph Grift" on-device trigger (calif.io 2026-09-30).
//  CoreGraphics aa_double_to_fixed: aa_moveto uses FCVTZS Wd (saturates) but
//  aa_lineto uses FCVTZS 2D + XTN (truncates) -> aa_add_edges bbox wraps ->
//  undersized coverage buffer -> controlled OOB 16-bit increments (stack via
//  alloca when width_px <= 1015, else malloc heap). Trigger: crafted TrueType
//  font (composite chain, ~2^9 scaling) embedded in a PDF, rendered through
//  the ImageIO thumbnail path (CGImageSourceCreateThumbnailAtIndex — the
//  same decode path WhatsApp/QuickLook previews use).
//
//  Fixed in iOS 26.7.1 / macOS 15.8.1. Lab device iPhone13,2 23F77 = 26.5
//  -> candidate UNPATCHED. This probe: benign-PDF CONTROL (proves the
//  in-app ImageIO path), then the bundled trigger PDF. If the session ends
//  right after the TRIGGER line with no SURVIVED line, the crash IS the
//  finding (log is per-line F_FULLFSYNC, survives the crash).
//
//  Honesty: userspace OOB in OUR process. NOT kernel. NOT KRW. NOT hasKread.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface P076GlyphProbe : NSObject
+ (NSString *)tap NS_SWIFT_NAME(tap());
/// Same control/console flow, trigger stages skipped — display-crash discriminator.
+ (NSString *)tapControlOnly NS_SWIFT_NAME(tapControlOnly());
@end

NS_ASSUME_NONNULL_END