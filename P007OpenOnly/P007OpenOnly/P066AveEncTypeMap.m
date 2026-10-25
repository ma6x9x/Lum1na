//
//  P066AveEncTypeMap.m
//  CVE-2026-84607 EncType class — VT reach MAP. One 128x128 H.264 session.
//  EncType mismatch string ABSENT on 23F77. No Close-vs-async remaining-fire.
//

#import "P066AveEncTypeMap.h"
#import "LabDeviceProfile.h"
#import "LabLocalTime.h"

#import <VideoToolbox/VideoToolbox.h>
#import <CoreMedia/CoreMedia.h>
#import <CoreVideo/CoreVideo.h>
#import <IOKit/IOKitLib.h>
#import <fcntl.h>
#import <string.h>
#import <unistd.h>

#define P066_BUILD @"p066-ave-enctype-map-v1"

static void p066_cb(void *ref, void *src, OSStatus st, VTEncodeInfoFlags f, CMSampleBufferRef sb) {
    (void)src; (void)f;
    NSMutableString *log = (__bridge NSMutableString *)ref;
    [log appendFormat:@"encode cb status=%d sample=%s\n", (int)st, sb ? "yes" : "nil"];
}

@implementation P066AveEncTypeMap

+ (NSString *)tap {
    NSMutableString *log = [NSMutableString string];
    NSString *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    NSString *path = [docs stringByAppendingPathComponent:@"p066_ave_enctype_log.txt"];
    int fd = open(path.UTF8String, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    void (^L)(NSString *) = ^(NSString *s) {
        NSString *out = [s hasSuffix:@"\n"] ? s : [s stringByAppendingString:@"\n"];
        [log appendString:out];
        if (fd >= 0) { const char *p = out.UTF8String; if (p) write(fd, p, strlen(p)); }
    };

    L([NSString stringWithFormat:@"=== p066 session %@ BUILD %@ ===", LabLocalMilitaryNow(), P066_BUILD]);
    L(@"CVE-2026-84607 EncType/VT MAP. Close 0xfffffff008371094 async 0xfffffff00837137C");
    L(@"Sibling 65410/84616: cve65410_AVE_CalcBufSizeOfCodedData 0xfffffff008216170");
    L(@"  32-bit width*height then *10/*2. 128x128 this TAP stays in-range.");
    L(@"23F77: EncType mismatch with session ABSENT. One session, no Invalidate race.");
    NSString *stop = [LabDeviceProfile stopUnlessA14_23F77:@"p066"];
    if (stop) {
        L(stop);
        if (fd >= 0) { fcntl(fd, F_FULLFSYNC); close(fd); }
        return log;
    }

    io_service_t svc = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("AppleAVE2Driver"));
    if (!svc) svc = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("AppleAVE2"));
    L([NSString stringWithFormat:@"AppleAVE2 service=%u", (unsigned)svc]);
    if (svc) {
        io_connect_t conn = 0;
        kern_return_t kr = IOServiceOpen(svc, mach_task_self(), 0, &conn);
        L([NSString stringWithFormat:@"IOServiceOpen type=0 kr=0x%x conn=0x%x", (unsigned)kr, (unsigned)conn]);
        if (conn) IOServiceClose(conn);
        IOObjectRelease(svc);
    }

    VTCompressionSessionRef session = NULL;
    OSStatus st = VTCompressionSessionCreate(kCFAllocatorDefault, 128, 128, kCMVideoCodecType_H264,
                                             NULL, NULL, NULL, p066_cb, (__bridge void *)log, &session);
    L([NSString stringWithFormat:@"VTCompressionSessionCreate H264 128x128 st=%d session=%p", (int)st, session]);
    if (st != noErr || !session) {
        L(@"VT create failed — sandbox/VT wall. EncType race still MAP, unfired.");
        if (fd >= 0) { fcntl(fd, F_FULLFSYNC); close(fd); }
        return log;
    }
    st = VTCompressionSessionPrepareToEncodeFrames(session);
    L([NSString stringWithFormat:@"PrepareToEncodeFrames st=%d", (int)st]);

    CVPixelBufferRef pb = NULL;
    NSDictionary *attrs = @{ (id)kCVPixelBufferPixelFormatTypeKey: @(kCVPixelFormatType_32BGRA) };
    CVReturn cvr = CVPixelBufferCreate(kCFAllocatorDefault, 128, 128, kCVPixelFormatType_32BGRA,
                                       (__bridge CFDictionaryRef)attrs, &pb);
    L([NSString stringWithFormat:@"CVPixelBufferCreate cvr=%d", (int)cvr]);
    if (pb) {
        VTEncodeInfoFlags flags = 0;
        st = VTCompressionSessionEncodeFrame(session, pb, CMTimeMake(1, 30), kCMTimeInvalid, NULL, NULL, &flags);
        L([NSString stringWithFormat:@"EncodeFrame st=%d flags=0x%x", (int)st, (unsigned)flags]);
        VTCompressionSessionCompleteFrames(session, kCMTimeInvalid);
        CVPixelBufferRelease(pb);
    }
    VTCompressionSessionInvalidate(session);
    CFRelease(session);
    L(@"session invalidated AFTER complete (no in-flight Close-vs-async).");
    L(@"=== VERDICT === EncType class LIVE (string absent). This TAP is reach. hasKread=NO.");
    if (fd >= 0) { fcntl(fd, F_FULLFSYNC); close(fd); }
    return log;
}

@end
