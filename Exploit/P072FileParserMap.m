//
//  P072FileParserMap.m
//  File-parser chain slot. Three honest positions:
//    1. In-app CG/ImageIO/SceneKit/JPEG/CoreMedia parse ACEs THIS process
//       (already owned by the IPA). Cannot skip kread / commitSlide.
//    2. Privileged-daemon parse of a planted file (MobileBackup 84598,
//       lockdownd, Photos) is sandbox-adjacent. PARK remaining-fire.
//    3. AfterKread payload parse (board JSON, basebin.tar / basebin.tc)
//       is the jailbreak file mechanic. HOLD until kread32(kbase)==MH_MAGIC_64.
//  Bounded PoC: dlopen census + 1x1 PNG ImageIO decode. Not ACE. Not 86950.
//

#import "P072FileParserMap.h"
#import "LabDeviceProfile.h"
#import "LabLocalTime.h"

#import <CoreGraphics/CoreGraphics.h>
#import <ImageIO/ImageIO.h>
#import <dlfcn.h>
#import <fcntl.h>
#import <string.h>
#import <unistd.h>

#define P072_BUILD @"p072-file-parser-map-v1"

static void p072_dl(void (^L)(NSString *), const char *path) {
    void *h = dlopen(path, RTLD_LAZY);
    L([NSString stringWithFormat:@"  %-72s %s", path, h ? "OPEN" : "MISS"]);
    if (h) dlclose(h);
}

@implementation P072FileParserMap

+ (NSString *)tap {
    NSMutableString *log = [NSMutableString string];
    NSString *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    int fd = open([[docs stringByAppendingPathComponent:@"p072_file_parser_log.txt"] UTF8String],
                  O_CREAT | O_WRONLY | O_TRUNC, 0644);
    void (^L)(NSString *) = ^(NSString *s) {
        NSString *out = [s hasSuffix:@"\n"] ? s : [s stringByAppendingString:@"\n"];
        [log appendString:out];
        if (fd >= 0) { const char *p = out.UTF8String; if (p) write(fd, p, strlen(p)); }
    };

    L([NSString stringWithFormat:@"=== p072 session %@ BUILD %@ ===", LabLocalMilitaryNow(), P072_BUILD]);
    L(@"File-parser chain slot. Print/dlopen census + 1x1 PNG smoke.");
    L(@"Not first KRW. No trigger.pdf. No ImageIO/CG/SceneKit overflow payload.");
    NSString *stop = [LabDeviceProfile stopUnlessA14_23F77:@"p072"];
    if (stop) {
        L(stop);
        if (fd >= 0) { fcntl(fd, F_FULLFSYNC); close(fd); }
        return log;
    }
    L([LabDeviceProfile identBlock]);

    L(@"=== THREE SLOTS ===");
    L(@"1 IN-APP ACE   CG / ImageIO / SceneKit / JPEG / CoreMedia in this IPA.");
    L(@"               Decode of a crafted file only ACEs the already-controlled");
    L(@"               process. Dest-lookup current_task() still applies unless a");
    L(@"               privileged XPC decoder is in the path. Cannot skip kread.");
    L(@"               PARK remaining-fire. Sibling: JPEGFrameworkDecodeProbe ABI");
    L(@"               smoke + P058 AppleJPEGDriver IOServiceOpen (no +0x30 teardown).");
    L(@"2 DAEMON PLANT MobileBackup 84598 / lockdownd / Photos parse a file the");
    L(@"               app can write. Sandbox-adjacent. Still not kread. PARK.");
    L(@"3 AFTER KREAD  board JSON + basebin.tar / basebin.tc ingest. This is the");
    L(@"               jailbreak file mechanic once commitSlide sticks.");
    L(@"               HOLD until kread32(kbase)==0xfeedfacf.");

    L(@"=== HT149041 FILE-ACE CVE IDS (PARK, no PoC) ===");
    L(@"  86950 CoreGraphics OOB write (26.7.1 HT149226). Userspace ACE.");
    L(@"  86882 Accelerate  84519 AppleDouble  65344/86876/43702 CoreMedia");
    L(@"  84552 DiskImages  84510 exFAT  84534 file_cmds  84524 FontParser");
    L(@"  84564/64758/43661/86869/65395 ImageIO  86870 libarchive  84497 ModelIO");
    L(@"  84532/28966 RealityKit");
    L(@"  84487/84546/84611/84632/84620/84526 SceneKit  84492 Graphics race");
    L(@"  43715/64718 WebKit  84624 CoreML path  84598 MobileBackup physical ACE");

    L(@"=== DLOPEN CENSUS (reach, not fire) ===");
    p072_dl(L, "/System/Library/Frameworks/ImageIO.framework/ImageIO");
    p072_dl(L, "/System/Library/Frameworks/CoreGraphics.framework/CoreGraphics");
    p072_dl(L, "/System/Library/Frameworks/CoreImage.framework/CoreImage");
    p072_dl(L, "/System/Library/Frameworks/CoreMedia.framework/CoreMedia");
    p072_dl(L, "/System/Library/Frameworks/VideoToolbox.framework/VideoToolbox");
    p072_dl(L, "/System/Library/Frameworks/SceneKit.framework/SceneKit");
    p072_dl(L, "/System/Library/Frameworks/ModelIO.framework/ModelIO");
    p072_dl(L, "/System/Library/Frameworks/RealityKit.framework/RealityKit");
    p072_dl(L, "/System/Library/Frameworks/Accelerate.framework/Accelerate");
    p072_dl(L, "/usr/lib/libarchive.dylib");
    p072_dl(L, "/System/Library/PrivateFrameworks/FontServices.framework/FontServices");
    p072_dl(L, "/System/Library/PrivateFrameworks/CoreSceneUnderstanding.framework/CoreSceneUnderstanding");

    L(@"=== 1x1 PNG SMOKE (ImageIO, not ACE) ===");
    NSMutableData *png = [NSMutableData data];
    CGColorSpaceRef cs = CGColorSpaceCreateDeviceRGB();
    CGContextRef bctx = CGBitmapContextCreate(NULL, 1, 1, 8, 4, cs,
                                              kCGImageAlphaPremultipliedLast);
    CGImageRef made = NULL;
    if (bctx) {
        CGContextSetRGBFillColor(bctx, 1, 0, 0, 1);
        CGContextFillRect(bctx, CGRectMake(0, 0, 1, 1));
        made = CGBitmapContextCreateImage(bctx);
        CGContextRelease(bctx);
    }
    if (cs) CGColorSpaceRelease(cs);
    BOOL destOk = NO;
    if (made) {
        CGImageDestinationRef dest = CGImageDestinationCreateWithData(
            (__bridge CFMutableDataRef)png, CFSTR("public.png"), 1, NULL);
        if (dest) {
            CGImageDestinationAddImage(dest, made, NULL);
            destOk = CGImageDestinationFinalize(dest);
            CFRelease(dest);
        }
        CGImageRelease(made);
    }
    L([NSString stringWithFormat:@"png encode destOk=%@ bytes=%lu",
       destOk ? @"YES" : @"NO", (unsigned long)png.length]);

    BOOL decodeOk = NO;
    size_t w = 0, h = 0;
    if (png.length) {
        CGImageSourceRef src = CGImageSourceCreateWithData(
            (__bridge CFDataRef)png, NULL);
        if (src) {
            CGImageRef img = CGImageSourceCreateImageAtIndex(src, 0, NULL);
            if (img) {
                w = CGImageGetWidth(img);
                h = CGImageGetHeight(img);
                decodeOk = (w == 1 && h == 1);
                CGImageRelease(img);
            }
            CFRelease(src);
        }
    }
    L([NSString stringWithFormat:@"png decode ok=%@ %zux%zu (want 1x1)",
       decodeOk ? @"YES" : @"NO", w, h]);
    L(@"Decode of a 1x1 PNG we just wrote proves ImageIO is reachable in-process.");
    L(@"It is not a file ACE, not 86950, not kread.");

    L(@"=== VERDICT ===");
    L(@"Slot 1: in-app parse is occupancy of THIS task. Keep PARK for ACE payloads.");
    L(@"Slot 2: daemon plant stays PARK (84598 / lockdownd).");
    L(@"Slot 3: AfterKread board + basebin ingest is the jailbreak file path.");
    L(@"hasKread stays NO. Isolation: one TAP per force-quit.");
    if (fd >= 0) { fcntl(fd, F_FULLFSYNC); close(fd); }
    return log;
}

@end
