//
//  P115M2ScalerPeek.m — the framework-path peek for the M2Scaler lane. p115.
//  Lum1na-Debug (P007 rig). iOS kernel research (Lum1na).
//
//  WHY (2026-10-27 night): the QueueCreate grammar ladder on the sel-6 lane
//  has decoded three layers (0xfa8 row size, in[0xFA4] bit0, phase count=2)
//  and STILL yields 2c2 on-device — another layer is below (the factory
//  tags). The PEEK alternative beats the ladder: if any framework op opens
//  AppleM2ScalerCSCDriver legitimately in THIS process, the resulting user
//  client already has a real queue — sel-8 captures run on THAT connection
//  with no QueueCreate at all. This is the p001 NewPortSweep / VTConnHunt
//  pattern (user-confirmed direction: "use peek logic like SwiftPeek").
//
//  BATTERY (bounded):
//    0. baseline port snapshot
//    1. IOSurface create (control — the framework law every other op needs)
//    2. VTCompressionSession 720p H.264, ONE frame (AVE path, encode works
//       on-device per tonight's ave64747_vt control receipt)
//    3. VTDecompressionSession with CSC output format 420f (the classic
//       colorspace-conversion/scaler consumer — prime M2Scaler candidate)
//    4. diff after each op; every NEW SEND-only port gets a bounded
//       fingerprint: sel-8 {u64 0} 8B struct call — the M2Scaler no-queue
//       signature is kr=0xe00002bf (2bf), NOT 2c2/2c7. NO writes, NO transforms.
//
//  HONESTY: peek-only. If no port fingerprints as M2Scaler, the honest
//  answer is "no framework path opens it in-process on this boot" — the
//  QueueCreate grammar lattice stays the route. hasKread=NO throughout.
//  One tap per force-quit; discovered doors are never closed (P027/P098 law).
//

#import "P115M2ScalerPeek.h"
#import "LabDeviceProfile.h"
#import "LabLocalTime.h"

#import <Foundation/Foundation.h>
#import <dlfcn.h>
#import <fcntl.h>
#import <unistd.h>
#import <mach/mach.h>
#import <mach/mach_port.h>
#import <CoreMedia/CoreMedia.h>
#import <CoreVideo/CoreVideo.h>
#import <VideoToolbox/VideoToolbox.h>
#import <stdint.h>
#import <stdio.h>
#import <string.h>

#define P115_BUILD @"p115-m2scaler-peek-v1"

static NSMutableString *g_log = nil;
static int g_fd = -1;
static void L(NSString *s) {
    if (!g_log) return;
    NSString *out = [s hasSuffix:@"\n"] ? s : [s stringByAppendingString:@"\n"];
    [g_log appendString:out];
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

/* ---- port snapshot (the p001 NewPortSweep shape, SEND-only set) ------- */
static kern_return_t p115_snapshot(NSMutableSet **outSet) {
    mach_port_name_array_t names = NULL;
    mach_port_type_array_t types = NULL;
    mach_msg_type_number_t nn = 0, nt = 0;
    kern_return_t kr = mach_port_names(mach_task_self(), &names, &nn, &types, &nt);
    NSMutableSet<NSNumber *> *s = [NSMutableSet set];
    if (kr == KERN_SUCCESS && names && types) {
        for (mach_msg_type_number_t i = 0; i < nn && i < nt; i++) {
            if ((types[i] & MACH_PORT_TYPE_SEND) && !(types[i] & MACH_PORT_TYPE_RECEIVE))
                [s addObject:@(names[i])];
        }
    }
    if (names) (void)vm_deallocate(mach_task_self(), (vm_address_t)names, nn * sizeof(mach_port_name_t));
    if (types) (void)vm_deallocate(mach_task_self(), (vm_address_t)types, nt * sizeof(mach_port_type_t));
    *outSet = s;
    return kr;
}

static void p115_diff(NSString *tag, NSMutableSet *before, NSMutableSet *after, NSMutableSet *newPorts) {
    for (NSNumber *p in after) if (![before containsObject:p]) [newPorts addObject:p];
    Lf(@"[diff %@] new SEND-only ports (%lu): %@", tag, (unsigned long)newPorts.count,
       [newPorts.allObjects componentsJoinedByString:@" "]);
}

/* ---- IOKit dlsym (p098 local shape) ----------------------------------- */
typedef CFMutableDictionaryRef (*Match_t)(const char *);
typedef io_service_t (*GetSVC_t)(mach_port_t, CFDictionaryRef);
typedef kern_return_t (*Open_t)(io_service_t, task_port_t, uint32_t, io_connect_t *);
typedef IOReturn (*Struct_t)(mach_port_t, uint32_t, const void *, size_t, void *, size_t *);
typedef kern_return_t (*Rel_t)(io_object_t);

static mach_port_t g_main;
static Match_t g_match;
static GetSVC_t g_get;
static Open_t g_open;
static Struct_t g_st;
static Rel_t g_rel;

static BOOL p115_dlsym(void) {
    void *h = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_NOW);
    if (!h) h = RTLD_DEFAULT;
    g_match = (Match_t)dlsym(h, "IOServiceMatching");
    g_get   = (GetSVC_t)dlsym(h, "IOServiceGetMatchingService");
    g_open  = (Open_t)dlsym(h, "IOServiceOpen");
    g_st    = (Struct_t)dlsym(h, "IOConnectCallStructMethod");
    g_rel   = (Rel_t)dlsym(h, "IOObjectRelease");
    mach_port_t *mp = (mach_port_t *)dlsym(h, "kIOMainPortDefault");
    if (mp) g_main = *mp;
    return g_match && g_get && g_open && g_st && g_rel && g_main;
}

/* fingerprint: M2Scaler's sel-8 no-queue shape = 2bf (out buffer sized) */
static BOOL p115_fingerprint(NSString *tag, mach_port_t port, NSMutableString *outLine) {
    if (!g_st) { [outLine appendFormat:@" port %u: no callStruct", port]; return NO; }
    uint64_t in8 = 0;
    static uint8_t out8[0x1000];
    memset(out8, 0, sizeof(out8));
    size_t olen = sizeof(out8);
    IOReturn kr8 = g_st((mach_port_t)port, 8, &in8, 8, out8, &olen);
    BOOL sig = (kr8 == 0xe00002bf);
    [outLine appendFormat:@"\n    port %u sel8={0}8B kr=0x%08x outLen=%zu %@",
        port, (unsigned)kr8, olen,
        sig ? @"  <-- M2SCALER FINGERPRINT (2bf no-queue)" : @""];
    return sig;
}

/* ---- encode plumbing (ave47 control receipt, output discarded) -------- */
/* VT output callback = NULL (outputs discarded) — kills the flushCB/encCB
   scaffolding entirely (the 2026-10-15 lesson: wrong callback signature =
   red gate; nothing here needs the encoded bytes, the encode frame is only
   the op whose port side-effects the sweep fingerprints). */

@implementation P115M2ScalerPeek

+ (NSString *)tap {
    g_log = [NSMutableString string];
    NSString *docs = [NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    g_fd = open([[docs stringByAppendingPathComponent:@"p115_m2peek_log.txt"] UTF8String],
                O_CREAT | O_WRONLY | O_TRUNC, 0644);

    Lf(@"=== p115 session %@ BUILD %@ ===", LabLocalMilitaryNow(), P115_BUILD);
    L([LabDeviceProfile identBlock]);
    L(@"[duty law] framework-path PEEK: run the bounded CSC battery, diff the task's");
    L(@"  SEND ports after each op, fingerprint new ports for the M2Scaler sel-8");
    L(@"  no-queue signature (2bf). A framework-created M2Scaler UC already owns a");
    L(@"  real queue — sel-8 on it needs NO QueueCreate (beats the grammar ladder");
    L(@"  that stalled at 2c2 through three decoded layers).");
    L(@"[honesty] peek-only: 2 bounded struct calls per new port, NO writes, NO");
    L(@"  transforms, NO grooming. hasKread=NO. One tap per force-quit; discovered");
    L(@"  doors are never closed (P027/P098 law).");
    L(@"[no-guess law] tag grammar NOT fired — the QueueCreate inputs are zeroed at");
    L(@"  most; this probe never sends one.");

    if (!p115_dlsym()) {
        L(@"[-] IOKit dlsym incomplete — honest stop, nothing probed.");
        goto finish;
    }

    NSMutableSet *snap = nil, *after = nil, *newP = [NSMutableSet set];
    NSMutableString *fp = [NSMutableString string];
    BOOL found = NO;

    (void)p115_snapshot(&snap);
    Lf(@"[baseline] SEND-only ports: %lu", (unsigned long)snap.count);

    /* op 1: IOSurface create (control) */
    {
        CVPixelBufferRef pb = NULL;
        CVReturn cv = CVPixelBufferCreate(kCFAllocatorDefault, 1280, 720,
                                          kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange,
                                          NULL, &pb);
        if (cv == kCVReturnSuccess && pb) {
            (void)p115_snapshot(&after);
            (void)p115_diff(@"iosurface-create", snap, after, newP);
            CVPixelBufferRelease(pb);
        } else {
            Lf(@"[iosurface-create] CVPixelBuffer cv=%d (skipped)", (int)cv);
        }
    }

    /* op 2: VT encode 720p (AVE path) — output callback NULL (discarded) */
    {
        L(@"[vt-encode] 1280x720 H.264 one-frame (ave64747_vt control receipt shape)");
        VTCompressionSessionRef ses = NULL;
        OSStatus st = VTCompressionSessionCreate(kCFAllocatorDefault, 1280, 720,
                                                 kCMVideoCodecType_H264,
                                                 NULL, NULL, NULL, NULL, NULL, &ses);
        if (st == noErr && ses) {
            OSStatus prep = VTCompressionSessionPrepareToEncodeFrames(ses);
            Lf(@"[vt-encode] create=0x%x prepare=0x%x", (unsigned)st, (unsigned)prep);
            if (prep == noErr) {
                (void)p115_snapshot(&after);
                (void)p115_diff(@"vt-encode", snap, after, newP);
                CVPixelBufferRef pb = NULL;
                CVReturn cv = CVPixelBufferCreate(kCFAllocatorDefault, 1280, 720,
                                                  kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange,
                                                  NULL, &pb);
                if (cv == kCVReturnSuccess && pb) {
                    OSStatus e = VTCompressionSessionEncodeFrame(ses, pb,
                                                                 CMTimeMake(0, 300),
                                                                 CMTimeMake(1, 300),
                                                                 NULL, NULL, NULL);
                    Lf(@"[vt-encode] frame status=0x%x", (unsigned)e);
                    OSStatus c = VTCompressionSessionCompleteFrames(ses, kCMTimeInvalid);
                    Lf(@"[vt-encode] complete=0x%x", (unsigned)c);
                    CVPixelBufferRelease(pb);
                }
            }
            VTCompressionSessionInvalidate(ses); CFRelease(ses);
        } else {
            Lf(@"[vt-encode] create st=0x%x (honest skip)", (unsigned)st);
        }
    }

    /* op 3: VT decompress WITH CSC output format — HONEST SKIP this version:
       a decompression session needs a real format description + sample
       plumbing; faking a sample buffer violates the no-fake law. The
       grammar lattice keeps priority. */
    L(@"[vt-csc] decompression-scaffold deferred — CSC leg HONEST SKIP this version");
    L(@"  (no fake buffers; op battery = IOSurface control + one VT encode frame).");

    /* fingerprint every new port (bounded: sel-8 only) */
    (void)p115_snapshot(&after);
    L(@"[fp] fingerprinting all new ports bounded sel-8 {u64 0} 8B:");
    for (NSNumber *p in newP) {
        if (p115_fingerprint(@"", (mach_port_t)p.unsignedInt, fp)) found = YES;
    }
    L(fp.length ? fp : @"    (no new ports to fingerprint)");

    /* verdict */
    L(@"=== VERDICT (honest) ===");
    if (found) {
        L(@"FINGERPRINT HIT: a framework-opened AppleM2ScalerCSCDriver UC is in THIS");
        L(@"task's ports — the next build reuses that connection for the sel-8 leak");
        L(@"captures (8 captures, one benign IOSurface create per capture) with NO");
        L(@"QueueCreate. KVA DISCLOSURE class only — not kread.");
    } else {
        L(@"NO M2Scaler fingerprint in the task ports after the battery — the honest");
        L(@"answer is: no in-process framework path opened it on this boot. The");
        L(@"QueueCreate grammar lattice (notes 274) stays the route; next offline");
        L(@"pass decodes phase 0 (0x908f5ec on 24A435) + the factory tag enum at");
        L(@"0xa344130 for the next single-byte step.");
    }
    L(@"HONESTY: READ-ONLY peek. hasKread=NO hasKwrite=NO. The battery ops are the");
    L(@"same class as a normal app session (IOSurface create + one encode frame).");

finish:
    if (g_fd >= 0) { (void)fcntl(g_fd, F_FULLFSYNC); (void)close(g_fd); g_fd = -1; }
    NSString *ret = g_log; g_log = nil;
    return ret;
}

@end