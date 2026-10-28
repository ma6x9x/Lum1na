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
/* v1.4: the IOKit types (io_service_t/io_connect_t/IOReturn) are NOT in the
   SDK transitively on iOS — the macOS SDK resolves them transitively and
   gave the local clang check a FALSE PASS. Import IOKitLib.h like the p114
   sibling (the proven p098 shape). */
#import <IOKit/IOKitLib.h>
#import <CoreMedia/CoreMedia.h>
#import <CoreVideo/CoreVideo.h>
#import <VideoToolbox/VideoToolbox.h>
#import <stdint.h>
#import <stdio.h>
#import <string.h>

#define P115_BUILD @"p115-m2scaler-peek-v1.9-immediate"

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

/* ---- port snapshot (the PROVEN p001 shape: mach_port_type brute scan
   over 0x100..0x10000 into fixed arrays — mach_port_names + vm_deallocate
   was the compile-risk path; AVEVTSmoke's scan compiled and ran on device) */
enum { kP115Cap = 256 };
static void p115_snap(mach_port_name_t *names, int *n) {
    *n = 0;
    for (mach_port_name_t pn = 0x100; pn < 0x10000 && *n < kP115Cap; pn++) {
        mach_port_type_t pt = 0;
        if (mach_port_type(mach_task_self(), pn, &pt) != KERN_SUCCESS) continue;
        if (((pt >> 16) & 0x1) == 0) continue;   /* SEND */
        if (((pt >> 16) & 0x8))      continue;   /* DEAD */
        names[(*n)++] = pn;
    }
}

/* forward declarations (v1.2: scanNew calls fingerprint — declare before
   use; the missing forward decl was the third red Lum1na-Debug layer) */
static void p115_fingerprint(mach_port_t port, BOOL *found);

/* the p001 GUARD law, restored (v1.7): NEVER MIG-probe a new SEND port
   unless its port NUMBER appears in our own framework objects' memory —
   the 09:32 runs EXC_GUARD'd exactly as p001's comment predicted ("not in
   obj memory (skip — XPC risk)"). The objects stay ALIVE through the
   fingerprint phase (holding pb/session refs until after the scan). */
static void p115_scanNew(const char *tag, mach_port_name_t *before, int nB,
                         mach_port_name_t *after, int nA,
                         uintptr_t *objs, int nObjs,
                         int *nNew, BOOL *found) {
    Lf(@"[diff %s] scanning added ports", tag);
    for (int i = 0; i < nA; i++) {
        int old = 0;
        for (int j = 0; j < nB; j++) if (before[j] == after[i]) { old = 1; break; }
        if (old) continue;
        mach_port_type_t pt = 0;
        if (mach_port_type(mach_task_self(), after[i], &pt) != KERN_SUCCESS) continue;
        if (pt != 0x10000) continue;             /* SEND-only only */
        (*nNew)++;
        int inObj = 0;
        for (int oi = 0; oi < nObjs && !inObj; oi++) {
            if (!objs[oi]) continue;
            for (ptrdiff_t off = 0; off < 4096 && !inObj; off += 8) {
                uintptr_t val = *(uintptr_t *)(objs[oi] + off);
                if (val == (uintptr_t)after[i]) {
                    inObj = 1;
                    Lf(@"  +port %u pt=0x%x in obj[%d]+0x%tx", after[i], (unsigned)pt, oi, off);
                }
            }
        }
        if (!inObj) {
            Lf(@"  +port %u pt=0x%x NOT in obj mem (skip — the p001 XPC-risk law)", after[i], (unsigned)pt);
            continue;
        }
        p115_fingerprint(after[i], found);
    }
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
    return g_st != NULL;   /* v1.6: the PEEK flow uses ONLY IOConnectCallStruct
                              Method (g_st) — the p114 sibling's dlsym gate
                              required six symbols incl. kIOMainPortDefault,
                              which isn't always resolvable on 23F77-class
                              trains; the 09:24 run stopped honestly because
                              of that strictness. The peek never opens a
                              service, so only the fingerprint sym matters. */
}

/* fingerprint: M2Scaler's sel-8 no-queue shape = 2bf (out buffer sized).
   v1.9: PRINTS IMMEDIATELY (the 09:43 v1.6 crash ate every fp line because
   they were buffered in one string that only printed at the verdict — a
   mid-loop death loses the whole loop's results; fsync'd per line now). */
static void p115_fingerprint(mach_port_t port, BOOL *found) {
    if (!g_st) { Lf(@"    port %u: no callStruct", port); return; }
    uint64_t in8 = 0;
    static uint8_t out8[0x1000];
    memset(out8, 0, sizeof(out8));
    size_t olen = sizeof(out8);
    IOReturn kr8 = g_st((mach_port_t)port, 8, &in8, 8, out8, &olen);
    BOOL sig = (kr8 == 0xe00002bf);
    if (sig) *found = YES;
    Lf(@"    port %u sel8={0}8B kr=0x%08x outLen=%zu%@",
       (unsigned)port, (unsigned)kr8, olen,
       sig ? @"  <-- M2SCALER FINGERPRINT (2bf no-queue)" : @"");
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
        /* v1.5: the ARC law — no goto over retainable declarations; the
           single early exit inlines the finish block (the goto-forward-
           over-initialized-locals error was the SIXTH red layer, and the
           only non-cascade one left) */
        if (g_fd >= 0) { (void)fcntl(g_fd, F_FULLFSYNC); (void)close(g_fd); g_fd = -1; }
        NSString *ret = g_log; g_log = nil;
        return ret;
    }

    mach_port_name_t A[kP115Cap], B[kP115Cap], C[kP115Cap];
    int nA = 0, nB = 0, nC = 0;
    int nNew = 0;
    BOOL found = NO;
    CVPixelBufferRef pbLive = NULL;   /* kept alive until AFTER the scans */
    VTCompressionSessionRef sesLive = NULL;

    p115_snap(A, &nA);
    Lf(@"[baseline] SEND-only ports: %d", nA);

    /* op 1: IOSurface create (control) — pb held alive (the p001 guard's
       obj-memory cross-ref needs the refs through the fingerprint phase) */
    {
        CVReturn cv = CVPixelBufferCreate(kCFAllocatorDefault, 1280, 720,
                                          kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange,
                                          NULL, &pbLive);
        if (cv == kCVReturnSuccess && pbLive) {
            p115_snap(B, &nB);
            /* v1.8: NO __bridge on video-framework opaque structs — the iOS
               toolchain rejects __bridge for CVPixelBufferRef/VTCompressionSessionRef
               (plain struct pointers, not bridgeable CF types); the p001
               guard pattern used __bridge only on id<MTLDevice> objc objects.
               Plain (void *) casts are correct here and compile on both. */
            uintptr_t objs[2] = { (uintptr_t)(void *)pbLive, 0 };
            p115_scanNew("iosurface-create", A, nA, B, nB, objs, 1, &nNew, &found);
        } else {
            Lf(@"[iosurface-create] CVPixelBuffer cv=%d (skipped)", (int)cv);
        }
    }

    /* op 2: VT encode 720p (AVE path) — output callback NULL (discarded);
       the session is held alive through op 2's scan + encode + final fp */
    {
        L(@"[vt-encode] 1280x720 H.264 one-frame (ave64747_vt control receipt shape)");
        OSStatus st = VTCompressionSessionCreate(kCFAllocatorDefault, 1280, 720,
                                                 kCMVideoCodecType_H264,
                                                 NULL, NULL, NULL, NULL, NULL, &sesLive);
        if (st == noErr && sesLive) {
            OSStatus prep = VTCompressionSessionPrepareToEncodeFrames(sesLive);
            Lf(@"[vt-encode] create=0x%x prepare=0x%x", (unsigned)st, (unsigned)prep);
            if (prep == noErr) {
                p115_snap(C, &nC);
                uintptr_t objs2[3] = { (uintptr_t)(void *)sesLive,
                                       (uintptr_t)(void *)pbLive, 0 };
                p115_scanNew("vt-session", A, nA, C, nC, objs2, 2, &nNew, &found);
                CVPixelBufferRef pb = NULL;
                CVReturn cv = CVPixelBufferCreate(kCFAllocatorDefault, 1280, 720,
                                                  kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange,
                                                  NULL, &pb);
                if (cv == kCVReturnSuccess && pb) {
                    OSStatus e = VTCompressionSessionEncodeFrame(sesLive, pb,
                                                                 CMTimeMake(0, 300),
                                                                 CMTimeMake(1, 300),
                                                                 NULL, NULL, NULL);
                    Lf(@"[vt-encode] frame status=0x%x", (unsigned)e);
                    OSStatus c = VTCompressionSessionCompleteFrames(sesLive, kCMTimeInvalid);
                    Lf(@"[vt-encode] complete=0x%x", (unsigned)c);
                    CVPixelBufferRelease(pb);
                }
            }
            VTCompressionSessionInvalidate(sesLive); CFRelease(sesLive); sesLive = NULL;
        } else {
            Lf(@"[vt-encode] create st=0x%x (honest skip)", (unsigned)st);
        }
    }
    if (pbLive) CVPixelBufferRelease(pbLive);   /* the guard's objects released AFTER the scans */

    /* op 3: VT decompress WITH CSC output format — HONEST SKIP this version:
       a decompression session needs a real format description + sample
       plumbing; faking a sample buffer violates the no-fake law. The
       grammar lattice keeps priority. */
    L(@"[vt-csc] decompression-scaffold deferred — CSC leg HONEST SKIP this version");
    L(@"  (no fake buffers; op battery = IOSurface control + one VT session).");

    /* verdict */
    Lf(@"new SEND-only probed: %d", nNew);
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

    if (g_fd >= 0) { (void)fcntl(g_fd, F_FULLFSYNC); (void)close(g_fd); g_fd = -1; }
    NSString *ret = g_log; g_log = nil;
    return ret;
}

@end