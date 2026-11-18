//
//  P172M2ContractSweep.m — M2ScalerCSC 24A435 queue-contract census (p172).
//  2026-11-17. The p170 receipts: QueueCreate sel=6 {0xfa8, word0=1000}
//  = 0xe00002c2 on the 17; sel-8 {u64} = 0xe00002bf. The v5 contract was
//  never attested on 24A435 — this census finds the live shape.
//

#import "P172M2ContractSweep.h"
#import "LabDeviceProfile.h"
#import "LabLocalTime.h"

#import <Foundation/Foundation.h>
#import <fcntl.h>
#import <unistd.h>
#import <mach/mach.h>
#import <dlfcn.h>
#import <string.h>

#define P172_BUILD @"p172-m2contract-v1"

typedef mach_port_t       io_obj_t;
typedef CFMutableDictionaryRef (*m_match_t)(const void *);
typedef io_obj_t          (*m_getsvc_t)(mach_port_t, CFDictionaryRef);
typedef kern_return_t     (*m_open_t)(io_obj_t, mach_port_t, uint32_t, mach_port_t *);
typedef kern_return_t     (*m_struct_t)(mach_port_t, uint32_t,
                                        const void *, uint32_t,       /* inputStruct   */
                                        void *, uint32_t *);          /* outputStruct  */
typedef CFTypeRef         (*m_cr_surf_t)(CFDictionaryRef);
typedef uint32_t          (*m_surf_id_t)(CFTypeRef);

static int g_fd = -1;
static void Lf(NSString *fmt, ...) NS_FORMAT_FUNCTION(1,2);
static void Lf(NSString *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    if (![s hasSuffix:@"\n"]) s = [s stringByAppendingString:@"\n"];
    if (g_fd >= 0) { const char *c = s.UTF8String; if (c) { write(g_fd, c, strlen(c)); fcntl(g_fd, F_FULLFSYNC); } }
}

@implementation P172M2ContractSweep

+ (NSString *)tap {
    NSMutableString *o = [NSMutableString string];
    NSString *docs = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    g_fd = open([docs stringByAppendingPathComponent:@"p172_m2_contract_log.txt"].fileSystemRepresentation,
                O_CREAT | O_WRONLY | O_TRUNC, 0644);
    NSString *head = [NSString stringWithFormat:
        @"=== p172 session %@ BUILD %@ ===\n%@\n"
        "24A435 M2Scaler queue-contract census (p170 blocker: 2c2/2bf).\n"
        "PANIC-POSSIBLE (real kernel contract attempts). ONE tap.\n",
        LabLocalMilitaryNow(), P172_BUILD, [LabDeviceProfile identBlock]];
    Lf(@"%@", head); [o appendString:head];

    void *h = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    void *d = h ? h : RTLD_DEFAULT;
    m_match_t matching    = (m_match_t)dlsym(d, "IOServiceMatching");
    m_getsvc_t getsvc     = (m_getsvc_t)dlsym(d, "IOServiceGetMatchingService");
    m_open_t open_        = (m_open_t)dlsym(d, "IOServiceOpen");
    m_struct_t method     = (m_struct_t)dlsym(d, "IOConnectCallStructMethod");   /* REAL 6-arg form */
    m_cr_surf_t crSurf    = (m_cr_surf_t)dlsym(RTLD_DEFAULT, "IOSurfaceCreate");
    m_surf_id_t surfId    = (m_surf_id_t)dlsym(RTLD_DEFAULT, "IOSurfaceGetID");
    if (!matching || !getsvc || !open_ || !method || !crSurf) {
        Lf(@"[-] dlsym incomplete — stop");
        if (g_fd >= 0) close(g_fd);
        return o;
    }

    CFMutableDictionaryRef md = matching("AppleM2ScalerCSCDriver");
    io_obj_t svc = getsvc(mach_task_self(), md);
    /* md deliberately never released (door-never-closes law) */
    mach_port_t conn = 0;
    kern_return_t kr = open_(svc, mach_task_self(), 0, &conn);
    Lf(@"[*] open kr=0x%x conn=%d", kr, (int)(uintptr_t)conn);
    if (kr != KERN_SUCCESS || !conn) { if (g_fd >= 0) close(g_fd); return o; }

    /* our live surfaces (the sids the contract wants are task-owned sids) */
    CFMutableDictionaryRef sp = CFDictionaryCreateMutable(
        kCFAllocatorDefault, 4, &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks);
    int32_t w = 0x40, hh = 0x40;
    CFNumberRef nw = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &w);
    CFNumberRef nh = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &hh);
    CFDictionarySetValue(sp, CFSTR("IOSurfaceWidth"), nw);
    CFDictionarySetValue(sp, CFSTR("IOSurfaceHeight"), nh);
    uint32_t ids[8] = {0};
    for (int i = 0; i < 8; i++) {
        CFTypeRef s = crSurf(sp);
        ids[i] = s ? surfId(s) : 0;
    }
    /* CFRelease NW-NH REMOVED per the P027/P0257 door-never-closes law (CFRelease of
   a kernel-touched CF tree trapped at CFRelease+84 on the 19:22:30 receipt) */
    Lf(@"[*] live sids: %08x %08x %08x %08x %08x %08x %08x %08x",
       ids[0], ids[1], ids[2], ids[3], ids[4], ids[5], ids[6], ids[7]);

    uint8_t *in = calloc(1, 0x1000);
    uint8_t *out = calloc(1, 0x8000);

    /* sweep struct sizes; fill the contract-ish prefix each time:
       {word0 = N or 0x3e8, then u32 sids, then flags at the tail} */
    const uint32_t sizes[] = {8, 16, 0x408, 0x410, 0xfa8};
    for (uint32_t si = 0; si < 5; si++) {
        uint32_t sz = sizes[si];
        memset(in, 0, 0x1000);
        uint32_t cnt = (sz >= 0x408) ? ((sz - 8) / 4) : 0;   /* sid slots */
        if (cnt > 8) {
            for (uint32_t i = 0; i < cnt && i < 1000; i++)
                ((uint32_t *)(in + 4))[i] = ids[i % 8];      /* repeats honestly logged */
            ((uint32_t *)in)[cnt + 1] = 1;                   /* tail flags */
        }
        uint32_t word0s[2] = {cnt == 0 ? 0u : cnt, 0x3e8u};
        for (uint32_t wi = 0; wi < 2; wi++) {
            ((uint32_t *)in)[0] = word0s[wi];
            for (uint32_t sel = 5; sel <= 6; sel++) {
                uint32_t scOutN = 2, stOutN = 0x8000; (void)stOutN;
                memset(out, 0, 0x8000);
                uint32_t oN = 0x8000;
                kr = method(conn, sel, in, sz, out, &oN);
                Lf(@"[qcreate] sel=%u size=0x%x word0=%u kr=0x%x outN=%u out0=%016llx out1=%016llx",
                   sel, sz, word0s[wi], kr, oN,
                   ((uint64_t *)out)[0], ((uint64_t *)out)[1]);
            }
        }
    }

    /* sel 7/8 readers: in-size + content variants */
    for (uint32_t sel = 7; sel <= 8; sel++) {
        const uint32_t rsz[] = {8, 16};
        for (uint32_t ri = 0; ri < 2; ri++) {
            memset(in, 0, 32);
            if (rsz[ri] == 8)  memcpy(in, &ids[0], 8);
            if (rsz[ri] == 16) { uint64_t pair[2] = {ids[0], 0x1000}; memcpy(in, pair, 16); }
            uint32_t oN = 0x8000;
            memset(out, 0, 0x8000);
            kr = method(conn, sel, in, rsz[ri], out, &oN);
            uint32_t nzq = 0, krq = 0;
            for (uint32_t b = 0; b + 8 <= oN && b < 0x2000; b += 8) {
                uint64_t v = ((uint64_t *)out)[b / 8];
                if (v != 0) nzq++;
                if ((v >> 48) >= 0xffff) krq++;
            }
            Lf(@"[reader] sel=%u in=%u B kr=0x%x outN=%u nonzero_q=%u kernel_range_q=%u out0=%016llx",
               sel, rsz[ri], kr, oN, nzq, krq, ((uint64_t *)out)[0]);
        }
    }

    Lf(@"=== p172 done (one tap per force-quit) ===");
    free(in); free(out);
    if (g_fd >= 0) { fcntl(g_fd, F_FULLFSYNC); close(g_fd); g_fd = -1; }
    return o;
}

@end
