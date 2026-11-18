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

    /* ===== CONTRACT V6 (bridge hunt 2026-11-17) =====
       QueueCreate = sel 6, EXACT 0xFA8 bytes; word0 = 1000 EXACTLY
       (wrapper rejects >1000, engine rejects <1000); sids[1000] @+4
       (sid==0 or >= root+0xd8 count fails; ANY bad slot aborts with 2c2
       before engines); flags u32 @0xFA4, bit0=1 MANDATORY; NO out struct.
       Discriminating variants (namespace-vs-ownership question):
         V1 word0=1000, 1000 DISTINCT live sids (p114's exact send)
         V2 word0=1000, ONE known-good sid in ALL 1000 slots
         V3 word0=1000, all-zero slots (expect 2c2 = resolve reached)
       Then sel-8 v6 read: {u64 userVA}, 8 B in, NO out; the kernel writes
       the activity dump INTO our buffer; census with kernel-range scan. */
    const uint32_t V6_SIZE = 0xFA8;
    int qc_ok = 0;
    for (int variant = 1; variant <= 3 && !qc_ok; variant++) {
        memset(in, 0, 0x1000);
        ((uint32_t *)in)[0] = 0x3E8;                      /* word0 = 1000 EXACT */
        for (uint32_t i = 0; i < 1000; i++) {
            uint32_t sid = 0;
            if (variant == 1) sid = ids[i % 8];           /* distinct (repeats after 8: logged) */
            if (variant == 2) sid = ids[0];               /* one good sid everywhere */
            if (variant == 3) sid = 0;                    /* all-zero (expect 2c2) */
            ((uint32_t *)(in + 4))[i] = sid;
        }
        ((uint32_t *)(in + 0xFA4))[0] = 1;                /* flags bit0 = 1 mandatory */
        kr = method(conn, 6, in, V6_SIZE, NULL, NULL);
        int created = (kr == KERN_SUCCESS);
        if (created) qc_ok = 1;
        Lf(@"[V%d qcreate] sel=6 bytes=0x%04x word0=0x3e8 kr=0x%x (%s)",
           variant, V6_SIZE, kr,
           created ? "QUEUE CREATED" :
           (kr == 0xe00002c2 ? "sid resolve rejected (pre-engine)" :
            kr == 0xe00002e2 ? "enablement gate" : "other"));
    }

    /* sel-8 v6 read: {u64 userVA}, 8 B, NO out; dump lands in OUR buffer */
    uint8_t *dump = calloc(1, 0x8000);
    uint64_t userVA = (uint64_t)(uintptr_t)dump;
    {
        uint64_t in8 = userVA;
        memset(dump, 0, 0x8000);
        kr = method(conn, 8, &in8, 8, NULL, NULL);
        uint32_t nzq = 0, krq = 0;
        for (uint32_t b = 0; b + 8 <= 0x8000; b += 8) {
            uint64_t v = ((uint64_t *)dump)[b / 8];
            if (v != 0) nzq++;
            if ((v >> 48) >= 0xffff) krq++;
        }
        Lf(@"[diag v6] sel=8 in={userVA=%016llx} kr=0x%x dump: nonzero_q=%u kernel_range_q=%u "
           "hdr=%016llx %016llx (0x7c-stride records @+0x20; rec+0x18 raw first-event)",
           (unsigned long long)userVA, kr, nzq, krq,
           nzq ? ((uint64_t *)dump)[0] : 0ull, nzq > 1 ? ((uint64_t *)dump)[1] : 0ull);
        if (nzq) Lf(@"[diag v6] KERNEL-DUMP LANDED in user memory — the serializer wrote %u qwords "
                    "(kernel->user write channel confirmed)", nzq);
    }

    /* queue-exists followup: sel-6 now returns the ~0x618 out struct */
    {
        uint8_t *qout = calloc(1, 0x800);
        memset(in, 0, 0x1000);
        ((uint32_t *)in)[0] = 0x3E8;
        for (uint32_t i = 0; i < 1000; i++) ((uint32_t *)(in + 4))[i] = ids[i % 8];
        ((uint32_t *)(in + 0xFA4))[0] = 1;
        uint32_t oN = 0x800;
        kr = method(conn, 6, in, V6_SIZE, qout, &oN);
        Lf(@"[qstate] sel=6 queue-exists out law: kr=0x%x outN=%u count=%u hub=%016llx",
           kr, oN, ((uint32_t *)qout)[0], oN >= 16 ? ((uint64_t *)qout)[1] : 0ull);
        free(qout);
    }

    free(dump);
    Lf(@"=== p172 done (one tap per force-quit) ===");
    free(in);
    if (g_fd >= 0) { fcntl(g_fd, F_FULLFSYNC); close(g_fd); g_fd = -1; }
    return o;
}

@end
