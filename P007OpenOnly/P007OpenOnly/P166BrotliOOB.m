//
//  P166BrotliOOB.m — CVE-2026-111497 fingerprint (userspace).
//  Credit: MchinaMd57764/CVE-2026-111497-PoC (MIT); generator by the same
//  author (Vendor/external/brotli-111497).
//
//  Decodes Documents/brotli_first.bin in 64 KiB chunks through
//  libcompression's Brotli decoder, then feeds brotli_second.bin.
//  Verdict:
//    error -17 (BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH) => PATCHED
//      (27.2.1/24B156 backport present)
//    SUCCESS after stage2 => VULNERABLE window (the corrupted pos drives the
//      fast-path memmove16 inside the decoder; userspace heap only)
//    other error => inconclusive, recorded honestly
//  PANIC-FREE: no kernel interface touched by this probe.
//

#import "P166BrotliOOB.h"
#import "LabDeviceProfile.h"
#import "LabLocalTime.h"

#import <Foundation/Foundation.h>
#import <dlfcn.h>
#import <fcntl.h>
#import <unistd.h>
#import <string.h>
#import <stdlib.h>

typedef struct BrotliDecoderStateStruct BrotliDecoderState;
typedef enum {
    BR_ERROR = 0, BR_SUCCESS = 1, BR_NEEDS_MORE_INPUT = 2, BR_NEEDS_MORE_OUTPUT = 3
} BrResult;
typedef BrotliDecoderState *(*br_create_t)(void *, void *, void *);
typedef int (*br_stream_t)(BrotliDecoderState *, size_t *, const uint8_t **,
                           size_t *, uint8_t **, size_t *);
typedef int (*br_errcode_t)(BrotliDecoderState *);
typedef void (*br_destroy_t)(BrotliDecoderState *);

#define P166_BUILD @"p166-brotli111497-v1"
#define P166_ERR_BLOCK_SWITCH (-17)

@implementation P166BrotliOOB

+ (NSString *)tap {
    NSMutableString *o = [NSMutableString string];
    NSString *docs = [NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    [o appendFormat:@"=== p166 session %@ BUILD %@ ===\n", LabLocalMilitaryNow(), P166_BUILD];
    [o appendString:@"CVE-2026-111497 fingerprint (userspace only; PANIC-FREE).\n"];
    [o appendString:@"credit: MchinaMd57764/CVE-2026-111497-PoC (MIT)\n"];
    [o appendString:[LabDeviceProfile identBlock]];
    [o appendString:@"\n"];

    NSString *f1 = [docs stringByAppendingPathComponent:@"brotli_first.bin"];
    NSString *f2 = [docs stringByAppendingPathComponent:@"brotli_second.bin"];
    NSData *d1 = [NSData dataWithContentsOfFile:f1];
    NSData *d2 = [NSData dataWithContentsOfFile:f2];
    [o appendFormat:@"[files] first=%lu B second=%lu B (missing -> run tools/brotli_trigger.sh push)\n",
        (unsigned long)d1.length, (unsigned long)d2.length];
    if (!d1.length || !d2.length) {
        [o appendString:@"[verdict] SKIP — trigger pair not present in Documents\n"];
        return o;
    }

    void *lc = dlopen("/usr/lib/libcompression.dylib", RTLD_LAZY);
    if (!lc) lc = dlopen("/usr/lib/libcompression.1.dylib", RTLD_LAZY);
    br_create_t create = lc ? (br_create_t)dlsym(lc, "BrotliDecoderCreateInstance") : NULL;
    br_stream_t stream = lc ? (br_stream_t)dlsym(lc, "BrotliDecoderDecompressStream") : NULL;
    br_errcode_t errcode = lc ? (br_errcode_t)dlsym(lc, "BrotliDecoderGetErrorCode") : NULL;
    br_destroy_t destroy = lc ? (br_destroy_t)dlsym(lc, "BrotliDecoderDestroyInstance") : NULL;
    [o appendFormat:@"[libcompression] h=%p create=%p stream=%p errcode=%p destroy=%p\n",
        lc, (void*)create, (void*)stream, (void*)errcode, (void*)destroy];
    if (!create || !stream || !errcode || !destroy) {
        [o appendString:@"[verdict] SKIP — BrotliDecoder symbols not exported on this build\n"];
        return o;
    }

    BrotliDecoderState *st = create(NULL, NULL, NULL);
    if (!st) { [o appendString:@"[verdict] SKIP — decoder create failed\n"]; return o; }

    const uint8_t *s1 = d1.bytes;
    const uint8_t *s2 = d2.bytes;
    size_t off = 0, n1 = d1.length;
    const size_t chunk = 65536;
    uint8_t out[65536];
    int lastCode = 0;
    BrResult last = BR_ERROR;
    int loops = 0;
    BOOL stage1Done = NO;
    while (!stage1Done && loops < 100000) {
        loops++;
        size_t want = n1 - off < chunk ? n1 - off : chunk;
        size_t avail_in = want;
        const uint8_t *next_in = s1 + off;
        size_t avail_out = sizeof out;
        uint8_t *next_out = out;
        last = (BrResult)stream(st, &avail_in, &next_in, &avail_out, &next_out, NULL);
        off += want - avail_in;
        if (last == BR_ERROR) { lastCode = errcode(st); break; }
        if (last == BR_SUCCESS) { stage1Done = YES; break; }
        if (last == BR_NEEDS_MORE_OUTPUT) continue;   /* drain until it wants input */
        if (last == BR_NEEDS_MORE_INPUT) {
            if (off >= n1) { stage1Done = YES; break; } /* parked at chunk boundary */
            continue;
        }
    }
    [o appendFormat:@"[stage1] off=%zu/%zu loops=%d r=%d code=%d\n",
        off, n1, loops, (int)last, lastCode];

    if (last == BR_ERROR) {
        int patched = (lastCode == P166_ERR_BLOCK_SWITCH);
        [o appendFormat:@"[verdict] %@ — stage1 rejected with code %d (%@)\n",
            patched ? @"PATCHED" : @"INCONCLUSIVE-ERROR", lastCode,
            patched ? @"BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH backport present" : @"unexpected"];
        destroy(st);
        return o;
    }

    /* stage2 — the corrupted block-switch stream */
    size_t avail_in = d2.length;
    const uint8_t *next_in = s2;
    size_t avail_out = sizeof out;
    uint8_t *next_out = out;
    BrResult r2 = (BrResult)stream(st, &avail_in, &next_in, &avail_out, &next_out, NULL);
    int code2 = (r2 == BR_ERROR) ? errcode(st) : 0;
    if (r2 == BR_NEEDS_MORE_INPUT || r2 == BR_NEEDS_MORE_OUTPUT) {
        /* the bug's signature: the 127-byte stage2 is fully consumed and the
           decoder keeps going with corrupted position tracking */
        size_t avail_in2 = 0;
        const uint8_t *nin2 = s2 + d2.length;
        size_t aout2 = sizeof out; uint8_t *nout2 = out;
        r2 = (BrResult)stream(st, &avail_in2, &nin2, &aout2, &nout2, NULL);
        if (r2 == BR_ERROR) code2 = errcode(st);
    }
    [o appendFormat:@"[stage2] r=%d code=%d\n", (int)r2, code2];
    if (code2 == P166_ERR_BLOCK_SWITCH) {
        [o appendString:@"[verdict] PATCHED — stage2 rejected with FORMAT_BLOCK_SWITCH (-17)\n"];
    } else if (r2 == BR_SUCCESS || r2 == BR_NEEDS_MORE_INPUT || r2 == BR_NEEDS_MORE_OUTPUT) {
        [o appendString:@"[verdict] VULNERABLE window — stage2 accepted; corrupted position state persisted "
                          @"(userspace OOB inside the decoder; app-local only)\n"];
    } else {
        [o appendFormat:@"[verdict] INCONCLUSIVE — stage2 r=%d code=%d\n", (int)r2, code2];
    }
    destroy(st);
    [o appendFormat:@"=== p166 end %@ ===\n", LabLocalMilitaryNow()];
    return o;
}

@end
