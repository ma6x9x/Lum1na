// brh: two-stage brotli decode harness (matches network delivery pattern)
// usage: brh first.bin second.bin [stage1_chunk_size]
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <brotli/decode.h>

static uint8_t *slurp(const char *p, size_t *n) {
    FILE *f = fopen(p, "rb"); if (!f) { perror(p); exit(2); }
    fseek(f, 0, SEEK_END); long sz = ftell(f); fseek(f, 0, SEEK_SET);
    uint8_t *b = malloc(sz ? sz : 1); *n = fread(b, 1, sz, f); fclose(f); return b;
}

int main(int argc, char **argv) {
    if (argc < 3) { fprintf(stderr, "usage: brh first second [chunk]\n"); return 2; }
    size_t n1, n2, chunk = argc > 3 ? strtoul(argv[3], 0, 0) : 65536;
    uint8_t *d1 = slurp(argv[1], &n1), *d2 = slurp(argv[2], &n2);
    BrotliDecoderState *s = BrotliDecoderCreateInstance(0, 0, 0);
    uint8_t out[65536];
    size_t off = 0; int ret = 0;
    while (off < n1) {
        size_t csize = n1 - off < chunk ? n1 - off : chunk;
        size_t avail_in = csize;
        const uint8_t *next_in = d1 + off;
        size_t avail_out = sizeof out; uint8_t *next_out = out;
        BrotliDecoderResult r = BrotliDecoderDecompressStream(s, &avail_in, &next_in, &avail_out, &next_out, 0);
        off += csize - avail_in;
        if (r == BROTLI_DECODER_RESULT_ERROR) { printf("ERR stage1 off=%zu code=%d\n", off, BrotliDecoderGetErrorCode(s)); ret = 1; goto done; }
        if (r == BROTLI_DECODER_RESULT_SUCCESS) { printf("SUCCESS (stage1) off=%zu\n", off); goto stage2; }
        if (avail_in != 0) { printf("STALL stage1 off=%zu r=%d avail_in=%zu\n", off, r, avail_in); break; }
    }
stage2:;
    {
        const uint8_t *next_in = d2; size_t avail_in = n2;
        size_t avail_out = sizeof out; uint8_t *next_out = out;
        BrotliDecoderResult r = BrotliDecoderDecompressStream(s, &avail_in, &next_in, &avail_out, &next_out, 0);
        printf("stage2: r=%d consumed=%zu/%zu produced=%zu err=%d\n", r, n2 - avail_in, n2, sizeof(out) - avail_out, BrotliDecoderGetErrorCode(s));
    }
done:
    BrotliDecoderDestroyInstance(s);
    return ret;
}
