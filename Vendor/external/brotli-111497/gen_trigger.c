// brgen2: emit trigger pair files for one config
// usage: brgen2 wbits body d15 d19 d23 b7 out_prefix
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

typedef struct { uint8_t *data; size_t len, cap; uint32_t value; int used; } Bits;
static void bi(Bits *b) { b->cap = 1 << 20; b->data = malloc(b->cap); b->len = 0; b->value = 0; b->used = 0; }
static void bp(Bits *b, uint32_t v, int n) {
    for (int i = 0; i < n; i++) {
        b->value |= ((v >> i) & 1u) << b->used; b->used++;
        if (b->used == 8) { if (b->len >= b->cap) { b->cap *= 2; b->data = realloc(b->data, b->cap); } b->data[b->len++] = (uint8_t)b->value; b->value = 0; b->used = 0; }
    }
}
static void ba(Bits *b, const uint8_t *v, size_t n) { while (b->len + n > b->cap) { b->cap *= 2; b->data = realloc(b->data, b->cap); } memcpy(b->data + b->len, v, n); b->len += n; }
static size_t bf(Bits *b, uint8_t **out) { if (b->used) { if (b->len >= b->cap) { b->cap *= 2; b->data = realloc(b->data, b->cap); } b->data[b->len++] = (uint8_t)b->value; b->value = 0; b->used = 0; } *out = b->data; return b->len; }
static int bitlen(uint32_t n) { int c = 0; while (n) { c++; n >>= 1; } return c; }
static void ost(Bits *bits, int alphabet_size, int symbol) { bp(bits, 1, 2); bp(bits, 0, 2); bp(bits, (uint32_t)symbol, bitlen((uint32_t)alphabet_size - 1)); }
static void vu8(Bits *bits, uint32_t value) {
    if (value == 0) { bp(bits, 0, 1); return; }
    bp(bits, 1, 1);
    if (value == 1) { bp(bits, 0, 3); return; }
    int width = bitlen(value) - 1;
    bp(bits, (uint32_t)width, 3);
    bp(bits, value - (1u << width), width);
}

static size_t gen_stage1(uint8_t **out, int wbits, uint32_t bodyval, int cmdcount_log2, const uint8_t trailer[3]) {
    Bits bits; bi(&bits);
    if (wbits == 16) { bp(&bits, 0, 1); }
    else if (wbits >= 18 && wbits <= 24) { bp(&bits, 1, 1); bp(&bits, (uint32_t)(wbits - 17), 3); }
    else if (wbits >= 10 && wbits <= 15) { bp(&bits, 1, 1); bp(&bits, 0, 3); bp(&bits, (uint32_t)(wbits - 8), 3); }
    else if (wbits == 17) { bp(&bits, 1, 1); bp(&bits, 0, 3); bp(&bits, 0, 3); }
    else { fprintf(stderr, "bad wbits\n"); exit(2); }
    bp(&bits, 0, 1);
    bp(&bits, 2, 2);
    bp(&bits, 0xFFFFFF, 24);
    bp(&bits, 0, 1);
    vu8(&bits, 0);
    vu8(&bits, 1);
    ost(&bits, 4, 0);
    ost(&bits, 26, 25);
    bp(&bits, 0xFFFFFF, 24);
    vu8(&bits, 0);
    bp(&bits, 3, 6);
    bp(&bits, 0, 2);
    vu8(&bits, 0);
    vu8(&bits, 0);
    ost(&bits, 256, 0);
    ost(&bits, 704, 130);
    ost(&bits, 704, 130);
    ost(&bits, 400, 184);
    uint64_t command_count = 1ull << cmdcount_log2;
    uint64_t completed = 0;
    while (bits.used && completed < command_count) { bp(&bits, bodyval, 11); completed++; }
    Bits group; bi(&group);
    for (int i = 0; i < 8; i++) bp(&group, bodyval, 11);
    uint8_t *gbytes; size_t glen = bf(&group, &gbytes);
    uint64_t groups = (command_count - completed) / 8, tail = (command_count - completed) % 8;
    for (uint64_t i = 0; i < groups; i++) ba(&bits, gbytes, glen);
    for (uint64_t i = 0; i < tail; i++) bp(&bits, bodyval, 11);
    size_t tlen = bf(&bits, out);
    uint8_t *first = malloc(tlen + 3);
    memcpy(first, *out, tlen);
    memcpy(first + tlen, trailer, 3);
    *out = first;
    return tlen + 3;
}

static void gen_stage2(uint8_t out[127], uint32_t d15, uint32_t d19, uint32_t d23, uint8_t b7) {
    memset(out, 0, 127);
    out[7] = b7;
    memcpy(out + 15, &d15, 4);
    memcpy(out + 19, &d19, 4);
    memcpy(out + 23, &d23, 4);
}

int main(int argc, char **argv) {
    if (argc != 8) { fprintf(stderr, "usage: brgen2 wbits body d15 d19 d23 b7 out_prefix\n"); return 2; }
    int wbits = atoi(argv[1]);
    uint32_t body = (uint32_t)strtoul(argv[2], 0, 0);
    uint32_t d15 = (uint32_t)strtoul(argv[3], 0, 0);
    uint32_t d19 = (uint32_t)strtoul(argv[4], 0, 0);
    uint32_t d23 = (uint32_t)strtoul(argv[5], 0, 0);
    uint8_t b7 = (uint8_t)strtoul(argv[6], 0, 0);
    const char *prefix = argv[7];
    uint8_t trailer[3] = {0, 0, 0};
    uint8_t *in1; size_t s1 = gen_stage1(&in1, wbits, body, 24, trailer);
    uint8_t s2[127]; gen_stage2(s2, d15, d19, d23, b7);
    char path[512];
    snprintf(path, sizeof path, "%s_first.bin", prefix);
    FILE *f = fopen(path, "wb"); fwrite(in1, 1, s1, f); fclose(f);
    snprintf(path, sizeof path, "%s_second.bin", prefix);
    f = fopen(path, "wb"); fwrite(s2, 1, 127, f); fclose(f);
    printf("%s s1=%zu s2=127 wbits=%d body=%u d15=%08x d19=%08x d23=%08x b7=%d\n", prefix, s1, wbits, body, d15, d19, d23, b7);
    return 0;
}
