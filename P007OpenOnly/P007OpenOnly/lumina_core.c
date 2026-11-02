/*
 * lumina_core.c — C translation of rust/lumina_core.
 * Keep this file and rust/lumina_core/src/lib.rs in lockstep.
 */

#include "lumina_core.h"

#include <math.h>
#include <string.h>

int lumina_mh_magic32_ok(uint32_t magic) {
    return magic == LUMINA_MH_MAGIC_64;
}

int lumina_mh_magic64_ok(uint64_t magic64) {
    return magic64 == LUMINA_MH_MAGIC_CPUTYPE;
}

int lumina_mh_typeinfo_ok(uint64_t typeinfo) {
    return typeinfo == LUMINA_MH_TYPEINFO_ARM64 ||
           typeinfo == LUMINA_MH_TYPEINFO_ARM64E ||
           typeinfo == LUMINA_MH_TYPEINFO_ARM64E19;
}

int lumina_slide_in_range(uint64_t slide) {
    return slide <= LUMINA_SLIDE_MAX;
}

int lumina_slide_live(uint64_t slide) {
    return slide != 0 && slide <= LUMINA_SLIDE_MAX;
}

uint64_t lumina_kbase_from_slide(uint64_t static_base, uint64_t slide) {
    if (!lumina_slide_in_range(slide)) return 0;
    return static_base + slide;
}

int lumina_kptr_zone(uint64_t v) {
    return v >= 0xFFFFFFE000000000ull && v < 0xFFFFFFF000000000ull;
}

int lumina_kptr_static(uint64_t v) {
    return v >= 0xFFFFFFF000000000ull;
}

int lumina_trustcache_parse(const void *blob, size_t len, lumina_tc_info *out) {
    if (out) {
        out->version = 0;
        out->length = 0;
        out->nentries = 0;
        out->ok = 0;
    }
    if (!blob || len < LUMINA_TC_HEADER_SIZE) return -1;

    const uint8_t *p = (const uint8_t *)blob;
    uint32_t version = 0, length = 0;
    memcpy(&version, p, 4);
    memcpy(&length, p + 20, 4);

    if (version != 1) return -2;
    if (length > LUMINA_TC_MAX_ENTRIES) return -3;

    size_t need = (size_t)LUMINA_TC_HEADER_SIZE +
                  (size_t)length * (size_t)LUMINA_TC_ENTRY_SIZE;
    if (need != len) return -4;

    if (out) {
        out->version = version;
        out->length = length;
        out->nentries = length;
        out->ok = 1;
    }
    return 0;
}

double lumina_bandit_reward(const char *outcome) {
    if (!outcome || !outcome[0]) return 0.25;
    if (!strcmp(outcome, "door") ||
        !strcmp(outcome, "claim-won") ||
        !strcmp(outcome, "ok") ||
        !strcmp(outcome, "conversion") ||
        !strcmp(outcome, "magic") ||
        !strcmp(outcome, "fault-with-far"))
        return 1.0;
    if (!strcmp(outcome, "maf") || !strcmp(outcome, "family-b"))
        return 0.0;
    if (!strcmp(outcome, "abort") ||
        !strcmp(outcome, "fires") ||
        !strcmp(outcome, "occupancy"))
        return 0.5;
    return 0.25;
}

double lumina_ucb1(double mean, double n_i, double N) {
    if (n_i <= 0.0) return 1e9;
    if (N < 1.0) N = 1.0;
    return mean + sqrt((2.0 * log(N)) / n_i);
}

uint32_t lumina_ane_req_in_for_arm(const char *arm) {
    if (!arm) return 0;
    if (!strcmp(arm, "oob192")) return 192u;
    if (!strcmp(arm, "inb191")) return 191u;
    if (!strcmp(arm, "small127")) return 127u;
    return 0;
}

const char *lumina_ane_model_for_arm(const char *arm) {
    if (!arm) return NULL;
    if (!strcmp(arm, "small127")) return "XVRC27_127inmin_1out";
    return NULL;
}

uint32_t lumina_ane_record_count(uint32_t req_in) {
    if (req_in < 2u || req_in > 4096u) return 0;
    return req_in + 1u;
}

uint32_t lumina_ane_oob_records(uint32_t req_in, uint32_t cap) {
    uint32_t rec = lumina_ane_record_count(req_in);
    if (rec == 0 || cap == 0) return 0;
    return rec > cap ? rec - cap : 0;
}

int lumina_ane_lock_oob192(int conversion_confirmed) {
    return conversion_confirmed ? 0 : 1;
}

const char *lumina_ak_step_name(int step) {
    switch (step) {
        case LUMINA_AK_HOLD:       return "HOLD";
        case LUMINA_AK_SELFTEST:   return "SELFTEST";
        case LUMINA_AK_ELEVATE:    return "ELEVATE";
        case LUMINA_AK_PMAP_CS:    return "PMAP_CS";
        case LUMINA_AK_TRUSTCACHE: return "TRUSTCACHE";
        case LUMINA_AK_INJECT:     return "INJECT";
        case LUMINA_AK_PKGMAN:     return "PKGMAN";
        case LUMINA_AK_RESPRING:   return "RESPRING";
        default:                   return "?";
    }
}

int lumina_ak_next_step(int has_kread, int magic_ok, int elevated,
                        int tc_loaded, int injected) {
    if (!has_kread || !magic_ok) return LUMINA_AK_HOLD;
    if (!elevated) return LUMINA_AK_ELEVATE;
    if (!tc_loaded) return LUMINA_AK_TRUSTCACHE;
    if (!injected) return LUMINA_AK_INJECT;
    return LUMINA_AK_PKGMAN;
}

size_t lumina_page_chunk(uint64_t addr, size_t size, size_t page_size) {
    if (size == 0 || page_size == 0) return 0;
    size_t off = (size_t)(addr & (uint64_t)(page_size - 1));
    size_t room = page_size - off;
    return size < room ? size : room;
}

const char *lumina_core_version(void) {
    return LUMINA_CORE_VERSION;
}

int lumina_core_selftest(void) {
    if (!lumina_mh_magic32_ok(0xfeedfacfu)) return 1;
    if (lumina_mh_magic32_ok(0xfeedfaceu)) return 2;
    if (!lumina_mh_magic64_ok(LUMINA_MH_MAGIC_CPUTYPE)) return 3;
    if (!lumina_mh_typeinfo_ok(LUMINA_MH_TYPEINFO_ARM64)) return 4;
    if (!lumina_mh_typeinfo_ok(LUMINA_MH_TYPEINFO_ARM64E)) return 5;
    if (!lumina_mh_typeinfo_ok(LUMINA_MH_TYPEINFO_ARM64E19)) return 6;
    if (lumina_mh_typeinfo_ok(0x1b00000000ull)) return 7;
    if (!lumina_slide_in_range(0x100000000ull)) return 8;
    if (lumina_slide_in_range(0x100000001ull)) return 9;
    if (lumina_slide_live(0)) return 10;
    if (!lumina_slide_live(0x1234000ull)) return 11;
    if (lumina_kbase_from_slide(0xFFFFFFF007004000ull, 0x1234000ull) !=
        0xFFFFFFF007004000ull + 0x1234000ull)
        return 12;
    if (!lumina_kptr_zone(0xFFFFFFE123400000ull)) return 13;
    if (!lumina_kptr_static(0xFFFFFFF007004000ull)) return 14;
    if (lumina_kptr_zone(0xFFFFFFF007004000ull)) return 15;

    uint8_t hdr[LUMINA_TC_HEADER_SIZE];
    memset(hdr, 0, sizeof hdr);
    hdr[0] = 1; /* version 1 little-endian */
    lumina_tc_info info;
    if (lumina_trustcache_parse(hdr, sizeof hdr, &info) != 0 || !info.ok)
        return 16;
    if (info.version != 1 || info.length != 0) return 17;
    if (lumina_trustcache_parse(hdr, sizeof hdr - 1, &info) == 0) return 18;

    if (lumina_bandit_reward("conversion") != 1.0) return 19;
    if (lumina_bandit_reward("magic") != 1.0) return 20;
    if (lumina_bandit_reward("occupancy") != 0.5) return 21;
    if (lumina_bandit_reward("maf") != 0.0) return 22;
    if (lumina_bandit_reward("hold") != 0.25) return 23;
    if (lumina_ucb1(0.5, 0.0, 10.0) < 1e8) return 24;
    if (lumina_ucb1(1.0, 4.0, 16.0) <= 1.0) return 25;

    if (lumina_ane_req_in_for_arm("oob192") != 192u) return 26;
    if (lumina_ane_req_in_for_arm("inb191") != 191u) return 27;
    if (lumina_ane_req_in_for_arm("small127") != 127u) return 28;
    if (strcmp(lumina_ane_model_for_arm("small127"), "XVRC27_127inmin_1out") != 0)
        return 29;
    if (lumina_ane_model_for_arm("oob192") != NULL) return 30;
    if (lumina_ane_record_count(192u) != 193u) return 40;
    if (lumina_ane_oob_records(192u, 192u) != 1u) return 41;
    if (lumina_ane_oob_records(191u, 192u) != 0u) return 42;
    if (lumina_ane_oob_records(192u, 255u) != 0u) return 43;
    if (lumina_ane_lock_oob192(0) != 1) return 44;
    if (lumina_ane_lock_oob192(1) != 0) return 45;

    if (strcmp(lumina_ak_step_name(LUMINA_AK_HOLD), "HOLD") != 0) return 31;
    if (lumina_ak_next_step(0, 0, 0, 0, 0) != LUMINA_AK_HOLD) return 32;
    if (lumina_ak_next_step(1, 1, 0, 0, 0) != LUMINA_AK_ELEVATE) return 33;
    if (lumina_ak_next_step(1, 1, 1, 0, 0) != LUMINA_AK_TRUSTCACHE) return 34;
    if (lumina_ak_next_step(1, 1, 1, 1, 0) != LUMINA_AK_INJECT) return 35;
    if (lumina_ak_next_step(1, 1, 1, 1, 1) != LUMINA_AK_PKGMAN) return 36;

    if (lumina_page_chunk(0x1000, 0x2000, 0x4000) != 0x2000) return 37;
    if (lumina_page_chunk(0x3000, 0x2000, 0x4000) != 0x1000) return 38;
    if (strcmp(lumina_core_version(), LUMINA_CORE_VERSION) != 0) return 39;
    return 0;
}
