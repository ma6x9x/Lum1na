/*
 * lumina_core.h — C ABI for parse-heavy / self-test helpers.
 *
 * Rust source of truth: rust/lumina_core (crate-type staticlib, #[no_mangle]).
 * This header is the ABI. Exploit/lumina_core.c is the IPA translation so
 * GitHub xcodebuild compiles without rustc. IOKit / detach / ACM stay ObjC.
 *
 * Credit: opa334 / Dopamine 3.0.12 — Mach-O identification, trustcache_file_v1
 * layout, enumerate_pages chunking, DOJailbreaker AfterKread order.
 * Hop-1 / kfd / Fugu14 kcall / physrw bodies are not here.
 */

#ifndef LUMINA_CORE_H
#define LUMINA_CORE_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define LUMINA_CORE_VERSION        "lumina-core-v2"
#define LUMINA_MH_MAGIC_64         0xfeedfacfu
#define LUMINA_MH_MAGIC_CPUTYPE    0x100000cfeedfacfull
#define LUMINA_MH_TYPEINFO_ARM64   0x0000000200000000ull
#define LUMINA_MH_TYPEINFO_ARM64E  0x0000000c00000002ull
#define LUMINA_MH_TYPEINFO_ARM64E19 0x0000000cc0000002ull
#define LUMINA_PAGE_SIZE           0x4000u
#define LUMINA_TC_HASH_LEN         20u
#define LUMINA_TC_ENTRY_SIZE       22u
#define LUMINA_TC_HEADER_SIZE      24u
#define LUMINA_TC_MAX_ENTRIES      4096u
#define LUMINA_SLIDE_MAX           0x100000000ull

/* ---- Mach-O / commitSlide bar ---- */

int      lumina_mh_magic32_ok(uint32_t magic);
int      lumina_mh_magic64_ok(uint64_t magic64);
int      lumina_mh_typeinfo_ok(uint64_t typeinfo);
int      lumina_slide_in_range(uint64_t slide);
int      lumina_slide_live(uint64_t slide);
uint64_t lumina_kbase_from_slide(uint64_t static_base, uint64_t slide);
int      lumina_kptr_zone(uint64_t v);
int      lumina_kptr_static(uint64_t v);

/* ---- Trustcache v1 (Dopamine trustcache_structs.h) ---- */

typedef struct {
    uint32_t version;
    uint32_t length;
    uint32_t nentries;
    int      ok;
} lumina_tc_info;

int lumina_trustcache_parse(const void *blob, size_t len, lumina_tc_info *out);

/* ---- Bandit (UCB1 Auer 2002 + LabBandit reward law) ---- */

double lumina_bandit_reward(const char *outcome);
double lumina_ucb1(double mean, double n_i, double N);

/* ---- ANE SKU arm → REQ_IN / model (LabLearn) ---- */

uint32_t    lumina_ane_req_in_for_arm(const char *arm);
const char *lumina_ane_model_for_arm(const char *arm);
/* Table records = REQ_IN + 1 output. Spill is records-cap, not REQ_IN-cap. */
uint32_t    lumina_ane_record_count(uint32_t req_in);
uint32_t    lumina_ane_oob_records(uint32_t req_in, uint32_t cap);
/* Hunt 23F77 conversion TAP stays N=192 until conversion is confirmed. */
int         lumina_ane_lock_oob192(int conversion_confirmed);

/* ---- AfterKread pipeline (DOJailbreaker order, HOLD until magic) ---- */

enum lumina_ak_step {
    LUMINA_AK_HOLD = 0,
    LUMINA_AK_SELFTEST,
    LUMINA_AK_ELEVATE,
    LUMINA_AK_PMAP_CS,
    LUMINA_AK_TRUSTCACHE,
    LUMINA_AK_INJECT,
    LUMINA_AK_PKGMAN,
    LUMINA_AK_RESPRING
};

const char *lumina_ak_step_name(int step);
int         lumina_ak_next_step(int has_kread, int magic_ok, int elevated,
                                int tc_loaded, int injected);

/* Dopamine enumerate_pages: first chunk stays inside one page. */
size_t lumina_page_chunk(uint64_t addr, size_t size, size_t page_size);

const char *lumina_core_version(void);
/* 0 = all built-in vectors pass. Safe on-device; no IOKit. */
int         lumina_core_selftest(void);

#ifdef __cplusplus
}
#endif

#endif /* LUMINA_CORE_H */
