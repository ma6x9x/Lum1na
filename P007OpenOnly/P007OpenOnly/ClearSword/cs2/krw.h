#ifndef cs2_krw_h
#define cs2_krw_h

#include "common.h"

#define CS2_CHAIN_WRITE_ZONE_MIN 0x20
#define CS2_EARLY_KRW_LENGTH 0x20  // 32

uint64_t cs2_early_kread64(uint64_t where);
void cs2_early_kwrite64(uint64_t where, uint64_t what);

int cs2_kreadbuf(uint64_t kaddr, void* output, size_t size);
int cs2_kwritebuf(uint64_t kaddr, const void* input, size_t size);


#endif /* cs2_krw_h */
