#ifndef cs2_utils_h
#define cs2_utils_h

#include "common.h"

void* cs2_reverse_memmem(const void* haystack, size_t haystack_len, const void* needle, size_t needle_len);
void cs2_hexdump(const void* data, size_t size);
char* cs2_machine(void);
void cs2_init_files(void);
void cs2_mem_clear_cache(void* ptr, uint64_t size);
int cs2_offsets_init(void);

#endif /* cs2_utils_h */
