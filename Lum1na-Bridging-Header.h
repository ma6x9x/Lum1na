#ifndef Lum1na_Bridging_Header_h
#define Lum1na_Bridging_Header_h

// ANE C API (from ANE.m)
int cs_init(void);
int cs_run(uint64_t *kb, uint64_t *ks);
void cs_cleanup(void);

// Add other C APIs here as they become available
// int kaslr_leak(uint64_t *slide);
// int upl_trigger(void);

#endif /* Lum1na_Bridging_Header_h */
