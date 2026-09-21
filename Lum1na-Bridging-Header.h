#ifndef Lum1na_Bridging_Header_h
#define Lum1na_Bridging_Header_h

#import <Foundation/Foundation.h>
#include <stdint.h>

// ANE C API (from ANE.m) — declared here for Swift. .m may be excluded from the app target.
int cs_init(void);
int cs_run(uint64_t *kb, uint64_t *ks);
void cs_cleanup(void);

#endif /* Lum1na_Bridging_Header_h */
