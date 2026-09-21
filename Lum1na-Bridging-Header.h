#ifndef Lum1na_Bridging_Header_h
#define Lum1na_Bridging_Header_h

#import <Foundation/Foundation.h>
#include <stdint.h>

// Exploit primitives
#import "KASLRLeak.h"
#import "UPLLeak.h"
#import "CSKRW.h"
#import "ANE.h"

// ANE C API (from ANE.m)
int cs_init(void);
int cs_run(uint64_t *kb, uint64_t *ks);
void cs_cleanup(void);

#endif /* Lum1na_Bridging_Header_h */
