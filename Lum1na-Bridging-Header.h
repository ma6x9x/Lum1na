#ifndef BRIDGING_HEADER_H
#define BRIDGING_HEADER_H

#import <Foundation/Foundation.h>
#import <stdint.h>
#import "KASLRLeak.h"
#import "UPLLeak.h"

// Main KRW API
int cs_init(void);
int cs_run(uint64_t *kb, uint64_t *ks);
void cs_cleanup(void);

// Status
int krw_get_status(void);
const char* krw_get_phase(void);

// Combined primitives
int necp_trigger_uaf(void);
int ane_trigger_overflow(const char* model_path);
int iogpu_setup_uaf(void);

#endif
