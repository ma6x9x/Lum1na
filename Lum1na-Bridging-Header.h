#ifndef Lum1na_Bridging_Header_h
#define Lum1na_Bridging_Header_h

// System headers first
#import <Foundation/Foundation.h>
#import <IOKit/IOKitLib.h>

// Runtime offset system (defines LabOffTab struct)
#import "LabRuntimeOffsets.h"

// Device detection
#import "LabDeviceProfile.h"

// Device-specific offsets
#import "A14_23F77_LabOffsets.h"
#import "A12X_23G71_LabOffsets.h"

// Exploit primitives
#import "CVE_2026_65343_AKS.h"
#import "APFS84523.h"
#import "P005JIT.h"

// Expose C functions to Swift
extern const LabOffTab* LabOff(void);
extern uint64_t LabKernSlide(void);
extern void LabSetKernSlide(uint64_t slide);

#endif
