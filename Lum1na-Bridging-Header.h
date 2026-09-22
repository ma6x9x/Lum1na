#ifndef Lum1na_Bridging_Header_h
#define Lum1na_Bridging_Header_h

// System headers
#import <Foundation/Foundation.h>
#import <IOKit/IOKitLib.h>
#import <mach/mach.h>
#import <sys/sysctl.h>
#import <sys/types.h>

// Runtime offset system
#import "LabRuntimeOffsets.h"
#import "LabDeviceProfile.h"

// Device-specific offsets
#import "A14_23F77_LabOffsets.h"
#import "A12X_23G71_LabOffsets.h"

// Exploit primitives
#import "CVE_2026_65343_AKS.h"      // KASLR bypass
#import "CVE_2026_65330_PAC.h"      // PAC bypass #0x307a
#import "CVE_2026_65349_OOB.h"      // getattrlist OOB
#import "APFS84523.h"              // APFS persistence
#import "P005JIT.h"                // JIT fallback

// C function exports for Swift
extern const LabOffTab* LabOff(void);
extern uint64_t LabKernSlide(void);
extern void LabSetKernSlide(uint64_t slide);

#endif
