//
//  P103M2ScalerCensus.h
//  M2ScalerCSCDriver UC census (notes 228/238/240).
//
//  Ghidra 23F77: the advisory IOSurfaceAccelerator family lives in this
//  kext (43655/43654/28897 kernel-memory READS, 28951 root gain,
//  28972 kernel-memory WRITE — all fixed in 26.5; 23F77 = fixed binary).
//  Method pool: user_transform_surface / user_set_filter /
//  user_get_histogram / user_get_iosaDiag / user_get_estimation /
//  user_set_client_property / user_get_capabilities / setCustomFilter /
//  findScalerDriver + IosaColorManagerMSR9/MSR23, HalMSR21,
//  SrcDestCfgControlMSR9/23, ScalingASEControlMSR20.
//  Boundary-assert family ("must called from user space!" /
//  "K2K call to user client!") = the call-context validation.
//  p038 (2026-10-19): AppleM2ScalerCSCDriver opens type 0 AND 1 on
//  P007OpenOnly (kr=0x0). p097/p098 leak windows = the iosaDiag sel 8
//  family; p101's sel=11 = the unnamed permissive mapper.
//  This tap: opens-only sel sweep 0..40 x benign shapes on types 0/1;
//  log every kr; flag non-standard verdicts (the boundary denials +
//  the permissive mapper). NO transforms. NO fires. hasKread unchanged.
//

#import <Foundation/Foundation.h>

@interface P103M2ScalerCensus : NSObject
+ (NSString *)tap;
@end