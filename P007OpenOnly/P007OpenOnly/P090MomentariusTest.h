//
//  P090MomentariusTest.h
//  P007OpenOnly
//
//  momentarius census v1 — offsets-DB + libkrw instrument (post-KRW lane).
//  Consumes the LabKernelOffsets DB (transcribed from Dopamine 3.0.11,
//  MIT (c) Lars Froeder) to validate kernel struct offsets AT RUNTIME on
//  a device that already has working KRW (rig iPhone 11, Dopamine 3.0.10).
//
//  v1 census scope:
//    1. Resolve + print the full LabKernelOffsets table for the RUNNING device.
//    2. libkrw glue: dlopen provider -> krw_initializer -> kbase sanity
//       (kbase >= 0xfffff00000000000 && kread32(kbase) == 0xfeedfacf).
//    3. __DATA scan (A13 22G100 only): locate "Darwin Kernel Version"
//       string via kreadbuf -> confirms base->VA mapping.
//    4. allproc queue-head heuristic: self-referential list head whose
//       first element has pid == 0 (proc0), verified prev->next back-edge.
//    5. Honest prereq report: what the DB does NOT provide (itk_space,
//       bsd_info, IOSurface ranges/rangeCount, struct sizes, vm_map->pmap)
//       = v2 runtime-derivation tasks. momentarius PPL-bypass port = v2.
//
//  HONESTY: this probe READS kernel memory. It writes nothing. It does
//  not claim or seek KRW. A panic from dereferencing an unmapped kernel
//  VA during the heuristic scan is an accepted risk on the rig.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface P090MomentariusTest : NSObject
+ (NSString *)tap;
@end

NS_ASSUME_NONNULL_END