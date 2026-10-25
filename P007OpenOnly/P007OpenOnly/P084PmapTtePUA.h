//
//  P084PmapTtePUA.h
//  Port of the public pmap-tte-remove PUAF recipe (Indegosblade, Kevin Estrada)
//  to P007 / iPhone13,2 A14 / iOS 26.5 23F77.
//
//  Recipe: 65,537 MAP_SHARED mach_vm_map calls of ONE 16KB physical page
//  (named memory entry over an IOSurface) wrap the uint16 pt_desc refcount.
//  Unmap all but 64 -> refcount hits 0 -> pmap_free_pt_delayed frees the
//  tracked page while 64 PTEs still map it -> userspace R/W into freed
//  kernel-adjacent physical memory through the survivors.
//
//  Status per public table: 26.5 GA (23F77) = MITIGATED-NOT-FIXED.
//  Device-proven by the author on A13/A17 Pro/A19 — A14 is UNTESTED publicly.
//
//  HONESTY: a PUAF primitive is NOT hasKread. commitSlide stays gated on
//  kread32(kbase)==MH_MAGIC_64. Panic possible — one tap per fresh boot.
//

#import <Foundation/Foundation.h>

@interface P084PmapTtePUA : NSObject
+ (NSString *)tap;
@end