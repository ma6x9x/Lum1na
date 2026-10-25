//
//  P098M2ScalerDiag.h
//  Lum1na
//
//  AppleM2ScalerCSCDriver iosaDiag IOSurface KVA leak probe.
//  Writeup: vschko/CaseStudies no-cve/m2scaler-leak-26.5.2 (possibly
//  CVE-2026-64709). Fixed in *OS 26.6 (23G71) -> LIVE on 23F77 (26.5.0).
//
//  Mechanics: IOSurfaceAcceleratorClient selector 8 (get_iosaDiag) copies
//  activity-log entries to user; every pointer field is sanitized with
//  vm_kernel_addrperm_external EXCEPT event_payload (@ entry offset 0x18),
//  which several log_activity call sites populate with an IOSurface KVA.
//
//  READ-ONLY. Presence check first (driver may be absent on some SKUs).
//  Output parsing is best-effort: raw dump + kernel-range qword scan, all
//  labeled candidates. Standalone tap.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface P098M2ScalerDiag : NSObject
+ (NSString *)tap;
@end

NS_ASSUME_NONNULL_END