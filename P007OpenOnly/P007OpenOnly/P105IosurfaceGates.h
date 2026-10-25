//
//  P105IosurfaceGates.h
//  IOSurface walk (note 243) — framework-level gate census.
//
//  Decoded 23F77 (whole __text analyzed, 1405 fns):
//    - four entitlement booleans in IOSurfaceRootUserClient::initWithTask
//      (uc+0x122 iosurfaceinfo, +0x127 private∥developer gpu-restricted,
//      +0x123 protected-access, +0x126 = info ∨ protected = the grant bit).
//    - the two "Security:" prints are LOG-ONLY warn-once-per-UC
//      (create-global +0x120 / global-lookup +0x121) — no denial.
//    - per-UC surface limit 0x4000 → 0xe00002be.
//    - IOSurfaceMemoryPool access gate: "can't access pool id %llu
//      (wrong entitlements)" / "pool off limits (%llu)".
//    - protection-bits guard: "Unsupported protection bits set".
//  This tap: framework-level only (IOSurfaceCreate/Lookup/GetProperties).
//  Pool-id + protection-bits + global flag shapes; NO IOPageList shapes
//  (the 64749 lane stays closed). Bounded: ≤6 creates. hasKread unchanged.
//

#import <Foundation/Foundation.h>

@interface P105IosurfaceGates : NSObject
+ (NSString *)tap;
@end