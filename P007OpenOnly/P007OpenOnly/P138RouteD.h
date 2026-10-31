//
//  P138RouteD.h — ROUTE D: the IOMD dmaref retain-wrap runner. p138.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface P138RouteD : NSObject
/// The corpus-complete route (iomd23.* rows, note 292/294), first run:
///   1. ARM: IOSurfaceCreate -> IOSurfaceCreateMachPort -> mach_vm_map
///      over the md port (the P069 DEVICE-PROVEN hop, kr=0 on the rig).
///   2. OP-CHANNEL CENSUS: the iomd23.op_protocol law says the dispatcher
///      (0xa515d60/23F77) takes w1 = op<<24|subsel, case=(w1>>24)-1,
///      default 0xE00002E7. Sweep the port as an IOConnect with op-encoded
///      sels (0x01000000/0x02000000/0x03000000/0x05000000 classes).
///   3. ORACLE: op-2 GET INFO copies [md+0x98] into out+0xc = the
///      APP-VISIBLE gate-state readback (the userland-readable kernel
///      counter!). Every op-2 row is kernel content we did not author.
///   4. THE WRAP LADDER: op-3 retain (unchecked ldaddh #1 @md+0x34, u16,
///      NO ceiling) x bounded ladder, watching the oracle — the 2^16 wrap
///      flips the count toward 0 = the named teardown/underflow receipt
///      ('_dmaReferences underflow') = a NAMED kernel receipt class.
/// PANIC-POSSIBLE (the wrap path panics BY DESIGN on this kext); one tap
/// per force-quit; no entitlement walls anywhere in the lane (the kext
/// decode: NO AMFI gate in any lane fn). hasKread stays gated.
+ (NSString *)tap;
@end

NS_ASSUME_NONNULL_END