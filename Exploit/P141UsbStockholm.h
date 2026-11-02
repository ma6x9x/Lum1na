//
//  P141UsbStockholm.h — the USB/Stockholm REACHABILITY ORACLE. p141.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface P141UsbStockholm : NSObject
/// In-app, SKU-free reachability oracle (the tonight pick):
///   lane 1 = the USB DEVICE-MODE family: IOServiceMatching
///     ("IOUSBDeviceInterface") + IOServiceOpen t0/t1 + bounded sel
///     census 0..15 (4 scalars out). The mini laws: service match PERMITTED
///     in-app; open = owner-held 2e2 consistently. This tap = the 23F77 row.
///   lane 2 = the Stockholm/hammerfest control UC (the nfc.disableentitlements
///     PEBL switch = the kext's OWN gate-void; the flag row is ABSENT on
///     21-D50, present on 23F77). Match "AppleStockholmControl" + open +
///     census; the 2e2/2c7 shape law records who holds it.
/// HONESTY: any kr row = reachability census ONLY — no kernel claim;
///   hasKread stays kread32-gated. One open per run per lane; a USB
///   wedge risk = accepted on the run device (reconnect possible);
///   the lane that opens runs the census then CLOSES.
+ (NSString *)tap;
@end

NS_ASSUME_NONNULL_END