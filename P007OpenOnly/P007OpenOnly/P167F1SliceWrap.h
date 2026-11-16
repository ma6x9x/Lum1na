//
//  P167F1SliceWrap.h — F1 compressed-plane BytesPerSlice 32-bit wrap
//  device-confirmation probe. p167.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface P167F1SliceWrap : NSObject
/// Ladder: control uncompressed -> compressed multi-slice shape hunt ->
/// unwrapped-overshoot (bounds must reject) -> wrap pair ((Data+Header)*Slice
/// wraps mod 2^32 while the true total is ~1 GiB). The only GPU-visible side
/// effect is IOSurfaceCreate itself; NO render, NO Metal. Read-back via
/// IOSurfaceGetAllocSize only.
/// PANIC-POSSIBLE (kernel parse/alloc on crafted plane shapes);
/// one tap per force-quit.
+ (NSString *)tap;
@end

NS_ASSUME_NONNULL_END
