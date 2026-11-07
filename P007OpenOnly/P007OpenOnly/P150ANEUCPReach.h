//
//  P150ANEUCPReach.h — ANE user-client reachability probe. p150.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface P150ANEUCPReach : NSObject
/// Answers the one open reachability fact after the 24A435 ProgramCreate
/// decode: can a sandboxed P007 install open the ANE user client at all?
///
/// The explicit "Not permitted to create program" gate
/// FUN_fffffe0008d51dd4 is a stub (mov w0,#1; retab), so the create
/// branch is dead — the only remaining gate is the UC open
/// (FUN_fffffe0008ca7974 caches com.apple.ane.iokit-user-access at
/// uc+0x10 and com.apple.ane.allow-dataChaining-access at uc+0x11).
///
/// This probe only matches services and calls IOServiceOpen — it never
/// invokes a kernel method, so nothing fires. An OPEN receipt unlocks the
/// p151 ProgramCreate test (client-mapped 0xd88/0xe8 args buffers:
/// kernel-VA leak on failure paths + the +0xd8 double-fetch memcpy).
/// All opens 0xe00002bd/0xe00002e2 = the ANE kernel paths are daemon-only
/// and the weightbufs route must go through the model-hwx trust pivot.
///
/// HONESTY: an open receipt is not KRW; no kread here.
+ (NSString *)tap;
@end

NS_ASSUME_NONNULL_END
