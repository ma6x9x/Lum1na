//
//  P104SepksCensus.h
//  AppleSEPKeyStore walk (notes 241/242) — opens-only UC census.
//
//  Ghidra 23F77 (the 163-sel dispatch table at 0xfffffff008d9f868):
//    - handle-0 gate: sels {7,17,31} outside a user session
//      (uid∈[10,0x7fffffff)) → 0xfffffffa; other gate paths 0xffffffff /
//      0xfffffffd / 0xe00002c2.
//    - aks_has_entitlement (FUN_8d932e8) gates ~40 sels
//      (device.remote-session ×10, filevault, devicebackup, config.set ×4,
//      absinthe, memento, …); non-entitled callers expect 0xe00002c2-family.
//    - AppleKeyStoreTest + AppleKeyStoreTestUserClient meta-classes are
//      REGISTERED in the production ctor (0x88/0xd8 objects).
//  This tap: open AppleKeyStore (and try the Test classes), sweep sels
//  0..0xa2 with benign zero/short shapes, log every kr, flag the
//  expected gate verdicts. NO writes. NO packed-arg payloads.
//  Bounded discovery only. hasKread unchanged.
//

#import <Foundation/Foundation.h>

@interface P104SepksCensus : NSObject
+ (NSString *)tap;
@end