//
//  P161SEPKeyStoreTestUC.h
//  AppleSEPKeyStore test-UC type sweep (P161).
//
//  The production ctor registers AppleKeyStoreTestUserClient
//  (0x8d8838c / 0x8d883e0 on 23F77), but P104 only opens types 0+1.
//  This probe sweeps IOServiceOpen types 0..32 on the KeyStore services,
//  reads IOUserClientClass/IOClass/CFBundleIdentifier, and lists the
//  service's registry children after each open to look for a "Test"
//  user-client class. NO selectors are called; nothing is written.
//  PANIC-POSSIBLE: unknown UC types can assert; one tap per force-quit.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface P161SEPKeyStoreTestUC : NSObject
+ (NSString *)tap;
@end

NS_ASSUME_NONNULL_END
