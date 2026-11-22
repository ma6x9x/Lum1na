//
//  P180NeonStackAlias.h
//  The P102-canary -> NEON bridge test: can a PurpleGfxMem surface page
//  ever become a thread's NEON save buffer, so a stale memory entry reads
//  kernel register state with NO write primitive?
//
//  PANIC-FREE (reads of our own mappings; no MMIO store, no kernel write).
//  Never sets hasKread.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface P180NeonStackAlias : NSObject
+ (NSString *)tap NS_SWIFT_NAME(tap());
@end

NS_ASSUME_NONNULL_END
