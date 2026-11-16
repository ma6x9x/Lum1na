//
//  P169OsunserReach.h — OSUnserializeBinary app-bytes reach confirmation.
//  p169.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface P169OsunserReach : NSObject
/// Proof that the app's bytes reach the binary parser DIRECTLY:
/// IOSurfaceRoot createSurface (sel 0, structureInput VARIABLE) is called
/// with a raw 0xD3/0xD4-magic OSUnserializeBinary stream at request+0x30
/// (length +0x38) — bypassing the framework dict assembly.
///   S-A  well-formed minimal binary dict -> parse accepted = CHANNEL LIVE
///   S-B  malformed type-id stream -> ARM-GATED behind Documents/p169_arm.txt
///        (the PRE-26.7 body has NO type-id-table bound and NO null-guard on
///        the class walk at the create path; 0xfffffff00a4799c4 is the
///        pre-fix body on 23F77). PANIC-POSSIBLE.
/// Codes and the creation-result qword are logged; no kernel writes.
+ (NSString *)tap;
@end

NS_ASSUME_NONNULL_END
