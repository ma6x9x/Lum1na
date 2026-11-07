//
//  P152IOSurfaceLookupGate.h — IOSurface global-lookup / lock gate probe. p152.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface P152IOSurfaceLookupGate : NSObject
/// Device-verification probe for the one unresolved IOSurface fact.
///
/// Ghidra 24A435 (IOSurface kext): the UC has two 60-entry dispatch tables
/// selected by a per-client bit (UC+0x127) attributed to
/// com.apple.private/developer.gpu-restricted; in that decode selector 4
/// (global-ID lookup) returns 0xe00002e2 for a plain client. That conflicts
/// with our app's observed foreign lookups, so this probe measures it:
///   1. create our own surface, lookup by our own ID (baseline);
///   2. resolve IDs around ours through IOSurfaceLookup (global path);
///   3. for each resolved foreign surface, read alloc size + useCount and
///      take a READ-ONLY IOSurfaceLock (never a write, never a copy-out).
///
/// Receipt classes: own lookup OK = the UC is open to this install;
/// foreign hits + lock rc=0 = global lookup and ownerless lock are live on
/// this build (the same surfaces the ANE/AVE/AVD kernel clients can DMA);
/// all foreign lookups NULL = the global door is gated for this install.
/// This is a reachability map, not a leak: no surface contents are read.
+ (NSString *)tap;
@end

NS_ASSUME_NONNULL_END
