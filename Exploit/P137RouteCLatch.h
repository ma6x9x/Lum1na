//
//  P137RouteCLatch.h — ROUTE C: the REAL latched kick (held-blit UAF). p137.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface P137RouteCLatch : NSObject
/// The proper stale-GVA write test, built from the b1b2 internals:
///   1. bytesNoCopy buffer over our vm pages (0xAA) — the b1b2 law (its
///      noop deallocator = our pages SURVIVE the buffer release).
///   2. a fill command encoded 0xBB, endEncoding, COMMIT **HELD**.
///   3. release the Metal buffer (the commitUnmaps cite path = the
///      kernel-side mapping undone) while our vm pages stay live.
///   4. the 64x0x4000 spray (0xCC).
///   5. COMMIT the held command = the submission references the DELETED
///      resource record: the kernel either validates-and-refuses (2c2/
///      2be/0xe00002bd = the retention law, honest) or the GPU executes
///      the 0xBB fill THROUGH THE STALE RECORD — landing in our old
///      pages (the record survived the unmap) OR in the spray (the
///      reclaim won) = THE AIMABLE-WRITE STATE.
///   6. verdict: scan old pages AND spray for 0xBB; report every hit
///      with its page class. All outcomes = laws. PANIC-POSSIBLE;
///      one tap per force-quit; honest tail.
+ (NSString *)tap;
@end

NS_ASSUME_NONNULL_END