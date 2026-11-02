//
//  P121IogpuCloseMerge.h — the iogpu_close × merge-machine REOPEN. p121.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface P121IogpuCloseMerge : NSObject
/// Reopen of the intercepted "iogpu_close" tap (note 283 #2) as a NEW
/// build: stage0 = the P040-ABI queue create(sel6)/destroy(sel7) calibrate
/// on THIS device; stage1 = the close-vs-merge race (destroy ping-pong ×
/// Metal blit commits on a REAL queue). PANIC-POSSIBLE; one tap.
+ (NSString *)tap;
@end

NS_ASSUME_NONNULL_END