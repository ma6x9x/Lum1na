//
//  P125KernIpcRace.h — the ipc_port request-table stale-index race
//  (CVE-2026-112507 port). p125.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface P125KernIpcRace : NSObject
/// 4 threads drive the allocate(RIGHT_RECEIVE) / double-notification /
/// interleaved-teardown ring on the task's mach namespace (Cinder27 kern.ipc
/// verbatim, bounded budget). The 27.2 kernel added ipr/table != NULL checks
/// over every request-table index consumer — pre-fix LIVE on 26.5/27.0.
/// PANIC-POSSIBLE (kernel UAF class); one tap per force-quit.
+ (NSString *)tap;
@end

NS_ASSUME_NONNULL_END