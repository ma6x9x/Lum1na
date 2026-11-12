#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/// Starts the embedded libssh server. Both `mobile` and `root` authenticate
/// with password `alpine`; each session gets the same in-process shell engine
/// rooted at the worse_query hub.
FOUNDATION_EXPORT BOOL WQSSHServerStart(NSString *_Nullable *_Nullable error);
FOUNDATION_EXPORT void WQSSHServerStop(void);
FOUNDATION_EXPORT BOOL WQSSHServerIsRunning(void);
FOUNDATION_EXPORT NSInteger WQSSHServerPort(void);
FOUNDATION_EXPORT NSString *WQSSHServerURL(void);

NS_ASSUME_NONNULL_END
