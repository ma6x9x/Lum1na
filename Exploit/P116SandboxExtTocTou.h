//
//  P116SandboxExtTocTou.h — the sandbox_extension NOFOLLOW TOCTOU port. p116.
//
#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface P116SandboxExtTocTou : NSObject
/// CVE-class: sandbox_extension_issue_file resolves symlinks at ISSUE but the
/// consume path never enforces SANDBOX_EXTENSION_NOFOLLOW — issue on a
/// symlink→in-container file, swap the symlink to point OUT of the container,
/// then consume = out-of-container file-read with NO race timing (deterministic;
/// live on 23F77/24A435/24B119 — Apple closed it as expected-behavior).
/// Port of speedyfriend433/sandbox_extension-TOCTOU-bug (MIT) with the rig's
/// log/fsync/one-tap laws. READ-ONLY: bounded target list, no writes outside
/// the container, no kernel claims. The receipt = out-of-container BYTES READ.
+ (NSString *)tap;
@end

NS_ASSUME_NONNULL_END