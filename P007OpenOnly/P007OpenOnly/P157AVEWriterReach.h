//
//  P157AVEWriterReach.h
//  P007OpenOnly
//
//  AppleAVE2 signed-count writer REACH test (macOS 26A5421a PoC port).
//
//  Static 2026-11-08: the signed underwrite writer and the
//  _AVE_DLList_PushBack `str x1,[x8]` sink are present on iOS 17.3/18.6/26.5
//  and iPad 26.7; the iOS 27.2 writer adds a negative clamp. This probe only
//  walks the macOS selector chain (1/4/3/7) with zeroed buffers and a
//  nonnegative count. Start (5) is opt-in and PANIC-POSSIBLE.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface P157AVEWriterReach : NSObject
+ (NSString *)tap;
@end

NS_ASSUME_NONNULL_END
