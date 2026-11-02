//
//  P063AioKqueueLeak.h
//  P007OpenOnly
//
//  CVE-2026-84530 AIO kn_sdata heap disclose (HT149041 / iOS 26.7).
//  Live on 23F77. Heap leak is not kslide and not hasKread.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface P063AioKqueueLeak : NSObject
+ (NSString *)tap NS_SWIFT_NAME(tap());
@end

NS_ASSUME_NONNULL_END
