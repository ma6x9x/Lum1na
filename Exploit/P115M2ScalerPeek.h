//
//  P115M2ScalerPeek.h — the framework-path peek for the M2Scaler lane. p115.
//
#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface P115M2ScalerPeek : NSObject
/// Peek lane: run a bounded CSC-battery (IOSurface create as control,
/// VT encode, VT decompress-with-CSC), diff the task's SEND ports after
/// each op, and fingerprint every new port for the AppleM2ScalerCSCDriver
/// signature (sel-8 {u64 0} 8B -> kr 0xe00002bf no-queue shape). If the
/// framework opened a real M2Scaler UC, this probe finds its connection —
/// no QueueCreate grammar needed. NO transforms, NO grooming, NO close.
+ (NSString *)tap;
@end

NS_ASSUME_NONNULL_END