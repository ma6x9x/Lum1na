//
//  P133ReadFrame.h — the composed READ frame. p133.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface P133ReadFrame : NSObject
/// The read lane composed from the primitives the board already ships:
///   stage ADDR   [P010QueueLeak tap]     — the queue-object KVA fragments
///              (truncated low-32, slide-tracked; the +0x558/+0xa8 class).
///              This names WHERE the kernel object we can measure lives.
///   stage PULL   [P114SurfaceLeak tap]   — N bounded sel-8 serializer
///              captures. Record law: rec 0 = OUR input echoed CALIBRATION
///              row (provenance check — echo is NOT a read); later records
///              = kernel-REFILLED = the content pull (kernel data arriving
///              in a copyout we did not author).
///   stage CLASS  every capture is classified by the echo law: any row
///              equal to a value WE wrote (or its obvious echo) = label
///              calibration; anything else with a 0xffffff-band KVA shape
///              = a READ-CANDIDATE row, printed verbatim with its offsets.
///   stage GATE   honest KRW self-test. A read candidate is NOT hasKread
///              (no arbitrary address); it is the relative-read receipt
///              the corrupt-object layer needs. The full claim still
///              waits for kread32(kbase)==0xfeedfacf.
/// The composed claim this frame makes: kernel-chosen content reached a
/// userland copyout through the sel-8 serializer, with our-side echoes
/// separated out by the calibration law. NEON is deliberately NOT part
/// of this stage (write-side instrument; reused at the conversion step).
+ (NSString *)tap;

@end

NS_ASSUME_NONNULL_END