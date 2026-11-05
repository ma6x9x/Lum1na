#import <Foundation/Foundation.h>

// CS2Runner — CS2 ladder, 27.0-corrected on patched trains.
// 23B+/24A+: copy-confusion lane (success pwritev + vm_page_size iov), the
// class LightSword calib already proved (PARTIAL/WRONG). OG EFAULT (w==-1)
// stays on 43520-viable trains (A13 18.x). hop-1 cluster_*_contig KEEP CLOSED.
// Lab-bridged: durable log, time budget, LabOff() offsets, MH-magic self-test.
//
// Credit: opa334 / Dopamine ClearSword for the pcb/icmp6filt shape.
// 27.0 T8150 is not that body verbatim.
@interface CS2Runner : NSObject
+ (NSString *)runUpstream;
@end