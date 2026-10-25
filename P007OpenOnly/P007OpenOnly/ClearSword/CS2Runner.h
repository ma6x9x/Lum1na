#import <Foundation/Foundation.h>

// CS2Runner — verbatim Dopamine 3.0.11 ClearSword core (ClearSword/cs2/),
// lab-bridged: durable log, time budget, LabOff() offsets ladder, MH-magic
// self-test. No NECP sockopt additions, no churn thread, full 22528-socket
// spray + 8x128MiB mlocked scan, upstream identification (executable_name +
// filter-default marker) and upstream iOS 17+ textPtr ladder.
//
// Credit: opa334 / Dopamine ClearSword. Lab deviations are marked "lab:" in
// the cs2 sources.
@interface CS2Runner : NSObject
+ (NSString *)runUpstream;
@end