//
//  P082AneKernelSid.h
//
//  P082 — two follow-ups to p081's GLOBAL-fetch confirmation:
//
//  1. PHASE K (kernel-sid fetch map): p081 run had first sid 177 — ids
//     1..176 were consumed before our first create (kernel/IOMFB/boot
//     surfaces). Feed x_126 = each of 1..24. no-abort => the ANE fetch
//     resolves KERNEL-OWNED surface ids => the forged OUTPUT-record-sid
//     hop (102 Chain 2) has kernel targets. nullptr => those ids dead.
//     PANIC POSSIBLE (kernel surface mapped into ANE DART).
//
//  2. PHASE L (staging lookup): IOSurfaceLookup on post-predict gap ids
//     (p081 Phase S: espresso staging churn, first 700-707). Lookup hit
//     => the staging surface is visible in OUR registry => content
//     injection into espresso staging is testable next. Lookup miss =>
//     IOSurface API is per-task while the ANE fetch is global (even
//     stronger evidence the ANE path bypasses the normal registry).
//     Read-only peek at hit surfaces — no writes to anything foreign.
//

#import <Foundation/Foundation.h>

@interface P082AneKernelSid : NSObject
+ (NSString *)tap;
@end