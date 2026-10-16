//
//  P100AutoLearn.h
//  Lum1na-Debug
//
//  READ-ONLY device/kernel learner. Runs on ANY device (LAB_DEBUG_APP gate
//  off): deep IDENT sweep, kern.version chip-tag parse, ABI fingerprint,
//  IOKit door census (opens only, no selectors), IOSurface create smoke,
//  table-nearest verdict, LEARN PACKET + JSON registry line.
//

#import <Foundation/Foundation.h>

@interface P100AutoLearn : NSObject
+ (NSString *)tap; // returns the log body
@end