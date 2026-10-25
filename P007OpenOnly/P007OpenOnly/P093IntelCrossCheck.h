//
//  P093IntelCrossCheck.h
//  Prints the merged intel offset DB and cross-checks the LADDER rows
//  against the live LabOff() runtime table on THIS device. Read-only.
//

#import <Foundation/Foundation.h>

@interface P093IntelCrossCheck : NSObject
+ (NSString *)tap;
@end