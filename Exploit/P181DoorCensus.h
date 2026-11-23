//
//  P181DoorCensus.h — the complete on-device door census (read intel).
//  p181 v1. KEYS ONLY (entitlement values are never reported).
//

#import <Foundation/Foundation.h>

@interface P181DoorCensus : NSObject
+ (NSString *)tap;   /* returns the log body */
@end
