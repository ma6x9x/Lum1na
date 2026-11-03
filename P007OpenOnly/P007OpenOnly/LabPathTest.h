//
//  LabPathTest.h
//  Lum1na
//
//  One TAP = SKU scorecard + the READ-ONLY tests for this device.
//  Occupancy (P044), P110, P142, P143 stay catalog-solo.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface LabPathTest : NSObject
+ (NSString *)tap;
+ (BOOL)runWithLog:(void (^)(NSString *msg))logger;
+ (NSString *)scoreLog:(NSString *)log forPath:(NSString *)pathId;
@end

NS_ASSUME_NONNULL_END
