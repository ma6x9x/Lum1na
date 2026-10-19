//
//  P102TitanWriteTest.h
//  Titan write TEST. SKIPs MMIO unless T7 already mapped IORVBAR.
//  Does not copy titan.m GPU ROP / PTE plant.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface P102TitanWriteTest : NSObject
+ (NSString *)tap NS_SWIFT_NAME(tap());
@end

NS_ASSUME_NONNULL_END
