//
//  P069DmaCommandMap.h
//  CVE-2026-43684 IOMD dmaCommandOperation MAP. One IOSurface map, no unbounded +0x34.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface P069DmaCommandMap : NSObject
+ (NSString *)tap NS_SWIFT_NAME(tap());
@end

NS_ASSUME_NONNULL_END
