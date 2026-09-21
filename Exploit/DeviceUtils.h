// DeviceUtils.h
#import <Foundation/Foundation.h>

typedef NS_ENUM(NSInteger, LuminaDeviceType) {
    LuminaDeviceTypeUnsupported = 0,
    LuminaDeviceTypeIPhone12,      // iPhone13,2
    LuminaDeviceTypeIPhone12Mini,  // iPhone13,1
    LuminaDeviceTypeIPhone12Pro,   // iPhone13,3
    LuminaDeviceTypeIPhone12ProMax,// iPhone13,4
    LuminaDeviceTypeIPadPro        // iPad8,x or iPad13,x
};

@interface DeviceUtils : NSObject
+ (LuminaDeviceType)currentDeviceType;
+ (BOOL)isSupportedDevice;  // Only iPhone 12 series & iPad Pro
+ (NSString *)deviceTypeString;
+ (NSString *)kernelVersion;
@end
