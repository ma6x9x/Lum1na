// DeviceUtils.m
#import "DeviceUtils.h"
#include <sys/utsname.h>

@implementation DeviceUtils

+ (NSString *)machineName {
    struct utsname systemInfo;
    uname(&systemInfo);
    return [NSString stringWithCString:systemInfo.machine encoding:NSUTF8StringEncoding];
}

+ (LuminaDeviceType)currentDeviceType {
    NSString *machine = [self machineName];
    
    // iPhone 12 series (A14)
    if ([machine isEqualToString:@"iPhone13,2"]) return LuminaDeviceTypeIPhone12;
    if ([machine isEqualToString:@"iPhone13,1"]) return LuminaDeviceTypeIPhone12Mini;
    if ([machine isEqualToString:@"iPhone13,3"]) return LuminaDeviceTypeIPhone12Pro;
    if ([machine isEqualToString:@"iPhone13,4"]) return LuminaDeviceTypeIPhone12ProMax;
    
    // iPad Pro (A12X/A12Z/M1/M2)
    if ([machine hasPrefix:@"iPad8,"] ||   // 3rd gen
        [machine hasPrefix:@"iPad13,"]) {    // 4th/5th gen
        return LuminaDeviceTypeIPadPro;
    }
    
    return LuminaDeviceTypeUnsupported;
}

+ (BOOL)isSupportedDevice {
    return [self currentDeviceType] != LuminaDeviceTypeUnsupported;
}

+ (NSString *)deviceTypeString {
    switch ([self currentDeviceType]) {
        case LuminaDeviceTypeIPhone12: return @"iPhone 12";
        case LuminaDeviceTypeIPhone12Mini: return @"iPhone 12 Mini";
        case LuminaDeviceTypeIPhone12Pro: return @"iPhone 12 Pro";
        case LuminaDeviceTypeIPhone12ProMax: return @"iPhone 12 Pro Max";
        case LuminaDeviceTypeIPadPro: return @"iPad Pro";
        default: return [self machineName];
    }
}

+ (NSString *)kernelVersion {
    struct utsname u;
    uname(&u);
    return [NSString stringWithUTF8String:u.release];
}

@end
