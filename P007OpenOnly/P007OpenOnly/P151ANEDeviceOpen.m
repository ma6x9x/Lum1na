//
//  P151ANEDeviceOpen.m — ANE DirectPath DeviceOpen pid probe. p151 (v1).
//  Lum1na-Debug (P007 rig). iOS kernel research (Lum1na).
//
//  DeviceOpen is the first DirectPath selector. The handler copies the
//  0x68 input struct into the 0x68 output, then calls the driver's
//  ANE_AddClientForProgram; the observed 0xe00002f0 is the kernel's
//  "Cannot find task from the given pid" branch (p071, p109 note).
//  This probe fills the struct with a real pid at four offsets and reads
//  the kr matrix. It does NOT call ProgramSendRequest; nothing fires.
//
//  Offsets are candidates from the handler: it copies the whole 0x68 and
//  uses bytes at +0x28/+0x29 for flags and fields at +0x0c/+0x54 for the
//  client; +0x00 and +0x10 cover the remaining likely pid slots.
//

#import "P151ANEDeviceOpen.h"
#import "LabDeviceProfile.h"
#import "LabLocalTime.h"

#import <Foundation/Foundation.h>
#import <IOKit/IOKitLib.h>
#import <mach/mach.h>
#import <objc/message.h>

@implementation P151ANEDeviceOpen

+ (uint32_t)pidFromPasteboardOrDefault {
    id pb = ((id (*)(Class, SEL))objc_msgSend)(
        NSClassFromString(@"UIPasteboard"),
        NSSelectorFromString(@"generalPasteboard"));
    NSString *pbs = pb ? ((NSString *(*)(id, SEL))objc_msgSend)(
        pb, NSSelectorFromString(@"string")) : nil;
    if (pbs.length) {
        NSRange mk = [pbs rangeOfString:@"p151_pid="];
        if (mk.location != NSNotFound) {
            NSUInteger at = mk.location + mk.length;
            NSUInteger e = at;
            while (e < pbs.length) {
                unichar ch = [pbs characterAtIndex:e];
                if (ch < '0' || ch > '9') break;
                e++;
            }
            if (e > at) {
                long v = [[pbs substringWithRange:NSMakeRange(at, e - at)] intValue];
                if (v >= 1 && v <= 100000) return (uint32_t)v;
            }
        }
    }
    return (uint32_t)getpid();
}

+ (io_connect_t)openType1:(const char *)name kr:(kern_return_t *)outKr {
    *outKr = kIOReturnNoDevice;
    CFMutableDictionaryRef m = IOServiceMatching(name);
    if (!m) return 0;
    io_service_t svc = IOServiceGetMatchingService(kIOMainPortDefault, m);
    if (!svc) return 0;
    io_connect_t conn = 0;
    *outKr = IOServiceOpen(svc, mach_task_self(), 1, &conn);
    IOObjectRelease(svc);
    if (*outKr != KERN_SUCCESS) return 0;
    return conn;
}

+ (NSString *)tap {
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"=== p151 session %@ BUILD p151-ane-deviceopen-v3 ===\n",
        LabLocalMilitaryNow()];
    [out appendString:[LabDeviceProfile identBlock]];

    NSString *therm = @"?";
    switch (NSProcessInfo.processInfo.thermalState) {
        case NSProcessInfoThermalStateNominal: therm = @"nominal"; break;
        case NSProcessInfoThermalStateFair: therm = @"fair"; break;
        case NSProcessInfoThermalStateSerious: therm = @"serious"; break;
        case NSProcessInfoThermalStateCritical: therm = @"critical"; break;
        default: break;
    }
    [out appendFormat:@"  [thermal] %@ (ANE returns NoPower at serious/critical)\n", therm];

    uint32_t pid = [self pidFromPasteboardOrDefault];
    [out appendFormat:@"  [pid] using %u (pasteboard p151_pid= or getpid)\n", pid];

    NSArray<NSString *> *svcs = @[@"H11ANEIn", @"H1xANELoadBalancer"];
    NSArray<NSNumber *> *offs = @[@0x00, @0x0c, @0x10, @0x54];
    int opens = 0, zeros = 0;

    for (NSString *svcName in svcs) {
        kern_return_t okr = 0;
        io_connect_t conn = [self openType1:svcName.UTF8String kr:&okr];
        [out appendFormat:@"  [open] %@ type=1 kr=0x%x\n", svcName, okr];
        if (!conn) continue;
        opens++;

        for (NSNumber *on in offs) {
            uint8_t in[0x68];
            uint8_t o[0x68];
            memset(in, 0, sizeof(in));
            memset(o, 0, sizeof(o));
            uint32_t o2 = (uint32_t)pid;
            memcpy(in + on.unsignedIntValue, &o2, sizeof(o2));

            size_t outSz = sizeof(o);
            kern_return_t kr = IOConnectCallStructMethod(conn, 0, in, sizeof(in),
                                                         o, &outSz);
            if (kr == KERN_SUCCESS) zeros++;
            const char *why = "";
            if (kr == 0) why = "  <-- DEVICEOPEN OK";
            else if (kr == 0xe00002f0) why = "  (NotFound: pid not at this offset)";
            else if (kr == 0xe00002e3) why = "  (NoPower: ANE powered down — cool/reboot)";
            else if (kr == 0xe00002c2) why = "  (bad struct size)";
            else if (kr == 0xe00002e2) why = "  (NotPermitted: task entitlement)";
            [out appendFormat:@"    [sel0 pid@0x%02x] kr=0x%x%s outSz=%zu out[0..31]=",
                on.unsignedIntValue, kr, why, outSz];
            for (size_t i = 0; i < 32 && i < outSz; i++) {
                [out appendFormat:@"%02x", o[i]];
            }
            [out appendString:@"\n"];
        }
        {
            uint32_t sc = 0;
            kern_return_t ckr = IOConnectCallScalarMethod(conn, 1, NULL, 0, NULL, &sc);
            [out appendFormat:@"    [sel1 DeviceClose] kr=0x%x\n", ckr];
        }
        IOServiceClose(conn);
    }
    [out appendFormat:@"  [res] opens=%d deviceOpen_success=%d\n", opens, zeros];
    [out appendFormat:@"  [verdict] %@\n",
        zeros ? @"DeviceOpen accepted a pid — DirectPath client is live"
              : (opens ? @"opened but DeviceOpen refused every pid slot"
                       : @"no DirectPath open on this boot")];
    [out appendFormat:@"=== p151 end %@ ===\n", LabLocalMilitaryNow()];
    return out;
}

@end
