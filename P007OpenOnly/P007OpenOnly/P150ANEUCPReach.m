//
//  P150ANEUCPReach.m — ANE user-client reachability probe. p150.
//  Lum1na-Debug (P007 rig). iOS kernel research (Lum1na).
//
//  2026-11-07 Ghidra 24A435 (AppleH11ANEInterface):
//    doProgramCreate FUN_fffffe0008ca9344 -> FUN_8ca9860 ->
//    FUN_8c103d0 (programLoadFromMachoFile) -> FUN_8c3ca64 ->
//    FUN_8d51434 (DataVault trust: AUTH_APFS or path prefix
//    /private/var/mobile/Library/Caches/com.apple.aned/, .hwx/.bin suffix).
//    The explicit create gate FUN_fffffe0008d51dd4 is a STUB
//    (ldr x19,[x0,#0x20]; cbz; retain; release; mov w0,#1; retab) and its
//    call-site branch is dead. Only the UC open remains:
//    FUN_fffffe0008ca7974 caches com.apple.ane.iokit-user-access at
//    uc+0x10 and com.apple.ane.allow-dataChaining-access at uc+0x11.
//
//  ProgramCreate contract (for p151 if this opens): client user VAs are
//  mapped with fixed sizes — request 0xd88 (programSize +8, pid +0x180,
//  path[0x400] +0x984, flag +0xd85), argsOutput 0xe8 (+0xd8 ptr, +0xe0
//  size). Kernel writes its mapping VA into argsOutput+0xd8 and cascades
//  +0x18..+0x98, scrubbing only on success (leak on failure); the
//  consumer memcpy re-reads +0xd8 at copy time (double fetch).
//
//  p150 only matches services and opens them. No kernel method runs.
//

#import "P150ANEUCPReach.h"
#import "LabDeviceProfile.h"
#import "LabLocalTime.h"

#import <Foundation/Foundation.h>
#import <IOKit/IOKitLib.h>
#import <mach/mach.h>

@implementation P150ANEUCPReach

+ (NSString *)tap {
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"=== p150 session %@ BUILD p150-aneucreach-v1 ===\n",
        LabLocalMilitaryNow()];
    [out appendString:[LabDeviceProfile identBlock]];

    NSArray<NSString *> *names = @[
        @"AppleH11ANEInterface", @"H11ANEIn", @"AppleH11ANEIn",
        @"H1xANELoadBalancer",
        @"H11ANEInUserClient", @"AppleH11ANEInterfaceUserClient",
        @"ANEDevice", @"AppleNeuralEngineDevice", @"ANEUserClient",
        @"AppleNeuralEngineUserClient"
    ];
    int found = 0, opened = 0;
    for (NSString *name in names) {
        CFMutableDictionaryRef m = IOServiceMatching(name.UTF8String);
        if (!m) {
            [out appendFormat:@"  [match] %@ — IOServiceMatching nil\n", name];
            continue;
        }
        io_service_t svc = IOServiceGetMatchingService(kIOMainPortDefault, m);
        if (!svc) {
            [out appendFormat:@"  [match] %@ — no service\n", name];
            continue;
        }
        found++;
        io_name_t rn;
        io_name_t cn;
        memset(rn, 0, sizeof(rn));
        memset(cn, 0, sizeof(cn));
        IORegistryEntryGetName(svc, rn);
        IOObjectGetClass(svc, cn);
        [out appendFormat:@"  [svc] %@ -> reg=%s class=%s\n", name, rn, cn];
        for (uint32_t type = 0; type <= 5; type++) {
            io_connect_t conn = 0;
            kern_return_t kr = IOServiceOpen(svc, mach_task_self(), type, &conn);
            BOOL ok = (kr == KERN_SUCCESS && conn != 0);
            [out appendFormat:@"    open type=%u kr=0x%x%s\n", type, kr,
                ok ? (type == 1 || type == 4
                        ? "  <-- OPEN (direct evaluate client; no iokit entitlement)"
                        : "  <-- OPEN") : ""];
            if (ok) { opened++; IOServiceClose(conn); }
        }
        IOObjectRelease(svc);
    }
    [out appendFormat:@"[res] services=%d opened=%d — %@\n", found, opened,
        opened ? @"UC OPEN: ProgramCreate path is app-reachable in principle (p151 next)"
               : @"UC CLOSED to this install: ANE kernel paths are daemon-only"];

    NSArray<NSString *> *cls = @[@"_ANEClient", @"_ANEModel",
                                 @"_ANEIOSurfaceObject", @"_ANEDeviceController",
                                 @"_ANEDaemonConnection"];
    for (NSString *c in cls) {
        [out appendFormat:@"  [framework] %@ = %@\n", c,
            NSClassFromString(c) ? @"present" : @"absent"];
    }
    [out appendFormat:@"=== p150 end %@ ===\n", LabLocalMilitaryNow()];
    return out;
}

@end
