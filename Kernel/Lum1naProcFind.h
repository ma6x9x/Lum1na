//
//  Lum1naProcFind.h
//  Lum1na
//
//  Symbol-free self-proc locator for the post-KRW elevate step.
//
//  Dopamine finds proc via ksymbol(allproc), which XPF patchfinding supplies.
//  We do not vendor XPF; instead this locator goes the other way:
//    mach_port_kobject(task_self) -> task_t
//    scan task_t for a pointer whose target has pid == getpid() and a valid
//    proc_ro pointer -> proc_t
//  No allproc/kernproc symbol and no static VA is required. The scan is
//  0x1000 bytes of task struct; each candidate costs two kreads.
//

#import <Foundation/Foundation.h>
#import "Lum1naStructOffsets.h"
#include <stdint.h>

/// @param pid        getpid()
/// @param pidOff     LabProcOff()->proc_pid (0x60 on iOS 16+)
/// @param procRoOff  LabProcOff()->proc_proc_ro (0x18 on iOS 16+)
/// @param how        optional out: human-readable locator path
/// @return proc_t kernel VA, or 0. Never guesses: if no candidate validates,
///         returns 0 and the caller HOLDs.
uint64_t Lum1naFindSelfProc(uint32_t pid, uint32_t pidOff, uint32_t procRoOff,
                            NSString * _Nullable * _Nullable how);

/// ClearSword-lane self-proc: pcb -> inpcb.inp_socket -> socket.so_background_thread
/// -> thread.t_ro -> thread_ro.proc. Requires the 22G100 traversal offsets
/// (LabProcOff()->socket_so_background_thread etc.) and a live rw-socket pcb.
/// Returns 0 if the ladder is not pinned or any read fails validation.
uint64_t Lum1naFindSelfProcViaSocket(const LabProcOffTab *po, uint32_t pid,
                                     uint64_t rwSocketPcb,
                                     NSString * _Nullable * _Nullable how);
