//
//  Lum1naStructOffsets.m
//  Lum1na
//
//  Struct-offset rows. Same SKU keying as LabOff() (LabDeviceProfile).
//  Three rows run darwin >= 24.4, so the ladder values are shared; they are
//  spelled out per row so a future per-SKU drift is a one-line change, not
//  a refactor. The 12 mini row (A14_21D50, iOS 17.3.x = darwin 23.3.0) is
//  the one darwin-23 exception: BEFORE the 24.4.0 proc_ro +0x8 shift and
//  BEFORE p_original_ppid removal — see PROC_ROW_D23 below.
//

#import "Lum1naStructOffsets.h"
#import "../Exploit/LabRuntimeOffsets.h"
#include <string.h>

#define PROC_ROW(TAG, KERNPROC) { \
    .tag = TAG, \
    .proc_list_next = 0x0, \
    .proc_list_prev = 0x8, \
    .proc_proc_ro   = 0x18, \
    .proc_svuid     = 0x38, \
    .proc_svgid     = 0x3C, \
    .proc_pid       = 0x60, \
    .proc_fd        = 0xD0, \
    .proc_flag      = 0x454, /* info.c:390 — darwin >= 22.4.0 (iOS 16.4+); 0x25C is the pre-16.4/16.4-beta row */ \
    .pro_ro_csflags = 0x24, \
    .pro_ro_ucred   = 0x28, \
    .pro_ro_task_tokens = 0x48, \
    .ucred_uid      = 0x18, \
    .ucred_ruid     = 0x1C, \
    .ucred_svuid    = 0x20, \
    .ucred_groups   = 0x28, \
    .ucred_rgid     = 0x68, \
    .ucred_svgid    = 0x6C, \
    .ucred_label    = 0x78, \
    .kernproc       = KERNPROC, \
}

/* Darwin-23 row (iOS 17.3.x = darwin 23.3.0): 12 mini, Dopamine rootless.
   info.c darwin>=23.1 <23.4 branch — BEFORE the 24.4.0 proc_ro +0x8 shift
   and BEFORE p_original_ppid removal: svuid/svgid still 0x3C/0x40 (24.4
   moved them to 0x38/0x3C), proc_ro.csflags 0x1C and proc_ro.ucred 0x20
   with NO +0x8. ucred cr_posix layout unchanged across both branches. */
#define PROC_ROW_D23(TAG, KERNPROC) { \
    .tag = TAG, \
    .proc_list_next = 0x0, \
    .proc_list_prev = 0x8, \
    .proc_proc_ro   = 0x18, \
    .proc_svuid     = 0x3C, \
    .proc_svgid     = 0x40, \
    .proc_pid       = 0x60, \
    .proc_fd        = 0xD0, \
    .proc_flag      = 0x454, /* info.c:390 — 17.3.x = darwin 23.3, >= 22.4.0 branch */ \
    .pro_ro_csflags = 0x1C, \
    .pro_ro_ucred   = 0x20, \
    .pro_ro_task_tokens = 0x40, \
    .ucred_uid      = 0x18, \
    .ucred_ruid     = 0x1C, \
    .ucred_svuid    = 0x20, \
    .ucred_groups   = 0x28, \
    .ucred_rgid     = 0x68, \
    .ucred_svgid    = 0x6C, \
    .ucred_label    = 0x78, \
    .kernproc       = KERNPROC, \
}

static const LabProcOffTab gProcOffTabs[] = {
    /* A14 hunt (26.5, darwin 25.5): Dopamine 24.4+ ladder + P7 leak agree.
       26.5 REMOVED proc_ro.task_tokens (info.c:602) — audit fix must skip. */
#define PROC_ROW_D25(TAG, KERNPROC) { \
    .tag = TAG, \
    .proc_list_next = 0x0, \
    .proc_list_prev = 0x8, \
    .proc_proc_ro   = 0x18, \
    .proc_svuid     = 0x38, \
    .proc_svgid     = 0x3C, \
    .proc_pid       = 0x60, \
    .proc_fd        = 0xD0, \
    .proc_flag      = 0x454, /* 26.5 DB-confirmed (P090 23F77 census 2026-10-14) */ \
    .pro_ro_csflags = 0x24, \
    .pro_ro_ucred   = 0x28, \
    .pro_ro_task_tokens = 0, \
    .ucred_uid      = 0x18, \
    .ucred_ruid     = 0x1C, \
    .ucred_svuid    = 0x20, \
    .ucred_groups   = 0x28, \
    .ucred_rgid     = 0x68, \
    .ucred_svgid    = 0x6C, \
    .ucred_label    = 0x78, \
    .kernproc       = KERNPROC, \
}
    PROC_ROW_D25("A14_23F77", 0),
    /* A13 rig (18.6.2, darwin 24.6): same 24.4+ ladder. */
    PROC_ROW("A13_22G100", 0),
    /* A12X iPad twin (23G71): same ladder, untested on T8020. */
    PROC_ROW("A12X_23G71", 0),
    /* XR (iPhone11,*) 18.7.x = darwin 24.x: same 24.4+ ladder as the rig.
       kernproc 0 = underived (T8010 22Hxxx Ghidra pass queued). */
    PROC_ROW("XR_22H311", 0),
    /* A14 12 mini (17.3.x, Dopamine rootless): the single darwin-23 row.
       kernproc 0 = underived: Ghidra pass on the 21D50 kernelcache queued;
       once libkrw kread is live on device, the backward le_prev walk from
       kernproc doubles as confirmation. */
    PROC_ROW_D23("A14_21D50", 0),
};

const LabProcOffTab *LabProcOff(void) {
    const LabOffTab *off = LabOff();
    if (!off || !off->tag) return NULL;
    for (size_t i = 0; i < sizeof(gProcOffTabs) / sizeof(gProcOffTabs[0]); i++) {
        if (strcmp(gProcOffTabs[i].tag, off->tag) == 0) return &gProcOffTabs[i];
    }
    return NULL;
}
