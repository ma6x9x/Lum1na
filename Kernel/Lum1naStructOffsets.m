//
//  Lum1naStructOffsets.m
//  Lum1na
//
//  Struct-offset rows. Same SKU keying as LabOff() (LabDeviceProfile).
//  All three supported SKUs run darwin >= 24.4, so the ladder values are
//  shared; they are spelled out per row so a future per-SKU drift is a
//  one-line change, not a refactor.
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
    .proc_flag      = 0x25C, \
    .pro_ro_csflags = 0x24, \
    .pro_ro_ucred   = 0x28, \
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
    /* A14 hunt (26.5, darwin 25.5): Dopamine 24.4+ ladder + P7 leak agree. */
    PROC_ROW("A14_23F77", 0),
    /* A13 rig (18.6.2, darwin 24.6): same 24.4+ ladder. */
    PROC_ROW("A13_22G100", 0),
    /* A12X iPad twin (23G71): same ladder, untested on T8020. */
    PROC_ROW("A12X_23G71", 0),
};

const LabProcOffTab *LabProcOff(void) {
    const LabOffTab *off = LabOff();
    if (!off || !off->tag) return NULL;
    for (size_t i = 0; i < sizeof(gProcOffTabs) / sizeof(gProcOffTabs[0]); i++) {
        if (strcmp(gProcOffTabs[i].tag, off->tag) == 0) return &gProcOffTabs[i];
    }
    return NULL;
}
