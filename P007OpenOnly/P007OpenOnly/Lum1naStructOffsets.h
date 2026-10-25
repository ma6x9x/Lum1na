//
//  Lum1naStructOffsets.h
//  Lum1na
//
//  Per-SKU kernel STRUCT offset table (NOT virtual addresses — those stay
//  exclusive to LabRuntimeOffsets.c per AGENTS.md). Feeds the post-KRW
//  elevate step (uid0 -> unsandbox -> CS_PLATFORM_BINARY).
//
//  Provenance: Dopamine 3.0.11 BaseBin/libjailbreak/src/info.c ladder,
//  darwin >= 24.4.0 block (proc_ro move + p_original_ppid removal).
//  Independently cross-checked 2026-10-14 against the DarkSword P7 kit's
//  leaked __A14_A18_OFFSETS table (chain_loader_26.js): proc_ro.csflags
//  0x24, proc_ro.ucred 0x28, ucred.uid 0x18 all AGREE. The P7 VAs did NOT
//  match 23F77 in Ghidra (proc_find claim had no function at the claimed
//  address) — struct offsets yes, VAs no.
//
//  kernproc VA is 0 until derived per SKU in Ghidra (allproc/kernproc
//  anchor). 0 = elevate holds with a logged reason, pipeline degrades to
//  the pre-elevate behavior. NEVER guess this value.
//

#import <Foundation/Foundation.h>
#include <stdint.h>
#include <stdbool.h>

NS_ASSUME_NONNULL_BEGIN

typedef struct {
    const char *tag;          // matches LabOffTab.tag

    // struct proc (darwin 24.4.0+ ladder)
    uint32_t proc_list_next;  // p_list.le_next  (LIST_ENTRY, offset 0)
    uint32_t proc_list_prev;  // p_list.le_prev  (offset 8)
    uint32_t proc_proc_ro;    // p_proc_ro       0x18 (iOS 16+)
    uint32_t proc_svuid;      // 0x38 (24.4.0+: p_original_ppid removed)
    uint32_t proc_svgid;      // 0x3C
    uint32_t proc_pid;        // 0x60
    uint32_t proc_fd;         // 0xD0
    uint32_t proc_flag;       // 0x25C

    // struct proc_ro (exists iOS 15.2+; shifted +0x8 on darwin 24.4.0+)
    uint32_t pro_ro_csflags;  // 0x1C + 0x8 = 0x24
    uint32_t pro_ro_ucred;    // 0x20 + 0x8 = 0x28
    uint32_t pro_ro_task_tokens; // 0x40 base, +0x8 = 0x48 (24.4+), REMOVED 26.5 = 0

    // struct ucred (cr_posix layout, stable since iOS 15)
    uint32_t ucred_uid;       // cr_posix + 0x00 = 0x18
    uint32_t ucred_ruid;      // cr_posix + 0x04 = 0x1C
    uint32_t ucred_svuid;     // cr_posix + 0x08 = 0x20
    uint32_t ucred_groups;    // cr_posix + 0x10 = 0x28
    uint32_t ucred_rgid;      // cr_posix + 0x50 = 0x68
    uint32_t ucred_svgid;     // cr_posix + 0x54 = 0x6C
    uint32_t ucred_label;     // 0x78

    // Unslid kernproc VA (proc 0, allproc-list member). 0 = UNDERIVED.
    // Backward le_prev walk from kernproc reaches every proc without the
    // allproc list-head symbol. Ghidra task queued per SKU.
    uint64_t kernproc;
} LabProcOffTab;

const LabProcOffTab * _Nullable LabProcOff(void);

// Constants (Dopamine kernel.h / codesign.h / util.c proc_ucred_update_content)
#define LAB_P_SUGID             0x00000100u
#define LAB_CS_PLATFORM_BINARY  0x04000000u
#define LAB_TASK_TOKEN_AUDIT    0x8u        // task_token_ro_data.audit_token
#define LAB_TT_UID_OFF          4           // auditToken+4  = uid
#define LAB_TT_GID_OFF          8           // auditToken+8  = gid
#define LAB_TT_RUID_OFF         12          // auditToken+12 = ruid
#define LAB_TT_RGID_OFF         16          // auditToken+16 = rgid

NS_ASSUME_NONNULL_END
