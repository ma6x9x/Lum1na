#include "surface.h"

#include <assert.h>

CFNumberRef cs2_cfnum(uint64_t value) {
    return CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt64Type, &value);  // idc if it leaks
}

IOSurfaceRef cs2_surface_at(mach_vm_address_t address, mach_vm_size_t size) {
    CFMutableDictionaryRef properties = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionarySetValue(properties, CFSTR("IOSurfaceAddress"), cs2_cfnum(address));
    CFDictionarySetValue(properties, CFSTR("IOSurfaceAllocSize"), cs2_cfnum(size));

    IOSurfaceRef surface = IOSurfaceCreate(properties);
    IOSurfacePrefetchPages(surface);  // prefetches all pages for the iosurface ("mlocks" them into memory)
    CFRelease(properties);

    return surface;  // caller owns
}

kern_return_t cs2_create_pc_mapping(mach_port_t* port_out, mach_vm_address_t* address_out, mach_vm_size_t size) {
    kern_return_t kr = KERN_SUCCESS;

    CFMutableDictionaryRef dict = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionarySetValue(dict, CFSTR("IOSurfaceAllocSize"), cs2_cfnum(size));
    CFDictionarySetValue(dict, CFSTR("IOSurfaceMemoryRegion"), CFSTR("PurpleGfxMem"));

    // create surface in PurpleGfxMem, which is contiguous by nature
    IOSurfaceRef surface = IOSurfaceCreate(dict);
    CFRelease(dict);

    if (surface == NULL) {
        return KERN_FAILURE;
    }

    // get its uaddr
    mach_vm_address_t physical_mapping_address = (mach_vm_address_t)IOSurfaceGetBaseAddress(surface);
    LOG("physical_mapping_address: %#llx", physical_mapping_address);

    // create a memory entry in PurpleGfxMem
    mach_port_t memory_object = MACH_PORT_NULL;
    kr = mach_make_memory_entry_64(mach_task_self(), &size, physical_mapping_address, VM_PROT_DEFAULT, &memory_object, MACH_PORT_NULL);
    if (kr != KERN_SUCCESS) {
        CFRelease(surface);
        return kr;
    }

    // map in PurpleGfxMem
    mach_vm_address_t new_mapping_address = 0;
    kr = mach_vm_map(mach_task_self(), &new_mapping_address, size, 0, VM_FLAGS_ANYWHERE | VM_FLAGS_RANDOM_ADDR, memory_object, 0, false, VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_NONE);
    CFRelease(surface);
    if (kr != KERN_SUCCESS) {
        mach_port_deallocate(mach_task_self(), memory_object);
        return kr;
    }

    *port_out = memory_object;
    *address_out = new_mapping_address;
    return KERN_SUCCESS;
}

void cs2_surface_mlock(mach_vm_address_t address, mach_vm_size_t size) {
    // create surface at address with size, and "mlock" it with IOSurfacePrefetchPages
    IOSurfaceRef surface = cs2_surface_at(address, size);
    // slot-reuse law (2026-10-24 SIGABRT postmortem): munlock NULLs slots but
    // never decremented the counter — pass 2 then overflowed the 8-slot table
    // and the assert aborted the app (P007OpenOnly-2026-10-24-183116.ips).
    // Find a NULL slot first; only grow the count when none is free.
    size_t idx = CS2_MAX_LOCKED_SURFACES;
    for (size_t i = 0; i < CS2_MAX_LOCKED_SURFACES; i++) {
        if (cs2_ctx.mlock_surfaces[i].surface == NULL && cs2_ctx.mlock_surfaces[i].address == 0) { idx = i; break; }
    }
    if (idx == CS2_MAX_LOCKED_SURFACES) idx = cs2_ctx.mlock_surfaces_count++;
    if (idx >= CS2_MAX_LOCKED_SURFACES) {
        // out of slots: release the oldest and take slot 0 (never abort)
        idx = 0;
        if (cs2_ctx.mlock_surfaces[0].surface) CFRelease(cs2_ctx.mlock_surfaces[0].surface);
        cs2_ctx.mlock_surfaces_count = CS2_MAX_LOCKED_SURFACES;
    }
    cs2_ctx.mlock_surfaces[idx].address = address;
    cs2_ctx.mlock_surfaces[idx].surface = surface;
}

void cs2_surface_reset_locked(void) {
    // release any surface slots still held and zero the table (call at pass end)
    for (size_t i = 0; i < CS2_MAX_LOCKED_SURFACES; i++) {
        if (cs2_ctx.mlock_surfaces[i].surface) { CFRelease(cs2_ctx.mlock_surfaces[i].surface); cs2_ctx.mlock_surfaces[i].surface = NULL; }
        cs2_ctx.mlock_surfaces[i].address = 0;
    }
    cs2_ctx.mlock_surfaces_count = 0;
}

void cs2_surface_munlock(mach_vm_address_t address) {
    // iterate mlocked surfaces until we find a match
    for (size_t idx = 0; idx < cs2_ctx.mlock_surfaces_count; idx++) {
        if (cs2_ctx.mlock_surfaces[idx].address == address && cs2_ctx.mlock_surfaces[idx].surface != NULL) {
            CFRelease(cs2_ctx.mlock_surfaces[idx].surface);
            cs2_ctx.mlock_surfaces[idx].surface = NULL;
            cs2_ctx.mlock_surfaces[idx].address = 0;
            break;
        }
    }
}
