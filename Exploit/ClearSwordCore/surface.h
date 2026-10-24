#ifndef cs2_surface_h
#define cs2_surface_h

#include <CoreFoundation/CoreFoundation.h>

#include "common.h"

CFNumberRef cs2_cfnum(uint64_t value);
IOSurfaceRef cs2_surface_at(mach_vm_address_t address, mach_vm_size_t size);
kern_return_t cs2_create_pc_mapping(mach_port_t* port_out, mach_vm_address_t* address_out, mach_vm_size_t size);
void cs2_surface_mlock(mach_vm_address_t address, mach_vm_size_t size);
void cs2_surface_munlock(mach_vm_address_t address);
void cs2_surface_reset_locked(void);

extern void IOSurfacePrefetchPages(IOSurfaceRef surface);

#endif /* cs2_surface_h */
