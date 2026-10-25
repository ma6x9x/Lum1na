#ifndef cs2_phys_oob_h
#define cs2_phys_oob_h

#include "common.h"

void cs2_init_phys_rw(mach_vm_size_t contiguous_mapping_size);
kern_return_t cs2_oob_read(mach_port_t mo, mach_vm_offset_t mo_offset, uint64_t size, uint64_t offset, uint8_t* buffer);
void cs2_oob_read_retry(mach_port_t memory_object, mach_vm_offset_t seeking_offset, uint64_t oob_size, uint64_t oob_offset, uint8_t* read_buffer);
void cs2_oob_write(mach_port_t mo, mach_vm_offset_t mo_offset, uint64_t size, uint64_t offset, uint8_t* buffer);

#endif /* cs2_phys_oob_h */
