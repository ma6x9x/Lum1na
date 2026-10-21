//
//  P105IosurfaceGates.m — IOSurface gate census (note 243). Framework-level.
//  No IOPageList shapes (64749 stays closed). Bounded create count.
//

#import "P105IosurfaceGates.h"
#import "LabDeviceProfile.h"
#import "LabLocalTime.h"

#import <IOKit/IOKitLib.h>
#import <CoreFoundation/CoreFoundation.h>
#import <fcntl.h>
#import <dlfcn.h>
#import <string.h>
#import <unistd.h>

#define P105_BUILD @"p105-iosurface-gates-v1"
#define P105_MAXCREATES 6

typedef void *(*p105_iscreate_t)(CFDictionaryRef);
typedef uint64_t (*p105_issid_t)(void *);
typedef void *(*p105_islookup_t)(uint64_t);
typedef void (*p105_isrelease_t)(void *);

static NSMutableString *g_log = nil;
static int g_fd = -1;
static void L(NSString *s) {
    if (!g_log) return;
    NSString *out = [s hasSuffix:@"\n"] ? s : [s stringByAppendingString:@"\n"];
    [g_log appendString:out];
    if (g_fd >= 0) {
        const char *p = out.UTF8String;
        if (p) { write(g_fd, p, strlen(p)); fcntl(g_fd, F_FULLFSYNC); }
    }
}

static CFDictionaryRef p105_pool_dict(void) {
    int64_t pool = 1;
    CFNumberRef nPool = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt64Type, &pool);
    CFMutableDictionaryRef d = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionarySetValue(d, CFSTR("Pool Id"), nPool);
    CFRelease(nPool);
    return (CFDictionaryRef)d;
}

@implementation P105IosurfaceGates

+ (NSString *)tap {
    g_log = [NSMutableString string];
    NSString *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    g_fd = open([[docs stringByAppendingPathComponent:@"p105_iosurface_gates_log.txt"] UTF8String],
                O_CREAT | O_WRONLY | O_TRUNC, 0644);

    L([NSString stringWithFormat:@"=== p105 session %@ BUILD %@ ===",
        LabLocalMilitaryNow(), P105_BUILD]);
    L(@"IOSurface gates (note 243). Framework-level. Entitlements in initWithTask:");
    L(@"  iosurfaceinfo +0x122, gpu-restricted +0x127, protected-access +0x123, grant bit +0x126.");
    L(@"Watch idevicesyslog for the two Security: warn-once lines + pool/protection oracles.");
    L(@"Bounded: <=6 creates total. NO IOPageList shapes (64749 closed). NO writes.");
    NSString *stop = [LabDeviceProfile stopUnlessA14_23F77:@"p105"];
    if (stop) {
        L(stop);
        if (g_fd >= 0) { fcntl(g_fd, F_FULLFSYNC); close(g_fd); }
        return g_log;
    }
    L([LabDeviceProfile identBlock]);

    void *ios = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
    if (!ios) ios = dlopen("/System/Library/PrivateFrameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
    p105_iscreate_t pCreate = ios ? (p105_iscreate_t)dlsym(ios, "IOSurfaceCreate") : NULL;
    p105_issid_t pSid    = ios ? (p105_issid_t)dlsym(ios, "IOSurfaceGetID") : NULL;
    p105_islookup_t pLook = ios ? (p105_islookup_t)dlsym(ios, "IOSurfaceLookup") : NULL;
    p105_isrelease_t pRel = ios ? (p105_isrelease_t)dlsym(ios, "IOSurfaceRelease") : NULL;
    if (!pCreate) {
        L(@"[-] IOSurfaceCreate absent");
        if (g_fd >= 0) { fcntl(g_fd, F_FULLFSYNC); close(g_fd); }
        return g_log;
    }

    int created = 0;
    int64_t sz = 0x1000, w = 64, h = 4;
    CFNumberRef nSz = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt64Type, &sz);
    CFNumberRef nW  = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt64Type, &w);
    CFNumberRef nH  = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt64Type, &h);

    /* shape 1: baseline private surface */
    CFMutableDictionaryRef d1 = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionarySetValue(d1, CFSTR("IOSurfaceAllocSize"), nSz);
    void *s1 = pCreate(d1);
    uint64_t sid1 = s1 && pSid ? pSid(s1) : 0;
    created++;
    L([NSString stringWithFormat:@"[baseline] surf=%p sid=%08llx (private, expect NO Security warn)", s1, sid1]);
    if (s1 && pRel) pRel(s1);

    /* shape 2: IOSurfaceIsGlobal — expect the "creating global IOSurfaces" warn-once */
    CFMutableDictionaryRef d2 = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionarySetValue(d2, CFSTR("IOSurfaceAllocSize"), nSz);
    CFDictionarySetValue(d2, CFSTR("IOSurfaceIsGlobal"), kCFBooleanTrue);
    CFDictionarySetValue(d2, CFSTR("IOSurfaceWidth"), nW);
    CFDictionarySetValue(d2, CFSTR("IOSurfaceHeight"), nH);
    void *s2 = pCreate(d2);
    uint64_t sid2 = s2 && pSid ? pSid(s2) : 0;
    created++;
    L([NSString stringWithFormat:@"[global]   surf=%p sid=%08llx (expect Security: create-global warn)", s2, sid2]);

    /* shape 3: global LOOKUP of our own sid — expect the "relying on global lookups" warn */
    if (pLook && sid2) {
        void *s3 = pLook(sid2);
        created++;
        L([NSString stringWithFormat:@"[lookup]   own sid=%08llx -> %p (expect Security: global-lookup warn)", sid2, s3]);
        if (s3 && pRel) pRel(s3);
    }

    /* shape 4: protection bits — the "Unsupported protection bits set: %016llx" oracle */
    int64_t prots[3] = { 0x01, 0xFF, 0x1FF };
    const char *protname[3] = { "0x1", "0xff", "0x1ff" };
    for (int i = 0; i < 3 && created < P105_MAXCREATES; i++) {
        int64_t p = prots[i];
        CFNumberRef nP = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt64Type, &p);
        CFMutableDictionaryRef d = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
            &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
        CFDictionarySetValue(d, CFSTR("IOSurfaceAllocSize"), nSz);
        CFDictionarySetValue(d, CFSTR("IOSurfaceProtectionOptions"), nP);
        void *s4 = pCreate(d);
        created++;
        if (s4) {
            uint64_t sid = pSid ? pSid(s4) : 0;
            L([NSString stringWithFormat:@"[prot %s] ACCEPTED sid=%08llx (protection bits NOT rejected!)",
               protname[i], sid]);
        } else {
            L([NSString stringWithFormat:@"[prot %s] reje (nil) — expect 'Unsupported protection bits' in syslog", protname[i]]);
        }
        if (s4 && pRel) pRel(s4);
        CFRelease(nP);
        CFRelease(d);
    }

    /* shape 5: memory pool id — the "pool off limits" / "wrong entitlements" oracle */
    if (created < P105_MAXCREATES) {
        CFMutableDictionaryRef d5 = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
            &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
        CFDictionarySetValue(d5, CFSTR("IOSurfaceAllocSize"), nSz);
        CFDictionaryRef poolDict = p105_pool_dict();
        CFDictionarySetValue(d5, CFSTR("IOSurfaceMemoryPoolInfo"), poolDict);
        void *s5 = pCreate(d5);
        created++;
        L([NSString stringWithFormat:@"[pool 1]   surf=%p (expect 'pool off limits (1)' or the entitlement denial)", s5]);
        if (s5 && pRel) pRel(s5);
        CFRelease(poolDict);
        CFRelease(d5);
    }

    if (s2 && pRel) pRel(s2);

    CFRelease(nSz); CFRelease(nW); CFRelease(nH); CFRelease(d1); CFRelease(d2);

    L([NSString stringWithFormat:@"=== VERDICT creates=%d/%d ===", created, P105_MAXCREATES]);
    L(@"Syslog lines to capture: 'Security: Process ... creating global IOSurfaces'");
    L(@"  + 'relying on global (insecure) IOSurface lookups' = the warn-once gates CONFIRMED live.");
    L(@"HONESTY: census only. hasKread=NO.");
    if (g_fd >= 0) { fcntl(g_fd, F_FULLFSYNC); close(g_fd); }
    return g_log;
}

@end