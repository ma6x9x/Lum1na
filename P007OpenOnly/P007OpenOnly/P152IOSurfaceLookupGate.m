//
//  P152IOSurfaceLookupGate.m — IOSurface global-lookup / lock gate probe. p152.
//  Lum1na-Debug (P007 rig). iOS kernel research (Lum1na).
//
//  IOSurface is loaded by dlsym (AGENTS: never import IOSurface headers).
//  Read-only: IOSurfaceLock with kIOSurfaceLockReadOnly, immediate unlock.
//  No surface bytes are copied out; this only measures which gates are open.
//
//  What the receipts mean (24A435/23F77 policy: owner task OR the global
//  insecure path — audit "relying on global (insecure) IOSurface lookups"):
//    own lookup ok            -> IOSurfaceRoot UC is reachable from this install
//    foreign hit + lock rc=0  -> global-ID resolution + ownerless lock are LIVE
//    no foreign hits          -> the global door is closed/gated here
//

#import "P152IOSurfaceLookupGate.h"
#import "LabDeviceProfile.h"
#import "LabLocalTime.h"

#import <Foundation/Foundation.h>
#import <CoreFoundation/CoreFoundation.h>
#import <dlfcn.h>

typedef CFTypeRef (*p152_create_t)(CFDictionaryRef);
typedef uint32_t  (*p152_getid_t)(CFTypeRef);
typedef CFTypeRef (*p152_lookup_t)(uint32_t);
typedef size_t    (*p152_allocs_t)(CFTypeRef);
typedef uint32_t  (*p152_usecnt_t)(CFTypeRef);
typedef int32_t   (*p152_lock_t)(CFTypeRef, uint32_t, uint32_t *);
typedef int32_t   (*p152_unlock_t)(CFTypeRef, uint32_t, uint32_t *);

@implementation P152IOSurfaceLookupGate

+ (NSString *)tap {
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"=== p152 session %@ BUILD p152-iosurf-gate-v1 ===\n",
        LabLocalMilitaryNow()];
    [out appendString:[LabDeviceProfile identBlock]];

    void *h = dlopen("/System/Library/PrivateFrameworks/IOSurface.framework/IOSurface",
                     RTLD_LAZY);
    if (!h) h = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface",
                       RTLD_LAZY);
    void *d = h ? h : RTLD_DEFAULT;
    p152_create_t  sCreate = (p152_create_t)dlsym(d, "IOSurfaceCreate");
    p152_getid_t   sGetID  = (p152_getid_t)dlsym(d, "IOSurfaceGetID");
    p152_lookup_t  sLookup = (p152_lookup_t)dlsym(d, "IOSurfaceLookup");
    p152_allocs_t  sAlloc  = (p152_allocs_t)dlsym(d, "IOSurfaceGetAllocSize");
    p152_usecnt_t  sUse    = (p152_usecnt_t)dlsym(d, "IOSurfaceGetUseCount");
    p152_lock_t    sLock   = (p152_lock_t)dlsym(d, "IOSurfaceLock");
    p152_unlock_t  sUnlock = (p152_unlock_t)dlsym(d, "IOSurfaceUnlock");
    [out appendFormat:@"  [lib] dlopen=%@ syms=%d%d%d%d%d%d%d\n",
        h ? @"ok" : @"fallback", sCreate != NULL, sGetID != NULL, sLookup != NULL,
        sAlloc != NULL, sUse != NULL, sLock != NULL, sUnlock != NULL];
    if (!sCreate || !sGetID || !sLookup) {
        [out appendString:@"  [res] IOSurface symbols missing — no probe\n"];
        return out;
    }

    /* our own 64x64 BGRA surface */
    CFMutableDictionaryRef props = CFDictionaryCreateMutable(
        kCFAllocatorDefault, 4, &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks);
    int w = 64, ht = 64, bpe = 4, row = 256;
    CFNumberRef nW = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &w);
    CFNumberRef nH = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &ht);
    CFNumberRef nB = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &bpe);
    CFNumberRef nR = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &row);
    CFDictionarySetValue(props, CFSTR("IOSurfaceWidth"), nW);
    CFDictionarySetValue(props, CFSTR("IOSurfaceHeight"), nH);
    CFDictionarySetValue(props, CFSTR("IOSurfaceBytesPerElement"), nB);
    CFDictionarySetValue(props, CFSTR("IOSurfaceBytesPerRow"), nR);
    CFTypeRef own = sCreate(props);
    CFRelease(nW); CFRelease(nH); CFRelease(nB); CFRelease(nR);
    CFRelease(props);
    if (!own) {
        [out appendString:@"  [own] IOSurfaceCreate failed — IOSurfaceRoot not reachable\n"];
        [out appendFormat:@"=== p152 end %@ ===\n", LabLocalMilitaryNow()];
        return out;
    }
    uint32_t ownID = sGetID(own);
    CFTypeRef own2 = sLookup(ownID);
    [out appendFormat:@"  [own] create ok id=%u lookupByID=%@ alloc=%zu\n",
        ownID, own2 ? @"ok" : @"NULL", sAlloc ? sAlloc(own) : 0];
    if (own2) CFRelease(own2);

    uint32_t seed = 0;
    int hits = 0, locks = 0, probed = 0;
    uint32_t lo = ownID > 80 ? ownID - 64 : 1;
    uint32_t hi = ownID + 192;
    for (uint32_t sid = lo; sid <= hi && hits < 24; sid++) {
        if (sid == ownID) continue;
        probed++;
        CFTypeRef s = sLookup(sid);
        if (!s) continue;
        hits++;
        uint32_t use = sUse ? sUse(s) : 0;
        size_t sz = sAlloc ? sAlloc(s) : 0;
        int32_t lr = -1;
        if (sLock) {
            seed = 0;
            lr = sLock(s, 0x1 /* read-only */, &seed);
            if (lr == 0) {
                locks++;
                if (sUnlock) sUnlock(s, 0x1, &seed);
            }
        }
        [out appendFormat:@"  [hit] sid=%u alloc=%zu use=%u lockRO=%d\n",
            sid, sz, use, lr];
        CFRelease(s);
    }
    [out appendFormat:@"  [res] probed=%d foreignHits=%d lockRO_ok=%d (window %u..%u)\n",
        probed, hits, locks, lo, hi];
    [out appendFormat:@"  [verdict] %@\n",
        (hits > 0 && locks > 0)
            ? @"GLOBAL LOOKUP + OWNERLESS LOCK LIVE on this install"
            : (hits > 0 ? @"global lookup live, lock refused"
                        : @"global lookup closed/gated for this install")];

    CFRelease(own);
    [out appendFormat:@"=== p152 end %@ ===\n", LabLocalMilitaryNow()];
    return out;
}

@end
