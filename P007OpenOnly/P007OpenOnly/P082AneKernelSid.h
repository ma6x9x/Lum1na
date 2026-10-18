//
//  P082AneKernelSid.h
//
//  P082 v2 — dump the object PHASE K already fetched.
//
//  In-bounds 127-in copyout (XVRC27_127in_copyout, 128 records, MemoryMap
//  consumes). x_i = sid. Output = OUR surface / y MultiArray.
//
//  Classification of the 512-byte window:
//    bytes 0xfffffff0…  = leak of that IOMD (live global surface read)
//    graphics / zeros   = another task's IOSurface
//    fp16(sid) echo     = espresso VALUE path (P080 READ DOOR still dead)
//
//  kread32(kbase)==0xfeedfacf only if that backing is kernel TEXT.
//  This TAP never flips hasKread from occupancy, fetch, or a kptr leak.
//
//  Dual binding:
//    D-CM    CoreML MultiArray, record sid = int(x_i)  (the P082 fetch path)
//    D-DIR   _ANEClient wrap of IOSurfaceGetID objects (pixel DMA, P044 v63)
//    Lookup of sid 1 is NULL in our task — Direct cannot wrap kernel sids
//    unless a post-fetch Lookup HIT appears.
//
#import <Foundation/Foundation.h>

@interface P082AneKernelSid : NSObject
+ (NSString *)tap;
@end
