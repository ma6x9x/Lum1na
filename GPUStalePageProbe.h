//
//  GPUStalePageProbe.h
//  Lum1na
//
//  CVE-2026-64788 Facet C — dangling-GART physical-page UAF.
//  After detach+REPLACE_OK, the GPU keeps DMA access to the freed old
//  pages. Spray kernel allocations (mach_msg OOL with magic markers),
//  then use the GPU's stale mapping as a read/write channel:
//    READ  test: GPU blit-out shows OOL magic  → kernel heap READ
//    WRITE test: GPU blit-in of magic2 lands in received OOL bodies
//                → kernel heap WRITE
//  Fully self-verifying — no KASLR, no panic needed.
//

#ifndef GPUStalePageProbe_h
#define GPUStalePageProbe_h

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface GPUStalePageProbe : NSObject

@property (nonatomic, readonly) uint32_t iterationsRun;
@property (nonatomic, readonly) uint32_t replaceOK;
@property (nonatomic, readonly) uint32_t readProofs;    // OOL magic seen via GPU read
@property (nonatomic, readonly) uint32_t writeProofs;   // magic2 seen in received OOL bodies

- (BOOL)runWithIterations:(uint32_t)iterations error:(NSError **)error;

@end

NS_ASSUME_NONNULL_END
#endif /* GPUStalePageProbe_h */
