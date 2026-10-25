//
//  P086IomdDmaFingerprint.h
//  CVE-2026-43684 dmaCommandOperation UC-fingerprint sweep.
//
//  Ghidra (23F77, cve43684_IOMD_dmaCommandOperation 0xfffffff00a507dbc)
//  gives the exact error fingerprint of the DMA-command path:
//    0xe00002d8  in-use address/length mismatch (reuse path)
//    0xe00002d0  alignment violation (param_3 & IOMD+0x38 mask)
//    0xe00002db  length over the memory descriptor (IOMD+0x30)
//  Any user client selector that returns these on bad args IS the
//  dmaCommandOperation family -> the P087 fire map targets it.
//
//  This tap: open candidate IOMD-consuming UCs, sweep selectors 0..40 with
//  benign scalar/struct shapes, log every kr, flag fingerprint hits.
//  NO fires. NO dmaCommand setup. Bounded discovery only.
//

#import <Foundation/Foundation.h>

@interface P086IomdDmaFingerprint : NSObject
+ (NSString *)tap;
@end