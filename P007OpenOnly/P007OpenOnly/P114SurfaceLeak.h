//
//  P114SurfaceLeak.h — Lum1na-Debug (P007 rig)
//
//  SOLO M2ScalerCSCDriver selector-8 (iosaDiag) leak tap — the leak law
//  validated independently of the p110 race. Numbered p114 because the
//  catalog id p113 is P113DescForgeControl (AGENTS.md collision law): the
//  wave brief said "p113"; the tree already owns that id.
//
//  The derived leak law (all from LabIntelOffsets rows, never hardcoded):
//    - m2scaler.get_iosaDiag_sel (PROVEN-EXT): sel 8; the event_payload
//      +0x18 field leaks an IOSurface KVA — iOS<=26.5.2 live on 23F77,
//      fixed 26.6 (23G71), likely CVE-2026-64709.
//    - t8150.m2scaler.leak8: the fn's own gate cmp x2,#8 = the struct
//      input is {u64} 8 BYTES (NOT p098's 16-byte {userVA,size} shape —
//      that was the v5 run-failer).
//    - t8150.m2scaler.serializer: the OUT = the activity-queue records:
//      +0x20 header, record stride 0x7c, and rec+0x18 = str x8,[x0,#0x18]
//      the RAW first-event qword passthrough — NO auth.
//    - t8150.m2scaler.client30: one recorder site stores a +0x30-shaped
//      client-ptr (the [surface+0x30] claim-law shape).
//
//  N bounded captures, the KV table print, the honest classification.
//  HONESTY: every kernel-range KV = LAW: KVA DISCLOSURE CLASS — not kread;
//  hasKread=NO until a kread32-class receipt exists. Out-shape mismatch
//  (kext drift) = honest hexdump + HOLD. READ-ONLY: door open + queue
//  create + sel-8 calls only; no race, no grooming, no writes.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface P114SurfaceLeak : NSObject
+ (NSString *)tap;   // returns the log body

/* 2026-11-22 the READBACK (the P130->P114 pair): the sel-8 activity-dump
   cycle as a callable — the 3072-write lane's observation step. Opens its
   own M2Scaler connection, banks its own 1000 distinct surfaces (the v5
   contract), creates the queue, runs 2 captures, parses up to max raw
   rec+0x18 values into kvas (kernel-range only, board-recorded). Read-only;
   returns YES if any capture completed. */
+ (BOOL)diagReadback:(uint64_t *)kvas outN:(int *)outN max:(int)max
             logLine:(void (^)(NSString *line))lg;
@end

NS_ASSUME_NONNULL_END