//
//  LabLearn.h
//  Lum1na
//
//  Per-SKU overlay (Documents/lab_learn.json). Device-observed facts only:
//  ANE model name, REQ_IN, occupancy/conversion receipts, heap VA, last
//  magic self-test. Does not paste kernel VAs into LabOff() — Ghidra first.
//  KERNEL + P044 read this so a ported SKU keeps the model/timing that
//  actually ran, and the bandit can pick the next arm.
//

#import <Foundation/Foundation.h>
#include <stdint.h>

NS_ASSUME_NONNULL_BEGIN

@interface LabLearn : NSObject

/// Current SKU row (empty dict if none yet).
+ (NSDictionary *)row;

/// Bandit arm KERNEL selected for this process (oob192 / inb191 / small127).
+ (void)setPendingArm:(nullable NSString *)arm;
+ (nullable NSString *)pendingArm;

/// Learned or SKU-default ANE model name. nil = keep P044 compile default.
+ (nullable NSString *)aneModel;

/// Learned or SKU-default REQ_IN. 0 = keep P044 compile default (192 on hunt).
+ (uint32_t)aneReqIn;

/// Device-observed conversion/magic receipts. Overlay never pastes VAs.
+ (BOOL)conversionConfirmed;
+ (BOOL)magicConfirmed;

/// Persist a KERNEL/P044 receipt. heap=0 and empty model are ignored.
+ (void)recordOccupancy:(BOOL)occ
             conversion:(BOOL)conv
                  magic:(BOOL)magic
                   heap:(uint64_t)heap
                  model:(nullable NSString *)model
                  reqIn:(uint32_t)reqIn
                 source:(NSString *)source;

/// P100 LEARN PACKET ingest (chip/sku/table only; no VAs).
+ (void)ingestIdent:(NSString *)ident;

/// P139 dossier ingest. Heap-shaped facts only. Never writes LabOff().
+ (void)ingestBootIntel;

@end

NS_ASSUME_NONNULL_END
