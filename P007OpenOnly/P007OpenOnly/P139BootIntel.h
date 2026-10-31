//
//  P139BootIntel.h — the BOOT INTEL COLLATOR (slide-triangulation). p139.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface P139BootIntel : NSObject
/// The Learner layer as ONE tap: harvest every per-boot user-observable
/// kernel state in a single session —
///   1. [P063] the aio kn_sdata KVA family (+0xC0 per-boot object law)
///   2. [P097] the console/gRegistryRoot-class leak row
///   3. [P010] the QueueCreate cursor + w1 band (slide-tracked)
///   4. [P090] the ipc/info rows
///   5. the IOMD op-2 ORACLE (the [md+0x98] gate readback, inline arm)
/// then collate a per-boot dossier (p139_boot_intel.txt) with the
/// SLIDE-TRIANGULATION check: any pair of observations separated by a
/// STATICALLY-VERIFIED distance (the aio +0xC0 law; the GHIDRA static
/// deltas like allproc 0x38FC770) pins the slide consistently. The
/// dossier FEEDS every lane's first aim (boot-1 known addresses); it is
/// not a receipt and never flips hasKread (no content read here).
/// READ-ONLY. One tap per force-quit; all child taps keep their own logs.
+ (NSString *)tap;
@end

NS_ASSUME_NONNULL_END