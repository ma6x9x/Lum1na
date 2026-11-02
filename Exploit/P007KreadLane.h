//
//  P007KreadLane.h
//  P007OpenOnly
//
//  One kread/kwrite lane picker shared by P094/P095 (and future elevate).
//  Cascade mirrors the official Lum1na Kernel/Lum1naKreadLane, adapted to
//  the lab app: libkrw glue (P090 pattern, Dopamine provider) -> registered
//  board kread32 (P007Board, commitSlide-gated). All callers print the lane
//  name so logs stay honest about which primitive answered.
//
//  libkrw interface: opa334/Dopamine BaseBin _external/include/libkrw
//  (krw_initializer ABI), MIT-licensed integration glue, credits in
//  docs/CREDITS.md.
//

#import <Foundation/Foundation.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

NS_ASSUME_NONNULL_BEGIN

bool    P007LaneLive(void);
const char *P007LaneName(void);     // "libkrw" | "board-kread32" | "none"
bool    P007LaneBuffered(void);     // bulk kreadbuf available (libkrw only)
/* Ground-truth slide for the live lane: committed board slide when set,
   else libkrw kbase - staticBase (kernel Mach-O header sanity passed). */
uint64_t P007LaneSlide(void);
/* Provider kbase when the libkrw lane is live, else 0. */
uint64_t P007LaneKbase(void);

uint64_t P007LaneKRead64(uint64_t kaddr);
uint32_t P007LaneKRead32(uint64_t kaddr);
bool     P007LaneKWrite64(uint64_t kaddr, uint64_t v);
bool     P007LaneKWrite32(uint64_t kaddr, uint32_t v);
/* Bulk read. Returns bytes read, -1 when the lane has no buffered path. */
ssize_t  P007LaneKReadBuf(uint64_t kaddr, void *buf, size_t len);

NS_ASSUME_NONNULL_END