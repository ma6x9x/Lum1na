//
//  LabHeapAnchor.h — same-boot REAL heap-anchor loader (2026-11-19)
//
//  Returns kernel-heap pointers the BOARD recorded THIS boot
//  (Documents/lum1na_board.json / p007_board.json leaks[], kind=heap,
//  e.g. the P159 IOSurface adjacency HARVEST). 0 = no same-boot leak.
//
//  LAB (anchor-tag): the returned values are spray-tag FILL material only.
//  They are leak-class evidence. They never set slide, never set hasKread,
//  and every kptr-shape classifier must EXCLUDE them — an anchor-tagged
//  window is a geometry measurement of our own pages, never a kernel
//  disclosure. No cross-boot reuse, no invented constants, no statics.
//
#import <Foundation/Foundation.h>
#include <stdint.h>

uint64_t LabHeapAnchorSameBoot(void);

/* All distinct same-boot heap anchors, freshest first, up to max.
   Returns the count written to out[]. */
int LabHeapAnchorsSameBoot(int max, uint64_t *out);

/* Auto-supply for the KRW paths: if the board's distinct same-boot anchor
   set is thinner than `want`, run ONE P159 harvest tap (self-bounded
   rounds) and re-count. Returns the distinct same-boot anchor count
   available after the call. Never blocks; never invents. */
int LabHeapAnchorHarvestIfThin(int want);
