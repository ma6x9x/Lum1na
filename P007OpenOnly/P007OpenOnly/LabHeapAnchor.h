//
//  LabHeapAnchor.h — same-boot REAL heap-anchor loader (2026-11-19)
//
//  Returns the freshest kernel-heap pointer the BOARD recorded THIS boot
//  (Documents/lum1na_board.json / p007_board.json leaks[], kind=heap,
//  e.g. a P159 IOSurface receipt). 0 = no same-boot leak.
//
//  LAW (anchor-tag): the returned value is spray-tag FILL material only.
//  It is leak-class evidence. It never sets slide, never sets hasKread,
//  and every kptr-shape classifier must EXCLUDE it — an anchor-tagged
//  window is a geometry measurement of our own pages, never a kernel
//  disclosure. No cross-boot reuse, no invented constants, no statics.
//
#import <Foundation/Foundation.h>
#include <stdint.h>

uint64_t LabHeapAnchorSameBoot(void);
