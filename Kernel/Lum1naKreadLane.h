//
//  Lum1naKreadLane.h
//  Lum1na
//
//  One kread/kwrite lane picker shared by Lum1naElevate, P094 and P095.
//  Cascade order matches AfterKread / Elevate: socketkrw context (board) ->
//  libkrw -> cs2core. All callers print the lane name so logs stay honest
//  about which primitive answered.
//

#import <Foundation/Foundation.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

NS_ASSUME_NONNULL_BEGIN

bool    Lum1naLaneLive(void);
const char *Lum1naLaneName(void);   // "socketkrw" | "libkrw" | "cs2core" | "none"
bool    Lum1naLaneBuffered(void);   // bulk kreadbuf available (socketkrw/libkrw)

uint64_t Lum1naLaneKRead64(uint64_t kaddr);
uint32_t Lum1naLaneKRead32(uint64_t kaddr);
bool     Lum1naLaneKWrite64(uint64_t kaddr, uint64_t v);
bool     Lum1naLaneKWrite32(uint64_t kaddr, uint32_t v);
/* Bulk read. Returns bytes read, -1 when the lane has no buffered path. */
ssize_t  Lum1naLaneKReadBuf(uint64_t kaddr, void *buf, size_t len);

NS_ASSUME_NONNULL_END