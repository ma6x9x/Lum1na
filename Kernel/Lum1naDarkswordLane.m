//
//  Lum1naDarkswordLane.m — see header. Wraps the vendored krw family.
//

#import "Lum1naDarkswordLane.h"
#import "DarkswordBridge.h"

static BOOL g_live = NO;

bool Lum1naDarksword_IsLive(void) { return g_live; }

uint64_t Lum1naDarksword_KRead64(uint64_t kaddr) { return g_live ? kread64(kaddr) : 0; }
uint32_t Lum1naDarksword_KRead32(uint64_t kaddr) { return g_live ? kread32(kaddr) : 0; }
bool     Lum1naDarksword_KWrite64(uint64_t kaddr, uint64_t v) {
    if (!g_live) return false;
    kwrite64(kaddr, v);
    return true;   /* the vendored lane writes without a checkable error */
}
bool     Lum1naDarksword_KWrite32(uint64_t kaddr, uint32_t v) {
    if (!g_live) return false;
    kwrite32(kaddr, v);
    return true;
}
ssize_t  Lum1naDarksword_KReadBuf(uint64_t kaddr, void *buf, size_t len) {
    if (!g_live || !buf || len == 0) return -1;
    kreadbuf(kaddr, buf, (uint64_t)len);
    return (ssize_t)len;
}
ssize_t  Lum1naDarksword_KWriteBuf(uint64_t kaddr, const void *buf, size_t len) {
    if (!g_live || !buf || len == 0) return -1;
    kwritebuf(kaddr, buf, (uint64_t)len);
    return (ssize_t)len;
}

@implementation DarkswordBridge (LaneMark)
+ (void)laneInstalled {
    g_live = YES;   /* set by establishWithLog after commitSlide */
}
@end

/* expose to the bridge implementation */
BOOL Lum1naDarksword_MarkLive(void) { g_live = YES; return YES; }
