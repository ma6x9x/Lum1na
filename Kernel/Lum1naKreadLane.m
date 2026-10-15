//
//  Lum1naKreadLane.m
//  Lum1na
//

#import "Lum1naKreadLane.h"
#import "Lum1naBoard.h"
#import "../Exploit/Lum1naSocketKRW.h"
#import "../Exploit/Lum1naLibkrw.h"
#import "../Exploit/Lum1naCS2Core.h"

#pragma mark - lane resolution

static Lum1naSocketKRWContext *LaneSocketCtx(void) {
    Lum1naBoard *b = [Lum1naBoard shared];
    return (Lum1naSocketKRWContext *)b.krwContext;
}

bool Lum1naLaneLive(void) {
    return LaneSocketCtx() != NULL || Lum1naLibkrw_IsLive() || Lum1naCS2Core_IsLive();
}

const char *Lum1naLaneName(void) {
    if (LaneSocketCtx()) return "socketkrw";
    if (Lum1naLibkrw_IsLive()) return "libkrw";
    if (Lum1naCS2Core_IsLive()) return "cs2core";
    return "none";
}

bool Lum1naLaneBuffered(void) {
    return LaneSocketCtx() != NULL || Lum1naLibkrw_IsLive();
}

#pragma mark - reads

uint64_t Lum1naLaneKRead64(uint64_t a) {
    Lum1naSocketKRWContext *ctx = LaneSocketCtx();
    if (ctx) return Lum1naSocketKRW_KRead64(ctx, a);
    if (Lum1naLibkrw_IsLive()) return Lum1naLibkrw_KRead64(a);
    if (Lum1naCS2Core_IsLive()) return Lum1naCS2Core_KRead64(a);
    return 0;
}

uint32_t Lum1naLaneKRead32(uint64_t a) {
    Lum1naSocketKRWContext *ctx = LaneSocketCtx();
    if (ctx) return Lum1naSocketKRW_KRead32(ctx, a);
    if (Lum1naLibkrw_IsLive()) return Lum1naLibkrw_KRead32(a);
    if (Lum1naCS2Core_IsLive()) return Lum1naCS2Core_KRead32(a);
    return 0;
}

#pragma mark - writes

bool Lum1naLaneKWrite64(uint64_t a, uint64_t v) {
    Lum1naSocketKRWContext *ctx = LaneSocketCtx();
    bool ok = ctx ? Lum1naSocketKRW_KWrite64(ctx, a, v) : false;
    if (!ok && Lum1naLibkrw_IsLive()) ok = Lum1naLibkrw_KWrite64(a, v);
    if (!ok && Lum1naCS2Core_IsLive()) ok = Lum1naCS2Core_KWrite64(a, v);
    return ok;
}

bool Lum1naLaneKWrite32(uint64_t a, uint32_t v) {
    Lum1naSocketKRWContext *ctx = LaneSocketCtx();
    bool ok = ctx ? Lum1naSocketKRW_KWrite32(ctx, a, v) : false;
    if (!ok && Lum1naLibkrw_IsLive()) ok = Lum1naLibkrw_KWrite32(a, v);
    if (!ok && Lum1naCS2Core_IsLive()) ok = Lum1naCS2Core_KWrite32(a, v);
    return ok;
}

#pragma mark - bulk

ssize_t Lum1naLaneKReadBuf(uint64_t kaddr, void *buf, size_t len) {
    if (!buf || !len) return -1;
    Lum1naSocketKRWContext *ctx = LaneSocketCtx();
    if (ctx) return Lum1naSocketKRW_KReadBuffered(ctx, kaddr, buf, len);
    if (Lum1naLibkrw_IsLive()) return Lum1naLibkrw_KReadBuf(kaddr, buf, len) ? (ssize_t)len : (ssize_t)-1;
    return -1;
}