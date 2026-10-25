#import "P051APFSXattr.h"
#import "LabDeviceProfile.h"
#import "LabLocalTime.h"
#import "LabRuntimeOffsets.h"

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/message.h>
#import <objc/runtime.h>
#import <fcntl.h>
#import <unistd.h>
#import <string.h>
#import <stdlib.h>
#import <sys/xattr.h>
#import <errno.h>
#import <dlfcn.h>

/*
 * P051 v6 — gamed XPC census under Game Mode.
 *
 * v3 (gamed-xpc-bridge): GKDaemonProxy often had no cacheImageData; then
 * sandboxed setxattr. v5 (trollrestore-aks): payload stayed in the app
 * container; 23F77 apfs_aks_create_wvek is BRK fail-closed for len>0x210.
 *
 * This TAP: dump what Game Center actually exposes while Game Mode groom
 * is on, and (only if the selector exists) write a BENIGN file into
 * gamed's own cache subdirectory. No "../", no AKS paths, no WVEK
 * overflow, no TrollRestore, no Find My, no SysContainerDomain restore.
 *
 * Userspace census. hasKread stays NO. Live AKS TAP is P057.
 */

#define P051_BUILD @"p051-gamed-census-v6-probeopen"

static int g_log_fd = -1;

static void p051_log(NSMutableString *buf, NSString *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    NSString *line = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    NSString *out = [line hasSuffix:@"\n"] ? line : [line stringByAppendingString:@"\n"];
    [buf appendString:out];
    if (g_log_fd >= 0) {
        const char *s = out.UTF8String;
        if (s) {
            write(g_log_fd, s, strlen(s));
            fcntl(g_log_fd, F_FULLFSYNC);
        }
    }
}

static BOOL p051_interesting(NSString *nm) {
    NSString *l = nm.lowercaseString;
    return [l containsString:@"cache"] || [l containsString:@"image"] ||
           [l containsString:@"file"] || [l containsString:@"util"] ||
           [l containsString:@"gamed"] || [l containsString:@"xpc"] ||
           [l containsString:@"write"] || [l containsString:@"load"];
}

static void p051_dump_methods(NSMutableString *log, Class cls, NSString *label) {
    if (!cls) {
        p051_log(log, @"  [%@] class=nil", label);
        return;
    }
    p051_log(log, @"  [%@] class=%@", label, NSStringFromClass(cls));
    unsigned n = 0;
    Method *mm = class_copyMethodList(cls, &n);
    unsigned shown = 0;
    unsigned star = 0;
    for (unsigned i = 0; i < n; i++) {
        NSString *nm = NSStringFromSelector(method_getName(mm[i]));
        if (p051_interesting(nm)) {
            p051_log(log, @"    ★ %@", nm);
            star++;
        } else if (shown < 16) {
            p051_log(log, @"    %@", nm);
            shown++;
        }
    }
    p051_log(log, @"    methods=%u star=%u (all ★ + first 16 others)", n, star);
    if (mm) free(mm);
}

static BOOL p051_has(id obj, NSString *selName) {
    return obj && [obj respondsToSelector:NSSelectorFromString(selName)];
}

@implementation P051APFSXattr

+ (NSString *)tap {
    NSMutableString *log = [NSMutableString string];
    NSString *docs = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    NSString *logPath = [docs stringByAppendingPathComponent:@"p051_apfs_xattr_log.txt"];
    g_log_fd = open([logPath UTF8String], O_CREAT | O_WRONLY | O_TRUNC, 0644);

    p051_log(log, @"=== p051 session BUILD %@ ===", P051_BUILD);
    p051_log(log, @"gamed XPC census + in-cache benign write. NOT TrollRestore. NOT WVEK overflow.");
    p051_log(log, @"hasKread=NO. Live AKS TAP is P057.");
    p051_log(log, @"");

    [LabDeviceProfile beginHuntGroom];
    NSString *warn = [LabDeviceProfile huntTapWarn:@"p051"];
    if (warn.length) p051_log(log, @"%@", warn);
    p051_log(log, @"%@", [LabDeviceProfile gameModeLine]);
    [LabDeviceProfile stampLastTap:@"p051"];

    const LabOffTab *off = LabOff();
    p051_log(log, @"sku=%@ table=%s wvek_pin=0x%llx",
             [LabDeviceProfile skuName],
             off ? off->tag : "NULL",
             off ? (unsigned long long)off->aks_wvek_overflow : 0ULL);
    p051_log(log, @"[SKIP] 84523 remaining-fire PARK. apfs_aks_create_wvek copies only if len<=0x210; larger is BRK fail-closed on 23F77. AKS does not parse a dropped /var/db/Keychains/pwned_wvek. TrollRestore SysContainerDomain restore is ACE and is not this TAP.");
    p051_log(log, @"");

    BOOL proxy_ok = NO;
    BOOL util_ok = NO;
    BOOL cache_sel = NO;
    BOOL using_gamed = NO;
    __block BOOL benign_cb = NO;
    __block BOOL load_cb = NO;
    __block NSUInteger load_len = 0;

    p051_log(log, @"[PHASE 1] GameCenter frameworks");
    void *gcf = dlopen("/System/Library/PrivateFrameworks/GameCenterFoundation.framework/GameCenterFoundation", RTLD_LAZY);
    void *gcuc = dlopen("/System/Library/PrivateFrameworks/GameCenterUICore.framework/GameCenterUICore", RTLD_LAZY);
    p051_log(log, @"  GameCenterFoundation %s", gcf ? "loaded" : "FAIL");
    p051_log(log, @"  GameCenterUICore %s", gcuc ? "loaded" : "FAIL (optional)");

    static NSString *const kCacheSel = @"cacheImageData:inSubdirectory:withFileName:handler:";
    static NSString *const kLoadSel  = @"loadCachedImageDataFromSubdirectory:withFileName:handler:";
    static NSString *const kDelSel   = @"deleteCachedImageDataFromSubdirectory:withFileName:handler:";
    static NSString *const kReqSel   = @"requestImageDataForURL:subdirectory:fileName:handler:";
    static NSString *const kUsingSel = @"cacheImageUsingGamed:cacheSubdirectory:withHandler:";
    static NSString *const kFromSel  = @"cachedImageFromGamedWithSubdirectory:handler:";

    p051_log(log, @"");
    p051_log(log, @"[PHASE 2] GKDaemonProxy + utilityService census");
    Class dpClass = NSClassFromString(@"GKDaemonProxy");
    p051_dump_methods(log, object_getClass(dpClass), @"GKDaemonProxy meta");
    p051_dump_methods(log, dpClass, @"GKDaemonProxy inst");

    id proxy = nil;
    if (dpClass && [dpClass respondsToSelector:@selector(daemonProxy)]) {
        proxy = ((id (*)(Class, SEL))objc_msgSend)(dpClass, @selector(daemonProxy));
    }
    p051_log(log, @"  daemonProxy=%@", proxy ?: @"(nil)");
    if (proxy) {
        proxy_ok = YES;
        p051_dump_methods(log, object_getClass(proxy), @"proxy isa");
    }

    id util = nil;
    if (p051_has(proxy, @"utilityService")) {
        util = ((id (*)(id, SEL))objc_msgSend)(proxy, @selector(utilityService));
    }
    p051_log(log, @"  utilityService=%@ class=%@",
             util ?: @"(nil)", util ? NSStringFromClass(object_getClass(util)) : @"-");
    if (util) {
        util_ok = YES;
        p051_dump_methods(log, object_getClass(util), @"util isa");
    }

    p051_log(log, @"");
    p051_log(log, @"[PHASE 3] Named gamed selectors on util");
    NSArray *named = @[kCacheSel, kLoadSel, kDelSel, kReqSel];
    for (NSString *s in named) {
        BOOL y = p051_has(util, s);
        p051_log(log, @"  util %@ = %d", s, y ? 1 : 0);
        if (y && [s isEqualToString:kCacheSel]) cache_sel = YES;
    }

    Class lisClass = NSClassFromString(@"GKLocalImageSource");
    id src = lisClass ? [[lisClass alloc] init] : nil;
    p051_log(log, @"  GKLocalImageSource=%@", src ?: @"(nil)");
    if (src) p051_dump_methods(log, object_getClass(src), @"GKLocalImageSource isa");
    p051_log(log, @"  src %@ = %d", kUsingSel, p051_has(src, kUsingSel) ? 1 : 0);
    p051_log(log, @"  src %@ = %d", kFromSel, p051_has(src, kFromSel) ? 1 : 0);
    if (p051_has(src, kUsingSel)) using_gamed = YES;
    if (!util && p051_has(src, @"utilityService")) {
        util = ((id (*)(id, SEL))objc_msgSend)(src, @selector(utilityService));
        p051_log(log, @"  src.utilityService=%@", util ?: @"(nil)");
        if (util) {
            util_ok = YES;
            cache_sel = p051_has(util, kCacheSel);
            p051_log(log, @"  src.util cacheImageData = %d", cache_sel ? 1 : 0);
        }
    }

    Class dgClass = NSClassFromString(@"GKDispatchGroup");
    p051_log(log, @"  GKDispatchGroup class=%@", dgClass ?: @"(nil)");
    if (dgClass) p051_dump_methods(log, object_getClass(dgClass), @"GKDispatchGroup meta");

    /* In-cache only. Filename is a basename. Subdir has no slash. */
    NSString *subdir = @"p051_census";
    NSString *benignName = @"p051_benign.txt";
    NSData *benignData = [@"P051_CENSUS_BENIGN" dataUsingEncoding:NSUTF8StringEncoding];

    if (cache_sel && util) {
        p051_log(log, @"");
        p051_log(log, @"[PHASE 4] Benign in-cache write (subdir=%@ file=%@). No path traversal.", subdir, benignName);
        dispatch_semaphore_t sem = dispatch_semaphore_create(0);
        void (^handler)(void) = ^{
            benign_cb = YES;
            p051_log(log, @"  [callback] cacheImageData completed");
            dispatch_semaphore_signal(sem);
        };
        ((void (*)(id, SEL, id, id, id, id))objc_msgSend)(
            util, NSSelectorFromString(kCacheSel), benignData, subdir, benignName, handler);
        long timed = dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, 10 * NSEC_PER_SEC));
        p051_log(log, @"  wait %@", timed == 0 ? @"signaled" : @"TIMEOUT");

        if (p051_has(util, kLoadSel)) {
            dispatch_semaphore_t sem2 = dispatch_semaphore_create(0);
            void (^loadH)(id) = ^(id data) {
                load_cb = YES;
                if ([data isKindOfClass:[NSData class]]) load_len = [(NSData *)data length];
                p051_log(log, @"  [callback] loadCached class=%@ len=%zu",
                         data ? NSStringFromClass([data class]) : @"(nil)",
                         (size_t)load_len);
                dispatch_semaphore_signal(sem2);
            };
            ((void (*)(id, SEL, id, id, id))objc_msgSend)(
                util, NSSelectorFromString(kLoadSel), subdir, benignName, loadH);
            long t2 = dispatch_semaphore_wait(sem2, dispatch_time(DISPATCH_TIME_NOW, 10 * NSEC_PER_SEC));
            p051_log(log, @"  load wait %@", t2 == 0 ? @"signaled" : @"TIMEOUT");
        }
    } else {
        p051_log(log, @"");
        p051_log(log, @"[PHASE 4] SKIP benign write — cacheImageData absent on util (same miss as v3).");
    }

    if (using_gamed && src) {
        p051_log(log, @"");
        p051_log(log, @"[PHASE 5] cacheImageUsingGamed with 1x1 UIImage, subdir=%@", subdir);
        UIGraphicsBeginImageContextWithOptions(CGSizeMake(1, 1), YES, 1);
        [[UIColor redColor] setFill];
        UIRectFill(CGRectMake(0, 0, 1, 1));
        UIImage *img = UIGraphicsGetImageFromCurrentImageContext();
        UIGraphicsEndImageContext();
        dispatch_semaphore_t sem3 = dispatch_semaphore_create(0);
        void (^h3)(id) = ^(id err) {
            p051_log(log, @"  [callback] usingGamed err=%@", err);
            dispatch_semaphore_signal(sem3);
        };
        ((void (*)(id, SEL, id, id, id))objc_msgSend)(
            src, NSSelectorFromString(kUsingSel), img, subdir, h3);
        long t3 = dispatch_semaphore_wait(sem3, dispatch_time(DISPATCH_TIME_NOW, 10 * NSEC_PER_SEC));
        p051_log(log, @"  usingGamed wait %@", t3 == 0 ? @"signaled" : @"TIMEOUT");
    } else {
        p051_log(log, @"");
        p051_log(log, @"[PHASE 5] SKIP cacheImageUsingGamed — selector absent on GKLocalImageSource.");
    }

    p051_log(log, @"");
    p051_log(log, @"[PHASE 6] Sandboxed xattr control (container only)");
    NSString *testFile = [docs stringByAppendingPathComponent:@"p051_local_test"];
    int fd = open([testFile UTF8String], O_CREAT | O_RDWR, 0644);
    if (fd >= 0) close(fd);
    int sizes[] = {0x100, 0x200, 0x210, 0x300};
    for (int si = 0; si < 4; si++) {
        int size = sizes[si];
        char *payload = (char *)malloc((size_t)size);
        if (!payload) continue;
        memset(payload, 0x41, (size_t)size);
        int ret = setxattr([testFile UTF8String], "user.p051", payload, (size_t)size, 0, XATTR_CREATE);
        p051_log(log, @"  setxattr(size=0x%x): ret=%d errno=%d", size, ret, errno);
        if (ret == 0) {
            char readBuf[0x400];
            ssize_t got = getxattr([testFile UTF8String], "user.p051", readBuf, sizeof(readBuf), 0, 0);
            p051_log(log, @"    getxattr: %zd", got);
            removexattr([testFile UTF8String], "user.p051", 0);
        }
        free(payload);
    }
    unlink([testFile UTF8String]);

    p051_log(log, @"");
    p051_log(log, @"=== VERDICT BUILD %@ ===", P051_BUILD);
    p051_log(log, @"gamed_proxy=%d utilityService=%d cacheImageData=%d usingGamed=%d",
             proxy_ok ? 1 : 0, util_ok ? 1 : 0, cache_sel ? 1 : 0, using_gamed ? 1 : 0);
    p051_log(log, @"benign_cb=%d load_cb=%d load_len=%zu",
             benign_cb ? 1 : 0, load_cb ? 1 : 0, (size_t)load_len);
    p051_log(log, @"occupancy=NO conversion=NO hasKread=NO");
    p051_log(log, @"A callback is XPC accept, not a kernel write and not a sandbox escape.");
    p051_log(log, @"cacheImageData=1 under Game Mode would be new vs v3 (selector was absent).");
    p051_log(log, @"Closest KRW is still hunt-12 P044 N=192 after GAME_MODE_NOTIFY=1. AKS reach is P057.");
    p051_log(log, @"=== p051 complete ===");

    if (g_log_fd >= 0) {
        fcntl(g_log_fd, F_FULLFSYNC);
        close(g_log_fd);
        g_log_fd = -1;
    }
    return log;
}

@end
