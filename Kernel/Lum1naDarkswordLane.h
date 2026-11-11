//
//  Lum1naDarkswordLane.h — the "darksword" lane over the verbatim vendored
//  kexploit. Joins the Lum1naLane cascade (socketkrw -> libkrw -> cs2core
//  -> darksword).
//

#import <Foundation/Foundation.h>
#import <stdint.h>
#import <stdbool.h>
#import <stddef.h>

bool Lum1naDarksword_IsLive(void);
uint64_t Lum1naDarksword_KRead64(uint64_t kaddr);
uint32_t Lum1naDarksword_KRead32(uint64_t kaddr);
bool     Lum1naDarksword_KWrite64(uint64_t kaddr, uint64_t v);
BOOL     Lum1naDarksword_MarkLive(void);
bool     Lum1naDarksword_KWrite32(uint64_t kaddr, uint32_t v);
ssize_t  Lum1naDarksword_KReadBuf(uint64_t kaddr, void *buf, size_t len);
ssize_t  Lum1naDarksword_KWriteBuf(uint64_t kaddr, const void *buf, size_t len);
