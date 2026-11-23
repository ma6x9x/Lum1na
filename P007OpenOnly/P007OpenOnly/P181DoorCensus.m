//
//  P181DoorCensus.m — the COMPLETE door census: every on-device plist source
//  x host-binary entitlement keys x the LIVE bootstrap oracle (which mach
//  services THIS sandboxed app can actually message) -> the proxy-door
//  shortlist.
//
//  WHY (the write-lane unlock recon, 2026-11-23): several write-lane doors
//  are entitlement-gated (AVE2 aocp-client, coredisplay, IOSurface AgentMask,
//  EXDisplayPipe, coredump...). A gate dissolves with ZERO new bugs if any
//  app-reachable system service holds the entitlement and forwards requests
//  to the driver. The census answers exactly that, on THIS build, from the
//  device itself:
//
//    FOUND (bootstrap_look_up kr=0 && port!=NULL)  = the app can message it
//    host binary's code-signature entitlement KEYS = what it holds
//    FOUND x private-keys                          = THE DOOR SHORTLIST
//
//  COVERAGE (the miss-nothing list):
//    P1  direct plist dirs — /System/Library/LaunchDaemons + LaunchAgents,
//        /Library/LaunchDaemons + LaunchAgents, /private/var/db/launchd.db
//        (com.apple.launchd + com.apple.launchd.peruser.<uid>), /var/jb
//        (absent on stock — one honest row)
//    P2  recursive /System/Library walk (depth<=7): *.xpc, *.appex, *.exilet,
//        *.dext, *.agent bundles -> Contents/Info.plist (MachServices)
//    P3  host-binary entitlement KEYS via the code-signature blob
//        (0xfade7171 XML, tail 4 MB window) — KEYS ONLY, never values
//    P4  the sandbox profile pool: /System/Library/Sandbox/Profiles/*.sbpl
//        strings (the mach-lookup name census for the Mac-side diff)
//    P5  THE LIVE ORACLE: bootstrap_look_up on every distinct mach service
//        name collected above
//    P6  the shortlist + counts + honest one-sided caveat
//    P7  JSON export Documents/p181_door_census.json (the full artifact)
//
//  READ INTEL ONLY. No kernel interaction, no writes outside the container,
//  panic-free, hasKread untouched. KEYS ONLY — values are the device's
//  private data, never reported (the intel.piggy law). One tap per app run.
//

#import "P181DoorCensus.h"
#import "LabDeviceProfile.h"
#import "LabLocalTime.h"
#import "P007Board.h"

#import <Foundation/Foundation.h>
#import <dirent.h>
#import <fcntl.h>
#import <limits.h>
#import <mach/mach.h>
#import <mach/mach_init.h>
#import <string.h>
#import <sys/stat.h>
#import <unistd.h>

#define P181_BUILD @"p181-door-census-v2-beblob"

/* bootstrap API (declared locally — no <servers/bootstrap.h> on iOS) */
extern mach_port_t bootstrap_port;
extern kern_return_t bootstrap_look_up(mach_port_t bp, char *name,
                                       mach_port_t *sp);

/* ── bounds (the census is read-only; bounds keep the tap fast) ── */
#define P181_MAX_DIRS      30000
#define P181_MAX_BUNDLES    4096
#define P181_MAX_MACH_HOST   512
#define P181_MAX_LOOKUPS    4096
#define P181_TAIL_WINDOW  (4 * 1024 * 1024)
#define P181_SBPL_MAX     (4 * 1024 * 1024)
#define P181_STR_PER_FILE   2048
#define P181_STR_TOTAL     32768

static NSMutableArray<NSDictionary *> *g_p181_hosts = nil;
static NSMutableSet<NSString *> *g_p181_seen = nil;
static int g_p181_walkDirs = 0, g_p181_bundles = 0;

/* ── host row helpers ── */
static void p181_add_host(NSString *src, NSString *plist, NSString *label,
                          NSString *program, NSArray<NSString *> *mach) {
    if (!g_p181_hosts) g_p181_hosts = [NSMutableArray array];
    /* dedup by plist path (or label when plistless): the roots pass and the
       general walk reach the same bundles — one row each (the v1 double-count
       risk). g_p181_seen is reset at the top of every tap. */
    if (!g_p181_seen) g_p181_seen = [NSMutableSet set];
    NSString *key = ([plist length] > 0) ? plist
        : [NSString stringWithFormat:@"%@|%@", label ?: @"?", program ?: @""];
    if ([g_p181_seen containsObject:key]) return;
    [g_p181_seen addObject:key];
    if (g_p181_hosts.count >= P181_MAX_BUNDLES * 4) return;
    if ([mach count] > P181_MAX_MACH_HOST)
        mach = [mach subarrayWithRange:NSMakeRange(0, P181_MAX_MACH_HOST)];
    [g_p181_hosts addObject:@{
        @"src": src ?: @"?",
        @"plist": plist ?: @"",
        @"label": label ?: @"?",
        @"program": program ?: @"",
        @"mach": mach ?: @[],
    }];
}

static NSDictionary *p181_load_plist(NSString *path) {
    return [NSDictionary dictionaryWithContentsOfFile:path];
}

/* one launchd/xpc plist -> host row (generic: Label or CFBundleIdentifier,
   Program or ProgramArguments[0], MachServices keys) */
static void p181_ingest_plist(NSString *src, NSString *path) {
    NSDictionary *pl = p181_load_plist(path);
    if (!pl) return;
    NSString *label = pl[@"Label"] ?: pl[@"CFBundleIdentifier"]
        ?: path.lastPathComponent;
    NSString *prog = pl[@"Program"] ?: @"";
    if ([prog length] == 0) {
        NSArray *args = [pl isKindOfClass:[NSDictionary class]]
            ? pl[@"ProgramArguments"] : nil;
        if ([args isKindOfClass:[NSArray class]] && args.count > 0)
            prog = [args firstObject];
    }
    NSArray *mach = nil;
    NSDictionary *ms = pl[@"MachServices"];
    if ([ms isKindOfClass:[NSDictionary class]])
        mach = [[ms allKeys] sortedArrayUsingSelector:
                @selector(compare:)];
    p181_add_host(src, path, label, prog, mach);
}

/* ── the recursive /System/Library bundle walk ── */
static int p181_suffix_is(const char *nm, size_t n, const char *suf,
                          size_t sufLen) {
    return n > sufLen && !strcmp(nm + n - sufLen, suf);
}

/* the bundle-name set (v2: + .app and .bundle — SpringBoard.app/PlugIns and
   CoreServices powerd.bundle are real hosts; powerd's binary sits at the
   bundle ROOT, not Contents/MacOS — the exe finder handles both shapes). */
static int p181_is_bundle_name(const char *nm) {
    size_t n = strlen(nm);
    return p181_suffix_is(nm, n, ".xpc", 4) ||
           p181_suffix_is(nm, n, ".app", 4) ||
           p181_suffix_is(nm, n, ".dext", 5) ||
           p181_suffix_is(nm, n, ".appex", 6) ||
           p181_suffix_is(nm, n, ".agent", 6) ||
           p181_suffix_is(nm, n, ".bundle", 7) ||
           p181_suffix_is(nm, n, ".exilet", 7);
}

/* the bundle executable: Contents/MacOS/<exe>, the bundle ROOT (<bp>/<exe>
   — the powerd.bundle law), then the first non-dot entry of either dir. */
static NSString *p181_find_exe(NSString *bp, NSDictionary *pl) {
    NSString *exe = pl[@"CFBundleExecutable"];
    if (![exe isKindOfClass:[NSString class]] || [exe length] == 0)
        exe = [bp.lastPathComponent stringByDeletingPathExtension];
    NSMutableArray *cands = [NSMutableArray array];
    if ([exe length] > 0) {
        [cands addObject:[bp stringByAppendingPathComponent:
            [NSString stringWithFormat:@"Contents/MacOS/%@", exe]]];
        [cands addObject:[bp stringByAppendingPathComponent:exe]];
    }
    NSArray *dirs = @[[bp stringByAppendingPathComponent:@"Contents/MacOS"], bp];
    for (NSString *d in dirs) {
        DIR *m = opendir(d.fileSystemRepresentation);
        if (!m) continue;
        struct dirent *me;
        while ((me = readdir(m)) != NULL) {
            if (me->d_name[0] == '.') continue;
            [cands addObject:[d stringByAppendingPathComponent:
                [NSString stringWithUTF8String:me->d_name]]];
            break;   /* first non-dot entry is the fallback */
        }
        closedir(m);
    }
    for (NSString *c in cands) {
        struct stat st;
        if (stat(c.fileSystemRepresentation, &st) == 0 &&
            st.st_size > 64 && !S_ISDIR(st.st_mode))
            return c;
    }
    return @"";
}

static void p181_ingest_bundle(NSString *bp, NSString *src) {
    if (g_p181_bundles > P181_MAX_BUNDLES) return;
    g_p181_bundles++;
    NSString *info = [bp stringByAppendingPathComponent:@"Contents/Info.plist"];
    NSDictionary *pl = p181_load_plist(info);
    if (!pl) {
        p181_add_host(src, bp, bp.lastPathComponent, @"", @[]);
        return;
    }
    NSString *label = pl[@"CFBundleIdentifier"] ?: pl[@"Label"]
        ?: bp.lastPathComponent;
    NSDictionary *ms = pl[@"MachServices"];
    NSArray *mach = [ms isKindOfClass:[NSDictionary class]]
        ? [[ms allKeys] sortedArrayUsingSelector:@selector(compare:)] : @[];
    p181_add_host(src, info, label, p181_find_exe(bp, pl), mach);
}

/* THE ROOTS PRE-PASS (the v1 failure: the depth-first walk burned the whole
   30001-dir budget inside the first framework resource trees and reached
   only 3 appex bundles). Enumerate the KNOWN service-container dirs
   directly first — coverage can never be starved by resource noise. */
static void p181_probe_dir(const char *dir, const char *sub) {
    char path[1024];
    snprintf(path, sizeof path, "%s/%s", dir, sub);
    DIR *d = opendir(path);
    if (!d) return;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (e->d_name[0] == '.') continue;
        if (!p181_is_bundle_name(e->d_name)) continue;
        char full[1024];
        snprintf(full, sizeof full, "%s/%s", path, e->d_name);
        p181_ingest_bundle([NSString stringWithUTF8String:full], @"roots");
    }
    closedir(d);
}

static void p181_bundle_roots(void) {
    static const char *roots[] = {
        "/System/Library/Frameworks",
        "/System/Library/PrivateFrameworks",
        "/System/Library/CoreServices",
        "/System/Library/ExtensionKit/Extensions",
        "/System/Library/XPCServices",
        "/System/Library/Extensions",
        "/System/Library/DriverKit",
        "/System/Applications",
    };
    for (size_t r = 0; r < sizeof roots / sizeof roots[0]; r++) {
        /* the ROOT'S OWN service containers FIRST — /System/Library/CoreServices
           itself carries an XPCServices dir (the 2026-11-23 catch), and probing
           only each entry's subdirs missed it entirely */
        p181_probe_dir(roots[r], "XPCServices");
        p181_probe_dir(roots[r], "PlugIns");
        p181_probe_dir(roots[r], "Extensions");
        p181_probe_dir(roots[r], "Drivers");
        DIR *d = opendir(roots[r]);
        if (!d) continue;
        struct dirent *e;
        while ((e = readdir(d)) != NULL) {
            if (e->d_name[0] == '.') continue;
            char ep[1024];
            snprintf(ep, sizeof ep, "%s/%s", roots[r], e->d_name);
            if (p181_is_bundle_name(e->d_name))
                p181_ingest_bundle([NSString stringWithUTF8String:ep], @"roots");
            /* the nested service containers */
            p181_probe_dir(ep, "XPCServices");
            p181_probe_dir(ep, "PlugIns");
            p181_probe_dir(ep, "Extensions");
            p181_probe_dir(ep, "Drivers");
        }
        closedir(d);
    }
}

static void p181_walk(const char *dir, int depth) {
    if (depth > 7 || g_p181_walkDirs > P181_MAX_DIRS ||
        g_p181_bundles > P181_MAX_BUNDLES)
        return;
    g_p181_walkDirs++;
    DIR *d = opendir(dir);
    if (!d) return;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        const char *nm = e->d_name;
        if (nm[0] == '.') continue;
        size_t n = strlen(nm);
        /* resource noise — do not spend the dir budget on .lproj/.nib/.storyboardc
           trees (the v1 starvation cause: 30001 dirs burned before any
           XPCServices dir was reached) */
        if (p181_suffix_is(nm, n, ".lproj", 6) ||
            p181_suffix_is(nm, n, ".nib", 4) ||
            p181_suffix_is(nm, n, ".storyboardc", 11))
            continue;
        char full[1024];
        snprintf(full, sizeof full, "%s/%s", dir, nm);
        struct stat st;
        if (stat(full, &st) != 0) continue;
        if (!S_ISDIR(st.st_mode)) continue;
        if (p181_is_bundle_name(nm)) {
            p181_ingest_bundle([NSString stringWithUTF8String:full], @"walk");
            continue;   /* do not descend into bundles */
        }
        p181_walk(full, depth + 1);
    }
    closedir(d);
}

/* ── entitlement KEYS from the code-signature blob (0xfade7171, tail window).
   v2 (2026-11-23, the v1 zero-keys receipt): the blob magic AND length are
   BIG-ENDIAN in the file — fa de 71 71 / len BE — proven against
   /usr/libexec/runningboardd on the Mac (40 keys parse cleanly). The v1 scan
   used the REVERSED tuple (71 71 de fa) and matched nothing; the same LE-tuple
   bug lived in the rig MachOInspector.entitlementKeys (fixed the same day).
   Two more v1 bugs fixed here: the bound (i+8+len>n) skipped blobs ending
   exactly at EOF — the blob is {magic 4B, len 4B, payload} with len counting
   the whole blob, so the bound is i+len<=n; and DER-only binaries (no XML
   blob) are now probed (fa de 8c 01) and reported as der-only — keys not
   parseable in-app, presence is the honest receipt.
   Returns nil = unreadable; @[] = readable, no XML blob/keys. */
static NSArray<NSString *> *p181_entitle_keys(NSString *bin,
                                              int *blobOutside, int *derOnly) {
    if (blobOutside) *blobOutside = 0;
    if (derOnly) *derOnly = 0;
    const char *cpath = bin.fileSystemRepresentation;
    FILE *f = fopen(cpath, "rb");
    if (!f) return nil;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return nil; }
    long long sz = ftell(f);
    if (sz < 64) { fclose(f); return nil; }
    long long win = sz > P181_TAIL_WINDOW ? P181_TAIL_WINDOW : sz;
    if (fseek(f, -win, SEEK_END) != 0) { fclose(f); return nil; }
    NSMutableData *data = [NSMutableData dataWithLength:(NSUInteger)win];
    if (!data) { fclose(f); return nil; }
    size_t got = fread(data.mutableBytes, 1, (size_t)win, f);
    fclose(f);
    if (got != (size_t)win) return nil;

    const uint8_t *b = (const uint8_t *)data.bytes;
    NSUInteger n = got;
    for (NSUInteger i = 0; i + 12 <= n; i++) {
        /* 0xfade7171 stored BIG-ENDIAN: fa de 71 71 */
        if (b[i] == 0xfa && b[i+1] == 0xde && b[i+2] == 0x71 && b[i+3] == 0x71) {
            uint32_t len = ((uint32_t)b[i+4] << 24) | ((uint32_t)b[i+5] << 16) |
                           ((uint32_t)b[i+6] << 8) | (uint32_t)b[i+7];
            if (len <= 8 || (uint64_t)i + len > (uint64_t)n) continue;
            NSData *xml = [data subdataWithRange:
                           NSMakeRange((NSUInteger)i + 8, (NSUInteger)len - 8)];
            id obj = [NSPropertyListSerialization propertyListWithData:xml
                       options:0 format:NULL error:NULL];
            if ([obj isKindOfClass:[NSDictionary class]]) {
                return [((NSDictionary *)obj) allKeys];
            }
            return @[];   /* blob present but not a dict — keys none */
        }
    }
    /* DER-entitlements probe (fa de 8c 01): the binary is signed with DER
       entitlements and no XML blob — record it, keys stay unparsed. */
    for (NSUInteger i = 0; i + 8 <= n; i++) {
        if (b[i] == 0xfa && b[i+1] == 0xde && b[i+2] == 0x8c && b[i+3] == 0x01) {
            if (derOnly) *derOnly = 1;
            break;
        }
    }
    if (sz > P181_TAIL_WINDOW && blobOutside) *blobOutside = 1;
    return @[];
}

/* the interesting-key filter (keys only — the piggy filter, private-wide) */
static BOOL p181_interesting(NSString *k) {
    if (![k isKindOfClass:[NSString class]]) return NO;
    NSString *l = [k lowercaseString];
    if ([l containsString:@"com.apple.private."]) return YES;
    if ([l containsString:@"iokit"]) return YES;
    if ([l containsString:@"user-client"]) return YES;
    if ([l containsString:@"userclient"]) return YES;
    if ([l containsString:@"unsandbox"]) return YES;
    if ([l isEqualToString:@"platform-application"]) return YES;
    if ([l isEqualToString:@"get-task-allow"]) return YES;
    return NO;
}

@implementation P181DoorCensus

+ (NSString *)tap {
    NSMutableString *log = [NSMutableString string];
    NSString *docs = NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    int fd = open([[docs stringByAppendingPathComponent:
                    @"p181_door_census_log.txt"] UTF8String],
                  O_CREAT | O_WRONLY | O_TRUNC, 0644);
    void (^L)(NSString *) = ^(NSString *s) {
        NSString *out = [s hasSuffix:@"\n"] ? s : [s stringByAppendingString:@"\n"];
        [log appendString:out];
        if (fd >= 0) { const char *p = out.UTF8String; if (p) write(fd, p, strlen(p)); }
    };

    L([NSString stringWithFormat:@"=== p181 session %@ BUILD %@ ===",
       LabLocalMilitaryNow() ?: @"?", P181_BUILD]);
    L(@"THE COMPLETE DOOR CENSUS: every plist source x host entitlement KEYS");
    L(@"x the LIVE bootstrap oracle -> the proxy-door shortlist (the");
    L(@"write-lane unlock recon). READ INTEL ONLY, KEYS ONLY, panic-free,");
    L(@"hasKread untouched.");
    L([LabDeviceProfile identBlock] ?: @"ident=?");

    g_p181_hosts = [NSMutableArray array];
    g_p181_seen = [NSMutableSet set];
    g_p181_walkDirs = 0;
    g_p181_bundles = 0;

    /* ── P1: the direct plist dirs (every root, honest verdicts) ── */
    L(@"");
    L(@"=== P1: plist sources ===");
    int uid = (int)getuid();
    NSString *peruser = [NSString
        stringWithFormat:@"/private/var/db/launchd.db/com.apple.launchd.peruser.%d", uid];
    NSArray *plistDirs = @[
        @"/System/Library/LaunchDaemons",
        @"/System/Library/LaunchAgents",
        @"/Library/LaunchDaemons",
        @"/Library/LaunchAgents",
        @"/private/var/db/launchd.db/com.apple.launchd",
        peruser,
        @"/var/jb/Library/LaunchDaemons",      /* stock: absent — one honest row */
        @"/System/Library/Extensions",         /* stock iOS: kexts live in the KC */
    ];
    for (NSString *dir in plistDirs) {
        const char *cp = dir.fileSystemRepresentation;
        DIR *d = opendir(cp);
        if (!d) {
            L([NSString stringWithFormat:@"[src] %@ — DENIED/absent (errno=%d)",
               dir, errno]);
            continue;
        }
        int n = 0, ingested = 0;
        struct dirent *e;
        while ((e = readdir(d)) != NULL) {
            if (e->d_name[0] == '.') continue;
            n++;
            size_t ln = strlen(e->d_name);
            if (ln > 6 && !strcmp(e->d_name + ln - 6, ".plist")) {
                NSString *p = [dir stringByAppendingPathComponent:
                               [NSString stringWithUTF8String:e->d_name]];
                int before = (int)g_p181_hosts.count;
                p181_ingest_plist(@"plist", p);
                if ((int)g_p181_hosts.count > before) ingested++;
            }
        }
        closedir(d);
        L([NSString stringWithFormat:@"[src] %@ — %d entries, %d agent plists",
           dir, n, ingested]);
    }

    /* ── P2: THE ROOTS PRE-PASS (XPCServices/PlugIns/Extensions under every
       known root — coverage cannot be starved), then the general walk ── */
    L(@"");
    L(@"=== P2: the bundle roots pass + the /System/Library walk ===");
    p181_bundle_roots();
    int rootsBundles = g_p181_bundles;
    L([NSString stringWithFormat:@"[roots] %d bundles ingested from the known "
       @"service containers (XPCServices/PlugIns/Extensions/Drivers)",
       rootsBundles]);
    p181_walk("/System/Library", 1);
    L([NSString stringWithFormat:@"[walk] +%d dirs visited, +%d more bundles "
       @"(cap %d) — the roots pass is the coverage guarantee, the walk only "
       @"adds strays", g_p181_walkDirs, g_p181_bundles - rootsBundles,
       P181_MAX_BUNDLES]);
    L([NSString stringWithFormat:@"[hosts] %d total host rows",
       (int)g_p181_hosts.count]);

    /* ── P3: host-binary entitlement KEYS (dedup by program path) ── */
    L(@"");
    L(@"=== P3: host-binary entitlement keys (KEYS ONLY, values never reported) ===");
    NSMutableDictionary<NSString *, NSArray<NSString *> *> *entByProg =
        [NSMutableDictionary dictionary];
    int binRead = 0, binKeys = 0, binNone = 0, binOutside = 0, binUnread = 0;
    int binDer = 0;
    NSMutableSet *progs = [NSMutableSet set];
    for (NSDictionary *h in g_p181_hosts) {
        NSString *p = h[@"program"];
        if ([p length] == 0) continue;
        [progs addObject:p];
    }
    for (NSString *p in progs) {
        int outside = 0, der = 0;
        NSArray *keys = p181_entitle_keys(p, &outside, &der);
        if (!keys) { binUnread++; continue; }
        if (outside) { binOutside++; binUnread++; continue; }
        binRead++;
        if ([keys count] > 0) {
            binKeys++;
            entByProg[p] = [keys sortedArrayUsingSelector:
                            @selector(compare:)];
        } else {
            binNone++;
            if (der) binDer++;   /* DER-only: signed with entitlements, XML absent */
        }
    }
    L([NSString stringWithFormat:@"[ent] %d distinct binaries: %d xml-keys, "
       @"%d der-only, %d keyless, %d unreadable/outside-tail (of %d hosts)",
       (int)progs.count, binKeys, binDer, binNone - binDer, binUnread,
       (int)g_p181_hosts.count]);

    /* attach keys + the source tag to host rows */
    for (NSUInteger i = 0; i < g_p181_hosts.count; i++) {
        NSMutableDictionary *h = [g_p181_hosts[i] mutableCopy];
        NSArray *k = entByProg[h[@"program"]];
        h[@"entitleKeys"] = k ?: @[];
        h[@"entitleSrc"] = ([k count] > 0) ? @"xml" : @"none";
        g_p181_hosts[i] = h;
    }

    /* ── P4: the sandbox profile pool (strings census for the Mac diff) ── */
    L(@"");
    L(@"=== P4: the sandbox profile pool (mach-lookup name strings) ===");
    NSMutableDictionary<NSString *, NSArray<NSString *> *> *sbplMap =
        [NSMutableDictionary dictionary];
    int sbplFiles = 0, sbplDenied = 0, sbplStrings = 0;
    {
        DIR *d = opendir("/System/Library/Sandbox/Profiles");
        if (!d) {
            L([NSString stringWithFormat:
               @"[sbpl] /System/Library/Sandbox/Profiles — DENIED/absent (errno=%d)",
               errno]);
        } else {
            struct dirent *e;
            while ((e = readdir(d)) != NULL) {
                size_t ln = strlen(e->d_name);
                if (ln > 5 && !strcmp(e->d_name + ln - 5, ".sbpl")) {
                    NSString *fp = [@"System/Library/Sandbox/Profiles/"
                        stringByAppendingPathComponent:
                        [NSString stringWithUTF8String:e->d_name]];
                    fp = [@"/" stringByAppendingString:fp];
                    struct stat st;
                    if (stat(fp.fileSystemRepresentation, &st) != 0)
                        { sbplDenied++; continue; }
                    if (st.st_size > P181_SBPL_MAX) { sbplDenied++; continue; }
                    NSData *dat = [NSData dataWithContentsOfFile:fp];
                    if (!dat) { sbplDenied++; continue; }
                    sbplFiles++;
                    /* extract com.apple.* ASCII runs (the compiled global names) */
                    NSMutableArray<NSString *> *strs = [NSMutableArray array];
                    const uint8_t *b = (const uint8_t *)dat.bytes;
                    NSUInteger n = dat.length, s = 0;
                    for (NSUInteger i = 0; i <= n; i++) {
                        uint8_t c = (i < n) ? b[i] : 0;
                        int printable = (c >= 0x20 && c < 0x7f);
                        if (printable) { if (s == 0) s = i; continue; }
                        if (s > 0) {
                            NSUInteger len = i - s;
                            if (len >= 8 && len <= 127) {
                                /* look for com.apple. inside the run */
                                const uint8_t *run = b + s;
                                for (NSUInteger j = 0; j + 11 <= len; j++) {
                                    if (!memcmp(run + j, "com.apple.", 10)) {
                                        NSString *one = [[NSString alloc]
                                            initWithBytes:run + j
                                                     length:len - j
                                                   encoding:NSUTF8StringEncoding];
                                        if (one) [strs addObject:one];
                                        break;
                                    }
                                }
                            }
                            s = 0;
                            if (strs.count >= P181_STR_PER_FILE) break;
                        }
                    }
                    sbplStrings += (int)strs.count;
                    sbplMap[[fp lastPathComponent]] = strs;
                }
            }
            closedir(d);
            L([NSString stringWithFormat:@"[sbpl] %d profiles read (%d denied/"
               @"oversize), %d com.apple.* strings (the mach-lookup census "
               @"for the Mac-side diff)", sbplFiles, sbplDenied, sbplStrings]);
        }
    }

    /* ── P5: THE LIVE ORACLE — bootstrap_look_up on every distinct service ── */
    L(@"");
    L(@"=== P5: the live bootstrap oracle ===");
    NSMutableSet<NSString *> *names = [NSMutableSet set];
    for (NSDictionary *h in g_p181_hosts)
        for (NSString *s in h[@"mach"])
            if ([s length] > 0) [names addObject:s];
    NSArray<NSString *> *sorted = [names allObjects];
    sorted = [sorted sortedArrayUsingSelector:@selector(compare:)];
    int lookups = 0, found = 0;
    NSMutableDictionary<NSString *, NSDictionary *> *svcMap =
        [NSMutableDictionary dictionary];
    if (sorted.count > P181_MAX_LOOKUPS)
        L([NSString stringWithFormat:@"[oracle] %lu names — CAPPED at %d lookups",
           (unsigned long)sorted.count, P181_MAX_LOOKUPS]);
    for (NSString *name in sorted) {
        if (lookups >= P181_MAX_LOOKUPS) break;
        lookups++;
        mach_port_t sp = MACH_PORT_NULL;
        kern_return_t kr = bootstrap_look_up(
            bootstrap_port, (char *)name.UTF8String, &sp);
        int isFound = (kr == KERN_SUCCESS && sp != MACH_PORT_NULL);
        if (isFound) {
            found++;
            if (sp != MACH_PORT_NULL)
                mach_port_deallocate(mach_task_self(), sp);
        }
        svcMap[name] = @{ @"kr": @(kr), @"found": @(isFound) };
    }
    L([NSString stringWithFormat:@"[oracle] %d lookups, %d FOUND "
       @"(kr=0 && live send right) — FOUND is one-sided proof of reachability;",
       lookups, found]);
    L(@"[oracle] not-found = sandbox-denied OR unregistered OR not-running —");
    L(@"[oracle] the polarity is one-sided; the Mac-side sbpl diff separates them.");

    /* ── P6: THE DOOR SHORTLIST — FOUND x private-entitlement holders ── */
    L(@"");
    L(@"=== P6: THE DOOR SHORTLIST (app-reachable service x host with private keys) ===");
    int doors = 0, printed = 0;
    NSMutableArray<NSDictionary *> *doorRows = [NSMutableArray array];
    for (NSString *name in sorted) {
        NSDictionary *sv = svcMap[name];
        if (![sv[@"found"] boolValue]) continue;
        NSMutableSet<NSString *> *keys = [NSMutableSet set];
        NSMutableArray<NSString *> *holders = [NSMutableArray array];
        for (NSDictionary *h in g_p181_hosts) {
            if (![h[@"mach"] containsObject:name]) continue;
            NSArray *ek = h[@"entitleKeys"];
            for (NSString *k in ek)
                if (p181_interesting(k)) [keys addObject:k];
            if ([ek count] > 0)
                [holders addObject:[NSString stringWithFormat:@"%@ (%@)",
                    h[@"program"] ?: @"?", h[@"label"] ?: @"?"]];
        }
        if ([keys count] == 0) continue;
        doors++;
        [doorRows addObject:@{
            @"service": name,
            @"keys": [[keys allObjects] sortedArrayUsingSelector:
                      @selector(compare:)],
            @"holders": [holders sortedArrayUsingSelector:
                         @selector(compare:)],
        }];
        if (printed < 64) {
            printed++;
            L([NSString stringWithFormat:@"[door] %@ — hosted by: %@",
               name, [holders componentsJoinedByString:@", "]]);
            L([NSString stringWithFormat:@"        holds: %@",
               [[[keys allObjects] sortedArrayUsingSelector:
                 @selector(compare:)] componentsJoinedByString:@", "]]);
        }
    }
    if (doors > printed)
        L([NSString stringWithFormat:@"[door] %d more rows in the JSON artifact",
           doors - printed]);
    if (doors == 0) {
        L(@"[door] none this tap — every FOUND service's hosts are keyless, or");
        L(@"      no gated host is reachable. The JSON still carries the full table.");
    }

    /* ── P7: the JSON artifact ── */
    L(@"");
    L(@"=== P7: the JSON artifact ===");
    NSString *jsonPath = [docs stringByAppendingPathComponent:
                          @"p181_door_census.json"];
    int jsonOk = 0;
    {
        NSMutableDictionary *root = [NSMutableDictionary dictionary];
        root[@"build"] = P181_BUILD;
        root[@"machine"] = [LabDeviceProfile machine] ?: @"?";
        root[@"osversion"] = [LabDeviceProfile osversion] ?: @"?";
        root[@"when"] = LabLocalMilitaryNow() ?: @"?";
        root[@"counts"] = @{
            @"hosts": @(g_p181_hosts.count),
            @"plistDirs": @([plistDirs count]),
            @"walkDirs": @(g_p181_walkDirs),
            @"bundles": @(g_p181_bundles),
            @"binaries": @(progs.count),
            @"binKeys": @(binKeys),
            @"binDerOnly": @(binDer),
            @"binKeyless": @(binNone - binDer),
            @"binUnread": @(binUnread),
            @"services": @(lookups),
            @"found": @(found),
            @"doors": @(doors),
        };
        root[@"hosts"] = g_p181_hosts;
        root[@"services"] = svcMap;
        root[@"doors"] = doorRows;
        root[@"sbpl"] = sbplMap;
        root[@"law"] = @"KEYS ONLY — entitlement values are never reported. "
                       @"Read intel only; not a kernel claim; hasKread untouched.";
        NSData *jd = [NSJSONSerialization dataWithJSONObject:root
                     options:NSJSONWritingSortedKeys error:NULL];
        if (jd && [jd writeToFile:jsonPath atomically:YES]) {
            jsonOk = 1;
            L([NSString stringWithFormat:@"[json] %@ (%lu bytes)",
               jsonPath, (unsigned long)jd.length]);
        } else {
            /* fallback: drop the biggest section (sbpl) and retry once */
            [root removeObjectForKey:@"sbpl"];
            jd = [NSJSONSerialization dataWithJSONObject:root
                   options:NSJSONWritingSortedKeys error:NULL];
            if (jd && [jd writeToFile:jsonPath atomically:YES]) {
                jsonOk = 1;
                L([NSString stringWithFormat:@"[json] %@ WITHOUT sbpl (%lu bytes)",
                   jsonPath, (unsigned long)jd.length]);
            }
        }
        if (!jsonOk) L(@"[json] WRITE FAILED — the log above is the only artifact");
    }

    L(@"");
    L(@"=== VERDICT ===");
    L([NSString stringWithFormat:@"[census] hosts=%d binaries=%d services=%d "
       @"found=%d doors=%d json=%@",
       (int)g_p181_hosts.count, (int)progs.count, lookups, found, doors,
       jsonOk ? @"YES" : @"NO"]);
    L(@"[=] READ INTEL ONLY: this census maps doors, it opens none. The");
    L(@"    composition (messaging a door holder) is a separate gated probe.");
    L(@"[=] FOUND is one-sided; not-found needs the Mac-side sbpl diff.");
    L(@"[=] KEYS ONLY. hasKread stays NO — it flips ONLY on kread32(kbase).");

    [[P007Board shared] recordEvent:@"p181_door_census"
                                 kind:@"census"
                               detail:[NSString stringWithFormat:
                                       @"hosts=%d found=%d doors=%d",
                                       (int)g_p181_hosts.count, found, doors]
                               source:@"p181"];
    if (fd >= 0) { fcntl(fd, F_FULLFSYNC); close(fd); }
    return log;
}

@end
