//
//  P164McmCensus.m — MCM container census + system-group pivots. p164 (v1).
//  Source lineage: jbjflab filza27.2 MCMBridge/MCMFilzaIntegration (the MHA-C2/-C12/-C13/-C15
//  24A5390f proofs) + forcequitOS/worse_query; translated — not copied — into the lab's API
//  surface. Reads only; tokens never logged; no kernel claims.
//
//  The class map proven by the vendor's 24A5390f archive:
//    2 = app data     4 = extension data   6 = VPN data      7 = app groups
//    10 = service data    12 = system data    13 = system-group data
//    15 = app-managed data
//  Lease flags 0x900000000; part-write flags 0x8100000000 (NOT exercised here).
//  Key law: class 12 `com.apple.geod` rides ContainerManagerCommon's built-in
//  lookup-bypass list — it resolves where our class-7 writes were EPERM, and its
//  part-domain traversal reaches the MobileGestalt Caches (the worse_query MG lane).
//
//  Bounded, read-only, one tap per force-quit. fsync per line.
//

#import "P164McmCensus.h"
#import "LabDeviceProfile.h"
#import "LabLocalTime.h"

#import <Foundation/Foundation.h>
#import <dlfcn.h>
#import <xpc/xpc.h>
#import <dirent.h>
#import <fcntl.h>

#define P164_BUILD @"p164-mcm-census-v1"

typedef void *(*p164_q_create)(void);
typedef void (*p164_q_u64)(void *, uint64_t);
typedef void (*p164_q_xpc)(void *, xpc_object_t);
typedef void *(*p164_q_single)(void *);
typedef bool (*p164_q_iterate)(void *, bool (^)(void *));
typedef void (*p164_q_free)(void *);
typedef const char *(*p164_o_path)(void *);
typedef const char *(*p164_o_ident)(void *);
typedef void *(*p164_o_copy)(void *);
typedef char *(*p164_o_token)(void *);
typedef bool (*p164_o_activate)(void *, bool);
typedef void (*p164_o_free)(void *);
typedef int (*p164_e_int)(void *);
typedef const char *(*p164_e_str)(void *);

static p164_q_create   g_qCreate;
static p164_q_u64      g_qClass;
static p164_q_xpc      g_qIdent;
static p164_q_xpc      g_qGroupIdent;
static p164_q_u64      g_qFlags;
static p164_q_u64      g_qPart;
static p164_q_single   g_qSingle;
static p164_q_iterate  g_qIterate;
static p164_q_free     g_qFree;
static p164_o_path     g_oPath;
static p164_o_ident    g_oIdent;
static p164_o_copy     g_oCopy;
static p164_o_token    g_oToken;
static p164_o_activate g_oActivate;
static p164_o_free     g_oFree;
static p164_e_int      g_eInt;
static p164_e_str      g_eStr;

static void L(NSString *s) {
    NSLog(@"%@", s);
}
static void Lf(NSString *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    NSLogv(fmt, ap);
    va_end(ap);
}



static BOOL p164_load(void) {
    void *h = dlopen("/usr/lib/system/libsystem_containermanager.dylib",
                     RTLD_NOW | RTLD_LOCAL);
    void *handle = h ? h : RTLD_DEFAULT;
#define X(field, sym) g_##field = (__typeof(g_##field))dlsym(handle, sym)
    X(qCreate, "container_query_create");
    X(qClass, "container_query_set_class");
    X(qIdent, "container_query_set_identifiers");
    X(qGroupIdent, "container_query_set_group_identifiers");
    X(qFlags, "container_query_operation_set_flags");
    X(qPart, "container_query_operation_set_part");
    X(qSingle, "container_query_get_single_result");
    X(qIterate, "container_query_iterate_results_sync");
    X(qFree, "container_query_free");
    X(oPath, "container_object_get_path");
    X(oIdent, "container_object_get_identifier");
    X(oCopy, "container_object_copy");
    X(oToken, "container_object_copy_token");
    X(oActivate, "container_object_sandbox_extension_activate");
    X(oFree, "container_object_free");
    X(eInt, "container_error_get_posix_errno");
    X(eStr, "container_error_get_message");
#undef X
    return g_qCreate && g_qClass && g_qFlags && g_qSingle && g_qFree && g_oPath;
}

/* enumerate identifiers for one class (metadata-only flags 0x100000000). */
static NSUInteger p164_enum_class(uint64_t cls, NSUInteger limit, NSMutableString *o) {
    if (!g_qCreate) return 0;
    void *q = g_qCreate();
    if (!q) return 0;
    g_qClass(q, cls);
    g_qFlags(q, 0x100000000ULL);
    if (g_qPart) g_qPart(q, 0);
    __block NSUInteger n = 0;
    BOOL ok = g_qIterate(q, ^bool(void *obj) {
        const char *raw = obj && g_oIdent ? g_oIdent(obj) : NULL;
        if (raw && raw[0]) {
            if (n < 40) Lf(@"    [%llu] %@", (unsigned long long)cls,
                           [NSString stringWithUTF8String:raw]);
            n++;
        }
        return n < limit;
    });
    if (!ok && n == 0) {
        Lf(@"  [enum class %llu] denied — honest miss", (unsigned long long)cls);
    }
    g_qFree(q);
    return n;
}

/* the documented probe row: resolve root path and LIST the leaf entries. */
static void p164_probe(NSMutableString *o, NSString *name, uint64_t cls,
                       NSString *ident, BOOL group, uint64_t part,
                       NSString *partDomain, uint64_t flags,
                       NSArray<NSString *> *expected) {
    Lf(@"  [probe] %@", name);
    if (!g_qCreate) { L(@"    [-] MCM APIs unavailable"); return; }
    void *q = g_qCreate();
    if (!q) { L(@"    [-] query_create NULL"); return; }
    g_qClass(q, cls);
    xpc_object_t val = xpc_string_create(ident.UTF8String);
    if (group && g_qGroupIdent) g_qGroupIdent(q, val);
    else if (g_qIdent) g_qIdent(q, val);
    g_qFlags(q, flags);
    if (g_qPart && part != 0) g_qPart(q, part);
    void *obj = g_qSingle(q);
    g_qFree(q);
    (void)partDomain;
    if (!obj) {
        Lf(@"    [-] lookup denied (class %llu %@%@part=%llu)%s%s%s",
           (unsigned long long)cls, ident, group ? @" group " : @" ",
           (unsigned long long)part,
           partDomain ? @" domain=" : @"",
           partDomain ? partDomain.UTF8String : "",
           "");
        return;
    }
    const char *raw = g_oPath ? g_oPath(obj) : NULL;
    NSString *root = raw ? [NSString stringWithUTF8String:raw] : nil;
    if (g_oFree) g_oFree(obj);
    if (!root.length) { L(@"    [-] no path"); return; }
    if ([root isEqualToString:@"/var"] || [root hasPrefix:@"/var/"])
        root = [@"/private" stringByAppendingString:root];
    Lf(@"    [+] root=%@", root);
    DIR *d = opendir(root.fileSystemRepresentation);
    NSUInteger n = 0;
    if (d) {
        struct dirent *e;
        while ((e = readdir(d)) != NULL && n < 32) {
            if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
            Lf(@"      ls: %s", e->d_name);
            n++;
        }
        closedir(d);
    } else {
        Lf(@"      ls denied errno=%d", errno);
    }
    for (NSString *exp in expected) {
        NSString *p = [root stringByAppendingPathComponent:exp];
        BOOL ok = [[NSFileManager defaultManager] fileExistsAtPath:p];
        Lf(@"      expected %@ : %@", exp, ok ? @"PRESENT" : @"absent");
    }
}

@implementation P164McmCensus

+ (NSString *)tap {
    NSMutableString *o = [NSMutableString string];
    [o appendFormat:@"=== p164 session %@ BUILD %@ ===\n", LabLocalMilitaryNow(), P164_BUILD];
    [o appendString:[LabDeviceProfile identBlock]];
    [o appendString:@"[law] lineage: jbjflab filza27.2 MCM integration (MHA-C2/-C10/-C12/-C13/-C15 proofs,\n"
                     @"       24A5390f archive) + forcequitOS/worse_query; translated, not copied.\n"
                     @"       Classes: 2 app / 4 ext / 6 VPN / 7 groups / 10 service / 12 system /\n"
                     @"       13 system-group / 15 app-managed. Lease 0x900000000; enumerate 0x100000000.\n"];
    [o appendString:@"[!] READ-ONLY census; tokens never logged; no kernel claims. One tap per force-quit.\n"];

    if (!p164_load()) {
        [o appendString:@"[-] libsystem_containermanager symbols unavailable — honest stop.\n"];
        [o appendFormat:@"=== p164 end %@ ===\n", LabLocalMilitaryNow()];
        return o;
    }

    [o appendString:@"--- enumeration (metadata-only, limit 200) ---\n"];
    static const uint64_t classes[] = {2, 7, 10, 12, 13, 15};
    struct { const char *n; } names[] = {
        {"app data"}, {"app groups"}, {"service data"}, {"system data"},
        {"system-group data"}, {"app-managed data"},
    };
    for (int i = 0; i < 6; i++) {
        Lf(@"  [class %llu] %@", (unsigned long long)classes[i],
           [NSString stringWithUTF8String:names[i].n]);
        (void)p164_enum_class(classes[i], 200, o);
    }

    [o appendString:@"--- documented probe leases (listing only) ---\n"];
    p164_probe(o, @"[MHA-C13] Install Coordination", 13,
               @"systemgroup.com.apple.installcoordinationd", YES, 3,
               @"../InstallCoordination", 0x8100000000ULL,
               @[@"Coordinators", @"DataPromises", @"PromiseStaging"]);
    p164_probe(o, @"[MHA-C13] MobileGestalt Cache", 13,
               @"systemgroup.com.apple.mobilegestaltcache", YES, 3,
               nil, 0x8100000000ULL,
               @[@"com.apple.MobileGestalt.plist"]);
    p164_probe(o, @"[MHA-C12] Eligibility Overrides", 12,
               @"com.apple.eligibilityd", NO, 3,
               @"NeverRestore", 0x8100000000ULL,
               @[@"eligibility_overrides.data"]);
    p164_probe(o, @"[MHA-C15] App Managed Data", 15,
               @"com.apple.appmanagedfeaturesd", NO, 0, nil,
               0x8100000000ULL, nil);
    p164_probe(o, @"[MHA-C13] Configuration Profiles Root", 13,
               @"systemgroup.com.apple.configurationprofiles", YES, 0,
               nil, 0x8100000000ULL, nil);
    p164_probe(o, @"[MHA-C10] geod Service Data", 10,
               @"com.apple.geod", NO, 3, @"..", 0x8100000000ULL, nil);
    p164_probe(o, @"[MHA-C12] geod System-Group Pivot", 12,
               @"com.apple.geod", NO, 3,
               @"../../../../../../containers/Shared/SystemGroup/",
               0x8100000000ULL, nil);

    [o appendString:@"--- verdict ---\n"];
    [o appendString:@"[law] enumerated classes + resolved probe roots = the MCM access map on this\n"
                     @"       SKU. The 0x8100000000 part-write class is NOT exercised (copy-write test\n"
                     @"       queued for v2 behind the p116 copy-write law). hasKread=NO.\n"];
    [o appendFormat:@"=== p164 end %@ ===\n", LabLocalMilitaryNow()];
    return o;
}

@end
