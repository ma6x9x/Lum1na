//
//  P118BootLearn.m — the BOOT-LEARNER slice (note 281). p118. P007 rig.
//
//  One tap = ONE TRAINING EVENT for this boot:
//    1. IDENT (LabDeviceProfile)
//    2. DERIVE (LabKernelOffsetsResolveRunning — p090's resolver, in-process)
//       → Documents/boot_learning/<bootId>/offsets.json (curated fields +
//         the full description text), plus latest.json for tooling
//    3. ECHO (the entitlement view: application-groups + get-task-allow +
//       platform-application types/values — the stripped-vs-honored map)
//    4. LEARN pointer = the shared LabBandit ledger stamps its own bootId
//       (the attribution law); this probe's JSON + that ledger = the pair
//       the pipeline reads.
//    5. COMMIT = the next intel-row diff reads these files (the byte-verify
//       law stays manual until a device writes the commit step).
//  READ-ONLY. Every field = from the fleet's existing modules; no KWR.
//

#import "P118BootLearn.h"
#import "LabDeviceProfile.h"
#import "LabLocalTime.h"
#import "LabKernelOffsets.h"

#import <Foundation/Foundation.h>
#import <CoreFoundation/CoreFoundation.h>
#import <dlfcn.h>
#import <fcntl.h>
#import <sys/sysctl.h>
#import <unistd.h>
#import <string.h>

#define P118_BUILD @"p118-bootlearn-v1"

typedef struct void_SecTask SecTask;
static SecTask *(*g_secTaskCreate)(CFAllocatorRef);
static CFTypeRef (*g_secTaskCopyValue)(SecTask *, CFStringRef);

static NSMutableString *g_log = nil;
static int g_fd = -1;
static void L(NSString *s) {
    if (!g_log) return;
    NSString *out = [s hasSuffix:@"\n"] ? s : [s stringByAppendingString:@"\n"];
    [g_log appendString:out];
    if (g_fd >= 0) {
        const char *p = out.UTF8String;
        if (p) { (void)write(g_fd, p, strlen(p)); (void)fcntl(g_fd, F_FULLFSYNC); }
    }
}
static void Lf(NSString *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    NSString *line = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    L(line);
}

static NSString *p118_bootId(void) {
    struct timeval t; size_t l = sizeof t;
    int mib[2] = { CTL_KERN, KERN_BOOTTIME };
    if (sysctl(mib, 2, &t, &l, NULL, 0) == 0)
        return [NSString stringWithFormat:@"%lld%03d", (long long)t.tv_sec, (int)(t.tv_usec / 1000)];
    return @"unknown-boot";
}

static void p118_jsonField(NSMutableString *j, NSString *k, NSString *v, BOOL *first) {
    if (!*first) [j appendString:@","];
    [j appendFormat:@"\n  \"%@\": \"%@\"", k, v];
    *first = NO;
}

static NSString *p118_echoType(CFStringRef key) {
    if (!g_secTaskCreate || !g_secTaskCopyValue) return @"[no SecTask]";
    SecTask *t = g_secTaskCreate(kCFAllocatorDefault);
    if (!t) return @"[task-fail]";
    CFTypeRef v = g_secTaskCopyValue(t, key);
    NSString *out;
    CFTypeID tid = v ? CFGetTypeID(v) : 0;
    if (v && tid == CFStringGetTypeID())
        out = [NSString stringWithFormat:@"STRING(%@)", (__bridge NSString *)v];
    else if (v && tid == CFArrayGetTypeID())
        out = [NSString stringWithFormat:@"ARRAY(%lu)", (unsigned long)CFArrayGetCount((CFArrayRef)v)];
    else if (v && tid == CFBooleanGetTypeID())
        out = CFBooleanGetValue((CFBooleanRef)v) ? @"BOOL(true)" : @"BOOL(false)";
    else if (v && tid == CFNumberGetTypeID())
        out = @"NUMBER";
    else if (v)
        out = [NSString stringWithFormat:@"OTHER(tid=%lu)", (unsigned long)tid];
    else
        out = @"NIL(stripped)";
    if (v) CFRelease(v);
    if (t) CFRelease(t);
    return out;
}

@implementation P118BootLearn

+ (NSString *)tap {
    g_log = [NSMutableString string];
    NSString *docs = [NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    g_fd = open([[docs stringByAppendingPathComponent:@"p118_bootlearn_log.txt"] UTF8String],
                O_CREAT | O_WRONLY | O_TRUNC, 0644);

    Lf(@"=== p118 session %@ BUILD %@ ===", LabLocalMilitaryNow(), P118_BUILD);
    L([LabDeviceProfile identBlock]);
    L(@"[law] one tap = one training event: DERIVE(per-boot offsets.json) +");
    L(@"  ECHO(entitlement map) + the LabBandit ledger's own bootId attribution");
    L(@"  = the pair the pipeline reads. READ-ONLY; no KWR.");

    /* ---- Phase 2: DERIVE ---- */
    LabKernelOffsets ko;
    BOOL ok = LabKernelOffsetsResolveRunning(&ko);
    NSString *bootId = p118_bootId();
    Lf(@"[*] bootId=%@ resolver=%@", bootId, ok ? @"OK" : @"FAILED");

    NSMutableString *j = [NSMutableString string];
    [j appendFormat:@"{\n  \"bootId\": \"%@\",\n  \"machine\": \"%@\",\n  \"osversion\": \"%@\",\n  \"staticBase\": \"0xfffffff007004000\",\n",
        bootId, LabDeviceProfile.machine, LabDeviceProfile.osversion];
    BOOL first = YES;
    if (ok) {
        #define P118_F(f) p118_jsonField(j, @#f, [NSString stringWithFormat:@"0x%llx", (unsigned long long)ko.f], &first)
        P118_F(socket_usecount); P118_F(inpcb_icmp6filt); P118_F(inpcb_socket);
        P118_F(proc_pid); P118_F(proc_ucred); P118_F(proc_ro_ucred);
        P118_F(task_itk_space); P118_F(task_bsd_info); P118_F(task_map);
        P118_F(task_task_can_transfer_memory_ownership);
        P118_F(IOSurface_memoryDescriptor); P118_F(IOMachPort_object);
        P118_F(pmap_pmap_cs_main); P118_F(ucred_cr_uid); P118_F(ucred_cr_label);
        P118_F(filedesc_ofiles_start); P118_F(socket_proto);
        #undef P118_F
    }
    [j appendString:@",\n  \"entitlements\": {\n"];
    // Phase 3: ECHO
    void *sec = dlopen("/System/Library/Frameworks/Security.framework/Security", RTLD_NOW);
    if (!sec) sec = RTLD_DEFAULT;
    g_secTaskCreate    = (SecTask *(*)(CFAllocatorRef))dlsym(sec, "SecTaskCreateFromSelf");
    g_secTaskCopyValue = (CFTypeRef (*)(SecTask *, CFStringRef))dlsym(sec, "SecTaskCopyValueForEntitlement");
    struct { const char *k; } ekeys[] = {
        { "com.apple.security.application-groups" },
        { "get-task-allow" },
        { "platform-application" },
        { "com.apple.private.security.no-sandbox" },
        { "com.apple.security.exception.iokit-user-client-class" },
        { "com.apple.security.exception.mach-lookup.global-name" },
    };
    {
        BOOL f2 = YES;
        for (int i = 0; i < (int)(sizeof ekeys / sizeof ekeys[0]); i++) {
            NSString *key = [NSString stringWithUTF8String:ekeys[i].k];
            NSString *val = p118_echoType((__bridge CFStringRef)key);
            if (!f2) [j appendString:@",\n  "];
            [j appendFormat:@"\"%@\": \"%@\"", key, val];
            f2 = NO;
            Lf(@"[echo] %@ = %@", key, val);
        }
    }
    [j appendString:@"\n  }\n}\n"];

    /* write the files */
    NSString *dir = [docs stringByAppendingPathComponent:@"boot_learning"];
    dir = [dir stringByAppendingPathComponent:bootId];
    [[NSFileManager defaultManager] createDirectoryAtPath:dir
                              withIntermediateDirectories:YES attributes:nil error:nil];
    NSString *jp = [dir stringByAppendingPathComponent:@"offsets.json"];
    [j writeToFile:jp atomically:YES encoding:NSUTF8StringEncoding error:nil];
    NSString *lp = [docs stringByAppendingPathComponent:@"boot_learning/latest.json"];
    [j writeToFile:lp atomically:YES encoding:NSUTF8StringEncoding error:nil];
    Lf(@"[*] DERIVE written: %@", jp);
    L(j);   /* the whole slice prints for paste-back */

    L(@"=== VERDICT (honest) ===");
    L(@"- This file pair (offsets.json + the bandit ledger's bootId rows) = the");
    L(@"  training event the pipeline reads; repeat taps on the same boot = the");
    L(@"  idempotency check; reboot = the next epoch.");
    L(@"- The COMMIT phase (intel-row diff from these files) stays manual/agent-side");
    L(@"  (the byte-verify law) until the auto-commit step ships.");
    L(@"READ-ONLY. hasKread=NO (the resolver = DB logic, not kernel reads).");

finish:
    if (g_fd >= 0) { (void)fcntl(g_fd, F_FULLFSYNC); (void)close(g_fd); g_fd = -1; }
    NSString *ret = g_log; g_log = nil;
    return ret;
}

@end