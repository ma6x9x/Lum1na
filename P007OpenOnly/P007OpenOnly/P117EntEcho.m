//
//  P117EntEcho.m — the AMFI entitlement-echo probe. p117. P007 rig.
//
//  WHY (2026-10-28): the application-groups scalar crash test produced NO
//  crash. Before any escalation claim: WHAT ENTITLEMENTS DOES THE KERNEL
//  ACTUALLY SEE on this sideloaded app? Free-profile signing strips
//  everything not provisioned by the cert — AMFI enforces before the
//  sandbox profile builder runs. This probe prints the kernel's OWN view
//  via SecTaskCopyValueForEntitlement(SecTaskCreateFromSelf, key) — the
//  exact API the sandbox profile ingestion uses — for every key the rig's
//  plist declares, printing the CF TYPE + value + a raw hex for scalars.
//
//  HONESTY: read-only; echoes the app's own task entitlements; no claims.
//

#import "P117EntEcho.h"
#import "LabDeviceProfile.h"
#import "LabLocalTime.h"

#import <Foundation/Foundation.h>
#import <CoreFoundation/CoreFoundation.h>
#import <dlfcn.h>
#import <fcntl.h>
#import <unistd.h>
#import <string.h>

#define P117_BUILD @"p117-entecho-v1"

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

static NSString *p117_echo(CFStringRef key) {
    if (!g_secTaskCreate || !g_secTaskCopyValue) return @"[dlsym missing]";
    SecTask *t = g_secTaskCreate(kCFAllocatorDefault);
    if (!t) return @"[SecTask create failed]";
    CFTypeRef v = g_secTaskCopyValue(t, key);
    NSString *out;
    CFTypeID tid = v ? CFGetTypeID(v) : 0;
    if (v && tid == CFStringGetTypeID()) {
        out = [NSString stringWithFormat:@"STRING \"%@\"", (__bridge NSString *)v];
    } else if (v && tid == CFArrayGetTypeID()) {
        out = [NSString stringWithFormat:@"ARRAY %lu items: %@",
               (unsigned long)CFArrayGetCount((CFArrayRef)v),
               (__bridge NSArray *)v];
    } else if (v && tid == CFBooleanGetTypeID()) {
        out = [NSString stringWithFormat:@"BOOL %@",
               CFBooleanGetValue((CFBooleanRef)v) ? @"true" : @"false"];
    } else if (v && tid == CFNumberGetTypeID()) {
        long long iv = 0; double dv = 0;
        if (CFNumberGetValue((CFNumberRef)v, kCFNumberLongLongType, &iv))
            out = [NSString stringWithFormat:@"INTEGER %lld", iv];
        else if (CFNumberGetValue((CFNumberRef)v, kCFNumberDoubleType, &dv))
            out = [NSString stringWithFormat:@"DOUBLE %f", dv];
        else out = @"NUMBER ?";
    } else if (v && tid == CFDictionaryGetTypeID()) {
        out = [NSString stringWithFormat:@"DICT %lu keys",
               (unsigned long)CFDictionaryGetCount((CFDictionaryRef)v)];
    } else if (v && tid == CFDataGetTypeID()) {
        out = [NSString stringWithFormat:@"DATA %lu bytes",
               (unsigned long)CFDataGetLength((CFDataRef)v)];
    } else if (v) {
        out = [NSString stringWithFormat:@"OTHER typeid=%lu", (unsigned long)tid];
    } else {
        out = @"NIL — STRIPPED/ABSENT (the kernel does not see this key)";
    }
    if (v) CFRelease(v);
    if (t) CFRelease(t);
    return out;
}

@implementation P117EntEcho

+ (NSString *)tap {
    g_log = [NSMutableString string];
    NSString *docs = [NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    g_fd = open([[docs stringByAppendingPathComponent:@"p117_entecho_log.txt"] UTF8String],
                O_CREAT | O_WRONLY | O_TRUNC, 0644);

    Lf(@"=== p117 session %@ BUILD %@ ===", LabLocalMilitaryNow(), P117_BUILD);
    L([LabDeviceProfile identBlock]);
    L(@"[law] SecTaskCopyValueForEntitlement(SecTaskCreateFromSelf, key) = the");
    L(@"  kernel's OWN view of this task's entitlements — the same API class the");
    L(@"  sandbox profile ingestion runs. NIL = the key was STRIPPED at install/");
    L(@"  launch (free-profile AMFI enforcement) — it never reaches the kernel,");
    L(@"  and any crash-experiment on it is VOID.");

    void *sec = dlopen("/System/Library/Frameworks/Security.framework/Security", RTLD_NOW);
    if (!sec) sec = RTLD_DEFAULT;
    g_secTaskCreate   = (SecTask *(*)(CFAllocatorRef))dlsym(sec, "SecTaskCreateFromSelf");
    g_secTaskCopyValue= (CFTypeRef (*)(SecTask *, CFStringRef))dlsym(sec, "SecTaskCopyValueForEntitlement");
    if (!g_secTaskCreate || !g_secTaskCopyValue) {
        L(@"[-] SecTask dlsyms missing — honest stop.");
        goto finish;
    }

    L(@"--- the kernel's view of the rig's declared keys ---");
    Lf(@"application-groups:            %@", p117_echo(CFSTR("com.apple.security.application-groups")));
    Lf(@"platform-application:          %@", p117_echo(CFSTR("platform-application")));
    Lf(@"get-task-allow:                %@", p117_echo(CFSTR("get-task-allow")));
    Lf(@"no-sandbox:                    %@", p117_echo(CFSTR("com.apple.private.security.no-sandbox")));
    Lf(@"no-container:                  %@", p117_echo(CFSTR("com.apple.private.security.no-container")));
    Lf(@"container-required:            %@", p117_echo(CFSTR("com.apple.private.security.container-required")));
    Lf(@"iokit-user-client-class:       %@", p117_echo(CFSTR("com.apple.security.exception.iokit-user-client-class")));
    Lf(@"files.absolute-path.read-write:%@", p117_echo(CFSTR("com.apple.security.exception.files.absolute-path.read-write")));
    Lf(@"mach-lookup.global-name:       %@", p117_echo(CFSTR("com.apple.security.exception.mach-lookup.global-name")));
    Lf(@"private.ane:                   %@", p117_echo(CFSTR("com.apple.private.ane")));
    Lf(@"private.IOSurface:             %@", p117_echo(CFSTR("com.apple.private.IOSurface")));
    Lf(@"task_for_pid-allow:            %@", p117_echo(CFSTR("task_for_pid-allow")));
    Lf(@"override-codesigning:          %@", p117_echo(CFSTR("com.apple.private.kernel.override-codesigning")));

    L(@"=== VERDICT (honest) ===");
    L(@"- NIL lines = stripped by AMFI free-profile enforcement — the corresponding");
    L(@"  kernel-side experiment on that key is VOID on free-signed devices.");
    L(@"- An INTEGER application-groups = the scalar REACHED the kernel → the no-");
    L(@"  crash outcome = the profile builder flattens, not the signing. Two different");
    L(@"  fixes, check which line fired first.");
    L(@"- Any STRING/ARRAY surviving = the free-profile law is wrong for that key —");
    L(@"  that key's whole kernel lane re-opens.");

finish:
    if (g_fd >= 0) { (void)fcntl(g_fd, F_FULLFSYNC); (void)close(g_fd); g_fd = -1; }
    NSString *ret = g_log; g_log = nil;
    return ret;
}

@end