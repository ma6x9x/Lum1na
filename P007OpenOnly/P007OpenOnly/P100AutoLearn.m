//
//  P100AutoLearn.m
//  Lum1na-Debug
//
//  P100 AutoLearn v1 — the "learner" half of Lum1na-Debug. Heuristic
//  inference + oracle validation, NOT a trained model: it classifies the
//  running device/kernel from userspace-visible facts, validates which known
//  table row is nearest, and emits a LEARN PACKET that becomes a new LabOff
//  row (Ghidra first — never pasted blind). Honesty: zero kernel writes, zero
//  IOConnect selector calls, hasKread unchanged. On unknown SKUs the
//  kernel-VA probes HOLD as always; AutoLearn is what tells us WHICH row to
//  create so they stop HOLDing.
//

#import "P100AutoLearn.h"
#import "LabDeviceProfile.h"
#import "LabLocalTime.h"
#import "P007Board.h"

#import <dlfcn.h>
#import <fcntl.h>
#import <string.h>
#import <unistd.h>
#import <sys/stat.h>
#import <sys/sysctl.h>
#import <sys/time.h>
#import <mach/mach.h>

#define P100_BUILD "p100-autolearn-v1"

static NSMutableString *g_al_buf = NULL;
static int g_al_fd = -1;

static void al_flush_line(NSString *line) {
    if (g_al_fd >= 0) {
        const char *s = line.UTF8String;
        ssize_t rc = write(g_al_fd, s, strlen(s));
        (void)rc;
        fcntl(g_al_fd, F_FULLFSYNC);
    }
}

static void L(NSString *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    NSString *line = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    if (![line hasSuffix:@"\n"]) line = [line stringByAppendingString:@"\n"];
    @synchronized ([P100AutoLearn class]) {
        [g_al_buf appendString:line];
        al_flush_line(line);
    }
}

/* ---- sysctl helpers (honest DENIED markers) ---- */

static NSString *al_sys_str(const char *name, BOOL *ok) {
    size_t len = 0;
    if (sysctlbyname(name, NULL, &len, NULL, 0) != 0 || len == 0) { if (ok) *ok = NO; return nil; }
    char *buf = malloc(len + 1);
    if (!buf) { if (ok) *ok = NO; return nil; }
    memset(buf, 0, len + 1);
    if (sysctlbyname(name, buf, &len, NULL, 0) != 0) { free(buf); if (ok) *ok = NO; return nil; }
    if (ok) *ok = YES;
    NSString *v = [NSString stringWithUTF8String:buf];
    free(buf);
    return v;
}

static long long al_sys_int(const char *name, BOOL *ok) {
    long long v = 0; size_t len = sizeof(v);
    if (sysctlbyname(name, &v, &len, NULL, 0) != 0) { if (ok) *ok = NO; return 0; }
    if (ok) *ok = YES;
    return v;
}

/* SoC family from the kernel string tag (inference, marked as such). */
static NSString *al_chip_family(NSString *tag) {
    NSDictionary *map = @{
        @"T8020": @"A12/A12X-class",
        @"T8101": @"A14-class",
        @"T8103": @"A13-class (M1 shares T8103)",
        @"T8110": @"A15-class",
        @"T8120": @"A16-class",
        @"T8130": @"A17-class",
        @"T8140": @"A17 Pro/M3-class",
        @"T8150": @"M4-class",
    };
    return map[tag] ?: @"UNKNOWN TAG (new SoC class — record verbatim)";
}

/* darwin major -> iOS family (inference). */
static NSString *al_darwin_family(long long darwinMajor) {
    if (darwinMajor >= 25) return [NSString stringWithFormat:@"darwin %lld -> iOS 26.x family", darwinMajor];
    if (darwinMajor == 24) return @"darwin 24 -> iOS 18.x family";
    if (darwinMajor == 23) return @"darwin 23 -> iOS 17.x family";
    if (darwinMajor == 22) return @"darwin 22 -> iOS 16.x family";
    return [NSString stringWithFormat:@"darwin %lld -> other/older", darwinMajor];
}

/* ---- IOKit via dlopen/dlsym (lab convention, P042 shape) ---- */

typedef CFDictionaryRef (*al_IOServiceMatching_t)(const char *name);
typedef mach_port_t (*al_IOServiceGetMatchingService_t)(mach_port_t mainPort, CFDictionaryRef matching);
typedef kern_return_t (*al_IOServiceOpen_t)(mach_port_t service, task_t task, uint32_t type, mach_port_t *conn);
typedef kern_return_t (*al_IOServiceClose_t)(mach_port_t conn);
typedef kern_return_t (*al_IOObjectRelease_t)(mach_port_t object);
typedef CFTypeRef (*al_iosCreate_t)(CFDictionaryRef properties);

@implementation P100AutoLearn

+ (NSString *)tap {
    @synchronized ([P100AutoLearn class]) {
        g_al_buf = [NSMutableString string];
        NSString *docs = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
        NSString *path = [docs stringByAppendingPathComponent:@"p100_learn_log.txt"];
        g_al_fd = open(path.fileSystemRepresentation, O_CREAT | O_WRONLY | O_APPEND, 0644);

        NSString *ret = nil;
        @try {
            ret = [self runLearn];
        } @catch (NSException *ex) {
            L(@"[-] autolearn exception: %@ (%@)", ex.name, ex.reason);
            ret = [g_al_buf copy] ?: @"p100 exception";
        }
        if (g_al_fd >= 0) { close(g_al_fd); g_al_fd = -1; }
        return ret ?: [g_al_buf copy] ?: @"";
    }
}

+ (NSString *)runLearn {
    size_t kinfoLen = 0;
    NSString *docs = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    L(@"=== p100 session %@ BUILD %s ===", LabLocalMilitaryNow() ?: @"?", P100_BUILD);
    L(@"AutoLearn: READ-ONLY learner. No kwrite, no IOConnect selector calls, hasKread unchanged.");
    L(@"%@", [LabDeviceProfile identBlock] ?: @"ident ?");
    L(@"[*] SKU gate mode: %@", [LabDeviceProfile gateMode]);
    L(@"[*] offset table  : %@ (LabOff runtime table)",
      [NSString stringWithUTF8String:(LabOff() && LabOff()->tag) ? LabOff()->tag : "none"]);

    /* ---- 1. deep IDENT sweep ---- */
    L(@"=== DEEP IDENT SWEEP ===");
    const char *strKeys[] = {
        "kern.ostype", "kern.osrelease", "kern.osversion", "kern.version",
        "kern.osproductversion", "hw.machine", "hw.model", "kern.secure_kernel",
    };
    for (size_t i = 0; i < sizeof(strKeys) / sizeof(strKeys[0]); i++) {
        BOOL ok = NO;
        NSString *v = al_sys_str(strKeys[i], &ok);
        if (ok) L(@"[*] %-22s = %@", strKeys[i], v);
        else    L(@"[-] %-22s = denied/absent (honest)", strKeys[i]);
    }
    const char *intKeys[] = {
        "kern.maxproc", "kern.maxfilesperproc", "kern.usrstack", "kern.argmax",
        "hw.ncpu", "hw.memsize", "hw.pagesize", "hw.cputype", "hw.cpusubtype",
        "hw.byteorder", "hw.l3cachesize", "hw.tbfrequency",
    };
    for (size_t i = 0; i < sizeof(intKeys) / sizeof(intKeys[0]); i++) {
        BOOL ok = NO;
        long long v = al_sys_int(intKeys[i], &ok);
        if (ok) L(@"[*] %-22s = %lld (0x%llx)", intKeys[i], v, (unsigned long long)v);
        else    L(@"[-] %-22s = denied/absent (honest)", intKeys[i]);
    }
    {
        struct timeval bt; size_t len = sizeof(bt);
        if (sysctlbyname("kern.boottime", &bt, &len, NULL, 0) == 0 && len >= sizeof(bt)) {
            L(@"[*] %-22s = %@ epoch sec %ld", "kern.boottime",
              [NSDate dateWithTimeIntervalSince1970:(double)bt.tv_sec], (long)bt.tv_sec);
        } else {
            L(@"[-] %-22s = denied/absent (honest)", "kern.boottime");
        }
    }

    /* ---- 2. chip tag + darwin family (the "learn" core) ---- */
    L(@"=== CHIP / KERNEL CLASS ===");
    BOOL kverOk = NO;
    NSString *kver = al_sys_str("kern.version", &kverOk);
    NSString *chipTag = nil;
    if (kverOk) {
        NSRegularExpression *re = [NSRegularExpression
            regularExpressionWithPattern:@"RELEASE_ARM64_([A-Z0-9]+)" options:0 error:nil];
        NSTextCheckingResult *m = [re firstMatchInString:kver options:0 range:NSMakeRange(0, kver.length)];
        if (m && m.numberOfRanges > 1) chipTag = [kver substringWithRange:[m rangeAtIndex:1]];
    }
    if (chipTag) {
        L(@"[*] chip tag (kern.version RELEASE_ARM64_*): %@ -> %@ [inference]",
          chipTag, al_chip_family(chipTag));
    } else {
        L(@"[-] chip tag not parsed from kern.version — packet still useful (honest miss).");
    }
    BOOL relOk = NO;
    NSString *osrel = al_sys_str("kern.osrelease", &relOk);
    long long darwinMajor = 0;
    if (relOk && osrel.length) {
        darwinMajor = [[osrel componentsSeparatedByString:@"."] firstObject].longLongValue;
        L(@"[*] darwin major: %lld -> %@ [inference]", darwinMajor, al_darwin_family(darwinMajor));
    }

    /* ---- 3. ABI fingerprint ---- */
    L(@"=== ABI FINGERPRINT ===");
    {
        int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, (int)getpid() };
        uint8_t kp[2048]; memset(kp, 0, sizeof(kp));
        size_t len = sizeof(kp);
        if (sysctl(mib, 4, kp, &len, NULL, 0) == 0) {
            kinfoLen = len;
            L(@"[*] kinfo_proc len = %zu bytes (ABI row for this build)", len);
        } else {
            L(@"[-] kinfo_proc size probe failed (errno %d) - honest miss.", errno);
        }
        L(@"[*] pid=%d uid=%d gid=%d", (int)getpid(), (int)getuid(), (int)getgid());
    }

    /* ---- 4. IOKit door census (opens only) ---- */
    L(@"=== IOKIT DOOR CENSUS (opens only, no selectors) ===");
    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    NSDictionary *doors = nil;
    if (!iokit) {
        L(@"[-] dlopen IOKit failed: %s — census skipped (honest).", dlerror());
    } else {
        al_IOServiceMatching_t        pMatch  = (al_IOServiceMatching_t)dlsym(iokit, "IOServiceMatching");
        al_IOServiceGetMatchingService_t pGet = (al_IOServiceGetMatchingService_t)dlsym(iokit, "IOServiceGetMatchingService");
        al_IOServiceOpen_t            pOpen   = (al_IOServiceOpen_t)dlsym(iokit, "IOServiceOpen");
        al_IOServiceClose_t           pClose  = (al_IOServiceClose_t)dlsym(iokit, "IOServiceClose");
        al_IOObjectRelease_t          pRel    = (al_IOObjectRelease_t)dlsym(iokit, "IOObjectRelease");
        mach_port_t *pMain = dlsym(iokit, "kIOMainPortDefault");
        if (!pMain) pMain = dlsym(iokit, "kIOMasterPortDefault");
        if (!pMatch || !pGet || !pOpen || !pClose || !pRel || !pMain) {
            L(@"[-] IOKit symbols incomplete — census skipped (honest).");
        } else {
            const char *names[] = {
                "IOSurfaceRoot", "IOGPU", "AGXAccelerator", "AppleH11ANEInterface",
                "H11ANEIn", "H1xANELoadBalancer", "AppleKeyStore", "AppleJPEGDriver",
                "AppleAVE2Driver", "AppleAVD",
            };
            NSMutableDictionary *d = [NSMutableDictionary dictionary];
            for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
                CFDictionaryRef match = pMatch(names[i]);
                if (!match) {
                    L(@"[-] %-22s not found", names[i]);
                    d[[NSString stringWithUTF8String:names[i]]] = @"nf";
                    continue;
                }
                mach_port_t svc = pGet(*pMain, match);
                CFRelease(match);
                if (svc == MACH_PORT_NULL) {
                    L(@"[-] %-22s matched but service port null", names[i]);
                    d[[NSString stringWithUTF8String:names[i]]] = @"nullsvc";
                    continue;
                }
                mach_port_t c0 = MACH_PORT_NULL, c1 = MACH_PORT_NULL;
                kern_return_t k0 = pOpen(svc, mach_task_self_, 0, &c0);
                kern_return_t k1 = pOpen(svc, mach_task_self_, 1, &c1);
                L(@"[*] %-22s open type0 kr=0x%x conn=%@  type1 kr=0x%x conn=%@",
                  names[i], k0, c0 != MACH_PORT_NULL ? @"open" : @"-",
                  k1, c1 != MACH_PORT_NULL ? @"open" : @"-");
                d[[NSString stringWithUTF8String:names[i]]] =
                    [NSString stringWithFormat:@"t0=0x%x/t1=0x%x", k0, k1];
                if (c0 != MACH_PORT_NULL) pClose(c0);
                if (c1 != MACH_PORT_NULL) pClose(c1);
                pRel(svc);
            }
            doors = d;
        }
        dlclose(iokit);
    }

    /* ---- 5. IOSurface create smoke ---- */
    BOOL surfOk = NO;
    {
        void *h = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
        if (!h) h = dlopen("/System/Library/PrivateFrameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
        if (h) {
            al_iosCreate_t pCreate = (al_iosCreate_t)dlsym(h, "IOSurfaceCreate");
            if (pCreate) {
                NSDictionary *props = @{
                    @"IOSurfaceWidth":  @1,
                    @"IOSurfaceHeight": @1,
                    @"IOSurfaceBytesPerElement": @4,
                };
                CFTypeRef surf = pCreate((__bridge CFDictionaryRef)props);
                if (surf) { CFRelease(surf); surfOk = YES; }
            }
            dlclose(h);
        }
        L(@"[%@] IOSurface create smoke (1x1 BGRA)", surfOk ? @"+" : @"-");
    }

    /* ---- 6. classifier verdict ---- */
    L(@"=== CLASSIFIER VERDICT ===");
    LabSku s = [LabDeviceProfile detectedSku];
    NSString *skuStr = [LabDeviceProfile skuString] ?: @"unknown";
    BOOL hasRow = (LabOffForSku(s) != NULL);
    NSString *verdict;
    if (hasRow) {
        verdict = [NSString stringWithFormat:@"KNOWN: sku %@ has a VA table row — kernel-VA probes runnable.", skuStr];
    } else if (s != LabSkuUnknown) {
        verdict = [NSString stringWithFormat:@"NEAREST: sku %@ recognized but no VA row — primitives run, kernel-VA probes HOLD; this packet becomes a new row.", skuStr];
    } else {
        verdict = @"UNKNOWN: new device/OS class — this packet is the input for a new LabOff row (Ghidra first, never pasted blind).";
    }
    L(@"[*] %@", verdict);
    L(@"[*] honesty: no KRW claim. A failed/absent tap does not close a CVE class.");

    /* ---- 7. LEARN PACKET + registry ---- */
    L(@"=== LEARN PACKET BEGIN (copy this whole block back) ===");
    NSMutableString *pkt = [NSMutableString string];
    [pkt appendFormat:@"machine=%@ osversion=%@ osrelease=%@ darwin=%lld chip_tag=%@ chip_family=%@ ",
      [LabDeviceProfile machine] ?: @"?", [LabDeviceProfile osversion] ?: @"?", osrel ?: @"?",
      darwinMajor, chipTag ?: @"none", chipTag ? al_chip_family(chipTag) : @"none"];
    [pkt appendFormat:@"sku=%@ table=%@ gate=%@ kinfo=%zu doors=%@ iosurface=%d verdict=\"%@\"",
      skuStr, hasRow ? @"yes" : @"no", [LabDeviceProfile gateMode],
      kinfoLen, doors ?: @"census-skipped", surfOk ? 1 : 0, verdict];
    L(@"%@", pkt);
    L(@"=== LEARN PACKET END ===");

    /* JSON-lines registry: Documents/lum1na_learn.json (append, F_FULLFSYNC).
       UIFileSharingEnabled=YES on this app — grab via Finder/Files too. */
    {
        NSString *doorsJson = @"\"census-skipped\"";
        if (doors) {
            NSData *dd = [NSJSONSerialization dataWithJSONObject:doors options:0 error:nil];
            doorsJson = dd ? [[NSString alloc] initWithData:dd encoding:NSUTF8StringEncoding] : @"{}";
        }
        NSString *jl = [NSString stringWithFormat:
            @"{\"ts\":\"%@\",\"machine\":\"%@\",\"osversion\":\"%@\",\"osrelease\":\"%@\","
            "\"darwin\":%lld,\"chip_tag\":\"%@\",\"sku\":\"%@\",\"table\":%@,\"iosurface\":%@,"
            "\"doors\":%@,\"verdict\":\"%@\"}\n",
            LabLocalMilitaryNow() ?: @"?", [LabDeviceProfile machine] ?: @"?", [LabDeviceProfile osversion] ?: @"?",
            osrel ?: @"?", darwinMajor, chipTag ?: @"none", skuStr,
            hasRow ? @"true" : @"false", surfOk ? @"true" : @"false",
            doorsJson, verdict];
        NSString *reg = [docs stringByAppendingPathComponent:@"lum1na_learn.json"];
        int fd = open(reg.fileSystemRepresentation, O_CREAT | O_WRONLY | O_APPEND, 0644);
        if (fd >= 0) {
            const char *bytes = jl.UTF8String;
            write(fd, bytes, strlen(bytes));
            fcntl(fd, F_FULLFSYNC);
            close(fd);
            L(@"[*] registry line appended: Documents/lum1na_learn.json");
        } else {
            L(@"[-] registry open failed (errno %d) - honest miss.", errno);
        }
    }

    [[P007Board shared] recordEvent:@"autolearn"
                               kind:@"learn"
                             detail:[NSString stringWithFormat:@"%@ | %@",
                                     chipTag ?: @"notag", verdict]
                             source:@"p100"];

    L(@"=== p100 end ===");
    return [g_al_buf copy];
}

@end