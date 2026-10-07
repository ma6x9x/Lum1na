//
//  P045HybridMap.m
//  P007OpenOnly
//
//  CVE-2026-84523: APFS VNOP Fuzzer
//  Replaces the dead kmsg-recv oracle with an active APFS extent/rename/exchange fuzzer.
//

#import "P045HybridMap.h"
#import "LabLocalTime.h"

#import <Foundation/Foundation.h>
#import <fcntl.h>
#import <unistd.h>
#import <string.h>
#import <pthread.h>
#import <sys/attr.h>
#import <sys/xattr.h>      // FIX: for setxattr/getxattr/removexattr
#import <sys/clonefile.h>  // FIX: for clonefile
#import <errno.h>

// FIX: Manually declare renamex_np since <sys/rename.h> is missing from public SDK
#ifndef RENAME_EXCHANGE
#define RENAME_EXCHANGE 0x00000002
#endif
extern int renamex_np(const char *from, const char *to, unsigned int flags);

#define P045_BUILD @"p045-apfs-vnop-fuzzer-v15"

static NSMutableString *p045_buf;
static int p045_fd = -1;
static volatile int p045_stop = 0;
static volatile int p045_panic = 0;

static void p045_log(NSString *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    NSString *line = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    NSString *out = [line hasSuffix:@"\n"] ? line : [line stringByAppendingString:@"\n"];
    @synchronized ([NSString class]) {
        if (p045_buf) [p045_buf appendString:out];
        if (p045_fd >= 0) {
            const char *s = out.UTF8String;
            if (s) write(p045_fd, s, strlen(s));
        }
    }
}

// Thread 1: Fragmented file creation + truncation (Extent stress)
static void *p045_extent_thread(void *arg) {
    NSString *docs = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    NSString *path = [docs stringByAppendingPathComponent:@"p045_extents.bin"];
    
    while (!p045_stop) {
        int fd = open(path.UTF8String, O_CREAT | O_RDWR | O_TRUNC, 0644);
        if (fd < 0) continue;
        
        // Create highly fragmented file (extents)
        for (int i = 0; i < 100; i++) {
            lseek(fd, i * 16384, SEEK_SET);
            write(fd, "A", 1);
        }
        
        // Truncate to trigger extent cleanup
        ftruncate(fd, 0);
        ftruncate(fd, 16384 * 100);
        
        // Force pageout
        fsync(fd);
        close(fd);
    }
    return NULL;
}

// Thread 2: Rename and Exchange stress (VNOP_RENAME / VNOP_EXCHANGE)
static void *p045_rename_thread(void *arg) {
    NSString *docs = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    NSString *path1 = [docs stringByAppendingPathComponent:@"p045_rename1.bin"];
    NSString *path2 = [docs stringByAppendingPathComponent:@"p045_rename2.bin"];
    
    // Create initial files
    int fd1 = open(path1.UTF8String, O_CREAT | O_RDWR, 0644);
    int fd2 = open(path2.UTF8String, O_CREAT | O_RDWR, 0644);
    if (fd1 >= 0) close(fd1);
    if (fd2 >= 0) close(fd2);
    
    while (!p045_stop) {
        // Standard rename
        rename(path1.UTF8String, path2.UTF8String);
        rename(path2.UTF8String, path1.UTF8String);
        
        // Exchange (renamex_np)
        renamex_np(path1.UTF8String, path2.UTF8String, RENAME_EXCHANGE);
        
        // Clonefile
        clonefile(path1.UTF8String, path2.UTF8String, 0);
        unlink(path2.UTF8String);
    }
    return NULL;
}

// Thread 3: getxattr / setxattr stress (VNOP_GETATTR / VNOP_SETATTR)
static void *p045_attr_thread(void *arg) {
    NSString *docs = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    NSString *path = [docs stringByAppendingPathComponent:@"p045_attrs.bin"];
    
    int fd = open(path.UTF8String, O_CREAT | O_RDWR, 0644);
    if (fd >= 0) close(fd);
    
    while (!p045_stop) {
        // Set and get attributes rapidly
        setxattr(path.UTF8String, "user.p045", "AAAA", 4, 0, 0);
        getxattr(path.UTF8String, "user.p045", NULL, 0, 0, 0);
        removexattr(path.UTF8String, "user.p045", 0);
    }
    return NULL;
}

@implementation P045HybridMap

+ (NSString *)tap {
    p045_buf = [NSMutableString string];
    NSString *docs = NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    NSString *path = [docs stringByAppendingPathComponent:@"p045_kmsg_recv_oracle_log.txt"];
    p045_fd = open(path.UTF8String, O_CREAT | O_WRONLY | O_TRUNC, 0644);

    p045_log(@"=== p045 session %@ BUILD %@ ===", LabLocalMilitaryNow(), P045_BUILD);
    p045_log(@"CVE-2026-84523: APFS VNOP Fuzzer");
    p045_log(@"Stressing extents, rename, exchange, clone, and attrs.");
    p045_log(@"If kernel panics, we found the APFS OOB write.");
    p045_log(@"");
    
    p045_stop = 0;
    p045_panic = 0;
    
    pthread_t t1, t2, t3;
    pthread_create(&t1, NULL, p045_extent_thread, NULL);
    pthread_create(&t2, NULL, p045_rename_thread, NULL);
    pthread_create(&t3, NULL, p045_attr_thread, NULL);
    
    p045_log(@"[*] Fuzzing for 30 seconds...");
    
    for (int t = 5; t <= 30; t += 5) {
        sleep(5);
        p045_log(@"[race] t=%ds", t);
    }
    
    p045_stop = 1;
    pthread_join(t1, NULL);
    pthread_join(t2, NULL);
    pthread_join(t3, NULL);
    
    p045_log(@"");
    p045_log(@"=== FINAL ===");
    if (p045_panic) {
        p045_log(@"*** PANIC DETECTED — APFS OOB write triggered! ***");
        p045_log(@"Check panic log for APFS function name.");
    } else {
        p045_log(@"SURVIVED clean — APFS VNOPs did not panic.");
        p045_log(@"Next: Ghidra diff 23F77 vs 23G90 APFS kext to find the exact bounds check.");
    }
    
    // Cleanup
    NSString *docsPath = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    unlink([[docsPath stringByAppendingPathComponent:@"p045_extents.bin"] UTF8String]);
    unlink([[docsPath stringByAppendingPathComponent:@"p045_rename1.bin"] UTF8String]);
    unlink([[docsPath stringByAppendingPathComponent:@"p045_rename2.bin"] UTF8String]);
    unlink([[docsPath stringByAppendingPathComponent:@"p045_attrs.bin"] UTF8String]);

    if (p045_fd >= 0) {
        fcntl(p045_fd, F_FULLFSYNC);
        close(p045_fd);
        p045_fd = -1;
    }
    return p045_buf ?: @"";
}

@end
