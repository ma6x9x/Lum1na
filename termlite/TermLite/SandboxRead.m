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
    if (total > 0 && outPath)
        return @{@"path": outPath, @"bytes": @(total), @"error": [NSNull null]};
    return @{@"path": [NSNull null], @"bytes": @(total), @"error": @"open/read refused"};
}

@end
