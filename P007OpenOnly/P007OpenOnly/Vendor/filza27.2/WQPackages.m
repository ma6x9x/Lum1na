//
//  WQPackages.m
//  FilzaSlop
//
//  In-process dpkg/apt for the normally signed build. Packages are unpacked
//  under Documents/.terminal/root; this is a plugin/utility prefix, not the
//  system root, because the app is sandboxed.
//

#import "WQPackages.h"

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <errno.h>
#import <fcntl.h>
#import <sys/stat.h>
#import <unistd.h>

typedef struct archive WQArchive;
typedef struct archive_entry WQArchiveEntry;

#define WQ_ARCHIVE_OK 0
#define ARCHIVE_OK 0
#define WQ_AE_IFMT  0170000
#define WQ_AE_IFREG 0100000
#define WQ_AE_IFDIR 0040000
#define WQ_AE_IFLNK 0120000

extern WQArchive *archive_read_new(void);
extern int archive_read_support_filter_all(WQArchive *);
extern int archive_read_support_format_all(WQArchive *);
extern int archive_read_support_format_raw(WQArchive *);
extern int archive_read_open_memory(WQArchive *, const void *, size_t);
extern int archive_read_next_header(WQArchive *, WQArchiveEntry **);
extern const char *archive_entry_pathname(WQArchiveEntry *);
extern const char *archive_entry_symlink(WQArchiveEntry *);
extern mode_t archive_entry_perm(WQArchiveEntry *);
extern mode_t archive_entry_filetype(WQArchiveEntry *);
extern long long archive_entry_size(WQArchiveEntry *);
extern ssize_t archive_read_data(WQArchive *, void *, size_t);
extern int archive_read_data_skip(WQArchive *);
extern int archive_read_free(WQArchive *);
extern const char *archive_error_string(WQArchive *);

static NSString *WQPackageRoot(void)
{
    NSString *configured = NSProcessInfo.processInfo.environment[@"TERM_ROOT"];
    if (configured.length) return configured;
    NSString *documents = NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    return [documents stringByAppendingPathComponent:@".terminal"];
}

static NSString *WQInstallRoot(void)
{
    return [WQPackageRoot() stringByAppendingPathComponent:@"root"];
}

static NSString *WQStatusPath(void)
{
    return [WQPackageRoot() stringByAppendingPathComponent:@"var/lib/dpkg/status"];
}

static NSString *WQInfoDirectory(void)
{
    return [WQPackageRoot() stringByAppendingPathComponent:@"var/lib/dpkg/info"];
}

static void WQEnsurePackageDirectories(void)
{
    NSFileManager *fm = NSFileManager.defaultManager;
    NSArray *directories = @[
        WQPackageRoot(),
        WQInstallRoot(),
        WQInfoDirectory(),
        [WQPackageRoot() stringByAppendingPathComponent:@"var/lib/apt/lists"],
        [WQPackageRoot() stringByAppendingPathComponent:@"var/cache/apt/archives"],
        [WQPackageRoot() stringByAppendingPathComponent:@"etc/apt"],
        [WQPackageRoot() stringByAppendingPathComponent:@"tmp"],
    ];
    for (NSString *directory in directories)
        [fm createDirectoryAtPath:directory withIntermediateDirectories:YES
                       attributes:nil error:nil];
    NSString *status = WQStatusPath();
    if (![fm fileExistsAtPath:status])
        [@"" writeToFile:status atomically:YES encoding:NSUTF8StringEncoding error:nil];
}

#pragma mark - ar / deb

static NSData *WQArMember(NSData *archive, NSString *namePrefix)
{
    const uint8_t *bytes = archive.bytes;
    NSUInteger length = archive.length;
    if (length < 8 || memcmp(bytes, "!<arch>\n", 8) != 0) return nil;
    NSUInteger offset = 8;
    while (offset + 60 <= length) {
        const uint8_t *header = bytes + offset;
        NSString *name = [[[NSString alloc] initWithBytes:header length:16
            encoding:NSASCIIStringEncoding] stringByTrimmingCharactersInSet:
            NSCharacterSet.whitespaceCharacterSet];
        name = [name stringByTrimmingCharactersInSet:
            [NSCharacterSet characterSetWithCharactersInString:@"/"]];
        NSString *sizeText = [[[NSString alloc] initWithBytes:header + 48 length:10
            encoding:NSASCIIStringEncoding] stringByTrimmingCharactersInSet:
            NSCharacterSet.whitespaceCharacterSet];
        NSUInteger size = (NSUInteger)sizeText.longLongValue;
        offset += 60;
        if (offset + size > length) break;
        if ([name hasPrefix:namePrefix])
            return [archive subdataWithRange:NSMakeRange(offset, size)];
        offset += size + (size & 1);
    }
    return nil;
}

static NSString *WQArchivePath(NSString *raw)
{
    NSString *path = raw;
    while ([path hasPrefix:@"./"]) path = [path substringFromIndex:2];
    while ([path hasPrefix:@"/"]) path = [path substringFromIndex:1];
    if ([path hasPrefix:@"var/jb/"]) path = [path substringFromIndex:7];
    if (path.length == 0 || [path containsString:@".."]) return nil;
    return path;
}

static BOOL WQExtractArchiveData(NSData *archiveData, NSString *destination,
                                 NSMutableArray<NSString *> *installedFiles)
{
    if (!archiveData.length) return NO;
    WQArchive *archive = archive_read_new();
    if (!archive) return NO;
    archive_read_support_filter_all(archive);
    archive_read_support_format_all(archive);
    if (archive_read_open_memory(archive, archiveData.bytes,
                                 archiveData.length) != ARCHIVE_OK) {
        archive_read_free(archive);
        return NO;
    }

    NSFileManager *fm = NSFileManager.defaultManager;
    struct archive_entry *entry;
    BOOL success = YES;
    while (archive_read_next_header(archive, &entry) == WQ_ARCHIVE_OK) {
        const char *rawName = archive_entry_pathname(entry);
        if (!rawName) { archive_read_data_skip(archive); continue; }
        NSString *relative = WQArchivePath([NSString stringWithUTF8String:rawName]);
        if (!relative.length) { archive_read_data_skip(archive); continue; }
        NSString *target = [destination stringByAppendingPathComponent:relative];
        mode_t filetype = archive_entry_filetype(entry);
        mode_t permissions = archive_entry_perm(entry);
        if (filetype == WQ_AE_IFDIR) {
            [fm createDirectoryAtPath:target withIntermediateDirectories:YES
                           attributes:@{ NSFilePosixPermissions: @(permissions ?: 0755) }
                                error:nil];
            continue;
        }
        [fm createDirectoryAtPath:target.stringByDeletingLastPathComponent
            withIntermediateDirectories:YES attributes:nil error:nil];
        if (filetype == WQ_AE_IFLNK) {
            const char *link = archive_entry_symlink(entry);
            [fm removeItemAtPath:target error:nil];
            if (link && symlink(link, target.fileSystemRepresentation) == 0)
                [installedFiles addObject:relative];
        } else if (filetype == WQ_AE_IFREG) {
            int descriptor = open(target.fileSystemRepresentation,
                O_WRONLY | O_CREAT | O_TRUNC, permissions ?: 0644);
            if (descriptor < 0) { success = NO; archive_read_data_skip(archive); continue; }
            uint8_t buffer[65536];
            ssize_t got;
            while ((got = archive_read_data(archive, buffer, sizeof(buffer))) > 0) {
                ssize_t written = 0;
                while (written < got) {
                    ssize_t step = write(descriptor, buffer + written,
                                         (size_t)(got - written));
                    if (step <= 0) break;
                    written += step;
                }
            }
            close(descriptor);
            chmod(target.fileSystemRepresentation, permissions ?: 0644);
            [installedFiles addObject:relative];
        } else {
            archive_read_data_skip(archive);
        }
    }
    archive_read_free(archive);
    return success;
}

static NSData *WQArchiveEntryNamed(NSData *archiveData, NSString *wanted)
{
    WQArchive *archive = archive_read_new();
    if (!archive) return nil;
    archive_read_support_filter_all(archive);
    archive_read_support_format_all(archive);
    if (archive_read_open_memory(archive, archiveData.bytes,
                                 archiveData.length) != ARCHIVE_OK) {
        archive_read_free(archive);
        return nil;
    }
    struct archive_entry *entry;
    NSData *result = nil;
    while (archive_read_next_header(archive, &entry) == WQ_ARCHIVE_OK) {
        const char *name = archive_entry_pathname(entry);
        if (name && (strcmp(name, wanted.UTF8String) == 0 ||
                     strcmp(name + (strlen(name) > 2 && name[0] == '.' &&
                                    name[1] == '/' ? 2 : 0), wanted.UTF8String) == 0)) {
            NSMutableData *data = [NSMutableData data];
            uint8_t buffer[65536];
            ssize_t got;
            while ((got = archive_read_data(archive, buffer, sizeof(buffer))) > 0)
                [data appendBytes:buffer length:(NSUInteger)got];
            result = data;
            break;
        }
        archive_read_data_skip(archive);
    }
    archive_read_free(archive);
    return result;
}

static NSDictionary *WQParseControl(NSString *control)
{
    NSMutableDictionary *fields = [NSMutableDictionary dictionary];
    NSString *currentKey = nil;
    NSMutableString *currentValue = nil;
    for (NSString *line in [control componentsSeparatedByString:@"\n"]) {
        if (line.length == 0) continue;
        if ([line hasPrefix:@" "] || [line hasPrefix:@"\t"]) {
            if (currentKey && currentValue)
                [currentValue appendFormat:@"\n%@", [line stringByTrimmingCharactersInSet:
                    NSCharacterSet.whitespaceCharacterSet]];
            continue;
        }
        NSRange colon = [line rangeOfString:@":"];
        if (colon.location == NSNotFound) continue;
        if (currentKey && currentValue) fields[currentKey] = currentValue.copy;
        currentKey = [[line substringToIndex:colon.location]
            stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceCharacterSet];
        currentValue = [[[line substringFromIndex:colon.location + 1]
            stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceCharacterSet] mutableCopy];
    }
    if (currentKey && currentValue) fields[currentKey] = currentValue.copy;
    return fields;
}

NSString *WQDebInfoText(NSString *path)
{
    NSData *archive = [NSData dataWithContentsOfFile:path];
    if (!archive.length) return nil;
    NSData *controlArchive = WQArMember(archive, @"control.tar");
    if (!controlArchive.length) return nil;
    NSData *controlData = WQArchiveEntryNamed(controlArchive, @"control");
    if (!controlData.length) return nil;
    NSString *control = [[NSString alloc] initWithData:controlData
        encoding:NSUTF8StringEncoding];
    if (!control.length) return nil;
    NSMutableString *text = [NSMutableString stringWithFormat:
        @" new Debian package, version 2.0.\n"
        @" size %lu bytes: control archive %lu bytes.\n",
        (unsigned long)archive.length, (unsigned long)controlArchive.length];
    [text appendString:control];
    if (![text hasSuffix:@"\n"]) [text appendString:@"\n"];
    return text;
}

static NSString *WQStanzaForKey(NSString *text, NSString *key, NSString *value)
{
    NSArray *stanzas = [text componentsSeparatedByString:@"\n\n"];
    for (NSString *stanza in stanzas) {
        BOOL match = NO;
        for (NSString *line in [stanza componentsSeparatedByString:@"\n"]) {
            if ([line hasPrefix:[key stringByAppendingString:@": "]]) {
                match = [[line substringFromIndex:key.length + 2]
                    isEqualToString:value];
                break;
            }
        }
        if (match) return stanza;
    }
    return nil;
}

static NSString *WQFieldFromStanza(NSString *stanza, NSString *key)
{
    for (NSString *line in [stanza componentsSeparatedByString:@"\n"])
        if ([line hasPrefix:[key stringByAppendingString:@": "]])
            return [line substringFromIndex:key.length + 2];
    return nil;
}

static void WQRemoveStatusStanza(NSString *package)
{
    NSString *text = [NSString stringWithContentsOfFile:WQStatusPath()
        encoding:NSUTF8StringEncoding error:nil] ?: @"";
    NSMutableArray *keep = [NSMutableArray array];
    for (NSString *stanza in [text componentsSeparatedByString:@"\n\n"]) {
        if (stanza.length == 0) continue;
        NSString *name = WQFieldFromStanza(stanza, @"Package");
        if (![name isEqualToString:package]) [keep addObject:stanza];
    }
    [[keep componentsJoinedByString:@"\n\n"] writeToFile:WQStatusPath()
        atomically:YES encoding:NSUTF8StringEncoding error:nil];
}

static BOOL WQInstallDeb(NSString *path, FILE *out, FILE *err,
                         NSDictionary *options)
{
    WQEnsurePackageDirectories();
    NSData *archive = [NSData dataWithContentsOfFile:path];
    if (!archive.length) {
        fprintf(err, "dpkg: cannot open %s\n", path.UTF8String);
        return NO;
    }
    NSData *controlArchive = WQArMember(archive, @"control.tar");
    NSData *dataArchive = WQArMember(archive, @"data.tar");
    if (!controlArchive || !dataArchive) {
        fprintf(err, "dpkg: %s is not a Debian archive\n", path.UTF8String);
        return NO;
    }
    NSData *controlData = WQArchiveEntryNamed(controlArchive, @"control");
    if (!controlData) {
        fprintf(err, "dpkg: missing control file in %s\n", path.UTF8String);
        return NO;
    }
    NSString *control = [[NSString alloc] initWithData:controlData
        encoding:NSUTF8StringEncoding];
    NSDictionary *fields = WQParseControl(control ?: @"");
    NSString *package = fields[@"Package"] ?: @"unknown";
    NSString *version = fields[@"Version"] ?: @"0";
    NSString *architecture = fields[@"Architecture"] ?: @"iphoneos-arm64";
    BOOL force = options[@"force"] != nil;
    if (!force &&
        ![architecture isEqualToString:@"iphoneos-arm64"] &&
        ![architecture isEqualToString:@"iphoneos-arm"] &&
        ![architecture isEqualToString:@"darwin-arm64"] &&
        ![architecture isEqualToString:@"all"]) {
        fprintf(err, "dpkg: package architecture %s is not native "
                "(use --force-architecture)\n", architecture.UTF8String);
        return NO;
    }

    fprintf(out, "Selecting previously unselected package %s.\n",
            package.UTF8String);
    NSMutableArray<NSString *> *installedFiles = [NSMutableArray array];
    if (!WQExtractArchiveData(dataArchive, WQInstallRoot(), installedFiles)) {
        fprintf(err, "dpkg: failed to unpack %s\n", path.UTF8String);
        return NO;
    }

    WQRemoveStatusStanza(package);
    NSMutableString *status = [NSMutableString stringWithContentsOfFile:WQStatusPath()
        encoding:NSUTF8StringEncoding error:nil] ?: [NSMutableString string];
    if (status.length && ![status hasSuffix:@"\n\n"]) [status appendString:@"\n\n"];
    [status appendFormat:
        @"Package: %@\n"
        @"Status: install ok installed\n"
        @"Priority: %@\n"
        @"Section: %@\n"
        @"Installed-Size: %@\n"
        @"Maintainer: %@\n"
        @"Architecture: %@\n"
        @"Version: %@\n"
        @"Description: %@\n\n",
        package,
        fields[@"Priority"] ?: @"optional",
        fields[@"Section"] ?: @"utility",
        fields[@"Installed-Size"] ?: @"0",
        fields[@"Maintainer"] ?: @"unknown",
        architecture,
        version,
        fields[@"Description"] ?: package];
    [status writeToFile:WQStatusPath() atomically:YES
               encoding:NSUTF8StringEncoding error:nil];
    NSString *listPath = [WQInfoDirectory()
        stringByAppendingPathComponent:[package stringByAppendingString:@".list"]];
    [[installedFiles componentsJoinedByString:@"\n"] writeToFile:listPath
        atomically:YES encoding:NSUTF8StringEncoding error:nil];
    fprintf(out, "Unpacking %s (%s) ...\n", package.UTF8String, version.UTF8String);
    fprintf(out, "Setting up %s (%s) ...\n", package.UTF8String, version.UTF8String);
    fprintf(out, "Installed to %s\n", WQInstallRoot().UTF8String);
    return YES;
}

#pragma mark - dpkg

static void WQDPKGUsage(FILE *out)
{
    fprintf(out,
        "Usage: dpkg <action>\n"
        "  -i, --install <file.deb>   Install a package\n"
        "  -r, --remove <package>     Remove a package\n"
        "  -P, --purge <package>      Remove a package\n"
        "  -l, --list                 List installed packages\n"
        "  -s, --status <package>     Show package status\n"
        "  -L, --listfiles <package>  List package files\n"
        "  -x, --extract <deb> <dir>  Extract data archive\n"
        "  --contents <deb>           List .deb contents\n"
        "  --print-architecture       Print iphoneos-arm64\n"
        "  --force-architecture       Allow non-native packages\n"
        "  --version                  Show version\n");
}

int WQDPKGMain(int argc, char **argv, FILE *out, FILE *err)
{
    WQEnsurePackageDirectories();
    if (argc < 2) { WQDPKGUsage(out); return 1; }
    NSString *action = [NSString stringWithUTF8String:argv[1]];
    BOOL force = NO;
    int index = 2;
    for (int i = 2; i < argc; i++) {
        NSString *arg = [NSString stringWithUTF8String:argv[i]];
        if ([arg isEqualToString:@"--force-architecture"]) force = YES;
    }
    NSDictionary *options = force ? @{ @"force": @YES } : @{};

    if ([action isEqualToString:@"--version"]) {
        fprintf(out, "dpkg 1.22 (FilzaSlop in-process)\n");
        return 0;
    }
    if ([action isEqualToString:@"--print-architecture"]) {
        fprintf(out, "iphoneos-arm64\n");
        return 0;
    }
    if ([action isEqualToString:@"-l"] || [action isEqualToString:@"--list"]) {
        NSString *text = [NSString stringWithContentsOfFile:WQStatusPath()
            encoding:NSUTF8StringEncoding error:nil] ?: @"";
        fprintf(out, "Desired=Unknown/Install/Remove/Purge/Hold\n"
                     "||/ Name                 Version        Architecture Description\n");
        for (NSString *stanza in [text componentsSeparatedByString:@"\n\n"]) {
            if (stanza.length == 0) continue;
            NSString *name = WQFieldFromStanza(stanza, @"Package");
            NSString *version = WQFieldFromStanza(stanza, @"Version") ?: @"";
            NSString *arch = WQFieldFromStanza(stanza, @"Architecture") ?: @"";
            NSString *description = WQFieldFromStanza(stanza, @"Description") ?: @"";
            fprintf(out, "ii  %-20s %-14s %-14s %s\n",
                (name ?: @"").UTF8String, version.UTF8String,
                arch.UTF8String, description.UTF8String);
        }
        return 0;
    }
    if ([action isEqualToString:@"-s"] || [action isEqualToString:@"--status"]) {
        if (index >= argc) { fprintf(err, "dpkg: missing package\n"); return 1; }
        NSString *package = [NSString stringWithUTF8String:argv[index]];
        NSString *text = [NSString stringWithContentsOfFile:WQStatusPath()
            encoding:NSUTF8StringEncoding error:nil] ?: @"";
        NSString *stanza = WQStanzaForKey(text, @"Package", package);
        if (!stanza) { fprintf(err, "dpkg: package %s is not installed\n",
                                package.UTF8String); return 1; }
        fprintf(out, "%s\n", stanza.UTF8String);
        return 0;
    }
    if ([action isEqualToString:@"-L"] || [action isEqualToString:@"--listfiles"]) {
        if (index >= argc) { fprintf(err, "dpkg: missing package\n"); return 1; }
        NSString *package = [NSString stringWithUTF8String:argv[index]];
        NSString *list = [NSString stringWithContentsOfFile:
            [WQInfoDirectory() stringByAppendingPathComponent:
                [package stringByAppendingString:@".list"]]
            encoding:NSUTF8StringEncoding error:nil];
        if (!list) { fprintf(err, "dpkg: package %s has no file list\n",
                              package.UTF8String); return 1; }
        fprintf(out, "%s\n", list.UTF8String);
        return 0;
    }
    if ([action isEqualToString:@"-r"] || [action isEqualToString:@"--remove"] ||
        [action isEqualToString:@"-P"] || [action isEqualToString:@"--purge"]) {
        if (index >= argc) { fprintf(err, "dpkg: missing package\n"); return 1; }
        NSString *package = [NSString stringWithUTF8String:argv[index]];
        NSString *listPath = [WQInfoDirectory()
            stringByAppendingPathComponent:[package stringByAppendingString:@".list"]];
        NSString *list = [NSString stringWithContentsOfFile:listPath
            encoding:NSUTF8StringEncoding error:nil];
        NSFileManager *fm = NSFileManager.defaultManager;
        for (NSString *relative in [list componentsSeparatedByString:@"\n"]) {
            if (!relative.length) continue;
            NSString *target = [WQInstallRoot() stringByAppendingPathComponent:relative];
            [fm removeItemAtPath:target error:nil];
        }
        [fm removeItemAtPath:listPath error:nil];
        WQRemoveStatusStanza(package);
        fprintf(out, "Removing %s ...\n", package.UTF8String);
        return 0;
    }
    if ([action isEqualToString:@"-x"] || [action isEqualToString:@"--extract"] ||
        [action isEqualToString:@"--contents"]) {
        if (index >= argc) { fprintf(err, "dpkg: missing .deb\n"); return 1; }
        NSString *path = [NSString stringWithUTF8String:argv[index]];
        NSData *archive = [NSData dataWithContentsOfFile:path];
        NSData *data = WQArMember(archive, @"data.tar");
        if (!data) { fprintf(err, "dpkg: no data archive\n"); return 1; }
        if ([action isEqualToString:@"--contents"]) {
            NSMutableArray<NSString *> *files = [NSMutableArray array];
            WQExtractArchiveData(data, NSTemporaryDirectory(), files);
            for (NSString *file in files) fprintf(out, "%s\n", file.UTF8String);
            return 0;
        }
        NSString *destination = index + 1 < argc
            ? [NSString stringWithUTF8String:argv[index + 1]]
            : WQInstallRoot();
        NSMutableArray *files = [NSMutableArray array];
        return WQExtractArchiveData(data, destination, files) ? 0 : 1;
    }
    if ([action isEqualToString:@"-i"] || [action isEqualToString:@"--install"]) {
        if (index >= argc) { fprintf(err, "dpkg: missing .deb\n"); return 1; }
        BOOL all = YES;
        for (; index < argc; index++) {
            NSString *path = [NSString stringWithUTF8String:argv[index]];
            if ([path isEqualToString:@"--force-architecture"]) continue;
            if (!WQInstallDeb(path, out, err, options)) all = NO;
        }
        return all ? 0 : 1;
    }
    WQDPKGUsage(out);
    return 1;
}

#pragma mark - apt

static NSString *WQAptIndexPath(void)
{
    return [WQPackageRoot() stringByAppendingPathComponent:
        @"var/lib/apt/lists/Packages"];
}

static NSString *WQAptSourcesPath(void)
{
    return [WQPackageRoot() stringByAppendingPathComponent:@"etc/apt/sources.list"];
}

static NSArray<NSString *> *WQAptStanzas(void)
{
    NSString *text = [NSString stringWithContentsOfFile:WQAptIndexPath()
        encoding:NSUTF8StringEncoding error:nil] ?: @"";
    NSMutableArray *stanzas = [NSMutableArray array];
    for (NSString *stanza in [text componentsSeparatedByString:@"\n\n"])
        if (stanza.length) [stanzas addObject:stanza];
    return stanzas;
}

static NSData *WQDownloadURL(NSString *urlString)
{
    NSURL *url = [NSURL URLWithString:urlString];
    if (!url) return nil;
    if ([url isFileURL]) return [NSData dataWithContentsOfURL:url];
    dispatch_semaphore_t semaphore = dispatch_semaphore_create(0);
    __block NSData *result = nil;
    NSURLSessionDataTask *task = [NSURLSession.sharedSession dataTaskWithURL:url
        completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
            if (!error && [(NSHTTPURLResponse *)response statusCode] / 100 == 2)
                result = data;
            dispatch_semaphore_signal(semaphore);
        }];
    [task resume];
    dispatch_semaphore_wait(semaphore, dispatch_time(DISPATCH_TIME_NOW, 30 * NSEC_PER_SEC));
    return result;
}

static void WQEnsureSources(void)
{
    NSString *path = WQAptSourcesPath();
    if ([[NSFileManager defaultManager] fileExistsAtPath:path]) return;
    NSString *root = WQPackageRoot();
    NSString *line = [NSString stringWithFormat:@"deb [trusted=yes] file://%@/repo ./\n", root];
    [line writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:nil];
}

static void WQAptUsage(FILE *out)
{
    fprintf(out,
        "Usage: apt <command>\n"
        "  update                  Refresh package indexes\n"
        "  list                    List packages in the index\n"
        "  search <text>           Search package names/descriptions\n"
        "  show <package>          Show package details\n"
        "  install <package|deb>   Install a package\n"
        "  remove|purge <package>  Remove a package\n"
        "  clean                   Clear downloaded archives\n"
        "  --version               Show version\n"
        "Root: %s\n", WQPackageRoot().UTF8String);
}

int WQAptMain(int argc, char **argv, FILE *out, FILE *err)
{
    WQEnsurePackageDirectories();
    WQEnsureSources();
    if (argc < 2) { WQAptUsage(out); return 1; }
    NSString *action = [NSString stringWithUTF8String:argv[1]];
    if ([action isEqualToString:@"--version"]) {
        fprintf(out, "apt 2.7 (FilzaSlop in-process)\n");
        return 0;
    }
    if ([action isEqualToString:@"update"]) {
        fprintf(out, "apt: updating package lists...\n");
        NSString *sources = [NSString stringWithContentsOfFile:WQAptSourcesPath()
            encoding:NSUTF8StringEncoding error:nil] ?: @"";
        NSMutableString *index = [NSMutableString string];
        for (NSString *line in [sources componentsSeparatedByString:@"\n"]) {
            if (![line hasPrefix:@"deb "]) continue;
            NSArray *parts = [line componentsSeparatedByString:@" "];
            NSString *uri = nil;
            for (NSString *part in parts) {
                if ([part hasPrefix:@"http://"] || [part hasPrefix:@"https://"] ||
                    [part hasPrefix:@"file://"]) { uri = part; break; }
            }
            if (!uri.length) continue;
            NSArray *names = @[@"Packages", @"Packages.gz"];
            BOOL loaded = NO;
            for (NSString *name in names) {
                NSString *url = [uri stringByAppendingPathComponent:name];
                NSData *data = WQDownloadURL(url);
                if (!data.length) continue;
                if ([name hasSuffix:@".gz"]) {
                    // Decompress gzip through libarchive's raw reader.
                    WQArchive *archive = archive_read_new();
                    archive_read_support_filter_all(archive);
                    archive_read_support_format_raw(archive);
                    if (archive_read_open_memory(archive, data.bytes, data.length) != ARCHIVE_OK) {
                        archive_read_free(archive);
                        continue;
                    }
                    struct archive_entry *entry;
                    NSMutableData *plain = [NSMutableData data];
                    if (archive_read_next_header(archive, &entry) == WQ_ARCHIVE_OK) {
                        uint8_t buffer[65536];
                        ssize_t got;
                        while ((got = archive_read_data(archive, buffer, sizeof(buffer))) > 0)
                            [plain appendBytes:buffer length:(NSUInteger)got];
                    }
                    archive_read_free(archive);
                    data = plain;
                }
                NSString *text = [[NSString alloc] initWithData:data
                    encoding:NSUTF8StringEncoding];
                if (text.length) {
                    [index appendString:text];
                    if (![index hasSuffix:@"\n"]) [index appendString:@"\n"];
                    loaded = YES;
                    break;
                }
            }
            fprintf(out, "%s: %s\n", loaded ? "Get" : "Err", uri.UTF8String);
        }
        [index writeToFile:WQAptIndexPath() atomically:YES
                  encoding:NSUTF8StringEncoding error:nil];
        fprintf(out, "Reading package lists... Done\n");
        return 0;
    }
    if ([action isEqualToString:@"list"]) {
        for (NSString *stanza in WQAptStanzas()) {
            NSString *name = WQFieldFromStanza(stanza, @"Package") ?: @"";
            NSString *version = WQFieldFromStanza(stanza, @"Version") ?: @"";
            NSString *description = WQFieldFromStanza(stanza, @"Description") ?: @"";
            fprintf(out, "%s/%s %s %s\n", name.UTF8String,
                (WQFieldFromStanza(stanza, @"Architecture") ?: @"iphoneos-arm64").UTF8String,
                version.UTF8String, description.UTF8String);
        }
        return 0;
    }
    if ([action isEqualToString:@"search"]) {
        NSString *text = argc > 2 ? [NSString stringWithUTF8String:argv[2]] : @"";
        for (NSString *stanza in WQAptStanzas())
            if (text.length == 0 || [stanza.lowercaseString containsString:text.lowercaseString]) {
                NSString *name = WQFieldFromStanza(stanza, @"Package") ?: @"";
                NSString *description = WQFieldFromStanza(stanza, @"Description") ?: @"";
                fprintf(out, "%s - %s\n", name.UTF8String, description.UTF8String);
            }
        return 0;
    }
    if ([action isEqualToString:@"show"]) {
        if (argc < 3) { fprintf(err, "apt: missing package\n"); return 1; }
        NSString *package = [NSString stringWithUTF8String:argv[2]];
        for (NSString *stanza in WQAptStanzas())
            if ([WQFieldFromStanza(stanza, @"Package") isEqualToString:package]) {
                fprintf(out, "%s\n", stanza.UTF8String);
                return 0;
            }
        fprintf(err, "apt: package %s not found\n", package.UTF8String);
        return 1;
    }
    if ([action isEqualToString:@"install"]) {
        if (argc < 3) { fprintf(err, "apt: missing package\n"); return 1; }
        NSString *target = [NSString stringWithUTF8String:argv[2]];
        if ([[NSFileManager defaultManager] fileExistsAtPath:target] ||
            [target hasSuffix:@".deb"])
            return WQDPKGMain(3, (char *[]){(char *)"dpkg", (char *)"-i",
                (char *)target.UTF8String}, out, err) ? 0 : 1;
        for (NSString *stanza in WQAptStanzas()) {
            if (![WQFieldFromStanza(stanza, @"Package") isEqualToString:target]) continue;
            NSString *filename = WQFieldFromStanza(stanza, @"Filename");
            NSString *source = @"";
            NSString *sources = [NSString stringWithContentsOfFile:WQAptSourcesPath()
                encoding:NSUTF8StringEncoding error:nil] ?: @"";
            for (NSString *line in [sources componentsSeparatedByString:@"\n"])
                for (NSString *part in [line componentsSeparatedByString:@" "])
                    if ([part hasPrefix:@"http"] || [part hasPrefix:@"file://"]) {
                        source = part; break;
                    }
            NSString *url = [source stringByAppendingPathComponent:filename ?: @""];
            NSData *deb = WQDownloadURL(url);
            NSString *cache = [[WQPackageRoot()
                stringByAppendingPathComponent:@"var/cache/apt/archives"]
                stringByAppendingPathComponent:filename.lastPathComponent ?: @"package.deb"];
            if (!deb.length || ![deb writeToFile:cache atomically:YES]) {
                fprintf(err, "apt: unable to download %s\n", url.UTF8String);
                return 1;
            }
            return WQDPKGMain(3, (char *[]){(char *)"dpkg", (char *)"-i",
                (char *)cache.UTF8String}, out, err) ? 0 : 1;
        }
        fprintf(err, "apt: package %s not found; run 'apt update'\n", target.UTF8String);
        return 1;
    }
    if ([action isEqualToString:@"remove"] || [action isEqualToString:@"purge"]) {
        if (argc < 3) { fprintf(err, "apt: missing package\n"); return 1; }
        return WQDPKGMain(argc, (char *[]){(char *)"dpkg", (char *)"-r",
            argv[2], NULL}, out, err) ? 0 : 1;
    }
    if ([action isEqualToString:@"clean"]) {
        NSString *archives = [WQPackageRoot()
            stringByAppendingPathComponent:@"var/cache/apt/archives"];
        for (NSString *name in [NSFileManager.defaultManager
                contentsOfDirectoryAtPath:archives error:nil])
            [NSFileManager.defaultManager removeItemAtPath:
                [archives stringByAppendingPathComponent:name] error:nil];
        fprintf(out, "apt: cache cleaned\n");
        return 0;
    }
    WQAptUsage(out);
    return 1;
}

BOOL WQInstallDebPackage(NSString *path, NSString **message)
{
    FILE *out = tmpfile();
    FILE *err = tmpfile();
    BOOL result = WQInstallDeb(path, out, err, @{});
    NSMutableString *text = [NSMutableString string];
    if (out) {
        fflush(out); rewind(out);
        char buffer[4096]; size_t got;
        while ((got = fread(buffer, 1, sizeof(buffer), out)) > 0)
            [text appendString:[[NSString alloc] initWithBytes:buffer
                length:got encoding:NSUTF8StringEncoding] ?: @""];
        fclose(out);
    }
    if (err) {
        fflush(err); rewind(err);
        char buffer[4096]; size_t got;
        while ((got = fread(buffer, 1, sizeof(buffer), err)) > 0)
            [text appendString:[[NSString alloc] initWithBytes:buffer
                length:got encoding:NSUTF8StringEncoding] ?: @""];
        fclose(err);
    }
    if (message) *message = text;
    return result;
}
