//
//  WQArchive.m
//  FilzaSlop
//
//  In-process archive extraction for the terminal and Filza's file browser.
//  libarchive is already linked by the package backend; this keeps archive
//  support working without /usr/bin/unzip, 7z, unrar or a root helper.
//

#import "WQArchive.h"

#import <Foundation/Foundation.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

// The iOS SDK does not ship libarchive headers. Declare the small ABI surface
// used here explicitly (the same approach as WQPackages.m).
typedef struct archive WQArchiveReader;
typedef struct archive_entry WQArchiveEntry;

#define WQ_ARCHIVE_OK  0
#define WQ_ARCHIVE_EOF 1
#define WQ_AE_IFMT  0170000
#define WQ_AE_IFREG 0100000
#define WQ_AE_IFDIR 0040000
#define WQ_AE_IFLNK 0120000

extern WQArchiveReader *archive_read_new(void);
extern int archive_read_support_filter_all(WQArchiveReader *);
extern int archive_read_support_format_all(WQArchiveReader *);
extern int archive_read_support_format_raw(WQArchiveReader *);
extern int archive_read_open_filename(WQArchiveReader *, const char *, size_t);
extern int archive_read_next_header(WQArchiveReader *, WQArchiveEntry **);
extern const char *archive_entry_pathname(WQArchiveEntry *);
extern unsigned int archive_entry_filetype(WQArchiveEntry *);
extern const char *archive_entry_symlink(WQArchiveEntry *);
extern unsigned int archive_entry_perm(WQArchiveEntry *);
extern ssize_t archive_read_data(WQArchiveReader *, void *, size_t);
extern int archive_read_data_skip(WQArchiveReader *);
extern const char *archive_error_string(WQArchiveReader *);
extern int archive_read_close(WQArchiveReader *);
extern int archive_read_free(WQArchiveReader *);

static NSString *WQArchiveSafeRelativePath(const char *name)
{
    if (!name) return nil;
    NSString *path = [NSString stringWithUTF8String:name];
    if (!path.length) return nil;
    while ([path hasPrefix:@"./"])
        path = [path substringFromIndex:2];
    if ([path isEqualToString:@"."] || [path hasPrefix:@"/"]) return nil;
    for (NSString *component in [path componentsSeparatedByString:@"/"])
        if ([component isEqualToString:@".."]) return nil;
    return path;
}

static BOOL WQArchiveWriteEntry(WQArchiveReader *reader,
                                WQArchiveEntry *entry,
                                NSString *target)
{
    NSFileManager *fm = NSFileManager.defaultManager;
    NSString *parent = target.stringByDeletingLastPathComponent;
    if (parent.length && ![fm createDirectoryAtPath:parent
            withIntermediateDirectories:YES attributes:nil error:nil])
        return NO;

    mode_t type = archive_entry_filetype(entry);
    if (type == WQ_AE_IFDIR) {
        return [fm createDirectoryAtPath:target withIntermediateDirectories:YES
            attributes:nil error:nil];
    }
    if (type == WQ_AE_IFLNK) {
        const char *link = archive_entry_symlink(entry);
        if (!link || link[0] == '/') return NO;
        unlink(target.fileSystemRepresentation);
        return symlink(link, target.fileSystemRepresentation) == 0;
    }
    if (type != WQ_AE_IFREG && type != 0) return NO;

    int descriptor = open(target.fileSystemRepresentation,
        O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (descriptor < 0) return NO;

    char buffer[65536];
    ssize_t got;
    BOOL ok = YES;
    while ((got = archive_read_data(reader, buffer, sizeof(buffer))) > 0) {
        ssize_t written = 0;
        while (written < got) {
            ssize_t step = write(descriptor, buffer + written,
                                 (size_t)(got - written));
            if (step <= 0) {
                ok = NO;
                break;
            }
            written += step;
        }
        if (!ok) break;
    }
    if (got < 0) ok = NO;
    if (close(descriptor) != 0) ok = NO;

    mode_t permissions = archive_entry_perm(entry);
    if (permissions)
        chmod(target.fileSystemRepresentation, permissions & 0777);
    return ok;
}

BOOL WQExtractArchive(NSString *archivePath, NSString *destination,
                      NSString **message)
{
    NSFileManager *fm = NSFileManager.defaultManager;
    if (!archivePath.length || !destination.length) {
        if (message) *message = @"extract: missing archive or destination";
        return NO;
    }
    [fm createDirectoryAtPath:destination withIntermediateDirectories:YES
        attributes:nil error:nil];

    WQArchiveReader *reader = archive_read_new();
    if (!reader) {
        if (message) *message = @"extract: cannot allocate libarchive";
        return NO;
    }
    archive_read_support_filter_all(reader);
    archive_read_support_format_all(reader);
    archive_read_support_format_raw(reader);

    int result = archive_read_open_filename(reader,
        archivePath.fileSystemRepresentation, 64 * 1024);
    if (result != WQ_ARCHIVE_OK) {
        if (message) *message = [NSString stringWithFormat:
            @"extract: %@: %s", archivePath, archive_error_string(reader) ?: "unreadable"];
        archive_read_free(reader);
        return NO;
    }

    NSUInteger extracted = 0;
    NSUInteger skipped = 0;
    WQArchiveEntry *entry = NULL;
    while ((result = archive_read_next_header(reader, &entry)) == WQ_ARCHIVE_OK) {
        const char *name = archive_entry_pathname(entry);
        NSString *relative = WQArchiveSafeRelativePath(name);
        if (!relative.length) {
            skipped++;
            archive_read_data_skip(reader);
            continue;
        }
        NSString *target = [destination stringByAppendingPathComponent:relative];
        if (WQArchiveWriteEntry(reader, entry, target))
            extracted++;
        else
            skipped++;
    }

    BOOL failed = result != WQ_ARCHIVE_EOF;
    NSString *error = failed ? [NSString stringWithUTF8String:
        archive_error_string(reader) ?: "corrupt archive"] : nil;
    archive_read_close(reader);
    archive_read_free(reader);

    if (failed) {
        if (message) *message = [NSString stringWithFormat:
            @"extract: %@: %@", archivePath, error ?: @"corrupt archive"];
        return NO;
    }
    if (message) *message = [NSString stringWithFormat:
        @"extract: %lu entries -> %@%@", (unsigned long)extracted, destination,
        skipped ? [NSString stringWithFormat:@" (%lu skipped)",
                   (unsigned long)skipped] : @""];
    return YES;
}

NSString *WQDefaultExtractDestination(NSString *archivePath)
{
    NSString *name = archivePath.lastPathComponent;
    NSArray<NSString *> *suffixes = @[
        @".tar.gz", @".tar.bz2", @".tar.xz", @".tar.zst",
        @".tgz", @".tbz", @".tbz2", @".txz", @".tzst",
        @".zip", @".7z", @".rar", @".tar", @".gz", @".bz2",
        @".xz", @".zst", @".deb", @".iso",
    ];
    NSString *lower = name.lowercaseString;
    for (NSString *suffix in suffixes) {
        if ([lower hasSuffix:suffix] && name.length > suffix.length) {
            name = [name substringToIndex:name.length - suffix.length];
            break;
        }
    }
    if (!name.length) name = @"extracted";
    return [archivePath.stringByDeletingLastPathComponent
        stringByAppendingPathComponent:name];
}
