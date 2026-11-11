//
//  WQTerminal.m
//  FilzaSlop
//
//  In-process terminal bridge. Filza's PTY UI normally starts a root helper;
//  under normal signing that helper is unavailable and fork() is denied. This
//  bridge keeps the same PTY contract but executes commands with a-Shell mini's
//  ios_system runtime in a background thread.
//

#import "WQTerminal.h"
#import "WQPackages.h"
#import "WQFilzaIntegration.h"
#import "WQRespring.h"
#import "WQArchive.h"

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <dlfcn.h>
#import <objc/message.h>
#import <errno.h>
#import <fcntl.h>
#import <pthread.h>
#import <spawn.h>
#import <stdarg.h>
#include <string.h>
#import <sys/ioctl.h>
#import <sys/mount.h>
#import <sys/sysctl.h>
#import <sys/utsname.h>
#include <sys/socket.h>
#import <sys/stat.h>
#import <sys/wait.h>
#import <termios.h>
#import <unistd.h>
#import <util.h>

extern char **environ;

typedef void (*WQInitializeEnvironmentFn)(void);
typedef int (*WQAddCommandListFn)(NSString *);
typedef int (*WQIosSystemFn)(const char *);
typedef void (*WQIosSetStreamsFn)(FILE *, FILE *, FILE *);
typedef void (*WQIosSetTtyFn)(FILE *);
typedef int (*WQIosSetEnvFn)(const char *, const char *, int);
typedef int (*WQIosSetMiniRootFn)(NSString *);
typedef NSArray *(*WQCommandsAsArrayFn)(void);
typedef void (*WQIosSetDirectoryURLFn)(NSURL *);
typedef void (*WQIosSwitchSessionFn)(const void *);

static void *gIOSSystemHandle;
static WQInitializeEnvironmentFn iosInitializeEnvironment;
static WQAddCommandListFn iosAddCommandList;
static WQIosSystemFn iosSystem;
static WQIosSetStreamsFn iosSetStreams;
static WQIosSetTtyFn iosSetTty;
static WQIosSetEnvFn iosSetEnv;
static WQIosSetMiniRootFn iosSetMiniRoot;
static WQCommandsAsArrayFn iosCommandsAsArray;
static WQIosSetDirectoryURLFn iosSetDirectoryURL;
static WQIosSwitchSessionFn iosSwitchSession;
static BOOL gPrepared;
static BOOL gPreparing;
static BOOL gIOSAvailable;

static NSString *WQTerminalRoot(void)
{
    NSString *documents = NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    return [documents stringByAppendingPathComponent:@".terminal"];
}

static void WQTerminalSetEnvironment(void)
{
    NSString *base = NSBundle.mainBundle.bundlePath;
    NSString *root = WQTerminalRoot();
    NSString *resources = [base stringByAppendingPathComponent:@"WQResources"];
    NSString *path = [NSString stringWithFormat:
        @"%@/bin:%@/usr/bin:%@/usr/bin:%@/bin:/usr/bin:/bin:/usr/sbin:/sbin",
        resources, resources, root, root];
    setenv("PATH", path.UTF8String, 1);
    setenv("HOME", NSHomeDirectory().UTF8String, 1);
    setenv("TERM", "xterm-256color", 1);
    setenv("TERM_PROGRAM", "Filza", 1);
    setenv("LANG", "en_US.UTF-8", 1);
    setenv("LC_ALL", "en_US.UTF-8", 1);
    setenv("TMPDIR", NSTemporaryDirectory().UTF8String, 1);
    setenv("TERM_ROOT", root.UTF8String, 1);
    if (iosSetEnv) {
        iosSetEnv("PATH", path.UTF8String, 1);
        iosSetEnv("HOME", NSHomeDirectory().UTF8String, 1);
        iosSetEnv("TERM", "xterm-256color", 1);
        iosSetEnv("TERM_PROGRAM", "Filza", 1);
        iosSetEnv("LANG", "en_US.UTF-8", 1);
        iosSetEnv("LC_ALL", "en_US.UTF-8", 1);
        iosSetEnv("TMPDIR", NSTemporaryDirectory().UTF8String, 1);
        iosSetEnv("TERM_ROOT", root.UTF8String, 1);
        iosSetEnv("PERL5LIB", [resources stringByAppendingPathComponent:@"Perl"].UTF8String, 1);
        iosSetEnv("MANPATH", [resources stringByAppendingPathComponent:@"man"].UTF8String, 1);
        iosSetEnv("MAGICK_CONFIGURE_PATH",
            [resources stringByAppendingPathComponent:@"ImageMagick-7"].UTF8String, 1);
        iosSetEnv("TERMINFO", [resources stringByAppendingPathComponent:@"terminfo"].UTF8String, 1);
    }
}

BOOL WQTerminalPrepare(void)
{
    if (gPrepared) return gIOSAvailable;
    if (gPreparing) return gIOSAvailable;
    gPreparing = YES;

    NSString *framework = [NSBundle.mainBundle.bundlePath
        stringByAppendingPathComponent:@"Frameworks/ios_system.framework/ios_system"];
    gIOSSystemHandle = dlopen(framework.fileSystemRepresentation,
                              RTLD_NOW | RTLD_GLOBAL);
    if (!gIOSSystemHandle) {
        NSLog(@"[Terminal] ios_system dlopen failed: %s", dlerror());
        gPreparing = NO;
        gPrepared = YES;
        return NO;
    }

#define WQ_LOAD(name) ios##name = (__typeof(ios##name))dlsym(gIOSSystemHandle, "ios_" #name)
    iosInitializeEnvironment = (WQInitializeEnvironmentFn)dlsym(gIOSSystemHandle,
        "initializeEnvironment");
    iosAddCommandList = (WQAddCommandListFn)dlsym(gIOSSystemHandle,
        "addCommandList");
    iosSystem = (WQIosSystemFn)dlsym(gIOSSystemHandle, "ios_system");
    iosSetStreams = (WQIosSetStreamsFn)dlsym(gIOSSystemHandle, "ios_setStreams");
    iosSetTty = (WQIosSetTtyFn)dlsym(gIOSSystemHandle, "ios_settty");
    iosSetEnv = (WQIosSetEnvFn)dlsym(gIOSSystemHandle, "ios_setenv");
    iosSetMiniRoot = (WQIosSetMiniRootFn)dlsym(gIOSSystemHandle,
        "ios_setMiniRoot");
    iosCommandsAsArray = (WQCommandsAsArrayFn)dlsym(gIOSSystemHandle,
        "commandsAsArray");
    iosSetDirectoryURL = (WQIosSetDirectoryURLFn)dlsym(gIOSSystemHandle,
        "ios_setDirectoryURL");
    iosSwitchSession = (WQIosSwitchSessionFn)dlsym(gIOSSystemHandle,
        "ios_switchSession");
#undef WQ_LOAD

    if (!iosSystem || !iosInitializeEnvironment) {
        NSLog(@"[Terminal] ios_system symbols missing");
        gPreparing = NO;
        gPrepared = YES;
        return NO;
    }

    WQTerminalSetEnvironment();
    if (iosInitializeEnvironment) iosInitializeEnvironment();
    NSString *dictionary = [NSBundle.mainBundle.bundlePath
        stringByAppendingPathComponent:@"commandDictionary.plist"];
    if (iosAddCommandList && [[NSFileManager defaultManager] fileExistsAtPath:dictionary])
        iosAddCommandList(dictionary);
    if (iosSetMiniRoot) iosSetMiniRoot(@"/");
    if (iosSetDirectoryURL)
        iosSetDirectoryURL([NSURL fileURLWithPath:NSHomeDirectory()]);

    bool *sideLoading = (bool *)dlsym(gIOSSystemHandle, "sideLoading");
    if (sideLoading) *sideLoading = true;
    bool *joinMainThread = (bool *)dlsym(gIOSSystemHandle, "joinMainThread");
    if (joinMainThread) *joinMainThread = true;

    NSArray *commands = iosCommandsAsArray ? iosCommandsAsArray() : nil;
    NSLog(@"[Terminal] ios_system ready commands=%lu", (unsigned long)commands.count);
    gIOSAvailable = YES;
    gPreparing = NO;
    gPrepared = YES;
    return YES;
}

#pragma mark - Shell context

@interface WQShellContext : NSObject
@property (nonatomic) int descriptor;
@property (nonatomic, assign) FILE *input;
@property (nonatomic, assign) FILE *output;
@property (nonatomic, assign) FILE *error;
@property (nonatomic, strong) NSMutableArray<NSString *> *history;
@property (nonatomic, copy) NSString *previousDirectory;
@property (nonatomic) BOOL running;
@end

@implementation WQShellContext
@end

static void WQShellWrite(WQShellContext *context, const char *text)
{
    if (!text || !*text) return;
    write(context.descriptor, text, strlen(text));
}

static void WQShellPrintf(WQShellContext *context, NSString *format, ...)
{
    va_list args;
    va_start(args, format);
    NSString *text = [[NSString alloc] initWithFormat:format arguments:args];
    va_end(args);
    WQShellWrite(context, text.UTF8String);
}

static NSString *WQDisplayDirectory(void)
{
    char buffer[PATH_MAX];
    if (!getcwd(buffer, sizeof(buffer))) return @"?";
    NSString *path = [NSString stringWithUTF8String:buffer];
    NSString *home = NSHomeDirectory();
    if ([path isEqualToString:home]) return @"~";
    if ([path hasPrefix:[home stringByAppendingString:@"/"]])
        return [@"~" stringByAppendingString:
            [path substringFromIndex:home.length]];
    return path;
}

static void WQShellPrompt(WQShellContext *context)
{
    NSString *directory = WQDisplayDirectory();
    if (gIOSAvailable)
        WQShellPrintf(context, @"\033[1;32mfilza27.2\033[0m \033[1;34m%s\033[0m$ ",
                      directory.UTF8String);
    else
        WQShellPrintf(context, @"filza27.2 %s$ ", directory.UTF8String);
    fflush(context.output);
}

static NSString *WQExpandPath(NSString *value)
{
    if ([value isEqualToString:@"~"]) return NSHomeDirectory();
    if ([value hasPrefix:@"~/"])
        return [NSHomeDirectory() stringByAppendingString:
            [value substringFromIndex:1]];
    return value;
}

static void WQChangeDirectory(WQShellContext *context, NSString *target)
{
    NSString *previous = [NSString stringWithUTF8String:getcwd(NULL, 0) ?: "/"];
    if ([target isEqualToString:@"-"]) target = context.previousDirectory ?: previous;
    target = WQExpandPath(target);
    if (chdir(target.fileSystemRepresentation) != 0) {
        WQShellPrintf(context, @"cd: %s: %s\r\n", target.UTF8String,
                      strerror(errno));
        return;
    }
    context.previousDirectory = previous;
    char buffer[PATH_MAX];
    if (getcwd(buffer, sizeof(buffer)))
        setenv("PWD", buffer, 1);
    if (iosSetEnv && getcwd(buffer, sizeof(buffer)))
        iosSetEnv("PWD", buffer, 1);
}

static NSArray<NSString *> *WQSplitCommand(NSString *line)
{
    NSMutableArray<NSString *> *words = [NSMutableArray array];
    NSMutableString *current = [NSMutableString string];
    BOOL singleQuote = NO, doubleQuote = NO, escaped = NO;
    for (NSUInteger index = 0; index < line.length; index++) {
        unichar character = [line characterAtIndex:index];
        if (escaped) {
            [current appendFormat:@"%C", character];
            escaped = NO;
            continue;
        }
        if (character == '\\' && !singleQuote) {
            escaped = YES;
            continue;
        }
        if (character == '\'' && !doubleQuote) {
            singleQuote = !singleQuote;
            continue;
        }
        if (character == '"' && !singleQuote) {
            doubleQuote = !doubleQuote;
            continue;
        }
        if ((character == ' ' || character == '\t') && !singleQuote && !doubleQuote) {
            if (current.length) {
                [words addObject:current.copy];
                [current setString:@""];
            }
            continue;
        }
        [current appendFormat:@"%C", character];
    }
    if (current.length) [words addObject:current.copy];
    return words;
}

static int WQRunPackages(NSArray<NSString *> *words, FILE *out, FILE *err)
{
    if (words.count == 0) return 1;
    NSUInteger count = (NSUInteger)words.count;
    char **argv = calloc(count + 1, sizeof(char *));
    for (NSUInteger index = 0; index < count; index++)
        argv[index] = strdup(words[index].UTF8String);
    argv[count] = NULL;
    int result = 127;
    NSString *command = words.firstObject;
    if ([command isEqualToString:@"dpkg"] ||
        [command isEqualToString:@"dpkg-deb"])
        result = WQDPKGMain((int)count, argv, out, err);
    else
        result = WQAptMain((int)count, argv, out, err);
    for (NSUInteger index = 0; index < count; index++) free(argv[index]);
    free(argv);
    return result;
}

static BOOL WQFallbackCommand(NSArray<NSString *> *words, WQShellContext *context)
{
    if (words.count == 0) return YES;
    NSString *command = words.firstObject;
    NSFileManager *fm = NSFileManager.defaultManager;
    if ([command isEqualToString:@"pwd"]) {
        char buffer[PATH_MAX];
        WQShellPrintf(context, @"%s\r\n", getcwd(buffer, sizeof(buffer)) ?: "?");
        return YES;
    }
    if ([command isEqualToString:@"echo"]) {
        NSArray *rest = [words subarrayWithRange:NSMakeRange(1, words.count - 1)];
        WQShellPrintf(context, @"%s\r\n", [rest componentsJoinedByString:@" "].UTF8String);
        return YES;
    }
    if ([command isEqualToString:@"ls"]) {
        NSString *path = words.count > 1 ? WQExpandPath(words[1]) : @".";
        NSArray *names = [fm contentsOfDirectoryAtPath:path error:nil];
        if (!names) {
            WQShellPrintf(context, @"ls: %s: %s\r\n", path.UTF8String, strerror(errno));
            return YES;
        }
        for (NSString *name in [names sortedArrayUsingSelector:@selector(localizedStandardCompare:)])
            WQShellPrintf(context, @"%s\r\n", name.UTF8String);
        return YES;
    }
    if ([command isEqualToString:@"cat"]) {
        if (words.count < 2) { WQShellPrintf(context, @"cat: missing file\r\n"); return YES; }
        NSData *data = [NSData dataWithContentsOfFile:WQExpandPath(words[1])];
        if (data) {
            write(context.descriptor, data.bytes, data.length);
            WQShellWrite(context, "\r\n");
        } else {
            WQShellPrintf(context, @"cat: %s: %s\r\n", words[1].UTF8String, strerror(errno));
        }
        return YES;
    }
    if ([command isEqualToString:@"mkdir"] || [command isEqualToString:@"rm"] ||
        [command isEqualToString:@"touch"]) {
        if (words.count < 2) return YES;
        NSString *path = WQExpandPath(words[1]);
        NSError *error = nil;
        BOOL ok = YES;
        if ([command isEqualToString:@"mkdir"])
            ok = [fm createDirectoryAtPath:path withIntermediateDirectories:YES
                                attributes:nil error:&error];
        else if ([command isEqualToString:@"rm"])
            ok = [fm removeItemAtPath:path error:&error];
        else
            ok = [fm createFileAtPath:path contents:nil attributes:nil];
        if (!ok) WQShellPrintf(context, @"%s: %s\r\n", command.UTF8String,
                               error.localizedDescription.UTF8String);
        return YES;
    }
    if ([command isEqualToString:@"help"] || [command isEqualToString:@"?"]) {
        WQShellWrite(context,
            "filza27.2 shell commands\r\n"
            "  cd, pwd, ls, cat, echo, mkdir, rm, touch, clear, exit\r\n"
            "  apt / apt-get  update | list | search | show | install | remove\r\n"
            "  dpkg           -i <deb> | -l | -s | -L | -r | --contents\r\n"
            "  any a-Shell mini command (ls, grep, sed, awk, curl, tar, vim, ...)\r\n");
        return YES;
    }
    return NO;
}

static void WQHexDump(WQShellContext *context, NSString *path, NSUInteger limit)
{
    NSData *data = [NSData dataWithContentsOfFile:WQExpandPath(path)];
    if (!data) {
        WQShellPrintf(context, @"hexdump: %@: %s\r\n", path, strerror(errno));
        return;
    }
    NSUInteger length = MIN(data.length, limit);
    const uint8_t *bytes = data.bytes;
    for (NSUInteger offset = 0; offset < length; offset += 16) {
        NSMutableString *line = [NSMutableString stringWithFormat:@"%08lx  ",
            (unsigned long)offset];
        NSUInteger row = MIN((NSUInteger)16, length - offset);
        for (NSUInteger i = 0; i < 16; i++) {
            if (i < row) [line appendFormat:@"%02x ", bytes[offset + i]];
            else [line appendString:@"   "];
            if (i == 7) [line appendString:@" "];
        }
        [line appendString:@" |"];
        for (NSUInteger i = 0; i < row; i++) {
            uint8_t c = bytes[offset + i];
            [line appendFormat:@"%c", (c >= 32 && c < 127) ? c : '.'];
        }
        [line appendString:@"|\r\n"];
        WQShellWrite(context, line.UTF8String);
    }
}

static BOOL WQRunSBXCommand(NSArray<NSString *> *words, WQShellContext *context)
{
    if (words.count == 0) return NO;
    NSString *command = words.firstObject;
    if ([command isEqualToString:@"sbx_help"]) command = @"sbxhelp";
    if ([command isEqualToString:@"sbx_status"]) {
        WQShellPrintf(context, @"hub: %@\r\n", WQVirtualRootFolder());
        WQShellPrintf(context, @"active handles: %lu\r\n",
            (unsigned long)WQActiveGrantHandles().count);
        for (NSString *root in WQAccessibleRoots())
            WQShellPrintf(context, @"  root: %@\r\n", root);
        return YES;
    }
    if ([command isEqualToString:@"sbx_remount"]) {
        WQRefreshDiscovery();
        WQShellWrite(context, "sbx_remount: discovery restarted\r\n");
        return YES;
    }
    if ([command isEqualToString:@"sbx_ls"]) {
        NSString *path = words.count > 1 ? WQExpandPath(words[1]) : @".";
        NSError *error = nil;
        NSArray *names = [NSFileManager.defaultManager contentsOfDirectoryAtPath:path
            error:&error];
        if (!names) {
            WQShellPrintf(context, @"sbx_ls: %@: %@\r\n", path,
                error.localizedDescription ?: @"unreadable");
            return YES;
        }
        for (NSString *name in [names sortedArrayUsingSelector:
                @selector(localizedStandardCompare:)]) {
            NSString *full = [path stringByAppendingPathComponent:name];
            BOOL directory = NO;
            [NSFileManager.defaultManager fileExistsAtPath:full isDirectory:&directory];
            WQShellPrintf(context, @"%@%@\r\n", name, directory ? @"/" : @"");
        }
        return YES;
    }
    if ([command isEqualToString:@"sbx_cat"]) {
        if (words.count < 2) { WQShellWrite(context, "usage: sbx_cat <file>\r\n"); return YES; }
        NSData *data = [NSData dataWithContentsOfFile:WQExpandPath(words[1])];
        if (!data) {
            WQShellPrintf(context, @"sbx_cat: %@: %s\r\n", words[1], strerror(errno));
        } else {
            write(context.descriptor, data.bytes, data.length);
            WQShellWrite(context, "\r\n");
        }
        return YES;
    }
    if ([command isEqualToString:@"sbx_cp"]) {
        if (words.count < 3) { WQShellWrite(context, "usage: sbx_cp <src> <dst>\r\n"); return YES; }
        NSError *error = nil;
        BOOL ok = [NSFileManager.defaultManager copyItemAtPath:WQExpandPath(words[1])
            toPath:WQExpandPath(words[2]) error:&error];
        if (!ok) WQShellPrintf(context, @"sbx_cp: %@\r\n",
            error.localizedDescription ?: @"copy failed");
        else WQShellWrite(context, "sbx_cp: copied\r\n");
        return YES;
    }
    if ([command isEqualToString:@"sbx_hexdump"]) {
        NSUInteger index = 1;
        NSUInteger limit = 256;
        if (index < words.count && [words[index] isEqualToString:@"-n"]) {
            if (index + 1 < words.count) {
                limit = (NSUInteger)MAX(1, words[index + 1].integerValue);
                index += 2;
            }
        }
        if (index >= words.count) {
            WQShellWrite(context, "usage: sbx_hexdump [-n N] <file>\r\n");
            return YES;
        }
        WQHexDump(context, words[index], limit);
        return YES;
    }
    if ([command isEqualToString:@"sbx_containers"]) {
        if (words.count > 1) {
            NSString *root = WQExpandPath(words[1]);
            NSArray *children = WQChildrenForRoot(root);
            WQShellPrintf(context, @"%@: %lu child(ren)\r\n", root,
                (unsigned long)children.count);
            for (NSString *child in children)
                WQShellPrintf(context, @"  %@\r\n", child);
        } else {
            for (NSString *root in WQAccessibleRoots())
                WQShellPrintf(context, @"%@ (%lu)\r\n", root,
                    (unsigned long)WQChildrenForRoot(root).count);
        }
        return YES;
    }
    if ([command isEqualToString:@"sbx_id"]) {
        if (words.count < 2) { WQShellWrite(context, "usage: sbx_id <container>\r\n"); return YES; }
        NSString *identifier = WQIdentifyContainerPath(WQExpandPath(words[1]));
        WQShellPrintf(context, @"%@\r\n", identifier ?: @"(unidentified)");
        return YES;
    }
    if ([command isEqualToString:@"sbx_grant"]) {
        BOOL create = NO;
        NSUInteger index = 1;
        if (index < words.count && [words[index] isEqualToString:@"-c"]) {
            create = YES; index++;
        }
        if (index >= words.count) {
            WQShellWrite(context, "usage: sbx_grant [-c] <path>\r\n");
            return YES;
        }
        NSString *path = WQExpandPath(words[index]);
        if (WQGrantExtraPath(path, create))
            WQShellPrintf(context, @"sbx_grant: ok %@\r\n", path);
        else
            WQShellPrintf(context, @"sbx_grant: failed %@\r\n", path);
        return YES;
    }
    if ([command isEqualToString:@"sbx_release"]) {
        if (words.count < 2) { WQShellWrite(context, "usage: sbx_release <handle|all>\r\n"); return YES; }
        if ([words[1] isEqualToString:@"all"]) {
            WQReleaseAllGrants();
            WQShellWrite(context, "sbx_release: released all\r\n");
        } else {
            NSNumber *handle = @(words[1].longLongValue);
            WQReleaseGrantHandle(handle);
            WQShellPrintf(context, @"sbx_release: %@\r\n", words[1]);
        }
        return YES;
    }
    return NO;
}

static void WQPrintMounts(WQShellContext *context)
{
    struct statfs *mounts = NULL;
    int count = getmntinfo(&mounts, MNT_NOWAIT);
    if (count <= 0) {
        WQShellPrintf(context, @"mount: %s\r\n", strerror(errno));
        return;
    }
    for (int index = 0; index < count; index++) {
        NSString *source = [NSString stringWithUTF8String:
            mounts[index].f_mntfromname];
        NSString *target = [NSString stringWithUTF8String:
            mounts[index].f_mntonname];
        NSString *type = [NSString stringWithUTF8String:
            mounts[index].f_fstypename];
        NSMutableArray<NSString *> *flags = [NSMutableArray array];
        [flags addObject:(mounts[index].f_flags & MNT_RDONLY)
            ? @"read-only" : @"read-write"];
        if (mounts[index].f_flags & MNT_LOCAL) [flags addObject:@"local"];
        if (mounts[index].f_flags & MNT_NOSUID) [flags addObject:@"nosuid"];
        if (mounts[index].f_flags & MNT_NODEV) [flags addObject:@"nodev"];
#ifdef MNT_DONTBROWSE
        if (mounts[index].f_flags & MNT_DONTBROWSE) [flags addObject:@"nobrowse"];
#endif
        WQShellPrintf(context, @"%@ on %@ (%@, %@)\r\n", source, target, type,
            [flags componentsJoinedByString:@", "]);
    }
}

static BOOL WQRunArchiveCommand(NSArray<NSString *> *words,
                                WQShellContext *context)
{
    if (words.count == 0) return NO;
    NSString *command = words.firstObject;
    if (![command isEqualToString:@"extract"] &&
        ![command isEqualToString:@"unarchive"] &&
        ![command isEqualToString:@"unzip"] &&
        ![command isEqualToString:@"untar"] &&
        ![command isEqualToString:@"un7z"] &&
        ![command isEqualToString:@"unrar"])
        return NO;

    NSMutableArray<NSString *> *arguments = [NSMutableArray array];
    NSString *destination = nil;
    for (NSUInteger index = 1; index < words.count; index++) {
        NSString *word = words[index];
        if (([word isEqualToString:@"-C"] || [word isEqualToString:@"-d"]) &&
            index + 1 < words.count) {
            destination = WQExpandPath(words[++index]);
        } else {
            [arguments addObject:word];
        }
    }
    if (arguments.count == 0) {
        WQShellPrintf(context,
            @"usage: %@ <archive> [-C <directory>]\r\n", command);
        return YES;
    }
    NSString *archive = WQExpandPath(arguments[0]);
    if (!destination && arguments.count > 1)
        destination = WQExpandPath(arguments[1]);
    if (!destination)
        destination = WQDefaultExtractDestination(archive);

    NSString *message = nil;
    BOOL ok = WQExtractArchive(archive, destination, &message);
    WQShellPrintf(context, @"%@\r\n", message ?:
        (ok ? @"extract: ok" : @"extract: failed"));
    return YES;
}

static NSString *WQSingleQuote(NSString *value)
{
    NSString *escaped = [value stringByReplacingOccurrencesOfString:@"'"
        withString:@"'\\''"];
    return [NSString stringWithFormat:@"'%@'", escaped];
}

static BOOL WQRunExternalExecutable(NSArray<NSString *> *words,
                                    WQShellContext *context)
{
    if (words.count == 0) return NO;
    NSString *command = words.firstObject;
    if (![command containsString:@"/"] && ![command hasPrefix:@"."]) return NO;
    NSString *path = WQExpandPath(command);

    struct stat info;
    if (stat(path.fileSystemRepresentation, &info) != 0) {
        WQShellPrintf(context, @"%s: %s\r\n", command.UTF8String,
            strerror(errno));
        return YES;
    }
    if (!S_ISREG(info.st_mode) || !(info.st_mode & S_IXUSR)) {
        WQShellPrintf(context, @"%s: permission denied\r\n", command.UTF8String);
        return YES;
    }

    // Scripts are executed inside the bundled dash. Executing a new Mach-O
    // from the data container is rejected by the sandbox on iOS.
    char shebang[3] = {0};
    int head = open(path.fileSystemRepresentation, O_RDONLY);
    if (head >= 0) {
        read(head, shebang, 2);
        close(head);
    }
    if (shebang[0] == '#' && shebang[1] == '!') {
        if (!iosSystem) {
            WQShellWrite(context, "dash: unavailable\r\n");
            return YES;
        }
        NSMutableString *line = [NSMutableString stringWithString:@"dash "];
        [line appendString:WQSingleQuote(path)];
        for (NSUInteger index = 1; index < words.count; index++) {
            [line appendString:@" "];
            [line appendString:WQSingleQuote(words[index])];
        }
        iosSystem(line.UTF8String);
        fflush(context.output);
        return YES;
    }

    posix_spawn_file_actions_t actions;
    posix_spawn_file_actions_init(&actions);
    posix_spawn_file_actions_adddup2(&actions, fileno(context.output),
        STDOUT_FILENO);
    posix_spawn_file_actions_adddup2(&actions, fileno(context.error),
        STDERR_FILENO);

    NSUInteger count = words.count;
    char **argv = calloc(count + 1, sizeof(char *));
    if (!argv) {
        posix_spawn_file_actions_destroy(&actions);
        return YES;
    }
    for (NSUInteger index = 0; index < count; index++)
        argv[index] = strdup(words[index].UTF8String);
    argv[count] = NULL;

    pid_t pid = 0;
    int result = posix_spawn(&pid, path.fileSystemRepresentation,
        &actions, NULL, argv, environ);
    posix_spawn_file_actions_destroy(&actions);
    for (NSUInteger index = 0; index < count; index++) free(argv[index]);
    free(argv);

    if (result != 0) {
        NSLog(@"[Exec] posix_spawn %@ failed: %s (%d)", path,
            strerror(result), result);
        WQShellPrintf(context, @"%s: %s (data-container binaries cannot be "
            @"executed; use a shell script)\r\n", command.UTF8String,
            strerror(result));
        return YES;
    }
    int status = 0;
    waitpid(pid, &status, 0);
    fflush(context.output);
    return YES;
}

static void WQPrintNeofetch(WQShellContext *context)
{
    struct utsname info;
    uname(&info);
    NSString *device = @"iPhone";
    size_t size = 0;
    if (sysctlbyname("hw.machine", NULL, &size, NULL, 0) == 0 && size > 0) {
        char *machine = calloc(1, size);
        if (machine && sysctlbyname("hw.machine", machine, &size, NULL, 0) == 0)
            device = [NSString stringWithUTF8String:machine] ?: device;
        free(machine);
    }
    NSString *os = [NSString stringWithFormat:@"iOS %@",
        NSProcessInfo.processInfo.operatingSystemVersionString];
    NSString *uptime = [NSString stringWithFormat:@"%.0f min",
        NSProcessInfo.processInfo.systemUptime / 60.0];
    double memory = NSProcessInfo.processInfo.physicalMemory / 1073741824.0;
    struct statfs disk = {0};
    statfs("/", &disk);
    double total = (double)disk.f_blocks * disk.f_bsize / 1073741824.0;
    double freeSpace = (double)disk.f_bavail * disk.f_bsize / 1073741824.0;

    const char *logo[] = {
        "                    'c.",
        "                 ,xNMM.",
        "               .OMMMMo",
        "               lMM\"",
        "     .;loddo:.  .olloddol;.",
        "   cKMMMMMMMMMMNWMMMMMMMMMM0:",
        " .KMMMMMMMMMMMMMMMMMMMMMMMWd.",
        " XMMMMMMMMMMMMMMMMMMMMMMMX.",
        ";MMMMMMMMMMMMMMMMMMMMMMMM:",
        ":MMMMMMMMMMMMMMMMMMMMMMMM:",
        ".MMMMMMMMMMMMMMMMMMMMMMMMX.",
        " kMMMMMMMMMMMMMMMMMMMMMMMMWd.",
        " 'XMMMMMMMMMMMMMMMMMMMMMMMMMMk",
        "  'XMMMMMMMMMMMMMMMMMMMMMMMMK.",
        "    kMMMMMMMMMMMMMMMMMMMMMMd",
        "     ;KMMMMMMMWXXWMMMMMMMk.",
        "       'cooc*\"    \"*coo'",
        NULL
    };
    NSMutableString *out = [NSMutableString string];
    [out appendString:@"\r\n"];
    NSInteger logoCount = 0;
    while (logo[logoCount]) logoCount++;
    NSArray *lines = @[
        [NSString stringWithFormat:@"filza27.2@%@", device],
        @"-----------------",
        [NSString stringWithFormat:@"OS: %@", os],
        [NSString stringWithFormat:@"Host: %@", device],
        [NSString stringWithFormat:@"Kernel: %s %s", info.sysname, info.release],
        [NSString stringWithFormat:@"Uptime: %@", uptime],
        [NSString stringWithFormat:@"Memory: %.1f GB", memory],
        [NSString stringWithFormat:@"Disk: %.1f/%.1f GB", total - freeSpace, total],
        [NSString stringWithFormat:@"Shell: filza27.2 (%@)", gIOSAvailable ? @"ios_system" : @"builtin"],
        [NSString stringWithFormat:@"Terminal: %@", @"Filza WQ"],
        [NSString stringWithFormat:@"WQ roots: %lu", (unsigned long)WQAccessibleRoots().count],
    ];
    for (NSInteger i = 0; i < MAX(logoCount, (NSInteger)lines.count); i++) {
        NSString *left = i < logoCount ? @(logo[i]) : @"";
        NSString *right = i < (NSInteger)lines.count ? lines[i] : @"";
        [out appendFormat:@"%@%@%@\r\n", left,
            left.length < 52 ? [@"" stringByPaddingToLength:52 - left.length
                withString:@" " startingAtIndex:0] : @" ", right];
    }
    [out appendString:@"\r\n"];
    WQShellWrite(context, out.UTF8String);
}

static void WQPrintSBXHelp(WQShellContext *context)
{
    WQShellWrite(context,
        "\r\nFilza WQ / worse_query shell\r\n"
        "================================\r\n"
        "  sbxhelp                     this help\r\n"
        "  sbx_status                  active grants and mount status\r\n"
        "  sbx_remount                 re-run container discovery\r\n"
        "  sbx_grant [-c] <path>       grant a sandbox extension\r\n"
        "  sbx_release <handle|all>    release extensions\r\n"
        "  sbx_ls <path>               list a directory\r\n"
        "  sbx_cat <file>              print a file\r\n"
        "  sbx_cp <src> <dst>          copy a file\r\n"
        "  sbx_hexdump [-n N] <file>   hex dump\r\n"
        "  sbx_containers [root]       enumerate container UUIDs\r\n"
        "  sbx_id <container_path>     identify a container\r\n"
        "  mount                       list mounted filesystems\r\n"
        "  extract <archive> [-C dir]  unzip/tar/gz/7z/rar/xz/bz2/zst\r\n"
        "  neofetch                    system information\r\n"
        "  respring                    restart SpringBoard\r\n"
        "  apt / apt-get               update|list|search|show|install|remove\r\n"
        "  dpkg / dpkg-deb             -i|-l|-s|-L|-r|-x|--contents\r\n"
        "  The full a-Shell mini command set is also available.\r\n\r\n");
}

static void WQShellLoop(WQShellContext *context)
{
    @autoreleasepool {
        [NSThread currentThread].name = @"filza27.2-shell";
        if (!WQTerminalPrepare())
            WQShellWrite(context, "ios_system unavailable; using built-in commands\r\n");
        char sessionName[64];
        snprintf(sessionName, sizeof(sessionName), "filza-wq-%p", context);
        if (iosSwitchSession) iosSwitchSession(sessionName);
        if (iosSetTty) iosSetTty(context.output);
        if (iosSetStreams) iosSetStreams(context.input, context.output, context.error);

        WQShellWrite(context,
            "\r\nfilza27.2 — iOS 27.2 worse_query terminal\r\n"
            "Type 'help' for commands. Filesystem uses the active sandbox extensions.\r\n\r\n");
        WQShellPrompt(context);

        NSMutableString *line = [NSMutableString string];
        NSInteger historyIndex = -1;
        char character;
        while (context.running) {
            ssize_t got = read(context.descriptor, &character, 1);
            if (got <= 0) break;
            if (character == '\r' || character == '\n') {
                WQShellWrite(context, "\r\n");
                NSString *command = [line stringByTrimmingCharactersInSet:
                    NSCharacterSet.whitespaceCharacterSet];
                [line setString:@""];
                historyIndex = -1;
                if (command.length) {
                    if (![context.history.lastObject isEqualToString:command]) {
                        [context.history addObject:command];
                        if (context.history.count > 100)
                            [context.history removeObjectAtIndex:0];
                    }
                    NSArray *words = WQSplitCommand(command);
                    NSString *first = words.firstObject;
                    if ([first isEqualToString:@"exit"] ||
                        [first isEqualToString:@"logout"]) {
                        WQShellWrite(context, "logout\r\n");
                        break;
                    }
                    if ([first isEqualToString:@"clear"]) {
                        WQShellWrite(context, "\033[2J\033[H");
                    } else if ([first isEqualToString:@"cd"]) {
                        NSString *target = words.count > 1 ? words[1] : NSHomeDirectory();
                        WQChangeDirectory(context, target);
                    } else if ([first hasPrefix:@"sbx_"]) {
                        if (!WQRunSBXCommand(words, context))
                            WQShellPrintf(context, @"%@: unknown sbx command\r\n",
                                          first);
                    } else if ([first isEqualToString:@"respring"] ||
                               [first isEqualToString:@"springboard"]) {
                        WQShellWrite(context, "respring: restarting SpringBoard...\r\n");
                        WQPerformRespring();
                    } else if ([first isEqualToString:@"mount"]) {
                        WQPrintMounts(context);
                    } else if ([first isEqualToString:@"neofetch"]) {
                        WQPrintNeofetch(context);
                    } else if ([first isEqualToString:@"sbxhelp"] ||
                               [first isEqualToString:@"badshell"]) {
                        WQPrintSBXHelp(context);
                    } else if ([first isEqualToString:@"apt"] ||
                               [first isEqualToString:@"apt-get"] ||
                               [first isEqualToString:@"dpkg"] ||
                               [first isEqualToString:@"dpkg-deb"]) {
                        WQRunPackages(words, context.output, context.error);
                        fflush(context.output);
                    } else if (WQRunArchiveCommand(words, context)) {
                        // extracted with libarchive
                    } else if (WQRunExternalExecutable(words, context)) {
                        // executed an explicit executable path
                    } else if (!gIOSAvailable && WQFallbackCommand(words, context)) {
                        // handled by fallback
                    } else {
                        int status = iosSystem ? iosSystem(command.UTF8String) : 127;
                        if (status != 0 && !gIOSAvailable) {
                            WQShellPrintf(context, @"%s: command not found\r\n",
                                          first.UTF8String);
                        }
                        fflush(context.output);
                    }
                }
                WQShellPrompt(context);
                continue;
            }
            if (character == 0x7f || character == 0x08) {
                if (line.length) {
                    [line deleteCharactersInRange:
                        NSMakeRange(line.length - 1, 1)];
                    WQShellWrite(context, "\b \b");
                }
                continue;
            }
            if (character == 0x03) {
                [line setString:@""];
                WQShellWrite(context, "^C\r\n");
                WQShellPrompt(context);
                continue;
            }
            if (character == 0x04) {
                if (line.length == 0) {
                    WQShellWrite(context, "logout\r\n");
                    break;
                }
                continue;
            }
            if (character == 0x1b) {
                char sequence[3] = {0};
                if (read(context.descriptor, sequence, 2) != 2) continue;
                if (sequence[0] == '[' && (sequence[1] == 'A' || sequence[1] == 'B')) {
                    if (context.history.count == 0) continue;
                    if (historyIndex < 0) historyIndex = (NSInteger)context.history.count;
                    historyIndex += (sequence[1] == 'A') ? -1 : 1;
                    if (historyIndex < 0) historyIndex = 0;
                    if (historyIndex >= (NSInteger)context.history.count)
                        historyIndex = (NSInteger)context.history.count;
                    for (NSUInteger i = 0; i < line.length; i++)
                        WQShellWrite(context, "\b \b");
                    [line setString:@""];
                    if (historyIndex < (NSInteger)context.history.count) {
                        [line appendString:context.history[(NSUInteger)historyIndex]];
                        WQShellWrite(context, line.UTF8String);
                    }
                }
                continue;
            }
            if (character == '\t') continue;
            if (character >= 0x20 || character < 0) {
                [line appendFormat:@"%c", character];
                write(context.descriptor, &character, 1);
            }
        }
        context.running = NO;
        fclose(context.input);
        fclose(context.output);
        fclose(context.error);
        close(context.descriptor);
    }
}

void WQTerminalSelfTest(void)
{
    int pid = -1;
    int descriptor = WQTerminalSpawnShell(&pid, NSHomeDirectory());
    if (descriptor < 0) {
        NSLog(@"[Terminal] self-test spawn failed");
        return;
    }
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 600 * NSEC_PER_MSEC),
        dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        NSMutableString *command = [NSMutableString stringWithString:
            @"echo WQ_TERMINAL_OK\r"
            @"sbxhelp\r"
            @"neofetch\r"
            @"sbx_status\r"
            @"ssh -V\r"
            @"apt --version\r"
            @"dpkg --version\r"
            @"perl -v\r"
            @"rg --version\r"
            @"make --version\r"
            @"badshell\r"
            @"ls /\r"];
        NSString *debPath = [[NSSearchPathForDirectoriesInDomains(
            NSDocumentDirectory, NSUserDomainMask, YES).firstObject
            stringByAppendingPathComponent:@"test.deb"] copy];
        if ([[NSFileManager defaultManager] fileExistsAtPath:debPath]) {
            [command appendFormat:@"dpkg -i %@\r", debPath];
            [command appendString:@"dpkg -l\r"];
            [command appendString:@"dpkg -L wqtest\r"];
            NSString *installed = [[[debPath stringByDeletingLastPathComponent]
                stringByAppendingPathComponent:@".terminal/root/usr/share/wqtest/hello.txt"] copy];
            [command appendFormat:@"cat %@\r", installed];
        }
        write(descriptor, command.UTF8String, strlen(command.UTF8String));
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 6000 * NSEC_PER_MSEC),
            dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
            char buffer[131072] = {0};
            ssize_t got = read(descriptor, buffer, sizeof(buffer) - 1);
            NSLog(@"[Terminal] self-test output (%zd bytes):\n%s",
                  got, got > 0 ? buffer : "(none)");
            close(descriptor);
        });
    });
}

void WQTerminalPresentTestUI(void)
{
    Class terminalClass = NSClassFromString(@"NewTerminalViewController");
    if (!terminalClass) terminalClass = NSClassFromString(@"TerminalViewController");
    if (!terminalClass) return;
    id controller = nil;
    SEL selector = NSSelectorFromString(@"initWithCommand:uiConfig:withKeyboard:");
    if ([terminalClass instancesRespondToSelector:selector]) {
        id (*function)(id, SEL, id, id, BOOL) = (id(*)(id, SEL, id, id, BOOL))objc_msgSend;
        controller = function([terminalClass alloc], selector, @"fish", nil, YES);
    } else {
        controller = [[terminalClass alloc] init];
    }
    dispatch_async(dispatch_get_main_queue(), ^{
        UIWindow *window = nil;
        for (UIWindow *candidate in UIApplication.sharedApplication.windows)
            if (candidate.isKeyWindow && !candidate.isHidden) { window = candidate; break; }
        if (!window)
            for (UIWindow *candidate in UIApplication.sharedApplication.windows)
                if (!candidate.isHidden) { window = candidate; break; }
        [window.rootViewController presentViewController:controller
            animated:YES completion:nil];
    });
}

int WQTerminalSpawnShell(int *pidOut, NSString *chdirPath)
{
    if (pidOut) *pidOut = 999999;
    WQTerminalPrepare();
    if (chdirPath.length) chdir(chdirPath.fileSystemRepresentation);

    int master = -1;
    int slave = -1;
    struct winsize windowSize = {0};
    windowSize.ws_row = 40;
    windowSize.ws_col = 100;
    BOOL usingPTY = openpty(&master, &slave, NULL, NULL, &windowSize) == 0;
    if (!usingPTY) {
        // The app sandbox denies /dev/ptmx (openpty returns EPERM). A
        // socketpair still gives the terminal UI a bidirectional descriptor,
        // and our in-process shell implements its own line editing.
        int pair[2] = {-1, -1};
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) != 0) {
            NSLog(@"[Terminal] socketpair failed errno=%d", errno);
            return -1;
        }
        master = pair[0];
        slave = pair[1];
        NSLog(@"[Terminal] openpty unavailable (errno=%d), using socketpair", errno);
    } else {
        // The UI puts the PTY in raw mode. Do the same on the slave so the
        // shell loop receives one keystroke at a time.
        struct termios attributes;
        if (tcgetattr(slave, &attributes) == 0) {
            cfmakeraw(&attributes);
            attributes.c_oflag |= OPOST | ONLCR;
            tcsetattr(slave, TCSANOW, &attributes);
        }
    }

    WQShellContext *context = [WQShellContext new];
    context.descriptor = slave;
    context.input = fdopen(dup(slave), "r");
    context.output = fdopen(dup(slave), "w");
    context.error = fdopen(dup(slave), "w");
    context.history = [NSMutableArray array];
    context.running = YES;
    setvbuf(context.output, NULL, _IONBF, 0);
    setvbuf(context.error, NULL, _IONBF, 0);

    dispatch_queue_t queue = dispatch_queue_create(
        "com.filzaslop.worsequery.shell", DISPATCH_QUEUE_SERIAL);
    dispatch_async(queue, ^{ WQShellLoop(context); });
    NSLog(@"[Terminal] in-process shell master=%d slave=%d", master, slave);
    return master;
}
