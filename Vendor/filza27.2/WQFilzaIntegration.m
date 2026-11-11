//
//  WQFilzaIntegration.m
//  FilzaSlop
//
//  worse_query (GPL-3.0) integration for iOS 26/27, including iOS 27.2.
//  The primitive needs only a provisioned App Group; it does not depend on
//  the MobileHouseArrest code identity or on a kernel exploit.
//

#import "WQFilzaIntegration.h"
#import "MCMFilzaIntegration.h"
#import "worse_query.h"
#import "pathleak.h"
#import "fallback_query.h"
#import "WQLSStore.h"

#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <dlfcn.h>
#import <errno.h>
#import <fcntl.h>
#import <sys/stat.h>
#import <unistd.h>

typedef struct __SecTask *WQSecTaskRef;
extern WQSecTaskRef SecTaskCreateFromSelf(CFAllocatorRef allocator);
extern CFTypeRef SecTaskCopyValueForEntitlement(WQSecTaskRef task,
                                                CFStringRef entitlement,
                                                CFErrorRef *error);

static NSString *const kWQFolderName = @"worse_query";
static NSString *const kWQFavoritesMarker = @"WQv1";

static NSLock *gQueryLock;
static NSLock *gAppsLock;
static NSMutableDictionary<NSString *, NSNumber *> *gGrantHandles;
static NSMutableArray<NSString *> *gGrantedRoots;
static NSMutableDictionary<NSString *, NSString *> *gRootDisplayNames;
static NSString *gAppGroup;
static BOOL gStarted;
static BOOL gFavoritesInstalled;

static NSArray<NSDictionary<NSString *, NSString *> *> *gAppsCache;
static NSDate *gAppsCacheDate;
static NSMutableDictionary<NSString *, NSString *> *gBundleMap;
static NSMutableDictionary<NSString *, NSString *> *gDataMap;
static BOOL gBundleMapAttempted;
static NSObject *gBundleMapLock;
static dispatch_queue_t gAppsQueue;
static dispatch_queue_t gFamiliesQueue;
static NSMutableDictionary<NSString *, NSArray<NSString *> *> *gPathleakCache;
static dispatch_group_t gStartupGroup;
static BOOL gStartupActive;
static NSArray<NSString *> *gVolumePaths;
static dispatch_once_t gVolumeOnce;
static NSMutableDictionary<NSString *, NSDictionary *> *gBundleInfo;

static void WQPostStartupProgress(double progress, NSString *status);
static NSArray<NSString *> *WQVolumeChildren(NSString *root);
static NSString *WQContainerIdentifier(NSString *containerPath);
static void WQDiscoverPerContainerFamilies(void);
static NSArray<NSDictionary<NSString *, NSString *> *> *WQBuildAppList(void);
static void WQInstallFavorites(void);

#pragma mark - Paths

static NSString *WQCanonicalPath(NSString *path)
{
    if (![path isKindOfClass:NSString.class] || path.length == 0) return nil;
    NSString *value = [path stringByStandardizingPath];
    if ([value isEqualToString:@"/var"] || [value hasPrefix:@"/var/"])
        value = [@"/private" stringByAppendingString:value];
    return value;
}

static BOOL WQPathExists(NSString *path)
{
    struct stat st;
    return path.length > 0 && lstat(path.fileSystemRepresentation, &st) == 0;
}

static NSInteger WQOSMajor(void)
{
    return NSProcessInfo.processInfo.operatingSystemVersion.majorVersion;
}

static BOOL WQUsesAlternateFlags(NSString *path)
{
    // iOS 26 needs the alternative query flags for app, extension, daemon
    // and app-group containers. iOS 27 normally uses the standard flags.
    (void)path;
    return WQOSMajor() < 27;
}

/// Paths documented by forcequitOS/worse_query, ordered from broadest to most
/// specific. The iOS 27 system locations are separate from the iOS 26 ones.
static NSArray<NSDictionary<NSString *, NSString *> *> *WQCandidateRoots(void)
{
    return @[
        @{ @"path": @"/private/var/mobile/Containers/Data/Application",
           @"name": @"App Data" },
        @{ @"path": @"/private/var/mobile/Containers/Shared/AppGroup",
           @"name": @"App Groups" },
        @{ @"path": @"/private/var/mobile/Containers/Data/PluginKitPlugin",
           @"name": @"Extension Data" },
        @{ @"path": @"/private/var/mobile/Containers/Data/InternalDaemon",
           @"name": @"Internal Daemon Data" },
        @{ @"path": @"/private/var/containers/Data/System",
           @"name": @"System Data" },
        @{ @"path": @"/private/var/containers/Shared/SystemGroup",
           @"name": @"System Groups" },
        // iOS 26 and earlier system container locations.
        @{ @"path": @"/private/var/mobile/Containers/Data/System",
           @"name": @"System Data (legacy)" },
        @{ @"path": @"/private/var/mobile/Containers/Shared/SystemGroup",
           @"name": @"System Groups (legacy)" },
        @{ @"path": @"/private/var/mobile/Containers/Data/VPNPlugin",
           @"name": @"VPN Plugin Data" },
        @{ @"path": @"/private/var/mobile/Containers/Data/Protected",
           @"name": @"Protected Data" },
    ];
}

#pragma mark - App Group

static NSArray<NSString *> *WQEntitledAppGroups(void)
{
    NSMutableOrderedSet<NSString *> *groups = [NSMutableOrderedSet orderedSet];

    WQSecTaskRef task = SecTaskCreateFromSelf(kCFAllocatorDefault);
    if (task) {
        CFTypeRef value = SecTaskCopyValueForEntitlement(task,
            CFSTR("com.apple.security.application-groups"), NULL);
        if (value) {
            if (CFGetTypeID(value) == CFArrayGetTypeID()) {
                for (id group in (__bridge NSArray *)value)
                    if ([group isKindOfClass:NSString.class] &&
                        [(NSString *)group hasPrefix:@"group."])
                        [groups addObject:group];
            }
            CFRelease(value);
        }
        CFRelease(task);
    }

    id plistGroups = [NSBundle.mainBundle objectForInfoDictionaryKey:@"WQAppGroups"];
    if ([plistGroups isKindOfClass:NSArray.class]) {
        for (id group in (NSArray *)plistGroups)
            if ([group isKindOfClass:NSString.class] && [group length] > 0)
                [groups addObject:group];
    }

    return groups.array;
}

NSString *WQBestAppGroup(void)
{
    static NSString *cached;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        NSFileManager *fm = NSFileManager.defaultManager;
        for (NSString *group in WQEntitledAppGroups()) {
            NSURL *container = [fm containerURLForSecurityApplicationGroupIdentifier:group];
            if (!container) continue;
            NSString *library = [container.path stringByAppendingPathComponent:@"Library"];
            [fm createDirectoryAtPath:library withIntermediateDirectories:YES
                           attributes:nil error:nil];
            cached = group;
            break;
        }
        NSLog(@"[WQ] entitled app groups=%@ selected=%@",
              WQEntitledAppGroups(), cached ?: @"(none)");
    });
    return cached;
}

#pragma mark - Query engine

static BOOL WQGrantActuallyOpens(NSString *target)
{
    int descriptor = open(target.fileSystemRepresentation,
        O_RDONLY | O_CLOEXEC);
    if (descriptor >= 0) {
        close(descriptor);
        return YES;
    }
    // An ordinary permission error is not a failed grant. Only EPERM means
    // the sandbox extension did not help.
    return errno != EPERM;
}

static int64_t WQQueryOnce(NSString *target, BOOL alternate,
                           BOOL createIfMissing)
{
    NSString *group = WQBestAppGroup();
    if (!group.length) return -1;
    int64_t handle = worse_query(target, group, alternate, createIfMissing);
    if (handle < 0)
        handle = fallback_query(target, alternate);
    return handle;
}

static int64_t WQAcquireExtension(NSString *target, BOOL createIfMissing)
{
    if (![target hasPrefix:@"/"]) return -255;
    if (!WQBestAppGroup().length) return -1;

    [gQueryLock lock];
    BOOL alternate = WQUsesAlternateFlags(target);
    int64_t handle = WQQueryOnce(target, alternate, createIfMissing);
    int64_t first = handle;
    if (handle >= 0 && !createIfMissing &&
        !WQGrantActuallyOpens(target)) {
        worse_query_release(handle);
        handle = -8;
    }
    if (handle < 0 && handle != -1 && handle != -2) {
        int64_t retry = WQQueryOnce(target, !alternate, createIfMissing);
        if (retry >= 0 && !createIfMissing && !WQGrantActuallyOpens(target)) {
            worse_query_release(retry);
            retry = -8;
        }
        if (retry >= 0) handle = retry;
    }
    if (handle < 0 && getenv("WQ_VERBOSE")) {
        NSLog(@"[WQ] grant failed path=%@ first=%lld final=%lld",
              target, (long long)first, (long long)handle);
    }
    [gQueryLock unlock];
    return handle;
}

static BOOL WQGrantPath(NSString *rawPath, NSString *displayName, BOOL publish)
{
    NSString *path = WQCanonicalPath(rawPath);
    if (!path || !WQPathExists(path)) return NO;

    if (!gGrantHandles) gGrantHandles = [NSMutableDictionary dictionary];
    if (!gGrantedRoots) gGrantedRoots = [NSMutableArray array];
    if (!gRootDisplayNames) gRootDisplayNames = [NSMutableDictionary dictionary];

    NSNumber *existing = gGrantHandles[path];
    if (existing && existing.longLongValue >= 0) {
        if (publish && ![gGrantedRoots containsObject:path]) {
            [gGrantedRoots addObject:path];
            gRootDisplayNames[path] = displayName ?: path.lastPathComponent;
        }
        return YES;
    }

    int64_t handle = WQAcquireExtension(path, NO);
    if (handle < 0) return NO;

    gGrantHandles[path] = @(handle);
    if (publish) {
        if (![gGrantedRoots containsObject:path]) [gGrantedRoots addObject:path];
        gRootDisplayNames[path] = displayName ?: path.lastPathComponent;
    }

    int descriptor = open(path.fileSystemRepresentation,
        O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    int openErrno = descriptor < 0 ? errno : 0;
    if (descriptor >= 0) close(descriptor);

    NSError *listError = nil;
    NSArray *entries = [NSFileManager.defaultManager
        contentsOfDirectoryAtPath:path error:&listError];
    if (publish) {
        NSLog(@"[WQ] granted %@ handle=%lld open=%d errno=%d entries=%lu listErr=%@",
              path, (long long)handle, descriptor >= 0, openErrno,
              (unsigned long)entries.count, listError.localizedDescription ?: @"none");
    }
    return YES;
}

static BOOL WQGrantRoot(NSString *rawPath, NSString *displayName)
{
    return WQGrantPath(rawPath, displayName, YES);
}

static BOOL WQGrantContainer(NSString *rawPath)
{
    return WQGrantPath(rawPath, rawPath.lastPathComponent, NO);
}

BOOL WQIsActive(void)
{
    return gGrantHandles.count > 0;
}

NSArray<NSString *> *WQAccessibleRoots(void)
{
    return gGrantedRoots ?: @[];
}

NSString *WQVirtualRootFolder(void)
{
    return [MCMFilzaVirtualRoot() stringByAppendingPathComponent:kWQFolderName];
}

BOOL WQGrantExtraPath(NSString *path, BOOL createIfMissing)
{
    if (!gQueryLock) gQueryLock = [NSLock new];
    NSString *canonical = WQCanonicalPath(path);
    if (!canonical.length) return NO;
    int64_t handle = WQAcquireExtension(canonical, createIfMissing);
    if (handle < 0) return NO;
    if (!gGrantHandles) gGrantHandles = [NSMutableDictionary dictionary];
    gGrantHandles[canonical] = @(handle);
    return YES;
}

void WQReleaseGrantHandle(NSNumber *handle)
{
    if (!handle) return;
    worse_query_release(handle.longLongValue);
    for (NSString *key in gGrantHandles.allKeys)
        if ([gGrantHandles[key] isEqualToNumber:handle]) {
            [gGrantHandles removeObjectForKey:key];
            [gGrantedRoots removeObject:key];
        }
}

void WQReleaseAllGrants(void)
{
    for (NSNumber *handle in gGrantHandles.allValues)
        worse_query_release(handle.longLongValue);
    [gGrantHandles removeAllObjects];
    [gGrantedRoots removeAllObjects];
}

NSArray<NSNumber *> *WQActiveGrantHandles(void)
{
    return gGrantHandles.allValues ?: @[];
}

NSArray<NSString *> *WQChildrenForRoot(NSString *root)
{
    NSString *canonical = WQCanonicalPath(root);
    if (!canonical.length) return @[];
    NSArray *children = WQVolumeChildren(canonical);
    if (children.count) return children;
    return [NSFileManager.defaultManager contentsOfDirectoryAtPath:canonical
        error:nil] ?: @[];
}

NSString *WQIdentifyContainerPath(NSString *path)
{
    NSString *canonical = WQCanonicalPath(path);
    if (!canonical.length) return nil;
    return WQContainerIdentifier(canonical);
}

void WQRefreshDiscovery(void)
{
    dispatch_async(gFamiliesQueue ?: dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        WQDiscoverPerContainerFamilies();
        if (!gAppsQueue) gAppsQueue = dispatch_queue_create(
            "com.filzaslop.worsequery.apps", DISPATCH_QUEUE_SERIAL);
        dispatch_sync(gAppsQueue, ^{
            gAppsCache = WQBuildAppList();
            gAppsCacheDate = [NSDate date];
        });
        dispatch_async(dispatch_get_main_queue(), ^{ WQInstallFavorites(); });
    });
}

#pragma mark - Virtual root / links

static BOOL WQCreateLink(NSString *linkPath, NSString *target)
{
    NSFileManager *fm = NSFileManager.defaultManager;
    NSString *existing = [fm destinationOfSymbolicLinkAtPath:linkPath error:nil];
    if (existing.length) {
        if ([existing isEqualToString:target]) return YES;
        [fm removeItemAtPath:linkPath error:nil];
    } else if ([fm fileExistsAtPath:linkPath]) {
        // Do not delete a user-created real directory.
        NSLog(@"[WQ] keeping existing non-link at %@", linkPath);
        return NO;
    }
    BOOL ok = [fm createSymbolicLinkAtPath:linkPath
                       withDestinationPath:target error:nil];
    if (!ok) NSLog(@"[WQ] link failed %@ -> %@", linkPath, target);
    return ok;
}

static NSString *WQAppDataFolder(void)
{
    return [WQVirtualRootFolder() stringByAppendingPathComponent:@"App Data (by app)"];
}

static NSString *WQAppDataUUIDFolder(void)
{
    return [WQVirtualRootFolder() stringByAppendingPathComponent:@"App Data (UUID)"];
}

static NSArray<NSDictionary<NSString *, NSString *> *> *WQFavoriteEntries(void)
{
    NSMutableArray *entries = [NSMutableArray array];
    NSString *folder = WQVirtualRootFolder();
    [entries addObject:@{ @"name": @"worse_query · Accessible Roots",
                          @"path": folder }];
    NSString *appFolder = WQAppDataFolder();
    if ([NSFileManager.defaultManager fileExistsAtPath:appFolder]) {
        [entries addObject:@{ @"name": @"worse_query · App Data (by app)",
                              @"path": appFolder }];
    }
    NSString *uuidFolder = WQAppDataUUIDFolder();
    if ([NSFileManager.defaultManager fileExistsAtPath:uuidFolder]) {
        [entries addObject:@{ @"name": @"worse_query · App Data (UUID)",
                              @"path": uuidFolder }];
    }
    for (NSString *path in gGrantedRoots ?: @[]) {
        NSString *name = gRootDisplayNames[path] ?: path.lastPathComponent;
        [entries addObject:@{
            @"name": [NSString stringWithFormat:@"WQ · %@", name],
            @"path": path,
        }];
    }
    for (NSString *name in @[@"System Groups (containers)",
                             @"Extension Data (containers)",
                             @"Internal Daemon Data (containers)"]) {
        NSString *path = [folder stringByAppendingPathComponent:name];
        if ([NSFileManager.defaultManager fileExistsAtPath:path]) {
            [entries addObject:@{ @"name": [NSString stringWithFormat:@"WQ · %@", name],
                                  @"path": path }];
        }
    }
    return entries;
}

static void WQInstallFavorites(void)
{
    Class prefsClass = NSClassFromString(@"TGPreferences");
    if (!prefsClass) return;
    id prefs = [prefsClass respondsToSelector:NSSelectorFromString(@"sharedInstance")]
        ? ((id(*)(id, SEL))objc_msgSend)(prefsClass,
            NSSelectorFromString(@"sharedInstance")) : nil;
    if (!prefs) return;

    NSArray *existing = [prefs respondsToSelector:NSSelectorFromString(@"favoritedLinks")]
        ? ((id(*)(id, SEL))objc_msgSend)(prefs,
            NSSelectorFromString(@"favoritedLinks")) : nil;
    NSMutableArray *mutableLinks = [existing isKindOfClass:NSMutableArray.class]
        ? (NSMutableArray *)existing : nil;
    NSMutableIndexSet *stale = [NSMutableIndexSet indexSet];
    NSFileManager *fm = NSFileManager.defaultManager;
    if (mutableLinks) {
        [mutableLinks enumerateObjectsUsingBlock:^(id item, NSUInteger idx, BOOL *stop) {
            if (![item isKindOfClass:NSDictionary.class]) return;
            NSString *name = item[@"name"];
            NSString *path = item[@"path"];
            BOOL isOurs = [name hasPrefix:@"WQ ·"] || [name hasPrefix:@"worse_query ·"];
            if (!isOurs) return;
            if (!path.length || ![fm fileExistsAtPath:path] ||
                [path containsString:@"App Data (apps)"])
                [stale addIndex:idx];
        }];
        if (stale.count) {
            [mutableLinks removeObjectsAtIndexes:stale];
            ((void(*)(id, SEL))objc_msgSend)(prefs,
                NSSelectorFromString(@"saveFavoritedLinks"));
            NSLog(@"[WQ] removed %lu stale Favorites entries",
                  (unsigned long)stale.count);
        }
    }

    NSMutableSet<NSString *> *paths = [NSMutableSet set];
    for (id item in [existing isKindOfClass:NSArray.class] ? existing : @[]) {
        if (![item isKindOfClass:NSDictionary.class]) continue;
        NSString *path = item[@"path"];
        if (path.length) [paths addObject:path];
    }

    NSUInteger added = 0;
    for (NSDictionary *entry in WQFavoriteEntries()) {
        NSString *path = entry[@"path"];
        if (!path.length || [paths containsObject:path]) continue;
        ((void(*)(id, SEL, id))objc_msgSend)(prefs,
            NSSelectorFromString(@"addItemToFavoritedLinks:"), entry);
        [paths addObject:path];
        added++;
    }
    if (added > 0) {
        ((void(*)(id, SEL))objc_msgSend)(prefs,
            NSSelectorFromString(@"saveFavoritedLinks"));
        NSLog(@"[WQ] added %lu Favorites entries (total requested=%lu)",
              (unsigned long)added,
              (unsigned long)WQFavoriteEntries().count);
    }
    gFavoritesInstalled = YES;
}

static void WQScheduleFavorites(void)
{
    static int attempts;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 1500 * NSEC_PER_MSEC),
        dispatch_get_main_queue(), ^{
            WQInstallFavorites();
            if (++attempts < 12) WQScheduleFavorites();
        });
}

static void WQInstallBundledTestFiles(void)
{
    NSFileManager *fm = NSFileManager.defaultManager;
    NSString *folder = WQVirtualRootFolder();
    NSString *source = [NSBundle.mainBundle.bundlePath
        stringByAppendingPathComponent:@"WQTestFiles"];
    NSArray<NSString *> *names = @[@"test.deb", @"test"];
    for (NSString *name in names) {
        NSString *from = [source stringByAppendingPathComponent:name];
        NSString *to = [folder stringByAppendingPathComponent:name];
        if (![fm fileExistsAtPath:from]) continue;
        NSDictionary *sourceAttributes = [fm attributesOfItemAtPath:from
            error:nil];
        unsigned long long sourceSize =
            [sourceAttributes[NSFileSize] unsignedLongLongValue];
        BOOL needsCopy = ![fm fileExistsAtPath:to];
        if (!needsCopy) {
            NSDictionary *attributes = [fm attributesOfItemAtPath:to error:nil];
            needsCopy = [attributes[NSFileSize] unsignedLongLongValue] != sourceSize;
        }
        if (!needsCopy) continue;
        [fm removeItemAtPath:to error:nil];
        NSError *error = nil;
        if (![fm copyItemAtPath:from toPath:to error:&error]) {
            NSLog(@"[WQ] test file copy failed %@: %@", name,
                error.localizedDescription);
            continue;
        }
        if ([name isEqualToString:@"test"])
            [fm setAttributes:@{ NSFilePosixPermissions: @0755 }
                 ofItemAtPath:to error:nil];
        NSLog(@"[WQ] installed bundled test file %@", name);
    }
}

static void WQInstallVirtualRoot(void)
{
    NSFileManager *fm = NSFileManager.defaultManager;
    NSString *folder = WQVirtualRootFolder();
    [fm createDirectoryAtPath:folder withIntermediateDirectories:YES
                   attributes:@{ NSFilePosixPermissions: @0700 } error:nil];

    // The application container family is enumerated per app so that hidden
    // apps are still identified from their data containers. The other
    // families get a per-container folder only when the root extension is
    // refused by containermanagerd.
    [fm createDirectoryAtPath:WQAppDataFolder() withIntermediateDirectories:YES
                   attributes:@{ NSFilePosixPermissions: @0700 } error:nil];
    [fm createDirectoryAtPath:WQAppDataUUIDFolder() withIntermediateDirectories:YES
                   attributes:@{ NSFilePosixPermissions: @0700 } error:nil];
    NSDictionary<NSString *, NSString *> *perContainerFolders = @{
        @"/private/var/mobile/Containers/Data/Application": @"App Data (apps)",
        @"/private/var/containers/Shared/SystemGroup": @"System Groups (containers)",
        @"/private/var/mobile/Containers/Shared/SystemGroup": @"System Groups (containers)",
        @"/private/var/mobile/Containers/Data/PluginKitPlugin": @"Extension Data (containers)",
        @"/private/var/mobile/Containers/Data/InternalDaemon": @"Internal Daemon Data (containers)",
    };
    for (NSString *root in perContainerFolders) {
        if (!WQPathExists(root)) continue;
        if ([gGrantedRoots containsObject:root]) continue;
        [fm createDirectoryAtPath:
            [folder stringByAppendingPathComponent:perContainerFolders[root]]
            withIntermediateDirectories:YES attributes:nil error:nil];
    }

    NSMutableSet<NSString *> *usedNames = [NSMutableSet set];
    for (NSString *path in gGrantedRoots ?: @[]) {
        NSString *name = gRootDisplayNames[path] ?: path.lastPathComponent;
        NSString *candidate = name;
        NSUInteger suffix = 2;
        while ([usedNames containsObject:candidate])
            candidate = [NSString stringWithFormat:@"%@ %lu", name,
                (unsigned long)suffix++];
        [usedNames addObject:candidate];
        WQCreateLink([folder stringByAppendingPathComponent:candidate], path);
    }

    NSString *readme =
        @"worse_query accessible roots\n"
        @"===========================\n\n"
        @"This folder is generated by FilzaSlop's worse_query integration.\n"
        @"Each symlink points at a path family for which the app holds a\n"
        @"live sandbox extension. The extension is scoped to the Filza\n"
        @"process and is not a jailbreak.\n\n"
        @"Supported: iOS 26.0 - 26.7.2 and iOS 27.0 - 27.2.\n"
        @"Signing: a normal Apple signing identity plus one App Group is\n"
        @"required. No MobileHouseArrest identity is used.\n";
    [readme writeToFile:[folder stringByAppendingPathComponent:@"README.txt"]
             atomically:YES encoding:NSUTF8StringEncoding error:nil];
    WQInstallBundledTestFiles();
}

#pragma mark - App discovery

static BOOL WQLooksLikeBundleIdentifier(NSString *value)
{
    if (value.length < 3 || value.length > 255) return NO;
    if ([value hasPrefix:@"."] || [value hasSuffix:@"."]) return NO;
    if ([value containsString:@".."] || [value containsString:@"/"]) return NO;
    if (![value containsString:@"."]) return NO;
    if ([value isEqualToString:@"com.apple"] || [value isEqualToString:@"com.apple."] ||
        [value isEqualToString:@"group"] || [value isEqualToString:@"systemgroup"])
        return NO;
    NSCharacterSet *allowed = [NSCharacterSet characterSetWithCharactersInString:
        @"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_"];
    return [value rangeOfCharacterFromSet:allowed.invertedSet].location == NSNotFound;
}

static NSString *WQInferIdentifierFromDataDirectory(NSString *containerPath)
{
    NSFileManager *fm = NSFileManager.defaultManager;
    NSArray<NSString *> *subdirectories = @[
        @"Library/Preferences",
        @"Library/Caches",
        @"Library/Saved Application State",
        @"Library/Application Support",
    ];
    NSMutableArray<NSString *> *allCandidates = [NSMutableArray array];
    for (NSString *subdirectory in subdirectories) {
        NSString *directory = [containerPath stringByAppendingPathComponent:subdirectory];
        NSArray<NSString *> *names = [fm contentsOfDirectoryAtPath:directory error:nil];
        for (NSString *name in names ?: @[]) {
            NSString *candidate = name;
            if ([candidate hasSuffix:@".savedState"])
                candidate = [candidate stringByDeletingPathExtension];
            if (candidate.pathExtension.length) candidate = candidate.stringByDeletingPathExtension;
            if (![candidate containsString:@"."]) continue;
            if (!WQLooksLikeBundleIdentifier(candidate)) continue;
            if ([candidate hasPrefix:@"com.apple.NS"] ||
                [candidate hasPrefix:@"com.apple.CF"] ||
                [candidate hasPrefix:@"com.apple.GS"] ||
                [candidate hasPrefix:@"com.apple.DT"] ||
                [candidate hasPrefix:@"com.apple.App"]) continue;
            [allCandidates addObject:candidate];
        }
    }
    // Prefer a third-party identifier over an Apple one when both are present.
    for (NSString *candidate in allCandidates)
        if (![candidate hasPrefix:@"com.apple."] && ![candidate hasPrefix:@"group."])
            return candidate;
    return allCandidates.firstObject;
}

static NSString *WQContainerIdentifier(NSString *containerPath)
{
    if (!containerPath.length) return nil;
    NSString *lsIdentifier = WQLSBundleIDForContainer(containerPath);
    if (lsIdentifier.length) return lsIdentifier;
    NSString *metadataPath = [containerPath
        stringByAppendingPathComponent:@".com.apple.mobile_container_manager.metadata.plist"];
    NSFileManager *fm = NSFileManager.defaultManager;
    NSError *readError = nil;
    NSData *data = [NSData dataWithContentsOfFile:metadataPath
        options:0 error:&readError];
    if (!data) {
        int64_t handle = WQAcquireExtension(metadataPath, NO);
        if (handle >= 0) {
            data = [NSData dataWithContentsOfFile:metadataPath];
            worse_query_release(handle);
        }
    }
    if (data) {
        id plist = [NSPropertyListSerialization propertyListWithData:data
            options:NSPropertyListImmutable format:NULL error:nil];
        if ([plist isKindOfClass:NSDictionary.class]) {
            NSString *identifier = plist[@"MCMMetadataIdentifier"];
            if ([identifier isKindOfClass:NSString.class] &&
                WQLooksLikeBundleIdentifier(identifier)) {
                return identifier;
            }
        }
    }

    static int debugCount;
    BOOL debug = debugCount < 3;
    NSString *inferred = WQInferIdentifierFromDataDirectory(containerPath);
    if (debug) {
        debugCount++;
        NSArray *rootEntries = [fm contentsOfDirectoryAtPath:containerPath error:nil];
        NSArray *prefs = [fm contentsOfDirectoryAtPath:
            [containerPath stringByAppendingPathComponent:@"Library/Preferences"] error:nil];
        NSArray *caches = [fm contentsOfDirectoryAtPath:
            [containerPath stringByAppendingPathComponent:@"Library/Caches"] error:nil];
        int descriptor = open(metadataPath.fileSystemRepresentation, O_RDONLY);
        int openErrno = descriptor < 0 ? errno : 0;
        if (descriptor >= 0) close(descriptor);
        NSLog(@"[WQ][debug] container=%@ metadataExists=%d readErr=%@ openErrno=%d "
              @"root=%@ prefs=%@ caches=%@ inferred=%@", containerPath,
              [fm fileExistsAtPath:metadataPath], readError.localizedDescription ?: @"none",
              openErrno, rootEntries, prefs, caches, inferred ?: @"(nil)");
    }
    return inferred;
}

static NSString *WQSafeLinkName(NSString *name)
{
    NSString *value = [name stringByReplacingOccurrencesOfString:@"/" withString:@"_"];
    value = [value stringByReplacingOccurrencesOfString:@":" withString:@"_"];
    if (value.length == 0 || [value hasPrefix:@"."]) value = [@"app-" stringByAppendingString:value];
    return value;
}

static void WQInstallAppLinks(NSArray<NSDictionary<NSString *, NSString *> *> *apps)
{
    NSString *folder = WQAppDataFolder();
    NSString *uuidFolder = WQAppDataUUIDFolder();
    [NSFileManager.defaultManager createDirectoryAtPath:folder
        withIntermediateDirectories:YES attributes:nil error:nil];
    [NSFileManager.defaultManager createDirectoryAtPath:uuidFolder
        withIntermediateDirectories:YES attributes:nil error:nil];
    NSUInteger linked = 0;
    NSUInteger uuidLinked = 0;
    for (NSDictionary *info in apps) {
        NSString *path = info[@"dataPath"];
        NSString *bundleID = info[@"bundleID"];
        if (!path.length || !bundleID.length) continue;
        NSString *name = info[@"name"];
        NSString *linkName = WQSafeLinkName(name.length
            ? [NSString stringWithFormat:@"%@ [%@]", name, bundleID] : bundleID);
        if (WQCreateLink([folder stringByAppendingPathComponent:linkName], path))
            linked++;
        NSString *uuid = path.lastPathComponent;
        if (uuid.length &&
            WQCreateLink([uuidFolder stringByAppendingPathComponent:uuid], path))
            uuidLinked++;
    }
    NSLog(@"[WQ] app data links byApp=%lu uuid=%lu total=%lu", (unsigned long)linked,
          (unsigned long)uuidLinked, (unsigned long)apps.count);
}

NSString *WQFallbackDisplayName(NSString *bundleID)
{
    static NSDictionary<NSString *, NSString *> *names;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        names = @{
            @"com.apple.mobilesafari": @"Safari",
            @"com.apple.mobilenotes": @"Notes",
            @"com.apple.Maps": @"Maps",
            @"com.apple.mobilemail": @"Mail",
            @"com.apple.MobileSMS": @"Messages",
            @"com.apple.Photos": @"Photos",
            @"com.apple.camera": @"Camera",
            @"com.apple.Preferences": @"Settings",
            @"com.apple.AppStore": @"App Store",
            @"com.apple.Music": @"Music",
            @"com.apple.podcasts": @"Podcasts",
            @"com.apple.reminders": @"Reminders",
            @"com.apple.weather": @"Weather",
            @"com.apple.stocks": @"Stocks",
            @"com.apple.news": @"News",
            @"com.apple.Health": @"Health",
            @"com.apple.Fitness": @"Fitness",
            @"com.apple.Home": @"Home",
            @"com.apple.tv": @"TV",
            @"com.apple.shortcuts": @"Shortcuts",
            @"com.apple.freeform": @"Freeform",
            @"com.apple.DocumentsApp": @"Files",
            @"com.apple.Passbook": @"Wallet",
            @"com.apple.MobileAddressBook": @"Contacts",
            @"com.apple.mobilecal": @"Calendar",
            @"com.apple.VoiceMemos": @"Voice Memos",
            @"com.apple.measure": @"Measure",
            @"com.apple.compass": @"Compass",
            @"com.apple.calculator": @"Calculator",
            @"com.apple.tips": @"Tips",
            @"com.apple.Translate": @"Translate",
            @"com.apple.Bridge": @"Watch",
            @"com.apple.PosterBoard": @"Wallpaper",
            @"com.apple.springboard": @"SpringBoard",
            @"com.apple.iBooks": @"Books",
            @"com.apple.facetime": @"FaceTime",
            @"com.apple.InCallService": @"Phone",
        };
    });
    NSString *known = names[bundleID];
    if (known.length) return known;
    NSString *last = [bundleID componentsSeparatedByString:@"."].lastObject;
    if (last.length > 1)
        return [last stringByReplacingOccurrencesOfString:@"-" withString:@" "].capitalizedString;
    return bundleID;
}

static NSArray<NSDictionary<NSString *, NSString *> *> *
WQAppInfoFromContainers(NSArray<NSString *> *containers)
{
    NSMutableArray *result = [NSMutableArray arrayWithCapacity:containers.count];
    NSMutableDictionary *dataMap = [NSMutableDictionary dictionary];

    for (NSString *container in containers) {
        NSString *containerPath = WQCanonicalPath(container);
        if (!containerPath.length) continue;
        NSString *bundleID = WQContainerIdentifier(containerPath);
        if (!bundleID.length) continue;

        NSMutableDictionary *info = [@{
            @"bundleID": bundleID,
            @"dataPath": containerPath,
            @"name": bundleID,
            @"version": @"1.0",
        } mutableCopy];
        if (!dataMap[bundleID]) dataMap[bundleID] = containerPath;

        NSString *bundlePath = WQLSBundlePathForIdentifier(bundleID);
        if (!bundlePath.length) bundlePath = gBundleMap[bundleID];
        if (bundlePath.length) {
            info[@"bundlePath"] = bundlePath;
            if (!WQGrantExtraPath(bundlePath, NO))
                WQGrantExtraPath(bundlePath.stringByDeletingLastPathComponent, NO);
            NSDictionary *infoPlist = [NSDictionary dictionaryWithContentsOfFile:
                [bundlePath stringByAppendingPathComponent:@"Info.plist"]];
            NSString *name = infoPlist[@"CFBundleDisplayName"];
            if (!name.length) name = infoPlist[@"CFBundleName"];
            if (name.length) info[@"name"] = name;
            NSString *version = infoPlist[@"CFBundleShortVersionString"];
            if (!version.length) version = infoPlist[@"CFBundleVersion"];
            if (version.length) info[@"version"] = version;
        }
        NSString *lsName = WQLSDisplayName(bundleID);
        if (lsName.length) info[@"name"] = lsName;

        Class proxyClass = NSClassFromString(@"LSApplicationProxy");
        id proxy = [proxyClass respondsToSelector:
            NSSelectorFromString(@"applicationProxyForIdentifier:")]
            ? ((id(*)(id, SEL, id))objc_msgSend)(proxyClass,
                NSSelectorFromString(@"applicationProxyForIdentifier:"), bundleID)
            : nil;
        NSString *proxyName = [proxy respondsToSelector:NSSelectorFromString(@"localizedName")]
            ? ((id(*)(id, SEL))objc_msgSend)(proxy,
                NSSelectorFromString(@"localizedName")) : nil;
        if (proxyName.length &&
            (![info[@"name"] isKindOfClass:NSString.class] ||
             [info[@"name"] isEqualToString:bundleID]))
            info[@"name"] = proxyName;
        if (getenv("WQ_APP_NAME_DEBUG")) {
            static int debugNames;
            if (debugNames++ < 40) {
                NSString *infoName = nil;
                NSInteger infoKeys = 0;
                NSString *debugPath = info[@"bundlePath"];
                if (debugPath.length) {
                    NSDictionary *plist = [NSDictionary dictionaryWithContentsOfFile:
                        [debugPath stringByAppendingPathComponent:@"Info.plist"]];
                    infoKeys = plist.count;
                    infoName = plist[@"CFBundleDisplayName"] ?:
                               plist[@"CFBundleName"];
                }
                NSLog(@"[WQ][name-debug] %@ ls=%@ path=%@ plistKeys=%ld plistName=%@",
                      bundleID, WQLSDisplayName(bundleID) ?: @"(nil)",
                      debugPath ?: @"(nil)", (long)infoKeys, infoName ?: @"(nil)");
            }
        }
        NSString *proxyVersion = [proxy respondsToSelector:NSSelectorFromString(@"bundleVersion")]
            ? ((id(*)(id, SEL))objc_msgSend)(proxy,
                NSSelectorFromString(@"bundleVersion")) : nil;
        if (proxyVersion.length && [info[@"version"] isEqualToString:@"1.0"])
            info[@"version"] = proxyVersion;
        NSURL *proxyBundle = [proxy respondsToSelector:NSSelectorFromString(@"bundleURL")]
            ? ((id(*)(id, SEL))objc_msgSend)(proxy,
                NSSelectorFromString(@"bundleURL")) : nil;
        if ([proxyBundle isKindOfClass:NSURL.class] && proxyBundle.path.length &&
            !info[@"bundlePath"]) {
            info[@"bundlePath"] = proxyBundle.path;
        }
        static int proxyDebugCount;
        if (proxyDebugCount < 6) {
            proxyDebugCount++;
            NSLog(@"[WQ][proxy-debug] id=%@ proxy=%@ name=%@ bundle=%@",
                  bundleID, proxy ? @"yes" : @"nil", proxyName ?: @"nil",
                  proxyBundle.path ?: @"nil");
        }
        if ([info[@"name"] isEqualToString:bundleID])
            info[@"name"] = WQFallbackDisplayName(bundleID);
        [result addObject:info];
    }

    gDataMap = dataMap;
    [result sortUsingComparator:^NSComparisonResult(NSDictionary *a, NSDictionary *b) {
        return [a[@"name"] localizedStandardCompare:b[@"name"]];
    }];
    return result;
}

static NSArray<NSString *> *WQVolumePaths(void)
{
    dispatch_once(&gVolumeOnce, ^{
        NSDate *start = [NSDate date];
        NSArray<NSString *> *roots = @[
            @"/private/var/mobile/Containers/Data/Application",
            @"/private/var/mobile/Containers/Shared/AppGroup",
            @"/private/var/mobile/Containers/Data/PluginKitPlugin",
            @"/private/var/mobile/Containers/Data/InternalDaemon",
            @"/private/var/mobile/Containers/Data/System",
            @"/private/var/mobile/Containers/Shared/SystemGroup",
            @"/private/var/containers/Data/System",
            @"/private/var/containers/Shared/SystemGroup",
            @"/private/var/containers/Bundle/Application",
        ];
        gVolumePaths = pathleak_roots(roots, 1, 5000000);
        NSTimeInterval elapsed = -[start timeIntervalSinceNow];
        NSLog(@"[WQ] volume inode scan paths=%lu elapsed=%.1fs",
              (unsigned long)gVolumePaths.count, elapsed);
    });
    return gVolumePaths ?: @[];
}

static NSArray<NSString *> *WQVolumeChildren(NSString *root)
{
    NSString *prefix = [root stringByAppendingString:@"/"];
    NSMutableArray<NSString *> *children = [NSMutableArray array];
    for (NSString *path in WQVolumePaths()) {
        if (![path hasPrefix:prefix]) continue;
        NSString *remainder = [path substringFromIndex:prefix.length];
        if ([remainder containsString:@"/"]) continue;
        [children addObject:path];
    }
    return children;
}

static NSArray<NSString *> *WQEnumerateContainers(NSString *root)
{
    NSFileManager *fm = NSFileManager.defaultManager;
    NSError *error = nil;
    NSArray<NSString *> *names = [fm contentsOfDirectoryAtPath:root error:&error];
    NSLog(@"[WQ] container root %@ direct entries=%lu error=%@",
          root, (unsigned long)names.count, error.localizedDescription ?: @"none");
    if (names.count > 0) {
        NSMutableArray *paths = [NSMutableArray arrayWithCapacity:names.count];
        for (NSString *name in names) {
            if ([name hasPrefix:@"."]) continue;
            [paths addObject:[root stringByAppendingPathComponent:name]];
        }
        if (paths.count > 0) return paths;
    }

    // iOS 26/27 can hide container entries from directory enumeration even
    // when the path itself is visible. The shared volume scan below converts
    // inode numbers to paths once and feeds every container family.
    NSArray<NSString *> *volumeChildren = WQVolumeChildren(root);
    if (volumeChildren.count > 0) {
        NSLog(@"[WQ] volume children %@ count=%lu", root,
              (unsigned long)volumeChildren.count);
        return volumeChildren;
    }

    if (!gPathleakCache) gPathleakCache = [NSMutableDictionary dictionary];
    NSArray<NSString *> *cached = gPathleakCache[root];
    if (cached) {
        NSLog(@"[WQ] pathleak cache %@ children=%lu", root,
              (unsigned long)cached.count);
        return cached;
    }

    uint64_t maximumInode = 5000000;
    NSString *probePath = [NSTemporaryDirectory() stringByAppendingPathComponent:
        [NSString stringWithFormat:@".wq-inode-%@", NSUUID.UUID.UUIDString]];
    NSData *probeData = [NSData data];
    if ([probeData writeToFile:probePath atomically:NO]) {
        struct stat status = {0};
        if (stat(probePath.fileSystemRepresentation, &status) == 0 && status.st_ino > 0) {
            maximumInode = (uint64_t)status.st_ino + (uint64_t)status.st_ino / 10 + 4096;
        }
        [[NSFileManager defaultManager] removeItemAtPath:probePath error:nil];
    }
    struct stat homeStatus = {0};
    if (stat(NSHomeDirectory().fileSystemRepresentation, &homeStatus) == 0 &&
        homeStatus.st_ino > maximumInode)
        maximumInode = (uint64_t)homeStatus.st_ino + (uint64_t)homeStatus.st_ino / 10 + 4096;
    if (maximumInode > 5000000) maximumInode = 5000000;
    NSLog(@"[WQ] pathleak %@ maxInode=%llu", root, (unsigned long long)maximumInode);
    NSArray *leaked = pathleak(root, maximumInode);
    NSLog(@"[WQ] pathleak %@ returned=%lu", root, (unsigned long)leaked.count);
    NSMutableArray *paths = [NSMutableArray arrayWithCapacity:leaked.count];
    for (NSString *path in leaked ?: @[]) {
        if (![path isKindOfClass:NSString.class]) continue;
        [paths addObject:path];
    }
    gPathleakCache[root] = paths.copy;
    return paths;
}

static void WQDiscoverPerContainerFamilies(void)
{
    NSArray<NSDictionary<NSString *, NSString *> *> *families = @[
        @{ @"path": @"/private/var/containers/Shared/SystemGroup",
           @"folder": @"System Groups (containers)" },
        @{ @"path": @"/private/var/mobile/Containers/Shared/SystemGroup",
           @"folder": @"System Groups (containers)" },
        @{ @"path": @"/private/var/mobile/Containers/Data/PluginKitPlugin",
           @"folder": @"Extension Data (containers)" },
        @{ @"path": @"/private/var/mobile/Containers/Data/InternalDaemon",
           @"folder": @"Internal Daemon Data (containers)" },
    ];
    NSString *hub = WQVirtualRootFolder();
    NSUInteger familyIndex = 0;
    for (NSDictionary *family in families) {
        NSString *root = WQCanonicalPath(family[@"path"]);
        NSString *folderName = family[@"folder"];
        if (!WQPathExists(root)) continue;
        if ([gGrantedRoots containsObject:root]) continue;
        familyIndex++;
        WQPostStartupProgress(0.58 + 0.07 * familyIndex,
            [NSString stringWithFormat:@"正在加载 %@…", folderName]);

        NSArray<NSString *> *children = WQEnumerateContainers(root);
        if (children.count == 0) continue;
        NSString *folder = [hub stringByAppendingPathComponent:folderName];
        [NSFileManager.defaultManager createDirectoryAtPath:folder
            withIntermediateDirectories:YES attributes:nil error:nil];

        NSUInteger granted = 0;
        for (NSString *child in children) {
            if (!WQGrantContainer(child)) continue;
            granted++;
            NSString *identifier = WQContainerIdentifier(child);
            NSString *linkName = WQSafeLinkName(identifier ?: child.lastPathComponent);
            WQCreateLink([folder stringByAppendingPathComponent:linkName], child);
        }
        NSLog(@"[WQ] per-container family %@ children=%lu granted=%lu folder=%@",
              root, (unsigned long)children.count, (unsigned long)granted, folder);
    }
}

static NSDictionary<NSString *, NSDictionary *> *WQMobileInstallationApps(void)
{
    static NSDictionary *apps;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        void *handle = dlopen(
            "/System/Library/PrivateFrameworks/MobileInstallation.framework/MobileInstallation",
            RTLD_LAZY);
        if (!handle) {
            NSLog(@"[WQ] MobileInstallation framework unavailable: %s", dlerror());
            return;
        }
        NSDictionary *(*lookup)(NSDictionary *, NSError **) =
            (NSDictionary *(*)(NSDictionary *, NSError **))dlsym(handle,
                "MobileInstallationLookup");
        if (lookup) {
            NSError *error = nil;
            id value = lookup(nil, &error);
            if ([value isKindOfClass:NSDictionary.class]) apps = [value copy];
            NSLog(@"[WQ] MobileInstallationLookup apps=%lu error=%@",
                (unsigned long)apps.count,
                error.localizedDescription ?: @"none");
        } else {
            NSLog(@"[WQ] MobileInstallationLookup symbol missing");
        }
        dlclose(handle);
    });
    return apps ?: @{};
}

static void WQAppendMobileInstallationApps(NSMutableArray *result,
                                           NSMutableSet<NSString *> *known)
{
    NSDictionary<NSString *, NSDictionary *> *apps = WQMobileInstallationApps();
    for (NSString *key in apps) {
        NSDictionary *entry = apps[key];
        if (![entry isKindOfClass:NSDictionary.class]) continue;
        NSString *bundleID = entry[@"CFBundleIdentifier"];
        if (![bundleID isKindOfClass:NSString.class] || !bundleID.length)
            bundleID = key;
        if (!bundleID.length || [known containsObject:bundleID]) continue;

        id containerValue = entry[@"Container"];
        NSString *dataPath = [containerValue isKindOfClass:NSURL.class]
            ? [(NSURL *)containerValue path] : containerValue;
        if (![dataPath isKindOfClass:NSString.class] || !dataPath.length) {
            NSString *error = nil;
            dataPath = MCMFilzaDataContainerPath(bundleID, &error);
        }
        id bundleValue = entry[@"Path"];
        NSString *bundlePath = [bundleValue isKindOfClass:NSURL.class]
            ? [(NSURL *)bundleValue path] : bundleValue;
        if (![bundlePath isKindOfClass:NSString.class] || !bundlePath.length) {
            bundleValue = entry[@"BundlePath"];
            bundlePath = [bundleValue isKindOfClass:NSURL.class]
                ? [(NSURL *)bundleValue path] : bundleValue;
        }
        if (![bundlePath isKindOfClass:NSString.class] || !bundlePath.length)
            bundlePath = WQBundlePathForIdentifier(bundleID);

        NSMutableDictionary *info = [@{
            @"bundleID": bundleID,
            @"name": bundleID,
            @"version": @"1.0",
        } mutableCopy];
        if (dataPath.length) info[@"dataPath"] = dataPath;
        if (bundlePath.length) {
            info[@"bundlePath"] = bundlePath;
            NSDictionary *plist = [NSDictionary dictionaryWithContentsOfFile:
                [bundlePath stringByAppendingPathComponent:@"Info.plist"]];
            NSString *name = plist[@"CFBundleDisplayName"];
            if (!name.length) name = plist[@"CFBundleName"];
            if (name.length) info[@"name"] = name;
            NSString *version = plist[@"CFBundleShortVersionString"];
            if (!version.length) version = plist[@"CFBundleVersion"];
            if (version.length) info[@"version"] = version;
        }
        NSString *name = entry[@"CFBundleDisplayName"];
        if (!name.length) name = entry[@"CFBundleName"];
        if ([name isKindOfClass:NSString.class] && name.length)
            info[@"name"] = name;
        NSString *version = entry[@"CFBundleShortVersionString"];
        if (!version.length) version = entry[@"CFBundleVersion"];
        if ([version isKindOfClass:NSString.class] && version.length)
            info[@"version"] = version;
        if ([info[@"name"] isEqualToString:bundleID])
            info[@"name"] = WQFallbackDisplayName(bundleID);
        [result addObject:info];
        [known addObject:bundleID];
    }
    if (apps.count)
        NSLog(@"[WQ] MobileInstallation merged=%lu total=%lu",
            (unsigned long)apps.count, (unsigned long)result.count);
}

static NSArray<NSDictionary<NSString *, NSString *> *> *WQBuildAppList(void)
{
    NSString *root = @"/private/var/mobile/Containers/Data/Application";
    // The data-container root itself is often rejected by containermanagerd
    // even though each child container is accepted. Always enumerate children
    // and request their extensions individually.
    WQGrantRoot(root, @"App Data");
    WQPostStartupProgress(0.20, @"正在读取 LaunchServices 应用数据库…");
    WQLoadLaunchServicesDatabase();

    NSMutableArray<NSString *> *lsContainers = [NSMutableArray array];
    NSString *lsPrefix = [root stringByAppendingString:@"/"];
    for (NSString *path in WQLSContainerPaths() ?: @[]) {
        NSString *canonical = WQCanonicalPath(path);
        if (![canonical hasPrefix:lsPrefix]) continue;
        if (canonical.length != lsPrefix.length + 36) continue;
        if (![[NSUUID alloc] initWithUUIDString:
                [canonical substringFromIndex:lsPrefix.length]]) continue;
        [lsContainers addObject:canonical];
    }

    NSArray<NSString *> *containers = nil;
    if (lsContainers.count >= 2) {
        containers = lsContainers;
        WQPostStartupProgress(0.30, [NSString stringWithFormat:
            @"应用数据库已列出 %lu 个数据容器，正在授权…",
            (unsigned long)containers.count]);
    } else {
        WQPostStartupProgress(0.26, @"正在扫描应用数据容器…");
        containers = WQEnumerateContainers(root);
    }
    WQPostStartupProgress(0.40, [NSString stringWithFormat:
        @"发现 %lu 个数据容器，正在逐个授权…", (unsigned long)containers.count]);
    NSUInteger granted = 0;
    for (NSString *container in containers) {
        if (WQGrantContainer(container)) granted++;
    }
    WQPostStartupProgress(0.48, @"正在从数据目录识别应用…");
    NSArray *containerApps = WQAppInfoFromContainers(containers);
    NSMutableArray *apps = [containerApps mutableCopy];
    NSMutableSet<NSString *> *known = [NSMutableSet set];
    for (NSDictionary *info in containerApps)
        if (info[@"bundleID"]) [known addObject:info[@"bundleID"]];
    WQAppendMobileInstallationApps(apps, known);
    WQInstallAppLinks(apps);
    NSLog(@"[WQ] app discovery containers=%lu granted=%lu apps=%lu",
          (unsigned long)containers.count, (unsigned long)granted,
          (unsigned long)apps.count);
    return apps;
}

NSArray<NSDictionary<NSString *, NSString *> *> *WQInstalledApplications(void)
{
    if (!gAppsQueue) gAppsQueue = dispatch_queue_create(
        "com.filzaslop.worsequery.apps", DISPATCH_QUEUE_SERIAL);
    __block NSArray *value = nil;
    dispatch_sync(gAppsQueue, ^{
        NSTimeInterval age = gAppsCacheDate
            ? -[gAppsCacheDate timeIntervalSinceNow] : 1e9;
        // Never cache an empty result: the first call can happen before the
        // worse_query grants and app-container scan have finished.
        if (!gAppsCache || gAppsCache.count == 0 || age > 120) {
            gAppsCache = WQBuildAppList();
            gAppsCacheDate = [NSDate date];
        }
        value = gAppsCache;
    });
    return value ?: @[];
}

NSString *WQDataPathForIdentifier(NSString *bundleID)
{
    if (!bundleID.length) return nil;
    WQInstalledApplications();
    return gDataMap[bundleID];
}

#pragma mark - Bundle map

static void WQBuildBundleMapIfNeeded(void)
{
    if (!gBundleMapLock) gBundleMapLock = [NSObject new];
    @synchronized (gBundleMapLock) {
    if (gBundleMapAttempted) return;
    gBundleMapAttempted = YES;
    gBundleMap = [NSMutableDictionary dictionary];
    gBundleInfo = [NSMutableDictionary dictionary];

    NSString *root = @"/private/var/containers/Bundle/Application";
    NSString *prefix = [root stringByAppendingString:@"/"];
    NSArray<NSString *> *volumePaths = WQVolumePaths();
    BOOL bundleInVolume = NO;
    for (NSString *path in volumePaths) {
        if ([path hasPrefix:prefix]) { bundleInVolume = YES; break; }
    }
    if (!bundleInVolume && WQPathExists(root)) {
        // The bundle container root can live on a different APFS volume from
        // the data containers, so the shared scan above may not include it.
        NSLog(@"[WQ] bundle root not in shared volume scan; scanning separately");
        volumePaths = pathleak_roots(@[root], 1, 5000000);
        NSLog(@"[WQ] bundle-only scan paths=%lu", (unsigned long)volumePaths.count);
    }
    NSUInteger appBundles = 0;
    NSUInteger candidates = 0;
    NSUInteger debugCount = 0;
    NSUInteger prefixed = 0;
    NSUInteger appSuffix = 0;
    NSMutableArray *prefixedSamples = [NSMutableArray array];

    for (NSString *path in volumePaths) {
        if (![path hasPrefix:prefix]) continue;
        prefixed++;
        if ([path hasSuffix:@".app"]) appSuffix++;
        if (prefixedSamples.count < 5 && [path hasSuffix:@".app"])
            [prefixedSamples addObject:path];
        NSString *remainder = [path substringFromIndex:prefix.length];
        NSArray<NSString *> *components = [remainder componentsSeparatedByString:@"/"];
        if (components.count != 2) continue;
        if (![path hasSuffix:@".app"]) continue;
        candidates++;

        // Grant the bundle itself. Bundle containers are not in the published
        // worse_query surface, but the same per-container query works on this
        // iOS build and lets us read Info.plist for names and icons.
        BOOL granted = WQGrantContainer(path);
        BOOL parentGranted = NO;
        if (!granted) {
            NSString *uuidPath = [root stringByAppendingPathComponent:components[0]];
            parentGranted = WQGrantContainer(uuidPath);
        }
        NSError *readError = nil;
        NSDictionary *plist = [NSDictionary dictionaryWithContentsOfFile:
            [path stringByAppendingPathComponent:@"Info.plist"]];
        if (debugCount < 3) {
            debugCount++;
            NSLog(@"[WQ][bundle-debug] path=%@ grant=%d parentGrant=%d plist=%lu",
                  path, granted, parentGranted, (unsigned long)plist.count);
        }
        NSString *bundleID = plist[@"CFBundleIdentifier"];
        if (![bundleID isKindOfClass:NSString.class] || !bundleID.length) {
            // The directory name is still useful for later LaunchServices
            // lookups even when Info.plist is protected.
            NSString *appName = [components[1] stringByDeletingPathExtension];
            if (appName.length) gBundleMap[appName] = path;
            continue;
        }
        gBundleMap[bundleID] = path;
        NSString *name = plist[@"CFBundleDisplayName"];
        if (!name.length) name = plist[@"CFBundleName"];
        NSString *version = plist[@"CFBundleShortVersionString"];
        if (!version.length) version = plist[@"CFBundleVersion"];
        gBundleInfo[bundleID] = @{
            @"path": path,
            @"name": name.length ? name : bundleID,
            @"version": version.length ? version : @"1.0",
        };
        appBundles++;
    }
    NSLog(@"[WQ] bundle map prefixed=%lu appSuffix=%lu candidates=%lu apps=%lu samples=%@",
          (unsigned long)prefixed, (unsigned long)appSuffix,
          (unsigned long)candidates, (unsigned long)appBundles, prefixedSamples);

    // Expose the bundle family in the hub only if at least one app bundle was
    // granted, so the user can open an app's .app directory too.
    if (appBundles > 0) {
        NSString *folder = [WQVirtualRootFolder()
            stringByAppendingPathComponent:@"App Bundles"];
        [NSFileManager.defaultManager createDirectoryAtPath:folder
            withIntermediateDirectories:YES attributes:nil error:nil];
        NSUInteger linked = 0;
        for (NSString *bundleID in gBundleMap) {
            NSDictionary *info = gBundleInfo[bundleID];
            NSString *path = info[@"path"] ?: gBundleMap[bundleID];
            if (!path.length) continue;
            NSString *linkName = WQSafeLinkName(info[@"name"]
                ? [NSString stringWithFormat:@"%@ [%@]", info[@"name"], bundleID]
                : bundleID);
            if (WQCreateLink([folder stringByAppendingPathComponent:linkName], path))
                linked++;
        }
        NSLog(@"[WQ] app bundle links=%lu folder=%@", (unsigned long)linked, folder);
    }
    }
}

NSString *WQBundlePathForIdentifier(NSString *bundleID)
{
    if (!bundleID.length) return nil;
    NSString *lsPath = WQLSBundlePathForIdentifier(bundleID);
    if (lsPath.length) return lsPath;
    if (getenv("WQ_BUNDLE_SCAN")) WQBuildBundleMapIfNeeded();
    NSString *mapped = gBundleMap[bundleID];
    if (mapped.length) return mapped;
    NSDictionary *info = gBundleInfo[bundleID];
    if ([info[@"path"] isKindOfClass:NSString.class]) return info[@"path"];

    NSDictionary *installation = WQMobileInstallationApps()[bundleID];
    if ([installation isKindOfClass:NSDictionary.class]) {
        NSString *path = installation[@"Path"];
        if (![path isKindOfClass:NSString.class] || !path.length)
            path = installation[@"BundlePath"];
        if ([path isKindOfClass:NSString.class] && path.length) return path;
    }

    Class proxyClass = NSClassFromString(@"LSApplicationProxy");
    id proxy = [proxyClass respondsToSelector:
        NSSelectorFromString(@"applicationProxyForIdentifier:")]
        ? ((id(*)(id, SEL, id))objc_msgSend)(proxyClass,
            NSSelectorFromString(@"applicationProxyForIdentifier:"), bundleID)
        : nil;
    NSURL *bundleURL = [proxy respondsToSelector:@selector(bundleURL)]
        ? ((id(*)(id, SEL))objc_msgSend)(proxy, @selector(bundleURL)) : nil;
    if ([bundleURL isKindOfClass:NSURL.class] && bundleURL.path.length)
        return bundleURL.path;
    return nil;
}

#pragma mark - Name diagnostics

static void WQDiagnoseAppNames(void)
{
    static BOOL ran;
    if (ran) return;
    ran = YES;

    Class proxyClass = NSClassFromString(@"LSApplicationProxy");
    unsigned int count = 0;
    Method *methods = class_copyMethodList(proxyClass, &count);
    NSMutableArray<NSString *> *interesting = [NSMutableArray array];
    NSMutableArray<NSString *> *workspaceInteresting = [NSMutableArray array];
    for (unsigned int index = 0; index < count; index++) {
        NSString *name = NSStringFromSelector(method_getName(methods[index]));
        NSString *lower = name.lowercaseString;
        if ([lower containsString:@"name"] || [lower containsString:@"display"] ||
            [lower containsString:@"title"] || [lower containsString:@"bundleurl"] ||
            [lower containsString:@"container"]) {
            if (method_getNumberOfArguments(methods[index]) == 2)
                [interesting addObject:name];
        }
    }
    free(methods);
    NSLog(@"[WQ][names] LSApplicationProxy zero-arg methods=%@", interesting);

    id proxy = [proxyClass respondsToSelector:
        NSSelectorFromString(@"applicationProxyForIdentifier:")]
        ? ((id(*)(id, SEL, id))objc_msgSend)(proxyClass,
            NSSelectorFromString(@"applicationProxyForIdentifier:"), @"com.rosiepie.flora")
        : nil;
    for (NSString *selectorName in interesting) {
        SEL selector = NSSelectorFromString(selectorName);
        if (![proxy respondsToSelector:selector]) continue;
        @try {
            id value = ((id(*)(id, SEL))objc_msgSend)(proxy, selector);
            NSLog(@"[WQ][names] proxy %@ => %@ (%@)", selectorName,
                  [value isKindOfClass:NSString.class] ||
                  [value isKindOfClass:NSURL.class] ||
                  [value isKindOfClass:NSNumber.class] ? value : NSStringFromClass([value class]),
                  NSStringFromClass([value class]));
        } @catch (NSException *exception) {
            NSLog(@"[WQ][names] proxy %@ threw %@", selectorName, exception.reason);
        }
    }

    Class workspaceClass = NSClassFromString(@"LSApplicationWorkspace");
    methods = class_copyMethodList(workspaceClass, &count);
    for (unsigned int index = 0; index < count; index++) {
        NSString *name = NSStringFromSelector(method_getName(methods[index]));
        NSString *lower = name.lowercaseString;
        if (([lower containsString:@"application"] || [lower containsString:@"installed"]) &&
            method_getNumberOfArguments(methods[index]) == 2)
            [workspaceInteresting addObject:name];
    }
    free(methods);
    NSLog(@"[WQ][names] LSApplicationWorkspace zero-arg methods=%@", workspaceInteresting);

    void *handle = dlopen("/System/Library/PrivateFrameworks/MobileInstallation.framework/MobileInstallation", RTLD_LAZY);
    if (handle) {
        typedef int (*LookupFn)(CFDictionaryRef, CFDictionaryRef *);
        LookupFn lookup = (LookupFn)dlsym(handle, "MobileInstallationLookup");
        if (lookup) {
            CFDictionaryRef info = NULL;
            int result = lookup(NULL, &info);
            NSDictionary *dictionary = info ? (__bridge NSDictionary *)info : nil;
            NSLog(@"[WQ][names] MobileInstallationLookup result=%d apps=%lu sample=%@",
                  result, (unsigned long)dictionary.count,
                  dictionary.count ? [dictionary.allKeys.firstObject description] : @"none");
            if (info) CFRelease(info);
        } else {
            NSLog(@"[WQ][names] MobileInstallationLookup symbol missing");
        }
        dlclose(handle);
    } else {
        NSLog(@"[WQ][names] MobileInstallation dlopen failed");
    }

    NSString *systemRoot = @"/private/var/containers/Data/System";
    NSArray *systemEntries = [NSFileManager.defaultManager
        contentsOfDirectoryAtPath:systemRoot error:nil];
    NSLog(@"[WQ][names] SystemData entries=%@", systemEntries);
    NSFileManager *fm = NSFileManager.defaultManager;
    for (NSString *uuid in systemEntries ?: @[]) {
        NSString *container = [systemRoot stringByAppendingPathComponent:uuid];
        NSString *caches = [container stringByAppendingPathComponent:@"Library/Caches"];
        NSArray *cacheEntries = [fm contentsOfDirectoryAtPath:caches error:nil];
        if (cacheEntries.count == 0) continue;
        NSLog(@"[WQ][names] system container=%@ caches=%@", uuid, cacheEntries);
        for (NSString *name in cacheEntries) {
            if (![name hasSuffix:@".csstore"] && ![name hasSuffix:@".db"] &&
                ![name hasSuffix:@".plist"] && ![name hasSuffix:@".sqlite"]) continue;
            NSString *source = [caches stringByAppendingPathComponent:name];
            NSDictionary *attributes = [fm attributesOfItemAtPath:source error:nil];
            if ([attributes[NSFileSize] unsignedLongLongValue] > 64 * 1024 * 1024)
                continue;
            NSString *destination = [MCMFilzaVirtualRoot()
                stringByAppendingPathComponent:
                    [@"store-" stringByAppendingString:name]];
            BOOL copied = [fm copyItemAtPath:source toPath:destination error:nil];
            NSLog(@"[WQ][names] store file %@ size=%llu copied=%d -> %@", name,
                  [attributes[NSFileSize] unsignedLongLongValue], copied, destination);
        }
    }
}

#pragma mark - Startup progress

static void WQPostStartupProgress(double progress, NSString *status)
{
    if (!gStartupActive) return;
    NSDictionary *info = @{ @"progress": @(progress), @"status": status ?: @"" };
    dispatch_async(dispatch_get_main_queue(), ^{
        [[NSNotificationCenter defaultCenter]
            postNotificationName:@"WQStartupProgress" object:nil userInfo:info];
    });
}

static void WQPostStartupFinished(void)
{
    gStartupActive = NO;
    dispatch_async(dispatch_get_main_queue(), ^{
        [[NSNotificationCenter defaultCenter]
            postNotificationName:@"WQStartupFinished" object:nil];
    });
}

#pragma mark - Public entry

void WQFilzaStart(void)
{
    if (gStarted) return;
    gStarted = YES;
    gStartupActive = YES;
    gQueryLock = [NSLock new];
    gAppsLock = [NSLock new];
    gStartupGroup = dispatch_group_create();

    WQPostStartupProgress(0.02, @"正在准备 worse_query…");

    NSString *group = WQBestAppGroup();
    if (!group.length) {
        NSLog(@"[WQ] disabled: no provisioned App Group. Normal signing needs "
              @"a profile with com.apple.security.application-groups.");
        WQPostStartupProgress(0.05, @"未找到 App Group，请检查签名配置");
        WQPostStartupFinished();
        return;
    }

    NSLog(@"[WQ] starting with group=%@ os=%@", group,
          NSProcessInfo.processInfo.operatingSystemVersionString);
    WQPostStartupProgress(0.06, @"已找到 App Group，正在申请沙盒扩展…");

    NSUInteger granted = 0;
    for (NSDictionary *root in WQCandidateRoots()) {
        if (WQGrantRoot(root[@"path"], root[@"name"])) granted++;
    }
    NSLog(@"[WQ] roots granted=%lu/%lu active=%d", (unsigned long)granted,
          (unsigned long)WQCandidateRoots().count, WQIsActive());
    WQPostStartupProgress(0.18, [NSString stringWithFormat:
        @"根目录扩展 %lu/%lu，正在加载应用数据…",
        (unsigned long)granted, (unsigned long)WQCandidateRoots().count]);

    WQInstallVirtualRoot();
    WQScheduleFavorites();

    // Build the app-container index before the user opens Apps manager.
    if (!gAppsQueue) gAppsQueue = dispatch_queue_create(
        "com.filzaslop.worsequery.apps", DISPATCH_QUEUE_SERIAL);
    if (!gFamiliesQueue) gFamiliesQueue = dispatch_queue_create(
        "com.filzaslop.worsequery.families", DISPATCH_QUEUE_SERIAL);

    // App containers are the priority: the Apps manager must populate before
    // the slower system-group sweep begins.
    dispatch_group_enter(gStartupGroup);
    dispatch_async(gAppsQueue, ^{
        WQPostStartupProgress(0.24, @"正在枚举应用数据容器…");
        if (!gAppsCache) gAppsCache = WQBuildAppList();
        gAppsCacheDate = [NSDate date];
        if (getenv("WQ_BUNDLE_SCAN")) WQBuildBundleMapIfNeeded();
        NSLog(@"[WQ] app prewarm complete apps=%lu",
              (unsigned long)(gAppsCache ?: @[]).count);
        WQDiagnoseAppNames();
        WQPostStartupProgress(0.55, [NSString stringWithFormat:
            @"已识别 %lu 个应用，正在加载系统目录…",
            (unsigned long)(gAppsCache ?: @[]).count]);
        dispatch_async(dispatch_get_main_queue(), ^{ WQInstallFavorites(); });
        dispatch_group_leave(gStartupGroup);
    });

    dispatch_group_enter(gStartupGroup);
    dispatch_async(gFamiliesQueue, ^{
        WQPostStartupProgress(0.58, @"正在枚举系统组与扩展目录…");
        WQDiscoverPerContainerFamilies();
        NSLog(@"[WQ] family prewarm complete grants=%lu roots=%lu",
              (unsigned long)gGrantHandles.count,
              (unsigned long)WQAccessibleRoots().count);
        WQPostStartupProgress(0.90, @"正在生成收藏夹与访问链接…");
        dispatch_async(dispatch_get_main_queue(), ^{ WQInstallFavorites(); });
        dispatch_group_leave(gStartupGroup);
    });

    dispatch_group_notify(gStartupGroup, dispatch_get_main_queue(), ^{
        WQInstallFavorites();
        WQPostStartupProgress(1.0, @"准备完成");
        NSLog(@"[WQ] startup complete apps=%lu grants=%lu roots=%lu",
              (unsigned long)WQInstalledApplications().count,
              (unsigned long)gGrantHandles.count,
              (unsigned long)WQAccessibleRoots().count);
        WQPostStartupFinished();
    });

    if (!WQIsActive()) {
        NSLog(@"[WQ] no supported root could be granted; check the App Group "
              @"entitlement and the iOS version.");
    }
}

#pragma mark - Proxy stand-in

@implementation WQApplicationProxy

- (instancetype)initWithAppInfo:(NSDictionary *)info
{
    self = [super init];
    if (!self) return nil;
    NSString *bundleID = info[@"bundleID"];
    _applicationIdentifier = bundleID ?: @"";
    _bundleIdentifier = bundleID ?: @"";
    _localizedName = info[@"name"] ?: bundleID ?: @"";
    _bundleVersion = info[@"version"] ?: @"1.0";
    _shortVersionString = _bundleVersion;
    _applicationType = @"User";
    _vendorName = bundleID ?: @"";
    NSString *bundlePath = info[@"bundlePath"];
    if (bundlePath.length) _bundleURL = [NSURL fileURLWithPath:bundlePath];
    NSString *dataPath = info[@"dataPath"];
    if (dataPath.length) _dataContainerURL = [NSURL fileURLWithPath:dataPath];
    return self;
}

- (NSDictionary *)iconsDictionary { return @{}; }
- (id)iconDataForVariant:(id)variant { return nil; }
- (NSNumber *)staticDiskUsage { return @0; }
- (NSNumber *)dynamicDiskUsage { return @0; }
- (BOOL)isDeletable { return YES; }
- (BOOL)isPlaceholder { return NO; }
- (BOOL)isSystem { return NO; }

@end
