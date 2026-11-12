#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/// Reads lsd's LaunchServices CSStore database (bundle names, display names,
/// data-container mapping and .app bundle paths). The first call is blocking;
/// run it on a background queue.
BOOL WQLoadLaunchServicesDatabase(void);
BOOL WQLSDisplayNamesLoaded(void);
void WQLSResetMiss(void);

/// Real display name for a bundle id (database, built-in Apple table, or
/// parent-app fallback).
NSString *_Nullable WQLSDisplayName(NSString *bundleID);

/// Bundle id for an app/extension data container.
NSString *_Nullable WQLSBundleIDForContainer(NSString *path);

/// .app bundle path from the database (used for icons where readable).
NSString *_Nullable WQLSBundlePathForIdentifier(NSString *bundleID);

/// App and extension data-container paths listed by the database. Reading the
/// store is much faster than enumerating every inode. Nil when unavailable.
NSArray<NSString *> *_Nullable WQLSContainerPaths(void);

NS_ASSUME_NONNULL_END
