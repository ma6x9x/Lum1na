#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/// Boots the worse_query integration. Grants every path family the primitive
/// supports, publishes a symlinked control folder inside Filza's virtual root,
/// registers Favorites entries, and prewarms app-container discovery.
FOUNDATION_EXPORT void WQFilzaStart(void);

/// YES once at least one worse_query sandbox extension was consumed.
FOUNDATION_EXPORT BOOL WQIsActive(void);

/// Canonical /private/var paths that currently have a live extension.
FOUNDATION_EXPORT NSArray<NSString *> *WQAccessibleRoots(void);

/// "…/Documents/Device Storage/worse_query", the browsing hub for the granted
/// roots. Kept stable so Favorites entries can point at it.
FOUNDATION_EXPORT NSString *WQVirtualRootFolder(void);

/// App records built from accessible data containers and their
/// .com.apple.mobile_container_manager.metadata.plist files.
/// Keys: bundleID, dataPath, name, version, bundlePath (optional),
/// iconPath (optional).
FOUNDATION_EXPORT NSArray<NSDictionary *> *WQInstalledApplications(void);

FOUNDATION_EXPORT NSString *_Nullable WQBundlePathForIdentifier(NSString *bundleID);
FOUNDATION_EXPORT NSString *_Nullable WQDataPathForIdentifier(NSString *bundleID);
FOUNDATION_EXPORT NSString *_Nullable WQBestAppGroup(void);

/// Minimal stand-in for LSApplicationProxy used when LaunchServices hides an
/// app but its data container is still discoverable.
@interface WQApplicationProxy : NSObject
@property (nonatomic, copy) NSString *applicationIdentifier;
@property (nonatomic, copy) NSString *bundleIdentifier;
@property (nonatomic, copy) NSString *localizedName;
@property (nonatomic, copy) NSString *bundleVersion;
@property (nonatomic, copy) NSString *shortVersionString;
@property (nonatomic, copy) NSString *applicationType;
@property (nonatomic, copy) NSString *vendorName;
@property (nonatomic, strong, nullable) NSURL *bundleURL;
@property (nonatomic, strong, nullable) NSURL *dataContainerURL;
- (instancetype)initWithAppInfo:(NSDictionary *)info;
@end

NS_ASSUME_NONNULL_END

/// Extra commands used by the sbx_* terminal helpers.
FOUNDATION_EXPORT BOOL WQGrantExtraPath(NSString * _Nonnull path, BOOL createIfMissing);
FOUNDATION_EXPORT void WQReleaseGrantHandle(NSNumber * _Nonnull handle);
FOUNDATION_EXPORT void WQReleaseAllGrants(void);
FOUNDATION_EXPORT void WQRefreshDiscovery(void);
FOUNDATION_EXPORT NSArray<NSString *> * _Nonnull WQChildrenForRoot(NSString * _Nonnull root);
FOUNDATION_EXPORT NSString *_Nullable WQIdentifyContainerPath(NSString * _Nonnull path);
FOUNDATION_EXPORT NSArray<NSNumber *> * _Nonnull WQActiveGrantHandles(void);
FOUNDATION_EXPORT NSString * _Nonnull WQFallbackDisplayName(NSString * _Nonnull bundleID);
