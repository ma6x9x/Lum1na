#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/// Extracts zip, tar, tar.gz, gz, bz2, xz, 7z, rar and other formats
/// supported by libarchive into `destination`.
FOUNDATION_EXPORT BOOL WQExtractArchive(NSString *archivePath,
                                         NSString *destination,
                                         NSString *_Nullable *_Nullable message);

/// Destination used when the caller does not specify one
/// (archive name with the archive suffix removed).
FOUNDATION_EXPORT NSString *WQDefaultExtractDestination(NSString *archivePath);

NS_ASSUME_NONNULL_END
