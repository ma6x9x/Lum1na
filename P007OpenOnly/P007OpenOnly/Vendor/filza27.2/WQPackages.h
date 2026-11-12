#import <Foundation/Foundation.h>

/// In-process dpkg/apt. Packages are installed under Documents/.terminal/root
/// because a normally signed app cannot write to /usr.
FOUNDATION_EXPORT int WQDPKGMain(int argc, char * _Nonnull * _Nonnull argv,
                                  FILE * _Nonnull out, FILE * _Nonnull err);
FOUNDATION_EXPORT int WQAptMain(int argc, char * _Nonnull * _Nonnull argv,
                                 FILE * _Nonnull out, FILE * _Nonnull err);
FOUNDATION_EXPORT BOOL WQInstallDebPackage(NSString * _Nonnull path,
                                            NSString * _Nullable * _Nullable message);

/// Returns the control fields of a .deb as display text (dpkg --info style).
FOUNDATION_EXPORT NSString * _Nullable WQDebInfoText(NSString * _Nonnull path);
