//
//  TermLiteBridge.m — Term Lite's integration shim. Defines the
//  WQTerminalPrepare / WQTerminalSpawnShell symbols that the vendored
//  WQSSHServer relies on, backed by the embedded a-Shell payload
//  (Frameworks/ios_system.framework) at RUNTIME. The payload-soft law:
//  missing framework -> prepare returns NO, spawn returns -1, the UI
//  reports honestly. No launches ever fail for a runtime that is absent.
//  Pattern adapted from the lab's vendored WQ bridge; implementation ours.
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <dlfcn.h>
#import <pthread.h>
#import <ptrauth.h>
#import <spawn.h>
#import <fcntl.h>
#import <unistd.h>
#import <dirent.h>

#pragma mark - ios_system symbols (loaded from the embedded framework)

static void *g_ios = NULL;

static BOOL ioss_prepare(void) {
    if (g_ios) return YES;
    NSString *path = [NSBundle.mainBundle.bundlePath
        stringByAppendingPathComponent:@"Frameworks/ios_system.framework/ios_system"];
    g_ios = dlopen(path.fileSystemRepresentation, RTLD_NOW | RTLD_GLOBAL);
    return g_ios != NULL;
}

#define LT_DLSYM(fn) extern fn;  /* unused; symbols dlsym'd below */

static BOOL ios_ready = NO;
static void (*ios_setStreams)(FILE *, FILE *, FILE *);
static int (*ios_system)(const char *);
static void (*ios_switchSession)(NSString *);
static void (*ios_setDirectoryURL)(NSURL *);

static BOOL lt_ios_init(void) {
    if (ios_ready) return YES;
    if (!ioss_prepare()) return NO;
    ios_setStreams = (__typeof(ios_setStreams))dlsym(g_ios, "ios_setStreams");
    ios_system = (__typeof(ios_system))dlsym(g_ios, "ios_system");
    ios_switchSession = (__typeof(ios_switchSession))dlsym(g_ios, "ios_switchSession");
    ios_setDirectoryURL = (__typeof(ios_setDirectoryURL))dlsym(g_ios, "ios_setDirectoryURL");
    void (*initializeEnvironment)(void) = (__typeof(initializeEnvironment))dlsym(g_ios, "initializeEnvironment");
    if (!ios_setStreams || !ios_system) return NO;
    if (initializeEnvironment) initializeEnvironment();
    if (ios_switchSession) ios_switchSession(@"term_lite");
    if (ios_setDirectoryURL) ios_setDirectoryURL([NSURL fileURLWithPath:NSHomeDirectory()]);
    bool *sideLoading = (bool *)dlsym(g_ios, "sideLoading");
    if (sideLoading) *sideLoading = true;
    ios_ready = YES;
    return YES;
}

#pragma mark - WQ bridge contract (consumed by vendored WQSSHServer.m)

BOOL WQTerminalPrepare(void) {
    return lt_ios_init();
}

NSString *WQVirtualRootFolder(void) {
    /* the filza build rooted its hub in Documents/worse_query — same law */
    NSString *docs = [NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    NSString *root = [docs stringByAppendingPathComponent:@"worse_query"];
    [[NSFileManager defaultManager] createDirectoryAtPath:root
        withIntermediateDirectories:YES attributes:nil error:nil];
    return root;
}

int WQTerminalSpawnShell(int *pidOut, NSString *chdir) {
    if (!lt_ios_init()) {
        if (pidOut) *pidOut = 0;
        return -1;
    }
    /* PTY pair; ios_system runs a login loop reading the master in a worker */
    int master = posix_openpt(O_RDWR | O_NOCTTY);
    if (master < 0) return -1;
    if (grantpt(master) != 0 || unlockpt(master) != 0) { close(master); return -1; }

    if (chdir.length) ios_setDirectoryURL([NSURL fileURLWithPath:chdir]);
    NSString *session = [NSString stringWithFormat:@"term_lite_%d", (int)getpid()];
    if (ios_switchSession) ios_switchSession(session);

    FILE *in = fdopen(dup(master), "r");
    FILE *out = fdopen(dup(master), "w");
    FILE *err = fdopen(dup(master), "w");
    if (ios_setStreams) ios_setStreams(in, out, err);

    int *sl = pidOut; /* the vendored UI only uses it for a stop row */
    (void)sl;

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        if (ios_system) ios_system("login -f");
    });
    return master;
}
