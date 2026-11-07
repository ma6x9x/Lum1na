//
//  RespringLogo.m — SpringBoard post-respring LUM1NA plate.
//
//  Build (needs the iPhoneOS SDK + ldid, not the IPA job):
//    ./build.sh
//  Deploy: copy RespringLogo.dylib into the app's Documents/tweaks before
//  the Full Chain injection. ElleKit/TweakLoader loads it into SpringBoard
//  if the jailbreak is live. Guarded by bundle id, so a leak into another
//  process is a no-op.
//

#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#import <QuartzCore/QuartzCore.h>

static UIWindow *gLogoWindow;

static void lum_show_logo(void) {
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(300 * NSEC_PER_MSEC)),
                   dispatch_get_main_queue(), ^{
        UIWindow *w = [[UIWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];
        w.windowLevel = UIWindowLevelAlert + 100;
        w.rootViewController = [UIViewController new];
        w.hidden = NO;

        CAGradientLayer *g = [CAGradientLayer layer];
        g.frame = w.bounds;
        g.colors = @[
            (id)[UIColor colorWithRed:1.00 green:0.16 blue:0.47 alpha:1].CGColor,
            (id)[UIColor colorWithRed:0.46 green:0.10 blue:0.92 alpha:1].CGColor,
        ];
        g.startPoint = CGPointMake(0, 0);
        g.endPoint = CGPointMake(1, 1);
        [w.rootViewController.view.layer addSublayer:g];

        UILabel *title = [[UILabel alloc] initWithFrame:w.bounds];
        title.text = @"LUM1NA";
        title.textColor = [UIColor whiteColor];
        title.font = [UIFont systemFontOfSize:34 weight:UIFontWeightHeavy];
        title.textAlignment = NSTextAlignmentCenter;
        [w.rootViewController.view addSubview:title];

        UILabel *sub = [[UILabel alloc] initWithFrame:CGRectOffset(w.bounds, 0, 44)];
        sub.text = @"respringing";
        sub.textColor = [[UIColor whiteColor] colorWithAlphaComponent:0.85];
        sub.font = [UIFont systemFontOfSize:13 weight:UIFontWeightMedium];
        sub.textAlignment = NSTextAlignmentCenter;
        [w.rootViewController.view addSubview:sub];

        gLogoWindow = w;
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2400 * NSEC_PER_MSEC)),
                       dispatch_get_main_queue(), ^{
            gLogoWindow.hidden = YES;
            gLogoWindow = nil;
        });
    });
}

__attribute__((constructor))
static void lum_respring_logo_init(void) {
    if (![[NSBundle mainBundle].bundleIdentifier isEqualToString:@"com.apple.springboard"]) {
        return;
    }
    lum_show_logo();
}
