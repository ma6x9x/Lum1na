//
//  WQRespring.m
//  FilzaSlop
//
//  WebKit-based respring method from Erosion / neonmodder123.
//

#import "WQRespring.h"
#import <UIKit/UIKit.h>
#import <WebKit/WebKit.h>

static WKWebView *gRespringWebView;

static NSString *const kWQRespringHTML =
@"<!DOCTYPE html><html><body>"
@"<iframe id=\"frame\" srcdoc=\"\" sandbox=\"allow-forms allow-modals "
@"allow-orientation-lock allow-pointer-lock allow-popups allow-presentation "
@"allow-scripts\"></iframe>"
@"<script>"
@"const frame=document.getElementById('frame');"
@"const respringScript=`<html><body><script>"
@"const container=document.createElement('div');"
@"container.style.cssText='perspective: 1px; perspective-origin: 9999999% 9999999%;';"
@"document.body.appendChild(container);"
@"for(let i=0;i<500;i++){let d=document.createElement('div');"
@"d.style.cssText='position:absolute;width:100vw;height:100vh;"
@"backdrop-filter:blur(100px);-webkit-backdrop-filter:blur(100px);"
@"transform:translate3d(100000px,100000px,'+i+'px) rotateY(90deg);';"
@"container.appendChild(d);}"
@"setInterval(()=>{navigator.share({title:'R',text:'R'.repeat(100000)}).catch(()=>{});"
@"let x=new Uint8Array(1024*1024*10);crypto.getRandomValues(x);},0);"
@"<\\/script></body></html>`;"
@"frame.srcdoc=respringScript;"
@"</script></body></html>";

void WQPerformRespring(void)
{
    dispatch_async(dispatch_get_main_queue(), ^{
        UIWindow *window = nil;
        for (UIWindow *candidate in UIApplication.sharedApplication.windows) {
            if (candidate.isKeyWindow && !candidate.isHidden) {
                window = candidate;
                break;
            }
        }
        if (!window) {
            for (UIWindow *candidate in UIApplication.sharedApplication.windows) {
                if (!candidate.isHidden) { window = candidate; break; }
            }
        }
        if (!window) return;

        if (!gRespringWebView) {
            WKWebViewConfiguration *configuration = [WKWebViewConfiguration new];
            gRespringWebView = [[WKWebView alloc] initWithFrame:window.bounds
                configuration:configuration];
            gRespringWebView.backgroundColor = UIColor.blackColor;
            gRespringWebView.opaque = YES;
        }
        if (gRespringWebView.superview != window) {
            gRespringWebView.frame = window.bounds;
            [window addSubview:gRespringWebView];
        }
        [gRespringWebView loadHTMLString:kWQRespringHTML baseURL:nil];
        NSLog(@"[Respring] WebKit respring pressure started");
    });
}
