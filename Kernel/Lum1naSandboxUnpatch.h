//
//  Lum1naSandboxUnpatch.h — P165. Post-KRW sandbox extension unpatch
//  (translated from the jbjflab filza27.2 sandbox_escape.m — CrazyMind90's
//  18.3_sandbox law: proc_ro -> ucred -> cr_label -> sandbox -> ext_set;
//  every extension path rewritten to "/", class = app-sandbox.read-write,
//  all 16 hash slots filled). Uses the live Lum1naLane cascade
//  (socketkrw/libkrw/cs2core). READS the walk for real, validates every
//  pointer against this boot's kernel band, and only fires after hasKread.
//  Not a KRW provider, not a bypass engine of its own.
//

#import <Foundation/Foundation.h>

@interface Lum1naSandboxUnpatch : NSObject
/// Run after the KRW self-test passes. Returns a transcript; sets hasFired.
+ (NSString *)tap;
@property (class, nonatomic, readonly) BOOL hasFired;
@end
