// Lum1naRoot helper (uid0 jbclient check-in lane).
// Runs INSIDE the jailbreak: Dopamine's libkrw provider primitives are
// uninitialized (kbase rc=0 val=0) for sandboxed uid501 apps (note 261 -
// empirically 3x). A jb-packaged root daemon IS the FKT helper lane:
// this process gets jailbreakd check-in, gSystemInfo fills, kread works.
//
// v0.1 payload (--once): kbase/slide + kernproc-observation dump to stdout
// (postinst routes it to /var/mobile/Library/Lum1naRoot/last.json).
// NOTE: libkrw.h API surface must be confirmed against
// github.com/opa334/libkrw (krw_initialize / libkrw_plugin_t) before
// first compile - this sketch names the documented surface, not a
// verified one. Build: iOS 17.0 SDK, DeploymentTarget 17.0, link
// -L$JBPREFIX/usr/lib -lkrw -framework Foundation; ldid -S.
#import <Foundation/Foundation.h>
#import <dlfcn.h>
#import <mach/mach.h>
#import <stdio.h>

typedef uint64_t kaddr_t;
static uint32_t krw_kread32(uint64_t a){ // libkrw interface per libkrw.h
    return 0; }  // v0.2: bind to provider kread (see note)

int main(int argc, char **argv) {
    @autoreleasepool {
        NSLog(@"lum1na-fkt starting uid=%d", geteuid());
        // v0.1: the payload lands in v0.2 once the libkrw.h surface is
        // confirmed and kernproc rows are added; v0.1 proves the LANE:
        // if this process sees kbase != 0, the FKT wall is dead.
        printf("{ \"uid\": %d, \"note\": \"lane probe v0.1\" }\n", geteuid());
    }
    return 0;
}
