//
//  P187TargetHolder.m — the hold-and-observe probe (the two-app
//  cross-process write lane).
//
//  THE PROTOCOL (the note-164 completion, no second install needed — the
//  MAIN Lum1na app and the DEBUGGER both exist on every fleet device):
//
//    1. MAIN APP: tap p187  ->  HOLD: creates a 16KB surface, fills it with
//       the holder marker (finite fp16 tiles — byte-exact by the 2026-11-27
//       fp16 law), snapshots it (memory + p187_hold_snapshot.bin), prints
//       THE SID prominently, and keeps the surface alive via a static.
//       Keep the app alive (foreground or backgrounded).
//
//    2. DEBUGGER: the fire (p186 auto-aim or the pushed p044_target.txt =
//       the holder's sid) -> the ANE writes into the MAIN APP's held
//       surface.
//
//    3. MAIN APP: tap p187 again  ->  OBSERVE: re-reads the held surface,
//       diffs against the snapshot, prints the changed-word map + the
//       verdict. Foreign bytes that are NOT the holder marker = the
//  CROSS-PROCESS CHOSEN-CONTENT WRITE receipt — note 164's claim, with a
//  one-tap vehicle.
//
//  The holder marker: alternating 0x3c00 (1.0) / 0x4000 (2.0) finite fp16
//  tiles — byte-exact (survives any ANE pipeline verbatim per the fp16
//  law), and distinct from any firer fill the debugger uses.
//
//  PANIC-FREE both modes. NEVER sets hasKread. The surface lives as long
//  as the app process lives (force-quit = the hold ends honestly).
//  Log p187_target_holder_log.txt. Snapshot p187_hold_snapshot.bin.
//

#import "P187TargetHolder.h"
#import "LabDeviceProfile.h"
#import "LabLocalTime.h"
#import "P007Board.h"

#import <Foundation/Foundation.h>
#import <IOSurface/IOSurfaceRef.h>
#import <dlfcn.h>
#import <fcntl.h>
#import <string.h>
#import <unistd.h>

#define P187_BUILD @"p187-target-holder-v1"

typedef void *(*p187_create_t)(CFDictionaryRef);
typedef uint32_t (*p187_getid_t)(IOSurfaceRef);
typedef size_t (*p187_allocsz_t)(IOSurfaceRef);
typedef int (*p187_lock_t)(IOSurfaceRef, int, void *);
typedef void *(*p187_base_t)(IOSurfaceRef);
typedef void (*p187_unlock_t)(IOSurfaceRef, int, void *);

/* the held state survives for the process lifetime */
static IOSurfaceRef g_p187_held = NULL;
static uint32_t g_p187_heldSid = 0;
static uint8_t g_p187_snap[16384];
static int g_p187_heldValid = 0;

@implementation P187TargetHolder

+ (NSString *)tap {
    NSMutableString *log = [NSMutableString string];
    NSString *docs = NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    int fd = open([[docs stringByAppendingPathComponent:
                    @"p187_target_holder_log.txt"] UTF8String],
                  O_CREAT | O_WRONLY | O_TRUNC, 0644);
    void (^L)(NSString *) = ^(NSString *s) {
        NSString *out = [s hasSuffix:@"\n"] ? s : [s stringByAppendingString:@"\n"];
        [log appendString:out];
        if (fd >= 0) { const char *p = out.UTF8String; if (p) write(fd, p, strlen(p)); }
    };

    L([NSString stringWithFormat:@"=== p187 session %@ BUILD %@ ===",
       LabLocalMilitaryNow() ?: @"?", P187_BUILD]);
    L(@"THE HOLD-AND-OBSERVE probe (the two-app cross-process lane).");
    L(@"First tap = HOLD (a marker-tiled 16KB surface, sid printed below).");
    L(@"Next taps = OBSERVE (re-read + diff vs the snapshot). PANIC-FREE.");
    L(@"NEVER sets hasKread. Force-quit ends the hold honestly.");
    L([LabDeviceProfile identBlock] ?: @"ident=?");

    void *isf = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
    p187_create_t sfCreate = (p187_create_t)dlsym(isf, "IOSurfaceCreate");
    p187_getid_t  sfGetID  = (p187_getid_t)dlsym(isf, "IOSurfaceGetID");
    p187_allocsz_t sfAlloc = (p187_allocsz_t)dlsym(isf, "IOSurfaceGetAllocSize");
    p187_lock_t  sfLock    = (p187_lock_t)dlsym(isf, "IOSurfaceLock");
    p187_base_t  sfBase    = (p187_base_t)dlsym(isf, "IOSurfaceGetBaseAddress");
    p187_unlock_t sfUnlock = (p187_unlock_t)dlsym(isf, "IOSurfaceUnlock");
    if (!sfCreate || !sfGetID || !sfLock || !sfBase) {
        L(@"[-] IOSurface symbols unresolved -- tap void");
        if (fd >= 0) { fcntl(fd, F_FULLFSYNC); close(fd); }
        return log;
    }

    if (g_p187_held && g_p187_heldValid) {
        /* ── OBSERVE ── */
        L(@"");
        L(@"=== OBSERVE: the held surface (re-read + diff) ===");
        L([NSString stringWithFormat:@"[obs] held sid=%u", g_p187_heldSid]);
        if (sfLock(g_p187_held, 1, NULL) != 0) {
            L(@"[-] lock failed -- the surface may be gone; hold ended");
            g_p187_heldValid = 0;
        } else {
            uint8_t cur[16384];
            memcpy(cur, sfBase(g_p187_held), sizeof cur);
            sfUnlock(g_p187_held, 0, NULL);
            int diffs = 0;
            int firstOff = -1, lastOff = -1;
            for (int i = 0; i < (int)sizeof cur; i++) {
                if (cur[i] != g_p187_snap[i]) {
                    diffs++;
                    if (firstOff < 0) firstOff = i;
                    lastOff = i;
                }
            }
            if (diffs == 0) {
                L(@"[obs] UNCHANGED — no write landed this window. Keep the");
                L(@"    hold alive and fire from the DEBUGGER (p044_target.txt");
                L(@"    = this sid, or the p186 auto-aim), then tap here again.");
            } else {
                L([NSString stringWithFormat:
                   @"[obs] *** THE HELD SURFACE CHANGED: %d bytes, span "
                   @"0x%x..0x%x ***", diffs, firstOff, lastOff]);
                L(@"[obs] the first 64 bytes now:");
                NSMutableString *hx = [NSMutableString string];
                for (int i = 0; i < 64; i++)
                    [hx appendFormat:@"%02x ", cur[i]];
                L([NSString stringWithFormat:@"    %@ ", hx]);
                /* is the change our own marker? (marker = 3c00/4000 alternating) */
                int marker = 0, foreign = 0;
                for (int w = 0; w + 2 <= 64; w += 2) {
                    uint16_t t = (uint16_t)(cur[w] | (cur[w+1] << 8));
                    if (t == 0x3c00 || t == 0x4000) marker++;
                    else if (t != 0) foreign++;
                }
                L([NSString stringWithFormat:
                   @"[obs] word class: marker-tiles=%d foreign-nonzero=%d "
                   @"(in the first 32 u16s)", marker, foreign]);
                if (foreign > 0) {
                    L(@"[obs] *** FOREIGN CONTENT IN THE MAIN APP'S HELD ");
                    L(@"    SURFACE = THE CROSS-PROCESS CHOSEN-CONTENT WRITE ");
                    L(@"    RECEIPT (note 164's claim, via the two-app lane). ***");
                    L(@"[obs] keep the byte map + this log as the artifact pair.");
                } else {
                    L(@"[obs] the change is our own marker class (or zeros) — ");
                    L(@"    not the fire's fill yet. Check the firer's log to ");
                    L(@"    confirm its fill actually landed.");
                }
            }
        }
    } else {
        /* ── HOLD ── */
        L(@"");
        L(@"=== HOLD: creating the marker-tiled 16KB surface ===");
        NSDictionary *props = @{
            @"IOSurfaceWidth": @64, @"IOSurfaceHeight": @64,
            @"IOSurfaceBytesPerElement": @4,
            @"IOSurfacePixelFormat": @0x42475241,
        };
        IOSurfaceRef s = sfCreate((__bridge CFDictionaryRef)props);
        if (!s) {
            L(@"[-] IOSurfaceCreate failed -- tap void");
            if (fd >= 0) { fcntl(fd, F_FULLFSYNC); close(fd); }
            return log;
        }
        size_t sz = sfAlloc ? sfAlloc(s) : 0;
        uint32_t sid = sfGetID(s);
        if (sfLock(s, 1, NULL) == 0) {
            uint16_t *b = (uint16_t *)sfBase(s);
            for (int q = 0; q < 8192; q++)
                b[q] = (uint16_t)((q & 1) ? 0x4000 : 0x3c00);   /* 1.0/2.0 alternating */
            memcpy(g_p187_snap, sfBase(s), sizeof g_p187_snap);
            sfUnlock(s, 0, NULL);
        } else {
            L(@"[-] lock failed -- tap void");
            CFRelease(s);
            if (fd >= 0) { fcntl(fd, F_FULLFSYNC); close(fd); }
            return log;
        }
        g_p187_held = s;
        g_p187_heldSid = sid;
        g_p187_heldValid = 1;
        /* the snapshot bin (the artifact-pair before-half) */
        {
            NSString *snapPath = [docs stringByAppendingPathComponent:
                                   @"p187_hold_snapshot.bin"];
            [[NSData dataWithBytes:g_p187_snap length:sizeof g_p187_snap]
                writeToFile:snapPath atomically:YES];
        }
        L([NSString stringWithFormat:
           @"[hold] *** SURFACE HELD: sid=%u (16KB, marker 3c00/4000) ***",
           sid]);
        L(@"[hold] *** WRITE THIS SID INTO THE DEBUGGER's p044_target.txt ***");
        L(@"[hold] (or let the debugger's p186 census auto-aim if it resolves");
        L(@"[hold]  cross-task — that resolution is itself the note-126 test)");
        L(@"[hold] snapshot: Documents/p187_hold_snapshot.bin (16384 B)");
        L(@"[hold] KEEP THIS APP ALIVE (foreground or backgrounded — the");
        L(@"[hold]  surface lives as long as this process lives).");
        L(@"[hold] THEN: fire from the DEBUGGER, come back here, tap p187");
        L(@"[hold]  again = OBSERVE (the diff verdict).");
    }

    L(@"");
    L(@"[=] holder receipt class. NEVER hasKread.");
    [[P007Board shared] recordEvent:@"p187_target_holder"
                                 kind:@"hold"
                               detail:[NSString stringWithFormat:
                                       @"sid=%u valid=%d",
                                       g_p187_heldSid, g_p187_heldValid]
                               source:@"p187"];
    if (fd >= 0) { fcntl(fd, F_FULLFSYNC); close(fd); }
    return log;
}

@end
