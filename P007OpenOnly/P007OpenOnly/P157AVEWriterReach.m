//
//  P157AVEWriterReach.m
//  P007OpenOnly
//

#import "P157AVEWriterReach.h"
#import "LabDeviceProfile.h"
#import "LabLocalTime.h"

#import <Foundation/Foundation.h>
#import <IOKit/IOKitLib.h>
#import <mach/mach.h>
#import <objc/message.h>
#import <stdlib.h>
#import <string.h>
#import <unistd.h>

#define P157_BUILD @"p157-ave2-writer-reach-v1"

@implementation P157AVEWriterReach

+ (NSString *)pasteboardString {
    id pb = ((id (*)(Class, SEL))objc_msgSend)(
        NSClassFromString(@"UIPasteboard"),
        NSSelectorFromString(@"generalPasteboard"));
    return pb ? ((NSString *(*)(id, SEL))objc_msgSend)(
        pb, NSSelectorFromString(@"string")) : nil;
}

+ (NSString *)knobsText {
    NSArray<NSString *> *dirs = NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *docs = dirs.count ? dirs.firstObject : nil;
    NSString *file = docs ? [NSString stringWithContentsOfFile:
        [docs stringByAppendingPathComponent:@"p157_knobs.txt"]
        encoding:NSUTF8StringEncoding error:NULL] : nil;
    return file.length ? file : [self pasteboardString];
}

+ (uint32_t)knob:(NSString *)key def:(uint32_t)d {
    NSString *s = [self knobsText];
    if (!s.length) return d;
    NSRange mk = [s rangeOfString:[key stringByAppendingString:@"="]];
    if (mk.location == NSNotFound) return d;
    NSUInteger at = mk.location + mk.length, e = at;
    BOOL hex = NO;
    if (at + 1 < s.length) {
        unichar c0 = [s characterAtIndex:at], c1 = [s characterAtIndex:at + 1];
        if (c0 == '0' && (c1 == 'x' || c1 == 'X')) { hex = YES; at += 2; e = at; }
    }
    while (e < s.length) {
        unichar c = [s characterAtIndex:e];
        if (hex) { if (!((c>='0'&&c<='9')||(c>='a'&&c<='f')||(c>='A'&&c<='F'))) break; }
        else if (c < '0' || c > '9') break;
        e++;
    }
    if (e == at) return d;
    unsigned long v = strtoul([[s substringWithRange:NSMakeRange(at, e-at)] UTF8String],
                              NULL, hex ? 16 : 10);
    return (uint32_t)v;
}

+ (void)logKr:(NSMutableString *)o tag:(NSString *)tag kr:(kern_return_t)kr
           out:(const uint8_t *)ob osz:(size_t)osz {
    const char *why = "";
    if (kr == 0) why = "  <-- SUCCESS";
    else if (kr == 0xe00002c2) why = "  (2c2 size/args)";
    else if (kr == 0xe00002c7) why = "  (2c7 Unsupported)";
    else if (kr == 0xe00002e2) why = "  (2e2 NotPermitted)";
    else if (kr == 0xe00002e3) why = "  (2e3 NoPower)";
    else if (kr == 0xe00002bc) why = "  (2bc no method)";
    [o appendFormat:@"      %@ kr=0x%x%s osz=%zu out=", tag, kr, why, osz];
    for (size_t i = 0; i < 20 && i < osz; i++) [o appendFormat:@"%02x", ob[i]];
    [o appendString:@"\n"];
}

+ (NSString *)tap {
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"=== p157 session %@ BUILD %@ ===\n",
        LabLocalMilitaryNow(), P157_BUILD];
    [out appendString:[LabDeviceProfile identBlock]];

    uint32_t type = [self knob:@"p157_type" def:1];
    uint32_t doOpen = [self knob:@"p157_open" def:1];
    uint32_t doPrep = [self knob:@"p157_prepare" def:0];
    uint32_t doCfg = [self knob:@"p157_config" def:0];
    uint32_t doStart = [self knob:@"p157_start" def:0];
    uint32_t doProc = [self knob:@"p157_process" def:0];
    /* Selector maps differ by SoC/build. 24A435 T8150: 0 Open, 2 Config,
       3 Prepare (0x12c08), 4 Start (0x12c18); 23F77 A14: 1 Open,
       3 Config, 4 Prepare (0x1a0a0), 5 Start (0x1a0b0). Process stays 7
       (sMethod_row7 on 24A435) with a knob override. */
    LabSku sku = [LabDeviceProfile detectedSku];
    BOOL t8150 = (sku == LabSkuT8150_24A435 || sku == LabSkuT8150_other);
    uint32_t selOpen  = [self knob:@"p157_sel_open"  def:(t8150 ? 0 : 1)];
    uint32_t selCfg   = [self knob:@"p157_sel_config" def:(t8150 ? 2 : 3)];
    uint32_t selPrep  = [self knob:@"p157_sel_prepare" def:(t8150 ? 3 : 4)];
    uint32_t selStart = [self knob:@"p157_sel_start" def:(t8150 ? 4 : 5)];
    uint32_t selProc  = [self knob:@"p157_sel_process" def:7];
    uint32_t sz1 = [self knob:@"p157_sel1_in" def:0x768];
    uint32_t o1  = [self knob:@"p157_sel1_out" def:0x38];
    uint32_t sz4 = [self knob:@"p157_sel4_in" def:(t8150 ? 0x12c08 : 0x1a0a0)];
    uint32_t o4  = [self knob:@"p157_sel4_out" def:0x20];
    uint32_t sz3 = [self knob:@"p157_sel3_in" def:0x38];
    uint32_t o3  = [self knob:@"p157_sel3_out" def:0x20];
    uint32_t sz5 = [self knob:@"p157_sel5_in" def:(t8150 ? 0x12c18 : 0x1a0b0)];
    uint32_t o5  = [self knob:@"p157_sel5_out" def:0x150];
    uint32_t sz7 = [self knob:@"p157_sel7_in" def:0x30];
    uint32_t o7  = [self knob:@"p157_sel7_out" def:0x20];
    uint32_t cntOff = [self knob:@"p157_count_off" def:(t8150 ? 0x12c10 : 0x1a0a8)];
    uint32_t cntVal = [self knob:@"p157_count" def:0];       /* 0 => +4, positive/safe */

    [out appendString:[NSString stringWithFormat:
        @"  [knobsrc] %@\n", [self knobsText].length ? @"file/pasteboard" : @"defaults"]];
    [out appendFormat:@"  [knobs] type=%u open=%u prep=%u cfg=%u start=%u proc=%u "
                       @"sizes %#x/%#x %#x/%#x %#x/%#x %#x/%#x %#x/%#x "
                       @"count=%#x@+%#x\n",
        type, doOpen, doPrep, doCfg, doStart, doProc,
        sz1,o1, sz4,o4, sz3,o3, sz5,o5, sz7,o7, cntVal, cntOff];
    if (doPrep || doCfg || doStart || doProc)
        [out appendString:@"  [PANIC-POSSIBLE] Prepare/Config/Start/Process enabled — fresh boot, one tap, zeroed request only\n"];
    [out appendString:@"  [law] iOS dispatch: sel3 Config 0x38/0x20, sel4 Prepare 0x1a0a0/0x20, sel5 Start 0x1a0b0/0x150, sel6-11 Process 0x30/0x20. The signed writer is UNCLAMPED on 27.0 and 27.2 (the cmp/csel is division rounding, not a lower bound). "
                       @"This probe does not call the negative-count path.\n"];

    CFMutableDictionaryRef m = IOServiceMatching("AppleAVE2Driver");
    if (!m) { [out appendString:@"[-] IOServiceMatching miss\n"]; return out; }
    io_service_t svc = IOServiceGetMatchingService(kIOMainPortDefault, m);
    if (!svc) { [out appendString:@"[-] AppleAVE2Driver not found\n"]; return out; }

    /* Open is the gate on stock: type 1 was NotPermitted. Sweep 0..5
       (the driver accepts type < 6); use the configured type if it
       opens, otherwise the first type that does. Opens only — no
       selectors. */
    io_connect_t conn = 0;
    uint32_t usedType = type;
    for (uint32_t t = 0; t <= 5; t++) {
        io_connect_t c = 0;
        kern_return_t okr = IOServiceOpen(svc, mach_task_self(), t, &c);
        [out appendFormat:@"  [open] AppleAVE2Driver type=%u kr=0x%x conn=%u%@\n",
            t, okr, (unsigned)c, (okr == KERN_SUCCESS ? @" (OPEN)" : @"")];
        if (okr == KERN_SUCCESS && c) {
            if (t == type || !conn) {
                if (conn && t != type) IOServiceClose(conn);
                conn = c;
                usedType = t;
            } else {
                IOServiceClose(c);
            }
        }
    }
    IOObjectRelease(svc);
    if (!conn) return out;
    if (usedType != type) {
        [out appendFormat:@"  [open] configured type=%u failed; using type=%u\n",
            type, usedType];
    }

    uint8_t *in = NULL, *ob = NULL;
    size_t osz;
    kern_return_t kr;

    if (doOpen) {
        in = calloc(1, sz1); ob = calloc(1, o1 ? o1 : 1);
        osz = o1;
        kr = IOConnectCallStructMethod(conn, selOpen, in, sz1, ob, &osz);
        [self logKr:out tag:[NSString stringWithFormat:@"sel%u Open", selOpen] kr:kr out:ob osz:osz];
        free(in); free(ob); in = ob = NULL;
    }
    if (doPrep) {
        in = calloc(1, sz4); ob = calloc(1, o4 ? o4 : 1);
        osz = o4;
        kr = IOConnectCallStructMethod(conn, selPrep, in, sz4, ob, &osz);
        [self logKr:out tag:[NSString stringWithFormat:@"sel%u Prepare", selPrep] kr:kr out:ob osz:osz];
        free(in); free(ob); in = ob = NULL;
    }
    if (doCfg) {
        /* macOS calls Config async (0x38/0x20). Try the sync shape first;
           a 2c2 means the async flag, not a wrong size. */
        in = calloc(1, sz3); ob = calloc(1, o3 ? o3 : 1);
        osz = o3;
        kr = IOConnectCallStructMethod(conn, selCfg, in, sz3, ob, &osz);
        [self logKr:out tag:[NSString stringWithFormat:@"sel%u Config sync", selCfg] kr:kr out:ob osz:osz];
        if (kr == 0xe00002c2) {
            mach_port_t wp = MACH_PORT_NULL;
            if (mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &wp) == KERN_SUCCESS) {
                mach_port_insert_right(mach_task_self(), wp, wp, MACH_MSG_TYPE_MAKE_SEND);
                uint64_t refs[8]; memset(refs, 0, sizeof(refs));
                osz = o3;
                kr = IOConnectCallAsyncMethod(conn, selCfg, wp, refs, 8,
                                              NULL, 0, in, sz3,
                                              NULL, NULL, ob, &osz);
                [self logKr:out tag:[NSString stringWithFormat:@"sel%u Config async", selCfg] kr:kr out:ob osz:osz];
                mach_port_destroy(mach_task_self(), wp);
            }
        }
        free(in); free(ob); in = ob = NULL;
    }
    if (doStart) {
        in = calloc(1, sz5); ob = calloc(1, o5 ? o5 : 1);
        if (cntOff + 4 <= sz5) memcpy(in + cntOff, &cntVal, 4);
        osz = o5;
        kr = IOConnectCallStructMethod(conn, selStart, in, sz5, ob, &osz);
        [self logKr:out tag:[NSString stringWithFormat:@"sel%u Start (zeroed, count nonneg)", selStart] kr:kr out:ob osz:osz];
        free(in); free(ob); in = ob = NULL;
    }
    if (doProc) {
        in = calloc(1, sz7); ob = calloc(1, o7 ? o7 : 1);
        osz = o7;
        kr = IOConnectCallStructMethod(conn, selProc, in, sz7, ob, &osz);
        [self logKr:out tag:[NSString stringWithFormat:@"sel%u Process", selProc] kr:kr out:ob osz:osz];
        free(in); free(ob); in = ob = NULL;
    }

    IOServiceClose(conn);
    [out appendString:@"  [verdict] selector-shape receipt only. Zeroed Start count is +4; no negative index, no underwrite. "
                       @"Full write needs the iOS client geometry (list vs writer base) from Ghidra.\n"];
    [out appendFormat:@"=== p157 end %@ ===\n", LabLocalMilitaryNow()];
    return out;
}

@end
