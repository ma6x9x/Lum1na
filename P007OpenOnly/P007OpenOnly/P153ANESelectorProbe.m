//
//  P153ANESelectorProbe.m — ANE UC class-ID + DirectPath reach probe. p153 v1.
//  See header for the static selector map and the knob list.
//

#import "P153ANESelectorProbe.h"
#import "LabDeviceProfile.h"
#import "LabLocalTime.h"

#import <Foundation/Foundation.h>
#import <IOKit/IOKitLib.h>
#import <mach/mach.h>
#import <objc/message.h>
#import <stdlib.h>

@implementation P153ANESelectorProbe

+ (NSString *)pasteboardString {
    id pb = ((id (*)(Class, SEL))objc_msgSend)(
        NSClassFromString(@"UIPasteboard"),
        NSSelectorFromString(@"generalPasteboard"));
    return pb ? ((NSString *(*)(id, SEL))objc_msgSend)(
        pb, NSSelectorFromString(@"string")) : nil;
}

+ (NSString *)knobsFileText {
    NSArray<NSString *> *dirs = NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *docs = dirs.count ? dirs.firstObject : nil;
    if (!docs) return nil;
    return [NSString stringWithContentsOfFile:
        [docs stringByAppendingPathComponent:@"p153_knobs.txt"]
        encoding:NSUTF8StringEncoding error:NULL];
}

+ (uint32_t)knobUInt:(NSString *)key def:(uint32_t)d {
    NSString *fileText = [self knobsFileText];
    NSString *pbs = fileText.length ? fileText : [self pasteboardString];
    if (!pbs.length) return d;
    NSString *needle = [key stringByAppendingString:@"="];
    NSRange mk = [pbs rangeOfString:needle];
    if (mk.location == NSNotFound) return d;
    NSUInteger at = mk.location + mk.length;
    BOOL hex = NO;
    if (at + 1 < pbs.length) {
        unichar c0 = [pbs characterAtIndex:at], c1 = [pbs characterAtIndex:at + 1];
        if (c0 == '0' && (c1 == 'x' || c1 == 'X')) { hex = YES; at += 2; }
    }
    NSUInteger e = at;
    while (e < pbs.length) {
        unichar ch = [pbs characterAtIndex:e];
        if (hex) {
            if (!((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') ||
                  (ch >= 'A' && ch <= 'F'))) break;
        } else if (ch < '0' || ch > '9') break;
        e++;
    }
    if (e == at) return d;
    unsigned long v = strtoul([[pbs substringWithRange:NSMakeRange(at, e - at)] UTF8String],
                              NULL, hex ? 16 : 10);
    return (uint32_t)v;
}

+ (NSString *)knobString:(NSString *)key def:(NSString *)d {
    NSString *fileText = [self knobsFileText];
    NSString *pbs = fileText.length ? fileText : [self pasteboardString];
    if (!pbs.length) return d;
    NSString *needle = [key stringByAppendingString:@"="];
    NSRange mk = [pbs rangeOfString:needle];
    if (mk.location == NSNotFound) return d;
    NSUInteger at = mk.location + mk.length, e = at;
    while (e < pbs.length) {
        unichar ch = [pbs characterAtIndex:e];
        if (ch == ' ' || ch == '\n' || ch == '\t' || ch == '\r') break;
        e++;
    }
    return e > at ? [pbs substringWithRange:NSMakeRange(at, e - at)] : d;
}

+ (io_connect_t)openType1:(const char *)name kr:(kern_return_t *)outKr {
    *outKr = kIOReturnNoDevice;
    CFMutableDictionaryRef m = IOServiceMatching(name);
    if (!m) return 0;
    io_service_t svc = IOServiceGetMatchingService(kIOMainPortDefault, m);
    if (!svc) return 0;
    io_connect_t conn = 0;
    *outKr = IOServiceOpen(svc, mach_task_self(), 1, &conn);
    IOObjectRelease(svc);
    if (*outKr != KERN_SUCCESS) return 0;
    return conn;
}

+ (kern_return_t)structMethod:(io_connect_t)conn sel:(uint32_t)sel
                         inBuf:(const void *)in inSz:(size_t)inSz
                         outBuf:(void *)ob outSz:(size_t *)outSz {
    return IOConnectCallStructMethod(conn, sel, in, inSz, ob, outSz);
}

+ (void)logKr:(NSMutableString *)o tag:(NSString *)tag kr:(kern_return_t)kr
        out:(const uint8_t *)ob osz:(size_t)osz {
    const char *why = "";
    if (kr == 0) why = "  <-- SUCCESS";
    else if (kr == 0xe00002f0) why = "  (Client not found / not registered)";
    else if (kr == 0xe00002e3) why = "  (NoPower: found, engine unpowered)";
    else if (kr == 0xe00002c2) why = "  (bad size / bad args)";
    else if (kr == 0xe00002e2) why = "  (NotPermitted: entitlement)";
    else if (kr == 0xe00002c7) why = "  (Unsupported)";
    [o appendFormat:@"      %@ kr=0x%x%s osz=%zu out=", tag, kr, why, osz];
    for (size_t i = 0; i < 24 && i < osz; i++) [o appendFormat:@"%02x", ob[i]];
    [o appendString:@"\n"];
}

+ (kern_return_t)asyncSend:(io_connect_t)conn
                     inCnt:(uint32_t)inCnt outCnt:(uint32_t)outCnt
                     offIn:(uint32_t)offIn offOut:(uint32_t)offOut
                       size:(uint32_t)sendSz outSize:(uint32_t)sendOutSz
                        log:(NSMutableString *)o refOut:(uint64_t *)refOut {
    if (sendSz < 0x100) sendSz = 0x948;
    if (sendOutSz < 0x28 || sendOutSz > 0x200) sendOutSz = 0x28;
    mach_port_t wp = MACH_PORT_NULL;
    kern_return_t kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &wp);
    if (kr != KERN_SUCCESS) { [o appendFormat:@"      async port alloc kr=0x%x\n", kr]; return kr; }
    mach_port_insert_right(mach_task_self(), wp, wp, MACH_MSG_TYPE_MAKE_SEND);

    uint8_t *in = calloc(1, sendSz);
    uint8_t *ob = calloc(1, sendOutSz);
    if (!in || !ob) { free(in); free(ob); mach_port_destroy(mach_task_self(), wp); return kIOReturnNoMemory; }
    if (inCnt && offIn + 4 <= sendSz) memcpy(in + offIn, &inCnt, 4);
    if (outCnt && offOut + 4 <= sendSz) memcpy(in + offOut, &outCnt, 4);

    uint64_t scalar = 0;
    uint64_t refs[8]; memset(refs, 0, sizeof(refs));
    size_t osz = sendOutSz;
    kr = IOConnectCallAsyncMethod(conn, 2, wp, refs, 8,
                                  &scalar, 1, in, sendSz,
                                  NULL, NULL, ob, &osz);
    [o appendFormat:@"      sel2 async in=%u@0x%x out=%u@0x%x size=0x%x kr=0x%x refs=%llu,0 "
                       @"osz=%zu\n",
        inCnt, offIn, outCnt, offOut, sendSz, kr,
        (unsigned long long)refs[0], osz];
    for (size_t i = 0; i < 24 && i < osz; i++) [o appendFormat:@"%02x", ob[i]];
    [o appendString:@"\n"];
    if (refOut) *refOut = refs[0];
    free(in); free(ob);
    mach_port_destroy(mach_task_self(), wp);
    return kr;
}

+ (NSString *)tap {
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"=== p153 session %@ BUILD p153-ane-selector-v1 ===\n",
        LabLocalMilitaryNow()];
    [out appendString:[LabDeviceProfile identBlock]];

    uint32_t pid = [self knobUInt:@"p153_pid" def:0];
    uint32_t t1 = [self knobUInt:@"p153_t1" def:1];
    uint32_t t4 = [self knobUInt:@"p153_t4" def:1];
    uint32_t doSend = [self knobUInt:@"p153_send" def:0];
    uint32_t doMap = [self knobUInt:@"p153_map" def:0];
    uint32_t doCreate = [self knobUInt:@"p153_create" def:0];
    uint32_t force = [self knobUInt:@"p153_force" def:0];
    uint32_t inCnt = [self knobUInt:@"p153_in_count" def:0];
    uint32_t outCnt = [self knobUInt:@"p153_out_count" def:0];
    uint32_t offIn = [self knobUInt:@"p153_off_in" def:0x1c];
    uint32_t offOut = [self knobUInt:@"p153_off_out" def:0x51c];
    BOOL is26 = ![[LabDeviceProfile osversion] hasPrefix:@"24"];
    BOOL is27 = [[LabDeviceProfile osversion] hasPrefix:@"24"];
    uint32_t createSz = [self knobUInt:@"p153_create_size" def:(is27 ? 0xd88 : 0x35e18)];
    uint32_t createMagic = [self knobUInt:@"p153_create_magic" def:0xac738];
    NSString *defaultSvc = is26 ? @"H11ANEIn" : @"H1xANELoadBalancer";
    NSString *svc = [self knobString:@"p153_svc" def:defaultSvc];
    /* 24A435 table @0xfffffe00080554f8 (11 sels, capstone): sel2 SendRequest
       structIn 0xc50/structOut 0x40; sel3 ProgramCreate structIn 0x28;
       sel5 MemoryMapRequest 1 scalar in + 0x828 + 1 scalar out; sel7 0x10/0x18.
       p153 v1 used 0xd88 send and 0x20 create from the 23F77 row. */
    uint32_t sendSz = [self knobUInt:@"p153_send_size" def:(is26 ? 0x948 : 0xc50)];
    uint32_t sendOutSz = [self knobUInt:@"p153_send_out_size" def:(is26 ? 0x28 : 0x40)];
    uint32_t mapSz = [self knobUInt:@"p153_map_size" def:(is26 ? 0x2008 : 0x828)];
    uint32_t devSz = [self knobUInt:@"p153_dev_size" def:(is26 ? 0x68 : 0x88)];
    uint32_t createStructSz = [self knobUInt:@"p153_create_struct_size" def:(is27 ? 0x28 : 0x20)];
    if (devSz < 0x40 || devSz > 0x200) devSz = is26 ? 0x68 : 0x88;
    if (mapSz < 0x828) mapSz = 0x828;
    if (sendOutSz < 0x28) sendOutSz = is26 ? 0x28 : 0x40;
    if (createStructSz < 0x20 || createStructSz > 0x80) createStructSz = is27 ? 0x28 : 0x20;
    NSString *knobSrc = [self knobsFileText].length ? @"Documents/p153_knobs.txt"
        : ([self pasteboardString].length ? @"pasteboard" : @"defaults");
    if (![svc isEqualToString:defaultSvc])
        [out appendFormat:@"  [warn] p153_svc=%@ overrides this SKU default %@\n", svc, defaultSvc];

    [out appendString:[NSString stringWithFormat:@"  [knobsrc] %@\n", knobSrc]];
    [out appendFormat:@"  [knobs] pid=%u svc=%@ types=%u/%u send=%u map=%u create=%u force=%u "
                       @"counts=%u/%u offs=0x%x/0x%x sizes send=0x%x out=0x%x map=0x%x dev=0x%x "
                       @"create=0x%x/0x%x struct=0x%x\n",
        pid, svc, t1, t4, doSend, doMap, doCreate, force, inCnt, outCnt, offIn, offOut,
        sendSz, sendOutSz, mapSz, devSz, createSz, createMagic, createStructSz];
    if (doSend || doMap || doCreate)
        [out appendString:@"  [PANIC-POSSIBLE] map/create/send enabled: one tap, fresh boot\n"];

    NSArray<NSNumber *> *types = @[@1, @4];
    int opened = 0, success = 0;
    for (NSNumber *tn in types) {
        uint32_t type = tn.unsignedIntValue;
        if ((type == 1 && !t1) || (type == 4 && !t4)) continue;
        kern_return_t okr = 0;
        io_connect_t conn = [self openType1:svc.UTF8String kr:&okr];
        [out appendFormat:@"  [open] %@ type=%u kr=0x%x\n", svc, type, okr];
        if (!conn && okr == 0xe00002c7 && ![svc isEqualToString:defaultSvc]) {
            /* Stale p153_svc knob from another SKU (the 2026-11-07 14:52 run
               opened H11ANEIn on 27.0 -> 2c7). Fall back to the SKU default. */
            [out appendFormat:@"  [warn] %@ unsupported here (2c7) — retrying SKU default %@\n",
                svc, defaultSvc];
            svc = defaultSvc;
            conn = [self openType1:svc.UTF8String kr:&okr];
            [out appendFormat:@"  [open] %@ type=%u kr=0x%x (default retry)\n", svc, type, okr];
        }
        if (!conn) continue;
        opened++;

        /* Class ID: sel7 UserClient GetStatus (in 0 / out 0x20) vs
           DirectPath SessionHint (in 0x10 / out 0x18). Wrong shape = 2c2. */
        uint8_t in16[0x10]; memset(in16, 0, sizeof(in16));
        uint8_t out18[0x18]; memset(out18, 0, sizeof(out18));
        size_t osz = sizeof(out18);
        kern_return_t krDP = [self structMethod:conn sel:7 inBuf:in16 inSz:0x10
                                         outBuf:out18 outSz:&osz];
        [self logKr:out tag:@"sel7 DP-shape (0x10/0x18)" kr:krDP out:out18 osz:osz];

        uint8_t out20[0x20]; memset(out20, 0, sizeof(out20));
        uint8_t dummy[1] = {0};
        osz = sizeof(out20);
        kern_return_t krUC = [self structMethod:conn sel:7 inBuf:dummy inSz:0
                                         outBuf:out20 outSz:&osz];
        [self logKr:out tag:@"sel7 UC-shape (0/0x20)" kr:krUC out:out20 osz:osz];

        BOOL isDP = (krDP != 0xe00002c2);
        BOOL isUC = (krUC != 0xe00002c2);
        [out appendFormat:@"    [class] %@\n",
            isDP && !isUC ? @"DirectPath (table2)"
            : isUC && !isDP ? @"UserClient (table1)"
            : (isDP && isUC ? @"ambiguous (both shapes accepted)"
                            : @"unidentified (both 2c2)")];
        if (!isDP && !isUC)
            [out appendString:@"    [hint] sel7 is not the class oracle on this train; "
                               @"sel0 DeviceOpen below is the receipt. Use p153_force=1 "
                               @"to exercise map/create (PANIC-POSSIBLE).\n"];

        if (doMap && (isDP || force)) {
            uint8_t *map = calloc(1, mapSz);
            uint64_t scalars[1] = {1};
            uint64_t mout = 0;
            uint32_t moutCnt = 1;
            size_t moutStructSz = 0;
            kern_return_t mkr = IOConnectCallMethod(conn, 5, scalars, 1, map, mapSz,
                                                    &mout, &moutCnt, NULL, &moutStructSz);
            [out appendFormat:@"      sel5 map 0x%x scalar=1 kr=0x%x scalar_out=0x%llx\n",
                mapSz, mkr, (unsigned long long)mout];
            free(map);
        }
        if (doMap && !isDP && !force)
            [out appendString:@"      sel5 map skipped (not DirectPath class)\n"];

        if (doCreate && (isUC || force)) {
            uint8_t cr[0x80]; memset(cr, 0, sizeof(cr));
            uint64_t sz = createSz, magic = createMagic;
            memcpy(cr + 0x08, &sz, 8);
            memcpy(cr + 0x18, &magic, 8);
            uint8_t cb[8]; memset(cb, 0, sizeof(cb));
            size_t cosz = sizeof(cb);
            kern_return_t ckr = IOConnectCallStructMethod(conn, 3, cr, createStructSz,
                                                          cb, &cosz);
            [self logKr:out tag:@"sel3 ProgramCreate (size/magic)" kr:ckr out:cb osz:cosz];
        }
        if (doCreate && !isUC && !force)
            [out appendString:@"      sel3 create skipped (not UserClient class)\n"];

        if (doSend) {
            uint64_t ref = 0;
            kern_return_t skr = [self asyncSend:conn inCnt:inCnt outCnt:outCnt
                                          offIn:offIn offOut:offOut size:sendSz outSize:sendOutSz
                                            log:out refOut:&ref];
            [out appendFormat:@"    [send] reach test kr=0x%x (zero counts unless knobs set)\n", skr];
        }

        /* DeviceOpen after any preceding calls, to see whether they registered
           this UC in the ANE client list. */
        uint8_t din[0x200], dob[0x200];
        memset(din, 0, devSz); memset(dob, 0, devSz);
        if (pid != 0) memcpy(din, &pid, 4);
        osz = devSz;
        kern_return_t dkr = IOConnectCallStructMethod(conn, 0, din, devSz, dob, &osz);
        [self logKr:out tag:[NSString stringWithFormat:@"sel0 DeviceOpen 0x%x", devSz]
               kr:dkr out:dob osz:osz];
        if (dkr == 0) success++;

        uint32_t sc = 0;
        IOConnectCallScalarMethod(conn, 1, NULL, 0, NULL, &sc);
        IOServiceClose(conn);
    }

    [out appendFormat:@"  [res] opens=%d deviceOpen_success=%d\n", opened, success];
    [out appendFormat:@"  [verdict] %@\n",
        success ? @"DeviceOpen accepted after the preceding selector(s) — path live"
                : @"no DeviceOpen success; class map is the receipt"];
    [out appendFormat:@"=== p153 end %@ ===\n", LabLocalMilitaryNow()];
    return out;
}

@end
