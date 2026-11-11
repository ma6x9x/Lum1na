//
//  P151ANEDeviceOpen.m — ANE DirectPath DeviceOpen + LB selector census. p151 (v6).
//  Lum1na-Debug (P007 rig). iOS kernel research (Lum1na).
//
//  STATIC RE (23F77, capstone, 2026-11-07): sel0 is NOT pid-resolved.
//  ------------------------------------------------------------------
//  sel0 handler 0xfffffff008757dc0: requires structIn>=0x68 && structOut>=0x68,
//  copies 0x68 bytes in->out, tail-calls ANE_DeviceOpen 0xfffffff008752524.
//  ANE_DeviceOpen reads:
//    [UC+0x20] = pid (log only)   [UC+0x2a] = client name
//    [UC+0x28]/[UC+0x29] bits -> out+0x1c / out+0x5d
//    if [UC+0x24] == 2  ->  return 0 EARLY (no AddClient, no power)
//    else buffer+8 q0 (16B) -> [UC+0xb0], then provider vtable+0x558
//    = ANE_AddClientForProgram_gated (0xfffffff0086f3624).
//  AddClientForProgram calls 0xfffffff0086ef7d0(self,buf,&ctx): that helper
//  scans the ANE client list at [self+0xe0] (count vtable+0x90, element
//  vtable+0x118) and matches the USER-CLIENT OBJECT POINTER. No pid is read.
//  Failure => 0xE00002F0 with "Client %p not found" (0xfffffff0073d4278),
//  and the second call (revalidation after the program loop) returns 0x2F0
//  too. The three "Cannot find task from the given pid" helpers
//  (0x8718728 / 0x8739b14 / 0x87ac4b8) are NOT on this path.
//  => writing pid 1 / aned's pid / any pid into the 0x68 buffer cannot fix
//  DeviceOpen. What matters is (a) whether the UC is in the ANE client list,
//  or (b) whether [UC+0x24] == 2 takes the early-success branch.
//
//  v5 therefore sweeps IOServiceOpen type 0..4 and makes the struct sizes and
//  pid offsets pasteboard knobs. It never calls ProgramSendRequest; nothing
//  fires. One tap per run.
//

#import "P151ANEDeviceOpen.h"
#import "LabDeviceProfile.h"
#import "LabLocalTime.h"

#import <Foundation/Foundation.h>
#import <IOKit/IOKitLib.h>
#import <mach/mach.h>
#import <objc/message.h>
#import <CoreML/CoreML.h>

@implementation P151ANEDeviceOpen

#define P151_ANE_DEVICEOPEN_BUILD @"p151-ane-deviceopen-v6-lbcensus"

/* v6: census of the SELECTORS on an ACCEPTED client (sel0 kr=0). For 24A435
   the H1xANELoadBalancer types 1/4 register via AddClient, so the LB's own
   selector space is reachable for the first time. For each selector we try
   each declared size with a ZERO-FILLED struct (never a send request, no
   program, nothing fires — this is the p109/p153 census form). The decode
   highlights the classes that matter: 0x2e2 = "Not permitted" entitlement
   gate (the pid-borrow target class), kr=0 = a real responder, 2f0/2e3 =
   registration/power echoes, 2c2/2c7 = shape noise (collapsed). */
+ (void)selCensus:(io_connect_t)conn svc:(NSString *)svcName type:(uint32_t)type
           maxSel:(uint32_t)maxSel pid:(uint32_t)pid baseSz:(uint32_t)baseSz
             out:(NSMutableString *)log {
    [log appendFormat:@"      [sel census] %@ type=%u sels=0..0x%x sizes=0x%x/0x68/0x88/0x150 (zero-filled; PANIC-POSSIBLE class — one tap per force-quit)\n",
        svcName, type, maxSel, baseSz];
    uint32_t gates = 0, responders = 0, closed = 0;
    NSMutableString *gateList = [NSMutableString string];
    NSMutableString *respList = [NSMutableString string];
    for (uint32_t sel = 2; sel < maxSel; sel++) {
        uint32_t sizes[4] = { baseSz, 0x68, 0x88, 0x150 };
        kern_return_t best = 0xe00002c2;
        uint32_t bestSz = 0;
        const char *why = "";
        for (int i = 0; i < 4; i++) {
            uint32_t sz = sizes[i];
            uint8_t *in = calloc(1, sz);
            uint8_t *ob = calloc(1, sz);
            if (!in || !ob) { free(in); free(ob); return; }
            if (pid && sz >= 4) { uint32_t p = pid; memcpy(in, &p, 4); }
            size_t osz = sz;
            kern_return_t kr = IOConnectCallStructMethod(conn, sel, in, sz, ob, &osz);
            free(in); free(ob);
            /* first call wins the row; later sizes only refine a 2c2 miss */
            if (best == 0xe00002c2 && kr != 0xe00002c2) {
                best = kr; bestSz = sz;
                if (kr == 0) { why = " (RESPONDER)"; }
                else if (kr == 0xe00002e2) { why = " (ENTITLEMENT GATE — pid-borrow target)"; }
                else if (kr == 0xe00002f0) { why = " (registration miss)"; }
                else if (kr == 0xe00002e3) { why = " (NoPower echo)"; }
                else if (kr == 0xe00002c7) { why = " (Unsupported)"; }
                else why = "";
                if (kr != 0xe00002c2 && kr != 0xe00002c7) {
                    /* capture the first 24 out bytes on the winning shape */
                    uint8_t *ob2 = calloc(1, sz);
                    uint8_t *in2 = calloc(1, sz);
                    if (in2 && ob2) {
                        if (pid && sz >= 4) { uint32_t p = pid; memcpy(in2, &p, 4); }
                        size_t o2 = sz;
                        kern_return_t k2 = IOConnectCallStructMethod(conn, sel, in2, sz, ob2, &o2);
                        if (k2 == kr) {
                            [log appendFormat:@"      sel%-3u in=0x%-5x kr=0x%x%s out=",
                                sel, bestSz, kr, why];
                            for (NSUInteger b = 0; b < 24 && b < o2; b++)
                                [log appendFormat:@"%02x", ob2[b]];
                            [log appendString:@"\n"];
                        }
                    }
                    free(in2); free(ob2);
                }
            }
        }
        if (best == 0) { responders++; [respList appendFormat:@"sel%u ", sel]; }
        else if (best == 0xe00002e2) { gates++; [gateList appendFormat:@"sel%u ", sel]; }
        else if (best == 0xe00002c2 || best == 0xe00002c7) closed++;
    }
    [log appendFormat:@"      [sel census] %@ t%u total: responders=[%@] gates=[%@] shape-noise=%u\n",
        svcName, type, respList.length ? respList : @"none", gateList.length ? gateList : @"none", closed];
    if (gates) {
        [log appendString:@"      [law] 2e2 rows = where the entitlement check sits; the request path behind them is\n"
                          @"       the Stage-B pid-borrow target (kern.proc live pid at req+0x180 — next build).\n"];
    } else {
        [log appendString:@"      [law] no 2e2 rows this census — no entitlement gate is selector-visible on this client.\n"];
    }
}

+ (NSString *)pasteboardString {
    id pb = ((id (*)(Class, SEL))objc_msgSend)(
        NSClassFromString(@"UIPasteboard"),
        NSSelectorFromString(@"generalPasteboard"));
    return pb ? ((NSString *(*)(id, SEL))objc_msgSend)(
        pb, NSSelectorFromString(@"string")) : nil;
}

/// v5.1: file knobs first, pasteboard second. Write the same key=value text to
/// Documents/p151_knobs.txt and no paste prompt is involved at all.
+ (NSString *)knobsFileText {
    NSArray<NSString *> *dirs = NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *docs = dirs.count ? dirs.firstObject : nil;
    if (!docs) return nil;
    return [NSString stringWithContentsOfFile:
        [docs stringByAppendingPathComponent:@"p151_knobs.txt"]
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
    NSUInteger e = at;
    BOOL hex = NO;
    if (e < pbs.length) {
        unichar c0 = [pbs characterAtIndex:e];
        if (c0 == '0' && e + 1 < pbs.length) {
            unichar c1 = [pbs characterAtIndex:e + 1];
            if (c1 == 'x' || c1 == 'X') { hex = YES; e += 2; at = e; }
        }
    }
    NSUInteger start = e;
    while (e < pbs.length) {
        unichar ch = [pbs characterAtIndex:e];
        if (hex) {
            if (!((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') ||
                  (ch >= 'A' && ch <= 'F'))) break;
        } else {
            if (ch < '0' || ch > '9') break;
        }
        e++;
    }
    if (e == start) return d;
    NSString *num = [pbs substringWithRange:NSMakeRange(start, e - start)];
    unsigned long v = hex ? strtoul(num.UTF8String, NULL, 16)
                          : strtoul(num.UTF8String, NULL, 10);
    return (uint32_t)v;
}

+ (uint32_t)pidFromPasteboardOrDefault {
    return [self knobUInt:@"p151_pid" def:0];
}

+ (io_connect_t)openType:(const char *)name type:(uint32_t)type kr:(kern_return_t *)outKr {
    *outKr = kIOReturnNoDevice;
    CFMutableDictionaryRef m = IOServiceMatching(name);
    if (!m) return 0;
    io_service_t svc = IOServiceGetMatchingService(kIOMainPortDefault, m);
    if (!svc) return 0;
    io_connect_t conn = 0;
    *outKr = IOServiceOpen(svc, mach_task_self(), type, &conn);
    IOObjectRelease(svc);
    if (*outKr != KERN_SUCCESS) return 0;
    return conn;
}

/// v4: power + register in the SAME tap. A successful CoreML predict makes
/// this pid an ANE client and powers the engine; DeviceOpen is then called
/// immediately in the same process.
+ (BOOL)wakeANE:(NSMutableString *)out {
    NSURL *url = [NSBundle.mainBundle URLForResource:@"simple_1in1out"
                                       withExtension:@"mlmodelc"];
    if (!url) {
        [out appendString:@"  [wake] simple_1in1out.mlmodelc missing\n"];
        return NO;
    }
    NSError *err = nil;
    MLModelConfiguration *cfg = [MLModelConfiguration new];
    cfg.computeUnits = MLComputeUnitsCPUAndNeuralEngine;
    MLModel *m = [MLModel modelWithContentsOfURL:url configuration:cfg error:&err];
    if (!m) {
        [out appendFormat:@"  [wake] load failed: %@\n", err.localizedDescription];
        return NO;
    }
    NSString *name = m.modelDescription.inputDescriptionsByName.allKeys.firstObject;
    MLFeatureDescription *fd = name ? m.modelDescription.inputDescriptionsByName[name] : nil;
    MLMultiArray *arr = nil;
    if (fd.multiArrayConstraint) {
        arr = [[MLMultiArray alloc] initWithShape:fd.multiArrayConstraint.shape
                                         dataType:fd.multiArrayConstraint.dataType
                                            error:&err];
    }
    if (!arr || !name) {
        [out appendFormat:@"  [wake] feature array unavailable (%@)\n",
            fd ? @"no multiArrayConstraint" : @"no input description"];
        return NO;
    }
    MLDictionaryFeatureProvider *fp =
        [[MLDictionaryFeatureProvider alloc] initWithDictionary:@{name: arr} error:&err];
    if (!fp) {
        [out appendFormat:@"  [wake] provider failed: %@\n", err.localizedDescription];
        return NO;
    }
    NSDate *t0 = [NSDate date];
    id<MLFeatureProvider> pred = [m predictionFromFeatures:fp error:&err];
    double ms = -[t0 timeIntervalSinceNow] * 1000.0;
    [out appendFormat:@"  [wake] predict %@ in %.1f ms err=%@ (registers this pid + powers the ANE)\n",
        pred ? @"ok" : @"FAILED", ms,
        err ? err.localizedDescription : @"none"];
    return pred != nil;
}

/// v5: one sel0 call with configurable sizes + pid placement. Returns the kr
/// and logs the output bytes. Caller closes the connection.
+ (kern_return_t)callDeviceOpen:(io_connect_t)conn pid:(uint32_t)pid
                         inSz:(uint32_t)inSz outSz:(uint32_t)outSz
                          off:(uint32_t)off qword:(BOOL)qword qoff:(uint32_t)qoff
                            out:(NSMutableString *)log {
    if (inSz < 4) inSz = 4;
    if (inSz > 0x2000) inSz = 0x2000;
    if (outSz > 0x2000) outSz = 0x2000;
    uint8_t *in = calloc(1, inSz);
    uint8_t *ob = calloc(1, outSz ? outSz : 8);
    if (!in || !ob) { free(in); free(ob); return kIOReturnNoMemory; }
    if (pid != 0 && off + 4 <= inSz) {
        uint32_t p = pid;
        memcpy(in + off, &p, sizeof(p));
    }
    if (qword && qoff + 8 <= inSz) {
        uint64_t p = (uint64_t)pid;
        memcpy(in + qoff, &p, sizeof(p));
    }
    size_t osz = outSz;
    kern_return_t kr = IOConnectCallStructMethod(conn, 0, in, inSz, ob, &osz);
    const char *why = "";
    if (kr == 0) why = "  <-- DEVICEOPEN OK";
    else if (kr == 0xe00002f0) why = "  (lookup/registration miss; 24A435 = send path only)";
    else if (kr == 0xe00002e3) why = "  (NoPower: client FOUND, engine unpowered)";
    else if (kr == 0xe00002c2) why = "  (bad struct size)";
    else if (kr == 0xe00002e2) why = "  (NotPermitted: entitlement)";
    else if (kr == 0xe00002c7) why = "  (Unsupported)";
    [log appendFormat:@"      sel0 pid=%u @0x%02x in=0x%x out=0x%x kr=0x%x%s osz=%zu out=",
        pid, off, inSz, outSz, kr, why, osz];
    for (size_t i = 0; i < 32 && i < osz; i++) [log appendFormat:@"%02x", ob[i]];
    [log appendString:@"\n"];
    free(in); free(ob);
    return kr;
}

+ (NSString *)probeInline {
    NSMutableString *o = [NSMutableString string];
    uint32_t pid = (uint32_t)getpid();
    BOOL is27 = [[LabDeviceProfile osversion] hasPrefix:@"24"];
    uint32_t sz = is27 ? 0x88 : 0x68;   /* table-declared sizes are enforced exactly */
    NSArray<NSString *> *svcs = @[@"H11ANEIn", @"H1xANELoadBalancer"];
    for (NSString *svcName in svcs) {
        kern_return_t okr = 0;
        io_connect_t conn = [self openType:svcName.UTF8String type:1 kr:&okr];
        [o appendFormat:@"  [inline] open %@ type=1 kr=0x%x\n", svcName, okr];
        if (!conn) continue;
        [self callDeviceOpen:conn pid:0 inSz:sz outSz:sz off:0 qword:NO qoff:8 out:o];
        { uint32_t sc = 0; IOConnectCallScalarMethod(conn, 1, NULL, 0, NULL, &sc); }
        IOServiceClose(conn);
    }
    return o;
}

+ (NSString *)tap {
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"=== p151 session %@ BUILD %@ ===\n",
        LabLocalMilitaryNow(), P151_ANE_DEVICEOPEN_BUILD];
    [out appendString:[LabDeviceProfile identBlock]];

    [out appendFormat:@"  [knobsrc] %@\n",
        [self knobsFileText].length ? @"Documents/p151_knobs.txt"
                                    : @"pasteboard (prompt only when content exists)"];

    NSString *therm = @"?";
    switch (NSProcessInfo.processInfo.thermalState) {
        case NSProcessInfoThermalStateNominal: therm = @"nominal"; break;
        case NSProcessInfoThermalStateFair: therm = @"fair"; break;
        case NSProcessInfoThermalStateSerious: therm = @"serious"; break;
        case NSProcessInfoThermalStateCritical: therm = @"critical"; break;
        default: break;
    }
    [out appendFormat:@"  [thermal] %@ (ANE returns NoPower at serious/critical)\n", therm];

    uint32_t pid   = [self pidFromPasteboardOrDefault];
    BOOL is27 = [[LabDeviceProfile osversion] hasPrefix:@"24"];
    uint32_t defSz = is27 ? 0x88 : 0x68;  /* 23xx (26.x, incl. A12X iPad) = 0x68; 24xx (27.x) = 0x88 */
    uint32_t inSz  = [self knobUInt:@"p151_in" def:defSz];
    uint32_t outSz = [self knobUInt:@"p151_out" def:defSz];
    uint32_t off   = [self knobUInt:@"p151_off" def:0x00];
    uint32_t oneT  = [self knobUInt:@"p151_type" def:1];
    uint32_t sweep = [self knobUInt:@"p151_sweep" def:1];
    BOOL qword     = [self knobUInt:@"p151_qword" def:0] != 0;
    uint32_t qoff  = [self knobUInt:@"p151_qoff" def:8];
    uint32_t census = [self knobUInt:@"p151_census" def:1];
    uint32_t maxSel = [self knobUInt:@"p151_maxsel" def:0x40];

    [out appendFormat:@"  [knobs] pid=%u type=%u sweep=%u in=0x%x out=0x%x pid@0x%02x qword=%d qoff=0x%x census=%u maxsel=0x%x\n",
        pid, oneT, sweep, inSz, outSz, off, (int)qword, qoff, census, maxSel];
    [out appendString:@"  [note] 24A435 sel0 = 0x88/0x88, no pid read, success when AddClient has\n"
                       @"         out[0]==0; H1xANELoadBalancer t1/t4 = the 24A435 door (H11ANEIn all 2c7);\n"
                       @"         23F77 sel0 = 0x68/0x68, pid is log-only, 2f0 = client-list miss\n"];
    [out appendString:@"  [!] PANIC-POSSIBLE (v6: unknown LB selectors receive zero-filled structs;\n"
                       @"      census only, no send request, no program). One tap per force-quit.\n"];

    [self wakeANE:out];

    NSArray<NSString *> *svcs = @[@"H11ANEIn", @"H1xANELoadBalancer"];
    int opens = 0, zeros = 0;

    for (NSString *svcName in svcs) {
        uint32_t t0 = sweep ? 0 : oneT;
        uint32_t t1 = sweep ? 4 : oneT;
        for (uint32_t type = t0; type <= t1; type++) {
            kern_return_t okr = 0;
            io_connect_t conn = [self openType:svcName.UTF8String type:type kr:&okr];
            [out appendFormat:@"  [open] %@ type=%u kr=0x%x\n", svcName, type, okr];
            if (!conn) continue;
            opens++;
            kern_return_t kr = [self callDeviceOpen:conn pid:pid inSz:inSz outSz:outSz
                                                off:off qword:qword qoff:qoff out:out];
            if (kr == KERN_SUCCESS) zeros++;
            /* v6: on an ACCEPTED client, census the selectors before closing.
               Zero-filled structs only; sel0/sel1 skipped (already called). */
            if (kr == KERN_SUCCESS && census) {
                [self selCensus:conn svc:svcName type:type maxSel:maxSel
                             pid:pid baseSz:(inSz > outSz ? inSz : outSz) out:out];
            }
            {
                uint32_t sc = 0;
                kern_return_t ckr = IOConnectCallScalarMethod(conn, 1, NULL, 0, NULL, &sc);
                [out appendFormat:@"      sel1 DeviceClose kr=0x%x\n", ckr];
            }
            IOServiceClose(conn);
        }
    }
    [out appendFormat:@"  [res] opens=%d deviceOpen_success=%d\n", opens, zeros];
    [out appendFormat:@"  [verdict] %@\n",
        zeros ? @"DeviceOpen accepted (early-success or registered UC) — record the type"
              : (opens ? @"opened but DeviceOpen refused every type/size/pid slot"
                       : @"no DirectPath open on this boot")];
    [out appendFormat:@"=== p151 end %@ ===\n", LabLocalMilitaryNow()];
    return out;
}

@end
