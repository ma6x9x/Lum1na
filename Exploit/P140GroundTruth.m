//
//  P140GroundTruth.m — the MINI GROUND-TRUTH VERIFIER. p140.
//  Lum1na-Debug (P007 rig). iOS kernel research (Lum1na).
//
//  The 12-mini cross-ref, composed as a tool: on the Dopamine rig the
//  lane can legally pass kread32(kbase)==MH_MAGIC_64, which turns every
//  "2c2-blind" lane question into a kernel-READ question. Tonight's use:
//  p138's Route-D object — hold the md mach port, locate its kernel
//  object via mach_port_kobject, and READ the slots the op channel
//  would have answered (the +0x98 gate, the +0x34 u16 dmaref, and the
//  21-D50 MD twin-class slot +0x80). The FIELD# law (match by class +
//  instSize + vt slot index, never by KVA / never per-SKU VAs) is why
//  every read is labeled a candidate-slot class read, not a decoded pin.
//
//  HONESTY: hasKread flips ONLY on the kread32 receipt of this device's
//  own kernel. commitSlide never from heap−staticBase. No wrap ladder
//  here (p138 owns it); P140 is the read-verified twin, not the fuzzer.
//

#import "P140GroundTruth.h"
#import "LabDeviceProfile.h"
#import "LabLocalTime.h"
#import "LabBandit.h"
#import "P007KreadLane.h"
#import "P007Board.h"

#import <CoreFoundation/CoreFoundation.h>
#import <Foundation/Foundation.h>
#import <dlfcn.h>
#import <fcntl.h>
#import <mach/mach.h>
#import <stdint.h>
#import <stdio.h>
#import <string.h>
#import <stdlib.h>
#import <unistd.h>

#define P140_BUILD @"p140-groundtruth-v1"

typedef void *(*IOSurfaceCreate_t)(CFDictionaryRef);
typedef mach_port_t (*IOSurfaceCreateMachPort_t)(void *);

/* the p138 dict law: the 5-key IOSurface alloc shape */
static CFMutableDictionaryRef p140_surf_dict(void) {
    CFMutableDictionaryRef d = CFDictionaryCreateMutable(
        kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks);
    const int32_t vv[5] = { 256, 1, 4, 1024, 1024 };
    const char *kk[5] = { "IOSurfaceWidth", "IOSurfaceHeight",
        "IOSurfaceBytesPerElement", "IOSurfaceBytesPerRow",
        "IOSurfaceAllocSize" };
    for (int i = 0; i < 5; i++) {
        CFNumberRef num = CFNumberCreate(NULL, kCFNumberSInt32Type, &vv[i]);
        CFDictionarySetValue(d, (__bridge CFStringRef)
            [NSString stringWithUTF8String:kk[i]], num); CFRelease(num);
    }
    return d;
}

typedef kern_return_t (*MachPortKObject_t)(ipc_space_t task,
    mach_port_name_t name, unsigned *typep, mach_vm_address_t *addrp);

static NSMutableString *g_buf; static int g_fd = -1;
static void L(NSString *s) {
    if (!g_buf) return;
    NSString *o = [s hasSuffix:@"\n"] ? s : [s stringByAppendingString:@"\n"];
    [g_buf appendString:o];
    if (g_fd >= 0) { const char *p = o.UTF8String;
        if (p) { write(g_fd, p, strlen(p)); fcntl(g_fd, F_FULLFSYNC); } }
}
static void Lf(NSString *fmt, ...) { va_list a; va_start(a, fmt);
    NSString *l = [[NSString alloc] initWithFormat:fmt arguments:a]; va_end(a); L(l); }
static NSString *P140R(void) { NSString *r = [g_buf copy]; g_buf = nil; return r; }

static void p140_bandit(const char *outcome) {
    static const char *arms[1] = { "main" };
    LabBanditSeedRow sr = { "main", "ok", 0 };
    char attr[288];
    LabBanditRegister("p140", arms, 1, &sr, 0, "p140 groundtruth auto-learn",
                      "ok", "receipt", attr, sizeof attr);
    LabBanditRecord("p140", 0, outcome);
}

@implementation P140GroundTruth

+ (NSString *)tap {
    g_buf = [NSMutableString string];
    NSString *docs = [NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    g_fd = open([[docs stringByAppendingPathComponent:@"p140_groundtruth_log.txt"]
                 UTF8String], O_CREAT | O_TRUNC | O_WRONLY, 0644);

    Lf(@"=== p140 session %@ BUILD %@ ===", LabLocalMilitaryNow(), P140_BUILD);
    Lf(@"%@", [LabDeviceProfile identBlock]);
    L(@"[law] the mini cross-ref: a lane-live rig ANSWERS port-guessing");
    L(@"  lanes by kernel READ. mach_port_kobject = the userland locator");
    L(@"  (SKU-free); every read slot is labeled candidate-class (the");
    L(@"  FIELD# law — 23F77 pins never transfer to 21-D50).");
    L(@"[!] READ-ONLY: no ladder, no wrap path; kread only.");

    NSMutableString *dossier = [NSMutableString string];

    /* ---- Stage A: the RECIPT ---- */
    L(@"=== STAGE A: the KRW lane receipt ===");
    BOOL laneLive = P007LaneLive();
    const char *laneName = P007LaneName();
    uint64_t kb = laneLive ? P007LaneKbase() : 0;
    BOOL receipt = NO;
    if (laneLive && kb) {
        uint32_t magic = P007LaneKRead32(kb);
        receipt = (magic == 0xfeedfacfULL);
        Lf(@"  lane=%s live=%d kbase=%#llx kread32=%#x %@",
           laneName ? laneName : "?", laneLive,
           (unsigned long long)kb, magic,
           receipt ? @"RECEIPT: PASS (MH_MAGIC_64)" : @"(not the magic)");
        if (receipt) [dossier appendFormat:
            @"[receipt] lane=%s kbase=%#llx kread32(kbase)=feedfacf\n",
            laneName ? laneName : "?", (unsigned long long)kb];
    } else {
        L(@"  lane CLOSED (run the KRW churn first this boot; honest hold) —");
        L(@"  stages B read rows degrade to the locator-only law.");
    }

    /* ---- Stage B: the md OBJECT, read directly ---- */
    L(@"=== STAGE B: the iosurf md port → its kernel object, READ ===");
    void *iosf = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface",
                        RTLD_LAZY);
    IOSurfaceCreate_t sc = iosf ? dlsym(iosf, "IOSurfaceCreate") : NULL;
    IOSurfaceCreateMachPort_t mp = iosf ? dlsym(iosf, "IOSurfaceCreateMachPort")
                                        : NULL;
    MachPortKObject_t kobj = dlsym(RTLD_DEFAULT, "mach_port_kobject");
    if (!sc || !mp || !kobj) {
        L(@"[-] dlsym incomplete (create/machport/mach_port_kobject) — skip.");
        p140_bandit("nodlsym");
    } else {
        CFMutableDictionaryRef d = p140_surf_dict();
        void *surf = sc(d);
        CFRelease(d);
        mach_port_t mdport = surf ? mp(surf) : MACH_PORT_NULL;
        if (!mdport) {
            L(@"[-] md port FAILED (create/machport miss) — honest skip.");
            p140_bandit("noport");
        } else {
            unsigned ktype = 0; mach_vm_address_t kaddr = 0;
            kern_return_t kok = kobj(mach_task_self_, mdport, &ktype, &kaddr);
            Lf(@"  port=%#x (held); mach_port_kobject kr=0x%x type=%#x"
               @" kaddr=%#llx", mdport, (unsigned)kok, ktype,
               (unsigned long long)kaddr);
            if (kok != KERN_SUCCESS) {
                L(@"    the kobject locator REFUSED (hardened-port law on");
                L(@"    this train) — the hash locator = v2 (p090 ipc class).");
            } else if (!laneLive) {
                Lf(@"    OBJECT LOCATED at %#llx — no kernel read lane this",
                   (unsigned long long)kaddr);
                L(@"    boot: the locator law STILL ships (SKU-free hop).");
                [dossier appendFormat:
                    @"[md.locator] kobjtype=%#x kaddr=%#llx (locator only,"
                    @" lane closed)\n", ktype, kaddr];
            } else {
                /* the candidate slots — class reads, labeled per train law */
                uint32_t gate98  = P007LaneKRead32(kaddr + 0x98);
                uint16_t dmaref34 = (uint16_t)P007LaneKRead32(kaddr + 0x34);
                uint32_t mdTwin80 = P007LaneKRead64(kaddr + 0x80) >> 32;
                uint64_t twin64   = P007LaneKRead64(kaddr + 0x80);
                Lf(@"    READ (candidate-class, not decoded pins):");
                Lf(@"      [obj+0x98]  (23f77 gate law)   = %#x", gate98);
                Lf(@"      [obj+0x34]  (23f77 dmaref law) = %#x (u16)",
                   dmaref34);
                Lf(@"      [obj+0x80]  (21d50 MD twin law) = %#llxx", twin64);
                Lf(@"      [obj+0x80].hi32 = %#x", mdTwin80);
                [dossier appendFormat:
                    @"[md.obj] kr(kobject)=0x%x type=%#x kaddr=%#llx\n",
                    (unsigned)kok, ktype, (unsigned long long)kaddr];
                [dossier appendFormat:
                    @"[md.obj+0x98]=%#x [md.obj+0x34](u16)=%#x"
                    @" [md.obj+0x80]=%#llx\n",
                    gate98, dmaref34, (unsigned long long)twin64];
                L(@"    INTERPRET GUARD: p138's op-2 oracle read gate=0 via");
                L(@"    2c2 refusals; the direct read above RE-DECIDES that");
                    L(@"    row under the FIELD# twin law (0x98 is a 23F77");
                L(@"    pin — on 21-D50 the gate/dmaref slots may sit");
                L(@"    elsewhere; the +0x80 twin row is the 21-D50-class");
                L(@"    comparator). A nonzero count row next to a 2c2 op");
                L(@"    channel = the ops are GATED, not absent.");
            }
            mach_port_destroy(mach_task_self_, mdport);
            (void)surf;
        }
    }

    /* ---- Stage C: the offset ledger status (og-source law) ---- */
    L(@"=== STAGE C: the A14_21-D50 offset ledger, og-source cross-ref ===");
    L(@"  DERIVED (not yet read-verified; v2 = the inpcb walk):");
    L(@"    socket_usecount   0x24C  (og info.c darwin<23.4 branch,");
    L(@"                            byte-verified against the Dopamine");
    L(@"                            BaseBin tree on this Mac tonight)");
    L(@"    inpcb_icmp6filt   0x148  (og CS2_KOFF law, same)");
    L(@"    inpcb_socket      0x40   (og CS2_KOFF law, same)");
    L(@"    proc_pid          0x60   task_map 0x28 socket_proto 0x18");
    L(@"  LightSword law note: og poc.c reads inp_gencnt from");
    L(@"  __proc_info(PIDFILEPORTSOCKETINFO) blob+0x110 (with the");
    L(@"  \"check this offset per version\" caveat) — the v10 calib's");
    L(@"  inpcb+0x78 gencnt scan is a DIFFERENT law; reconcile before");
    L(@"  judging the 12-mini misses.");

    [dossier writeToFile:[docs stringByAppendingPathComponent:
        @"p140_groundtruth.txt"]
        atomically:YES encoding:NSUTF8StringEncoding error:nil];
    L(@"  dossier written: p140_groundtruth.txt.");
    p140_bandit(receipt ? "receipt-pass" : "receipt-hold");
    Lf(@"=== p140 end %@ ===", LabLocalMilitaryNow());
    return P140R();
}

@end