//
//  LabPanicSig.m — panic-PC ingest (the P123 anchor law, automated).
//  Lum1na / Lum1na-Debug. See LabPanicSig.h for the contract.
//

#import "LabPanicSig.h"
#import "LabBandit.h"
#import "LabRuntimeOffsets.h"  /* LabOffPins; the only VA source */

#import <Foundation/Foundation.h>
#import <fcntl.h>
#import <math.h>
#import <string.h>

/* proximity window: a captured PC within this distance of a pin is "the
   same object family" (the P123 band law, tightened by the anchor-claim
   history: bands misattributed from OOB-copy class kept near the pin) */
#define PANIC_SIG_WINDOW 0x4000ULL

void LabPanicSigDrain(void) {
    NSString *docs = [NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    NSString *f = [docs stringByAppendingPathComponent:@"panic_pc.txt"];
    if (![[NSFileManager defaultManager] fileExistsAtPath:f]) return;
    NSString *txt = [NSString stringWithContentsOfFile:f
                            encoding:NSUTF8StringEncoding error:nil];
    if (txt.length == 0) return;

    const LabOffPin *pins = NULL;
    int pinsN = LabOffPins(&pins);

    uint32_t hits = 0, misses = 0;
    for (NSString *ln in [txt componentsSeparatedByCharactersInSet:
                          [NSCharacterSet newlineCharacterSet]]) {
        NSString *s = [ln stringByTrimmingCharactersInSet:
                       [NSCharacterSet whitespaceAndNewlineCharacterSet]];
        if (s.length == 0 || ![s hasPrefix:@"0x"]) continue;
        uint64_t pc = 0;
        NSScanner *sc = [NSScanner scannerWithString:s];
        if (![sc scanHexLongLong:&pc]) continue;
        /* strip KASLR: a slid PC minus the leaked slide can't be derived
           here — rows pushed by tools/panic_pc.sh are either unslid or
           slide-adjusted Mac-side, so compare as-is against unslid pins */
        const char *nearTag = NULL;
        uint64_t bestD = PANIC_SIG_WINDOW, nearVa = 0;
        for (int i = 0; i < pinsN; i++) {
            if (!pins[i].va) continue;
            uint64_t d = (uint64_t)llabs((long long)pc - (long long)pins[i].va);
            if (d < bestD) { bestD = d; nearTag = pins[i].tag; nearVa = pins[i].va; }
        }
        char featK[2][24], featV[2][48];
        snprintf(featK[0], sizeof featK[0], "pc");
        snprintf(featV[0], sizeof featV[0], "0x%llx", (unsigned long long)pc);
        if (nearTag) {
            hits++;
            snprintf(featK[1], sizeof featK[1], "near");
            snprintf(featV[1], sizeof featV[1], "%s @0x%llx (d=0x%llx)",
                     nearTag, (unsigned long long)nearVa,
                     (unsigned long long)bestD);
            LabBanditFeat fe[2] = { { featK[0], featV[0] },
                                    { featK[1], featV[1] } };
            LabBanditRecordFeat("panic", 0, LABB_SIG_PANIC_VA, LABB_E_DEVICE,
                                fe, 2);
            LabBanditNote("panic", featV[1]);
        } else {
            misses++;
            LabBanditFeat fe[1] = { { featK[0], featV[0] } };
            LabBanditRecordFeat("panic", 0, "panic-miss", LABB_E_DEVICE,
                                fe, 1);
        }
    }
    if (![[NSFileManager defaultManager] removeItemAtPath:f error:nil]) {
        (void)[@"" writeToFile:f atomically:YES encoding:NSUTF8StringEncoding
                 error:nil];
    }
    /* one visible line lands in the NEXT tap's advisory via the advisor —
       nothing printed here; the ledger row IS the receipt */
    (void)hits; (void)misses;
}
