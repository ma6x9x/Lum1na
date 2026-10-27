//
//  LabBandit.m — shared UCB1 bandit harness (p099 v22 prototype extracted).
//  Lum1na-Debug (P007 rig). iOS kernel research (Lum1na).
//
//  One ledger: Documents/lab_bandit.json
//    { "reward_law": { "win":1.0, "crash":0.0, "miss":0.25, "mid":0.5,
//                      "classes": { "win":   ["door","claim-won","ok",
//                                   "fault-with-far"],
//                                   "crash": ["maf","family-b"],
//                                   "miss":  ["nofire","lost","window-lost",
//                                   "miss-adjacency","survived"],
//                                   "mid":   ["abort","fires"] } },
//      "domains": { "<probe>": { "seeded_from", "arms": {<arm>:{<outcome>:n}},
//                                "arm_order": [...], "history": [ last 24 ],
//                                "boot_id", "last_arm", "round_open",
//                                "last_outcome", "last_note" } }
//  Every mutation is written atomically then F_FULLFSYNC'd (the p099 ledger
//  law), so a post-panic reboot's ledger names the in-flight round.
//
//  UCB1 (Auer 2002) exactly as the p099 v22 prototype: arm score =
//  mean(reward) + sqrt(2 ln N / n_i); means come from the per-arm outcome
//  COUNTS x the shared reward table (history rows are the human-readable
//  ring, never the score source); an arm with n=0 explores first.
//

#import "LabBandit.h"

#import <Foundation/Foundation.h>
#import <fcntl.h>
#import <math.h>
#import <os/lock.h>
#import <stdio.h>
#import <string.h>
#import <sys/sysctl.h>

#import "LabLocalTime.h"

#pragma mark - shared reward law

double LabBanditReward(const char *outcome) {
    if (!outcome || !*outcome) return 0.25;             /* conservative miss */
    /* 1.0 WIN — the door/conversion/value-control receipts */
    if (!strcmp(outcome, "door"))             return 1.0;
    if (!strcmp(outcome, "claim-won"))        return 1.0;
    if (!strcmp(outcome, "ok"))               return 1.0;
    /* p112's (b): the value-control receipt IS the striking class the
       ledger learns (not a crash from the ledger's point of view). */
    if (!strcmp(outcome, "fault-with-far"))   return 1.0;
    /* 0.0 CRASH — the auth-poison / panic classes */
    if (!strcmp(outcome, "maf"))              return 0.0;
    if (!strcmp(outcome, "family-b"))         return 0.0;
    /* 0.5 MID — half-loss / landed-but-not-converted */
    if (!strcmp(outcome, "abort"))            return 0.5;
    if (!strcmp(outcome, "fires"))            return 0.5;
    /* 0.25 MISS — fired-and-lost classes (default) */
    return 0.25;
}

#pragma mark - ledger state

static os_unfair_lock g_labbLock = OS_UNFAIR_LOCK_INIT;
static NSMutableDictionary *g_labbDoc = nil;
static NSString *g_labbPath = nil;

static uint64_t labb_boot_id(void) {
    struct timeval tv; size_t sz = sizeof tv;
    if (sysctlbyname("kern.boottime", &tv, &sz, NULL, 0) == 0 && tv.tv_sec > 0)
        return (uint64_t)tv.tv_sec;
    return 0;
}

/* POSIX f_fullsync on the json after the atomic write — the p099 law. */
static BOOL labb_save_locked(NSMutableDictionary *doc) {
    if (!g_labbPath) return NO;
    NSData *out = [NSJSONSerialization dataWithJSONObject:doc
                                                  options:NSJSONWritingSortedKeys
                                                    error:nil];
    if (!out || ![out writeToFile:g_labbPath options:NSDataWritingAtomic error:nil])
        return NO;
    int fd = open(g_labbPath.fileSystemRepresentation, O_RDONLY);
    if (fd >= 0) { (void)fcntl(fd, F_FULLFSYNC); (void)close(fd); }
    return YES;
}

/* mutable-enforcement: a loaded json's nested collections are immutable —
   promote before every mutation (the p099 ledger law). */
static id labb_mut(id obj, Class cls, id makeNew) {
    if ([obj isKindOfClass:cls]) return obj;
    return obj ? [obj mutableCopy] : makeNew;
}

static NSMutableDictionary *labb_load(void) {
    if (g_labbDoc) return g_labbDoc;
    if (!g_labbPath) {
        NSString *docs = [NSSearchPathForDirectoriesInDomains(
            NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
        g_labbPath = [docs stringByAppendingPathComponent:@"lab_bandit.json"];
    }
    NSData *d = [NSData dataWithContentsOfFile:g_labbPath];
    id j = d ? [NSJSONSerialization JSONObjectWithData:d options:0 error:nil] : nil;
    if ([j isKindOfClass:[NSDictionary class]]) {
        g_labbDoc = [j mutableCopy];
    } else {
        g_labbDoc = [NSMutableDictionary dictionary];
    }
    NSMutableDictionary *doc = g_labbDoc;
    if (!doc[@"reward_law"]) {
        doc[@"reward_law"] = @{
            @"win":   @1.0, @"crash": @0.0, @"miss": @0.25, @"mid": @0.5,
            @"classes": @{
                @"win":   @[ @"door", @"claim-won", @"ok", @"fault-with-far" ],
                @"crash": @[ @"maf", @"family-b" ],
                @"miss":  @[ @"nofire", @"lost", @"window-lost",
                             @"miss-adjacency", @"survived" ],
                @"mid":   @[ @"abort", @"fires" ],
            },
        };
    }
    if (!doc[@"domains"]) doc[@"domains"] = [NSMutableDictionary dictionary];
    doc[@"domains"] = labb_mut(doc[@"domains"], [NSMutableDictionary class],
                               [NSMutableDictionary dictionary]);
    return doc;
}

static NSMutableDictionary *labb_domain(NSMutableDictionary *doc,
                                        const char *domain) {
    NSMutableDictionary *doms = labb_mut(doc[@"domains"],
                                         [NSMutableDictionary class],
                                         [NSMutableDictionary dictionary]);
    doc[@"domains"] = doms;
    NSString *key = [NSString stringWithUTF8String:domain];
    NSMutableDictionary *dom = labb_mut(doms[key],
                                        [NSMutableDictionary class],
                                        [NSMutableDictionary dictionary]);
    doms[key] = dom;
    return dom;
}

/* bump an arm's outcome count + append to the domain's history ring */
static void labb_bump(NSMutableDictionary *dom, NSString *armName,
                      NSString *outcome) {
    if (armName.length == 0 || outcome.length == 0) return;
    NSMutableDictionary *arms = labb_mut(dom[@"arms"],
                                        [NSMutableDictionary class],
                                        [NSMutableDictionary dictionary]);
    dom[@"arms"] = arms;
    NSMutableDictionary *a = labb_mut(arms[armName],
                                      [NSMutableDictionary class],
                                      [NSMutableDictionary dictionary]);
    arms[armName] = a;
    uint32_t c = [a[outcome] isKindOfClass:[NSNumber class]]
               ? [a[outcome] unsignedIntValue] + 1u : 1u;
    a[outcome] = @(c);
    NSMutableArray *h = labb_mut(dom[@"history"],
                                 [NSMutableArray class],
                                 [NSMutableArray array]);
    dom[@"history"] = h;
    [h addObject:@{ @"t": LabLocalMilitaryNow() ?: @"?",
                    @"arm": armName, @"outcome": outcome }];
    while (h.count > LABB_HIST_RING) [h removeObjectAtIndex:0];
}

/* per-arm UCB1 numbers (n and reward come from the outcome counts only) */
static void labb_arm_stats(NSDictionary *arms, NSString *armName,
                           double *nOut, double *meanOut) {
    NSDictionary *a = arms[armName];
    double n = 0, reward = 0;
    if ([a isKindOfClass:[NSDictionary class]]) {
        for (NSString *k in a) {
            if (![a[k] isKindOfClass:[NSNumber class]]) continue;
            double c = [a[k] doubleValue];
            if (c <= 0) continue;
            n += c;
            reward += c * LabBanditReward(k.UTF8String);
        }
    }
    *nOut = n;
    *meanOut = n > 0 ? reward / n : 0.0;
}

static BOOL labb_is_manual(const char *arm) {
    return arm && strncmp(arm, "manual", 6) == 0;
}

#pragma mark - API

int LabBanditRegister(const char *domain,
                      const char *const *arms, int armCount,
                      const LabBanditSeedRow *seeds, int seedCount,
                      const char *seededFrom,
                      const char *bootChangeOpen, const char *sameBootOpen,
                      char *attrLineOut, int attrLineCap) {
    if (attrLineOut && attrLineCap > 0) attrLineOut[0] = '\0';
    if (!domain || !*domain || !arms || armCount <= 0
        || armCount > LABB_MAX_ARMS) return -1;

    int ret = 0;
    os_unfair_lock_lock(&g_labbLock);
    NSMutableDictionary *doc = labb_load();
    NSMutableDictionary *dom = labb_domain(doc, domain);

    BOOL fresh = (dom[@"arms"] == nil);
    if (fresh) {
        /* order-preserving arm table + zeroed counts (honest: arms with no
           documented history seed at zero and UCB1 explores them first) */
        NSMutableDictionary *armOrder = [NSMutableDictionary dictionary];
        NSMutableArray *order = [NSMutableArray array];
        for (int i = 0; i < armCount; i++) {
            NSString *nm = [NSString stringWithUTF8String:arms[i] ?: ""];
            if (nm.length == 0) continue;
            armOrder[nm] = [NSMutableDictionary dictionary];
            [order addObject:nm];
        }
        dom[@"arm_order"] = order;
        dom[@"arms"] = armOrder;
        dom[@"seeded_from"] = (seededFrom && *seededFrom)
            ? [NSString stringWithUTF8String:seededFrom]
            : @"none documented (arms seeded at zero)";
        if (seeds && seedCount > 0) {
            /* documented-history priors ONLY (approximate counts, honestly
               labeled by seeded_from above) */
            for (int i = 0; i < seedCount; i++) {
                if (!seeds[i].arm || !seeds[i].outcome || seeds[i].count <= 0)
                    continue;
                NSMutableDictionary *a =
                    labb_mut(armOrder[[NSString stringWithUTF8String:seeds[i].arm]],
                             [NSMutableDictionary class],
                             [NSMutableDictionary dictionary]);
                armOrder[[NSString stringWithUTF8String:seeds[i].arm]] = a;
                a[[NSString stringWithUTF8String:seeds[i].outcome]] =
                    @((uint32_t)seeds[i].count);
            }
        }
        if (attrLineOut && attrLineCap > 0)
            snprintf(attrLineOut, (size_t)attrLineCap,
                     "ledger SEEDED (priors from documented history only): %s",
                     [(NSString *)dom[@"seeded_from"] UTF8String] ?: "(?)");
    }

    /* ---- dirty-boot attribution (the p099 v22 law, shared) ---- */
    uint64_t bootNow  = labb_boot_id();
    uint64_t bootPrev = [dom[@"boot_id"] isKindOfClass:[NSNumber class]]
                      ? [dom[@"boot_id"] unsignedLongLongValue] : 0;
    NSString *lastArm = [dom[@"last_arm"] isKindOfClass:[NSString class]]
                      ? dom[@"last_arm"] : nil;
    BOOL wasOpen = [dom[@"round_open"] boolValue];
    if (!fresh && lastArm.length > 0 && wasOpen) {
        BOOL bootChanged = (bootPrev != 0 && bootNow != 0 && bootPrev != bootNow);
        const char *oc = bootChanged ? (bootChangeOpen ?: "abort")
                                     : (sameBootOpen  ?: "abort");
        labb_bump(dom, lastArm, [NSString stringWithUTF8String:oc]);
        if (bootChanged) {
            ret = 1;
            if (attrLineOut && attrLineCap > 0)
                snprintf(attrLineOut, (size_t)attrLineCap,
                         "ATTRIBUTION: boot %llu -> %llu with the %s round "
                         "still open -> last session died mid-round -> %s "
                         "credited to %s",
                         (unsigned long long)bootPrev,
                         (unsigned long long)bootNow, lastArm.UTF8String, oc,
                         lastArm.UTF8String);
        } else {
            ret = 2;
            if (attrLineOut && attrLineCap > 0)
                snprintf(attrLineOut, (size_t)attrLineCap,
                         "ATTRIBUTION: %s round was open but the boot is "
                         "unchanged/unknown (%llu -> %llu) -> conservative %s "
                         "credited to %s",
                         lastArm.UTF8String,
                         (unsigned long long)bootPrev,
                         (unsigned long long)bootNow, oc, lastArm.UTF8String);
        }
    }
    dom[@"boot_id"] = @(bootNow);
    dom[@"round_open"] = @NO;

    labb_save_locked(doc);
    os_unfair_lock_unlock(&g_labbLock);
    return ret;
}

int LabBanditPick(const char *domain, char *lineOut, int lineCap) {
    if (lineOut && lineCap > 0) lineOut[0] = '\0';
    if (!domain || !*domain) return 0;

    int best = 0;
    os_unfair_lock_lock(&g_labbLock);
    NSMutableDictionary *doc = labb_load();
    NSMutableDictionary *dom = labb_domain(doc, domain);
    NSArray *order = labb_mut(dom[@"arm_order"], [NSMutableArray class],
                              [NSMutableArray array]);
    dom[@"arm_order"] = order;
    NSMutableDictionary *arms = labb_mut(dom[@"arms"],
                                         [NSMutableDictionary class],
                                         [NSMutableDictionary dictionary]);
    dom[@"arms"] = arms;
    int n = (int)order.count;
    if (n == 0) {
        labb_save_locked(doc);
        os_unfair_lock_unlock(&g_labbLock);
        if (lineOut && lineCap > 0)
            snprintf(lineOut, (size_t)lineCap, "bandit: (empty domain) (UCB1)");
        return 0;
    }

    double nArm[LABB_MAX_ARMS], mean[LABB_MAX_ARMS];
    double nTotal = 0;
    for (int i = 0; i < n; i++) {
        labb_arm_stats(arms, order[i], &nArm[i], &mean[i]);
        nTotal += nArm[i];
    }
    double lg = log(nTotal > 1.0 ? nTotal : 2.0);
    double bestV = -1e300;
    for (int i = 0; i < n; i++) {
        if (labb_is_manual([(NSString *)order[i] UTF8String])) continue;  /* never picked */
        double expl = nArm[i] > 0 ? sqrt(2.0 * lg / nArm[i]) : 1e9;
        double ucb = mean[i] + expl;
        if (ucb > bestV) { bestV = ucb; best = i; }
    }
    if (bestV == -1e300) best = 0;   /* all-manual domain degenerate case */

    NSString *pick = order[best];
    dom[@"last_arm"] = pick;
    dom[@"round_open"] = @YES;
    NSMutableArray *h = labb_mut(dom[@"history"], [NSMutableArray class],
                                 [NSMutableArray array]);
    dom[@"history"] = h;
    [h addObject:@{ @"t": LabLocalMilitaryNow() ?: @"?",
                    @"arm": pick, @"outcome": @"@pick" }];
    while (h.count > LABB_HIST_RING) [h removeObjectAtIndex:0];
    (void)labb_save_locked(doc);
    os_unfair_lock_unlock(&g_labbLock);

    if (lineOut && lineCap > 0)
        snprintf(lineOut, (size_t)lineCap, "bandit: %s (UCB1)", pick.UTF8String);
    return best;
}

const char *LabBanditArmName(const char *domain, int armIndex) {
    static __thread char nameBuf[64];
    nameBuf[0] = '\0';
    if (!domain || !*domain) return nameBuf;
    os_unfair_lock_lock(&g_labbLock);
    NSMutableDictionary *doc = labb_load();
    NSArray *order = labb_mut(labb_domain(doc, domain)[@"arm_order"],
                              [NSMutableArray class], [NSMutableArray array]);
    if (armIndex >= 0 && armIndex < (int)order.count) {
        NSString *nm = order[armIndex];
        strlcpy(nameBuf, nm.UTF8String ?: "", sizeof nameBuf);
    }
    os_unfair_lock_unlock(&g_labbLock);
    return nameBuf;
}

int LabBanditArmIndex(const char *domain, const char *armName) {
    if (!domain || !*domain || !armName || !*armName) return -1;
    int idx = -1;
    os_unfair_lock_lock(&g_labbLock);
    NSMutableDictionary *doc = labb_load();
    NSArray *order = labb_mut(labb_domain(doc, domain)[@"arm_order"],
                              [NSMutableArray class], [NSMutableArray array]);
    NSString *want = [NSString stringWithUTF8String:armName];
    for (int i = 0; i < (int)order.count; i++)
        if ([order[i] isKindOfClass:[NSString class]]
            && [order[i] isEqualToString:want]) { idx = i; break; }
    os_unfair_lock_unlock(&g_labbLock);
    return idx;
}

void LabBanditRecord(const char *domain, int armIndex, const char *outcome) {
    if (!domain || !*domain || !outcome || !*outcome) return;
    os_unfair_lock_lock(&g_labbLock);
    NSMutableDictionary *doc = labb_load();
    NSMutableDictionary *dom = labb_domain(doc, domain);
    NSArray *order = labb_mut(dom[@"arm_order"], [NSMutableArray class],
                              [NSMutableArray array]);
    if (armIndex >= 0 && armIndex < (int)order.count) {
        labb_bump(dom, order[armIndex],
                  [NSString stringWithUTF8String:outcome]);
        dom[@"last_outcome"] = [NSString stringWithUTF8String:outcome];
    }
    (void)labb_save_locked(doc);
    os_unfair_lock_unlock(&g_labbLock);
}

void LabBanditNote(const char *domain, const char *note) {
    if (!domain || !*domain) return;
    os_unfair_lock_lock(&g_labbLock);
    NSMutableDictionary *doc = labb_load();
    NSMutableDictionary *dom = labb_domain(doc, domain);
    NSMutableArray *h = labb_mut(dom[@"history"], [NSMutableArray class],
                                 [NSMutableArray array]);
    dom[@"history"] = h;
    dom[@"last_note"] = (note && *note)
        ? [NSString stringWithUTF8String:note] : [NSNull null];
    if (h.count && note && *note) {
        NSMutableDictionary *last =
            labb_mut(h.lastObject, [NSMutableDictionary class],
                     [NSMutableDictionary dictionary]);
        h[h.count - 1] = last;
        last[@"note"] = [NSString stringWithUTF8String:note];
    }
    (void)labb_save_locked(doc);
    os_unfair_lock_unlock(&g_labbLock);
}

void LabBanditRoundClose(const char *domain, const char *summaryOutcome) {
    if (!domain || !*domain) return;
    os_unfair_lock_lock(&g_labbLock);
    NSMutableDictionary *doc = labb_load();
    NSMutableDictionary *dom = labb_domain(doc, domain);
    dom[@"round_open"] = @NO;
    if (summaryOutcome && *summaryOutcome)
        dom[@"last_outcome"] = [NSString stringWithUTF8String:summaryOutcome];
    dom[@"boot_id"] = @(labb_boot_id());
    NSMutableArray *h = labb_mut(dom[@"history"], [NSMutableArray class],
                                 [NSMutableArray array]);
    dom[@"history"] = h;
    [h addObject:@{ @"t": LabLocalMilitaryNow() ?: @"?",
                    @"arm": dom[@"last_arm"] ?: @"?",
                    @"outcome": summaryOutcome && *summaryOutcome
                        ? [NSString stringWithUTF8String:summaryOutcome]
                        : @"@close" }];
    while (h.count > LABB_HIST_RING) [h removeObjectAtIndex:0];
    (void)labb_save_locked(doc);
    os_unfair_lock_unlock(&g_labbLock);
}

int LabBanditScores(const char *domain, char *out, int cap) {
    if (out && cap > 0) out[0] = '\0';
    if (!domain || !*domain || !out || cap <= 0) return -1;
    int used = 0;
    out[0] = '\0';
    os_unfair_lock_lock(&g_labbLock);
    NSMutableDictionary *doc = labb_load();
    NSMutableDictionary *dom = labb_domain(doc, domain);
    NSArray *order = labb_mut(dom[@"arm_order"], [NSMutableArray class],
                              [NSMutableArray array]);
    NSMutableDictionary *arms = labb_mut(dom[@"arms"],
                                         [NSMutableDictionary class],
                                         [NSMutableDictionary dictionary]);
    dom[@"arms"] = arms;
    double nArm[LABB_MAX_ARMS], mean[LABB_MAX_ARMS];
    double nTotal = 0;
    int n = (int)order.count;
    for (int i = 0; i < n; i++) {
        labb_arm_stats(arms, order[i], &nArm[i], &mean[i]);
        nTotal += nArm[i];
    }
    double lg = log(nTotal > 1.0 ? nTotal : 2.0);
    for (int i = 0; i < n; i++) {
        double expl = nArm[i] > 0 ? sqrt(2.0 * lg / nArm[i]) : 1e9;
        double ucb = mean[i] + expl;
        used += snprintf(out + used, (size_t)(cap - used), "%s%s n=%.0f mean=%.3f ucb=%.3f",
                         i ? " | " : "", [(NSString *)order[i] UTF8String] ?: "?",
                         nArm[i], mean[i], ucb);
        if (used >= cap) break;
    }
    os_unfair_lock_unlock(&g_labbLock);
    return used;
}