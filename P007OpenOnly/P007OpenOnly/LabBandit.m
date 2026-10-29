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
#import <stdlib.h>
#import <string.h>
#import <sys/sysctl.h>
#import <time.h>

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

/* per-arm v2 EV numbers. Schema: arm dict holds flat keys
     "<class>:<outcome>" -> class-weighted count (device=1, emu=0.5,
     map=0.3 — the honest fractional evidence downweights), plus the
     legacy plain outcome keys (== device). n and mean come from those. */
static double labb_ev_weight(const char *cls) {
    if (!cls || !*cls)                                    return 1.0;
    if (strcmp(cls, LABB_E_EMU) == 0)                     return 0.5;
    if (strcmp(cls, LABB_E_MAP) == 0)                     return 0.3;
    return 1.0;                                             /* device/other */
}

static void labb_arm_stats(NSDictionary *arms, NSString *armName,
                           double *nOut, double *meanOut) {
    NSDictionary *a = arms[armName];
    double n = 0, reward = 0;
    if ([a isKindOfClass:[NSDictionary class]]) {
        for (NSString *k in a) {
            if (![a[k] isKindOfClass:[NSNumber class]]) continue;
            double c = [a[k] doubleValue];
            if (c <= 0) continue;
            double w = 1.0;
            NSRange colon = [k rangeOfString:@":"];
            if (colon.location != NSNotFound && colon.location > 0) {
                w = labb_ev_weight([[k substringToIndex:colon.location] UTF8String]);
                k = [k substringFromIndex:colon.location + 1];
            }
            double r = LabBanditReward(k.UTF8String);
            /* the crash cost = the reboot: only the crash/maf class goes
               negative (-0.25); MISS/MID keep their honest low rewards */
            double rEff = (r <= 0.001) ? -0.25 : r;
            n += c;
            reward += c * rEff;
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
    } else {
        /* v1.1 arm-merge law: a probe may ADD arms in a later build (p110 v2
           added the leakgate-on/leakgate-off arm pair). The first-seen ledger
           keeps its arm_order, so newly registered arms are APPENDED with
           zeroed counts (UCB1 explores them first) instead of being silently
           lost to the fresh-only seed path. Order-preserving; capped at
           LABB_MAX_ARMS so Pick/Scores' fixed stat buffers stay in range.
           Existing order rows are also normalized so every order entry has a
           backing counts dict. */
        NSMutableArray *order = labb_mut(dom[@"arm_order"],
                                         [NSMutableArray class],
                                         [NSMutableArray array]);
        dom[@"arm_order"] = order;
        NSMutableDictionary *armsDict = labb_mut(dom[@"arms"],
                                                 [NSMutableDictionary class],
                                                 [NSMutableDictionary dictionary]);
        dom[@"arms"] = armsDict;
        for (int i = 0; i < armCount && order.count < LABB_MAX_ARMS; i++) {
            NSString *nm = [NSString stringWithUTF8String:arms[i] ?: ""];
            if (nm.length == 0) continue;
            if ([order indexOfObject:nm] != NSNotFound) continue;
            if ([armsDict objectForKey:nm] != nil) continue;
            armsDict[nm] = [NSMutableDictionary dictionary];
            [order addObject:nm];
        }
        for (int i = 0; i < armCount && i < (int)order.count; i++) {
            NSString *nm = [NSString stringWithUTF8String:arms[i] ?: ""];
            if (nm.length == 0 || [order indexOfObject:nm] == NSNotFound) continue;
            if ([armsDict objectForKey:nm] == nil) armsDict[nm] = [NSMutableDictionary dictionary];
        }
        while (order.count > LABB_MAX_ARMS) [order removeLastObject];
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

static int labb_pick_impl(const char *domain, char *lineOut, int lineCap,
                          const char *label);

int LabBanditPick(const char *domain, char *lineOut, int lineCap) {
    return labb_pick_impl(domain, lineOut, lineCap, "bandit");
}

int LabBanditPick2(const char *domain, char *lineOut, int lineCap) {
    return labb_pick_impl(domain, lineOut, lineCap, "oracle");
}

/* v2 pick core: Thompson over the class-weighted Beta posterior (one
   draw per arm, crash-penalty inside rEff), with the boot-phase context:
   uptime < 10 min = flatten the posteriors (x0.35) = explore;
   uptime > 120 min = sharpen (x2.5) = exploit (the panic-cost law). */
static double labb_gamma_sample(double shape);
static double labb_beta_sample(double a, double b) {
    double g1 = labb_gamma_sample(a), g2 = labb_gamma_sample(b);
    return (g1 + g2) > 0 ? g1 / (g1 + g2) : 0.0;
}
/* Marsaglia-Tsang gamma (shape > 0); arc4random uniform [0,1) */
static double labb_gamma_sample(double shape) {
    double u = (double)arc4random() / 4294967296.0 + 1e-12;
    if (shape < 1.0)
        return labb_gamma_sample(shape + 1.0) * pow(u, 1.0 / shape);
    double d = shape - 1.0 / 3.0;
    double c = 1.0 / sqrt(9.0 * d);
    for (;;) {
        double u1 = (double)arc4random() / 4294967296.0 + 1e-12;
        double u2 = (double)arc4random() / 4294967296.0;
        double x = sqrt(-2.0 * log(u1)) * cos(2.0 * M_PI * u2);
        if (x <= -1.0 / c) continue;
        double v = pow(1.0 + c * x, 3.0);
        double u3 = (double)arc4random() / 4294967296.0;
        if (log(u3) < 0.5 * x * x + d * (1.0 - v + log(v)) && v > 0)
            return d * v;
    }
}

static int labb_pick_impl(const char *domain, char *lineOut, int lineCap,
                          const char *label) {
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
    if (n > LABB_MAX_ARMS) n = LABB_MAX_ARMS;
    if (n == 0) {
        labb_save_locked(doc);
        os_unfair_lock_unlock(&g_labbLock);
        if (lineOut && lineCap > 0)
            snprintf(lineOut, (size_t)lineCap, "%s: (empty domain) (Thompson)", label);
        return 0;
    }

    struct timeval bt; size_t bl = sizeof bt;
    int mib[2] = { CTL_KERN, KERN_BOOTTIME };
    double uptimeMin = -1.0;
    if (sysctl(mib, 2, &bt, &bl, NULL, 0) == 0)
        uptimeMin = difftime(time(NULL), bt.tv_sec) / 60.0;
    double ctxMul = 1.0;
    if (uptimeMin >= 0 && uptimeMin < 10.0)  ctxMul = 0.35;
    else if (uptimeMin > 120.0)              ctxMul = 2.5;

    double bestV = -1e300;
    for (int i = 0; i < n; i++) {
        if (labb_is_manual([(NSString *)order[i] UTF8String])) continue;
        double nn = 0, rr = 0;
        labb_arm_stats(arms, order[i], &nn, &rr);
        double pEff = rr < 0.0 ? 0.0 : (rr > 1.0 ? 1.0 : rr);
        double alpha = 1.0 + pEff * nn * ctxMul;
        double beta  = 1.0 + (1.0 - pEff) * nn * ctxMul;
        double d = labb_beta_sample(alpha, beta);
        if (d > bestV) { bestV = d; best = i; }
    }
    if (bestV == -1e300) best = 0;

    NSString *pick = order[best];
    dom[@"last_arm"] = pick;
    dom[@"round_open"] = @YES;
    dom[@"last_ctx_uptime_min"] = @(uptimeMin);
    NSMutableArray *h = labb_mut(dom[@"history"], [NSMutableArray class],
                                [NSMutableArray array]);
    dom[@"history"] = h;
    [h addObject:@{ @"t": LabLocalMilitaryNow() ?: @"?",
                    @"arm": pick, @"outcome": @"@pick" }];
    while (h.count > LABB_HIST_RING) [h removeObjectAtIndex:0];
    (void)labb_save_locked(doc);
    os_unfair_lock_unlock(&g_labbLock);

    if (lineOut && lineCap > 0)
        snprintf(lineOut, (size_t)lineCap, "%s: %s (Thompson, boot=%dm)", label,
                 pick.UTF8String, uptimeMin >= 0 ? (int)uptimeMin : -1);
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
    if (n > LABB_MAX_ARMS) n = LABB_MAX_ARMS;   /* fixed stat buffers (merge cap) */
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
/* ---- v2 additions: class-weighted record + the cross-domain plan ---- */

void LabBanditRecordE(const char *domain, int armIndex,
                      const char *outcome, const char *evidenceClass) {
    if (!domain || !*domain || !outcome || !*outcome) return;
    const char *arm = LabBanditArmName(domain, armIndex);
    if (!arm) return;
    double w = labb_ev_weight(evidenceClass ? evidenceClass : LABB_E_DEVICE);

    os_unfair_lock_lock(&g_labbLock);
    NSMutableDictionary *doc = labb_load();
    if (doc) {
        NSMutableDictionary *doms = labb_mut(doc[@"domains"],
                                             [NSMutableDictionary class],
                                             [NSMutableDictionary dictionary]);
        doc[@"domains"] = doms;
        NSMutableDictionary *dom = labb_mut(doms[@(domain)],
                                            [NSMutableDictionary class],
                                            [NSMutableDictionary dictionary]);
        doms[@(domain)] = dom;
        if (dom) {
            NSString *key1 = [NSString stringWithFormat:@"%@:%@",
                @(evidenceClass ? evidenceClass : LABB_E_DEVICE), @(outcome)];
            NSMutableDictionary *arms = labb_mut(dom[@"arms"],
                                                 [NSMutableDictionary class],
                                                 [NSMutableDictionary dictionary]);
            dom[@"arms"] = arms;
            NSMutableDictionary *a = labb_mut(arms[@(arm)],
                                              [NSMutableDictionary class],
                                              [NSMutableDictionary dictionary]);
            arms[@(arm)] = a;
            double prev = [a[key1] isKindOfClass:[NSNumber class]]
                        ? [a[key1] doubleValue] : 0.0;
            a[key1] = @(prev + w);   /* the honest fractional evidence count */
            NSMutableArray *h = labb_mut(dom[@"history"],
                                         [NSMutableArray class],
                                         [NSMutableArray array]);
            dom[@"history"] = h;
            [h addObject:@{ @"t": LabLocalMilitaryNow() ?: @"?",
                            @"arm": @(arm), @"outcome": key1,
                            @"cls": @(evidenceClass ? evidenceClass : LABB_E_DEVICE) }];
            while (h.count > LABB_HIST_RING) [h removeObjectAtIndex:0];
            (void)labb_save_locked(doc);
        }
    }
    os_unfair_lock_unlock(&g_labbLock);
}

int LabBanditPlan(char *lineOut, int lineCap) {
    if (lineOut && lineCap > 0) lineOut[0] = '\0';
    os_unfair_lock_lock(&g_labbLock);
    NSMutableDictionary *doc = labb_load();
    NSDictionary *doms = doc[@"domains"];
    int used = 0;
    if ([doms isKindOfClass:[NSDictionary class]]) {
        NSMutableArray *rows = [NSMutableArray array];
        for (NSString *d in doms) {
            NSDictionary *dom = doms[d];
            if (![dom isKindOfClass:[NSDictionary class]]) continue;
            NSArray *order = dom[@"arm_order"];
            NSDictionary *arms = dom[@"arms"];
            if (![order isKindOfClass:[NSArray class]] ||
                ![arms isKindOfClass:[NSDictionary class]]) continue;
            double bestV = -1e300; NSString *bestArm = nil; double bestN = 0;
            for (NSString *an in order) {
                if (labb_is_manual(an.UTF8String)) continue;
                double nn = 0, rr = 0;
                labb_arm_stats(arms, an, &nn, &rr);
                /* EV with exploration: the untried arm still ranks by mean
                   but the plan text carries n so the operator sees trust */
                double ev = rr;
                if (nn > 0 && 1.0 / sqrt(nn) > 0) ev = rr * (1.0 - 0.35 / sqrt(nn));
                else                           ev = rr;     /* untried = prior */
                if (ev > bestV) { bestV = ev; bestArm = an; bestN = nn; }
            }
            if (bestArm) {
                [rows addObject:@{ @"domain": d, @"arm": bestArm,
                                   @"ev": @(bestV), @"n": @(bestN) }];
            }
        }
        [rows sortUsingComparator:^NSComparisonResult(NSDictionary *a, NSDictionary *b) {
            double ea = [a[@"ev"] doubleValue], eb = [b[@"ev"] doubleValue];
            return ea > eb ? NSOrderedAscending : (ea < eb ? NSOrderedDescending : NSOrderedSame);
        }];
        int cap = lineCap > 0 ? lineCap : 0;
        for (NSDictionary *r in rows) {
            char ln[192];
            int m = snprintf(ln, sizeof(ln), "plan: %-8s -> %-24s ev=%+.3f n=%.1f\n",
                             [r[@"domain"] UTF8String], [r[@"arm"] UTF8String],
                             [r[@"ev"] doubleValue], [r[@"n"] doubleValue]);
            if (m > 0 && used + m < cap - 1) {
                memcpy(lineOut + used, ln, (size_t)m);
                used += m;
            } else break;
        }
        if (lineOut && cap > 0) lineOut[used] = '\0';
    }
    os_unfair_lock_unlock(&g_labbLock);
    return used > 0;
}
