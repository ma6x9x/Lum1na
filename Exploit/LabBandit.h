//
//  LabBandit.h — shared UCB1 bandit harness for the P007 lab probes (Lum1na).
//
//  Generalizes the p099 v22 prototype bandit (P099AnePrewireGroom.m — the
//  UCB1 core, the kern.boottime dirty-boot attribution law, the atomic
//  fsync'd json, the seeded-priors honesty rule) into one unit so every
//  probe is a "domain" over ONE persisted ledger:
//
//      Documents/lab_bandit.json
//      { "reward_law": {...},
//        "domains": { "p099": {...}, "p110": {...}, "p112": {...},
//                     "p073": {...} } }
//
//  One shared reward law (LabBanditReward — the shared reward-class helper):
//      1.0  WIN   : door, claim-won, ok, fault-with-far
//      0.0  CRASH : maf, family-b
//      0.25 MISS  : nofire, lost, window-lost, miss-adjacency, survived
//      0.5  MID   : abort, fires
//      unknown    : 0.25 (conservative miss)
//  UCB1 exactly as the p099 prototype did it (Auer 2002: mean +
//  sqrt(2 ln N / n_i); unpicked arms explored first). No CoreML, no fancy
//  math.
//
//  Honest priors: ONLY documented history is seeded, via LabBanditSeedRow +
//  a seeded_from string (approximate counts are labeled approximate in the
//  string). Arms with no documented history seed at zero and UCB1 explores
//  them first.
//
//  Manual buckets: an arm whose name begins with "manual" records outcomes
//  but is NEVER picked — the manual-override dial laws (p073_conv.txt) land
//  there when the operator's shape matches no named arm.
//
//  Dirty-boot attribution law (the p099 v22 law, shared): Register loads the
//  ledger, stamps kern.boottime; a still-open round from the previous
//  session is credited to last_arm — the domain's "bootChangeOpen" outcome
//  on a PROVEN boottime change, its "sameBootOpen" outcome (conservative)
//  when the boot is unchanged or unreadable. Pick marks round_open;
//  per-round/per-sweep outcomes record against the tap's arm; RoundClose
//  closes. Every pick and record is fsync'd (atomic write + F_FULLFSYNC —
//  the p099 ledger law), so a post-panic reboot's ledger names the
//  in-flight round.
//
//  p099 itself stays on its in-probe prototype bandit (Documents/
//  p099_bandit.json, prototype reward law); the shared file's "p099" row is
//  a seed-only REFERENCE row (registered by P099AnePrewireGroom, no shared
//  pick, no shared record).
//
//  C-only API (probe .m files import this header; no Swift visibility —
//  not in the bridging header, like LabLocalTime.h).
//

#ifndef LabBandit_h
#define LabBandit_h

#define LABB_MAX_ARMS  8
#define LABB_HIST_RING 24

/* one documented-history prior row (approximate counts, honestly labeled) */
typedef struct {
    const char *arm;      /* arm name as registered                          */
    const char *outcome;  /* outcome key in the shared reward-class table    */
    int         count;    /* approximate documented count (>= 0)             */
} LabBanditSeedRow;

/* Load-or-seed the shared ledger for `domain`, run the dirty-boot
   attribution for the previous session, stamp boot_id.
   Returns: 1 = attribution on a PROVEN boot change, 2 = attribution with
   the boot unchanged/unknown, 0 = no open round, -1 = error.
   attrLineOut (optional) receives the human-readable attribution/seed line
   for the probe's own log. `arms` is a NULL-terminated-safe array of
   armCount C strings (order is preserved in the ledger and is the pick
   order). */
int    LabBanditRegister(const char *domain,
                         const char *const *arms, int armCount,
                         const LabBanditSeedRow *seeds, int seedCount,
                         const char *seededFrom,
                         const char *bootChangeOpen,   /* NULL -> "abort" */
                         const char *sameBootOpen,     /* NULL -> "abort" */
                         char *attrLineOut, int attrLineCap);

/* UCB1 pick (skips "manual*" buckets). Marks round_open and stamps
   last_arm (fsync'd). lineOut (optional) gets exactly
   "bandit: <pick> (UCB1)". Returns the arm index (0 on error). */
int    LabBanditPick(const char *domain, char *lineOut, int lineCap);

const char *LabBanditArmName(const char *domain, int armIndex);
int         LabBanditArmIndex(const char *domain, const char *armName);

/* Bump the arm's outcome count, append to the domain's history ring, fsync.
   Async-signal-unsafe: never call from a fault handler (the (b) catcher
   paths in p110/p112 die without recording; the shared attribution law
   credits the open round on the next tap). */
void   LabBanditRecord(const char *domain, int armIndex, const char *outcome);

/* Attach a note to the last history row of `domain` (the IN FLIGHT /
   value-pattern ledger data; e.g. p112's in-flight chosen-double bits).
   Pass NULL to clear. */
void   LabBanditNote(const char *domain, const char *note);

/* Close the open round (round_open = NO, last_outcome stamped from
   summaryOutcome when non-NULL, boot_id re-stamped). */
void   LabBanditRoundClose(const char *domain, const char *summaryOutcome);

/* the shared reward-class mapping helper (one reward law for all domains) */
double LabBanditReward(const char *outcome);

/* human-readable UCB1 score line: "<arm> n=%u mean=%.3f ucb=%.3f | ..." */
int    LabBanditScores(const char *domain, char *out, int cap);

#endif /* LabBandit_h */