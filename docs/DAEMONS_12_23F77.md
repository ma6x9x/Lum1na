# LaunchDaemons of the 12 (23F77/26.5) — lane confirms + launchd-policy laws

On-device Daemons tool dump from the iPhone 13,2 (A14/23F77), 2026-11-11.
The raw list lives in the app's Documents export (`launchd_detail.txt`,
Tools v2); this doc records the lane deltas and the launchd laws. The 17's
raw dump is [DAEMONS_17_24A435_launchdaemons.txt](DAEMONS_17_24A435_launchdaemons.txt).

## P109 deputy family — CONFIRMED on BOTH SKUs
`aned`, `nesessionmanager`, `mlruntimed`, `mlhostd`, `modelmanagerd`,
`corespeechd`, `siriinferenced`, `sirittsd`, `speechmodeltrainingd`,
`photoanalysisd`, `mediaanalysisd` (+`.service`), `sensingpredictd`,
`generativeexperiencesd`, `intelligenceplatformd`, `intelligenceflowd`,
`visualintelligenced`, `mobilegestalt.xpc`, `videocodecd` — the whole
borrow pool predates 27.x, so P109 v1 can use the same name set on the
12 and the 17.

## Key deltas vs the 17 (24A435)
- **No `modelcatalogd` on 23F77** — a 27.x-only component; `modelmanagerd`
  carries the catalog role on 26.5.
- Camera ISP: `appleh16camerad` + `dietappleh16camerad` (A14) vs the 17's
  `appleh13camerad`/`dietappleh13camerad` + `applecamerad`.
- 23F77-only: `internal.ptdremoted` (internal trace relay — the 12's build
  is the A14 hunt train, still carrying internal daemons), `GSSCred`,
  `applekeystored`, `assistant_service`, `arkitd`, `realitycamerad`,
  `imageplaygroundd`, `weatherd`, `adid`, `diskimagespawner`, `mobilebackup2`,
  `amsaccountsd`, `mobile_diagnostics_relay`.
- 24A435-only: `deviceinterfaced`, `timesync.audioclocksyncd`,
  `jetsamproperties.D53g/D53p` (12 has the V54 class).

## RunAtLoad / KeepAlive — what they mean and how the lab uses them
- **RunAtLoad** — launchd starts the job when the bootstrap loads the plist
  (boot for /System daemons). Effect: the daemon's pid exists from boot →
  it is present in every Processes census → the **stable-pid** set for P109.
- **KeepAlive (bool)** — launchd reswawns the job whenever it exits,
  including after a crash. Two lab consequences:
  1. presence is effectively permanent (best borrow candidates), and
  2. the daemon is a **self-healing experiment target**: a probe that
     crashes it gets it back without a reboot — bounded, repeatable.
- **KeepAlive (dict)** — conditional respawn (SuccessfulExit/Sched/…);
  spawn timing is event-driven, so the pid may not exist until the trigger
  fires. For aned-class on-demand daemons: fire the trigger FIRST
  (e.g. the p151 wake predict) → then census the pid.
- **Lab laws this implies:**
  1. Prefer deputy pids that are RunAtLoad+KeepAlive for the borrow feed.
  2. On-demand deputies must be triggered before the census, else the
     honest answer is "not running" — not a negative result.
  3. Never kill or crash a non-KeepAlive daemon in an experiment — it stays
     dead until reboot and degrades the device for further taps.
  4. Tools v2's `launchd_detail.txt` export records these flags per daemon;
     cross them with the Processes census per-device to build the live
     deputy table used by P109.
