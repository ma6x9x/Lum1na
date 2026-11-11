# LaunchDaemons of the 17 (24A435/27.0) — Theory-D / P109 feed

Raw dump (on-device Daemons tool, 2026-11-11): [DAEMONS_17_24A435_launchdaemons.txt](DAEMONS_17_24A435_launchdaemons.txt).
These are the confirmed **on-device names** behind KRW_THEORY §10's daemon targets.
LaunchDaemon plist presence ≠ running — the P109 kr oracle is the only live
confirmation; this list feeds the kern.proc candidate set.

## ANE pid-borrow candidates (P109 first-tap feed, ranked)
| Daemon | Why it's first |
|---|---|
| `com.apple.aned` | the ANE managing daemon — by definition ANE-entitled; §10's name confirmed on-device |
| `com.apple.nesessionmanager` | Neural Engine Session Manager — session/entitlement broker |
| `com.apple.mlruntimed` / `com.apple.mlhostd` | CoreML runtime host — opens ANE client paths on inference |
| `com.apple.modelmanagerd` / `com.apple.modelcatalogd` | ML model load/catalog — ANE program loads route through them |
| `com.apple.siriinferenced` / `com.apple.corespeechd` / `com.apple.siriknowledged` | steady ANE inference users (likely long-lived ANE clients) |
| `com.apple.photoanalysisd` / `com.apple.mediaanalysisd` | batch ANE+AVE consumers |
| `com.apple.generativeexperiencesd` / `com.apple.intelligenceplatformd` / `com.apple.intelligenceflowd` / `com.apple.visualintelligenced` | the AI-feature cluster (27.x) — Apple Intelligence entitlements |

## Other lane-confirmed daemons
- `com.apple.videocodecd` — the AVE2 client (p110/p142, 84607-class, `task=videocodecd`).
- `com.apple.mobilegestalt.xpc` — the MG proxy; pairs with the
  `systemgroup.com.apple.mobilegestaltcache` cache (P116 dump path, the
  copy-write law).
- `com.apple.mobile.installd`, `com.apple.mobile.house_arrest` — the
  afc/house_arrest family our own `afcclient` flow sits on.
- `com.apple.gamepolicyd` — the ident-block GAME_MODE rows come from here.

## Class-7/P116 read feed (each `p116_path.txt` tap, read-only)
- `/System/Library/LaunchDaemons/com.apple.<daemon>.plist` — the plists
  themselves (Program/EnvironmentVariables) are the daemon inventory source;
  the Daemons tool already enumerates them.
- `/var/preferences/com.apple.*.plist` — one dir-level listing tap per SKU.

## P109 mechanics (next build after p151 v6)
1. `kern.proc` enumerate all pids from the app (known pattern — the p109 spec).
2. For each candidate above, feed the pid into the Stage-B request at
   `req+0x180`; the kernel validates **that pid's** entitlements (8739b14 law).
3. Oracle: `2e2/2f0/2e2` = not ANE-entitled (or not running); `kr=0` = a live
   ANE-entitled proc found → that's the deputy pid. No writes requested from
   this probe; bounded, read-oracle only.
