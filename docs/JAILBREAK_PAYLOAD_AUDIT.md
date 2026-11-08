# Jailbreak payload audit (2026-11-08)

What the app installs and injects after a passing KRW self-test.

## Basebin (installed to /var/jb/basebin from Resources/basebin/basebin.tar)

`launchdhook.dylib`, `systemhook.dylib`, `dyldhook_merge.arm64e.iOS15/16-17/18+.dylib`,
`watchdoghook.dylib`, `forkfix.dylib`, `libjailbreak.dylib`, `libchoma.dylib`,
`libxpf.dylib`, `rootlesshooks.dylib`, `fallback/CydiaSubstrate.framework`
(ElleKit fallback), `jbctl`, `opainject`, `hookd`, `dopamine`, `idownloadd`,
`boomerang`, `MachOMerger`, `LaunchDaemons/*.plist`, `basebin.tc`, `.version`.

`launchdhook` hooks launchd's `xpc_dictionary_get_value` and injects the
`basebin/LaunchDaemons` plists into the LaunchDaemons dictionary/paths, so a
launchd reload picks up `com.opa334.Dopamine.startup` (`jbctl internal startup`)
and the idownloadd plist. `systemhook` loads tweaks by dlopening
`/var/jb/usr/lib/TweakLoader.dylib` when tweak injection is enabled.

## Tweaks

`ak_installTweaks` now copies `Documents/tweaks/*.dylib|*.plist` to **both**
standard ElleKit locations:

- `/var/jb/Library/MobileSubstrate/DynamicLibraries/`
- `/var/jb/usr/lib/TweakInject/`

`Documents/tweaks` remains the source; bundle tweaks (Resources/tweaks) are
auto-copied there first. If `/var/jb/usr/lib/TweakLoader.dylib` is missing the
log says `TweakLoader MISSING (needs the ElleKit/bootstrap package)`; the
basebin tar does not contain TweakLoader.

## Bootstrap / Procursus gap

`ak_reportBootstrap` logs `dpkg`, `sbreload`, `ellekit` presence under
`/var/jb/usr`. These come from the Procursus bootstrap, not `basebin.tar`.
On the already-Dopamine-jailbroken 11/mini they exist. On a stock device:

- `dpkg -i Sileo/Zebra` HOLDs (no dpkg).
- `jbctl respring` falls back to `killall /usr/libexec/backboardd SIGTERM`
  internally, so a session respring still works after elevate; `sbreload` is
  only the preferred path.
- Tweak injection needs TweakLoader.dylib (ElleKit package).
- Persistence across reboot needs the dyld merge (`dopamine`/MachOMerger) and
  a bootstrap `/var/jb`; our app does not run the Dopamine installer.

## Entitlements

`Lum1na.entitlements` and the debug entitlements already carry the private
set: `platform-application`, `com.apple.private.security.no-sandbox`,
`no-container`, `com.apple.private.kernel.override-codesigning`,
`task_for_pid-allow`, `com.apple.system-task-ports`, the IOKit user-client
classes (IOGPU, IOSurface, AVE2, ANE, KeyStore, SEP), and the jailbreakd mach
lookup names. These only apply when the IPA is signed with them (ldid on a
jailbroken device, TrollStore, or a developer certificate); a free-account
signature strips them. No entitlement changes were made.

## Consistency

- `Exploit/ClearSwordCore` and the debug `ClearSword/cs2` copies share the
  gencnt fix, pass count, QoS `so_background_thread` trick, and socket-proto
  fix.
- `LabRuntimeOffsets`/`LabDeviceProfile` are synced between the main app and
  `P007OpenOnly`.
- The 22G100 traversal fields and `Lum1naFindSelfProcViaSocket` are main-app
  only (the debug app has no ELEVATE stage); `p156`/`p157` are debug-only.

## Bootstrap staging (session, testable now)

`tools/push_bootstrap.sh <UDID> <BUNDLE_ID>` downloads the Procursus
bootstrap, decompresses it on the Mac, and pushes `bootstrap.tar` into the
app's Documents. After elevate, `ak_installBootstrap` maps the tar's
`./var/jb/...` entries into the existing `/var/jb` (real dir or a Dopamine
preboot symlink), handling regular files, dirs, symlinks and hardlinks. That
gives `/var/jb/usr/bin/dpkg`, `sbreload`, `launchctl`, and the bootstrap
libraries for a session.

Opt-in persistence/dyld merge: create `Documents/lum1na_dopamine_activate`.
The app then copies `/var/jb/basebin/dopamine` to `/var/tmp/dopamine` and runs
`dopamine activate`, which performs update_var_jb_symlink / basebin gen
(dyldhook merge via MachOMerger) / trustcache / launchd hook / daemon load.
It can replace `/var/jb` with the preboot symlink, so it is opt-in; a failed
activation leaves the session bootstrap usable.

Still not supplied: the ElleKit package (`TweakLoader.dylib`). Install it via
Sileo/Zebra after dpkg works, or drop an `ellekit.deb` into Documents/pkgman.

## Full Chain CS2 panic (2026-11-08)

Solo CS2 lands KRW; Full Chain panicked at the CS2 stage. Fixes:

- AMFI UC 2/7 removed from the A13_22G100/A14_21D50 rows (23F77-only proof).
  The Full Chain now honestly SKIPs AMFI on those SKUs.
- Socket→thread→proc locator is opt-in (`Documents/lum1na_socket_locator`);
  default is the kobject locator, and the located proc is re-checked against
  getpid() before any write.
- `Lum1naCS2Core_Establish` has a process-level attempt guard: a second call
  in the same process cannot spray, even if the first failed.

Cross-app caveat: the boot guard is per container. ONE CS2 spray per boot
across Lum1na and Lum1na-Debug. If you run the debug `cs2` solo, reboot before
the main Full Chain, or run main KERNEL→Full Chain in the same process.
