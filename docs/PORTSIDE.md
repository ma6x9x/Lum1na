# Portside — third Lum1na-family app (planning)

Goal: a clean, on-device **file manager + command environment** built on the
worse_query/class-7 sandbox escape. It is the userland counterpart to Lum1na:
it does not touch the kernel and does not replace the KRW chain.

## What the reference projects are

| Project | Contents | License | Reuse |
|---|---|---|---|
| `MchinaMd57764/filza-wq` | repackaged **Filza** IPA + injected `FilzaApplySandboxExt.dylib`; no source | none stated; Filza itself is TIGI proprietary | behavior/UX only — **do not copy the IPA or dylib** |
| `ztby/terminal_worse` | GPL-3.0 fork of **a-Shell 2.3.2** + worse_query + `env/` apt/dpkg/plugin layer; `src/TerminalSBX.m` | GPL-3.0 | source is usable only if Portside is GPL-3.0 and source-distributed; otherwise reimplement |
| `jailbreakdotparty/Erosion` | Swift toolbox on worse_query (file browser, MG, keypads, PosterBoard) | no LICENSE; worse_query/pathleak GPL-3.0 | logic/UX only |
| `forcequitOS/worse_query` | class-7 escape primitive | GPL-3.0 | mechanism is already reimplemented in p160; credit |

a-Shell's own source is BSD-2-Clause; build from its source, never from the
decrypted App Store IPA. Filza is proprietary; do not redistribute it.

## The key unknown: free Personal Team app groups

filza-wq's README claims that on **Xcode 27.0 a free Personal Team profile
(7 days) was issued with the App Groups entitlement**, and the escape worked
on-device. Historically free profiles cannot provision app groups. If the
claim holds on our setup, p160/Portside becomes usable on stock free-signed
devices. Test it first:

1. Give a test target a real array:
   `com.apple.security.application-groups = [group.com.ma6x9x.Portside]`.
2. Sign with the free Personal Team (Xcode 27) and install.
3. Run p160; the new log lines `[ent] app-group array: N id(s)` and
   `[profile] app-group array: N id(s)` show whether the entitlement survived
   and whether the profile carries the group. `containerURLForSecurityApplicationGroupIdentifier:`
   must return non-nil.
4. If it fails, the escape remains paid-profile/ldid-only on stock.

portside must also handle the group container appearing late at launch;
terminal_worse retries for ~1.5 s. Our p160 runs on tap, so it is less
sensitive, but a real app should retry.

## Architecture

- **SwiftUI app**, own bundle/team and `Portside` name; no Lum1na branding.
- **Escape engine** (clean-room p160 logic): class 7, part 3,
  symlink `Library/Caches` to the target, flags `0x8000000000` on 27.x /
  `0x800000000` on 26.x AppGroup targets, consume token, restore Caches.
  Group sources: `AppGroupIdentifier` Info.plist key, SecTask entitlement,
  embedded.mobileprovision, then a user knob.
- **Accessible roots** hub (as filza-wq): ConfigurationProfiles,
  MobileGestalt cache, System Data, AppGroup containers, own Documents.
  Every path outside a granted root redirects to the hub.
- **File browser**: list/read/write/rename/copy/delete, trash in
  `Documents/.Trash`, plist/text/hex viewers, bundle-ID naming from
  `MCMMetadataIdentifier`.
- **Commands**: `sbxhelp`, `sbx_status`, `sbx_remount`, `sbx_grant`,
  `sbx_release`, `sbx_ls/cat/cp/write/rm/hexdump`, `sbx_containers`,
  `sbx_id`, `sbx_sysgroups`, `sbx_probe`, `sbx_paths`, `neofetch`-style
  device receipt.
- **Plugin environment** (optional): apt/dpkg-like front-end for script and
  WASM packages. **No unsigned Mach-O execution on stock**; native binaries
  need a jailbreak. State this in the UI.
- **Sideloader**: out of scope for v1; a separate signing/installation
  feature (see the earlier Portside sideloader notes).

## Build / CI

- New `Portside/` folder with its own `.xcodeproj` and CI job
  (`Portside-unsigned-ipa`). The main IPA job uses a synchronized root that
  swallows nested projects, so it must `rm -rf Portside` (the same rule as
  `P007OpenOnly`).
- Entitlements live in `Portside/Portside.entitlements`; start with the
  app-group array and the free-profile set. Do not copy Lum1na's private
  entitlement list.
- Free profiles expire in 7 days; document re-signing.

## Phases

0. **Free-profile app-group test** (decides feasibility).
1. **Escape + file browser** (roots, read/write, trash, viewers).
2. **Commands + pathleak** (read-only enumeration, bundle IDs).
3. **Plugin environment** (scripts/WASM; apt/dpkg-like).
4. **Sideloader** (only if the chain/tooling warrants it).

## Licensing / naming

- If Portside includes terminal_worse code, Portside is **GPL-3.0** and must
  publish source. If the goal is a closed app, reimplement its logic.
- Do not copy Filza, a-Shell's IPA, or Erosion's source (no license).
- Credit worse_query (Taj C / forcequitOS), Erosion, terminal_worse,
  filza-wq, a-Shell and bench27 in the about screen.
