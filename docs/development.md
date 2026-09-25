# Development

Record the device model, OS version/build, Xcode version, component tested, result, and recovery steps for each experiment.

Lab notes live in `~/Desktop/lumina_primitives/`. Start at `00_README.txt`, then `86_WEEK_HANDOFF.txt` and `87_EXTERNAL_CONTEXT_NOTES.txt`.

Agents: read `AGENTS.md` first. Do not break the IPA job (Xcode 16.4). Repo contents: `docs/REPO_MAP.md`.

## Devices

- Active: iPhone 12 family (`iPhone13,*`) A14, iOS 26.5 **23F77**
- Twin: iPad Pro 2018 (`iPad8,*`) A12X, iPadOS 26.6 **23G71**
- SKU is `hw.machine` + `kern.osversion`, not `UIDevice` “26.5”
- Runtime `LabOff()` always wins. Do not paste T8101 VAs onto T8020

## What is true

- This app is a research catalog + UI. Kernel read/write is **not** obtained
- `Lum1naKRW` `kread64` is a placeholder
- P009 PathB is F (stale GPU), not W
- PATCHSET “chain complete” after a sleep is a stub
- Ident first. TAP markers go to `p011_tap_log.txt` before invoke

## After a real kreadbuf (not before)

Dopamine 3.0.10 does not run on this SKU. Its BaseBin names (trustcache, jbserver, launchdhook, userspace reboot) are the post-KRW map, not a KRW.

A14 uses PPL. momentarius is A12/A13 after KRW. Do not copy it here.

## Open vs closed

A class stays **open** until the 23F77 binary shows the 27-era guard, or two different angles on this SKU both die with a named IPS/errno. P039 VT wall does not close AVE. JPEG dest-timeout does not close AppleJPEGDriver UAR. P053 hits=0 does not close NECP. P017 0 cd8 does not close 64788. See `88_GOLDMINE_26.5.txt` and `89_REOPEN_ONE_ANGLE.txt`.

## Do not

- Remaining UAF/OOB/race/phys_oob/gamed-wvek/CS contig
- Dopamine plist End bump
- Treat Nugget BookRestore as persist

