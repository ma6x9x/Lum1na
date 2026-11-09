# Bench27 / iOS 27 research integration (2026-11-09)

Source: `SKVLENT/iOS27-Research-Exploits` ("Bench27", iPhone18,1 / A19 Pro /
iOS 27.0.1 24A446, compared statically with 27.2 24B119). The repository has
**no license file**; it is read-only reference. We re-implement mechanisms and
credit the author; no code is vendored.

Its verdicts corroborate ours and close several lanes cleanly.

## What to take

### 1. Sandbox escape (direction 10) — proven shape, needs an App Group

Bench27 reached other apps' containers and the shared SystemGroups on 27.0.1
with the worse_query class-7 technique:

```
inside our App Group: remove Library/Caches
replace it with a symlink to the target
container_query class 7, part 3, group id, flags 0x8000000000
container_copy_sandbox_token -> sandbox_extension_consume
```

Measured there: 28 shared system groups reachable, R/W in foreign app
containers, MobileGestalt cache editable. Part 2 (`Library/Preferences`) also
works. Class 2/12/13 produced no token in every combination, and the class-2
fallback fails at `rename Library -> EPERM`. **An App Group entitlement is
required**; no no-entitlement variant worked.

This is exactly p160's lane. p160 now implements Bench27's shape:

- `p160_class7_try` replaces the group's `Library/Caches` (part 3) and then
  `Library/Preferences` (part 2) with the target symlink, queries class 7 with
  an empty domain, and tries flags `0x8000000000` then `0x8100000000`.
- A leaf symlink inside Caches is wrong: the daemon grants the part directory,
  not its children (this corrected our first class-7 attempt).
- Candidate groups still come from `Documents/p160_group.txt` and
  `group.<bundle-id>`, and `containerURLForSecurityApplicationGroupIdentifier:`
  is the provisioned-group check.

The blocker is the same on the stock 12/17: no provisioned app group. This is a
paid-profile or ldid/Dopamine-rig capability, not something a free Sideloadly
profile can grant. The app's `com.apple.security.application-groups` value is
still the malformed integer `1`; it must become an array of real group IDs and
the profile must carry them.

The MobileGestalt cache is at
`/private/var/containers/Shared/SystemGroup/systemgroup.com.apple.mobilegestaltcache/Library/Caches/com.apple.MobileGestalt.plist`
(11 087 bytes, `CacheExtra` with 84 opaque keys). Bench27's safety rule is
mandatory for us too: back up into Documents before any write, restore after,
and never touch `CacheUUID`.

### 2. IOHIDFamily 112515 — still open, build-specific

Their 27.2 fix adds `cmp w8, w9; b.ge` before a `smull x8, w8, #0x14`
indexed read (`index` from `[obj+8]+0x30`, array at `[obj+0x38]`, count at
`[obj+0x40]`, magic `" hid"`). Reachability was **not** demonstrated: the
multitouch user client refuses every open type.

Our scan of the 23F77 kernelcache for either immediate encoding of the `" hid"`
magic (`movz/movk`) found nothing, so 26.5's IOHIDFamily 2360.2.2 builds the
comparison differently. Next step is the mnemonic-profile diff of 23F77 vs a
fixed build (24B119) on IOHIDFamily, not a magic hunt.

### 3. Entitlement-free clients worth a probe

| Service | Bench27 result | Notes for us |
|---|---|---|
| `AppleM2ScalerCSCDriver` | opens all 4 types with no entitlement; needs a `VTPixelTransferSessionTransferImage` warm-up; property/read-back inert | a real fuzz surface, unclaimed on 26.5 |
| `AppleJPEGDriver` | opens all 4 types; every method gated by `com.apple.applejpegdriver.*` | client reach is free; dispatch table unknown |
| `AppleAVE2Driver` | NotPermitted for every type | matches our p157 `0xe00002e2` |
| `H11ANEIn` | every type `kIOReturnUnsupported`; daemons refuse XPC | matches our p151/p153 |

### 4. Other directions (not chain material)

- **IOSurface size validation**: a 4 GiB header region is accepted for a
  64 KiB surface, but only 64 KiB is mapped. Value defect, no expansion.
- **Metal GPU VA (same context)**: a shader `device` pointer reaches other GPU
  pages of the same context once they have been used; another process's
  buffers were not reached in their test. Pairs with our AGX-RW work, not a
  kernel primitive.
- **mediaplaybackd FigXPC**: full protocol reproduced; `cre8` without
  `ExtensionTokenData` NULL-derefs the daemon. DoS only.
- **fsgetpath path disclosure**: 235 container paths, contents denied. Useful
  as UUID input to other bugs, not data access.

## Sideloader (Tetherless)

`tetherlessios.com` is an on-device sideloader (free Apple ID or user
certificate, LocalDevVPN for the free route, pairing-file/on-device pairing,
tweak injection, resign). Its GitHub repo `pwnapplehat/TetherlessiOS` contains
**only the website** — no app source, no license. Copying the product
completely is therefore both impossible and not appropriate; we build a
clean-room equivalent with its own name and design.

Minimum viable route, in order of engineering cost:

1. **Custom certificate + OTA install** (no pairing, no VPN per the vendor):
   import a `.p12` + provisioning profile, sign an IPA (zsign/ldid-style
   signing), serve a manifest + IPA over a local HTTP listener, hand
   `itms-services://` to the system installer. This is the fastest path to a
   working install on stock iOS.
2. **Pairing-file import + host-assisted install**: reuse libimobiledevice
   semantics (AFC + `installation_proxy`) from a companion, as AltStore does.
3. **Free Apple ID on-device**: Anisette/GSa auth, 2FA, developer-portal
   profile creation, then the same OTA install. This is the hard one and
   handles the user's Apple ID credentials — Keychain only, never logged,
   never pushed. It also depends on Apple's private developer API and is
   ToS-sensitive.

Repo/CI constraint: a third Xcode project under the synchronized root is
swallowed as an implicit subproject (same reason Build IPA does
`rm -rf P007OpenOnly`). A new app needs its own folder, its own CI job, and an
explicit main-CI removal/exclusion — do not drop an `.xcodeproj` at the root.
