# Signed GitHub IPA for the debug app (development profile + app group)

The `build-debug` job can produce **`Lum1na-Debug-signed-ipa`** when the four
repository secrets below are present. It signs `ma6x9x.P007OpenOnly` with
`P007OpenOnly.free.entitlements` (app group + get-task-allow) and embeds a
development provisioning profile that must include:

- Bundle ID `ma6x9x.P007OpenOnly`
- App Group `group.com.Lum1naDebug`
- Your device UDIDs in `ProvisionedDevices`

If any of those is missing, the signing step fails fast with a clear error.

## What to export

### 1. Development certificate (.p12)

- **Xcode-created certificate** (free Personal Team or paid): Keychain Access
  → login → **My Certificates** → `Apple Development: <name> (<TEAMID>)` →
  right-click → **Export** → `.p12`, set a password. The private key must be
  included.
- **SideStore/AltStore certificate**: these apps manage a development
  certificate in their own keychain. Export is only usable if the app exposes
  the `.p12` and the private key. SideStore's own provisioning profile is for
  **SideStore's bundle ID**, not `ma6x9x.P007OpenOnly`, so it cannot sign this
  app. If SideStore can export the certificate and a profile it generated for
  the target app, use those; otherwise use Xcode/the developer portal.

### 2. Provisioning profile (.mobileprovision)

- The profile must be for **`ma6x9x.P007OpenOnly`** (or an explicit App ID that
  matches it; wildcard profiles cannot carry app groups).
- It must contain `group.com.Lum1naDebug` and your devices.
- Xcode-created profiles live in:
  `~/Library/MobileDevice/Provisioning Profiles/`
- Inspect one before uploading:

```bash
security cms -D -i profile.mobileprovision > /tmp/profile.plist
/usr/libexec/PlistBuddy -c "Print :Name" /tmp/profile.plist
/usr/libexec/PlistBuddy -c "Print :Entitlements:application-identifier" /tmp/profile.plist
/usr/libexec/PlistBuddy -c "Print :Entitlements:com.apple.security.application-groups" /tmp/profile.plist
/usr/libexec/PlistBuddy -c "Print :ProvisionedDevices" /tmp/profile.plist
```

If `application-groups` is absent or does not list `group.com.Lum1naDebug`,
the workflow will reject the profile.

A paid account profile lasts a year. A free Personal Team profile lasts
**7 days**; the signed IPA stops launching after expiry, so re-run the
workflow and reinstall weekly.

## Secrets

Add under **GitHub → repo → Settings → Secrets and variables → Actions**:

| Secret | Value |
|---|---|
| `DEBUG_P12_BASE64` | `base64 -i debug.p12 \| tr -d '\n' \| pbcopy` |
| `DEBUG_P12_PASSWORD` | the `.p12` export password |
| `DEBUG_PROFILE_BASE64` | `base64 -i profile.mobileprovision \| tr -d '\n' \| pbcopy` |
| `DEBUG_KEYCHAIN_PASSWORD` | any random string for the temporary CI keychain |

Never commit the `.p12`, the profile, or the passwords. The workflow imports
them into a temporary keychain on the runner and does not upload them.

## What the workflow does

1. Builds the unsigned debug app (Xcode 26.x on `macos-26`).
2. ldid-signs the unsigned artifact with the free entitlements (always).
3. If the secrets are set: imports the `.p12`, installs the profile, verifies
   the profile's App ID and app group, copies `embedded.mobileprovision`,
   signs nested frameworks/dylibs, signs the app with
   `P007OpenOnly.free.entitlements` plus the profile's
   `application-identifier`/team ID, verifies, and packages
   `Lum1na-Debug-signed.ipa`.
4. Uploads `Lum1na-Debug-signed-ipa` (7-day artifact retention) and, if
   secrets are absent, only the unsigned artifact.

## Install

A development-signed IPA installs without re-signing on a device whose UDID
is in the profile. Use Apple Configurator, Xcode Devices, ESign, or
Sideloadly's “install only” path. Do not re-sign it with a different profile
unless that profile also has the app group.

## SideStore note

SideStore is a **signing front-end**, not a portable profile export. Its own
profile is tied to SideStore's App ID. For this workflow you need a profile
for `ma6x9x.P007OpenOnly`; if SideStore generated one and lets you export it,
verify it with the commands above. Otherwise export the certificate from
Keychain and the profile from `~/Library/MobileDevice/Provisioning Profiles`.
