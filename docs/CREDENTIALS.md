# In-app credentials (Signing pane) and the LocalDevVPN console path

Build: `P007OpenOnly` debug app. New files:

- `P007OpenOnly/Cinder/Credentials.swift` — models, profile/p12 parsers, Keychain
  vault, `SecTask` live check, `CredentialStore`.
- `P007OpenOnly/Cinder/CredentialPane.swift` — Files → **Signing** pane.
- `P007OpenOnly/Cinder/FilesPane.swift` — "Import files…" in the Files menu and a
  `Credentials` bookmark.
- `P007OpenOnly/DeviceConsole.swift` — IPv4 interface census for the console.

## What the pane does

1. **Import** `.p12` / `.pfx`, `.mobileprovision`, `.ipa` from the system file
   picker. Files are copied into `Documents/Credentials` (visible in the Files
   app because `UIFileSharingEnabled` and `LSSupportsOpeningDocumentsInPlace`
   are already set).
2. **Open `.p12`** with `SecPKCS12Import`. Shows the certificate common name,
   team ID (subject OU, falling back to the `(TEAMID)` suffix of the CN), expiry
   and SHA-256 fingerprint. The password is stored in the app's Keychain item
   (service `com.lum1na.signing`), never in Documents.
3. **Read `.mobileprovision`** through the same `<?xml … </plist>` slice p160
   uses. Shows name, UUID, team, App ID, application-identifier prefix, app
   groups, `get-task-allow`, platforms, expiry and provisioned devices.
4. **Select a certificate + profile pair** and run the pair check:
   - certificate present and not expired,
   - profile present and not expired,
   - certificate team == profile team,
   - profile App ID matches this bundle (wildcard noted),
   - `group.com.Lum1naDebug` present,
   - this device UDID in `ProvisionedDevices` (when `Documents/Pairing.plist`
     carries a UDID),
   - `get-task-allow`.
5. **Live row**: `SecTaskCopyValueForEntitlement` on the running process (same
   dlsym as p160) prints the actual `application-identifier` and app groups. This
   is the row that cannot be faked by a file in Documents.
6. **Copy handoff block** — paths, team, App ID, groups, expiry, fingerprint,
   ready to paste into the GitHub signed run or a terminal signer.

## What it cannot do

**It cannot grant the running app an app group.** App Groups are code-signing
metadata in the provisioning profile embedded in the `.app`; AMFI reads them at
launch. Importing, validating or selecting a profile inside the app does not
change this process's signature, and `SecTaskCopyValueForEntitlement` will keep
returning nil. The live row in the pane exists to make that impossible to
misread.

The pane is a credential **selector**, not a signer. It prepares and validates
the pair for one of these:

- the GitHub signed job (`docs/SIGNED_CI.md`),
- Xcode with the free/paid team,
- ESign / Sideloadly / SideStore "install only" with a matching profile.

Do not expect a p12 or profile stored in `Documents/Credentials` to make p160's
class-7 path run. Only re-signing and reinstalling with that profile does.

## Current 12 / 17 device state

The 2026-11-09 15:56 p160 log:

```
[ent] no com.apple.security.application-groups
[profile] app-group array: 0 id(s)
```

Both lines are red in the Signing pane until the installed `.app` is signed by a
profile that contains `group.com.Lum1naDebug`. The p12 certificates are valid to
October 2027; the missing piece is the profile for `ma6x9x.P007OpenOnly` with
the group and the device UDIDs.

## LocalDevVPN and the live console

`DeviceConsole` already implements the StikDebug-style path:

1. `Documents/Pairing.plist` (imported in Settings),
2. TCP to `127.0.0.1:62078`, then `10.7.0.1`, `10.7.1.1`, then the utun/LAN IPv4,
3. `QueryType` → `StartSession` → `EnableSessionSSL` → STARTTLS,
4. `StartService(com.apple.syslog_relay)` → TLS stream.

The console sheet now prints the IPv4 interface census and the exact candidate
order. A `utunN` entry with an address means LocalDevVPN is up; without one only
loopback is live.

### What it buys

- On-device `syslog_relay` without a Mac: sandbox/MCM/IOSurface/AVE2 kernel
  messages and our own probe lines in real time.
- Immediate evidence for whether p160 or a probe actually ran (and which branch
  it took) while the app is alive.
- The same lockdown session a future `installation_proxy` installer needs, so
  the pairing + VPN work is reusable for install/uninstall and debugger work.
- The persisted `Documents/device_console_log.txt` survives a stop/relaunch
  (append + `F_FULLFSYNC`).

### What it does not buy

- No app-group entitlement, no private entitlements, no KRW. It is a logging and
  transport path.
- Nothing for the current instant crash: if the process dies during launch,
  the relay client dies with it. Use Analytics Data / Xcode → Devices → View
  Device Logs, or the tail of the previous run's `device_console_log.txt`.
- The console cannot capture its own launch crash. It only helps after the app
  stays alive long enough to connect.

## Suggested order for the 12

1. Create/export a profile for `ma6x9x.P007OpenOnly` under team `GLVKP6RZ39`
   (kolby619) or `V467U8LP46` (kolbymaxx0) with App Groups enabled and
   `group.com.Lum1naDebug`, plus the device UDIDs.
2. Import the `.p12` and `.mobileprovision` in the Signing pane. The pair check
   should show certificate, profile, team, bundle, group and device green.
3. Re-sign/install (Xcode, ESign, Sideloadly install-only, or the GitHub signed
   job). The Signing pane's live row must turn green in the **reinstalled** app.
4. Only then run p160; expect:
   `[ent] app-group array: 1 id(s) — group.com.Lum1naDebug` and class-7
   `open=1`.
5. Keep the `.p12` password in Keychain if the same Mac/phone will sign again;
   otherwise delete the credential when done.
