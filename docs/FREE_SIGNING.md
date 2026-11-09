# Free-team app-group signing test (P007 / p160)

The Xcode screenshot's failure is **not** the App Group alone: the
provisioning profile does not include the private entitlement set
(`platform-application`, `task_for_pid-allow`, `com.apple.private.*`,
`com.apple.security.exception.*`, `no-sandbox`, etc.). A free Personal Team
profile will never include those. They are for the ldid/Dopamine rigs and are
ignored on stock.

## What to do

1. Use the minimal file
   `P007OpenOnly/P007OpenOnly/P007OpenOnly.free.entitlements` for the free
   test build. It contains only:
   - `com.apple.security.application-groups = [group.com.Lum1naDebug]`
   - `get-task-allow = true`
2. In Xcode: target → **Build Settings → Code Signing Entitlements**, set the
   **Debug** configuration to
   `P007OpenOnly/P007OpenOnly.free.entitlements` (leave Release on the
   private file, or use a separate configuration).
3. In **Signing & Capabilities → App Groups**, keep only
   `group.com.Lum1naDebug` checked. Do **not** check the SideStore/AltStore
   groups; they belong to other teams and are not in your profile.
4. `Try Again`. Three outcomes:
   - Signing succeeds → the free profile contains the group. Install and run
     p160; the logs must show `[ent] app-group array: 1 id(s) — group...` and
     `[profile] app-group array: 1 id(s) — group...`, and the class-7 target
     line must show `open=1`.
   - Fails only on `com.apple.security.application-groups` → the free team
     cannot provision this group on this Xcode. Options: paid certificate,
     ESign/轻松签 with App Groups enabled, or Xcode 27 on Apple Silicon (the
     filza-wq free-team claim).
   - Fails on another private entitlement → the minimal file was not applied;
     check `CODE_SIGN_ENTITLEMENTS`.
5. The on-disk `P007OpenOnly.entitlements` currently still has
   `com.apple.security.application-groups = <integer>1</integer>`; Xcode's
   App Groups UI can show a checked group without writing the array. The file
   used by the build must contain the array. The `.free.entitlements` file is
   the safe test file; do not edit the private one.

## Why this matters

If the free profile carries `group.com.Lum1naDebug`, p160's class-7 escape
can run on the stock 12/17/XR/iPad without a paid account. If it does not,
the escape stays paid-profile/ldid-only on stock, as before.

## Reading the p160 log

The 2026-11-09 15:56 run on the 12 (23F77) shows:

```
[ent] no com.apple.security.application-groups
[profile] app-group array: 0 id(s)
[kernelcache] handle=-5 ... open=0 w=0 err=posix=1
[class2] miss ...
```

That is the signature, not the probe: the running app has **no app-group
entitlement**, and the embedded profile has **zero groups**. Class 7 cannot
run, class 13 is patched on 26.x, and class 2 returns ENOENT. The parent
fallback is opt-in and Bench27 measured `rename Library -> EPERM`; it is not
a substitute for the group.

**An app cannot add this entitlement to itself at runtime.** App Groups are
code-signing metadata read by the kernel at launch. A debugger or injector
(StikDebug, SideStore, a dylib) can add code at runtime but cannot add an
entitlement to the running signature. Only re-signing the IPA with a profile
that contains the group changes the answer.

## Do not

- Do not put SideStore/AltStore groups in our entitlements.
- Do not delete the private entitlements file; the JB builds use it.
- Do not expect `platform-application`/`no-sandbox` to be honored on a
  free-signed stock build; they are stripped or rejected.
