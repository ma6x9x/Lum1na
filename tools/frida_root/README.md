# frida_root — the 12-mini (21-D50 / Dopamine) root-lane instrument

Proven 2026-10-31 night (see notes: P007OpenOnly/NOTES_MINI_CROSSREF_21D50.md).

## Stack
- **ssh**: `iproxy <mac-port> 22` then `ssh root@localhost -p <mac-port>`
  (keyless, Dopamine; jbroot `/var/jb`; `sleep` = `/var/jb/usr/bin/sleep`).
- **frida**: 17.25 on both ends. Mac tools:
  `pip3 install --user --break-system-packages frida-tools`
  (CLI in `~/Library/Python/3.14/bin`, not on PATH).
- **Launch the app**: `dev.spawn("ma6x9x.P007OpenOnly.V467U8LP46")`
  (bundle-id string accepted; attaches suspended-at-entry).

## Driving
`python3 p140_run.py <script.js>` — frida-spawns a uid-0 host
(`/var/jb/usr/bin/sleep 300`), loads the script, prints `send()` rows,
detaches after 15 s.
`python3 p140_duo.py` — the two-host instrument: the APP session creates
the IOSurface + md mach port + `mach_port_kobject` locator; the ROOT
session runs the libkrw kread server; the driver crosses the kaddr.

## Scripts
- `p140_rootserver.js` — ROOT-host libkrw kread/kbase server
  (`krw_initializer(handlers{version,kbase,kread,...}); rpc read(kaddr,len)`).
- `p140_root.js` — the full root census: receipt +
  IOSurfaceCreate/CreateMachPort + mach_port_kobject + direct object reads
  + the op census (the p138 A/B) + the root ent echo (A, last).
- `p140_app.js` / `p140_app2.js` — the APP-host stages (uid 501; the
  same stages, the sandbox comparison; p140_app2 = lazy via rpc `run`).
- `p140_echo.js` — the ent-echo in ANY attached host (SpringBoard /
  app / spawned root) with the full typeid decoder
  (bool/null/num/str/arr + the OTHER-type rows).
- `p140_dbg.js` — the dlopen/dlsym stepwise debug (paths + dlerror law).
- `p140_root_iokit.js` — the IOSurfaceRoot UC open census from root.

## Frida-17 script gotchas (paid for)
- Static `Module.getExportByName` is gone: shim
  `Module.getGlobalExportByName(name)` first.
- `mach_task_self` = MACRO; resolve `mach_task_self_` and `.readU32()`.
- `kCFAllocatorDefault` and friends = const-pointer VARIABLES in CoreFoundation:
  pass `.readPointer()`'s value; the callbacks struct (`kCFTypeDictionaryKeyCallBacks`)
  passes as an ADDRESS.
- `SecTaskCopyValueForEntitlement` takes a CFStringRef (build via
  `CFStringCreateWithCString`), never a char*.
- libkrw ABI (libkrw_plugin.h): handlers = {version, kbase, kread, kwrite,
  kmalloc, kdealloc, kcall, physread, physwrite} — offsets 8/0x10/…/0x30.

## Laws landed with this instrument
1. Root receipt: `kread32(kbase)=0xfeedfacf` PASS from a uid-0 spawned
   host (kbase re-slides per boot).
2. `uid 0` does NOT un-strip entitlements — capability = trust-cache/CS
   identity; `platform-application` comes back as a typeid-21 OTHER
   object (present shape, decode pending).
3. libkrw loads + initializes INSIDE the free-signed app, kread = no-op:
   the jbserver mach-lookup dies under the app's sandbox profile.
4. `IOSurfaceCreate` works in-app under frida;
   `IOSurfaceCreateMachPort` access-violates in the frida-spawned context
   (AV tail `0x…f001300`, fixed-field read) — normal-launch isolate pending.
5. IOSurfaceRoot UC from root: type 0 = `2e2` EXCLUSIVE ACCESS (already
   held), types 1/2 = `2c7`.
