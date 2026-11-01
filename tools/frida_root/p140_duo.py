#!/usr/bin/env python3
"""p140_duo.py — the two-host instrument (12 mini, 21-D50 / Dopamine):
- the APP session (P007OpenOnly, uid mobile): IOSurfaceCreate +
  CreateMachPort + mach_port_kobject locator + the in-app op census
- the ROOT session (frida-spawned sleep, uid 0): libkrw kread server
Driver: locator kaddr from the app -> kread the p138 oracle slots from
the ROOT lane. Everything printed as p140 rows."""
import frida, time, sys

def relay(tag, m):
    if m["type"] == "send":
        print(m["payload"], flush=True)
    elif m["type"] == "error":
        print("[%-4s script-error] %s" % (tag, m.get("stack", str(m))), flush=True)

def main():
    dev = frida.get_usb_device(timeout=10)
    app_pid = None
    for p in dev.enumerate_processes():
        if "P007OpenOnly" in p.name:
            app_pid = p.pid
    if app_pid is None:
        print("[-] the P007 app is not running - open it and re-run"); return

    root_pid = dev.spawn(["/var/jb/usr/bin/sleep", "300"])
    root_s = dev.attach(root_pid)
    root_js = root_s.create_script(open("/tmp/p140_rootserver.js").read())
    root_js.on("message", lambda m: None)
    root_js.load()
    dev.resume(root_pid)
    print("=== root-host kread server up (pid %d) ===" % root_pid, flush=True)

    app_s = dev.attach(app_pid)
    app_js = app_s.create_script(open("/tmp/p140_app.js").read())
    app_js.on("message", lambda m: relay("app", m))
    app_js.load()
    print("=== app-host stage done (pid %d) ===" % app_pid, flush=True)

    found, ktype, kaddr = app_js.exports_sync.kobject_of()
    print("\n=== BRIDGE: app-located md object type=0x%s addr=0x%s (found=%s) ===" % (hex(ktype), kaddr, found), flush=True)
    src = root_js.exports_sync or None
    if found and kaddr:
        rows = []
        for off, ln, name in [(0x34, 4, "u16-slot/23F77 dmaref law"),
                              (0x38, 4, "next-qword"),
                              (0x80, 8, "21-D50 MD twin slot"),
                              (0x90, 8, "23F77 SysMemory MD slot"),
                              (0x98, 4, "23F77 gate law"),
                              (0x00, 8, "vt/metaclass head")]:
            stat, val = root_js.exports_sync.read(hex(kaddr + off)[2:], ln)
            print("    BRIDGE kread [obj+0x%x] %-26s = 0x%s (%s)" % (off, name, val, stat), flush=True)
        # post-census: is the port still live? re-run census from root lane? (ops belong to the app's port)
        print("=== p140 duo end ===", flush=True)
    else:
        print("[-] no located object; census only", flush=True)

    root_s.detach()
    app_s.detach()
    try: dev.kill(root_pid)
    except Exception: pass

if __name__ == "__main__":
    main()