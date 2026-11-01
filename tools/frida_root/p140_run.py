#!/usr/bin/env python3
"""Run a frida JS script in a frida-spawned ROOT process on the mini."""
import frida, time, sys

def on_message(m, data):
    if m["type"] == "send":
        print(m["payload"], flush=True)
    elif m["type"] == "error":
        print("[script-error] " + m.get("stack", str(m)), flush=True)

def main(js_path):
    dev = frida.get_usb_device(timeout=10)
    pid = dev.spawn(["/var/jb/usr/bin/sleep", "300"])
    session = dev.attach(pid)
    script = session.create_script(open(js_path).read())
    script.on("message", on_message)
    dev.resume(pid)
    script.load()
    time.sleep(15)
    print("=== driver: detach ===", flush=True)
    session.detach()
    try: dev.kill(pid)
    except Exception: pass

if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "/tmp/p140_dbg.js")