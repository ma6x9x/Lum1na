// p142_usb_oracle.js — the USB DEVICE-MODE reachability oracle (root host).
// IOServiceMatching("IOUSBDeviceInterface") -> IOServiceGetMatchingService ->
// IOServiceOpen type 0/1 -> if a connect lands: BOUNDED sel census 0..15
// (4 scalars out + 0x40 struct out, no inputs), then IOServiceClose +
// releases. One open per run; a USB wedge = the accepted reconnect risk.
function sym(n) {
  if (Module.getGlobalExportByName) return Module.getGlobalExportByName(n);
  return Module.getExportByName(null, n);
}
(function () {
  var P = function (s) { send(s); };
  var iokit = new NativeFunction(sym("dlopen"), "pointer", ["pointer", "int"])(
    Memory.allocUtf8String("/System/Library/Frameworks/IOKit.framework/IOKit"), 2);
  if (iokit.isNull()) { P("[-] iokit dlopen fail"); return; }
  function iokf(n) {
    return new NativeFunction(
      new NativeFunction(sym("dlsym"), "pointer", ["pointer", "pointer"])(iokit, Memory.allocUtf8String(n)),
      "pointer", ["pointer"]);
  }
  var IOServiceMatching = new NativeFunction(
    new NativeFunction(sym("dlsym"), "pointer", ["pointer", "pointer"])(iokit, Memory.allocUtf8String("IOServiceMatching")),
    "pointer", ["pointer"]);
  var IOServiceGetMatchingService = new NativeFunction(
    new NativeFunction(sym("dlsym"), "pointer", ["pointer", "pointer"])(iokit, Memory.allocUtf8String("IOServiceGetMatchingService")),
    "uint32", ["uint32", "pointer"]);
  var IOServiceOpen = new NativeFunction(
    new NativeFunction(sym("dlsym"), "pointer", ["pointer", "pointer"])(iokit, Memory.allocUtf8String("IOServiceOpen")),
    "int", ["uint32", "uint", "uint", "pointer"]);
  var IOObjectGetClass = new NativeFunction(
    new NativeFunction(sym("dlsym"), "pointer", ["pointer", "pointer"])(iokit, Memory.allocUtf8String("IOObjectGetClass")),
    "int", ["uint32", "pointer"]);
  var IOObjectRelease = new NativeFunction(
    new NativeFunction(sym("dlsym"), "pointer", ["pointer", "pointer"])(iokit, Memory.allocUtf8String("IOObjectRelease")),
    "int", ["uint32"]);
  var IOServiceClose = new NativeFunction(
    new NativeFunction(sym("dlsym"), "pointer", ["pointer", "pointer"])(iokit, Memory.allocUtf8String("IOServiceClose")),
    "int", ["uint32"]);
  var mts = sym("mach_task_self_").readU32();
  var uid = new NativeFunction(sym("getuid"), "uint", []);
  P("[oracle] uid=" + uid() + " — USB device-mode reachability (mini-first law) ===");

  // the service set: the family's own nub names
  var names = ["IOUSBDeviceInterface", "AppleUSBDeviceInterface"];
  names.forEach(function (nm) {
    var svc = IOServiceGetMatchingService(0, IOServiceMatching(Memory.allocUtf8String(nm)));
    if (svc === 0 || svc >= 0xffffff00) { P("    match '" + nm + "' -> NO SERVICE"); return; }
    var cls = Memory.alloc(0x80); var gkr = IOObjectGetClass(svc, cls);
    var clss = (gkr === 0 ? cls.readUtf8String() : "(getClass refused kr=0x" + (gkr >>> 0).toString(16) + ")");
    P("    match '" + nm + "' -> svc=0x" + (svc >>> 0).toString(16) + " class=" + clss);
    var conn = Memory.alloc(4);
    for (var t = 0; t < 2; t++) {
      var okr = IOServiceOpen(svc, mts, t, conn);
      P("      open type=" + t + " kr=0x" + (okr >>> 0).toString(16) + " conn=0x" + conn.readU32().toString(16));
      if (okr === 0) {
        var out4 = Memory.alloc(32); var nOut = Memory.alloc(4);
        var callM = new NativeFunction(
          new NativeFunction(sym("dlsym"), "pointer", ["pointer", "pointer"])(iokit, Memory.allocUtf8String("IOConnectCallMethod")),
          "int", ["uint", "uint", "pointer", "uint", "pointer", "ulong", "pointer", "pointer", "pointer", "pointer"]);
        for (var s = 0; s <= 15; s++) {
          nOut.writeU32(4); out4.writeU64(0);
          var kr = callM(conn.readU32(), s, ptr(0), 0, ptr(0), 0, out4, nOut, Memory.alloc(8), Memory.alloc(4));
          P("        sel " + s + " kr=0x" + (kr >>> 0).toString(16) + " out0=0x" + out4.readU64().toString(16));
          if (kr === 0xe00002c2) continue; // unsupported = the silent wall, keep sweeping
        }
        var ckr = IOServiceClose(conn.readU32());
        P("      IOServiceClose kr=0x" + (ckr >>> 0).toString(16));
      }
    }
    IOObjectRelease(svc);
  });
  P("=== oracle end ===");
})();