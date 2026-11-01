// p140_root_iokit.js — ROOT host: the IOSurfaceRoot user-client open test
// (the IOKit route, no framework dict API). Law: root UC open from a
// uid-0 non-trust-cache process. Then, if opened, the p018-class surface
// lanes on the connect (bounded, read-only census).
function sym(n) {
  if (Module.getGlobalExportByName) return Module.getGlobalExportByName(n);
  return Module.getExportByName(null, n);
}
(function () {
  var getuid = new NativeFunction(sym("getuid"), "uint", []);
  send("[iokit-root] uid=" + getuid());
  var iokit = new NativeFunction(sym("dlopen"), "pointer", ["pointer", "int"])(
    Memory.allocUtf8String("/System/Library/Frameworks/IOKit.framework/IOKit"), 2);
  if (iokit.isNull()) { send("[-] iokit dlopen fail"); return; }
  function iok(n) { return new NativeFunction(
    new NativeFunction(sym("dlsym"), "pointer", ["pointer", "pointer"])(
      iokit, Memory.allocUtf8String(n)), "pointer", ["pointer"]); }
  var IOServiceMatching = new NativeFunction(
    new NativeFunction(sym("dlsym"), "pointer", ["pointer", "pointer"])(
      iokit, Memory.allocUtf8String("IOServiceMatching")),
    "pointer", ["pointer"]);
  var IOServiceGetMatchingService = new NativeFunction(
    new NativeFunction(sym("dlsym"), "pointer", ["pointer", "pointer"])(
      iokit, Memory.allocUtf8String("IOServiceGetMatchingService")),
    "uint32", ["uint32", "pointer"]);
  var IOServiceOpen = new NativeFunction(
    new NativeFunction(sym("dlsym"), "pointer", ["pointer", "pointer"])(
      iokit, Memory.allocUtf8String("IOServiceOpen")),
    "int", ["uint32", "uint", "uint", "pointer"]);
  var IOObjectGetClass = new NativeFunction(
    new NativeFunction(sym("dlsym"), "pointer", ["pointer", "pointer"])(
      iokit, Memory.allocUtf8String("IOObjectGetClass")),
    "int", ["uint32", "pointer"]);
  var IOObjectRelease = new NativeFunction(
    new NativeFunction(sym("dlsym"), "pointer", ["pointer", "pointer"])(
      iokit, Memory.allocUtf8String("IOObjectRelease")),
    "int", ["uint32"]);
  var mts = sym("mach_task_self_").readU32();

  var svc = IOServiceGetMatchingService(0, IOServiceMatching(Memory.allocUtf8String("IOSurfaceRoot")));
  var cls = Memory.alloc(0x80); var cn = svc ? IOObjectGetClass(svc, cls) : -1;
  send("[iokit-root] svc=0x" + (svc >>> 0).toString(16) + " class=" +
    (cn === 0 ? cls.readUtf8String() : "n/a"));
  if (svc !== 0 && svc < 0xffffff00) {
    var conn = Memory.alloc(4);
    for (var t = 0; t < 3; t++) {
      var okr = IOServiceOpen(svc, mts, t, conn);
      send("    IOServiceOpen type=" + t + " kr=0x" + (okr >>> 0).toString(16) + " conn=0x" + conn.readU32().toString(16));
      IOObjectRelease(svc);
      svc = IOServiceGetMatchingService(0, IOServiceMatching(Memory.allocUtf8String("IOSurfaceRoot")));
    }
    IOObjectRelease(svc);
  } else send("[-] no IOSurfaceRoot service found from root context");
  send("=== iokit-root end ===");
})();