// p142_hammer.js — the re-enumeration race oracle (root host).
// Hammers IOServiceOpen type-0 on IOUSBDeviceInterface every 1.5 s for
// 60 tries; if ANY kr==0 lands, runs the bounded sel census + closes.
function sym(n) {
  if (Module.getGlobalExportByName) return Module.getGlobalExportByName(n);
  return Module.getExportByName(null, n);
}
var iokit = new NativeFunction(sym("dlopen"), "pointer", ["pointer", "int"])(
  Memory.allocUtf8String("/System/Library/Frameworks/IOKit.framework/IOKit"), 2);
function iok(n) {
  return new NativeFunction(
    new NativeFunction(sym("dlsym"), "pointer", ["pointer", "pointer"])(iokit, Memory.allocUtf8String(n)),
    "pointer", ["pointer"]);
}
var P = function (s) { send(s); };
function attempt(i) {
  var IOServiceMatching = new NativeFunction(
    new NativeFunction(sym("dlsym"), "pointer", ["pointer", "pointer"])(iokit, Memory.allocUtf8String("IOServiceMatching")),
    "pointer", ["pointer"]);
  var IOServiceGetMatchingService = new NativeFunction(
    new NativeFunction(sym("dlsym"), "pointer", ["pointer", "pointer"])(iokit, Memory.allocUtf8String("IOServiceGetMatchingService")),
    "uint32", ["uint32", "pointer"]);
  var IOServiceOpen = new NativeFunction(
    new NativeFunction(sym("dlsym"), "pointer", ["pointer", "pointer"])(iokit, Memory.allocUtf8String("IOServiceOpen")),
    "int", ["uint32", "uint", "uint", "pointer"]);
  var IOServiceClose = new NativeFunction(
    new NativeFunction(sym("dlsym"), "pointer", ["pointer", "pointer"])(iokit, Memory.allocUtf8String("IOServiceClose")),
    "int", ["uint32"]);
  var IOObjectRelease = new NativeFunction(
    new NativeFunction(sym("dlsym"), "pointer", ["pointer", "pointer"])(iokit, Memory.allocUtf8String("IOObjectRelease")),
    "int", ["uint32"]);
  var mts = sym("mach_task_self_").readU32();
  var conn = Memory.alloc(4);
  for (var i = 1; i <= 60; i++) {
    var svc = IOServiceGetMatchingService(0, IOServiceMatching(Memory.allocUtf8String("IOUSBDeviceInterface")));
    if (svc === 0 || svc >= 0xffffff00) { P("[" + i + "] svc gone"); }
    else {
      var okr = IOServiceOpen(svc, mts, 0, conn);
      P("[" + i + "] open kr=0x" + (okr >>> 0).toString(16) + " conn=0x" + conn.readU32().toString(16));
      if (okr === 0) {
        P("    *** THE OPEN LANED — running the sel census ***");
        var out4 = Memory.alloc(32); var nOut = Memory.alloc(4);
        var callM = new NativeFunction(
          new NativeFunction(sym("dlsym"), "pointer", ["pointer", "pointer"])(iokit, Memory.allocUtf8String("IOConnectCallMethod")),
          "int", ["uint", "uint", "pointer", "uint", "pointer", "ulong", "pointer", "pointer", "pointer", "pointer"]);
        for (var s = 0; s <= 15; s++) {
          nOut.writeU32(4); out4.writeU64(0);
          var kr = callM(conn.readU32(), s, ptr(0), 0, ptr(0), 0, out4, nOut, Memory.alloc(8), Memory.alloc(4));
          P("      sel " + s + " kr=0x" + (kr >>> 0).toString(16) + " out0=0x" + out4.readU64().toString(16));
        }
        IOServiceClose(conn.readU32());
      }
      IOObjectRelease(svc);
    }
    if (i < 60) { setTimeout(function () { attempt(i + 1); }, 1500); }
  }
}
attempt(1);