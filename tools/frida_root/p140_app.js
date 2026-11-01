// p140_app.js — the APP-host script: identity, libkrw-attempt, IOSurface
// Create + MachPort + mach_port_kobject locator, then the op census.
// rpc.exports: kobjectOf() -> [type, kaddr] for the driver to kread
// via the ROOT host.
function P(s) { send(s); }
function sym(n) {
  if (Module.getGlobalExportByName) return Module.getGlobalExportByName(n);
  return Module.getExportByName(null, n);
}
var RTLD_NOW = 2, kCFNumberSInt32Type = 3;

var lastKobj = { type: 0, addr: 0, found: false };
var lastPort = 0;

function doStage() {
  var getuid = new NativeFunction(sym("getuid"), "uint", []);
  P("=== p140-app host: uid=" + getuid() + " ===");

  // B-test: CAN the sandboxed app dlopen libkrw?
  try {
    var dlopen_ = new NativeFunction(sym("dlopen"), "pointer", ["pointer", "int"]);
    var dlsym_  = new NativeFunction(sym("dlsym"), "pointer", ["pointer", "pointer"]);
    var lib = dlopen_(Memory.allocUtf8String("/var/jb/usr/lib/libkrw/libkrw-dopamine.dylib"), RTLD_NOW);
    if (!lib.isNull()) {
      var hInit = new NativeFunction(dlsym_(lib, Memory.allocUtf8String("krw_initializer")), "int", ["pointer"]);
      var h = Memory.alloc(9 * 8);
      var rk = hInit(h);
      P("[app] libkrw dlopen OK handle=" + lib + " krw_initializer rv=" + rk);
      if (rk === 0) {
        var kbaseFn = new NativeFunction(h.add(8).readPointer(), "int", ["pointer"]);
        var kreadFn = h.add(0x10).readPointer();
        var kbOut = Memory.alloc(8);
        var kbKr = kbaseFn(kbOut);
        if (kbKr === 0) {
          var kb = kbOut.readU64();
          var kr32 = new NativeFunction(kreadFn, "int", ["ulong", "pointer", "ulong"]);
          var b4 = Memory.alloc(4);
          var k32 = kr32(kb, b4, 4);
          var magic = k32 === 0 ? b4.readU32() : 0;
          P("[app] RECEIPT kbase=0x" + kb.toString(16) + " kread32=" + (magic >>> 0).toString(16) +
            (magic === 0xfeedfacf ? " -> KRW IN THE APP = the app-lane question ANSWERED" : ""));
        }
      }
    } else P("[app] dlopen libkrw FAILED (sandbox law for this signature) — the honest hold");
  } catch (e) { P("[B-ERR] " + e); }

  // C: the surface + locator (the app demonstrably creates these fine)
  try {
    var dlopen2 = new NativeFunction(sym("dlopen"), "pointer", ["pointer", "int"]);
    var dlsym2  = new NativeFunction(sym("dlsym"), "pointer", ["pointer", "pointer"]);
    var iosf  = dlopen2(Memory.allocUtf8String("/System/Library/Frameworks/IOSurface.framework/IOSurface"), RTLD_NOW);
    var iokit = dlopen2(Memory.allocUtf8String("/System/Library/Frameworks/IOKit.framework/IOKit"), RTLD_NOW);
    var IOSurfaceCreate = new NativeFunction(dlsym2(iosf, Memory.allocUtf8String("IOSurfaceCreate")), "pointer", ["pointer"]);
    var IOSurfaceCreateMachPort = new NativeFunction(dlsym2(iosf, Memory.allocUtf8String("IOSurfaceCreateMachPort")), "uint32", ["pointer"]);
    var kCFAllocatorDefault = sym("kCFAllocatorDefault").readPointer();
    var kcb = sym("kCFTypeDictionaryKeyCallBacks");
    var CFDictionaryCreateMutable = new NativeFunction(sym("CFDictionaryCreateMutable"), "pointer", ["pointer", "long", "pointer", "pointer"]);
    var mkCFStr = new NativeFunction(sym("CFStringCreateWithCString"), "pointer", ["pointer", "pointer", "uint"]);
    var CFNumberCreate = new NativeFunction(sym("CFNumberCreate"), "pointer", ["pointer", "long", "pointer"]);
    var CFDictionarySetValue = new NativeFunction(sym("CFDictionarySetValue"), "void", ["pointer", "pointer", "pointer"]);
    var d = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, kcb, kcb);
    var keysS = ["IOSurfaceWidth", "IOSurfaceHeight", "IOSurfaceBytesPerElement", "IOSurfaceBytesPerRow", "IOSurfaceAllocSize"];
    var vals = [256, 1, 4, 1024, 1024];
    for (var i = 0; i < 5; i++) {
      var s = mkCFStr(kCFAllocatorDefault, Memory.allocUtf8String(keysS[i]), 0);
      var num = Memory.alloc(4); num.writeS32(vals[i]);
      CFDictionarySetValue(d, s, CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt32Type, num));
    }
    var surf = IOSurfaceCreate(d);
    P("[C] IOSurfaceCreate -> " + surf);
    if (!surf.isNull()) {
      var mdport = IOSurfaceCreateMachPort(d);
      lastPort = mdport;
      P("[C] md port=0x" + (mdport >>> 0).toString(16));
      var selfPort = sym("mach_task_self_").readU32();
      var kobjFn = new NativeFunction(sym("mach_port_kobject"), "int", ["uint", "uint", "pointer", "pointer"]);
      var kt = Memory.alloc(4), ka = Memory.alloc(8);
      var kok = kobjFn(selfPort, mdport, kt, ka);
      P("[C] mach_port_kobject kr=0x" + (kok >>> 0).toString(16) + " type=0x" + kt.readU32().toString(16) +
        " kaddr=0x" + ka.readU64().toString(16));
      if (kok === 0) { lastKobj = { type: kt.readU32(), addr: ka.readU64(), found: true }; }

      var callM = new NativeFunction(dlsym2(iokit, Memory.allocUtf8String("IOConnectCallMethod")),
        "int", ["uint", "uint", "pointer", "uint", "pointer", "ulong", "pointer", "pointer", "pointer", "pointer"]);
      var out4 = Memory.alloc(32); var nOut = Memory.alloc(4);
      var ops = [0x01000000, 0x02000000, 0x03000000, 0x04000000, 0x05000000, 0x06000000];
      P("--- [C] op census IN-APP (the p138 comparison row) ---");
      for (var oi = 0; oi < ops.length; oi++) {
        nOut.writeU32(4);
        var kr = callM(mdport, ops[oi], ptr(0), 0, ptr(0), 0, out4, nOut, Memory.alloc(8), Memory.alloc(4));
        P("    op 0x" + ops[oi].toString(16) + " -> kr=0x" + (kr >>> 0).toString(16) + " out0=0x" + out4.readU64().toString(16));
        out4.writeU64(0);
      }
    }
  } catch (e) { P("[C-ERR] " + e); }
}

doStage();
rpc.exports = {
  kobjectOf: function () { return [lastKobj.found, lastKobj.type, lastKobj.addr.toString(16)]; }
};