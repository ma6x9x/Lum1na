// p140_root.js — the ROOT-lane ground truth (12 mini, 21-D50, Dopamine).
// B: libkrw-dopamine -> kbase -> kread32(kbase) receipt.
// C: IOSurfaceCreate + CreateMachPort -> mach_port_kobject -> DIRECT kread
//    of the p138 oracle slots -> the op census FROM ROOT (the A/B).
// A: ent echo from ROOT (p117 differential) — last, crash-isolated.
function P(s) { send(s); }
function sym(n) {
  if (Module.getGlobalExportByName) return Module.getGlobalExportByName(n);
  return Module.getExportByName(null, n);
}
var RTLD_NOW = 2, kCFNumberSInt32Type = 3;
var kbaseVal = 0;

function main() {
  var getuid = new NativeFunction(sym("getuid"), "uint", []);
  P("=== p140-root identity: uid=" + getuid() + " ===");

  // ---------- B: libkrw + receipt ----------
  var kreadFn = null;
  try {
    var dlopen_ = new NativeFunction(sym("dlopen"), "pointer", ["pointer", "int"]);
    var dlsym_  = new NativeFunction(sym("dlsym"), "pointer", ["pointer", "pointer"]);
    var lib = dlopen_(Memory.allocUtf8String("/var/jb/usr/lib/libkrw/libkrw-dopamine.dylib"), RTLD_NOW);
    P("[B] dlopen libkrw-dopamine -> " + lib);
    var hInit = new NativeFunction(dlsym_(lib, Memory.allocUtf8String("krw_initializer")), "int", ["pointer"]);
    var h = Memory.alloc(9 * 8);
    var rk = hInit(h);
    P("[B] krw_initializer rv=" + rk);
    if (rk === 0) {
      var kbaseFn = new NativeFunction(h.add(8).readPointer(), "int", ["pointer"]);
      kreadFn = h.add(0x10).readPointer();
      var kbOut = Memory.alloc(8);
      var kbKr = kbaseFn(kbOut);
      if (kbKr === 0) {
        kbaseVal = kbOut.readU64();
        P("[B] kbase=0x" + kbaseVal.toString(16));
        var kr32 = new NativeFunction(kreadFn, "int", ["ulong", "pointer", "ulong"]);
        var b4 = Memory.alloc(4);
        var k32 = kr32(kbaseVal, b4, 4);
        var magic = k32 === 0 ? b4.readU32() : 0;
        P("[B] RECEIPT kread32(kbase)=0x" + (magic >>> 0).toString(16) +
          (magic === 0xfeedfacf ? " -> MH_MAGIC_64 PASS" : " -> not the magic"));
      } else P("[B] kbase() kr=" + kbKr);
    }
  } catch (e) { P("[B-ERR] " + e); }

  // ---------- C: the md object census, FROM ROOT ----------
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
      var n = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt32Type, num);
      CFDictionarySetValue(d, s, n);
    }
    var surf = IOSurfaceCreate(d);
    P("[C] IOSurfaceCreate -> " + surf);
    if (!surf.isNull()) {
      var mdport = IOSurfaceCreateMachPort(d);
      P("[C] md port=0x" + (mdport >>> 0).toString(16));
      var selfPort = sym("mach_task_self_").readU32();
      var kobjFn = new NativeFunction(sym("mach_port_kobject"), "int", ["uint", "uint", "pointer", "pointer"]);
      var kt = Memory.alloc(4), ka = Memory.alloc(8);
      var kok = kobjFn(selfPort, mdport, kt, ka);
      P("[C] mach_port_kobject kr=0x" + (kok >>> 0).toString(16) + " type=0x" + kt.readU32().toString(16) + " kaddr=0x" + ka.readU64().toString(16));

      if (kreadFn && kok === 0) {
        var kr32b = new NativeFunction(kreadFn, "int", ["ulong", "pointer", "ulong"]);
        var o = ka.readU64();
        function r(off, len, fm) { var b = Memory.alloc(len); var rr = kr32b(o.add(off), b, len); return rr === 0 ? fm(b) : "kread-kr" + rr; }
        P("--- [C] DIRECT READ of the md object (candidate-class, FIELD# law) ---");
        P("    [obj+0x34] u16 (23F77 dmaref law)  : " + r(0x34, 4, function (b) { return "0x" + (b.readU32() >>> 0).toString(16); }));
        P("    [obj+0x38]:  " + r(0x38, 4, function (b) { return "0x" + (b.readU32() >>> 0).toString(16); }));
        P("    [obj+0x80] u64 (21-D50 MD twin)    : " + r(0x80, 8, function (b) { return "0x" + b.readU64().toString(16); }));
        P("    [obj+0x98] u32 (23F77 gate law)    : " + r(0x98, 4, function (b) { return "0x" + (b.readU32() >>> 0).toString(16); }));
        P("    [obj+0x90] u64 (23F77 SysMemoryMD) : " + r(0x90, 8, function (b) { return "0x" + b.readU64().toString(16); }));
        P("    [obj+0x00] u64 (vt/metaclass head) : " + r(0x00, 8, function (b) { return "0x" + b.readU64().toString(16); }));
      }

      var callM = new NativeFunction(dlsym2(iokit, Memory.allocUtf8String("IOConnectCallMethod")),
        "int", ["uint", "uint", "pointer", "uint", "pointer", "ulong", "pointer", "pointer", "pointer", "pointer"]);
      var out4 = Memory.alloc(32); var nOut = Memory.alloc(4);
      var ops = [0x01000000, 0x02000000, 0x03000000, 0x04000000, 0x05000000, 0x06000000];
      P("--- [C] op census FROM ROOT (p138's calls; the decisive A/B) ---");
      for (var oi = 0; oi < ops.length; oi++) {
        nOut.writeU32(4);
        var kr = callM(mdport, ops[oi], ptr(0), 0, ptr(0), 0, out4, nOut, Memory.alloc(8), Memory.alloc(4));
        P("    op 0x" + ops[oi].toString(16) + " -> kr=0x" + (kr >>> 0).toString(16) + " out0=0x" + out4.readU64().toString(16));
        out4.writeU64(0);
      }
      if (kreadFn && kok === 0) {
        var kr32c = new NativeFunction(kreadFn, "int", ["ulong", "pointer", "ulong"]);
        var b16 = Memory.alloc(8); kr32c(ka.readU64().add(0x34), b16, 8);
        P("    POST-census [obj+0x34..0x3b] = 0x" + b16.readU64().toString(16) + " (op-3 fired once)");
      }
    }
  } catch (e) { P("[C-ERR] " + e); }

  // ---------- A: ent echo from ROOT ----------
  try {
    var SecTaskCreateFromSelf = new NativeFunction(sym("SecTaskCreateFromSelf"), "pointer", ["pointer"]);
    var SecTaskCopyValueForEntitlement = new NativeFunction(sym("SecTaskCopyValueForEntitlement"), "pointer", ["pointer", "pointer", "pointer"]);
    var mkS = new NativeFunction(sym("CFStringCreateWithCString"), "pointer", ["pointer", "pointer", "uint"]);
    var getType = new NativeFunction(sym("CFGetTypeID"), "ulong", ["pointer"]);
    var boolType = new NativeFunction(sym("CFBooleanGetTypeID"), "ulong", []);
    var numType = new NativeFunction(sym("CFNumberGetTypeID"), "ulong", []);
    var strType = new NativeFunction(sym("CFStringGetTypeID"), "ulong", []);
    var arrType = new NativeFunction(sym("CFArrayGetTypeID"), "ulong", []);
    var numGet = new NativeFunction(sym("CFNumberGetValue"), "bool", ["pointer", "long", "pointer"]);
    var arrCount = new NativeFunction(sym("CFArrayGetCount"), "long", ["pointer"]);
    var taskA = SecTaskCreateFromSelf(ptr(0));
    P("--- [A] SecTask echo from ROOT (p117 differential) ---");
    if (taskA.isNull()) { P("    SecTask handle NULL - ent echo SKIPPED"); }
    else {
      var boolT = sym("kCFBooleanTrue"), boolF = sym("kCFBooleanFalse");
      var keys = ["application-groups", "platform-application", "get-task-allow",
        "no-sandbox", "com.apple.private.security.no-sandbox",
        "com.apple.security.exception.iokit-user-client-class",
        "com.apple.security.exception.mach-lookup.global-name",
        "private.IOKit", "com.apple.private.IOKit", "task_for_pid-allow"];
      for (var i = 0; i < keys.length; i++) {
        var ks = mkS(ptr(0), Memory.allocUtf8String(keys[i]), 0);
        var v = SecTaskCopyValueForEntitlement(taskA, ks, ptr(0));
        var shape = "NULL(stripped)";
        if (v && !v.isNull()) {
          var t = getType(v);
          if (t === boolType()) shape = "BOOL " + (v.equals(boolT) ? "true" : "false");
          else if (t === numType()) { var nn = Memory.alloc(4); numGet(v, 9, nn); shape = "NUMBER " + nn.readS32(); }
          else if (t === strType()) shape = "STRING(survived!)";
          else if (t === arrType()) shape = "ARRAY(count=" + arrCount(v) + ")";
          else shape = "OTHER typeid=" + t;
        }
        P("    " + keys[i] + ": " + shape);
      }
    }
  } catch (e) { P("[A-ERR] " + e); }

  P("=== p140-root end ===");
}
main();