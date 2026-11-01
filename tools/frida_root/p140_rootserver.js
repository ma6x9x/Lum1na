// p140_rootserver.js — the ROOT-host kread server (frida-spawned sleep,
// uid 0): rpc.exports read64/read32/read16 via libkrw-dopamine.
function sym(n) {
  if (Module.getGlobalExportByName) return Module.getGlobalExportByName(n);
  return Module.getExportByName(null, n);
}
var RTLD_NOW = 2;
var kreadFn = null, kbaseVal = 0;

(function () {
  var dlopen_ = new NativeFunction(sym("dlopen"), "pointer", ["pointer", "int"]);
  var dlsym_  = new NativeFunction(sym("dlsym"), "pointer", ["pointer", "pointer"]);
  var lib = dlopen_(Memory.allocUtf8String("/var/jb/usr/lib/libkrw/libkrw-dopamine.dylib"), RTLD_NOW);
  if (lib.isNull()) { send("[rootserver] libkrw load FAILED"); return; }
  var hInit = new NativeFunction(dlsym_(lib, Memory.allocUtf8String("krw_initializer")), "int", ["pointer"]);
  var h = Memory.alloc(9 * 8);
  var rk = hInit(h);
  if (rk !== 0) { send("[rootserver] krw_initializer rv=" + rk); return; }
  var kbaseFn = new NativeFunction(h.add(8).readPointer(), "int", ["pointer"]);
  kreadFn = h.add(0x10).readPointer();
  var kbOut = Memory.alloc(8);
  if (kbaseFn(kbOut) === 0) kbaseVal = kbOut.readU64();
  var kr32 = new NativeFunction(kreadFn, "int", ["ulong", "pointer", "ulong"]);
  var b4 = Memory.alloc(4);
  var k32 = kr32(kbaseVal, b4, 4);
  var magic = k32 === 0 ? b4.readU32() : 0;
  send("[rootserver] live kbase=0x" + kbaseVal.toString(16) + " kread32(kbase)=0x" +
    (magic >>> 0).toString(16) + (magic === 0xfeedfacf ? " RECEIPT PASS" : ""));
})();

rpc.exports = {
  read: function (kaddrHex, len) {
    if (!kreadFn) return ["no-lane", 0];
    var kr = new NativeFunction(kreadFn, "int", ["ulong", "pointer", "ulong"]);
    var b = Memory.alloc(len);
    var r = kr(ptr(kaddrHex), b, len);
    if (r !== 0) return ["kr" + r, 0];
    return ["ok", b.readU64().toString(16)];
  }
};