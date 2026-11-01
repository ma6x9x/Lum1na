// p140_dbg.js — B-only, stepwise, with dlerror between every step.
function P(s) { console.log(s); send(s); }
function sym(n) {
  if (Module.getGlobalExportByName) return Module.getGlobalExportByName(n);
  return Module.getExportByName(null, n);
}
var RTLD_NOW = 2;
var dlopen_ = new NativeFunction(sym("dlopen"), "pointer", ["pointer", "int"]);
var dlsym_ = new NativeFunction(sym("dlsym"), "pointer", ["pointer", "pointer"]);
var dlerror_ = new NativeFunction(sym("dlerror"), "pointer", []);
function dlerr() { var e = dlerror_(); return e.isNull() ? "(none)" : e.readUtf8String(); }

P("--- B-step: the paths on disk ---");
var access_ = new NativeFunction(sym("access"), "int", ["pointer", "int"]);
["/var/jb/usr/lib/libkrw/libkrw-dopamine.dylib", "/var/jb/usr/lib/libkrw.dylib",
 "/var/jb/usr/lib/libjailbreak.dylib"].forEach(function (p) {
  var a = Memory.allocUtf8String(p);
  P("    " + p + " access=" + access_(a, 0) + " " + dlerr());
});

P("--- B-step: dlopen each, print handle + dlerror + dlsym ---");
[["libkrw-dopamine", "/var/jb/usr/lib/libkrw/libkrw-dopamine.dylib", "krw_initializer"],
 ["libkrw.0", "/var/jb/usr/lib/libkrw.0.dylib", "krw_initializer"],
 ["libjailbreak", "/var/jb/usr/lib/libjailbreak.dylib", "jbclient_initialize_primitives"]].forEach(
function (row) {
  var h = dlopen_(Memory.allocUtf8String(row[1]), RTLD_NOW);
  P("    " + row[0] + " handle=" + h + " dlerror=" + dlerr());
  if (!h.isNull()) {
    var f = dlsym_(h, Memory.allocUtf8String(row[2]));
    P("    " + row[2] + " -> " + f + " " + dlerr());
  }
});

P("--- B-step: the primitives route via libjailbreak ---");
var lb = dlopen_(Memory.allocUtf8String("/var/jb/usr/lib/libjailbreak.dylib"), RTLD_NOW);
P("    libjailbreak handle=" + lb + " " + dlerr());
["jbclient_initialize_primitives", "_jbclient_task_self", "jbclient_kread",
 "jbclient_kwrite", "jbclient_kbase", "proc_find"].forEach(function (n) {
  var f = dlsym_(lb, Memory.allocUtf8String(n));
  P("    " + n + " -> " + f + " " + dlerr());
});
P("=== debug end ===");