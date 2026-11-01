// p140_echo.js — the ent-echo in ANY attached host (platform-trust probe).
function sym(n) {
  if (Module.getGlobalExportByName) return Module.getGlobalExportByName(n);
  return Module.getExportByName(null, n);
}
var RTLD_NOW = 2;
(function () {
  var getuid = new NativeFunction(sym("getuid"), "uint", []);
  var geteuid = new NativeFunction(sym("geteuid"), "uint", []);
  send("=== p140-echo host: uid=" + getuid() + " euid=" + geteuid() + " ===");
  try {
    var SecTaskCopyValueForEntitlement = new NativeFunction(sym("SecTaskCopyValueForEntitlement"), "pointer", ["pointer", "pointer", "pointer"]);
    var SecTaskCreateFromSelf = new NativeFunction(sym("SecTaskCreateFromSelf"), "pointer", ["pointer"]);
    var mkS = new NativeFunction(sym("CFStringCreateWithCString"), "pointer", ["pointer", "pointer", "uint"]);
    var kCFAllocatorDefault = sym("kCFAllocatorDefault").readPointer();
    var task = SecTaskCreateFromSelf(ptr(0));
    if (task.isNull()) { send("    SecTask NULL - skip"); return; }
    var boolT = sym("kCFBooleanTrue"), boolF = sym("kCFBooleanFalse");
    var getType = new NativeFunction(sym("CFGetTypeID"), "ulong", ["pointer"]);
    var boolType = new NativeFunction(sym("CFBooleanGetTypeID"), "ulong", []);
    var nullType = new NativeFunction(sym("CFNullGetTypeID"), "ulong", []);
    var numType = new NativeFunction(sym("CFNumberGetTypeID"), "ulong", []);
    var strType = new NativeFunction(sym("CFStringGetTypeID"), "ulong", []);
    var arrType = new NativeFunction(sym("CFArrayGetTypeID"), "ulong", []);
    // decode tables
    send("    [typeid decoder] bool=" + boolType() + " null=" + nullType() + " num=" + numType() + " str=" + strType() + " arr=" + arrType());
    var numGet = new NativeFunction(sym("CFNumberGetValue"), "bool", ["pointer", "long", "pointer"]);
    var arrCount = new NativeFunction(sym("CFArrayGetCount"), "long", ["pointer"]);
    var keys = ["platform-application", "get-task-allow", "application-groups",
      "private.IOKit", "com.apple.private.IOKit",
      "iokit-user-access", "com.apple.private.memorystatus"
    ];
    for (var i = 0; i < keys.length; i++) {
      var ks = mkS(kCFAllocatorDefault, Memory.allocUtf8String(keys[i]), 0);
      var v = SecTaskCopyValueForEntitlement(task, ks, ptr(0));
      var shape = "NULL(absent)";
      if (v && !v.isNull()) {
        var t = getType(v);
        if (t === boolType()) shape = "BOOL " + (v.equals(boolT) ? "true" : "false");
        else if (t === nullType()) shape = "CFNULL(typed-empty!)";
        else if (t === numType()) { var nn = Memory.alloc(4); numGet(v, 9, nn); shape = "NUMBER " + nn.readS32(); }
        else if (t === strType()) shape = "STRING(survived)";
        else if (t === arrType()) shape = "ARRAY(count=" + arrCount(v) + ")";
        else shape = "OTHER typeid=" + t;
      }
      send("    " + keys[i] + ": " + shape);
    }
    send("=== p140-echo end ===");
  } catch (e) { send("[echo-ERR] " + e); }
})();