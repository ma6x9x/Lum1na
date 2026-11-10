# 23F77 small-kext sweep — AUC / Multitouch / JPEG / CoreAnalytics / SEPKeyStoreTest

Date: 2026-11-09. Image: A14 `kernelcache.research.iPhone13,2` (23F77, T8101).
Tool: Ghidra bridge program `A14_iPhone13_2` (VA base `0xfffffff007004000`),
plus capstone reads of the on-disk cache. Goal: find the missing *client-
controlled length/offset* write for the 12 after v63/43748/p154 all proved
bounded.

## AUC.kext (load `0xfffffff00712c580`, text `0xfd0`)

- Class hierarchy registered from `0x80bdd44/0x80be78c/0x80bf260/0x80c018c/
  0x80c0f6c`; `AUCUserClient` = `0x80be78c`, object size `0x148`, superclass
  meta `0x7bb6d28`.
- Strings: `IOMobileFramebuffer`, `hdcp-hoover-protocol`, `IOAVVideoInterface`,
  `CommonAVVideoInterface`, `CloseUserClient`, `ConnectionWatchdog`. This is
  the display/AV-interface **client** side of AUC, not a report parser.
- No `IOExternalMethodDispatch` table found in the AUC code range
  (`0x80b0000-0x80d0000`) at strides `0x18/0x20/0x28/0x30`, and no vtable run
  into that range other than the metaclass tables. **No external selector
  surface found.** Low value; park.

## AppleMultitouchDriver / SPI (`0x755a7f0` / `0x7560e10`)

- `AppleMultitouchHIDService::getMultitouchReport` `0x8bb0698`:
  requires `*length < 0x400`, allocates `0x400`, passes `length+1` into
  `simpleGetReport` `0x8bb07e8`. The core rejects
  `received > requested` with `0xe00002e8` and only then copies
  `*length` bytes to the caller. **Bounds-checked.**
- `setMultitouchReport` `0x8bb0ae0`: requires `length != 0 && length < 0x400`,
  writes the report ID at `buf+0`, copies `length` bytes at `buf+1`; the
  buffer is `0x400`, so the copy ends at `0x400` exactly. **No overflow.**
- `handleInterruptReport` `0x8bafec4`: the 5-byte report-ID read is guarded
  by the report length (`iVar13`); the buffer is passed to the logger only
  with that same length.
- `AppleMultitouchDeviceUserClient` uses the HID service/data-queue path
  (`createDataQueue`, `clientMemoryForType`), not a length-taking external
  method. **Report lane closed.**

## AppleJPEGDriver (`0x7491750`, text `0xfc9c`)

- `AppleJPEGDriverUserClient` registration `0x89c061c` (and duplicate
  `0x89c0758`), size `0x110`, superclass `0x7d11b40`. Dispatch table at
  `0x7d13bd8`, stride `0x28`; handlers include `0x89c0f80` (88-byte struct),
  `0x89c0fc0`/`0x89c0ff4` (4096), `0x89c1028`/`0x89c105c` (3488).
- `startDecoder` `0x89b9450`: validates `inputSize >= 0x100`, output `>= 7`,
  resolution fields, then copies `param_2[0x1f] & ~3` bytes from
  `param_2+0x21` into a vector grown by `FUN_89b8a24`. That helper allocates
  `elements * 4` bytes and the copy length is the same `u32 & ~3`, so the
  copy is exact (the later `buffer_end - base < len` check is an assertion,
  not the only guard). **Safe.**
- `startEncoder` `0x89b8fb4`: validates `(param_2[7] & 0xfffe) < 10`,
  `param_2[1] >= 0x100`, `param_2[3] >= 7`, `param_2[5]` split 4/0,
  `param_2[6]` range. The `local_170[33]` stack table is filled by a **fixed
  4-iteration** loop (`lVar9` 0..0x60, max write 0x100 < 0x108). It stores
  `local_170+0x10` / `local_170` into request `+0x90/+0x98`, but no read of
  those request fields was found in the start path; the apparent consumers
  were the driver's `+0x90/+0x98` (codec pointer/current request), a
  different object. **No confirmed UAR.**
- `JpegRequest` is allocated from `site.JpegRequest` via `IOMallocType`
  (`0x89b74c4`); the view flags are `0x8004` (`Z_CRITICAL|Z_ZERO`), so the
  constructor's `[0x79]/[0x7a]` scan reads zeros, not stale pointers. The
  uninitialized-vector theory is dead.
- Deeper surface remains (IOSurface source/dest mapping in
  `FUN_89b6cdc`, surface-stride checks in `FUN_89d72a8`), but no dispatch-
  level length bug.

## CoreAnalyticsTestUserClient (`0x7656d20`)

- Registered in production at `0x90fcfac` (size `0xe0`); the production
  `CoreAnalyticsUserClient` is gated by `com.apple.iokit.CoreAnalytics.user`
  (`checkEntitlement` `0x90fbfe8`).
- `externalMethod` `0x90fcda8` accepts **selector 0x65** and passes
  `structureInput`/`structureInputSize` (`args+0x30/+0x38`) to
  `0xa478da4`: size must be `> 3`; XML requires a NUL at `buffer[size-1]`
  and then calls the **size-less** `OSUnserializeXML` `0xa478bc4`; binary
  uses `0xa4799c4`. This is a client-controlled kernel XML parser.
- Reachability: the class object `0xaa544d8` and name are referenced only by
  the registration, the metaclass factory `0x90fc814`, and the release
  `0x90fcffc`. The hub's `__newUserClientGated` string/method exists
  (`0x7657df6`) but no xref to the test class object or name was found from
  it. The test UC is **registered but not instantiated** by the production
  hub. Do not count it as an app-reachable parser without a new door.

## AppleSEPKeyStoreTestUserClient (open lead)

- Registered in the production ctor `0x8d8838c` at `0x8d883e0`
  (`AppleKeyStoreTestUserClient` name `0x75c6453`); production UC is
  `AppleKeyStoreUserClient` (`0x75c92eb`).
- The driver's 163-selector dispatch is the 132 KB megafunction
  (`0x8d97474`), so the test UC's selector set is not separately decoded yet.
- **Built as P161** (`Exploit/P161SEPKeyStoreTestUC.m` + the P007 copy,
  log `p161_sepks_testuc_log.txt`): opens `AppleKeyStore`,
  `AppleKeyStoreTest`, `AppleSEPKeyStore`, `AppleSEPKeyStoreTest` and the
  bundle-id spelling with types 0–32; logs the service and child classes.
  No selectors, no writes. PANIC-POSSIBLE — one tap per force-quit.
- **v1 device result (17 Pro Max, 24A435/27.0, 2026-11-09 19:42):**
  only `AppleKeyStore` matched (`AppleKeyStoreTest`, `AppleSEPKeyStore`,
  `AppleSEPKeyStoreTest`, bundle-id spelling all absent). Types **0–23**
  all returned `KERN_SUCCESS`; every child was `AppleKeyStoreUserClient`;
  `IOUserClientClass` on the service was `(null)`. `test_hits=0`.
  **v1 had two blind spots:** it stopped after 24 successful opens (type
  23) so types 24–32 were never tested, and it capped the child list at 16
  so a new UC past the first 16 children was invisible.
- **v2** removes both caps: full type range 0–32, and a child
  registry-entry-ID diff before/after each open (logs `connClass` and only
  the new children). Re-run once; if every type still yields
  `AppleKeyStoreUserClient`, the type field is not a test-UC selector on
  this build and the `AppleKeyStoreTest` personality is not published —
  the test UC stays a static-only surface, and p104's 163-sel census on
  `AppleKeyStoreUserClient` remains the only AKS door.

## Verdict

The 23F77 dispatch-level surfaces for AUC, Multitouch, JPEG and the
CoreAnalytics test UC are closed or unreachable. The remaining small-kext
leads are the SEPKeyStore test UC (type sweep) and the Sandbox round-3
leads (`exception.*` raw OSObject jumptable, `FUN_9b81044` TLV file,
translated-binary filter exemption). The 12 still needs a new unbounded
client length/offset write or a read that feeds a targetable overlap.
