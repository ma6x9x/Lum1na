# Term Lite

Standalone payload-soft terminal — always launches; the full stack arrives
when the a-Shell mini payload embeds.

| Layer | Without payload | With payload (ios_system + openssl + libssh) |
|---|---|---|
| Shell tab | REPL + P116 `sbx`/`dump` + deputies | full a-Shell mini commands via `ios_system` |
| SSH tab | reports soft honestly | real embedded SSH server (mobile/root, alpine, port 2222) |
| Grants | none needed | `sbx_grant <path>`-style leases via the vendored worse_query() |

Weak-linked libssh: the vendored dylib is weak-imported, so a missing
openssl.framework (payload-only) leaves the launch intact and the SSH rows
honest. WQSSHServer never runs unless ssh symbols are live (dlsym guard in
LTWQSSHBridge).

Build: CI job `build-termlite` produces `TermLite.ipa`. Embed the payload by
placing an a-Shell mini IPA on the runner (`Terminal.ipa` / `a-Shell-mini*.ipa`
in ~/Downloads) — same convention the two fleet apps use.

Credits: a-Shell (MIT, holzschu); the WQ shell bridge + SSH server
(lab-internal, git.jbjflab.top filza27.2); worse_query/pathleak (GPL-3, Taj C /
forcequitOS); libssh (LGPL-2.1). Licenses ship inside `Vendor/`.
