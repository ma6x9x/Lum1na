# lumina_core

C ABI parse / self-test helpers for Lum1na.

- Mach-O `MH_MAGIC_64` + packed magic+cputype + kernel typeinfo (commitSlide bar)
- Dopamine `trustcache_file_v1` bounds (header + `length * 22` == blob)
- UCB1 + LabBandit reward law
- ANE arm → REQ_IN / model
- AfterKread step names (DOJailbreaker order)
- `enumerate_pages` chunk helper

IPA links the C translation `Exploit/lumina_core.c` (GitHub xcodebuild has no rustc). Keep `src/lib.rs` and that C file in lockstep.

IOKit, detach, ACM, hop-1, kfd, Fugu14 kcall stay out.

```
cargo test --manifest-path rust/lumina_core/Cargo.toml
```
