# Rust Hard Mode - Unsafe Soundness, FFI, Miri, Fuzzing, Sanitizers, Loom, Crate Tooling

Companion to the `backend-audit` skill. Deepens SKILL.md §1 (Unsafe Rust and Soundness Boundaries) into an actionable tooling-and-soundness playbook for the places Rust's guarantees stop being automatic: `unsafe`, FFI, concurrency primitives, and the build/supply-chain surface. SKILL.md names the tools; this pack tells you how to wield them and what each one actually catches.

## A. Unsafe soundness checklist

Inventory EVERY `unsafe` block (`rg -n "unsafe " --type rust`) and triage each:
- **No adjacent `SAFETY:` comment** stating the upheld invariant -> finding. The comment must name *what* makes it sound, not just "this is fine". (Clippy `clippy::undocumented_unsafe_blocks` enforces presence; absence of the lint is itself a gap.)
- **Soundness rule**: a *safe* function/wrapper exposing `unsafe` internals must be sound for ALL safe inputs an attacker can supply. If any safe call sequence can violate the invariant, the wrapper is unsound regardless of "we never call it that way". Check the full invariant set: **length, alignment, aliasing (`&` vs `&mut`), lifetime/dangling, initialization, and thread-safety**.
- **`unsafe impl Send` / `unsafe impl Sync`** on types holding raw pointers, `Cell`/`UnsafeCell`, OS handles, or FFI resources - the most common source of data races and use-after-free in "safe" Rust. Verify the type is genuinely safe to move/share across threads. A wrong `Sync` is data-race UB -> can be CRITICAL under concurrent load.
- **`std::mem::transmute`** - flag every one. Layout, validity, and lifetime are all unchecked; transmuting to a type with invalid bit patterns (e.g. `bool`, `char`, enum, references) is instant UB. Prefer typed conversions / `bytemuck`/`zerocopy` for POD reinterpretation.
- **`MaybeUninit` + `assume_init`** - reading uninitialized memory is UB; verify full init before `assume_init`. **`Vec::set_len`** must be preceded by actual initialization of those elements.
- **`slice::from_raw_parts`/`_mut`**, **`Box/Vec/String::from_raw`/`into_raw`**, **`Rc/Arc::from_raw`** - ownership and provenance must round-trip exactly (same allocator, same layout, no double-free, no aliasing the `_mut` slice).
- **`get_unchecked`/`get_unchecked_mut`** (OOB if index unproven) and **`unwrap_unchecked`/`unreachable_unchecked`** (UB if the "impossible" case is reachable from attacker input). Both turn a logic bug into memory unsafety.
- **`Pin` projections** - a manual `Unpin`/projection that lets a `!Unpin` field move breaks pinning guarantees (UB for self-referential futures). Prefer `pin-project`/`pin-project-lite` over hand-rolled `unsafe` projection.
- **`#[no_mangle]` / `#[export_name]` / `#[link_section]`** - symbol-level surface; a clashing/exported symbol can be hijacked or placed in an unexpected section. Inventory exported symbols.
- Cross-reference: deserialization/alloc-bomb UB-adjacent issues live in `references/web-crypto-hardening-rust.md` §G.

## B. FFI checklist (CWE-787 OOB write, CWE-476 NULL deref, CWE-248 uncaught exception)

Audit each `extern "C"` declaration and call:
- **Panic/unwind policy is the #1 FFI bug.** A `panic!` unwinding across an `extern "C"` boundary was **Undefined Behavior** before Rust 1.81; as of 1.81 the non-unwind ABIs (`"C"`, `"system"`, ...) **abort the process** on an uncaught unwind (defined, but still a crash/DoS). Either way it is wrong. Every Rust function exposed as `extern "C"` to foreign callers, and every Rust callback handed to C, should wrap its body in `std::panic::catch_unwind` and convert to an error code - OR be declared `extern "C-unwind"` (stable since Rust 1.71, rust-lang RFC 2945) when controlled unwinding across the boundary is intended. Flag any boundary function that can panic (indexing, `unwrap`, `.expect`, allocation, arithmetic overflow in debug). Real advisory: `libpulse-binding` panic-in-callback, RUSTSEC-2019-0038 / CVE-2019-25055 (CWE-248).
- **Ownership / who-frees-what**: every pointer crossing the boundary needs a documented owner. Allocate and free with the *same* allocator (a `Box` from Rust must be freed by Rust via `from_raw`, never C `free`, and vice-versa). Flag asymmetric alloc/free -> double-free / corruption (CWE-415/CWE-416).
- **Nullability**: foreign pointers are untrusted - null-check before deref (CWE-476). Don't materialize a `&T`/`&mut T` from a possibly-null/dangling raw pointer.
- **Alignment & `repr(C)`**: structs shared with C MUST be `#[repr(C)]` (or `repr(transparent)`); `repr(Rust)` layout is unspecified. Verify field order/padding and integer widths (`c_int` vs `i32`, `c_char` signedness) match the C header.
- **Lifetimes across the boundary**: a pointer/slice handed to C must outlive C's use of it; returning a pointer into a dropped `Vec`/`CString` is use-after-free (CWE-416).
- **`CString`/`CStr` / NUL handling**: interior NUL -> `CString::new` errors; don't `unwrap` on attacker text. A `&str` is not NUL-terminated - never pass `.as_ptr()` of a Rust `str` where C expects a C string.
- **Callback re-entrancy / aliasing**: a C callback that re-enters Rust can alias data Rust thinks it owns `&mut` -> UB. Document re-entrancy assumptions.
- Validate the boundary's native side under ASan (§E); validate the safe-Rust side under Miri (§C, which cannot cross FFI).

## C. Miri - UB interpreter

`cargo +nightly miri test` (and `cargo +nightly miri run`) interprets MIR and detects UB that compiles fine:
- Catches: out-of-bounds, use-after-free, invalid/misaligned pointer deref, reads of uninitialized memory, invalid values (e.g. `bool` != 0/1), pointer-provenance / Stacked-Borrows / Tree-Borrows aliasing violations, some memory leaks, and **some** data races.
- Useful flags via `MIRIFLAGS`: `-Zmiri-strict-provenance`, `-Zmiri-symbolic-alignment-check`, `-Zmiri-tree-borrows`, `-Zmiri-ignore-leaks`, `-Zmiri-seed=N` (vary scheduling to shake out races).
- **Hard limitation: Miri cannot execute FFI / real syscalls / inline asm.** It does not exercise your C side (use ASan/§E for that). It also runs slowly, so target it at unit tests that drive `unsafe` abstractions, not the whole suite.
- Required check: any crate with non-trivial `unsafe` should have a Miri job in CI over its unit tests. Absence is a Medium gap; absence on a crate doing manual `Vec`/pointer surgery is High.

## D. Fuzzing - `cargo fuzz` / `afl.rs`

Coverage-guided fuzzing finds the panics/UB/OOM that hand-written tests miss:
- **`cargo fuzz`** (libFuzzer) is the default: `cargo fuzz init`, `cargo fuzz add TARGET_NAME`, `cargo fuzz run TARGET_NAME`. Use `cargo fuzz cmin` to minimize the corpus and `cargo fuzz tmin TARGET_NAME INPUT_FILE` to minimize a crasher (UPPERCASE = placeholder, substitute real values). **`afl.rs`** (AFL++) is the alternative for harder-to-trigger paths.
- **Structure-aware fuzzing**: derive `arbitrary::Arbitrary` and take a typed struct in `fuzz_target!` instead of `&[u8]`, so the fuzzer explores valid-ish inputs deep into the parser rather than bouncing off the first length check.
- **High-value targets in a backend** (any code that eats attacker bytes): parsers/tokenizers, **webhook payload** verification + parsing, **JWT/token** parsing (`jsonwebtoken` claims, base64url segments), `serde`/`bincode`/`postcard`/CBOR (`ciborium`)/MessagePack **deserialization**, **decompression** (gzip/zstd/brotli), **image/metadata** decode, **URL parsing** (`url` crate, SSRF-allowlist logic), and binary/**protobuf** (`prost`) / `tonic` message decode.
- **Process requirement**: every crash + the minimized input MUST become a committed regression test (drop the file into the target's corpus AND add a `#[test]` replaying it). A fuzz crash that is fixed but not regression-tested is a re-occurrence waiting to happen.
- Run fuzz targets under sanitizers - `cargo fuzz` builds with ASan by default; add `-s thread`/`-s memory`/`-s leak` for the relevant class.

## E. Sanitizers - runtime instrumentation (nightly)

LLVM sanitizers via `RUSTFLAGS="-Zsanitizer=<name>"` on **nightly** (all require nightly):
- `address` (ASan) - heap/stack OOB, use-after-free/return, double-free. `thread` (TSan) - data races. `memory` (MSan) - uninitialized reads. `leak` (LSan) - leaks.
- **Build requirement**: pass `--target <triple>` so the sanitizer is NOT applied to build scripts/proc-macros, and `-Zbuild-std` is strongly recommended to instrument `std` (MSan *requires* it). Targets are limited - ASan: `x86_64`/`aarch64` Linux + `x86_64`/`aarch64` Apple Darwin; TSan: same minus `aarch64` Darwin caveats; MSan: Linux only (no Darwin); LSan: Linux + `x86_64` Darwin. Confirm your CI runner's triple is supported.
- **When to run**: unsafe-heavy crates, FFI/native integrations (sanitizers DO cross into C, unlike Miri - pair with `-Zexternal-clangrt` to link clang's runtime for cross-language builds), and as the engine under fuzzing. TSan complements Loom: TSan finds races on *executed* interleavings; Loom (§F) proves their absence over *all* explored interleavings.
- Example: `RUSTFLAGS="-Zsanitizer=address" cargo +nightly test --target x86_64-unknown-linux-gnu`.

## F. Loom - concurrency model checker

`loom` exhaustively explores thread interleavings for hand-written concurrency:
- Use for: **custom synchronization primitives**, **lock-free / atomic** code (`AtomicUsize`, `compare_exchange`, fences), `Arc`/`UnsafeCell`-based sharing, and tricky async coordination/waker logic.
- Mechanism: swap `std::sync`/`std::sync::atomic`/`UnsafeCell` for `loom::sync::*` under `#[cfg(loom)]`, wrap the test in `loom::model(|| { ... })`. Loom permutes orderings and memory-ordering choices, catching races, missed-wakeup, and ordering bugs that ad-hoc tests and even TSan can miss.
- Cost: state space explodes - keep models small (2-3 threads, few ops); bound exploration with `LOOM_MAX_PREEMPTIONS` (or `Builder::preemption_bound`). Absence of Loom coverage on a crate that ships its OWN lock-free primitive is a High gap; standard `Mutex`/channel usage does not need it.

## G. Crate / supply-chain tooling

(SBOM/CI depth lives in `references/supply-chain-ci-cd-security.md` - cross-reference, don't duplicate. SKILL.md §6 names these; this is the operator's view.)
- **`cargo audit`** - RustSec advisory DB scan of `Cargo.lock`; `cargo audit --deny warnings` to fail CI (also fails on yanked versions); flags unmaintained crates and yanked versions.
- **`cargo deny check`** - superset gate running `advisories`, `bans` (deny specific crates / **duplicate versions** via `cargo deny check bans`), `sources` (only allow crates from trusted registries/git), `licenses`. The `sources` check is the typosquat/registry-substitution defense.
- **`cargo vet`** - records human *review state* ("audited"/"trusted") per third-party crate version; gates that every dependency has been vetted or is covered by an imported audit set. The strongest defense against malicious-update supply-chain attacks.
- **`cargo geiger`** - counts `unsafe` usage per dependency; use to prioritize where §A-F effort goes (note: it can undercount macro-generated `unsafe`, and maintenance is intermittent).
- **`cargo auditable build`** - embeds the dependency list INTO the binary (linker section `.dep-v0`) so a deployed artifact can be scanned later (`cargo audit bin <binary>`).
- **`cargo tree -e features`** (see which features pulled a crate in) and **`cargo tree -d`** (duplicate versions - wasted audit surface + version-confusion risk).

## H. Build-time code execution & feature unification

`build.rs` and proc-macros run **arbitrary code on the developer/CI machine at build time** - a primary supply-chain RCE vector (CWE-829 Untrusted Functionality):
- Audit every `build.rs` and proc-macro dep for **network access, filesystem writes outside `OUT_DIR`, env/secret reads, spawning processes, and codegen that hides logic**. `cargo build -v` / `cargo tree -e build` enumerates the build-dep graph. A build script doing `reqwest`/`std::process::Command` is a finding.
- **Feature unification is security-relevant.** Cargo unifies features across the workspace: one crate enabling a dangerous feature turns it on everywhere. Audit for features that flip:
  - **TLS backend** - `rustls` vs `native-tls`/`openssl-sys`/`openssl` `vendored` (system OpenSSL footguns; see crypto reference §F). A transitive crate flipping `reqwest`/`sqlx`/`tonic` to native-tls is a regression.
  - **Crypto backend / RNG**, **native C libs** (`libsqlite3-sys` bundled vs system), and any **`unsafe`/`unsound`/"fast"/"nightly"** feature flags that opt into less-checked code paths.
- Use `cargo tree -e features -i CRATE_NAME` to find *who* enabled a given feature, and verify the resolved feature set in CI matches intent. Pin `default-features = false` and re-add explicitly for security-sensitive deps.

## Search patterns

```bash
rg -n "unsafe |transmute|from_raw|from_raw_parts|set_len|MaybeUninit|assume_init|zeroed|get_unchecked|unwrap_unchecked|unreachable_unchecked" --type rust
rg -n "unsafe impl (Send|Sync)" --type rust
rg -n 'extern "C"|extern "C-unwind"|#\[no_mangle\]|#\[export_name\]|link_section|catch_unwind' --type rust
rg -n "repr\(C\)|repr\(transparent\)|CString|CStr::from_ptr|as_ptr" --type rust
rg -n "Pin|unsafe.*poll|get_unchecked_mut" --type rust
rg --files -g 'build.rs'; rg -n 'proc-macro = true' --glob 'Cargo.toml'
rg -n 'native-tls|openssl|vendored|default-features\s*=\s*false' --glob 'Cargo.toml'
```

## Tooling commands

```bash
# Miri (UB interpreter) - drives unsafe abstractions; cannot do FFI/syscalls
rustup +nightly component add miri
MIRIFLAGS="-Zmiri-strict-provenance -Zmiri-symbolic-alignment-check" cargo +nightly miri test

# Fuzzing - crashers + minimized inputs become regression tests
cargo install cargo-fuzz
cargo fuzz add parse_webhook && cargo fuzz run parse_webhook
cargo fuzz tmin parse_webhook CRASH_FILE   # minimize, then commit to corpus + add a #[test]

# Sanitizers (nightly + explicit --target so build scripts stay uninstrumented)
RUSTFLAGS="-Zsanitizer=address" cargo +nightly test --target x86_64-unknown-linux-gnu
RUSTFLAGS="-Zsanitizer=thread"  cargo +nightly test --target x86_64-unknown-linux-gnu

# Loom (model-check custom concurrency)
LOOM_MAX_PREEMPTIONS=3 RUSTFLAGS="--cfg loom" cargo test --release --lib

# Supply chain
cargo audit --deny warnings              # advisories; fail on yanked/advisory
cargo deny check                         # advisories + bans/sources/licenses/dups
cargo vet                                # third-party review state
cargo geiger                             # unsafe usage counts (prioritization)
cargo tree -e features -i CRATE_NAME     # who enabled which feature
cargo tree -d                            # duplicate versions
```

## Sources

- Rustonomicon: https://doc.rust-lang.org/nomicon/
- Unsafe Code Guidelines: https://rust-lang.github.io/unsafe-code-guidelines/
- Miri: https://github.com/rust-lang/miri
- Rust Fuzz Book (cargo-fuzz): https://rust-fuzz.github.io/book/cargo-fuzz.html
- Cargo Vet: https://mozilla.github.io/cargo-vet/
- Cargo build scripts: https://doc.rust-lang.org/cargo/reference/build-scripts.html
- Cargo features: https://doc.rust-lang.org/cargo/reference/features.html
- Rust sanitizer support: https://doc.rust-lang.org/beta/unstable-book/compiler-flags/sanitizer.html
- Loom: https://docs.rs/loom/latest/loom/
- rust-lang RFC 2945 (`C-unwind` ABI): https://rust-lang.github.io/rfcs/2945-c-unwind-abi.html
- Rust 1.81 release notes (non-unwind ABIs abort on unwind): https://blog.rust-lang.org/2024/09/05/Rust-1.81.0/
- RUSTSEC-2019-0038 (libpulse-binding FFI panic): https://rustsec.org/advisories/RUSTSEC-2019-0038.html
- CWE-248 Uncaught Exception: https://cwe.mitre.org/data/definitions/248.html
