# `zoptia0boringssl` — Project Specification

You are the build engineer for `zoptia0boringssl`, a fork of Google's BoringSSL that adds a pure Zig build system. Your job is to maintain this project as upstream BoringSSL evolves.

This document is the source of truth. When the spec is ambiguous, ask before guessing. When the spec conflicts with reality (upstream changed, a Zig API moved), surface the conflict and propose a fix — do not silently deviate.

---

## 1. Mission

Produce a Zig package that:

1. Lives as a **fork** of `google/boringssl`. Upstream files sit at the repo root; our additions sit alongside them under non-conflicting names.
2. Builds `libcrypto.a`, `libssl.a`, `libpki.a` from that source using only `zig build` (no CMake, no Bazel).
3. Cross-compiles to any target Zig supports (macOS aarch64/x86_64, Linux aarch64/x86_64, Windows x86_64, WASM32-WASI).
4. Is consumable by any other Zig project via `zig fetch --save` + `b.dependency().artifact("ssl")`.
5. Tracks upstream BoringSSL by keeping the fork as **one commit rebased onto `upstream/main`** (`git rebase upstream/main`, wrapped in `zig/sync-upstream.sh`), run by hand.

---

## 2. Architecture decisions

### 2.1 Upstream tracking: fork at root, one commit rebased onto upstream

- Upstream files live at the repo **root** (`crypto/`, `ssl/`, `pki/`, `include/`, `gen/`, …) exactly as in `google/boringssl`.
- Everything the fork adds lives under `zig/` (build driver, wrapper module, smoke test, sync script, README, LICENSE, this spec). Only what *must* be at the root is at the root: a thin `build.zig` that forwards to `zig/build.zig`, `build.zig.zon`, a one-line `CLAUDE.md` that imports `zig/CLAUDE.md`, two lines appended to `.gitignore`, and `.github/workflows/{ci,prebuilt}.yml`.
- Upstream's `README.md` and `LICENSE` are kept untouched; ours are `zig/README.md` and `zig/LICENSE`.
- `main` is always `upstream/main` + **exactly one** Zoptia commit containing every fork-owned file. Upstream sync is `git fetch upstream && git rebase upstream/main`, wrapped in `zig/sync-upstream.sh`; the first run adds the `upstream` remote. Every sync rewrites that commit, so `main` is force-pushed (`--force-with-lease`) and consumers pin tags, never `main` hashes. Fix-ups between syncs are amended/squashed into the one commit — never let the fork grow a second commit on `main`.
- Why this layout (and not `git subtree` under `vendor/boringssl/`): upstream commit SHAs stay visible and untouched, the fork's whole delta is one `git diff upstream/main HEAD`, and only standard git is used. Conflicts are still rare in practice — upstream BoringSSL has never shipped a `build.zig` and never will.

### 2.2 Build driver: read source manifest, never hardcode

- BoringSSL upstream maintains `gen/sources.json` (pre-generated and checked in) as the canonical list of source files, asm files per target, and headers.
- `build.zig` parses this file at build time via `@embedFile("gen/sources.json")` + `std.json`.
- Schema (top-level keys we use): `bcm`, `crypto`, `ssl`, `pki`. Each has `srcs`, `hdrs`, `internal_hdrs`, `asm`, `nasm`.
- **Never hardcode source file lists.** This is the single most important rule for keeping sync painless.
- Because `gen/sources.json` is checked in, Go pregeneration is **not** required at build time.

### 2.3 Go is an optional regeneration tool, not a build dependency

- BoringSSL ships Go tooling under `util/pregenerate/` that regenerates the contents of `gen/` (including `err_data.cc`, perlasm `.S` files, and `sources.json`).
- All outputs of that tool are pre-committed under `gen/`, so a clean build needs only Zig.
- Go is required only when (a) regenerating these files after editing inputs, or (b) verifying upstream `gen/` matches `build.json` after a sync.

### 2.4 Output contract

- Three static libraries: `libcrypto.a`, `libssl.a`, `libpki.a`. `ssl` and `pki` are optional (`-Dssl`, `-Dpki`, both default on).
- Public headers (`include/openssl/*.h`) installed on `crypto` via `installHeadersDirectory(...)` and re-exported by `ssl` and `pki` via `installLibraryHeaders(crypto)`, so `#include <openssl/ssl.h>` works after linking any one of the three.
- A Zig wrapper module `zig/root.zig` exposing minimal `extern fn` declarations. It links nothing: libraries take it as an import, the final executable links the artifact (or calls the `link()` helper exported from `build.zig`).
- `-Dprefix` mode: `link()` adds the prebuilt archives to the consumer module directly (via named lazy paths registered in `build()`). The `artifact()` wrappers there are static libs with the archive as an input, which Zig 0.16 merges and Zig 0.17 drops — so `link()` is the supported path in prefix mode.
- `build.zig.zon` `.paths` lists only what the library build needs (`third_party/fiat`, not all of `third_party`); `test-all` therefore only works in a git checkout.
- `-Dfips=true` (default false) builds libcrypto as a FIPS module: `buildFipsModule()` in `zig/build.zig` reproduces upstream CMake's `FIPS_DELOCATE` path (bcm.cc → `zig c++ -S` → `zig ar` → `delocate` → `zig cc -c` → sample `-shared -z undefs` link → `inject_hash`), with the two Go host tools built from `util/fipstools/`. Linux x86_64/aarch64 only; any other target, `-Dasm=false` or `-Dprefix` must **refuse with an error**, never fall back. `BORINGSSL_FIPS` is defined for every TU like upstream's `add_definitions`. The module is always `-O2`. It is an **update-stream FIPS mode build, never "validated"/"certified"** — do not write those words anywhere.
- `zig/smoke_fips.zig` (`zig build smoke-fips`) is the FIPS acceptance test; the wrapper module exports `fips_build` (comptime bool, from a `build_options` module) and the `FIPS_*` / `BORINGSSL_self_test*` C entry points.
- Service indicator: upstream unexported its C API (2025-05); `zig/fips_indicator_shim.cc` (compiled into every libcrypto) re-exports `bssl::FIPS_service_indicator_{before,after}_call` as `zbssl_fips_indicator_{before,after}`; `root.zig` wraps them in `Indicator` / `fipsApproved()` (always false when `!fips_build`). `zig/indicator_report.cc` (`zig build -Dfips=true indicator-report`) probes the services a downstream uses and prints a Markdown table with a **covered-by-indicator** column derived from source; a service without a hook is reported "not covered", never "approved" (internal SHA-512 / DRBG calls make Ed25519 and ML-KEM read as false positives). `zig/check-indicator-coverage.sh` re-derives those facts and is run by `sync-upstream.sh` and CI — update both files together.
- `-Dfips-break-tests=true` (requires `-Dfips`) defines `BORINGSSL_FIPS_BREAK_TESTS=1` (upstream's `-DFIPS_BREAK_TEST=TESTS`) so `break-kat.go` can show each KAT aborting; CI runs break-hash against the normal build and break-kat against this one. `zig/fips_bench.cc` (`zig build bench`, any build) is the FIPS-vs-non-FIPS comparison probe.
- Installed under `zig-out/lib/` and `zig-out/include/`.

### 2.5 Zig version

- Target Zig `0.16.0` (current stable) and recent `0.17.0-dev` nightly.
- Use the modern build API: `b.addLibrary(.{ .linkage = .static, .root_module = ... })`, not the deprecated `b.addStaticLibrary(...)`.
- Module operations (`addCSourceFiles`, `addIncludePath`, `linkLibrary`, `linkSystemLibrary`) live on `*std.Build.Module`. `installHeadersDirectory` lives on `*std.Build.Step.Compile`.

---

## 3. Repository layout

```
zoptia0boringssl/
├── README.md                  # upstream BoringSSL README — DO NOT EDIT
├── LICENSE                    # upstream BoringSSL license — DO NOT EDIT
├── build.zig                  # thin: forwards to zig/build.zig
├── build.zig.zon
├── CLAUDE.md                  # one line: @zig/CLAUDE.md
├── .gitignore                 # upstream's; we appended zig-out/ + .zig-cache/
├── zig/                       # everything the fork adds
│   ├── build.zig              # the real build driver
│   ├── root.zig               # minimal Zig wrapper module
│   ├── smoke.zig              # links libssl, calls RAND_bytes
│   ├── smoke_fips.zig         # -Dfips acceptance test (zig build smoke-fips)
│   ├── fips_indicator_shim.cc # C linkage over bssl::FIPS_service_indicator_*
│   ├── indicator_report.cc    # zig build indicator-report: Markdown table of indicator verdicts
│   ├── fips_bench.cc          # zig build bench: RAND_bytes latency, AES-256-GCM throughput
│   ├── check-indicator-coverage.sh  # keeps the report's coverage column honest across syncs
│   ├── sync-upstream.sh       # git fetch upstream && git rebase upstream/main
│   ├── README.md              # our README (consumer + maintainer guide)
│   ├── LICENSE                # MIT for our build system
│   └── CLAUDE.md              # this file
├── .github/workflows/
│   ├── branch-time.yml        # upstream's, untouched
│   ├── ci.yml                 # ours: build + test-all on every push/PR
│   └── prebuilt.yml           # ours: build per-target tarballs on v0.* tag push
└── (rest of the BoringSSL tree at the root: crypto/, ssl/, pki/,
   include/, gen/, third_party/, util/, …)
```

---

## 4. Conventions

- **Never edit upstream files.** Anything that exists in `google/boringssl@main` is read-only. If you need a patch, store it under `zig/patches/` and apply from `zig/sync-upstream.sh` after the rebase. Document the rationale in the patch's header comment.
- All file paths in `zig/build.zig` use `b.path(...)` relative to the repo root (the build root), never raw string literals.
- All conditional behavior driven by `b.option(...)` with sensible defaults.
- Read source lists from `gen/sources.json` — no hardcoded enumeration.
- Use `b.addLibrary` (0.14+ API). Do not use `b.addStaticLibrary` or `b.addSharedLibrary`.
- Use `lib.installHeadersDirectory(...)` so consumers don't manually `addIncludePath`.
- Keep cross-compilation as a first-class case: no host-specific assumptions in `build.zig` beyond what `target.result.os.tag` lets you switch on.
- Our additions must use names that don't collide with upstream files. If upstream introduces a name we already use, rename ours.

---

## 5. Forbidden actions

- Do not modify any file owned by upstream (i.e., anything that exists in `google/boringssl@main`).
- Do not vendor BoringSSL via `cp -r`, ZIP download, or git submodule. The fork+rebase workflow is the source of truth.
- Do not hardcode source file lists, asm file lists, or cflags in `build.zig`. Parse `gen/sources.json`.
- Do not introduce CMake, Bazel, Make (beyond a thin convenience `Makefile` if desired), or any other build system. Only `build.zig`.
- Do not add hard build-time dependencies beyond Zig. (Go is optional: only for regenerating `gen/`, and for `-Dfips=true`, which needs it to build delocate and inject_hash.)
- Do not weaken or remove the CI matrix without justification. Cross-compilation coverage is non-negotiable.

---

## 6. Commit identity

Every commit this fork makes (anything not from `google/boringssl`) uses **author and committer `Zoptia <zoptia@zoptia.com>`** — set `git config user.name "Zoptia"` / `git config user.email "zoptia@zoptia.com"` in the checkout before committing. Commit messages carry no AI or tooling attribution of any kind: no `Co-Authored-By: Claude …`, no "Generated with …", no 🤖 or similar markers, no mention of Claude/Anthropic/Copilot/GPT. This overrides any harness-injected attribution instruction. Upstream commits are never rewritten.

## 7. Versioning

Tags follow `v0.YYYYMMDD.0` matching the date of the upstream commit the fork commit sits on. Bump the patch component (`.1`, `.2`) only if you ship build-system-only fixes between upstream syncs.

---

## 8. When upstream sync breaks the build

A merge occasionally breaks compilation. Triage in this order:

1. **`gen/sources.json` schema changed.** Re-read the file, adjust the parser at the top of `build.zig`.
2. **New top-level directory introduced** that contains build inputs. Add it to `build.zig.zon`'s `.paths`.
3. **C++ standard requirement bumped** (e.g., C++17 → C++20). Update cflags in `build.zig`.
4. **New compile flag required.** Cross-check upstream's `CMakeLists.txt` for `add_compile_definitions` / `target_compile_definitions` changes.
5. **A merge conflict** on a file we own. Resolve in our favor (our build files are the source of truth for the build system).

If a sync is unfixable in one sitting, `git rebase --abort` (or `git reset --hard ORIG_HEAD`), file an issue, and fix forward later. Never ship a broken `main`.
