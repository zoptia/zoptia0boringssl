# zoptia0boringssl

A pure-Zig build of [Google's BoringSSL](https://github.com/google/boringssl).

This repository is a **fork** of `google/boringssl`: upstream files live at
the repo root unchanged, and everything the fork adds lives under
[`zig/`](.) — the build driver, a minimal wrapper module, a smoke test, the
sync script and these docs. Only what Zig or GitHub *require* at the root is
at the root: a thin `build.zig` that forwards to `zig/build.zig`,
`build.zig.zon`, a one-line `CLAUDE.md`, two lines appended to `.gitignore`,
and `.github/workflows/`. The fork is kept as a single commit on top of
`upstream/main`; upstream sync is `git fetch upstream && git rebase`.

The build driver parses BoringSSL's own [`gen/sources.json`](../gen/sources.json)
manifest at build time — no source list is duplicated here, so upstream
churn is mostly absorbed without touching `zig/build.zig`.

> Note: BoringSSL's own README is preserved at [`README.md`](../README.md).
> BoringSSL's license is at [`LICENSE`](../LICENSE). The build-system additions
> in this fork are MIT-licensed; see [`zig/LICENSE`](LICENSE).

## Quick start (consumer)

Add this package to your project:

```sh
zig fetch --save=boringssl git+https://github.com/zoptia/zoptia0boringssl#v0.20260924.3
```

Then in your `build.zig`:

```zig
const boringssl = b.dependency("boringssl", .{
    .target = target,
    .optimize = optimize,
});

const exe_mod = b.createModule(.{
    .root_source_file = b.path("src/main.zig"),
    .target = target,
    .optimize = optimize,
    .link_libc = true,
});
// Make `@import("boringssl")` resolve to the wrapper module (declarations
// only — it links nothing by itself).
exe_mod.addImport("boringssl", boringssl.module("boringssl"));
// Link libssl (pulls in libcrypto too). Linking lives on the *module*, and
// the artifact carries the <openssl/...> headers — no addIncludePath needed.
exe_mod.linkLibrary(boringssl.artifact("ssl"));

const exe = b.addExecutable(.{ .name = "myapp", .root_module = exe_mod });
b.installArtifact(exe);
```

If you want only `libcrypto`, link `boringssl.artifact("crypto")` instead. A
third artifact, `pki`, is also available. Every artifact exports the headers,
so a module that links only `ssl` (or only `pki`) can still `#include
<openssl/ssl.h>` from C.

The same thing as a one-liner, via the helper exported by this package's
`build.zig` (importable by the dependency name from your `build.zig.zon`):

```zig
const bssl = @import("boringssl");
bssl.link(exe_mod, boringssl, .{ .ssl = true, .pki = false });
```

### For library authors

Zig has no way to override a transitive dependency, so a library that does
its own `b.dependency("boringssl", ...)` pins a BoringSSL that may differ
from the one the final application uses — two `libcrypto`s, duplicate
symbols. The pattern that composes:

- The **library** takes the wrapper module as an import parameter and never
  links: `lib_mod.addImport("boringssl", <module handed in by the app>)`.
  Its code uses `@import("boringssl").c.*` and any `extern fn` it adds.
- The **application** owns the dependency: it creates the module once via
  `b.dependency(...).module("boringssl")`, hands it to every library, and
  links `artifact("ssl")` / `artifact("crypto")` exactly once on its own
  executable module.

This is why the wrapper module links nothing.

The wrapper module gives you:

```zig
const bssl = @import("boringssl");
var buf: [32]u8 = undefined;
_ = bssl.c.RAND_bytes(&buf, buf.len);
```

The wrapper currently exposes only a tiny set of `extern fn` declarations
(`RAND_bytes`, `OpenSSL_version`). BoringSSL's headers are too macro-heavy
for `zig translate-c` to handle reliably, so the recommended pattern for
broader use is to declare the functions you need yourself — with
`boringssl.artifact("ssl")` linked, the symbols are available.

### What the fetched package contains

`zig fetch` receives only what the library build needs (`include/`,
`crypto/`, `ssl/`, `pki/`, `gen/`, `third_party/fiat/`, `zig/`), which keeps
the download to a fraction of the full tree. BoringSSL's C++ test suite
(`zig build test-all`) additionally needs `third_party/googletest` and
`third_party/wycheproof_testvectors`, so it only works in a git checkout of
this repository, not through a dependency.

## Supported targets

CI verifies builds on `ubuntu-latest` and `macos-latest`, including:

- `aarch64-macos`, `x86_64-macos`
- `aarch64-linux-gnu`, `x86_64-linux-gnu`
- `wasm32-wasi` (with `-Dasm=false`)
- `x86_64-windows-gnu` (with `-Dasm=false`; see Windows note)

Other Zig targets should generally work; please open an issue if not.

### Build options

| Flag | Default | Description |
|------|---------|-------------|
| `-Dtarget=<triple>` | host | Standard Zig cross target |
| `-Doptimize=<mode>` | Debug | ReleaseFast / ReleaseSafe / ReleaseSmall |
| `-Dasm=true\|false` | `true` | Include perlasm-generated assembly |
| `-Dssl=true\|false` | `true` | Build and install `libssl` (the `ssl` artifact) |
| `-Dpki=true\|false` | `true` | Build and install `libpki` (the `pki` artifact) |
| `-Dprefix=<path>` | (none) | Skip source compilation; use prebuilt libs at `<path>/lib` + headers at `<path>/include` |
| `-Dfips=true\|false` | `false` | Build libcrypto as a FIPS module — update stream, **not** a validated module. Linux x86_64/aarch64 only, needs Go. See [FIPS](#fips-mode-build) |

#### `-Dprefix` for cached / system / patched builds

If you already have `lib{crypto,ssl,pki}.a` (or `{crypto,ssl,pki}.lib` on
MSVC) and `include/openssl/*.h` somewhere on disk, point `-Dprefix=<path>`
at the parent directory and the build will skip compiling BoringSSL
entirely — it just re-exports the existing archives behind the same
`b.dependency().artifact("ssl")` interface. Useful for:

- Local caching (one slow source build, many fast incremental ones)
- Pinning to a system-supplied or distro-supplied build
- Linking against a patched BoringSSL you maintain elsewhere

Layout expected at `<path>/`:

```
lib/
  libcrypto.a   (or crypto.lib  on -windows-msvc)
  libssl.a      (or ssl.lib     on -windows-msvc)
  libpki.a      (or pki.lib     on -windows-msvc)
include/openssl/*.h
```

Source mode and prefix mode produce the same `zig-out/` layout. In prefix
mode, link through the `link()` helper rather than `artifact(...)`:

```zig
const bssl = @import("boringssl");
bssl.link(exe_mod, boringssl_dep, .{ .ssl = true });
```

`link()` adds the prebuilt archives to your module directly. The
`artifact("crypto"|"ssl"|"pki")` wrappers only contain the prebuilt code on
Zig 0.16: Zig 0.17 stopped merging input archives into static libraries, and
Zig never forwards a dependency's archive *inputs* to the final link, so on
0.17 those wrappers are empty shells (the build prints a warning). `link()`
works on both.

### Windows note

For `x86_64-windows`, BoringSSL's perlasm output is in NASM syntax and Zig
does not bundle NASM. Build with `-Dasm=false` for a portable build (slower
crypto), or install NASM in `PATH` and the build will shell out to it. ARM
Windows uses GAS-format `.S` files and works without external tools.

`test-all` on `x86_64-windows-gnu` skips one upstream file,
`crypto/fipsmodule/ec/p256_test.cc`: its `#if` guard is looser than the one
on the SysV-only `fiat_p256_adx_*` asm it tests, so it does not compile on
mingw clang (see `filterTestSources` in `zig/build.zig`). The two tests it
holds are ABI checks of asm that is never built on COFF, so no coverage is
lost.

For `x86_64-windows-msvc`, **`crypto.lib`/`ssl.lib`/`pki.lib` build fine
and are usable from MSVC consumers**, but Zig 0.16's bundled libcxx
clashes with `<typeinfo>` from the MSVC SDK when linking a Zig-side
executable against them — a `using ::type_info;` collision via
libcxxabi's `cxa_exception.cpp`. Our CI builds `windows-msvc` but does
not run the smoke test there. C/C++ consumers using `cl.exe`/`link.exe`
do **not** hit this — they link the `.lib` files with the MSVC C++
runtime, which is what BoringSSL was designed for on Windows.

### FIPS mode build

`-Dfips=true` builds `libcrypto` the way upstream's `cmake -DFIPS=1` static
build does: `bcm.cc` (the BoringCrypto module) is compiled to assembly with
Zig's clang, run through upstream's `delocate` to merge the perlasm and
remove relocations, assembled, and the module's HMAC-SHA-256 is written in
by upstream's `inject_hash`. The result is a `libcrypto.a` whose
`FIPS_mode()` returns 1 and which runs the integrity check and the KAT
self-tests in a constructor before `main` (a failure aborts the process).

```sh
zig build -Dtarget=x86_64-linux-gnu -Dfips=true -Doptimize=ReleaseFast          # libs
zig build -Dtarget=x86_64-linux-gnu -Dfips=true -Doptimize=ReleaseFast smoke-fips  # + run the FIPS smoke test
```

**What this is and is not.** This is a *FIPS mode build from the update
stream*: the current upstream `main`, with all of BoringCrypto's FIPS
machinery enabled (`FIPS_mode()==1`, integrity check, power-on and
on-demand KATs, service indicator, CTR-DRBG seeded from the jitter/CPU
entropy source, `FIPS_version()==0`). It is **not a validated module** and
must not be described as "FIPS validated" or "certified". Validation binds
a specific source revision to a specific toolchain and the exact module
hash they produce; this module's hash comes from Zig's bundled clang and
is not covered by any certificate. See
[`crypto/fipsmodule/FIPS.md`](../crypto/fipsmodule/FIPS.md) for upstream's
validation history.

Requirements and limits:

- **Targets:** `x86_64-linux-*` and `aarch64-linux-*` only (delocate and
  inject_hash are ELF-specific). Any other target, `-Dasm=false`, or
  `-Dprefix` together with `-Dfips=true` makes the build **refuse with an
  error**; it never silently falls back to a non-FIPS libcrypto. A macOS
  host can cross-build a Linux FIPS module; the smoke test then has to run
  on Linux (CI does this).
- **Host tools:** `go` on `PATH` (the version in `go.mod` or newer). Go
  builds `util/fipstools/{delocate,inject_hash}` from this tree; nothing is
  downloaded. Perl is not needed (the perlasm output is pre-generated under
  `gen/`). Without `-Dfips` the build still needs only Zig.
- **The module is always `-O2`** regardless of `-Doptimize`; the rest of
  libcrypto follows `-Doptimize` as usual.
- **First `RAND_bytes` is slow** (several milliseconds: the CTR-DRBG is
  instantiated and seeded from the CPU jitter entropy source on first use;
  measured 5.6 ms / 8.5 ms / 30 ms on three different machines). Call
  `RAND_bytes` once at start-up so the cost does not land on the first
  request, as upstream's `crypto/fipsmodule/FIPS.md` ("RNG design") also
  recommends.
- `libssl` / `libpki` are built as normal, with `BORINGSSL_FIPS` defined
  like upstream does.
- `-Dprefix` prebuilt archives: a prefix produced by a `-Dfips=true` build is
  a FIPS libcrypto; consume it *without* `-Dfips` (the option only controls
  compilation). Keep FIPS and non-FIPS prefixes apart yourself.
- **Stripping:** the integrity check hashes the module's own text/rodata
  between symbols the delocated object defines, so a stripped executable
  still self-checks correctly. Upstream's `util/fipstools/break-hash.go`
  (which corrupts the module to prove the check fires) needs the symbol
  table, so run it on an unstripped binary.

From Zig, `@import("boringssl").fips_build` is a `comptime` bool telling a
consumer which kind of libcrypto it was built against, and
`bssl.c.FIPS_mode()`, `FIPS_module_name()`, `FIPS_module_hash()`,
`FIPS_version()`, `BORINGSSL_self_test_all()` (plus
`bssl.BORINGSSL_integrity_test` in FIPS builds) are declared in the wrapper.
`zig/smoke_fips.zig` is the reference usage.

#### Service indicator

FIPS 140-3 requires a module to *indicate* when a service was performed in
an approved manner. BoringCrypto does this with a per-thread counter that
approved services bump. Upstream unexported the C API for reading it in
2025 (`<openssl/service_indicator.h>` is now empty; the functions live in
`bssl::`), so this fork ships a tiny C++ shim, `zig/fips_indicator_shim.cc`,
compiled into every libcrypto, exporting `zbssl_fips_indicator_before()` /
`zbssl_fips_indicator_after()` with C linkage. The wrapper builds on it:

```zig
const bssl = @import("boringssl");
const r = bssl.fipsApproved(bssl.c.RAND_bytes, .{ &buf, buf.len });
// r.result == 1, r.approved == true (FIPS build)
const ind = bssl.Indicator.begin();
_ = bssl.c.EVP_AEAD_CTX_seal(...);   // generic AES-GCM, caller nonce
std.debug.assert(!ind.approved());    // external IV: not approved, by design
```

Two limits, both inherited from upstream's design, that you must know
before trusting a reading:

1. **In a non-FIPS build the counter is a stub**; `Indicator.approved()` is
   hard-wired to `false` there (`fips_build == false`) rather than let every
   call look approved.
2. **The counter is bumped by every hooked service, including internal
   calls.** A function with no hook of its own can still read "approved"
   because something it calls internally is hooked: `ED25519_sign` (via
   SHA-512), `MLKEM768_generate_key` / `MLKEM768_encap` (via the DRBG).
   These are false positives. Only services the module actually hooks can
   be judged by the counter; for everything else the honest answer is
   "not covered by the indicator", never "approved".

`zig build -Dfips=true indicator-report` (Linux) runs `zig/indicator_report.cc`,
which exercises the services an IKEv2/IPsec stack uses — AES-GCM in every
nonce mode, HMAC, EC keygen, ECDH, MODP/FFDHE DH, X25519, ML-KEM-768,
ECDSA/RSA signatures, `RAND_bytes` — and prints a Markdown table with the
measured indicator reading, whether the service is covered by a hook (with
the source location as evidence), and the resulting verdict. CI runs it on
Linux x86_64 and aarch64 and uploads the table as the `fips-report-*`
artifact. `zig/check-indicator-coverage.sh` (run by `zig/sync-upstream.sh`
and CI) re-derives the coverage facts from upstream source so the table
cannot silently go stale across syncs.

#### Break tests and benchmarks

`-Dfips-break-tests=true` (only with `-Dfips=true`) defines
`BORINGSSL_FIPS_BREAK_TESTS`, upstream's switch that makes the integrity
failure non-fatal so `util/fipstools/break-kat.go` can corrupt each KAT in
turn and show the module aborting on it. Never ship that build. FIPS builds
also install `fips-exercise` (`zig/fips_exercise.cc`, `zig build
fips-exercise`), which uses every algorithm family once: that is the binary
the KAT break tests need, because most KATs run lazily on first use and
`BORINGSSL_self_test_all()` only *returns* 0 on failure, whereas the lazy
path aborts. Upstream's own `util/fipstools/test_fips.cc` cannot be used
for this: it exits with "No module version set" because `FIPS_version()`
is hard-coded to 0 on upstream `main`. CI runs `break-hash.go` against
`smoke-fips` and `fips-exercise` (both must abort with `FIPS integrity test
failed`) and `break-kat.go` for every KAT against the break-tests build's
`fips-exercise`.

`zig build bench` (any build) prints the CPU model, first-`RAND_bytes`
latency (DRBG seeding; the jitter entropy path in FIPS builds) and
AES-256-GCM throughput on 1400-byte packets. CI runs it for both a FIPS and
a non-FIPS libcrypto and records cold build times and archive sizes next to
it in the same artifact. GitHub runners are shared VMs, so treat those
numbers as indicative; run `zig build bench` on your own hardware for
authoritative ones.

### Mobile platform support

#### Android — via the musl tarballs (no NDK required)

The two `linux-musl-{aarch64,x86_64}` prebuilt tarballs **work as
drop-ins for Android apps**, even though they were never built against
the NDK:

- The release-mode `.a` only references standard POSIX, C, pthread,
  and `operator new`/`operator delete` symbols. Android's Bionic libc
  + libc++ provide every one of them with the same C calling
  convention and (since they sit on the same Linux/AArch64 kernel ABI)
  the same syscall behavior.
- Build:

  ```sh
  # On any host that can do Zig cross-compile
  zig build -Dtarget=aarch64-linux-musl -Doptimize=ReleaseFast
  ```

- Link inside an Android NDK project: feed `libcrypto.a` / `libssl.a`
  to `ld` (or `add_library(... IMPORTED STATIC)`) like any other
  static lib. No NDK headers, no Zig build, no Rust toolchain on the
  consumer side.

Caveat: this is symbol-analysis correctness, not field-tested at
runtime on a device — if you do verify on a phone, please open an
issue with the result.

#### iOS — Xcode SDK still required

iOS lacks an equivalent "swap the libc" escape hatch: it's not Linux,
not Mach-O-compatible with macOS in the way the linker enforces, and
Zig 0.16/0.17 can't fully suppress its bundled libcxx headers even
with `link_libcpp = false` + `-nostdinc++`, so the SDK's libc++ never
wins the include ordering against Zig's. The `-Dsysroot` and
`applySysroot` plumbing in `build.zig` is ready — point it at
`$(xcrun --sdk iphoneos --show-sdk-path)` once Zig's `link_libcpp`
gets stricter and you should be unblocked. iOS prebuilt tarballs are
not in the current release.

#### `-Dsysroot=<path>` for bring-your-own-SDK

If you _do_ have a platform SDK and want the build to use it
(e.g. linking against system libraries on an embedded board, or for
Android-with-NDK experimentation), the option is plumbed through:

```sh
zig build -Dtarget=<triple> -Dsysroot=<path-to-sysroot>
```

`applySysroot` in `build.zig` adds `<sysroot>/usr/include/c++/v1`,
`<sysroot>/usr/include`, and `<sysroot>/usr/lib` to the include/lib
search paths, plus an Android-specific
`<sysroot>/usr/include/<triple>/` tier where the NDK keeps
arch-specific headers. The wider toolchain compatibility issues
described above still apply.

## Prebuilt downloads

Each `v0.YYYYMMDD.0` tag triggers
[`prebuilt.yml`](../.github/workflows/prebuilt.yml), which uploads
per-target tarballs as assets on the corresponding GitHub Release:

```
boringssl-v0.YYYYMMDD.0-linux-x86_64.tar.gz        (glibc)
boringssl-v0.YYYYMMDD.0-linux-aarch64.tar.gz       (glibc)
boringssl-v0.YYYYMMDD.0-linux-musl-x86_64.tar.gz   (musl; doubles as Android x86_64)
boringssl-v0.YYYYMMDD.0-linux-musl-aarch64.tar.gz  (musl; doubles as Android aarch64)
boringssl-v0.YYYYMMDD.0-macos-aarch64.tar.gz
boringssl-v0.YYYYMMDD.0-windows-x86_64-gnu.tar.gz
boringssl-v0.YYYYMMDD.0-windows-x86_64-msvc.tar.gz
boringssl-v0.YYYYMMDD.0-windows-aarch64-gnu.tar.gz   (mingw ABI; MSVC ARM not yet, no runner)
boringssl-v0.YYYYMMDD.0-wasm32-wasi.tar.gz
SHA256SUMS
```

Layout inside each tarball:

```
boringssl-v0.YYYYMMDD.0-<target>/
├── lib/lib{crypto,ssl,pki}.a   (or .lib on -windows-msvc)
└── include/openssl/*.h
```

Verify with `shasum -a 256 -c SHA256SUMS`, then point a downstream
`-Dprefix=<extracted-dir>` at it (see [`-Dprefix`](#-dprefix-for-cached--system--patched-builds)
above).

## Build requirements

- **Zig 0.16+** (development tracks Zig nightly `0.17.0-dev.298+ad1b746e2`
  or newer; the `0.16.0` stable release also works).
- **Nothing else.** Go is *only* needed if you regenerate the files under
  `gen/`, which zoptia0boringssl never does at build time (they ship
  pre-generated upstream).

## Versioning

Tags follow `v0.YYYYMMDD.0`, where `YYYYMMDD` is the date of the upstream
BoringSSL commit that was merged. The `.0` patch component bumps for
build-system-only fixes between syncs (e.g., `v0.20260908.1`).

## Maintainer guide

Sync and release happen locally — there's no cron-driven server-side
automation. The flow is two commands you (or Claude Code) run in the
checkout, followed by a tag push that triggers `prebuilt.yml` server-side.

### Sync upstream and ship a release

```sh
# 1. Rebase the fork's single commit onto the latest upstream main
./zig/sync-upstream.sh

# 2. Validate against BoringSSL's own ~3500 C++ tests in release mode
zig build -Doptimize=ReleaseFast test-all

# 3. Bump the package version to the tag you are about to create and commit.
#    prebuilt.yml refuses to build a tag whose build.zig.zon .version differs
#    (Zig names fetched packages "<name>-<version>-<hash>", so a stale
#    .version makes two releases look alike in consumers' caches).
TAG="v0.$(date -u +%Y%m%d).0"
sed -i '' "s/\.version = \"[^\"]*\"/.version = \"${TAG#v}\"/" build.zig.zon   # macOS sed; GNU: sed -i
git commit -am "release: bump version to ${TAG#v} after upstream sync"

# 4. Push main. The fork is one commit on top of upstream/main, so every
#    sync rewrites it: a force push is expected here.
git push --force-with-lease origin main

# 5. Tag and push — this triggers prebuilt.yml on GitHub
git tag -a "$TAG" -m "Sync upstream BoringSSL $(date -u +%Y-%m-%d)"
git push origin "$TAG"
```

`main` is always `upstream/main` plus **one** commit holding everything the
fork adds ("patch on top"), so the fork's entire delta is that one commit:

```sh
git diff --stat upstream/main HEAD          # every file the fork adds or changes
git log upstream/main..HEAD                 # exactly one commit
```

`zig/sync-upstream.sh` is idempotent: it adds an `upstream` remote on
first run if not present, then `git fetch upstream && git rebase upstream/main`.
Conflicts are rare — everything we own lives under `zig/` or under names
upstream doesn't use (`build.zig`, `build.zig.zon`, `CLAUDE.md`,
`.github/workflows/{ci,prebuilt}.yml`); the only shared file is `.gitignore`,
where we append two lines. Keep the fork at one commit: amend or squash
fix-ups into it before pushing. Because the commit is rewritten on every
sync, consumers should pin a **tag**, not a `main` hash.

#### Fresh clones on a new machine

Git remotes live in the local `.git/config` and are **not** cloned with the
repo, so a fresh `git clone` only has `origin` — there is no `upstream`. You
do **not** need to add it by hand: the upstream URL is baked into
`zig/sync-upstream.sh` (the `UPSTREAM_URL` variable), and the script adds
the remote automatically on its first run. Just run `./zig/sync-upstream.sh`
on any new checkout and syncing works. (Git has no mechanism to ship a remote
inside the repository itself, which is exactly why the URL lives in the
script rather than in git config.)

### What `prebuilt.yml` does after the tag push

| Trigger | Action |
|---|---|
| `git push origin v0.*` | GitHub runs `prebuilt.yml`, which checks out the *tag* (not main HEAD), builds 9 target tarballs in `ReleaseFast`, runs `test-all` on every native runner, and uploads them + `SHA256SUMS` as assets on the GitHub Release for that tag |
| `workflow_dispatch` (manual UI / `gh workflow run`) | Same, but you specify the tag — useful for back-filling an old tag |

If any native job's `test-all` fails, that target's tarball isn't staged
and the publish job's dependency fails — the broken artifact never lands
on the release.

### Why this and not GitHub-side automation

Earlier the repo had `sync-upstream.yml` (weekly cron, PR + auto-tag) and
`auto-tag.yml`. They were removed because:

- Local validation runs the full `zig build test-all` on the host where
  you'd actually catch a regression first, before any commit hits CI.
- `gh pr create` from `GITHUB_TOKEN` doesn't trigger pre-merge CI
  (GitHub's anti-recursion protection), so the server-side path either
  needed a PAT or shipped without CI gating.
- For a fork this size, "run two commands and push a tag" is faster than
  reviewing an auto-generated PR.

The git workflow is still standard: `git fetch upstream && git rebase upstream/main`
is what `zig/sync-upstream.sh` does, so any contributor can run it by hand.

### When a sync breaks the build

Triage in this order:

1. `gen/sources.json` schema changed → fix the parser at the top of
   `zig/build.zig`.
2. New top-level directory in upstream that holds build inputs → add it
   to `build.zig.zon`'s `.paths`.
3. New compile flag required → mirror it from `CMakeLists.txt`.
4. Merge conflict on a file we own → resolve in our favor.
5. Unfixable in one sitting → `git reset --hard ORIG_HEAD`, file an issue,
   ship the previous good tree.

## Project layout

```
zoptia0boringssl/
├── README.md             # upstream BoringSSL README (untouched)
├── LICENSE               # upstream BoringSSL license (untouched)
├── build.zig             # thin: forwards to zig/build.zig (Zig needs it at the root)
├── build.zig.zon         # package manifest
├── CLAUDE.md             # one line: @zig/CLAUDE.md
├── .gitignore            # upstream's, plus zig-out/ and .zig-cache/
├── zig/                  # everything the fork adds
│   ├── build.zig         # parses gen/sources.json, builds libcrypto/libssl/libpki
│   ├── root.zig          # minimal Zig wrapper module
│   ├── smoke.zig         # links libssl, calls RAND_bytes
│   ├── sync-upstream.sh  # git fetch upstream && git rebase upstream/main
│   ├── README.md         # this file
│   ├── LICENSE           # MIT license for the build system
│   └── CLAUDE.md         # internal project spec
├── .github/workflows/
│   ├── ci.yml            # build + test-all on every push / PR
│   └── prebuilt.yml      # per-target tarballs on v0.* tag push
└── (full BoringSSL source tree at the root: crypto/, ssl/, pki/,
   include/, gen/, third_party/, util/, …)
```

## License

The build system and supporting files in this repository (`zig/`, the root
`build.zig` / `build.zig.zon`, `.github/workflows/{ci,prebuilt}.yml`) are
MIT-licensed; see [`zig/LICENSE`](LICENSE).

The vendored BoringSSL source retains its own licensing — see
[`LICENSE`](../LICENSE).
