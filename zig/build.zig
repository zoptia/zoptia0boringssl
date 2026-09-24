// zoptia0boringssl — pure Zig build for Google's BoringSSL.
//
// This repo is a fork of google/boringssl: upstream files live at the repo
// root, and everything the fork adds lives under zig/ (this file, the wrapper
// module, the smoke test, the sync script, docs). The root build.zig only
// forwards here, because Zig requires it at the package root. Upstream sync
// is plain `git merge upstream/main`.
//
// We never duplicate BoringSSL's source lists. Instead, we parse the
// upstream-published manifest at gen/sources.json at build time.
//
// Schema (top-level keys we use): "bcm", "crypto", "ssl", "pki".
// Each has: { srcs: [...], hdrs: [...], internal_hdrs: [...],
//            asm: [...], nasm: [...] }.
//
// Asm filename suffixes encode platform: -apple.S, -linux.S, -win.S, -win.asm.
// Each .S file also carries `#if defined(OPENSSL_<arch>) && defined(__<os>__)`
// guards, so it is safe to feed the C preprocessor a file for the wrong arch
// — the result is an empty translation unit. We still filter by OS suffix to
// avoid wasted compile work.

const std = @import("std");

const sources_json = @embedFile("../gen/sources.json");

const SourceSet = struct {
    srcs: []const []const u8 = &.{},
    hdrs: []const []const u8 = &.{},
    internal_hdrs: []const []const u8 = &.{},
    asm_files: []const []const u8 = &.{},
    nasm_files: []const []const u8 = &.{},
};

const Sources = struct {
    arena: std.heap.ArenaAllocator,
    bcm: SourceSet,
    crypto: SourceSet,
    ssl: SourceSet,
    pki: SourceSet,
    test_support: SourceSet,
    crypto_test: SourceSet,
    ssl_test: SourceSet,
    pki_test: SourceSet,
    urandom_test: SourceSet,
};

fn parseSources(gpa: std.mem.Allocator) !Sources {
    var arena = std.heap.ArenaAllocator.init(gpa);
    errdefer arena.deinit();
    const aalloc = arena.allocator();

    const Group = struct {
        srcs: ?[]const []const u8 = null,
        hdrs: ?[]const []const u8 = null,
        internal_hdrs: ?[]const []const u8 = null,
        data: ?[]const []const u8 = null,
        @"asm": ?[]const []const u8 = null,
        nasm: ?[]const []const u8 = null,
    };
    const Schema = struct {
        bcm: ?Group = null,
        crypto: ?Group = null,
        ssl: ?Group = null,
        pki: ?Group = null,
        test_support: ?Group = null,
        crypto_test: ?Group = null,
        ssl_test: ?Group = null,
        pki_test: ?Group = null,
        urandom_test: ?Group = null,
    };

    const parsed = try std.json.parseFromSliceLeaky(
        Schema,
        aalloc,
        sources_json,
        .{ .ignore_unknown_fields = true, .allocate = .alloc_always },
    );

    const conv = struct {
        fn pick(g: ?Group) SourceSet {
            const gv = g orelse return .{};
            return .{
                .srcs = gv.srcs orelse &.{},
                .hdrs = gv.hdrs orelse &.{},
                .internal_hdrs = gv.internal_hdrs orelse &.{},
                .asm_files = gv.@"asm" orelse &.{},
                .nasm_files = gv.nasm orelse &.{},
            };
        }
    };

    return .{
        .arena = arena,
        .bcm = conv.pick(parsed.bcm),
        .crypto = conv.pick(parsed.crypto),
        .ssl = conv.pick(parsed.ssl),
        .pki = conv.pick(parsed.pki),
        .test_support = conv.pick(parsed.test_support),
        .crypto_test = conv.pick(parsed.crypto_test),
        .ssl_test = conv.pick(parsed.ssl_test),
        .pki_test = conv.pick(parsed.pki_test),
        .urandom_test = conv.pick(parsed.urandom_test),
    };
}

/// Returns the OS-suffix of a perlasm-generated .S file: "apple", "linux",
/// "win", or null if the filename doesn't follow the convention (these are
/// hand-written .S files that carry their own arch guards and are always
/// safe to include).
fn asmOsSuffix(path: []const u8) ?[]const u8 {
    const base = std.fs.path.basename(path);
    const stem = if (std.mem.lastIndexOfScalar(u8, base, '.')) |i| base[0..i] else base;
    inline for (.{ "apple", "linux", "win" }) |suffix| {
        const tag = "-" ++ suffix;
        if (std.mem.endsWith(u8, stem, tag)) return suffix;
    }
    return null;
}

fn osSuffixFor(target: std.Target) ?[]const u8 {
    return switch (target.os.tag) {
        .macos, .ios, .tvos, .watchos, .visionos => "apple",
        .windows => "win",
        .linux,
        .freebsd,
        .openbsd,
        .netbsd,
        .dragonfly,
        .illumos,
        .haiku,
        .fuchsia,
        => "linux",
        else => null,
    };
}

fn collectAsm(
    b: *std.Build,
    target: std.Target,
    use_nasm: bool,
    sets: []const SourceSet,
) std.ArrayList([]const u8) {
    var list: std.ArrayList([]const u8) = .empty;
    if (use_nasm) {
        for (sets) |s| for (s.nasm_files) |f| list.append(b.allocator, f) catch @panic("OOM");
        return list;
    }
    const want_os = osSuffixFor(target);
    for (sets) |s| for (s.asm_files) |f| {
        if (asmOsSuffix(f)) |suf| {
            if (want_os == null or !std.mem.eql(u8, suf, want_os.?)) continue;
        }
        list.append(b.allocator, f) catch @panic("OOM");
    };
    return list;
}

fn baseCxxFlags(b: *std.Build, target: std.Target, asm_disabled: bool, no_cxx_runtime: bool, sysroot: ?[]const u8, fips: bool, fips_break_tests: bool) []const []const u8 {
    var list: std.ArrayList([]const u8) = .empty;
    list.appendSlice(b.allocator, &.{
        "-std=c++17",
        "-fno-strict-aliasing",
        "-fno-common",
        "-fvisibility=hidden",
        "-DBORINGSSL_IMPLEMENTATION",
    }) catch @panic("OOM");
    // Upstream applies this globally (add_definitions) in a FIPS build: it
    // turns on FIPS_mode(), the self tests, the service indicator, and the
    // CTR-DRBG/jitter entropy path in every translation unit, not just bcm.
    if (fips) list.append(b.allocator, "-DBORINGSSL_FIPS") catch @panic("OOM");
    // Upstream: cmake -DFIPS_BREAK_TEST=TESTS -> -DBORINGSSL_FIPS_BREAK_TESTS=1
    // (integrity failure non-fatal, KATs breakable via break-kat.go / env var).
    if (fips_break_tests) list.append(b.allocator, "-DBORINGSSL_FIPS_BREAK_TESTS=1") catch @panic("OOM");
    // When -Dsysroot is in play, suppress clang's default C++ stdlib include
    // path so the SDK's libc++ (added via addSystemIncludePath in
    // applySysroot) wins. We keep `-nostdlibinc` off because it would also
    // strip clang's resource-dir builtins (stdarg.h, stddef.h, _LIBCPP
    // helper macros), which the SDK's stdlib.h transitively needs.
    if (sysroot != null) {
        list.append(b.allocator, "-nostdinc++") catch @panic("OOM");
    }
    // BoringSSL upstream CMake applies `-fno-exceptions -fno-rtti` only to the
    // crypto (bcm + libcrypto) target; ssl and pki are built with the default
    // C++ runtime so their classes emit typeinfo. Mirroring that matters when
    // test binaries inherit from ssl/pki classes (e.g. pki_test extending
    // bssl::SimplePathBuilderDelegate) — the derived typeinfo needs the base
    // typeinfo to exist.
    if (no_cxx_runtime) list.appendSlice(b.allocator, &.{
        "-fno-exceptions",
        "-fno-rtti",
    }) catch @panic("OOM");
    if (asm_disabled) list.append(b.allocator, "-DOPENSSL_NO_ASM") catch @panic("OOM");
    switch (target.os.tag) {
        .windows => list.appendSlice(b.allocator, &.{
            // Mirror BoringSSL's Windows defines: keep windows.h slim and
            // prevent symbol collisions with wincrypt.h (X509_NAME, etc.).
            "-DWIN32_LEAN_AND_MEAN",
            "-DNOMINMAX",
            "-D_CRT_SECURE_NO_WARNINGS",
            "-D_HAS_EXCEPTIONS=0",
        }) catch @panic("OOM"),
        .linux => list.append(b.allocator, "-D_XOPEN_SOURCE=700") catch @panic("OOM"),
        else => {},
    }
    // WASM/WASI lacks BSD sockets. The socket-using BIOs are wrapped in
    // `#if !defined(OPENSSL_NO_SOCK)` upstream, so disable them globally
    // for WASM targets to avoid undeclared-identifier errors.
    if (target.cpu.arch.isWasm()) {
        list.appendSlice(b.allocator, &.{
            "-DOPENSSL_NO_SOCK",
            "-DOPENSSL_NO_THREADS_CORRUPT_MEMORY_AND_LEAK_SECRETS_IF_THREADED",
        }) catch @panic("OOM");
    }
    return list.toOwnedSlice(b.allocator) catch @panic("OOM");
}

const asm_flags: []const []const u8 = &.{
    "-DBORINGSSL_IMPLEMENTATION",
};

const Libs = struct {
    /// True when crypto is the delocated FIPS module build (-Dfips=true).
    fips: bool = false,
    fips_break_tests: bool = false,
    crypto: *std.Build.Step.Compile,
    /// null when built with -Dssl=false.
    ssl: ?*std.Build.Step.Compile,
    /// null when built with -Dpki=false (or if upstream ever drops pki/).
    pki: ?*std.Build.Step.Compile,
};

pub const LinkOptions = struct {
    /// Link libssl (which pulls in libcrypto). false links libcrypto only.
    ssl: bool = true,
    /// Also link libpki.
    pki: bool = false,
};

/// Link BoringSSL into a consumer module. `dep` is the result of
/// `b.dependency("boringssl", .{ ... })`. Headers under <openssl/...> become
/// visible to `mod`; no addIncludePath needed.
///
///     const bssl = @import("boringssl"); // this build.zig, by dependency name
///     bssl.link(exe_mod, boringssl_dep, .{ .ssl = true });
///
/// In source mode this is `mod.linkLibrary(dep.artifact(...))`. In -Dprefix
/// mode it adds the prebuilt archives to `mod` directly: Zig only forwards a
/// dependency's *own* emitted archive to the final link, and since 0.17 a
/// static library no longer absorbs archives given as inputs, so the
/// `artifact()` wrappers are empty there. Prefer this helper over
/// `artifact()` whenever -Dprefix may be in play.
///
/// Library authors should NOT call this: take the `boringssl` module as an
/// import and let the final executable link (see zig/README.md).
pub fn link(mod: *std.Build.Module, dep: *std.Build.Dependency, opts: LinkOptions) void {
    if (prefixPathsOf(dep.builder)) |paths| {
        linkPrefixArchives(mod, paths, opts);
        return;
    }
    if (opts.pki) mod.linkLibrary(dep.artifact("pki"));
    mod.linkLibrary(dep.artifact(if (opts.ssl) "ssl" else "crypto"));
}

/// Named lazy paths registered by build() in -Dprefix mode so link() can
/// reach the prebuilt archives from a consumer's build.zig.
const PrefixPaths = struct {
    include: std.Build.LazyPath,
    crypto: std.Build.LazyPath,
    ssl: ?std.Build.LazyPath,
    pki: ?std.Build.LazyPath,
};

const prefix_names = .{
    .include = "boringssl-prefix-include",
    .crypto = "boringssl-prefix-libcrypto",
    .ssl = "boringssl-prefix-libssl",
    .pki = "boringssl-prefix-libpki",
};

fn prefixPathsOf(b: *std.Build) ?PrefixPaths {
    return .{
        .include = b.named_lazy_paths.get(prefix_names.include) orelse return null,
        .crypto = b.named_lazy_paths.get(prefix_names.crypto) orelse return null,
        .ssl = b.named_lazy_paths.get(prefix_names.ssl),
        .pki = b.named_lazy_paths.get(prefix_names.pki),
    };
}

fn linkPrefixArchives(mod: *std.Build.Module, paths: PrefixPaths, opts: LinkOptions) void {
    // Archive order matters for single-pass linkers: dependents first.
    if (opts.pki) mod.addObjectFile(paths.pki orelse @panic("boringssl: -Dpki=false, no libpki to link"));
    if (opts.ssl) mod.addObjectFile(paths.ssl orelse @panic("boringssl: -Dssl=false, no libssl to link"));
    mod.addObjectFile(paths.crypto);
    mod.addIncludePath(paths.include);
    // What the source-mode artifacts would have carried along.
    mod.link_libc = true;
    mod.link_libcpp = true;
    if (mod.resolved_target) |rt| {
        if (rt.result.os.tag == .windows) {
            mod.linkSystemLibrary("ws2_32", .{});
            mod.linkSystemLibrary("advapi32", .{});
        }
    }
}

/// Resolve a path that may be absolute (user-supplied prefix) or relative
/// (anything inside the package). `b.path` only accepts relative paths.
fn lazyPath(b: *std.Build, p: []const u8) std.Build.LazyPath {
    if (std.fs.path.isAbsolute(p)) return .{ .cwd_relative = b.dupe(p) };
    return b.path(p);
}

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const enable_asm = b.option(bool, "asm", "Include perlasm-generated assembly (default: true)") orelse true;
    const enable_ssl = b.option(bool, "ssl", "Build and install libssl (default: true)") orelse true;
    const enable_pki = b.option(bool, "pki", "Build and install libpki (default: true)") orelse true;
    const enable_fips = b.option(
        bool,
        "fips",
        "Build libcrypto as a FIPS module (update stream — NOT a validated module): " ++
            "bcm.cc goes through upstream's delocate + inject_hash so FIPS_mode()==1 and " ++
            "the integrity/KAT self-tests run at startup. Linux x86_64/aarch64 only; " ++
            "needs `go` on PATH. (default: false)",
    ) orelse false;
    const fips_break_tests = b.option(
        bool,
        "fips-break-tests",
        "With -Dfips=true: define BORINGSSL_FIPS_BREAK_TESTS so the integrity check " ++
            "is non-fatal and util/fipstools/break-kat.go can demonstrate each KAT " ++
            "failing. For break testing only — never ship this build. (default: false)",
    ) orelse false;
    const prefix = b.option(
        []const u8,
        "prefix",
        "Use prebuilt libcrypto/libssl/libpki from <path>/lib + <path>/include " ++
            "instead of compiling from source. Useful for caching, system installs, " ++
            "or testing a patched build.",
    );
    const sysroot = b.option(
        []const u8,
        "sysroot",
        "SDK sysroot for targets where Zig doesn't bundle libc/headers — iOS " ++
            "(xcrun --sdk iphoneos --show-sdk-path) or Android NDK " ++
            "(<NDK>/toolchains/llvm/prebuilt/<host>/sysroot). " ++
            "Ignored when -Dprefix is used.",
    );

    var sources = parseSources(b.allocator) catch |err| {
        std.debug.panic("failed to parse gen/sources.json: {t}", .{err});
    };
    _ = &sources;

    if (fips_break_tests and !enable_fips) {
        std.debug.print("error: -Dfips-break-tests=true requires -Dfips=true\n", .{});
        std.process.exit(1);
    }
    if (enable_fips) {
        if (fipsUnsupportedReason(b, target.result, enable_asm, prefix != null)) |why| {
            // Refuse loudly: a silent fallback to a non-FIPS libcrypto would let a
            // consumer that asked for FIPS ship without it.
            std.debug.print("error: -Dfips=true is not supported here: {s}\n", .{why});
            std.process.exit(1);
        }
    }

    const want = LibSelection{ .ssl = enable_ssl, .pki = enable_pki, .fips = enable_fips, .fips_break_tests = fips_break_tests };
    const libs = if (prefix) |p|
        buildFromPrefix(b, target, optimize, p, want)
    else
        buildFromSource(b, target, optimize, enable_asm, sysroot, &sources, want);

    // In prefix mode, expose the prebuilt archives to consumers' build.zig
    // (see link()). The artifact() wrappers only carry the archive's code on
    // Zig 0.16; 0.17 stopped merging input archives into static libraries.
    if (prefix) |p| {
        b.addNamedLazyPath(prefix_names.include, lazyPath(b, b.pathJoin(&.{ p, "include" })));
        b.addNamedLazyPath(prefix_names.crypto, prebuiltArchivePath(b, target.result, p, "crypto"));
        if (libs.ssl != null) b.addNamedLazyPath(prefix_names.ssl, prebuiltArchivePath(b, target.result, p, "ssl"));
        if (libs.pki != null) b.addNamedLazyPath(prefix_names.pki, prebuiltArchivePath(b, target.result, p, "pki"));
        if (@import("builtin").zig_version.minor >= 17) {
            std.log.warn("-Dprefix on Zig 0.17+: link via the link() helper from this package's build.zig; " ++
                "artifact(\"crypto\"/\"ssl\"/\"pki\") wrappers do not contain the prebuilt code on this Zig version", .{});
        }
    }

    // -------- public Zig wrapper module --------
    //
    // BoringSSL's headers cannot be reliably translated by `zig translate-c`
    // (the macro-heavy DEFINE_STACK_OF defeats the C importer). The wrapper
    // therefore exposes only hand-written extern declarations — see
    // zig/root.zig — and consumers add more as they need them.
    //
    // The module deliberately links nothing. A library can take it as an
    // import without being forced into a particular BoringSSL build; the
    // final executable links `artifact("ssl")` / `artifact("crypto")` (or
    // calls `link()` above), which also carries the <openssl/...> headers.
    const mod = b.addModule("boringssl", .{
        .root_source_file = b.path("zig/root.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    // Compile-time facts about this build, readable as
    // `@import("boringssl").fips_build` etc.
    const build_options = b.addOptions();
    build_options.addOption(bool, "fips", enable_fips);
    mod.addOptions("build_options", build_options);

    // -------- smoke test --------
    //
    // Links the way a consumer executable does: the declarations-only module
    // as an import, plus the library artifact on the executable's module.
    const smoke_mod = b.createModule(.{
        .root_source_file = b.path("zig/smoke.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    smoke_mod.addImport("boringssl", mod);
    if (prefixPathsOf(b)) |paths| {
        linkPrefixArchives(smoke_mod, paths, .{ .ssl = libs.ssl != null });
    } else {
        smoke_mod.linkLibrary(libs.ssl orelse libs.crypto);
    }
    const smoke = b.addExecutable(.{
        .name = "smoke",
        .root_module = smoke_mod,
    });

    const run_smoke = b.addRunArtifact(smoke);
    const test_step = b.step("test", "Build, install, and run the smoke test");
    test_step.dependOn(b.getInstallStep());
    test_step.dependOn(&run_smoke.step);

    // -------- FIPS smoke test (only exists with -Dfips=true) --------
    //
    // Asserts FIPS_mode()==1 and BORINGSSL_self_test_all()==1 against the
    // freshly built module and prints its name, version and hash. Linking it
    // statically is exactly how a consumer would, so this also proves the
    // integrity check survives the final link.
    if (enable_fips) {
        const sf_mod = b.createModule(.{
            .root_source_file = b.path("zig/smoke_fips.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        });
        sf_mod.addImport("boringssl", mod);
        sf_mod.linkLibrary(libs.crypto);
        const smoke_fips = b.addExecutable(.{ .name = "smoke-fips", .root_module = sf_mod });
        b.installArtifact(smoke_fips);
        const run_sf = b.addRunArtifact(smoke_fips);
        const sf_step = b.step("smoke-fips", "Build, install, and run the FIPS smoke test (needs -Dfips=true)");
        sf_step.dependOn(b.getInstallStep());
        sf_step.dependOn(&run_sf.step);

        // indicator-report: probe the services a downstream uses and print a
        // Markdown table of what the FIPS service indicator says (zig/indicator_report.cc).
        const report = addCxxTool(b, target, optimize, "indicator-report", "zig/indicator_report.cc", libs.crypto, .{ .install = true, .fips = true });
        const run_report = b.addRunArtifact(report);
        const report_step = b.step("indicator-report", "Run the FIPS service-indicator probe and print a Markdown report (needs -Dfips=true)");
        report_step.dependOn(&run_report.step);

        // fips-exercise: uses every algorithm family once so the lazily-run
        // KATs are triggered; a KAT corrupted by break-kat.go then makes the
        // module abort (BORINGSSL_self_test_all() would merely return 0).
        // Upstream's util/fipstools/test_fips.cc cannot serve here: it exits
        // on FIPS_version()==0, which upstream main hard-codes.
        const exercise = addCxxTool(b, target, optimize, "fips-exercise", "zig/fips_exercise.cc", libs.crypto, .{ .install = true, .fips = true });
        const run_exercise = b.addRunArtifact(exercise);
        const exercise_step = b.step("fips-exercise", "Run every algorithm family once against the FIPS module (triggers the lazy KATs)");
        exercise_step.dependOn(&run_exercise.step);
    }

    // bench: first-RAND_bytes latency and AES-256-GCM throughput; available in
    // every build so a FIPS and a non-FIPS libcrypto can be compared. Not part
    // of the default install: a C++ executable does not link on
    // x86_64-windows-msvc (Zig's libcxx vs the MSVC SDK <typeinfo>), and the
    // default build must stay usable there.
    {
        const bench = addCxxTool(b, target, optimize, "bench", "zig/fips_bench.cc", libs.crypto, .{ .install = false, .fips = libs.fips });
        const run_bench = b.addRunArtifact(bench);
        const bench_step = b.step("bench", "Run zig/fips_bench.cc against this build's libcrypto");
        bench_step.dependOn(&run_bench.step);
    }

    // -------- BoringSSL upstream C++ test suite --------
    //
    // Only available in source mode (test_support / *_test sources live in the
    // upstream tree, not in any prefix install). Builds gtest, test_support,
    // then four test binaries (crypto/ssl/pki/urandom) linked against our
    // freshly-built .a's. Run them all via `zig build test-all`.
    if (prefix == null) {
        addUpstreamTests(b, target, optimize, enable_asm, &sources, libs);
    }
}

/// Which optional libraries to build (-Dssl / -Dpki). libcrypto is always built;
/// `fips` selects the delocated FIPS module build of it.
const LibSelection = struct { ssl: bool, pki: bool, fips: bool = false, fips_break_tests: bool = false };

fn buildFromSource(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    enable_asm: bool,
    sysroot: ?[]const u8,
    sources: *Sources,
    want: LibSelection,
) Libs {
    const t = target.result;
    // When -Dsysroot is set, headers/libs come from the SDK, not Zig's
    // bundle. We also disable Zig's bundled libc/libc++ so its includes
    // don't fight the SDK's (Apple `<math.h>` macros vs Zig libcxx
    // `<__math_constants_FP_*>` is the classic clash).
    const use_sdk = sysroot != null;
    const link_via_zig = !use_sdk;
    const applySysroot = struct {
        fn apply(mod: *std.Build.Module, sr: ?[]const u8, bb: *std.Build, tgt: std.Target) void {
            const s = sr orelse return;
            // C++ headers first so libc++ shadows the C-only entries.
            mod.addSystemIncludePath(.{ .cwd_relative = bb.pathJoin(&.{ s, "usr/include/c++/v1" }) });
            // The Android NDK splits arch-specific headers (e.g. <asm/types.h>
            // pulled in by <linux/types.h>) into usr/include/<triple>/. Same
            // for libs. Add those paths first so clang sees them before the
            // generic include/.
            if (tgt.os.tag == .linux and tgt.abi.isAndroid()) {
                const triple = bb.fmt("{s}-linux-android", .{@tagName(tgt.cpu.arch)});
                mod.addSystemIncludePath(.{ .cwd_relative = bb.pathJoin(&.{ s, "usr/include", triple }) });
                mod.addLibraryPath(.{ .cwd_relative = bb.pathJoin(&.{ s, "usr/lib", triple }) });
            }
            mod.addSystemIncludePath(.{ .cwd_relative = bb.pathJoin(&.{ s, "usr/include" }) });
            mod.addLibraryPath(.{ .cwd_relative = bb.pathJoin(&.{ s, "usr/lib" }) });
            // The SDK provides its own libc++ — record it on the module so
            // anything linking the produced lib pulls it in.
            mod.linkSystemLibrary("c++", .{});
        }
    }.apply;
    const is_win_x86_family = t.os.tag == .windows and (t.cpu.arch == .x86 or t.cpu.arch == .x86_64);
    const use_nasm = enable_asm and is_win_x86_family;
    // crypto (incl. bcm) is built with -fno-rtti -fno-exceptions to match
    // upstream. ssl and pki use a separate cflag set without those, so their
    // typeinfo gets emitted (test binaries depend on this).
    const crypto_cflags = baseCxxFlags(b, t, !enable_asm, true, sysroot, want.fips, want.fips_break_tests);
    const ssl_pki_cflags = baseCxxFlags(b, t, !enable_asm, false, sysroot, want.fips, want.fips_break_tests);

    // -------- libcrypto --------
    const crypto_mod = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .link_libc = link_via_zig,
        .link_libcpp = link_via_zig,
    });
    applySysroot(crypto_mod, sysroot, b, t);
    crypto_mod.addIncludePath(b.path("include"));
    crypto_mod.addCSourceFiles(.{
        .files = sources.crypto.srcs,
        .flags = crypto_cflags,
        .language = .cpp,
    });
    // Fork-owned C shim over the (now C++-only) service-indicator API, in
    // every build; see zig/fips_indicator_shim.cc.
    crypto_mod.addCSourceFile(.{ .file = b.path("zig/fips_indicator_shim.cc"), .flags = crypto_cflags, .language = .cpp });

    if (want.fips) {
        // The FIPS module: bcm.cc plus its assembly, delocated and hashed into
        // one relocatable object. Its asm must NOT also be compiled below.
        crypto_mod.addObjectFile(buildFipsModule(b, target, sources, crypto_cflags));
    } else {
        crypto_mod.addCSourceFiles(.{
            .files = sources.bcm.srcs,
            .flags = crypto_cflags,
            .language = .cpp,
        });
    }

    if (enable_asm) {
        const asm_sets: []const SourceSet = if (want.fips) &.{sources.crypto} else &.{ sources.crypto, sources.bcm };
        var asm_list = collectAsm(b, t, use_nasm, asm_sets);
        defer asm_list.deinit(b.allocator);
        if (asm_list.items.len > 0) {
            if (use_nasm) {
                addNasmObjects(b, crypto_mod, target, asm_list.items);
            } else {
                crypto_mod.addCSourceFiles(.{
                    .files = asm_list.items,
                    .flags = asm_flags,
                    .language = .assembly_with_preprocessor,
                });
            }
        }
        // Note for the win64 nasm path: upstream's fiat P-256 ADX field ops
        // (third_party/fiat/asm/fiat_p256_adx_*.S) are SysV-only and gated on
        // `__ELF__ || __APPLE__` in p256_64.h, so COFF builds never reference
        // them and need no substitute. zig/sync-upstream.sh warns if that
        // gate ever changes.
    }

    if (t.os.tag == .windows) {
        crypto_mod.linkSystemLibrary("ws2_32", .{});
        crypto_mod.linkSystemLibrary("advapi32", .{});
    }

    const crypto_lib = b.addLibrary(.{
        .name = "crypto",
        .linkage = .static,
        .root_module = crypto_mod,
    });
    crypto_lib.installHeadersDirectory(
        b.path("include"),
        "",
        .{ .include_extensions = &.{".h"} },
    );
    b.installArtifact(crypto_lib);

    // -------- libssl (optional: -Dssl) --------
    var ssl_lib_opt: ?*std.Build.Step.Compile = null;
    if (want.ssl) {
        const ssl_mod = b.createModule(.{
            .target = target,
            .optimize = optimize,
            .link_libc = link_via_zig,
            .link_libcpp = link_via_zig,
        });
        applySysroot(ssl_mod, sysroot, b, t);
        ssl_mod.addIncludePath(b.path("include"));
        ssl_mod.addCSourceFiles(.{
            .files = sources.ssl.srcs,
            .flags = ssl_pki_cflags,
            .language = .cpp,
        });
        ssl_mod.linkLibrary(crypto_lib);
        const ssl_lib = b.addLibrary(.{
            .name = "ssl",
            .linkage = .static,
            .root_module = ssl_mod,
        });
        // Re-export libcrypto's <openssl/...> headers so a module that only
        // links `ssl` can #include them. linkLibrary() does not propagate
        // headers transitively on its own.
        ssl_lib.installLibraryHeaders(crypto_lib);
        b.installArtifact(ssl_lib);
        ssl_lib_opt = ssl_lib;
    }

    // -------- libpki (optional: -Dpki; also absent if upstream drops it) --------
    var pki_lib_opt: ?*std.Build.Step.Compile = null;
    if (want.pki and sources.pki.srcs.len > 0) {
        const pki_mod = b.createModule(.{
            .target = target,
            .optimize = optimize,
            .link_libc = link_via_zig,
            .link_libcpp = link_via_zig,
        });
        applySysroot(pki_mod, sysroot, b, t);
        pki_mod.addIncludePath(b.path("include"));
        var pki_flags: std.ArrayList([]const u8) = .empty;
        pki_flags.appendSlice(b.allocator, ssl_pki_cflags) catch @panic("OOM");
        if (t.os.tag.isDarwin()) pki_flags.append(b.allocator, "-fno-aligned-new") catch @panic("OOM");
        pki_mod.addCSourceFiles(.{
            .files = sources.pki.srcs,
            .flags = pki_flags.items,
            .language = .cpp,
        });
        pki_mod.linkLibrary(crypto_lib);
        const pki_lib = b.addLibrary(.{
            .name = "pki",
            .linkage = .static,
            .root_module = pki_mod,
        });
        pki_lib.installLibraryHeaders(crypto_lib);
        b.installArtifact(pki_lib);
        pki_lib_opt = pki_lib;
    }

    return .{ .fips = want.fips, .fips_break_tests = want.fips_break_tests, .crypto = crypto_lib, .ssl = ssl_lib_opt, .pki = pki_lib_opt };
}

// =============================================================================
// FIPS module build (-Dfips=true)
// =============================================================================
//
// Mirrors upstream CMake's FIPS_DELOCATE path (CMakeLists.txt, "if(FIPS_DELOCATE)")
// and crypto/fipsmodule/FIPS.md "Static build":
//
//   bcm.cc --(zig c++ -S -fPIC)--> bcm.S            textual asm, single TU
//   bcm.S  --(zig ar)-----------> bcm.a             delocate wants it un-preprocessed
//   bcm.a + perlasm .S --(delocate)--> bcm-delocated.S   merges asm, kills relocations
//   bcm-delocated.S --(zig cc -c)--> bcm_hashunset.o
//   bcm_hashunset.o --(zig cc -shared -z undefs)--> bcm_relocated.so   sample link to hash
//   bcm_hashunset.o + bcm_relocated.so --(inject_hash)--> bcm.o        HMAC of the module written in
//
// delocate and inject_hash are upstream Go programs (util/fipstools/), built
// for the host with `go build`. Everything else is Zig's own clang/lld, so a
// macOS host can cross-produce a Linux FIPS module. The result is an
// "update stream" module (FIPS_version()==0): it runs the same integrity and
// KAT self-tests as a validated BoringCrypto build, but it is NOT a validated
// module — validation binds a specific source revision to a specific toolchain
// and resulting module hash, and this hash comes from Zig's clang.

/// Why -Dfips=true cannot be honoured for this configuration, or null if it can.
fn fipsUnsupportedReason(b: *std.Build, t: std.Target, enable_asm: bool, have_prefix: bool) ?[]const u8 {
    if (have_prefix) return "-Dprefix supplies prebuilt archives; a FIPS module must be built from source (drop -Dprefix, or prebuild with -Dfips=true and use that prefix without -Dfips)";
    if (!enable_asm) return "the FIPS module is built through delocate, which merges the perlasm assembly; -Dasm=false is not compatible";
    if (t.os.tag != .linux) return b.fmt("target OS is {s}; upstream's delocate/inject_hash static FIPS build is ELF/Linux only", .{@tagName(t.os.tag)});
    switch (t.cpu.arch) {
        .x86_64, .aarch64 => {},
        else => return b.fmt("target arch is {s}; delocate supports x86_64 and aarch64", .{@tagName(t.cpu.arch)}),
    }
    if (!hostHasGo(b)) return "`go` was not found on PATH; delocate and inject_hash (util/fipstools/) are Go programs";
    return null;
}

fn hostHasGo(b: *std.Build) bool {
    // Zig 0.17 changed findProgram to take an options struct.
    if (@hasDecl(std.Build, "FindProgramOptions")) {
        return b.findProgram(.{ .names = &.{"go"} }) != null;
    } else {
        _ = b.findProgram(&.{"go"}, &.{}) catch return false;
        return true;
    }
}

/// `go build` one of upstream's host tools. The Go sources are registered as
/// inputs so an upstream change to the tool rebuilds it instead of reusing a
/// cached binary.
fn goBuildTool(b: *std.Build, name: []const u8, pkg: []const u8, inputs: []const []const u8) std.Build.LazyPath {
    const run = b.addSystemCommand(&.{ "go", "build", "-trimpath", "-o" });
    const exe = run.addOutputFileArg(name);
    run.addArg(pkg);
    run.setCwd(b.path("."));
    run.setEnvironmentVariable("GOFLAGS", "-mod=mod");
    run.addFileInput(b.path("go.mod"));
    for (inputs) |f| run.addFileInput(b.path(f));
    return exe;
}

fn buildFipsModule(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    sources: *Sources,
    crypto_cflags: []const []const u8,
) std.Build.LazyPath {
    const t = target.result;
    const zig_exe = b.graph.zig_exe;
    const triple = b.fmt("{s}-{s}-{s}", .{ @tagName(t.cpu.arch), @tagName(t.os.tag), @tagName(t.abi) });
    const mcpu = target.query.serializeCpuAlloc(b.allocator) catch @panic("OOM");

    if (sources.bcm.srcs.len != 1) {
        std.debug.print("error: -Dfips: expected gen/sources.json \"bcm\".srcs to be the single bcm.cc translation unit, found {d} entries\n", .{sources.bcm.srcs.len});
        std.process.exit(1);
    }

    // Host tools. These are the upstream sources the tools are built from; the
    // list is for dependency tracking only (go resolves the packages itself).
    const delocate = goBuildTool(b, "delocate", "./util/fipstools/delocate", &.{
        "util/fipstools/delocate/delocate.go",
        "util/fipstools/delocate/delocate.peg.go",
        "util/fipstools/fipscommon/const.go",
        "util/ar/ar.go",
    });
    const inject_hash = goBuildTool(b, "inject_hash", "./util/fipstools/inject_hash", &.{
        "util/fipstools/inject_hash/inject_hash.go",
        "util/fipstools/fipscommon/const.go",
        "util/ar/ar.go",
    });

    // 1. bcm.cc -> textual assembly. Same cflags as the rest of libcrypto
    // (already includes -DBORINGSSL_FIPS, -fno-exceptions, -fno-rtti), plus
    // what upstream adds for this TU: -S, PIC, and no sanitizers (delocate
    // needs plain code). Always -O2: the module is hashed, a debug build of
    // it would only be a different, slower module.
    const compile = b.addSystemCommand(&.{
        zig_exe,                     "c++",
        "-target",                   triple,
        b.fmt("-mcpu={s}", .{mcpu}), "-O2",
        "-S",                        "-fPIC",
        "-fno-sanitize=all",         "-Wno-unused-command-line-argument",
    });
    compile.addArgs(crypto_cflags);
    compile.addPrefixedDirectoryArg("-I", b.path("include"));
    compile.addArg("-o");
    const bcm_s = compile.addOutputFileArg("bcm.S");
    compile.addFileArg(b.path(sources.bcm.srcs[0]));
    // Dependency tracking. bcm.cc is one TU that #includes ~120 .cc.inc and
    // header files; a Run step only sees its argv, so register the manifest's
    // header lists as inputs. (A -MD depfile is not an option: `zig c++`
    // switches to dependency-only mode when it sees -MF and drops the -S
    // output.) gen/sources.json covers everything bcm.cc pulls in; verify with
    // a recursive #include walk if that ever seems in doubt.
    for (sources.bcm.internal_hdrs) |f| compile.addFileInput(b.path(f));
    for (sources.crypto.internal_hdrs) |f| compile.addFileInput(b.path(f));
    for (sources.crypto.hdrs) |f| compile.addFileInput(b.path(f));

    // 2. Wrap in a single-member archive: delocate preprocesses loose inputs
    // with `cc -E`, which would mangle the compiler's `#`-comments.
    const ar = b.addSystemCommand(&.{ zig_exe, "ar", "--format=gnu", "rcs" });
    const bcm_a = ar.addOutputFileArg("bcm.a");
    ar.addFileArg(bcm_s);

    // 3. delocate. Perlasm inputs are the bcm asm files for this OS (each
    // carries its own arch guard, so the wrong-arch ones preprocess to
    // nothing, exactly like the non-FIPS build). `-cc` is Zig's clang, used
    // only as a preprocessor. The .h args tell delocate the -I roots.
    const deloc = std.Build.Step.Run.create(b, "delocate bcm");
    deloc.addFileArg(delocate);
    deloc.addArg("-a");
    deloc.addFileArg(bcm_a);
    deloc.addArg("-o");
    const delocated_s = deloc.addOutputFileArg("bcm-delocated.S");
    deloc.addArgs(&.{ "-cc", zig_exe, "-cc-flags", b.fmt("cc -target {s}", .{triple}) });
    var asm_list = collectAsm(b, t, false, &.{sources.bcm});
    defer asm_list.deinit(b.allocator);
    for (asm_list.items) |f| deloc.addFileArg(b.path(f));
    deloc.addFileArg(b.path("include/openssl/asm_base.h"));
    deloc.addFileArg(b.path("include/openssl/target.h"));

    // 4. Assemble.
    const assemble = b.addSystemCommand(&.{ zig_exe, "cc", "-target", triple, "-c", "-o" });
    const hashunset_o = assemble.addOutputFileArg("bcm_hashunset.o");
    assemble.addFileArg(delocated_s);

    // 5. Sample link. bcm_hashunset.o still has link-independent relocations
    // (to the redirectors); inject_hash hashes the module as it appears in a
    // linked image, so link a throwaway shared object with undefined symbols
    // allowed (upstream: `-Wl,-z,undefs`).
    const sample = b.addSystemCommand(&.{ zig_exe, "cc", "-target", triple, "-shared", "-nostdlib", "-Wl,-z,undefs", "-o" });
    const relocated_so = sample.addOutputFileArg("bcm_relocated.so");
    sample.addFileArg(hashunset_o);

    // 6. Inject the HMAC-SHA-256 of the module text/rodata into the object.
    const inject = std.Build.Step.Run.create(b, "inject_hash bcm");
    inject.addFileArg(inject_hash);
    inject.addArg("-o");
    const bcm_o = inject.addOutputFileArg("bcm.o");
    inject.addArg("-in-object");
    inject.addFileArg(hashunset_o);
    inject.addArg("-in-hash");
    inject.addFileArg(relocated_so);
    return bcm_o;
}

/// Build "libraries" that just re-export prebuilt archives from a user-supplied
/// install prefix. Layout expected at `<prefix>/`:
///   lib/lib{crypto,ssl,pki}.a       (Unix / MinGW)
///   lib/{crypto,ssl,pki}.lib        (MSVC)
///   include/openssl/*.h
fn buildFromPrefix(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    prefix: []const u8,
    want: LibSelection,
) Libs {
    const t = target.result;
    const inc = lazyPath(b, b.pathJoin(&.{ prefix, "include" }));

    const crypto = wrapPrebuiltLib(b, "crypto", target, optimize, prefix, inc);
    if (t.os.tag == .windows) {
        crypto.root_module.linkSystemLibrary("ws2_32", .{});
        crypto.root_module.linkSystemLibrary("advapi32", .{});
    }
    crypto.installHeadersDirectory(inc, "", .{ .include_extensions = &.{".h"} });
    b.installArtifact(crypto);

    var ssl: ?*std.Build.Step.Compile = null;
    if (want.ssl) {
        const lib = wrapPrebuiltLib(b, "ssl", target, optimize, prefix, inc);
        lib.root_module.linkLibrary(crypto);
        lib.installLibraryHeaders(crypto);
        b.installArtifact(lib);
        ssl = lib;
    }

    var pki: ?*std.Build.Step.Compile = null;
    if (want.pki) {
        const lib = wrapPrebuiltLib(b, "pki", target, optimize, prefix, inc);
        lib.root_module.linkLibrary(crypto);
        lib.installLibraryHeaders(crypto);
        b.installArtifact(lib);
        pki = lib;
    }

    return .{ .crypto = crypto, .ssl = ssl, .pki = pki };
}

/// `<prefix>/lib/lib<name>.a`, or `<name>.lib` on -windows-msvc.
fn prebuiltArchivePath(b: *std.Build, t: std.Target, prefix: []const u8, name: []const u8) std.Build.LazyPath {
    const archive_basename = if (t.os.tag == .windows and t.abi == .msvc)
        b.fmt("{s}.lib", .{name})
    else
        b.fmt("lib{s}.a", .{name});
    return lazyPath(b, b.pathJoin(&.{ prefix, "lib", archive_basename }));
}

fn wrapPrebuiltLib(
    b: *std.Build,
    name: []const u8,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    prefix: []const u8,
    include_path: std.Build.LazyPath,
) *std.Build.Step.Compile {
    const archive = prebuiltArchivePath(b, target.result, prefix, name);

    const mod = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .link_libcpp = true,
    });
    mod.addObjectFile(archive);
    mod.addIncludePath(include_path);
    return b.addLibrary(.{
        .name = name,
        .linkage = .static,
        .root_module = mod,
    });
}

fn addNasmObjects(
    b: *std.Build,
    mod: *std.Build.Module,
    target: std.Build.ResolvedTarget,
    files: []const []const u8,
) void {
    const nasm_format = switch (target.result.cpu.arch) {
        .x86 => "win32",
        .x86_64 => "win64",
        else => @panic("addNasmObjects: unsupported arch"),
    };
    for (files) |rel| {
        const src = b.path(rel);
        const stem = blk: {
            const base = std.fs.path.basename(rel);
            const dot = std.mem.lastIndexOfScalar(u8, base, '.') orelse base.len;
            break :blk base[0..dot];
        };
        const obj_name = b.fmt("{s}.obj", .{stem});
        const run = b.addSystemCommand(&.{ "nasm", "-f", nasm_format });
        run.addArg("-o");
        const obj = run.addOutputFileArg(obj_name);
        run.addFileArg(src);
        mod.addObjectFile(obj);
    }
}

// =============================================================================
// Upstream BoringSSL C++ test suite
// =============================================================================
//
// gtest is vendored under third_party/googletest/. test_support, crypto_test,
// ssl_test, pki_test, urandom_test sources come from sources.json.
//
// The test code (unlike libcrypto/libssl/libpki) needs RTTI and exceptions
// because gtest does. We therefore use a separate cflag set without the
// -fno-rtti / -fno-exceptions BoringSSL builds itself with.

/// sources.json may list both .cc (C++) and .c (C) sources for a test group,
/// plus the occasional .c.inc / .h that is purely an #include fragment.
/// Split them so each compiles with the right language flag.
fn splitSourcesByLang(b: *std.Build, srcs: []const []const u8) struct {
    cpp: []const []const u8,
    c: []const []const u8,
} {
    var cpp: std.ArrayList([]const u8) = .empty;
    var c: std.ArrayList([]const u8) = .empty;
    for (srcs) |s| {
        if (std.mem.endsWith(u8, s, ".cc")) {
            cpp.append(b.allocator, s) catch @panic("OOM");
        } else if (std.mem.endsWith(u8, s, ".c")) {
            c.append(b.allocator, s) catch @panic("OOM");
        }
        // .c.inc / .h / etc. are include fragments; let them ride along
        // implicitly via the .cc files that #include them.
    }
    return .{
        .cpp = cpp.toOwnedSlice(b.allocator) catch @panic("OOM"),
        .c = c.toOwnedSlice(b.allocator) catch @panic("OOM"),
    };
}

fn baseTestCFlags(b: *std.Build, target: std.Target, fips: bool, fips_break_tests: bool) []const []const u8 {
    var list: std.ArrayList([]const u8) = .empty;
    list.appendSlice(b.allocator, &.{
        "-std=c11",
        "-fno-strict-aliasing",
        "-fno-common",
    }) catch @panic("OOM");
    if (fips) list.append(b.allocator, "-DBORINGSSL_FIPS") catch @panic("OOM");
    if (fips_break_tests) list.append(b.allocator, "-DBORINGSSL_FIPS_BREAK_TESTS=1") catch @panic("OOM");
    switch (target.os.tag) {
        .windows => list.appendSlice(b.allocator, &.{
            "-DWIN32_LEAN_AND_MEAN",
            "-DNOMINMAX",
            "-D_CRT_SECURE_NO_WARNINGS",
        }) catch @panic("OOM"),
        .linux => list.append(b.allocator, "-D_XOPEN_SOURCE=700") catch @panic("OOM"),
        else => {},
    }
    return list.toOwnedSlice(b.allocator) catch @panic("OOM");
}

fn baseTestCxxFlags(b: *std.Build, target: std.Target, fips: bool, fips_break_tests: bool) []const []const u8 {
    var list: std.ArrayList([]const u8) = .empty;
    list.appendSlice(b.allocator, &.{
        "-std=c++17",
        "-fno-strict-aliasing",
        "-fno-common",
    }) catch @panic("OOM");
    if (fips) list.append(b.allocator, "-DBORINGSSL_FIPS") catch @panic("OOM");
    if (fips_break_tests) list.append(b.allocator, "-DBORINGSSL_FIPS_BREAK_TESTS=1") catch @panic("OOM");
    switch (target.os.tag) {
        .windows => list.appendSlice(b.allocator, &.{
            "-DWIN32_LEAN_AND_MEAN",
            "-DNOMINMAX",
            "-D_CRT_SECURE_NO_WARNINGS",
        }) catch @panic("OOM"),
        .linux => list.append(b.allocator, "-D_XOPEN_SOURCE=700") catch @panic("OOM"),
        else => {},
    }
    return list.toOwnedSlice(b.allocator) catch @panic("OOM");
}

const CxxToolOptions = struct {
    /// Add to the default install step (only for tools that CI or a user
    /// needs on disk, e.g. to feed to break-kat.go).
    install: bool,
    /// Define BORINGSSL_FIPS for the tool's own TU (upstream test_fips.cc
    /// selects code paths on it).
    fips: bool,
};

/// A small C++ program linked against libcrypto (bench, indicator report,
/// upstream's test_fips). C++ runtime on; relative includes let it read
/// upstream internal headers (read-only).
fn addCxxTool(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    name: []const u8,
    src: []const u8,
    crypto: *std.Build.Step.Compile,
    opts: CxxToolOptions,
) *std.Build.Step.Compile {
    const mod = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .link_libcpp = true,
    });
    mod.addIncludePath(b.path("include"));
    const flags: []const []const u8 = if (opts.fips)
        &.{ "-std=c++17", "-fno-strict-aliasing", "-DBORINGSSL_FIPS" }
    else
        &.{ "-std=c++17", "-fno-strict-aliasing" };
    mod.addCSourceFile(.{ .file = b.path(src), .flags = flags, .language = .cpp });
    mod.linkLibrary(crypto);
    const exe = b.addExecutable(.{ .name = name, .root_module = mod });
    if (opts.install) b.installArtifact(exe);
    return exe;
}

fn addUpstreamTests(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    enable_asm: bool,
    sources: *Sources,
    libs: Libs,
) void {
    const t = target.result;
    const test_cxx_flags = baseTestCxxFlags(b, t, libs.fips, libs.fips_break_tests);
    const test_c_flags = baseTestCFlags(b, t, libs.fips, libs.fips_break_tests);

    // gtest static lib (vendored under third_party/googletest/).
    const gtest_mod = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .link_libcpp = true,
    });
    inline for (.{
        "third_party/googletest/googlemock/include",
        "third_party/googletest/googletest/include",
        "third_party/googletest/googlemock",
        "third_party/googletest/googletest",
    }) |p| gtest_mod.addIncludePath(b.path(p));
    gtest_mod.addCSourceFiles(.{
        .files = &.{
            "third_party/googletest/googlemock/src/gmock-all.cc",
            "third_party/googletest/googletest/src/gtest-all.cc",
        },
        .flags = test_cxx_flags,
        .language = .cpp,
    });
    const gtest_lib = b.addLibrary(.{
        .name = "boringssl_gtest",
        .linkage = .static,
        .root_module = gtest_mod,
    });

    // test_support static lib.
    const ts_mod = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .link_libcpp = true,
    });
    ts_mod.addIncludePath(b.path("include"));
    ts_mod.addIncludePath(b.path("third_party/googletest/googletest/include"));
    ts_mod.addIncludePath(b.path("third_party/googletest/googlemock/include"));
    {
        const split = splitSourcesByLang(b, sources.test_support.srcs);
        ts_mod.addCSourceFiles(.{ .files = split.cpp, .flags = test_cxx_flags, .language = .cpp });
        if (split.c.len > 0) {
            ts_mod.addCSourceFiles(.{ .files = split.c, .flags = test_c_flags, .language = .c });
        }
    }
    if (enable_asm) {
        const is_win_x86_family = t.os.tag == .windows and (t.cpu.arch == .x86 or t.cpu.arch == .x86_64);
        const use_nasm = is_win_x86_family;
        var asm_list = collectAsm(b, t, use_nasm, &.{sources.test_support});
        defer asm_list.deinit(b.allocator);
        if (asm_list.items.len > 0) {
            if (use_nasm) {
                addNasmObjects(b, ts_mod, target, asm_list.items);
            } else {
                ts_mod.addCSourceFiles(.{
                    .files = asm_list.items,
                    .flags = asm_flags,
                    .language = .assembly_with_preprocessor,
                });
            }
        }
    }
    ts_mod.linkLibrary(gtest_lib);
    ts_mod.linkLibrary(libs.crypto);
    const ts_lib = b.addLibrary(.{
        .name = "boringssl_test_support",
        .linkage = .static,
        .root_module = ts_mod,
    });

    const test_all = b.step("test-all", "Build and run BoringSSL's C++ test suite linked to our libs");

    // crypto_test links libssl too when it is built (matches upstream CMake).
    const ssl_crypto: []const *std.Build.Step.Compile = if (libs.ssl) |ssl|
        b.allocator.dupe(*std.Build.Step.Compile, &.{ ssl, libs.crypto }) catch @panic("OOM")
    else
        b.allocator.dupe(*std.Build.Step.Compile, &.{libs.crypto}) catch @panic("OOM");
    addOneTest(b, target, optimize, "crypto_test", filterTestSources(b, t, sources.crypto_test.srcs), test_cxx_flags, test_c_flags, gtest_lib, ts_lib, ssl_crypto, test_all);
    if (libs.ssl != null) {
        addOneTest(b, target, optimize, "ssl_test", sources.ssl_test.srcs, test_cxx_flags, test_c_flags, gtest_lib, ts_lib, ssl_crypto, test_all);
    }
    if (libs.pki) |pki| {
        var deps = [_]*std.Build.Step.Compile{ pki, libs.crypto };
        addOneTest(b, target, optimize, "pki_test", sources.pki_test.srcs, test_cxx_flags, test_c_flags, gtest_lib, ts_lib, deps[0..], test_all);
    }
    if (t.os.tag == .linux) {
        addOneTest(b, target, optimize, "urandom_test", sources.urandom_test.srcs, test_cxx_flags, test_c_flags, gtest_lib, ts_lib, &.{libs.crypto}, test_all);
    }
}

/// Drop upstream test sources whose `#if` guard is looser than the guard on
/// the symbols they reference, so they cannot compile on some targets. This
/// is a per-target exclusion applied to the sources.json list, not a source
/// list of our own, and it keeps upstream files untouched.
///
/// - crypto/fipsmodule/ec/p256_test.cc on x86_64 COFF (windows-gnu / mingw
///   clang): the file is gated on `__GNUC__ && __x86_64__`, but the
///   fiat_p256_adx_{mul,sqr} it CHECK_ABI's are declared and assembled only
///   under `__ELF__ || __APPLE__` (p256_64.h, upstream 28950bf42), so it
///   references undeclared identifiers. Its two tests check the SysV ABI of
///   SysV-only asm, so nothing is lost on COFF. zig/sync-upstream.sh prints a
///   notice once upstream aligns the guard; remove the entry then.
fn filterTestSources(b: *std.Build, target: std.Target, srcs: []const []const u8) []const []const u8 {
    const drop_p256_abi_test = target.os.tag == .windows and target.cpu.arch == .x86_64;
    var out: std.ArrayList([]const u8) = .empty;
    for (srcs) |s| {
        if (drop_p256_abi_test and std.mem.eql(u8, s, "crypto/fipsmodule/ec/p256_test.cc")) continue;
        out.append(b.allocator, s) catch @panic("OOM");
    }
    return out.toOwnedSlice(b.allocator) catch @panic("OOM");
}

fn addOneTest(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    name: []const u8,
    srcs: []const []const u8,
    test_cxx_flags: []const []const u8,
    test_c_flags: []const []const u8,
    gtest_lib: *std.Build.Step.Compile,
    ts_lib: *std.Build.Step.Compile,
    extra_libs: []const *std.Build.Step.Compile,
    test_all: *std.Build.Step,
) void {
    const mod = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .link_libcpp = true,
    });
    mod.addIncludePath(b.path("include"));
    mod.addIncludePath(b.path("third_party/googletest/googletest/include"));
    mod.addIncludePath(b.path("third_party/googletest/googlemock/include"));

    const split = splitSourcesByLang(b, srcs);
    mod.addCSourceFiles(.{ .files = split.cpp, .flags = test_cxx_flags, .language = .cpp });
    if (split.c.len > 0) {
        mod.addCSourceFiles(.{ .files = split.c, .flags = test_c_flags, .language = .c });
    }

    mod.linkLibrary(ts_lib);
    mod.linkLibrary(gtest_lib);
    for (extra_libs) |l| mod.linkLibrary(l);

    // On Windows, BoringSSL's ABI test harness uses dbghelp for stack
    // walking / symbolization (SymFromAddr, SymInitialize, …). Not needed
    // on other platforms.
    if (target.result.os.tag == .windows) {
        mod.linkSystemLibrary("dbghelp", .{});
    }

    const exe = b.addExecutable(.{
        .name = name,
        .root_module = mod,
    });
    const run = b.addRunArtifact(exe);
    // Test data files (crypto/blake2/*_tests.txt, pki/testdata/*) are
    // referenced relative to the BoringSSL root; run with cwd = repo root.
    run.setCwd(b.path("."));
    test_all.dependOn(&run.step);
}
