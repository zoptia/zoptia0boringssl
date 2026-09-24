//! Minimal Zig wrapper for zoptia0boringssl.
//!
//! BoringSSL's headers are not directly translatable by Zig's `translate-c`
//! (the macro-heavy `DEFINE_STACK_OF` and friends defeat the C importer).
//! This module therefore exposes only hand-written extern declarations for
//! commonly-needed entry points. Consumers who need more should add their own
//! `extern fn` declarations against `<openssl/...>` — link with the artifact
//! and the symbols are available.
//!
//! This module links nothing by itself; the executable links the `crypto` /
//! `ssl` artifact (see zig/README.md, "For library authors").

const build_options = @import("build_options");

/// True when the linked libcrypto was built with `-Dfips=true`, i.e. bcm.cc
/// went through delocate + inject_hash and `FIPS_mode()` returns 1. This is
/// the "update stream" FIPS build, NOT a validated module (`FIPS_version()`
/// is 0). Known at compile time so consumers can `comptime` assert on it.
pub const fips_build: bool = build_options.fips;

pub const c = struct {
    /// Generate `len` cryptographically-secure random bytes into `buf`.
    /// Returns 1 on success, 0 on failure.
    pub extern fn RAND_bytes(buf: [*]u8, len: usize) c_int;

    /// Return the BoringSSL version string.
    pub extern fn OpenSSL_version(which: c_int) [*:0]const u8;

    // ---- FIPS (<openssl/crypto.h>) ----
    // All of these exist in every build; in a non-FIPS build FIPS_mode()
    // returns 0 and the self-test functions return 1 without testing.

    /// 1 if libcrypto was built as a FIPS module (BORINGSSL_FIPS), else 0.
    pub extern fn FIPS_mode() c_int;
    /// Returns 1 if `on` matches FIPS_mode(); the mode cannot be changed at runtime.
    pub extern fn FIPS_mode_set(on: c_int) c_int;
    /// Name of the FIPS module ("BoringCrypto").
    pub extern fn FIPS_module_name() [*:0]const u8;
    /// 32-byte HMAC-SHA-256 of the module as injected by inject_hash.
    pub extern fn FIPS_module_hash() [*]const u8;
    /// Version of a validated module, or 0 for an update-stream build like this one.
    pub extern fn FIPS_version() u32;
    /// 1 if `algorithm` is FIPS-approved in this build (see upstream for the names).
    pub extern fn FIPS_query_algorithm_status(algorithm: [*:0]const u8) c_int;
    /// Run the (cached) KAT self tests. Returns 1 on success.
    pub extern fn BORINGSSL_self_test() c_int;
    /// Run every KAT self test, uncached. Returns 1 on success.
    pub extern fn BORINGSSL_self_test_all() c_int;

    // ---- FIPS service indicator (zig/fips_indicator_shim.cc) ----
    // Upstream unexported the C API; the shim re-exports the bssl:: functions.
    // Read the counter before and after one call: if it moved, the module
    // counted an approved service. See `Indicator` / `fipsApproved` below for
    // the caveats.
    pub extern fn zbssl_fips_indicator_before() u64;
    pub extern fn zbssl_fips_indicator_after() u64;

    // ---- AEAD (<openssl/aead.h>), enough for the smoke test ----
    pub const EVP_AEAD = opaque {};
    /// Mirrors `struct evp_aead_ctx_st` in <openssl/aead.h> exactly.
    pub const EVP_AEAD_CTX = extern struct {
        aead: ?*const EVP_AEAD,
        state: extern union { @"opaque": [560]u8, alignment: u64 },
        tag_len: u8,
    };
    pub extern fn EVP_aead_aes_128_gcm() *const EVP_AEAD;
    pub extern fn EVP_aead_aes_256_gcm() *const EVP_AEAD;
    pub extern fn EVP_AEAD_CTX_zero(ctx: *EVP_AEAD_CTX) void;
    pub extern fn EVP_AEAD_CTX_init(ctx: *EVP_AEAD_CTX, aead: *const EVP_AEAD, key: [*]const u8, key_len: usize, tag_len: usize, impl: ?*anyopaque) c_int;
    pub extern fn EVP_AEAD_CTX_cleanup(ctx: *EVP_AEAD_CTX) void;
    pub extern fn EVP_AEAD_CTX_seal(ctx: *const EVP_AEAD_CTX, out: [*]u8, out_len: *usize, max_out_len: usize, nonce: [*]const u8, nonce_len: usize, in: [*]const u8, in_len: usize, ad: ?[*]const u8, ad_len: usize) c_int;
    pub extern fn EVP_AEAD_CTX_open(ctx: *const EVP_AEAD_CTX, out: [*]u8, out_len: *usize, max_out_len: usize, nonce: [*]const u8, nonce_len: usize, in: [*]const u8, in_len: usize, ad: ?[*]const u8, ad_len: usize) c_int;
};

/// One service-indicator measurement.
///
///     const ind = bssl.Indicator.begin();
///     const rc = bssl.c.RAND_bytes(&buf, buf.len);
///     if (!ind.approved()) ... // the module did not count an approved service
///
/// Caveats, both inherited from upstream's design:
/// - In a non-FIPS build `approved()` is always false (`fips_build` is false),
///   because upstream's stub counter would otherwise make every call look
///   approved.
/// - The counter is bumped by every hooked service, including ones called
///   *internally* by a function that has no hook of its own. Ed25519 (via
///   SHA-512) and ML-KEM keygen/encap (via the DRBG) therefore read as
///   "approved" although they are not indicated services. Only trust a
///   reading for services the module actually hooks; `zig build
///   indicator-report` lists which those are.
pub const Indicator = struct {
    before: u64,

    pub fn begin() Indicator {
        return .{ .before = c.zbssl_fips_indicator_before() };
    }

    pub fn approved(self: Indicator) bool {
        return fips_build and c.zbssl_fips_indicator_after() != self.before;
    }
};

fn ReturnOf(comptime f: anytype) type {
    return @typeInfo(@TypeOf(f)).@"fn".return_type.?;
}

/// Call `f` with `args` and report whether the indicator counted it.
///
///     const r = bssl.fipsApproved(bssl.c.RAND_bytes, .{ &buf, buf.len });
///     // r.result == 1, r.approved == true in a FIPS build
pub fn fipsApproved(comptime f: anytype, args: anytype) struct { result: ReturnOf(f), approved: bool } {
    const ind = Indicator.begin();
    const result = @call(.auto, f, args);
    return .{ .result = result, .approved = ind.approved() };
}

/// Only exported by a FIPS build without ASAN: recomputes the module hash and
/// compares it to the injected one. Returns 1 on success.
pub const BORINGSSL_integrity_test: if (fips_build) *const fn () callconv(.c) c_int else void =
    if (fips_build) &fips_only.BORINGSSL_integrity_test else {};

const fips_only = struct {
    pub extern fn BORINGSSL_integrity_test() c_int;
};

pub const OPENSSL_VERSION: c_int = 0;
