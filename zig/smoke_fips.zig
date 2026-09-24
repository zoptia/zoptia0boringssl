//! FIPS smoke test: linked statically against the freshly built FIPS module,
//! the way a consumer executable would be.
//!
//! Exit 0 only if FIPS_mode()==1 and every KAT self test passes. Prints the
//! module name, version (0 = update stream, not a validated module) and hash.
const std = @import("std");
const bssl = @import("boringssl");

comptime {
    if (!bssl.fips_build) @compileError("smoke_fips.zig must be built with -Dfips=true");
}

pub fn main() !void {
    const out = std.debug.print;

    const mode = bssl.c.FIPS_mode();
    out("FIPS_mode()             = {d}\n", .{mode});
    if (mode != 1) return error.NotFipsMode;
    if (bssl.c.FIPS_mode_set(1) != 1) return error.FipsModeSetMismatch;

    out("FIPS_module_name()      = {s}\n", .{bssl.c.FIPS_module_name()});
    const version = bssl.c.FIPS_version();
    out("FIPS_version()          = {d}{s}\n", .{ version, if (version == 0) "  (update stream: NOT a validated module)" else "" });
    out("FIPS_module_hash()      = {x}\n", .{bssl.c.FIPS_module_hash()[0..32]});

    // The constructor already ran the integrity check and the power-on KATs
    // (a failure there aborts the process before main). Run them again
    // explicitly, uncached, so the result is observable.
    if (bssl.BORINGSSL_integrity_test() != 1) return error.IntegrityTestFailed;
    out("BORINGSSL_integrity_test() = 1\n", .{});
    if (bssl.c.BORINGSSL_self_test_all() != 1) return error.SelfTestFailed;
    out("BORINGSSL_self_test_all()  = 1\n", .{});

    var buf: [32]u8 = undefined;
    const r = bssl.fipsApproved(bssl.c.RAND_bytes, .{ &buf, buf.len });
    if (r.result != 1) return error.RandFailed;
    if (!r.approved) return error.RandNotIndicatedApproved;
    out("RAND_bytes(32)          = ok, service indicator: approved\n", .{});
    // Generic AES-GCM seal with a caller nonce is NOT approved by design; the
    // indicator must say so, or the shim is broken.
    var key: [16]u8 = @splat(0x11);
    var nonce: [12]u8 = @splat(0x22);
    var ct: [32 + 16]u8 = undefined;
    var ct_len: usize = 0;
    const aead = bssl.c.EVP_aead_aes_128_gcm();
    var ctx: bssl.c.EVP_AEAD_CTX = undefined;
    bssl.c.EVP_AEAD_CTX_zero(&ctx);
    if (bssl.c.EVP_AEAD_CTX_init(&ctx, aead, &key, key.len, 16, null) != 1) return error.AeadInit;
    defer bssl.c.EVP_AEAD_CTX_cleanup(&ctx);
    const s = bssl.fipsApproved(bssl.c.EVP_AEAD_CTX_seal, .{ &ctx, &ct, &ct_len, ct.len, &nonce, nonce.len, &buf, buf.len, null, 0 });
    if (s.result != 1) return error.AeadSeal;
    if (s.approved) return error.ExternalIvGcmMustNotBeApproved;
    out("AES-128-GCM seal, caller nonce = ok, service indicator: not approved (expected)\n", .{});
    out("OK: FIPS mode build (update stream, not a validated module)\n", .{});
}
