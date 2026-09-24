//! Negative test for zig/mlkem_fips_shim.cc: with upstream's `MLKEM_PWCT`
//! break test switched on, the ML-KEM pairwise consistency test fails and
//! zbssl_mlkem*_generate_key_fips must return 0 and leave every output
//! cleansed. This pins the shim's return mapping (only bcm_status::approved
//! reads as 1), which a consumer cannot test.
//!
//! Needs `-Dfips=true -Dfips-break-tests=true` (BORINGSSL_FIPS_BREAK_TESTS
//! makes boringssl_fips_break_test() read the BORINGSSL_FIPS_BREAK_TEST
//! environment variable). `zig build mlkem-pwct-break` sets
//! BORINGSSL_FIPS_BREAK_TEST=MLKEM_PWCT; the program refuses to run without
//! it, then clears it and checks that the same calls return 1 again.
const std = @import("std");
const bssl = @import("boringssl");
const c = bssl.c;

comptime {
    if (!bssl.fips_break_tests) @compileError("mlkem_pwct_break.zig needs -Dfips=true -Dfips-break-tests=true");
}

extern "c" fn getenv(name: [*:0]const u8) ?[*:0]const u8;
extern "c" fn unsetenv(name: [*:0]const u8) c_int;

const env_name = "BORINGSSL_FIPS_BREAK_TEST";

pub fn main() !void {
    const v = getenv(env_name) orelse return error.BreakTestEnvNotSet;
    if (!std.mem.eql(u8, std.mem.span(v), "MLKEM_PWCT")) return error.BreakTestEnvNotMlkemPwct;

    try expectBroken("ML-KEM-768", c.MLKEM768_PUBLIC_KEY_BYTES, c.MLKEM768_private_key, c.zbssl_mlkem768_generate_key_fips);
    try expectBroken("ML-KEM-1024", c.MLKEM1024_PUBLIC_KEY_BYTES, c.MLKEM1024_private_key, c.zbssl_mlkem1024_generate_key_fips);

    // Control: the same process, with the break test off, gets 1. Proves the
    // 0 above came from the PCT and not from something else.
    if (unsetenv(env_name) != 0) return error.UnsetenvFailed;
    try expectWorking(c.MLKEM768_PUBLIC_KEY_BYTES, c.MLKEM768_private_key, c.zbssl_mlkem768_generate_key_fips);
    try expectWorking(c.MLKEM1024_PUBLIC_KEY_BYTES, c.MLKEM1024_private_key, c.zbssl_mlkem1024_generate_key_fips);
    std.debug.print("OK: with {s} unset, both wrappers return 1 again\n", .{env_name});
}

fn allZero(bytes: []const u8) bool {
    for (bytes) |b| if (b != 0) return false;
    return true;
}

fn expectBroken(comptime name: []const u8, comptime pub_len: usize, comptime PrivateKey: type, comptime keygen: anytype) !void {
    var pub_bytes: [pub_len]u8 = @splat(0xaa);
    var seed: [c.MLKEM_SEED_BYTES]u8 = @splat(0xaa);
    var priv: PrivateKey = undefined;
    @memset(std.mem.asBytes(&priv), 0xaa);

    if (keygen(&pub_bytes, &seed, &priv) != 0) {
        std.debug.print("FAIL: {s}: wrapper returned non-zero with the PCT broken\n", .{name});
        return error.BrokenPctReadAsSuccess;
    }
    if (!allZero(&pub_bytes) or !allZero(&seed) or !allZero(std.mem.asBytes(&priv))) {
        std.debug.print("FAIL: {s}: outputs not cleansed after a failed PCT\n", .{name});
        return error.OutputsNotCleansed;
    }

    @memset(std.mem.asBytes(&priv), 0xaa);
    if (keygen(&pub_bytes, null, &priv) != 0) return error.BrokenPctReadAsSuccess;
    if (!allZero(&pub_bytes) or !allZero(std.mem.asBytes(&priv))) return error.OutputsNotCleansed;

    std.debug.print("OK: {s}: MLKEM_PWCT broken -> wrapper returned 0, outputs cleansed\n", .{name});
}

fn expectWorking(comptime pub_len: usize, comptime PrivateKey: type, comptime keygen: anytype) !void {
    var pub_bytes: [pub_len]u8 = undefined;
    var seed: [c.MLKEM_SEED_BYTES]u8 = undefined;
    var priv: PrivateKey = undefined;
    if (keygen(&pub_bytes, &seed, &priv) != 1) return error.ControlKeygenFailed;
}
