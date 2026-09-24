const std = @import("std");
const bssl = @import("boringssl");
const c = bssl.c;

pub fn main() !void {
    var buf: [32]u8 = undefined;
    if (c.RAND_bytes(&buf, buf.len) != 1) {
        std.debug.print("RAND_bytes failed\n", .{});
        return error.RandFailed;
    }
    std.debug.print("OK: libcrypto produced {d} random bytes\n", .{buf.len});

    try mlkemRoundTrip(Mlkem768);
    try mlkemRoundTrip(Mlkem1024);
}

/// The two ML-KEM parameter sets, as one shape so the test is written once.
const Mlkem768 = struct {
    const name = "ML-KEM-768";
    const PublicKey = c.MLKEM768_public_key;
    const PrivateKey = c.MLKEM768_private_key;
    const public_key_bytes = c.MLKEM768_PUBLIC_KEY_BYTES;
    const ciphertext_bytes = c.MLKEM768_CIPHERTEXT_BYTES;
    const generateKeyFips = c.zbssl_mlkem768_generate_key_fips;
    const parsePublicKey = c.MLKEM768_parse_public_key;
    const privateKeyFromSeed = c.MLKEM768_private_key_from_seed;
    const encap = c.MLKEM768_encap;
    const decap = c.MLKEM768_decap;
};

const Mlkem1024 = struct {
    const name = "ML-KEM-1024";
    const PublicKey = c.MLKEM1024_public_key;
    const PrivateKey = c.MLKEM1024_private_key;
    const public_key_bytes = c.MLKEM1024_PUBLIC_KEY_BYTES;
    const ciphertext_bytes = c.MLKEM1024_CIPHERTEXT_BYTES;
    const generateKeyFips = c.zbssl_mlkem1024_generate_key_fips;
    const parsePublicKey = c.MLKEM1024_parse_public_key;
    const privateKeyFromSeed = c.MLKEM1024_private_key_from_seed;
    const encap = c.MLKEM1024_encap;
    const decap = c.MLKEM1024_decap;
};

/// zbssl_mlkem*_generate_key_fips (zig/mlkem_fips_shim.cc) must return 1, and
/// the key pair it returns must work: encapsulate to the *encoded* public key,
/// decapsulate with the private key, and get the same secret again from a
/// private key rebuilt from the returned seed. Runs in every build.
fn mlkemRoundTrip(comptime V: type) !void {
    // Without a seed.
    {
        var pub_bytes: [V.public_key_bytes]u8 = undefined;
        var priv: V.PrivateKey = undefined;
        if (V.generateKeyFips(&pub_bytes, null, &priv) != 1) return error.MlkemKeygenFipsFailed;
        _ = try encapDecap(V, &pub_bytes, &priv);
    }
    // With a seed.
    var pub_bytes: [V.public_key_bytes]u8 = undefined;
    var seed: [c.MLKEM_SEED_BYTES]u8 = undefined;
    var priv: V.PrivateKey = undefined;
    if (V.generateKeyFips(&pub_bytes, &seed, &priv) != 1) return error.MlkemKeygenFipsFailed;
    const r = try encapDecap(V, &pub_bytes, &priv);

    var priv2: V.PrivateKey = undefined;
    if (V.privateKeyFromSeed(&priv2, &seed, seed.len) != 1) return error.MlkemFromSeedFailed;
    var ss2: [c.MLKEM_SHARED_SECRET_BYTES]u8 = undefined;
    if (V.decap(&ss2, &r.ct, r.ct.len, &priv2) != 1) return error.MlkemDecapFailed;
    if (!std.mem.eql(u8, &r.ss, &ss2)) return error.MlkemSeedKeyMismatch;

    std.debug.print("OK: {s} keygen with PCT (zbssl shim) = 1; encap/decap and seed round trip agree\n", .{V.name});
}

fn encapDecap(comptime V: type, pub_bytes: *const [V.public_key_bytes]u8, priv: *const V.PrivateKey) !struct {
    ct: [V.ciphertext_bytes]u8,
    ss: [c.MLKEM_SHARED_SECRET_BYTES]u8,
} {
    var cbs: c.CBS = .{ .data = pub_bytes, .len = pub_bytes.len };
    var pub_key: V.PublicKey = undefined;
    if (V.parsePublicKey(&pub_key, &cbs) != 1 or cbs.len != 0) return error.MlkemParsePublicKeyFailed;

    var ct: [V.ciphertext_bytes]u8 = undefined;
    var ss: [c.MLKEM_SHARED_SECRET_BYTES]u8 = undefined;
    V.encap(&ct, &ss, &pub_key);
    var ss_dec: [c.MLKEM_SHARED_SECRET_BYTES]u8 = undefined;
    if (V.decap(&ss_dec, &ct, ct.len, priv) != 1) return error.MlkemDecapFailed;
    if (!std.mem.eql(u8, &ss, &ss_dec)) return error.MlkemSharedSecretMismatch;
    return .{ .ct = ct, .ss = ss };
}
