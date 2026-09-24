// ML-KEM FIPS key-generation shim (fork-owned; upstream files are untouched).
//
// Upstream's public MLKEM768_generate_key / MLKEM1024_generate_key call
// bssl::BCM_mlkem*_generate_key, which draws a seed from the module's DRBG but
// does NOT run the pairwise consistency test (PCT) that FIPS 140-3 asks for on
// a generated key pair. The PCT path, bssl::BCM_mlkem*_generate_key_fips, is
// declared only in the internal crypto/fipsmodule/bcm_interface.h, in C++,
// returning a scoped enum. This file gives it a C symbol with a return
// contract the fork owns:
//
//   1  if and only if the module returned bcm_status::approved
//      (key generated from the DRBG and the PCT passed);
//   0  otherwise (PCT failed, or a required pointer was null). Everything the
//      call may have written (public key, private key, seed) is cleansed, so
//      0 never leaves usable material behind.
//
// The mapping compares against the enumerator by name. Do not use
// bcm_success(): it also accepts not_approved, and a key the module did not
// test must read as failure here. The static_asserts below turn an upstream
// change of the return type or the parameter list into a compile error in
// this fork at sync time, instead of a silent misread in a consumer.
//
// Compiled into libcrypto in every build (FIPS or not, every target), like
// zig/fips_indicator_shim.cc. Upstream's function exists and runs the PCT in
// a non-FIPS build too, so the symbols mean the same thing everywhere.
#include <openssl/mem.h>
#include <openssl/mlkem.h>

#include <type_traits>

#include "../crypto/fipsmodule/bcm_interface.h"

namespace {

template <typename Fn, typename Expected>
constexpr bool kSameSignature = std::is_same_v<Fn, Expected>;

static_assert(
    kSameSignature<decltype(bssl::BCM_mlkem768_generate_key_fips),
                   bssl::bcm_status(uint8_t *, uint8_t *,
                                    MLKEM768_private_key *)>,
    "upstream changed BCM_mlkem768_generate_key_fips; revisit "
    "zig/mlkem_fips_shim.cc and its return mapping");
static_assert(
    kSameSignature<decltype(bssl::BCM_mlkem1024_generate_key_fips),
                   bssl::bcm_status(uint8_t *, uint8_t *,
                                    MLKEM1024_private_key *)>,
    "upstream changed BCM_mlkem1024_generate_key_fips; revisit "
    "zig/mlkem_fips_shim.cc and its return mapping");

template <size_t kPublicKeyBytes, typename PrivateKey>
int finish(bssl::bcm_status status, uint8_t *out_encoded_public_key,
           uint8_t *optional_out_seed, PrivateKey *out_private_key) {
  if (status == bssl::bcm_status::approved) {
    return 1;
  }
  if (out_encoded_public_key != nullptr) {
    OPENSSL_cleanse(out_encoded_public_key, kPublicKeyBytes);
  }
  if (optional_out_seed != nullptr) {
    OPENSSL_cleanse(optional_out_seed, MLKEM_SEED_BYTES);
  }
  if (out_private_key != nullptr) {
    OPENSSL_cleanse(out_private_key, sizeof(*out_private_key));
  }
  return 0;
}

}  // namespace

extern "C" {

int zbssl_mlkem768_generate_key_fips(
    uint8_t out_encoded_public_key[MLKEM768_PUBLIC_KEY_BYTES],
    uint8_t optional_out_seed[MLKEM_SEED_BYTES],
    struct MLKEM768_private_key *out_private_key) {
  const bssl::bcm_status status = bssl::BCM_mlkem768_generate_key_fips(
      out_encoded_public_key, optional_out_seed, out_private_key);
  return finish<MLKEM768_PUBLIC_KEY_BYTES>(status, out_encoded_public_key,
                                           optional_out_seed, out_private_key);
}

int zbssl_mlkem1024_generate_key_fips(
    uint8_t out_encoded_public_key[MLKEM1024_PUBLIC_KEY_BYTES],
    uint8_t optional_out_seed[MLKEM_SEED_BYTES],
    struct MLKEM1024_private_key *out_private_key) {
  const bssl::bcm_status status = bssl::BCM_mlkem1024_generate_key_fips(
      out_encoded_public_key, optional_out_seed, out_private_key);
  return finish<MLKEM1024_PUBLIC_KEY_BYTES>(status, out_encoded_public_key,
                                            optional_out_seed, out_private_key);
}

}  // extern "C"
