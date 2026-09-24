// fips-exercise: use every algorithm family once so that each lazily-run
// FIPS known-answer test (KAT) is triggered, then print PASS. Fork-owned.
//
// Why this exists: upstream's util/fipstools/test_fips.cc refuses to run when
// FIPS_version()==0 ("No module version set"), and upstream main hard-codes
// FIPS_version() to 0 — only Google's validated branches set it. An
// update-stream build therefore needs its own exerciser for the KAT break
// tests (util/fipstools/break-kat.go): most KATs run on first use of their
// algorithm, and only that path calls BORINGSSL_FIPS_abort(); calling
// BORINGSSL_self_test_all() would merely return 0.
//
// This program deliberately does NOT check the integrity test: in a
// -Dfips-break-tests=true build the integrity failure caused by the patched
// KAT is non-fatal, and the point is to reach the KAT.
//
// Which call triggers which KAT (break-kat.go names; upstream `main` as of
// 2026-09-24). Power-on KATs run from the module constructor before main()
// (bcm.cc:185 -> boringssl_self_test_startup -> boringssl_self_test_fast,
// self_check.cc.inc:728,1092): AES-CBC-*, AES-GCM-*, DRBG, DRBG-reseed,
// HKDF, HMAC-SHA-256, SHA-1/256/512, TLS10/12/13-KDF. The rest are lazy,
// each behind a CRYPTO_once that calls BORINGSSL_FIPS_abort() on failure:
//
//   RSA-sign         boringssl_ensure_rsa_sign_self_test (self_check.cc.inc:619)
//                    from rsa.cc.inc / rsa_impl.cc.inc  -> EVP_DigestSign(RSA)
//   RSA-verify       boringssl_ensure_rsa_verify_self_test (:633)          -> EVP_DigestVerify(RSA)
//   ECDSA-sign, ECDSA-verify, Z-computation
//                    boringssl_ensure_ecc_self_test (:647), one KAT function
//                    (boringssl_self_test_ecc, :402) covering all three,
//                    from ec_key.cc.inc / ecdsa.cc.inc / ecdh.cc.inc
//                    -> EC_KEY_generate_key_fips, EVP_DigestSign/Verify(EC),
//                       ECDH_compute_key_fips
//   FFDH             boringssl_ensure_ffdh_self_test (:661) from dh.cc.inc
//                    -> DH_generate_key / DH_compute_key_hashed
//   MLKEM-keygen/encap/decap
//                    mlkem.cc.inc:1164,1388,1239 fips::ensure_*_self_test
//                    -> MLKEM768_generate_key / MLKEM768_encap / MLKEM768_decap
//   MLDSA-keygen/sign/verify
//                    mldsa.cc.inc:2022,2162,2307 -> MLDSA65_generate_key / _sign / _verify
//   SLHDSA-keygen/sign/verify
//                    slhdsa.cc.inc:311,499,670 -> SLHDSA_SHA2_128S_generate_key / _sign / _verify
//
// What the module prints before aborting differs from the break-kat names
// for the post-quantum KATs ("ML-KEM keygen public key failed." for
// MLKEM-keygen, etc.), and the ML-DSA / SLH-DSA verify KATs print nothing
// at all (mldsa.cc.inc:2578, slhdsa.cc.inc:288: `if (!verify_self_test())
// BORINGSSL_FIPS_abort();`). The CI matcher accounts for that per KAT.
#include <openssl/aead.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/dh.h>
#include <openssl/digest.h>
#include <openssl/ec_key.h>
#include <openssl/ecdh.h>
#include <openssl/evp.h>
#include <openssl/hkdf.h>
#include <openssl/hmac.h>
#include <openssl/mldsa.h>
#include <openssl/mlkem.h>
#include <openssl/nid.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/slhdsa.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <memory>
#include <vector>

namespace {

#define STEP(name)                 \
  do {                             \
    printf("%s\n", name);          \
    fflush(stdout);                \
  } while (0)

bool exercise() {
  const uint8_t msg[32] = {1, 2, 3};
  uint8_t buf[64];

  STEP("RAND_bytes (DRBG)");
  if (!RAND_bytes(buf, sizeof(buf))) return false;

  STEP("SHA-256 / HMAC / HKDF (power-on KATs, exercised anyway)");
  SHA256(msg, sizeof(msg), buf);
  unsigned hlen;
  if (!HMAC(EVP_sha256(), buf, 32, msg, sizeof(msg), buf, &hlen)) return false;
  if (!HKDF(buf, 32, EVP_sha256(), msg, sizeof(msg), buf, 8, msg, 4)) return false;

  STEP("AES-256-GCM seal/open");
  {
    uint8_t key[32] = {9}, nonce[12] = {8}, ct[64 + EVP_AEAD_MAX_OVERHEAD], pt[64];
    size_t ct_len, pt_len;
    bssl::ScopedEVP_AEAD_CTX ctx;
    if (!EVP_AEAD_CTX_init(ctx.get(), EVP_aead_aes_256_gcm(), key, sizeof(key), 16, nullptr) ||
        !EVP_AEAD_CTX_seal(ctx.get(), ct, &ct_len, sizeof(ct), nonce, sizeof(nonce), msg, sizeof(msg), nullptr, 0) ||
        !EVP_AEAD_CTX_open(ctx.get(), pt, &pt_len, sizeof(pt), nonce, sizeof(nonce), ct, ct_len, nullptr, 0)) {
      return false;
    }
  }

  STEP("RSA-2048 sign/verify (lazy RSA KATs)");
  {
    bssl::UniquePtr<RSA> rsa(RSA_new());
    bssl::UniquePtr<BIGNUM> e(BN_new());
    bssl::UniquePtr<EVP_PKEY> pkey(EVP_PKEY_new());
    if (!rsa || !e || !pkey || !BN_set_word(e.get(), RSA_F4) ||
        !RSA_generate_key_ex(rsa.get(), 2048, e.get(), nullptr) ||
        !EVP_PKEY_set1_RSA(pkey.get(), rsa.get())) {
      return false;
    }
    bssl::ScopedEVP_MD_CTX md;
    std::vector<uint8_t> sig(EVP_PKEY_size(pkey.get()));
    size_t sig_len = sig.size();
    if (!EVP_DigestSignInit(md.get(), nullptr, EVP_sha256(), nullptr, pkey.get()) ||
        !EVP_DigestSign(md.get(), sig.data(), &sig_len, msg, sizeof(msg))) {
      return false;
    }
    bssl::ScopedEVP_MD_CTX vd;
    if (!EVP_DigestVerifyInit(vd.get(), nullptr, EVP_sha256(), nullptr, pkey.get()) ||
        !EVP_DigestVerify(vd.get(), sig.data(), sig_len, msg, sizeof(msg))) {
      return false;
    }
  }

  STEP("ECDSA P-256 sign/verify + ECDH (lazy ECC KATs: ECDSA-sign, ECDSA-verify, Z-computation)");
  {
    bssl::UniquePtr<EC_KEY> a(EC_KEY_new_by_curve_name(NID_X9_62_prime256v1));
    bssl::UniquePtr<EC_KEY> b(EC_KEY_new_by_curve_name(NID_X9_62_prime256v1));
    if (!a || !b || !EC_KEY_generate_key_fips(a.get()) || !EC_KEY_generate_key_fips(b.get())) return false;
    bssl::UniquePtr<EVP_PKEY> pkey(EVP_PKEY_new());
    if (!pkey || !EVP_PKEY_set1_EC_KEY(pkey.get(), a.get())) return false;
    bssl::ScopedEVP_MD_CTX md;
    uint8_t sig[128];
    size_t sig_len = sizeof(sig);
    if (!EVP_DigestSignInit(md.get(), nullptr, EVP_sha256(), nullptr, pkey.get()) ||
        !EVP_DigestSign(md.get(), sig, &sig_len, msg, sizeof(msg))) {
      return false;
    }
    bssl::ScopedEVP_MD_CTX vd;
    if (!EVP_DigestVerifyInit(vd.get(), nullptr, EVP_sha256(), nullptr, pkey.get()) ||
        !EVP_DigestVerify(vd.get(), sig, sig_len, msg, sizeof(msg))) {
      return false;
    }
    uint8_t z[32];
    if (!ECDH_compute_key_fips(z, sizeof(z), EC_KEY_get0_public_key(b.get()), a.get())) return false;
  }

  STEP("FFDHE-2048 (lazy FFDH KAT)");
  {
    bssl::UniquePtr<DH> a(DH_get_rfc7919_2048()), b(DH_get_rfc7919_2048());
    uint8_t out[32];
    size_t out_len;
    if (!a || !b || !DH_generate_key(a.get()) || !DH_generate_key(b.get()) ||
        !DH_compute_key_hashed(a.get(), out, &out_len, sizeof(out), DH_get0_pub_key(b.get()), EVP_sha256())) {
      return false;
    }
  }

  STEP("ML-KEM-768 keygen/encap/decap");
  {
    static uint8_t pub_bytes[MLKEM768_PUBLIC_KEY_BYTES], seed[MLKEM_SEED_BYTES];
    static uint8_t ct[MLKEM768_CIPHERTEXT_BYTES], ss1[MLKEM_SHARED_SECRET_BYTES], ss2[MLKEM_SHARED_SECRET_BYTES];
    static MLKEM768_private_key priv;
    static MLKEM768_public_key pub;
    MLKEM768_generate_key(pub_bytes, seed, &priv);
    MLKEM768_public_from_private(&pub, &priv);
    MLKEM768_encap(ct, ss1, &pub);
    if (!MLKEM768_decap(ss2, ct, sizeof(ct), &priv) || memcmp(ss1, ss2, sizeof(ss1)) != 0) return false;
  }

  STEP("ML-DSA-65 keygen/sign/verify");
  {
    static uint8_t pub_bytes[MLDSA65_PUBLIC_KEY_BYTES], seed[MLDSA_SEED_BYTES], sig[MLDSA65_SIGNATURE_BYTES];
    static MLDSA65_private_key priv;
    static MLDSA65_public_key pub;
    if (!MLDSA65_generate_key(pub_bytes, seed, &priv) || !MLDSA65_public_from_private(&pub, &priv) ||
        !MLDSA65_sign(sig, &priv, msg, sizeof(msg), nullptr, 0) ||
        !MLDSA65_verify(&pub, sig, sizeof(sig), msg, sizeof(msg), nullptr, 0)) {
      return false;
    }
  }

  STEP("SLH-DSA-SHA2-128s keygen/sign/verify (slow)");
  {
    static uint8_t pub[SLHDSA_SHA2_128S_PUBLIC_KEY_BYTES], priv[SLHDSA_SHA2_128S_PRIVATE_KEY_BYTES];
    static uint8_t sig[SLHDSA_SHA2_128S_SIGNATURE_BYTES];
    SLHDSA_SHA2_128S_generate_key(pub, priv);
    if (!SLHDSA_SHA2_128S_sign(sig, priv, msg, sizeof(msg), nullptr, 0) ||
        !SLHDSA_SHA2_128S_verify(sig, sizeof(sig), pub, msg, sizeof(msg), nullptr, 0)) {
      return false;
    }
  }
  return true;
}

}  // namespace

int main() {
  printf("FIPS_mode() = %d, FIPS_version() = %u (0 = update stream)\n", FIPS_mode(), FIPS_version());
  if (!exercise()) {
    printf("FAIL\n");
    fflush(stdout);
    abort();
  }
  printf("PASS\n");
  return 0;
}
