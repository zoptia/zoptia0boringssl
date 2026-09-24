// indicator-report: exercise the services a downstream IKEv2/IPsec stack uses
// and record what BoringCrypto's FIPS service indicator says about each.
// Prints a Markdown table. Fork-owned; upstream files are untouched.
//
// Reading the table:
//   Indicator  — what the counter said around this exact call: "approved" if
//                it moved, "not approved" if it did not.
//   Covered    — whether the module has an indicator hook that makes a
//                deliberate decision about THIS service. Derived from source
//                (zig/check-indicator-coverage.sh keeps it honest). When a
//                service is NOT covered, the counter can still move because
//                of an internal call (Ed25519 uses SHA-512, ML-KEM keygen
//                uses the DRBG), so its reading is a false positive and the
//                verdict is "not covered", never "approved".
//   Verdict    — covered ? Indicator : "not covered".
#include <openssl/aead.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/curve25519.h>
#include <openssl/dh.h>
#include <openssl/digest.h>
#include <openssl/ec.h>
#include <openssl/ec_key.h>
#include <openssl/ecdh.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/mem.h>
#include <openssl/mlkem.h>
#include <openssl/nid.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <functional>
#include <string>
#include <vector>

// Internal upstream header (read-only): BCM_mlkem768_generate_key_fips has no
// public wrapper, but the report should say what the FIPS keygen path does.
#include "../crypto/fipsmodule/bcm_interface.h"

extern "C" uint64_t zbssl_fips_indicator_before(void);
extern "C" uint64_t zbssl_fips_indicator_after(void);

namespace {

struct Row {
  std::string service;
  std::string call;
  bool covered;
  std::string hook;  // source evidence for `covered`
  bool ok;           // the call itself succeeded
  bool approved;     // counter moved
  std::string note;
};

std::vector<Row> rows;
bool open_moved = false;  // set by aead_open: did the counter move around open()?
bool sign_moved = false;  // set by digest_sign: did the counter move around sign()?

void probe(const char *service, const char *call, bool covered, const char *hook,
           const std::function<bool()> &fn, const char *note = "") {
  const uint64_t before = zbssl_fips_indicator_before();
  const bool ok = fn();
  const uint64_t after = zbssl_fips_indicator_after();
  rows.push_back({service, call, covered, hook, ok, after != before, note});
}

// ---- AEAD -----------------------------------------------------------------

bool aead_seal(const EVP_AEAD *aead, size_t nonce_len) {
  std::vector<uint8_t> key(EVP_AEAD_key_length(aead), 0x11);
  std::vector<uint8_t> nonce(nonce_len, 0x22);
  const uint8_t pt[64] = {0};
  uint8_t out[64 + EVP_AEAD_MAX_OVERHEAD];
  size_t out_len;
  bssl::ScopedEVP_AEAD_CTX ctx;
  if (!EVP_AEAD_CTX_init(ctx.get(), aead, key.data(), key.size(),
                         EVP_AEAD_DEFAULT_TAG_LENGTH, nullptr)) {
    return false;
  }
  return EVP_AEAD_CTX_seal(ctx.get(), out, &out_len, sizeof(out), nonce.data(),
                           nonce.size(), pt, sizeof(pt), nullptr, 0) == 1;
}

bool aead_open(const EVP_AEAD *aead) {
  std::vector<uint8_t> key(EVP_AEAD_key_length(aead), 0x11);
  std::vector<uint8_t> nonce(EVP_AEAD_nonce_length(aead), 0x22);
  const uint8_t pt[64] = {0};
  uint8_t ct[64 + EVP_AEAD_MAX_OVERHEAD], back[64];
  size_t ct_len, back_len;
  bssl::ScopedEVP_AEAD_CTX ctx;
  if (!EVP_AEAD_CTX_init(ctx.get(), aead, key.data(), key.size(),
                         EVP_AEAD_DEFAULT_TAG_LENGTH, nullptr) ||
      !EVP_AEAD_CTX_seal(ctx.get(), ct, &ct_len, sizeof(ct), nonce.data(),
                         nonce.size(), pt, sizeof(pt), nullptr, 0)) {
    return false;
  }
  // Open is measured on its own; the seal above happened before `before`.
  const uint64_t before = zbssl_fips_indicator_before();
  const bool ok = EVP_AEAD_CTX_open(ctx.get(), back, &back_len, sizeof(back),
                                    nonce.data(), nonce.size(), ct, ct_len,
                                    nullptr, 0) == 1;
  const uint64_t after = zbssl_fips_indicator_after();
  // Stash the open-only reading by moving the counter delta into the result:
  // report it through a side channel (see probe_open).
  open_moved = after != before;
  return ok;
}

void probe_open(const char *service, const EVP_AEAD *aead, const char *hook) {
  open_moved = false;
  const bool ok = aead_open(aead);
  rows.push_back({service, "EVP_AEAD_CTX_open, caller nonce", true, hook, ok,
                  open_moved, "decrypt with external IV: approved by design"});
}

// ---- HMAC -----------------------------------------------------------------

bool hmac_once(const EVP_MD *md) {
  const uint8_t key[32] = {1}, msg[16] = {2};
  uint8_t out[EVP_MAX_MD_SIZE];
  unsigned out_len;
  return HMAC(md, key, sizeof(key), msg, sizeof(msg), out, &out_len) != nullptr;
}

// ---- EC / ECDH ------------------------------------------------------------

bssl::UniquePtr<EC_KEY> ec_key_fips(int nid) {
  bssl::UniquePtr<EC_KEY> k(EC_KEY_new_by_curve_name(nid));
  if (!k || !EC_KEY_generate_key_fips(k.get())) k.reset();
  return k;
}

// ---- DH / MODP ------------------------------------------------------------

bool bn_mod_exp_modp2048() {
  bssl::UniquePtr<BIGNUM> p(BN_get_rfc3526_prime_2048(nullptr));
  bssl::UniquePtr<BIGNUM> g(BN_new()), x(BN_new()), r(BN_new());
  bssl::UniquePtr<BN_CTX> ctx(BN_CTX_new());
  return p && g && x && r && ctx && BN_set_word(g.get(), 2) &&
         BN_rand_range_ex(x.get(), 1, p.get()) &&
         BN_mod_exp(r.get(), g.get(), x.get(), p.get(), ctx.get());
}

// ---- Signatures -----------------------------------------------------------

struct SigCase {
  bssl::UniquePtr<EVP_PKEY> pkey;
  const EVP_MD *md;
  bool pss;
};

bool digest_sign(SigCase &c, std::vector<uint8_t> *sig) {
  const uint8_t msg[32] = {7};
  bssl::ScopedEVP_MD_CTX ctx;
  EVP_PKEY_CTX *pctx = nullptr;
  if (!EVP_DigestSignInit(ctx.get(), &pctx, c.md, nullptr, c.pkey.get())) return false;
  if (c.pss && (!EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) ||
                !EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, -1 /* digest length */))) {
    return false;
  }
  size_t len;
  if (!EVP_DigestSign(ctx.get(), nullptr, &len, msg, sizeof(msg))) return false;
  sig->resize(len);
  const uint64_t before = zbssl_fips_indicator_before();
  const bool ok = EVP_DigestSign(ctx.get(), sig->data(), &len, msg, sizeof(msg)) == 1;
  const uint64_t after = zbssl_fips_indicator_after();
  sig->resize(len);
  sign_moved = after != before;
  return ok;
}

bool digest_verify(SigCase &c, const std::vector<uint8_t> &sig) {
  const uint8_t msg[32] = {7};
  bssl::ScopedEVP_MD_CTX ctx;
  EVP_PKEY_CTX *pctx = nullptr;
  if (!EVP_DigestVerifyInit(ctx.get(), &pctx, c.md, nullptr, c.pkey.get())) return false;
  if (c.pss && (!EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) ||
                !EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, -1))) {
    return false;
  }
  return EVP_DigestVerify(ctx.get(), sig.data(), sig.size(), msg, sizeof(msg)) == 1;
}

void probe_sig(const char *service, SigCase c, const char *sign_note,
               const char *verify_note) {
  const char *hook = "digestsign/digestsign.cc.inc: EVP_DigestSign/Verify_verify_service_indicator";
  std::vector<uint8_t> sig;
  sign_moved = false;
  const bool sok = digest_sign(c, &sig);
  rows.push_back({service, "EVP_DigestSign", true, hook, sok, sign_moved, sign_note});
  probe(service, "EVP_DigestVerify", true, hook, [&] { return digest_verify(c, sig); }, verify_note);
}

bssl::UniquePtr<EVP_PKEY> rsa_key(int bits) {
  bssl::UniquePtr<RSA> rsa(RSA_new());
  bssl::UniquePtr<BIGNUM> e(BN_new());
  bssl::UniquePtr<EVP_PKEY> pkey(EVP_PKEY_new());
  if (!rsa || !e || !pkey || !BN_set_word(e.get(), RSA_F4) ||
      !RSA_generate_key_ex(rsa.get(), bits, e.get(), nullptr) ||
      !EVP_PKEY_set1_RSA(pkey.get(), rsa.get())) {
    pkey.reset();
  }
  return pkey;
}

bssl::UniquePtr<EVP_PKEY> ec_pkey(int nid) {
  bssl::UniquePtr<EC_KEY> k = ec_key_fips(nid);
  bssl::UniquePtr<EVP_PKEY> pkey(EVP_PKEY_new());
  if (!k || !pkey || !EVP_PKEY_set1_EC_KEY(pkey.get(), k.get())) pkey.reset();
  return pkey;
}

// ---- ML-KEM ---------------------------------------------------------------

struct Mlkem {
  MLKEM768_private_key priv;
  MLKEM768_public_key pub;
  uint8_t pub_bytes[MLKEM768_PUBLIC_KEY_BYTES];
  uint8_t seed[MLKEM_SEED_BYTES];
  uint8_t ct[MLKEM768_CIPHERTEXT_BYTES];
  uint8_t ss[MLKEM_SHARED_SECRET_BYTES];
};

}  // namespace

int main() {
  const bool fips = FIPS_mode() == 1;
  printf("# BoringCrypto service-indicator report\n\n");
  printf("- FIPS_mode(): %d%s\n", FIPS_mode(),
         fips ? "" : "  **(not a FIPS build: the counter is meaningless, every row below is invalid)**");
  printf("- FIPS_module_name(): %s\n", FIPS_module_name());
  printf("- FIPS_version(): %u (0 = update stream, not a validated module)\n", FIPS_version());
  if (fips) {
    printf("- FIPS_module_hash(): ");
    const uint8_t *h = FIPS_module_hash();
    for (int i = 0; i < 32; i++) printf("%02x", h[i]);
    printf("\n");
  }
  printf("- OpenSSL_version(): %s\n\n", OpenSSL_version(OPENSSL_VERSION));

  const char *gcm_hook =
      "cipher/e_aes.cc.inc: AEAD_GCM_verify_service_indicator in openv_detached, "
      "sealv_randnonce, tls12_sealv, tls13_sealv; absent from generic sealv";
  probe("AES-128-GCM encrypt", "EVP_AEAD_CTX_seal, caller 12-byte nonce", true, gcm_hook,
        [] { return aead_seal(EVP_aead_aes_128_gcm(), 12); },
        "external IV: not approved by design (IG C.H); upstream test expects NOT_APPROVED");
  probe("AES-256-GCM encrypt", "EVP_AEAD_CTX_seal, caller 12-byte nonce", true, gcm_hook,
        [] { return aead_seal(EVP_aead_aes_256_gcm(), 12); },
        "external IV: not approved by design (IG C.H)");
  probe_open("AES-128-GCM decrypt", EVP_aead_aes_128_gcm(), gcm_hook);
  probe_open("AES-256-GCM decrypt", EVP_aead_aes_256_gcm(), gcm_hook);
  probe("AES-256-GCM encrypt, internal IV", "EVP_AEAD_CTX_seal, EVP_aead_aes_256_gcm_randnonce", true, gcm_hook,
        [] { return aead_seal(EVP_aead_aes_256_gcm_randnonce(), 0); },
        "module generates the 96-bit IV from its DRBG (IG C.H technique 2)");
  probe("AES-128-GCM encrypt, TLS 1.2 nonce", "EVP_AEAD_CTX_seal, EVP_aead_aes_128_gcm_tls12", true, gcm_hook,
        [] { return aead_seal(EVP_aead_aes_128_gcm_tls12(), 12); },
        "4-byte fixed + 8-byte strictly increasing counter, enforced per ctx");
  probe("AES-256-GCM encrypt, TLS 1.3 nonce", "EVP_AEAD_CTX_seal, EVP_aead_aes_256_gcm_tls13", true, gcm_hook,
        [] { return aead_seal(EVP_aead_aes_256_gcm_tls13(), 12); },
        "12-byte XOR-masked counter nonce, enforced per ctx");
  probe("ChaCha20-Poly1305 encrypt", "EVP_AEAD_CTX_seal", false,
        "crypto/cipher/e_chacha20poly1305.cc is outside the FIPS module; not an approved algorithm",
        [] { return aead_seal(EVP_aead_chacha20_poly1305(), 12); });

  const char *hmac_hook = "hmac/hmac.cc.inc: HMAC_verify_service_indicator (SHA-1/224/256/384/512/512-256)";
  probe("HMAC-SHA-1", "HMAC() one-shot", true, hmac_hook, [] { return hmac_once(EVP_sha1()); },
        "HMAC with SHA-1 is approved (SP 800-131A: SHA-1 remains acceptable for HMAC)");
  probe("HMAC-SHA-256", "HMAC() one-shot", true, hmac_hook, [] { return hmac_once(EVP_sha256()); });
  probe("HMAC-SHA-384", "HMAC() one-shot", true, hmac_hook, [] { return hmac_once(EVP_sha384()); });
  probe("HMAC-SHA-512", "HMAC() one-shot", true, hmac_hook, [] { return hmac_once(EVP_sha512()); });

  const char *ec_hook = "ec/ec_key.cc.inc: EC_KEY_keygen_verify_service_indicator in EC_KEY_check_fips "
                        "(called by EC_KEY_generate_key_fips only)";
  const std::pair<const char *, int> curves[] = {
      {"P-256", NID_X9_62_prime256v1}, {"P-384", NID_secp384r1}, {"P-521", NID_secp521r1}};
  for (const auto &cv : curves) {
    const char *name = cv.first;
    const int nid = cv.second;
    const std::string svc = std::string("EC keygen ") + name;
    probe(svc.c_str(), "EC_KEY_generate_key", true, ec_hook,
          [nid] { bssl::UniquePtr<EC_KEY> k(EC_KEY_new_by_curve_name(nid)); return k && EC_KEY_generate_key(k.get()); },
          "no pairwise consistency test: not approved; use EC_KEY_generate_key_fips");
    probe(svc.c_str(), "EC_KEY_generate_key_fips", true, ec_hook,
          [nid] { return ec_key_fips(nid) != nullptr; });
  }

  const char *ecdh_hook = "ecdh/ecdh.cc.inc: ECDH_verify_service_indicator in ECDH_compute_key_fips only";
  for (const auto &cv : curves) {
    const char *name = cv.first;
    const int nid = cv.second;
    bssl::UniquePtr<EC_KEY> a = ec_key_fips(nid), b = ec_key_fips(nid);
    probe((std::string("ECDH ") + name + " raw shared secret").c_str(), "ECDH_compute_key", true, ecdh_hook,
          [&] { uint8_t out[66]; return a && b && ECDH_compute_key(out, sizeof(out), EC_KEY_get0_public_key(b.get()), a.get(), nullptr) > 0; },
          "raw Z output (what IKEv2 SKEYSEED needs): not approved");
    probe((std::string("ECDH ") + name + " hashed").c_str(), "ECDH_compute_key_fips", true, ecdh_hook,
          [&] { uint8_t out[64]; return a && b && ECDH_compute_key_fips(out, nid == NID_secp521r1 ? 64 : (nid == NID_secp384r1 ? 48 : 32), EC_KEY_get0_public_key(b.get()), a.get()) == 1; },
          "output is SHA-2 of Z, not Z itself");
  }

  probe("MODP-2048 DH via bignum", "BN_mod_exp with BN_get_rfc3526_prime_2048", false,
        "bn/ has no indicator hook; this is arithmetic, not a module DH service",
        bn_mod_exp_modp2048);
  {
    bssl::UniquePtr<DH> a(DH_get_rfc7919_2048()), b(DH_get_rfc7919_2048());
    const bool keys = a && b && DH_generate_key(a.get()) && DH_generate_key(b.get());
    const char *dh_hook = "dh/dh.cc.inc has no indicator hook at all (only ECDH has one); "
                          "DH_compute_key_hashed locks the counter around its internal SHA";
    probe("FFDHE-2048 DH raw shared secret", "DH_compute_key_padded", false, dh_hook,
          [&] { std::vector<uint8_t> out(DH_size(a.get())); return keys && DH_compute_key_padded(out.data(), DH_get0_pub_key(b.get()), a.get()) > 0; });
    probe("FFDHE-2048 DH hashed", "DH_compute_key_hashed, SHA-256", false, dh_hook,
          [&] { uint8_t out[32]; size_t out_len; return keys && DH_compute_key_hashed(a.get(), out, &out_len, sizeof(out), DH_get0_pub_key(b.get()), EVP_sha256()) == 1; });
  }

  probe("X25519", "X25519_keypair + X25519", false,
        "crypto/curve25519/ is outside the FIPS module",
        [] { uint8_t pub[32], priv[32], peer_pub[32], peer_priv[32], out[32];
             X25519_keypair(pub, priv); X25519_keypair(peer_pub, peer_priv); return X25519(out, priv, peer_pub) == 1; });

  {
    const char *kem_hook = "fipsmodule/mlkem/ has no indicator hook; any 'approved' reading comes from the DRBG (RAND_bytes) it calls internally";
    static Mlkem m;
    probe("ML-KEM-768 keygen", "MLKEM768_generate_key", false, kem_hook,
          [] { MLKEM768_generate_key(m.pub_bytes, m.seed, &m.priv); return true; },
          "public wrapper calls BCM_mlkem768_generate_key (no PCT)");
    probe("ML-KEM-768 keygen, FIPS path", "BCM_mlkem768_generate_key_fips (internal, bcm_interface.h)", false, kem_hook,
          [] { return bssl::BCM_mlkem768_generate_key_fips(m.pub_bytes, m.seed, &m.priv) == bssl::bcm_status::approved; },
          "keygen with pairwise consistency test; no public C wrapper exists");
    probe("ML-KEM-768 key from seed", "MLKEM768_private_key_from_seed", false, kem_hook,
          [] { return MLKEM768_private_key_from_seed(&m.priv, m.seed, sizeof(m.seed)) == 1; });
    probe("ML-KEM-768 encap", "MLKEM768_encap", false, kem_hook,
          [] { MLKEM768_public_from_private(&m.pub, &m.priv); MLKEM768_encap(m.ct, m.ss, &m.pub); return true; },
          "counter moves because encap draws from the DRBG: false positive");
    probe("ML-KEM-768 decap", "MLKEM768_decap", false, kem_hook,
          [] { uint8_t ss[MLKEM_SHARED_SECRET_BYTES]; return MLKEM768_decap(ss, m.ct, sizeof(m.ct), &m.priv) == 1; });
  }

  probe_sig("ECDSA P-256 / SHA-256", {ec_pkey(NID_X9_62_prime256v1), EVP_sha256(), false}, "", "");
  probe_sig("ECDSA P-384 / SHA-384", {ec_pkey(NID_secp384r1), EVP_sha384(), false}, "", "");
  probe_sig("ECDSA P-521 / SHA-512", {ec_pkey(NID_secp521r1), EVP_sha512(), false}, "", "");
  {
    bssl::UniquePtr<EVP_PKEY> rsa2048 = rsa_key(2048), rsa3072 = rsa_key(3072), rsa1024 = rsa_key(1024);
    auto share = [](const bssl::UniquePtr<EVP_PKEY> &k) { EVP_PKEY_up_ref(k.get()); return bssl::UniquePtr<EVP_PKEY>(k.get()); };
    probe_sig("RSA-2048 PKCS#1 v1.5 / SHA-256", {share(rsa2048), EVP_sha256(), false}, "", "");
    probe_sig("RSA-2048 PKCS#1 v1.5 / SHA-384", {share(rsa2048), EVP_sha384(), false}, "", "");
    probe_sig("RSA-2048 PKCS#1 v1.5 / SHA-512", {share(rsa2048), EVP_sha512(), false}, "", "");
    probe_sig("RSA-3072 PKCS#1 v1.5 / SHA-256", {share(rsa3072), EVP_sha256(), false}, "", "");
    probe_sig("RSA-2048 PSS / SHA-256, salt = digest", {share(rsa2048), EVP_sha256(), true}, "", "");
    probe_sig("RSA-3072 PSS / SHA-384, salt = digest", {share(rsa3072), EVP_sha384(), true}, "", "");
    probe_sig("RSA-2048 PKCS#1 v1.5 / SHA-1", {share(rsa2048), EVP_sha1(), false},
              "SHA-1 signature generation: not approved (is_md_fips_approved_for_signing excludes SHA-1)",
              "SHA-1 signature verification: legacy use");
    probe_sig("RSA-1024 PKCS#1 v1.5 / SHA-256", {share(rsa1024), EVP_sha256(), false},
              "RSA-1024 signature generation", "RSA-1024 signature verification: legacy use");
  }

  probe("Ed25519 sign", "ED25519_sign", false,
        "crypto/curve25519/ is outside the FIPS module; the counter moves because of the internal SHA-512 (false positive)",
        [] { uint8_t pub[32], priv[64], sig[64]; const uint8_t msg[4] = {1}; ED25519_keypair(pub, priv); return ED25519_sign(sig, msg, sizeof(msg), priv) == 1; });
  probe("Ed25519 verify", "ED25519_verify", false,
        "crypto/curve25519/ is outside the FIPS module (false positive via SHA-512)",
        [] { uint8_t pub[32], priv[64], sig[64]; const uint8_t msg[4] = {1}; ED25519_keypair(pub, priv); ED25519_sign(sig, msg, sizeof(msg), priv); return ED25519_verify(msg, sizeof(msg), sig, pub) == 1; });

  probe("Random bytes", "RAND_bytes", true,
        "rand/ctrdrbg.cc.inc: FIPS_service_indicator_update_state in CTR_DRBG_generate",
        [] { uint8_t b[32]; return RAND_bytes(b, sizeof(b)) == 1; });

  printf("| Service | Call | Indicator | Covered by indicator | Verdict | Hook (source) | Note |\n");
  printf("|---|---|---|---|---|---|---|\n");
  int bad = 0;
  for (const Row &r : rows) {
    if (!r.ok) bad++;
    const char *ind = r.approved ? "approved" : "not approved";
    const char *verdict = !r.covered ? "**not covered**" : (r.approved ? "APPROVED" : "not approved");
    printf("| %s | `%s`%s | %s | %s | %s | %s | %s |\n", r.service.c_str(), r.call.c_str(),
           r.ok ? "" : " **(call FAILED)**", ind, r.covered ? "yes" : "no", verdict,
           r.hook.c_str(), r.note.c_str());
  }
  printf("\n%zu services probed, %d call failures.\n", rows.size(), bad);
  if (!fips) {
    fprintf(stderr, "indicator-report: not a FIPS build (FIPS_mode()==0); readings are meaningless\n");
    return 2;
  }
  return bad == 0 ? 0 : 1;
}
