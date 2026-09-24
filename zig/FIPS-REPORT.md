# FIPS report — BoringCrypto via zoptia0boringssl

Status: **draft** — section 4.3 and the non-FIPS half of 4.2 wait for the next green CI run. Written 2026-09-24 against upstream BoringSSL `83b18cdb1`.

Note on commit references: on 2026-09-24 the fork's history was squashed
into a single commit on top of `upstream/main` (author Zoptia). Fork commit
hashes quoted below (`fbc3c6102`, `v0.20260924.2`) refer to the pre-squash
history and no longer resolve; the content they name is what tag
`v0.20260924.3` contains. Upstream hashes (`83b18cdb1`) are unchanged.

This document separates **facts** (quoted or paraphrased from a named source,
with the location) from **inferences** (our reading of those facts). Nothing in
it makes the module "FIPS validated"; a `-Dfips=true` build is an update-stream
FIPS mode build with `FIPS_version() == 0`.

Sources used (local copies of the PDFs were text-extracted for citation):

- [IG] *Implementation Guidance for FIPS PUB 140-3 and the Cryptographic Module
  Validation Program*, NIST/CCCS, last update **August 19, 2026**. Cited as
  IG §x.y, page numbers as printed.
- [SP135] NIST SP 800-135 Rev. 1, *Recommendation for Existing
  Application-Specific Key Derivation Functions*, December 2011.
- [SP-BC] *BoringCrypto FIPS 140-3 Non-Proprietary Security Policy*, Google LLC,
  Version 1.0 (2026), for **software version 20240805**, CMVP document
  `140sp5244.pdf` (certificate #5244).
- [SP-AWS] *AWS-LC 3 Cryptographic Module (static) FIPS 140-3 Non-Proprietary
  Security Policy*, AWS / atsec, last update 2026-05-20, for **AWS-LC FIPS
  3.1.0**, `140sp5314.pdf` (certificate #5314).
- [CAVP-A7700] CAVP validation A7700, BoringCrypto version 20251031, first
  validated 2025-11-21.
- [BSSL] this tree: `crypto/fipsmodule/**`, `include/openssl/**`,
  `crypto/fipsmodule/FIPS.md`.
- [AWSLC] `aws/aws-lc` `main` as of 2026-09-24: `crypto/fipsmodule/FIPS.md`,
  `crypto/fipsmodule/service_indicator/service_indicator.c`,
  `crypto/fipsmodule/cipher/e_aes.c`, `crypto/fipsmodule/dh/dh.c`,
  `util/fipstools/delocate/delocate.go`, `CMakeLists.txt`.

---

## 1. Service-indicator measurements

Measured on GitHub Actions (CI run 36064583875 for commit `fbc3c6102`, job `fips`),
Zig 0.16.0, Go 1.27.0, `-Dfips=true -Doptimize=ReleaseFast`, by
`zig build indicator-report` (`zig/indicator_report.cc`). Both architectures
produced the identical table; module hashes: x86_64 `80778a203995baad6be0f2252cba141ead4cb4e785a424fd4e414c0a66782ad8`, aarch64 `44299ce2381350f4044c923805e2be2f7afb84e1a5e936af047a3c91a2cea25f`.
`FIPS_mode()==1`, `FIPS_version()==0`. 58 services probed, 0 call failures.

**Downstream measurement (same table).** The downstream ran the same
`indicator-report` on `fbc3c6102` with `-Dfips=true -Doptimize=fast` on
Debian 13 (Linux 6.12.95+deb13-amd64), QEMU Virtual CPU 2.5+ (6 cores, KVM;
`aes`, `ssse3`, `sse4_2`, no `pclmulqdq`/AVX/ADX), Zig 0.17.0-dev.2131,
Go 1.27.0: 58 services, 0 call failures, every row identical to the table
below. Module hash there: `86dff17c41b8d1ceff5df197e55edcdee1909eeff578cfa9e378624582332782`,
unchanged from `v0.20260924.1` through `fbc3c6102` (the module bytes did not
change between those versions); the CI hashes above differ because CI builds
with Zig 0.16.0 and a different `-mcpu`.

Summary:

- **APPROVED**: AES-GCM decrypt (caller nonce); AES-GCM encrypt only through
  the `_randnonce`, `_tls12`, `_tls13` AEADs; HMAC-SHA-1/256/384/512;
  `EC_KEY_generate_key_fips`; `ECDH_compute_key_fips`; ECDSA P-256/384/521 with
  SHA-2, sign and verify; RSA-2048/3072 PKCS#1 v1.5 and PSS with SHA-2, sign
  and verify; `RAND_bytes`.
- **not approved** (covered, deliberate): AES-GCM encrypt with a caller nonce;
  `EC_KEY_generate_key`; `ECDH_compute_key` (raw Z); RSA with SHA-1 (sign
  *and* verify); RSA-1024 (sign and verify).
- **not covered** (no hook; the counter is not evidence): ChaCha20-Poly1305,
  X25519, Ed25519, MODP via `BN_mod_exp`, FFDHE via `DH_compute_key_padded`
  and `DH_compute_key_hashed`, every ML-KEM-768 entry point.

Column meaning: *Indicator* is what the counter said around that exact call;
*Covered* is whether the module has a hook that makes a deliberate decision
for this service (derived from source, checked by
`zig/check-indicator-coverage.sh`); *Verdict* is the honest reading —
"not covered" means the counter is not evidence either way.

| Service | Call | Indicator | Covered by indicator | Verdict | Hook (source) | Note |
|---|---|---|---|---|---|---|
| AES-128-GCM encrypt | `EVP_AEAD_CTX_seal, caller 12-byte nonce` | not approved | yes | not approved | cipher/e_aes.cc.inc: AEAD_GCM_verify_service_indicator in openv_detached, sealv_randnonce, tls12_sealv, tls13_sealv; absent from generic sealv | external IV: not approved by design (IG C.H); upstream test expects NOT_APPROVED |
| AES-256-GCM encrypt | `EVP_AEAD_CTX_seal, caller 12-byte nonce` | not approved | yes | not approved | cipher/e_aes.cc.inc: AEAD_GCM_verify_service_indicator in openv_detached, sealv_randnonce, tls12_sealv, tls13_sealv; absent from generic sealv | external IV: not approved by design (IG C.H) |
| AES-128-GCM decrypt | `EVP_AEAD_CTX_open, caller nonce` | approved | yes | APPROVED | cipher/e_aes.cc.inc: AEAD_GCM_verify_service_indicator in openv_detached, sealv_randnonce, tls12_sealv, tls13_sealv; absent from generic sealv | decrypt with external IV: approved by design |
| AES-256-GCM decrypt | `EVP_AEAD_CTX_open, caller nonce` | approved | yes | APPROVED | cipher/e_aes.cc.inc: AEAD_GCM_verify_service_indicator in openv_detached, sealv_randnonce, tls12_sealv, tls13_sealv; absent from generic sealv | decrypt with external IV: approved by design |
| AES-256-GCM encrypt, internal IV | `EVP_AEAD_CTX_seal, EVP_aead_aes_256_gcm_randnonce` | approved | yes | APPROVED | cipher/e_aes.cc.inc: AEAD_GCM_verify_service_indicator in openv_detached, sealv_randnonce, tls12_sealv, tls13_sealv; absent from generic sealv | module generates the 96-bit IV from its DRBG (IG C.H technique 2) |
| AES-128-GCM encrypt, TLS 1.2 nonce | `EVP_AEAD_CTX_seal, EVP_aead_aes_128_gcm_tls12` | approved | yes | APPROVED | cipher/e_aes.cc.inc: AEAD_GCM_verify_service_indicator in openv_detached, sealv_randnonce, tls12_sealv, tls13_sealv; absent from generic sealv | 4-byte fixed + 8-byte strictly increasing counter, enforced per ctx |
| AES-256-GCM encrypt, TLS 1.3 nonce | `EVP_AEAD_CTX_seal, EVP_aead_aes_256_gcm_tls13` | approved | yes | APPROVED | cipher/e_aes.cc.inc: AEAD_GCM_verify_service_indicator in openv_detached, sealv_randnonce, tls12_sealv, tls13_sealv; absent from generic sealv | 12-byte XOR-masked counter nonce, enforced per ctx |
| ChaCha20-Poly1305 encrypt | `EVP_AEAD_CTX_seal` | not approved | no | **not covered** | crypto/cipher/e_chacha20poly1305.cc is outside the FIPS module; not an approved algorithm |  |
| HMAC-SHA-1 | `HMAC() one-shot` | approved | yes | APPROVED | hmac/hmac.cc.inc: HMAC_verify_service_indicator (SHA-1/224/256/384/512/512-256) | HMAC with SHA-1 is approved (SP 800-131A: SHA-1 remains acceptable for HMAC) |
| HMAC-SHA-256 | `HMAC() one-shot` | approved | yes | APPROVED | hmac/hmac.cc.inc: HMAC_verify_service_indicator (SHA-1/224/256/384/512/512-256) |  |
| HMAC-SHA-384 | `HMAC() one-shot` | approved | yes | APPROVED | hmac/hmac.cc.inc: HMAC_verify_service_indicator (SHA-1/224/256/384/512/512-256) |  |
| HMAC-SHA-512 | `HMAC() one-shot` | approved | yes | APPROVED | hmac/hmac.cc.inc: HMAC_verify_service_indicator (SHA-1/224/256/384/512/512-256) |  |
| EC keygen P-256 | `EC_KEY_generate_key` | not approved | yes | not approved | ec/ec_key.cc.inc: EC_KEY_keygen_verify_service_indicator in EC_KEY_check_fips (called by EC_KEY_generate_key_fips only) | no pairwise consistency test: not approved; use EC_KEY_generate_key_fips |
| EC keygen P-256 | `EC_KEY_generate_key_fips` | approved | yes | APPROVED | ec/ec_key.cc.inc: EC_KEY_keygen_verify_service_indicator in EC_KEY_check_fips (called by EC_KEY_generate_key_fips only) |  |
| EC keygen P-384 | `EC_KEY_generate_key` | not approved | yes | not approved | ec/ec_key.cc.inc: EC_KEY_keygen_verify_service_indicator in EC_KEY_check_fips (called by EC_KEY_generate_key_fips only) | no pairwise consistency test: not approved; use EC_KEY_generate_key_fips |
| EC keygen P-384 | `EC_KEY_generate_key_fips` | approved | yes | APPROVED | ec/ec_key.cc.inc: EC_KEY_keygen_verify_service_indicator in EC_KEY_check_fips (called by EC_KEY_generate_key_fips only) |  |
| EC keygen P-521 | `EC_KEY_generate_key` | not approved | yes | not approved | ec/ec_key.cc.inc: EC_KEY_keygen_verify_service_indicator in EC_KEY_check_fips (called by EC_KEY_generate_key_fips only) | no pairwise consistency test: not approved; use EC_KEY_generate_key_fips |
| EC keygen P-521 | `EC_KEY_generate_key_fips` | approved | yes | APPROVED | ec/ec_key.cc.inc: EC_KEY_keygen_verify_service_indicator in EC_KEY_check_fips (called by EC_KEY_generate_key_fips only) |  |
| ECDH P-256 raw shared secret | `ECDH_compute_key` | not approved | yes | not approved | ecdh/ecdh.cc.inc: ECDH_verify_service_indicator in ECDH_compute_key_fips only | raw Z output (what IKEv2 SKEYSEED needs): not approved |
| ECDH P-256 hashed | `ECDH_compute_key_fips` | approved | yes | APPROVED | ecdh/ecdh.cc.inc: ECDH_verify_service_indicator in ECDH_compute_key_fips only | output is SHA-2 of Z, not Z itself |
| ECDH P-384 raw shared secret | `ECDH_compute_key` | not approved | yes | not approved | ecdh/ecdh.cc.inc: ECDH_verify_service_indicator in ECDH_compute_key_fips only | raw Z output (what IKEv2 SKEYSEED needs): not approved |
| ECDH P-384 hashed | `ECDH_compute_key_fips` | approved | yes | APPROVED | ecdh/ecdh.cc.inc: ECDH_verify_service_indicator in ECDH_compute_key_fips only | output is SHA-2 of Z, not Z itself |
| ECDH P-521 raw shared secret | `ECDH_compute_key` | not approved | yes | not approved | ecdh/ecdh.cc.inc: ECDH_verify_service_indicator in ECDH_compute_key_fips only | raw Z output (what IKEv2 SKEYSEED needs): not approved |
| ECDH P-521 hashed | `ECDH_compute_key_fips` | approved | yes | APPROVED | ecdh/ecdh.cc.inc: ECDH_verify_service_indicator in ECDH_compute_key_fips only | output is SHA-2 of Z, not Z itself |
| MODP-2048 DH via bignum | `BN_mod_exp with BN_get_rfc3526_prime_2048` | not approved | no | **not covered** | bn/ has no indicator hook; this is arithmetic, not a module DH service |  |
| FFDHE-2048 DH raw shared secret | `DH_compute_key_padded` | not approved | no | **not covered** | dh/dh.cc.inc has no indicator hook at all (only ECDH has one); DH_compute_key_hashed locks the counter around its internal SHA |  |
| FFDHE-2048 DH hashed | `DH_compute_key_hashed, SHA-256` | not approved | no | **not covered** | dh/dh.cc.inc has no indicator hook at all (only ECDH has one); DH_compute_key_hashed locks the counter around its internal SHA |  |
| X25519 | `X25519_keypair + X25519` | approved | no | **not covered** | crypto/curve25519/ is outside the FIPS module |  |
| ML-KEM-768 keygen | `MLKEM768_generate_key` | approved | no | **not covered** | fipsmodule/mlkem/ has no indicator hook; any 'approved' reading comes from the DRBG (RAND_bytes) it calls internally | public wrapper calls BCM_mlkem768_generate_key (no PCT) |
| ML-KEM-768 keygen, FIPS path | `BCM_mlkem768_generate_key_fips (internal, bcm_interface.h)` | approved | no | **not covered** | fipsmodule/mlkem/ has no indicator hook; any 'approved' reading comes from the DRBG (RAND_bytes) it calls internally | keygen with pairwise consistency test; no public C wrapper exists |
| ML-KEM-768 key from seed | `MLKEM768_private_key_from_seed` | not approved | no | **not covered** | fipsmodule/mlkem/ has no indicator hook; any 'approved' reading comes from the DRBG (RAND_bytes) it calls internally |  |
| ML-KEM-768 encap | `MLKEM768_encap` | approved | no | **not covered** | fipsmodule/mlkem/ has no indicator hook; any 'approved' reading comes from the DRBG (RAND_bytes) it calls internally | counter moves because encap draws from the DRBG: false positive |
| ML-KEM-768 decap | `MLKEM768_decap` | not approved | no | **not covered** | fipsmodule/mlkem/ has no indicator hook; any 'approved' reading comes from the DRBG (RAND_bytes) it calls internally |  |
| ECDSA P-256 / SHA-256 | `EVP_DigestSign` | approved | yes | APPROVED | digestsign/digestsign.cc.inc: EVP_DigestSign/Verify_verify_service_indicator |  |
| ECDSA P-256 / SHA-256 | `EVP_DigestVerify` | approved | yes | APPROVED | digestsign/digestsign.cc.inc: EVP_DigestSign/Verify_verify_service_indicator |  |
| ECDSA P-384 / SHA-384 | `EVP_DigestSign` | approved | yes | APPROVED | digestsign/digestsign.cc.inc: EVP_DigestSign/Verify_verify_service_indicator |  |
| ECDSA P-384 / SHA-384 | `EVP_DigestVerify` | approved | yes | APPROVED | digestsign/digestsign.cc.inc: EVP_DigestSign/Verify_verify_service_indicator |  |
| ECDSA P-521 / SHA-512 | `EVP_DigestSign` | approved | yes | APPROVED | digestsign/digestsign.cc.inc: EVP_DigestSign/Verify_verify_service_indicator |  |
| ECDSA P-521 / SHA-512 | `EVP_DigestVerify` | approved | yes | APPROVED | digestsign/digestsign.cc.inc: EVP_DigestSign/Verify_verify_service_indicator |  |
| RSA-2048 PKCS#1 v1.5 / SHA-256 | `EVP_DigestSign` | approved | yes | APPROVED | digestsign/digestsign.cc.inc: EVP_DigestSign/Verify_verify_service_indicator |  |
| RSA-2048 PKCS#1 v1.5 / SHA-256 | `EVP_DigestVerify` | approved | yes | APPROVED | digestsign/digestsign.cc.inc: EVP_DigestSign/Verify_verify_service_indicator |  |
| RSA-2048 PKCS#1 v1.5 / SHA-384 | `EVP_DigestSign` | approved | yes | APPROVED | digestsign/digestsign.cc.inc: EVP_DigestSign/Verify_verify_service_indicator |  |
| RSA-2048 PKCS#1 v1.5 / SHA-384 | `EVP_DigestVerify` | approved | yes | APPROVED | digestsign/digestsign.cc.inc: EVP_DigestSign/Verify_verify_service_indicator |  |
| RSA-2048 PKCS#1 v1.5 / SHA-512 | `EVP_DigestSign` | approved | yes | APPROVED | digestsign/digestsign.cc.inc: EVP_DigestSign/Verify_verify_service_indicator |  |
| RSA-2048 PKCS#1 v1.5 / SHA-512 | `EVP_DigestVerify` | approved | yes | APPROVED | digestsign/digestsign.cc.inc: EVP_DigestSign/Verify_verify_service_indicator |  |
| RSA-3072 PKCS#1 v1.5 / SHA-256 | `EVP_DigestSign` | approved | yes | APPROVED | digestsign/digestsign.cc.inc: EVP_DigestSign/Verify_verify_service_indicator |  |
| RSA-3072 PKCS#1 v1.5 / SHA-256 | `EVP_DigestVerify` | approved | yes | APPROVED | digestsign/digestsign.cc.inc: EVP_DigestSign/Verify_verify_service_indicator |  |
| RSA-2048 PSS / SHA-256, salt = digest | `EVP_DigestSign` | approved | yes | APPROVED | digestsign/digestsign.cc.inc: EVP_DigestSign/Verify_verify_service_indicator |  |
| RSA-2048 PSS / SHA-256, salt = digest | `EVP_DigestVerify` | approved | yes | APPROVED | digestsign/digestsign.cc.inc: EVP_DigestSign/Verify_verify_service_indicator |  |
| RSA-3072 PSS / SHA-384, salt = digest | `EVP_DigestSign` | approved | yes | APPROVED | digestsign/digestsign.cc.inc: EVP_DigestSign/Verify_verify_service_indicator |  |
| RSA-3072 PSS / SHA-384, salt = digest | `EVP_DigestVerify` | approved | yes | APPROVED | digestsign/digestsign.cc.inc: EVP_DigestSign/Verify_verify_service_indicator |  |
| RSA-2048 PKCS#1 v1.5 / SHA-1 | `EVP_DigestSign` | not approved | yes | not approved | digestsign/digestsign.cc.inc: EVP_DigestSign/Verify_verify_service_indicator | SHA-1 signature generation: not approved (is_md_fips_approved_for_signing excludes SHA-1) |
| RSA-2048 PKCS#1 v1.5 / SHA-1 | `EVP_DigestVerify` | not approved | yes | not approved | digestsign/digestsign.cc.inc: EVP_DigestSign/Verify_verify_service_indicator | SHA-1 signature verification: legacy use |
| RSA-1024 PKCS#1 v1.5 / SHA-256 | `EVP_DigestSign` | not approved | yes | not approved | digestsign/digestsign.cc.inc: EVP_DigestSign/Verify_verify_service_indicator | RSA-1024 signature generation |
| RSA-1024 PKCS#1 v1.5 / SHA-256 | `EVP_DigestVerify` | not approved | yes | not approved | digestsign/digestsign.cc.inc: EVP_DigestSign/Verify_verify_service_indicator | RSA-1024 signature verification: legacy use |
| Ed25519 sign | `ED25519_sign` | approved | no | **not covered** | crypto/curve25519/ is outside the FIPS module; the counter moves because of the internal SHA-512 (false positive) |  |
| Ed25519 verify | `ED25519_verify` | approved | no | **not covered** | crypto/curve25519/ is outside the FIPS module (false positive via SHA-512) |  |
| Random bytes | `RAND_bytes` | approved | yes | APPROVED | rand/ctrdrbg.cc.inc: FIPS_service_indicator_update_state in CTR_DRBG_generate |  |

Differences from the downstream's own measurements on `v0.20260924.1`
(Debian 13): none in substance. Two rows are worth calling out because they
differ from what one might expect from the AWS-LC design: **RSA-2048 PKCS#1
v1.5 / SHA-1 verification** and **RSA-1024 verification** both read "not
approved" (covered) — BoringCrypto's `is_md_fips_approved_for_verifying` /
RSA size rules do not grant them legacy-verify status through
`EVP_DigestVerify`, unlike AWS-LC's `rsa_1024_ok` path. X25519 reads
"approved" but is **not covered**: `X25519_keypair` draws from the DRBG, a
false positive of the same kind as ML-KEM keygen.
---

## 2. Can IKEv2 run entirely on BoringCrypto's approved services?

Short answer, with the reasoning below: **no, not today, on three of the four
points** — raw shared secret, IKEv2 KDF, and ESP/IKE AES-GCM with a
caller-constructed IV all fall outside what BoringCrypto's indicator and
Security Policy call approved. ML-KEM is CAVP-tested for the newest
BoringCrypto version but not yet in a completed CMVP validation.

### 2.1 Raw ECDH / DH shared secret (g^ir for SKEYSEED)

**Facts**

- IKEv2 needs the unhashed shared secret: SP 800-135 §4.1.2 defines
  `SKEYSEED = HMAC(Ni || Nr, g^ir)` — the HMAC *is* the randomness-extraction
  step over the raw DH value [SP135 §4.1.2, p.10].
- IG D.F allows a module to be validated for the shared-secret computation
  alone: "(1) A CAVP-tested compliance with the derivation of a shared secret Z
  in one or more of the key agreement schemes in Section 6 of SP 800-56Arev3.
  This compliance will be annotated as KAS-ECC-SSC or KAS-FFC-SSC in the
  module's validation certificate." [IG D.F, Scenario 2, p.187]. The KDF may
  then be a separate KDA or CVL [IG D.F, p.188].
- BoringCrypto #5244 lists KAS-ECC-SSC (P-224/256/384/521, ephemeralUnified and
  staticUnified, initiator and responder) and KAS-FFC-SSC (domain parameter
  generation methods **FB, FC**; scheme dhEphem; KAS role initiator)
  [SP-BC Table 8]. Its §2.10: "The module provides the cryptographic building
  blocks for key agreement in its SP 800-56Arev3 KAS-ECC-SSC and KAS-FFC-SSC
  algorithms. A calling application may link these to the module's SP
  800-135rev1 TLS v1.2 KDF or RFC 8446 TLS v1.3 KDF to form a complete
  KAS-ECC or KAS-FFC approved key agreement scheme." The approved-services
  table shows a Key Agreement service with "fips_service_indicator set to 1"
  and outputs "Return code, shared secret" [SP-BC Table 11].
- Raw DH is explicitly non-approved: "DH (non-compliant) — Non-Approved key
  agreement" [SP-BC Table 7] and "Key Agreement: Perform non-compliant DH key
  agreement" [SP-BC Table 12].
- In the source, the only ECDH path with an indicator hook is
  `ECDH_compute_key_fips`, whose output is a SHA-2 digest of Z
  (`crypto/fipsmodule/ecdh/ecdh.cc.inc:89`); `ECDH_compute_key` (raw Z) has
  none. The only DH path with any indicator interaction is
  `DH_compute_key_hashed`, which *locks* the counter while it runs and never
  updates it (`crypto/fipsmodule/dh/dh.cc.inc:309-345`); there is no DH hook
  anywhere in the module. [BSSL]

**Inferences**

- The "shared secret" the Security Policy's KAS-SSC service outputs is the
  hashed Z of `ECDH_compute_key_fips` / `DH_compute_key_hashed`. (The
  ACVP KAS-SSC test lets an implementation return a hash of Z instead of Z;
  we have not verified BoringCrypto's ACVP capability registration, so this
  is an inference from the code and the service table.)
- Therefore **BoringCrypto has no approved entry point that returns raw
  g^ir**, so IKEv2's `SKEYSEED = prf(Ni|Nr, g^ir)` cannot be fed from an
  indicated-approved service. An application that calls `ECDH_compute_key`
  gets a "not approved" reading (measured by the downstream, consistent with
  the code).
- For MODP groups specifically: IG D.D permits RFC 3526 MODP and RFC 7919
  FFDHE safe-prime groups in approved key agreement [IG D.D, p.183], but
  BoringCrypto's KAS-FFC-SSC entry is validated with FB/FC domain parameters
  only, and the raw `DH_compute_key_padded` is non-approved. We read this as:
  **no approved MODP-2048/3072/4096 path exists in BoringCrypto**, hashed or
  raw. A CST lab's reading of the certificate would be needed to confirm.

### 2.2 The IKEv2 KDF (prf+)

**Facts**

- SP 800-135 treats the IKEv2 KDF as an approved application-specific KDF:
  "The IKEv2 KDFs, which are compliant with SP 800-56C, are approved when used
  with an approved HMAC function using an approved hash function" [SP135
  §4.1.2, p.10]. Its scope statement: "Conformance testing for implementations
  of this Recommendation will be conducted within the framework of the CMVP
  and the CAVP … Some of these requirements may be out-of-scope for CMVP or
  CAVP validation testing, and thus are the responsibility of entities using,
  implementing, installing or configuring applications that incorporate this
  Recommendation." [SP135 §1, p.4].
- The CAVP has a test for it ("KDF IKEv2", `kdf-components` / `ikev2`) and it
  is an approved algorithm only as a CVL with the usage restriction "Shall
  only be used in the context of their respective protocols" [IG 2.4.B].
- IG D.C spells out the cases [IG D.C, pp.181-182]: (1) module implements an
  SP 800-135 KDF without CAVP validation → "none of the keys derived using
  this key derivation function can be used in the approved mode"; (2) module
  implements it with CAVP validation → listed as CVL; (3) "If the module does
  not implement any KDFs from SP 800-135rev1 but the module's Security Policy
  claims that the module supports or uses parts of the corresponding
  protocol(s) then no entry on the certificate's approved or allowed
  algorithms lines is required … the Security Policy shall state that this
  protocol has not been reviewed or tested by the CAVP and CMVP. This
  situation may occur when a module implements a portion of a protocol, e.g.
  not including the KDF, and it is the calling application's responsibility
  to perform the entire protocol."
- BoringCrypto's module contains HKDF, the TLS 1.0-1.3 KDFs, and no IKEv2 KDF
  (`crypto/fipsmodule/bcm.cc` includes `hkdf/hkdf.cc.inc` and
  `tls/kdf.cc.inc`; no prf+ exists in the tree). Its certificate lists KDA
  HKDF and TLS v1.2/v1.3 KDF only [SP-BC Table 8; CAVP-A7700 likewise]. The
  HKDF implementation has no indicator hook; the TLS KDF does
  (`crypto/fipsmodule/tls/kdf.cc.inc:139,177`). [BSSL]
- AWS-LC's FIPS module likewise implements no IKEv2 KDF [AWSLC
  `service_indicator.c`; SP-AWS Table 5 lists HKDF, OneStep, SP 800-108, SSH,
  TLS].

**Inference**

- prf+ built in the application from BoringCrypto's approved HMAC is IG D.C
  case 3 from the module's side: the HMAC calls are approved services, but the
  IKEv2 KDF as an algorithm is unvalidated and the protocol "has not been
  reviewed or tested by the CAVP and CMVP". Whether that is acceptable is a
  question for the *product's* validation or the customer's compliance
  authority, not something the library can settle. The only way to get an
  approved IKEv2 KDF is a module that implements it inside its boundary and
  has the "KDF IKEv2" CVL (case 2); neither BoringCrypto nor AWS-LC does.

### 2.3 AES-GCM with a caller-constructed nonce (ESP / IKE SK)

**Facts — the guidance**

- IG C.H lists five acceptable IV-generation scenarios. Scenario 1 is
  "Construct the IV in compliance with the provisions of a peer-to-peer
  industry standard protocol" and the acceptable protocols include both
  "TLS 1.2 GCM Cipher Suites … TLS 1.3 …" and "IPsec-v3 protocol, as described
  in RFCs 4106, 5282, and 7296" [IG C.H, p.146].
- For TLS: "If an IV is constructed according to the TLS/DTLS 1.2 or TLS/DTLS
  1.3 protocol, then this IV may only be used in the context of the AES-GCM
  mode encryption within the same version of the TLS/DTLS protocol." [IG C.H,
  p.147].
- For IPsec: "If the vendor claims that the IV generation is in compliance
  with the IPsec-v3 specification and only for use within the IPsec-v3
  protocol then the module's Security Policy and the Validation Test Report
  shall explicitly state the module's compliance with RFC 4106 and/or RFC 5282
  … shall also state that the module uses RFC 7296 compliant IKEv2 to
  establish the shared secret SKEYSEED … the construction of the last 64 bits
  of the 'nonce' (the IV in RFC 5282) … shall be deterministic (e.g., using a
  counter) and satisfy one of the IV restoration conditions defined in
  Scenario 3a … The implementation of the management logic for the last 64
  bits of the 'nonce' inside the module shall ensure that when the IV …
  exhausts the maximum number of possible values … either party … triggers a
  rekeying with IKEv2" [IG C.H, p.148].

**Facts — BoringCrypto**

- The Security Policy claims Scenario 5 (TLS 1.3), Scenario 1 for TLS 1.2 (RFC
  5288) and Scenario 2 (internal DRBG, 96-bit IV) and then states: "In
  approved mode, only internally generated IVs, or the TLS modes described
  above, are considered compliant for use." [SP-BC §2.7 AES-GCM, pp.13-14].
  IPsec, RFC 4106 and RFC 5282 are not mentioned anywhere in the policy.
- Code: generic `EVP_aead_aes_*_gcm` seal has no indicator hook; open does
  (`e_aes.cc.inc:880`); `_randnonce`, `_tls12` and `_tls13` seal are hooked
  (`e_aes.cc.inc:981,1098,1200`). Upstream's own test expects the generic
  external-IV seal to be NOT_APPROVED
  (`service_indicator_test.cc:560-590`). [BSSL]
- `EVP_aead_aes_*_gcm_tls12` seal constraints, from
  `aead_aes_gcm_tls12_sealv` (`e_aes.cc.inc:1071-1094`): nonce must be 12
  bytes; the counter is the **last 8 bytes, big-endian**; it must satisfy
  `counter != UINT64_MAX && counter >= min_next_nonce`, where
  `min_next_nonce` starts at 0 and is set to `counter + 1` after each seal.
  So: the first counter may be any value (0 allowed), gaps are allowed,
  strictly increasing is enforced, `2^64-1` is rejected. **The first 4 bytes
  are not checked** by the code. There is no tls12-specific open: decryption
  is the generic open with no nonce check.
- RFC 4106 §3.1 fixes the ESP GCM IV field on the wire at 8 octets, with the
  4-octet salt taken from the key material (cited in IG C.H's own wording:
  "IPsec-v3 requires four octets of salt followed by eight octets of
  deterministic nonce").

**Inferences**

- Structurally the tls12 AEAD does exactly what IG C.H asks of the IPsec
  scenario's last 64 bits (deterministic, monotonic, exhaustion detectable),
  and an ESP sequence-number IV would pass its checks. But IG C.H binds a
  TLS-constructed IV to "the same version of the TLS/DTLS protocol", and
  BoringCrypto's policy restricts approved use to "the TLS modes described
  above". Using `_tls12` for ESP is therefore **outside both the IG's TLS
  scenario and the module's approved-mode claims**; the indicator saying
  "approved" would be measuring the TLS-1.2 service, not an IPsec one. We do
  not think this can be presented as approved AES-GCM for IPsec.
- The IPsec-v3 scenario can only be claimed by a module whose Security Policy
  and test report state RFC 4106/5282 compliance and the IKEv2 linkage.
  BoringCrypto and AWS-LC both claim only TLS + internal-DRBG scenarios. A
  module that does claim it (e.g. Linux kernel crypto API modules for
  `rfc4106(gcm(aes))`) would be the way to get approved ESP encryption.
- `_randnonce` (Scenario 2) is approved but incompatible with ESP: it produces
  a 96-bit random IV that the caller must transmit, while ESP's IV field is 8
  octets. It fits IKE SK payloads only if the peer also accepts a 12-byte IV,
  which RFC 5282 does not.
- Decryption with a caller nonce is approved in both libraries; only the
  encrypt direction is the problem.

### 2.4 ML-KEM

**Facts**

- BoringCrypto #5244 (20240805) has no ML-KEM entry in its approved-algorithm
  tables [SP-BC Tables 5-8]. The 20251031 version is CAVP-validated with
  "ML-KEM KeyGen and EncapDecap" (A7700, 2025-11-21), alongside ML-DSA and
  SLH-DSA [CAVP-A7700]; its CMVP validation is listed as "Review Pending at
  NIST" [BSSL `FIPS.md`, Validations table]. The BoringCrypto ML-KEM is
  inside the module (`bcm.cc` includes `mlkem/mlkem.cc.inc`) and has a
  power-on KAT (`self_check.cc.inc:1073`).
- No counter hook exists under `crypto/fipsmodule/mlkem/`. Instead the BCM
  interface returns an in-band status: "Two success values are used to
  correspond to the FIPS service indicator. For the moment, the official
  service indicator remains the counter, not these values. Once we fully
  transition to these return values from bcm we will change that."
  (`crypto/fipsmodule/bcm_interface.h:36-40`, `bcm_status_t { approved,
  not_approved, failure }`).
- The public C wrappers discard that distinction: `MLKEM768_decap`,
  `MLKEM768_private_key_from_seed` etc. return `bcm_success(...)`, which maps
  both `approved` and `not_approved` to 1 (`crypto/mlkem/mlkem.cc`).
  `MLKEM768_generate_key` calls `BCM_mlkem768_generate_key` (no pairwise
  consistency test); `BCM_mlkem768_generate_key_fips` (with the PCT,
  returning `bcm_status`) has no public wrapper and is reachable only through
  the internal `bcm_interface.h`. [BSSL]

**Inferences**

- "Is ML-KEM an approved service in BoringCrypto?" — not in any *completed*
  validation as of this report; it is in the CAVP-tested, CMVP-pending
  20251031 version. Our `-Dfips=true` build of today's `main` carries that
  implementation but no certificate.
- "Why no indicator?" — by upstream's own comment, ML-KEM sits on the new
  return-value indicator that has not yet become "official"; the public API
  throws that value away, and the counter that *is* official was never
  wired for it. That is why the counter reads as a false positive (DRBG
  usage) for keygen/encap and as nothing for decap.
- The approved-shaped path, once a validation covers it, is the BCM
  interface: `BCM_mlkem768_generate_key_fips` (keygen with PCT), then
  encap/decap, reading the `bcm_status` return. From the public API alone
  there is currently no way to observe the approval status.

---

## 3. AWS-LC as an alternative

### 3.1 Comparison

| Question | BoringCrypto (this fork) | AWS-LC FIPS 3.1 (static) |
|---|---|---|
| Current certificates | #5244 for version 20240805 (Level 1). Newer versions 20250107 / 20250728 / 20251031: CAVP done (A6838 / A7303 / A7700), CMVP "Review Pending" [BSSL FIPS.md] | Static v3.1: **#5314**; dynamic v3.1: #5298; also #4816 (v2.0 static), #5429 (v2.0 dynamic), #4631 (v1.0), #5146 (dynamic, NetOS) [AWSLC FIPS.md]. SP last updated 2026-05-20 [SP-AWS] |
| Raw ECDH shared secret (KAS-ECC-SSC) | Hashed only: indicator on `ECDH_compute_key_fips` (SHA-2 of Z); raw `ECDH_compute_key` not indicated [BSSL] | **Raw Z approved**: `ECDH_verify_service_indicator` marks `ECDH_compute_key` approved for P-224/256/384/521 [AWSLC `service_indicator.c`]; certificate lists KAS-ECC-SSC "IG D.F scenario 2 path (1)" [SP-AWS §2.6] |
| Raw FFC DH (MODP / FFDHE) | Raw DH non-approved [SP-BC Table 7]; KAS-FFC-SSC validated with FB/FC params, hashed output only | **Non-approved**: "Diffie Hellman Shared Secret Computation (not CAVP tested)" [SP-AWS non-approved table]; `dh.c` has no indicator hook [AWSLC] |
| IKEv2 KDF (prf+) | Not implemented | Not implemented; KDFs are HKDF, OneStep, SP 800-108, SSH (CVL), TLS (CVL), PBKDF [SP-AWS Table 5] |
| AES-GCM, caller IV, encrypt | Not approved (generic seal unhooked); `_randnonce`, `_tls12`, `_tls13` approved [BSSL] | Same design: "AES-GCM is approved only with an internal IV"; generic seal unhooked, open hooked, randnonce/tls12/tls13 seal hooked [AWSLC `e_aes.c`]; SP claims IG C.H Scenarios 1 (TLS 1.2), 2, 5 only [SP-AWS §2.7] |
| AES-GCM, caller IV, decrypt | Approved | Approved |
| ML-KEM | Implemented in module, CAVP-tested in 20251031, CMVP pending; no counter indicator; public API drops approval status | **Approved** in #5314: ML-KEM-512/768/1024 KeyGen and EncapDecap [SP-AWS Table 5]; indicated through `EVP_PKEY_keygen/encapsulate/decapsulate` [AWSLC `service_indicator.c`] |
| ECDSA / RSA signatures | Approved via `EVP_DigestSign/Verify`; SHA-1 sign not approved, verify legacy; RSA sizes per policy | Approved; RSA sign ≥ 2048, verify ≥ 1024 (`rsa_1024_ok`), SHA-1 verify only, PSS salt = hash length only [AWSLC `service_indicator.c`] |
| Ed25519 / X25519 | Outside the module, not approved | Ed25519 **approved** (EDDSA KeyGen/SigGen/SigVer in certificate) [SP-AWS]; X25519 not indicated [AWSLC] |
| Platforms / toolchain in the certificate | Linux 5.10 (Google Prodimage) on AMD EPYC 7B12, ARM Neoverse-N1, Intel Xeon 8273CL; Android 15 (Pixel 6); build tools clang 17.0.6, Go 1.22.3, ninja 1.12.1, cmake 3.29.3 [SP-BC Tables 3, §5] | Amazon Linux 2023 on Graviton4 (r8g.metal-24xl) and Xeon Platinum 8375C (c6i.metal); build: `yum install cmake3 golang`, `cmake3 -DFIPS=1`, verify with `./tool/bssl isfips`; source zip SHA-256 pinned [SP-AWS §11.1] |
| Static FIPS build support | Linux ELF only (delocate) [BSSL FIPS.md] | "Static FIPS builds are only supported on Linux platforms"; shared FIPS builds also on Windows; "Building AWS-LC for FIPS requires Go and Perl" [AWSLC FIPS.md, CMakeLists.txt] |
| delocate | x86_64, aarch64 [BSSL] | x86_64, aarch64, ppc64le; extra `-s2n-bignum-include` flag [AWSLC `delocate.go`] |
| Source manifest for a Zig build | `gen/sources.json`, pre-generated perlasm under `gen/` — the basis of this fork | Source lists live in `sources.cmake`; no `gen/sources.json`. Perl is required for the FIPS build (perlasm run at build time) [AWSLC CMakeLists.txt]. Whether a pre-generated assembly tree exists that a Zig build could consume was **not verified** in this report. |

### 3.2 Would switching solve the IKEv2 gaps?

- Raw ECDH for P-curves: **yes** (approved in AWS-LC).
- MODP/FFDHE DH: **no** (non-approved in AWS-LC too).
- IKEv2 KDF: **no** (neither has it).
- ESP/IKE AES-GCM encrypt with caller IV: **no** (same design, same policy
  scope: TLS + internal IV only).
- ML-KEM: **yes** (approved and indicated in AWS-LC today; pending in
  BoringCrypto).

So AWS-LC closes two of the five gaps; the two that matter most for an IPsec
data path (GCM encrypt IV and the KDF) stay open with either library.

### 3.3 Could this fork's architecture carry AWS-LC?

*Inferences and estimates; not verified by building.*

- The fork-at-root, `git merge upstream/main` model would carry over: AWS-LC
  keeps BoringSSL's tree shape (`crypto/`, `ssl/`, `include/`,
  `crypto/fipsmodule/`, `util/fipstools/`) and its FIPS static pipeline is the
  same delocate → inject_hash sequence, so `buildFipsModule()` would need
  small changes (the `-s2n-bignum-include` flag, PPC support optional).
- The part that does **not** carry over is the manifest: `zig/build.zig` is
  built on `gen/sources.json`, which AWS-LC does not ship. Either parse
  `sources.cmake` (CMake list syntax, maintainable but a new parser) or keep
  a generated manifest in the fork (violates the no-hardcoded-lists rule
  unless generated on sync). Add the perlasm question: if AWS-LC has no
  pre-generated `.S` tree, every build — not just FIPS — needs Perl, which
  breaks the "only Zig" contract.
- Sync cadence: AWS-LC's validated code lives on release branches
  (`AWS-LC-FIPS-3.x`), separate from `main`; a weekly `main` merge would
  track the update stream exactly as now, and a validated-stream line would
  pin a release tag.
- Effort estimate: re-doing the manifest layer and re-validating the test
  suite is on the order of the original port of this repository (the FIPS
  pipeline itself is reusable), i.e. **1-2 weeks of work**, plus the open
  perlasm question which could add a Perl dependency. Not recommended unless
  approved raw ECDH or an already-validated ML-KEM is a hard requirement,
  because it does not fix the GCM-IV or KDF gaps.

---

## 4. Validated stream and comparison data

### 4.1 Validated stream (which certificate, which toolchain, can Zig build it?)

**Facts**

- The most recent *completed* BoringCrypto validation is certificate **#5244**
  for software version **20240805** (Security Level 1) [SP-BC §1.1; BSSL
  FIPS.md]. Three later versions (2025-01-07, 2025-07-28, 2025-10-31) are
  "Review Pending at NIST" with CAVP certificates A6838, A7303, A7700 [BSSL
  FIPS.md].
- #5244's build recipe: "To build the approved version of the module the
  following tools are required": clang 17.0.6, Go 1.22.3, ninja 1.12.1,
  cmake 3.29.3, on Linux, with the CMake toolchain file forcing clang, then
  `cmake -GNinja … -DFIPS=1 -DCMAKE_BUILD_TYPE=Release` [SP-BC §5; BSSL
  FIPS.md]. The tested operational environments are the Google Prodimage
  Linux 5.10 platforms and Android 15 listed in §3.1 above [SP-BC Table 3].
- The module's integrity check covers the module text/rodata and the injected
  HMAC-SHA-256 of it; the certificate binds the source set and this build
  procedure [SP-BC §2.2, §5].

**Conclusion (inference from the facts above)**

- **A `zig build -Dfips=true` product cannot be the validated module.** The
  validation covers a specific binary produced by a specific compiler
  (clang 17.0.6) from a specific source revision on listed operational
  environments; Zig's bundled clang (21.1 stable, 22.x nightly) produces a
  different module with a different hash, and neither the compiler nor the
  environments are on the certificate. This is not a matter of effort; it is
  what the certificate certifies.
- What *can* be done: maintain a **validated-stream line** that pins the
  20240805 source (git tag / revision), builds `bcm.o` + `libcrypto.a`
  with exactly the certificated toolchain and CMake procedure on a listed
  operational environment, and lets Zig consumers link that archive via
  `-Dprefix`. The fork's merge model coexists with such a branch (it is just
  a pinned branch that never merges `main`). The conditions for it to
  count: exact source set, exact toolchain, listed OE, no local patches, and
  the consuming product's own compliance review accepting a bound module.
  We have not built this line; it is documented as feasible, not delivered.

### 4.2 Build comparison and benchmarks

Measured on GitHub Actions shared runners (same run as section 1); treat as
indicative. The non-FIPS half of the comparison did not run in that job
(a later step failed first); it is produced by the same job on the next
green run and will be added here. The downstream's own hardware numbers take
precedence when available.

| | linux-x86_64 (AMD EPYC 9V45, Azure VM) | linux-aarch64 (Neoverse N2, CPU part 0xd49, Azure VM) |
|---|---|---|
| FIPS cold build (`zig build -Dfips=true -Doptimize=ReleaseFast`, incl. Go tool builds) | 109 s | 178 s |
| FIPS `libcrypto.a` | 26.3 MB | 26.4 MB |
| first `RAND_bytes(32)` in the process (DRBG instantiate + jitter/CPU entropy) | 5555.3 us | 30037.1 us |
| second `RAND_bytes(32)` | 0.9 us | 1.2 us |
| AES-256-GCM seal, 1400 B, caller nonce | 6180496 pkt/s, 8652.7 MB/s (2.00 s, 12362000 packets) | 2433913 pkt/s, 3407.5 MB/s (2.00 s, 4868000 packets) |
| non-FIPS cold build / `libcrypto.a` / bench | pending | pending |

**Downstream measurement** (source: downstream, environment as in section 1;
`-Doptimize=fast`; the FIPS and non-FIPS columns were measured on the same
machine, so they compare to each other but are not absolute performance —
without `pclmulqdq`/AVX the GHASH path is the slow one):

| | FIPS | non-FIPS |
|---|---|---|
| Cold-cache build (`zig build -Doptimize=fast`, 6 cores; FIPS includes `go build` of delocate/inject_hash) | ~57 s | ~50 s |
| `libcrypto.a` | 25,947,020 B | 26,108,714 B |
| first `RAND_bytes(32)` | **8516.1 µs** (jitter entropy seeding the DRBG, one-time) | 38.5 µs |
| second `RAND_bytes(32)` | 1.2 µs | 0.6 µs |
| AES-256-GCM encrypt, 1400 B, caller nonce (`zig build bench`) | 602,295 pkt/s, 843.2 MB/s | 587,225 pkt/s, 822.1 MB/s |

The FIPS/non-FIPS AES-GCM difference is within measurement noise. The ~8.5 ms
first `RAND_bytes` is the one cost worth designing around: call `RAND_bytes`
once at start-up to take it off the first request's latency (upstream's
`crypto/fipsmodule/FIPS.md`, "RNG design", recommends the same); the README's
FIPS section says so.

Downstream application-level numbers (zoptia0ike `tools/bench.zig`, same
machine, FIPS vs non-FIPS libcrypto): prf+ (HMAC-SHA-256) about 6 % slower
under FIPS (918.6 vs 864.6 ns/op); AES-256-GCM encrypt/decrypt, X25519,
ML-KEM-768, ESP encrypt/decrypt and a full PSK handshake all within ±1.5 %.

### 4.3 Upstream test suite under `-Dfips=true`

**Downstream measurement** (environment as in section 1):
`zig build -Dfips=true -Doptimize=fast test-all` exits 0 with 0 failures.

| binary | ran | passed | skipped |
|---|---|---|---|
| `urandom_test` (1 test) | 1 | 1 | 0 |
| `ssl_test` (13 suites) | 486 | 486 | 0 |
| `pki_test` (90 suites) | 1332 | 1332 | 0 |
| `crypto_test` (107 suites) | 2102 | 2078 | 24 |

`crypto_test` grows from 96 suites in a non-FIPS build to 107 because the
FIPS-only suites (`service_indicator_test.cc`, `*ServiceIndicatorTest`) are
compiled in. That file passes in full, including its assertion that generic
AES-GCM encryption with an external IV is `NOT_APPROVED`
(`service_indicator_test.cc:560-590`) — direct corroboration of section 2.3.

The 24 skips, with the reason from source:

- `X25519Test.AdxMulABI`, `X25519Test.AdxSquareABI`, `P256Test.AdxMulABI`,
  `P256Test.AdxSquareABI` (4): `GTEST_SKIP()` unless the CPU has BMI1+BMI2+ADX;
  the downstream's QEMU CPU exposes no ADX.
- `ECDSAServiceIndicatorTest.ECDSAKeyCheck/20-24`, `…ECDSASigGen/20-24`,
  `…ECDSASigVer/20-24` (15): parameters 20-24 of `kECDSATestVectors` are the
  five `NID_secp256k1` rows (one per hash), and every test in that suite does
  `if (test.nid == NID_secp256k1 && !kCurveSecp256k1Supported) GTEST_SKIP();`
  with `kCurveSecp256k1Supported = false`
  (`service_indicator_test.cc:105,1490,1535,1595`). P-224 is *not* skipped:
  rows 0-4 are `NID_secp224r1` and run.
- `ECDH_ServiceIndicatorTest.ECDH/19` (1): same rule, `kECDHTestVectors[19]`
  is the `secp256k1` row (`:1757`).
- The remaining 4 are the non-FIPS-independent skips also seen in every
  non-FIPS `test-all`: `AEADTest.WycheproofAESEAX`, `ForkDetect.TestAlternateFork`
  and two more that the CI log of the next green run will name here.

The CI run of this step is added once the `fips` job is green.

---

## 5. Known limitations

- The indicator counter cannot distinguish an approved service from an
  approved *internal* call; the report's coverage column is the mitigation,
  and it is only as good as `zig/check-indicator-coverage.sh`.
- Everything here about the module's approved-mode claims is read from the
  #5244 policy for version 20240805; the pending 2025 validations may change
  the ML-KEM and KDF rows once their policies are published.
- Upstream's `util/fipstools/test_fips.cc` cannot be used on an update-stream
  build: `FIPS_version()` is hard-coded to 0 on upstream `main`
  (`self_check/fips.cc.inc:43`) and `test_fips` exits "No module version set"
  (`test_fips.cc:72-75`) and aborts before touching any algorithm. Between
  `v0.20260924.2` and `fbc3c6102` the break-kat CI step used it, which
  validated only the 14 power-on KATs; the 15 lazy KATs never ran. The fork's
  `zig/fips_exercise.cc` replaces it (section 1.3 of the third-round request).
- Upstream's `test-break-kat.sh` expects the aborting module to print a line
  starting with the break-kat name. For `MLKEM-*`, `MLDSA-keygen/sign` and
  `SLHDSA-keygen/sign` the module prints its `BORINGSSL_check_test` names
  instead ("ML-KEM keygen public key failed."), and for `MLDSA-verify` and
  `SLHDSA-verify` it prints nothing before `BORINGSSL_FIPS_abort()`
  (`mldsa.cc.inc:2578`, `slhdsa.cc.inc:288`). CI therefore checks a per-KAT
  expected message and, for those two, only the abort.
- No CST laboratory reviewed this document.
