#!/usr/bin/env bash
# check-indicator-coverage.sh — keep zig/indicator_report.cc's "covered by
# indicator" column honest across upstream syncs.
#
# The service indicator is a counter bumped by hooks inside the FIPS module.
# indicator_report.cc labels each probed service as covered (a hook exists and
# makes a deliberate decision) or not covered (no hook; any "approved" reading
# is a false positive from an internal call). Those labels are derived from
# upstream source; this script re-derives the facts they rest on and fails if
# they moved, so the report cannot silently go stale. Run from
# zig/sync-upstream.sh and in CI.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
fail=0
ok()   { echo "ok: $*"; }
bad()  { echo "STALE: $*" >&2; fail=1; }

FM=crypto/fipsmodule
# Positive: hooks that the report relies on, at the function the report probes.
# Format: file | hook symbol | enclosing function must contain
while IFS='|' read -r file hook fn; do
  if awk -v H="$hook" -v F="$fn" '
      /^(static )?(int|void|size_t|uint8_t \*|bcm_status|bcm_infallible) [A-Za-z_0-9:]+\(/ { cur=$0 }
      index($0,H) && index(cur,F) { found=1 }
      END { exit found?0:1 }' "$FM/$file"; then
    ok "$file: $hook inside $fn"
  else
    bad "$file: expected $hook inside a function matching '$fn'"
  fi
done <<'LIST'
cipher/e_aes.cc.inc|AEAD_GCM_verify_service_indicator|aead_aes_gcm_openv_detached
cipher/e_aes.cc.inc|AEAD_GCM_verify_service_indicator|aead_aes_gcm_sealv_randnonce
cipher/e_aes.cc.inc|AEAD_GCM_verify_service_indicator|aead_aes_gcm_tls12_sealv
cipher/e_aes.cc.inc|AEAD_GCM_verify_service_indicator|aead_aes_gcm_tls13_sealv
hmac/hmac.cc.inc|HMAC_verify_service_indicator|HMAC
ec/ec_key.cc.inc|EC_KEY_keygen_verify_service_indicator|EC_KEY_check_fips
ecdh/ecdh.cc.inc|ECDH_verify_service_indicator|ECDH_compute_key_fips
digestsign/digestsign.cc.inc|EVP_DigestSign_verify_service_indicator|EVP_DigestSign
digestsign/digestsign.cc.inc|EVP_DigestVerify_verify_service_indicator|EVP_DigestVerify
rand/ctrdrbg.cc.inc|FIPS_service_indicator_update_state|CTR_DRBG_generate
LIST

# Negative: the generic (external-IV) AES-GCM seal path must NOT carry the hook
# (upstream's service_indicator_test expects NOT_APPROVED for it).
if awk '/^static int aead_aes_gcm_sealv_detached\(/{f=1} f&&/^}/{exit} f&&/AEAD_GCM_verify_service_indicator/{found=1} END{exit found?1:0}' "$FM/cipher/e_aes.cc.inc"; then
  ok "generic aead_aes_gcm_sealv_detached has no indicator hook (external IV not approved)"
else
  bad "generic aead_aes_gcm_sealv_detached now calls the indicator; the AES-GCM rows changed meaning"
fi

# Negative: services the report labels "not covered" must still have no hook.
for d in "$FM/mlkem" "$FM/dh" crypto/curve25519 "$FM/bn" crypto/cipher; do
  if grep -rqE "FIPS_service_indicator_update_state|_verify_service_indicator\(" "$d" --include='*.inc' --include='*.cc' 2>/dev/null | grep -v _test; then
    bad "$d now contains an indicator hook; update indicator_report.cc coverage labels"
  else
    ok "$d: no indicator hook (report labels it 'not covered')"
  fi
done

# The shim depends on these two staying declared in the internal header.
if grep -q "FIPS_service_indicator_before_call()" "$FM/service_indicator/internal.h" && \
   grep -q "FIPS_service_indicator_after_call()" "$FM/service_indicator/internal.h"; then
  ok "service_indicator/internal.h still declares before_call/after_call (zig/fips_indicator_shim.cc)"
else
  bad "service_indicator/internal.h no longer declares before/after_call; fix zig/fips_indicator_shim.cc"
fi

[ "$fail" -eq 0 ] && echo "check-indicator-coverage: OK" || { echo "check-indicator-coverage: STALE" >&2; exit 1; }
