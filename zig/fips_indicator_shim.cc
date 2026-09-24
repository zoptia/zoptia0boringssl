// FIPS service-indicator shim (fork-owned; upstream files are untouched).
//
// Upstream unexported <openssl/service_indicator.h> (cb7bac03b, 2025-05-15).
// FIPS_service_indicator_before_call / after_call now live in the bssl::
// namespace, declared only in crypto/fipsmodule/service_indicator/internal.h,
// so C and Zig callers cannot reach them. This file re-exports them with C
// linkage. It is compiled into libcrypto in every build: in a non-FIPS build
// upstream's inline versions are used, which return constants, and
// @import("boringssl").fips_build tells a Zig consumer whether the counter
// means anything.
//
// The counter is incremented by every service that has an indicator hook,
// including services called *internally* by another function. A call that is
// not itself hooked can therefore look "approved" because of an internal
// SHA-512 or RAND_bytes. Consumers must combine the counter with knowledge of
// which services carry a hook; zig/indicator_report.cc does this.
#include "../crypto/fipsmodule/service_indicator/internal.h"

extern "C" {

uint64_t zbssl_fips_indicator_before(void) {
  return bssl::FIPS_service_indicator_before_call();
}

uint64_t zbssl_fips_indicator_after(void) {
  return bssl::FIPS_service_indicator_after_call();
}

}  // extern "C"
