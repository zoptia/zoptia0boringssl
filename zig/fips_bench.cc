// bench: the numbers a downstream asked for when comparing a FIPS and a
// non-FIPS libcrypto — first RAND_bytes latency (DRBG seeding; the jitter
// entropy path in FIPS builds) and AES-256-GCM throughput on 1400-byte
// packets with a caller-supplied nonce (the ESP/IKE shape). Fork-owned.
//
// Build both ways and diff:  zig build [-Dfips=true] bench
#include <openssl/aead.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>

#include <chrono>
#include <cstdio>
#include <cstring>
#include <string>

#if defined(__linux__)
#include <fstream>
#endif
#if defined(__APPLE__)
#include <sys/sysctl.h>
#endif

static std::string cpu_model() {
#if defined(__linux__)
  std::ifstream f("/proc/cpuinfo");
  std::string line;
  while (std::getline(f, line)) {
    if (line.rfind("model name", 0) == 0 || line.rfind("Model name", 0) == 0 ||
        line.rfind("Hardware", 0) == 0) {
      return line.substr(line.find(':') + 2);
    }
  }
  // aarch64 often lists only "CPU part"; fall back to that.
  f.clear(); f.seekg(0);
  while (std::getline(f, line)) if (line.rfind("CPU part", 0) == 0) return "aarch64 " + line;
  return "unknown (no model name in /proc/cpuinfo)";
#elif defined(__APPLE__)
  char buf[256]; size_t len = sizeof(buf);
  if (sysctlbyname("machdep.cpu.brand_string", buf, &len, nullptr, 0) == 0) return buf;
  return "unknown";
#else
  return "unknown";
#endif
}

int main() {
  using clock = std::chrono::steady_clock;
  printf("# bench\n\n- CPU: %s\n- FIPS_mode(): %d\n- OpenSSL_version(): %s\n\n",
         cpu_model().c_str(), FIPS_mode(), OpenSSL_version(OPENSSL_VERSION));

  // 1. First RAND_bytes in this process (the DRBG instantiates and seeds here).
  {
    uint8_t b[32];
    const auto t0 = clock::now();
    const int ok = RAND_bytes(b, sizeof(b));
    const auto t1 = clock::now();
    const double us = std::chrono::duration<double, std::micro>(t1 - t0).count();
    printf("- first RAND_bytes(32): %.1f us (ok=%d)\n", us, ok);
    const auto t2 = clock::now();
    RAND_bytes(b, sizeof(b));
    const auto t3 = clock::now();
    printf("- second RAND_bytes(32): %.1f us\n", std::chrono::duration<double, std::micro>(t3 - t2).count());
  }

  // 2. AES-256-GCM seal, 1400-byte packets, caller nonce, ~2 s.
  {
    uint8_t key[32] = {1}, nonce[12] = {2}, in[1400] = {3}, out[1400 + EVP_AEAD_MAX_OVERHEAD];
    size_t out_len;
    bssl::ScopedEVP_AEAD_CTX ctx;
    if (!EVP_AEAD_CTX_init(ctx.get(), EVP_aead_aes_256_gcm(), key, sizeof(key),
                           EVP_AEAD_DEFAULT_TAG_LENGTH, nullptr)) {
      fprintf(stderr, "EVP_AEAD_CTX_init failed\n");
      return 1;
    }
    uint64_t n = 0;
    const auto start = clock::now();
    double elapsed;
    do {
      for (int i = 0; i < 2000; i++, n++) {
        memcpy(nonce + 4, &n, 8);
        if (!EVP_AEAD_CTX_seal(ctx.get(), out, &out_len, sizeof(out), nonce, sizeof(nonce),
                               in, sizeof(in), nullptr, 0)) {
          fprintf(stderr, "seal failed\n");
          return 1;
        }
      }
      elapsed = std::chrono::duration<double>(clock::now() - start).count();
    } while (elapsed < 2.0);
    const double mbps = n * 1400.0 / elapsed / 1e6;
    printf("- AES-256-GCM seal, 1400 B, caller nonce: %.0f pkt/s, %.1f MB/s (%.2f s, %llu packets)\n",
           n / elapsed, mbps, elapsed, (unsigned long long)n);
  }
  return 0;
}
