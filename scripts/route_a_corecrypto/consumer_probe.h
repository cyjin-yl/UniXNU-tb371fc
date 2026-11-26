/* Original XNU-side consumer tests. The independently compiled consumer calls
 * the published table after the real provider and PRNG initialization return.
 * Test vectors are standard MD5/SHA digests and HMACs, not substitute crypto.
 */
#ifndef ROUTE_A_CORECRYPTO_CONSUMER_PROBE_H
#define ROUTE_A_CORECRYPTO_CONSUMER_PROBE_H
#include <libkern/crypto/crypto_internal.h>
#include <libkern/section_keywords.h>
#include <libkern/libkern.h>
#include <kern/debug.h>
#include "abi_contract.h"

SECURITY_READ_ONLY_LATE(uint32_t) route_a_crypto_consumer_status = 0;
SECURITY_READ_ONLY_LATE(uint32_t) route_a_crypto_consumer_vectors = 0;

static void ra_probe_require(bool condition, const char *what)
{
    if (!condition) panic("Route A published crypto consumer failed: %s", what);
}

static unsigned ra_probe_nibble(char c)
{
    return c <= '9' ? (unsigned)(c - '0') : (unsigned)(c - 'a' + 10);
}

static void ra_probe_hex(unsigned char *out, const char *text, size_t count)
{
    for (size_t i = 0; i < count; i++) out[i] = (unsigned char)((ra_probe_nibble(text[2*i]) << 4) | ra_probe_nibble(text[2*i+1]));
}

static void ra_probe_guard(const unsigned char *data, size_t start, size_t end)
{
    for (size_t i = start; i < end; i++) ra_probe_require(data[i] == 0xa5, "buffer guard");
}

static void route_a_crypto_consumer_check(void)
{
    static const struct {
        crypto_digest_alg_t alg;
        size_t size;
        const char *digest;
        const char *hmac;
    } vectors[] = {
        {CRYPTO_DIGEST_ALG_MD5, 16, "900150983cd24fb0d6963f7d28e17f72", "80070713463e7749b90c2dc24911e275"},
        {CRYPTO_DIGEST_ALG_SHA1, 20, "a9993e364706816aba3e25717850c26c9cd0d89d", "de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9"},
        {CRYPTO_DIGEST_ALG_SHA256, 32, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"},
        {CRYPTO_DIGEST_ALG_SHA384, 48, "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7", "d7f4727e2c0b39ae0f1e40cc96f60242d5b7801841cea6fc592c5d3e1ae50700582a96cf35e1e554995fe4e03381c237"},
        {CRYPTO_DIGEST_ALG_SHA512, 64, "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f", "b42af09057bac1e2d41708e48a902e09b5ff7f12ab428a4fe86653c73dd248fb82f948a549f7b791a5b41915ee4d1ec3935357e4e2317250d0372afa2ebeeb3a"},
    };
    static const char *empty_digests[] = {
        "d41d8cd98f00b204e9800998ecf8427e",
        "da39a3ee5e6b4b0d3255bfef95601890afd80709",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
    };
    static const char *empty_hmacs[] = {
        "74e6f7298a9c2d168935f58c001bad88",
        "fbdb1d1b18aa6c08324b7d64b71fb76370690e1d",
        "b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad",
        "6c1f2ee938fad2e24bd91298474382ca218c75db3d83e114b3d4367776d14d3551289e75e8209cd4b792302840234adc",
        "b936cee86c9f87aa5d3c6f2e84cb5a4239a5fe50480a6ec66b70ab5b1f4ac6730c6c515421b327ec1d69402e53dfb49ad7381eb067b338fd7b0cb22247225d47",
    };
    static const char message[] = "The quick brown fox jumps over the lazy dog";
    crypto_functions_t f = g_crypto_funcs;
    ra_probe_require(f != NULL && crypto_init, "table published");
    _Static_assert(sizeof(*f) == 448, "fixed XNU table size");
    for (size_t offset = 0; offset < sizeof(*f); offset += sizeof(uintptr_t)) {
        uintptr_t pointer;
        memcpy(&pointer, (const unsigned char *)f + offset, sizeof(pointer));
        ra_probe_require(pointer != 0, "all 56 table entries populated");
    }

    for (size_t n = 0; n < sizeof(vectors) / sizeof(vectors[0]); n++) {
        crypto_digest_alg_t alg = vectors[n].alg;
        size_t digest_size = vectors[n].size;
        unsigned char expected_digest[64], expected_hmac[64], out[80];
        unsigned char ctx[1040] __attribute__((aligned(16)));
        ra_probe_hex(expected_digest, vectors[n].digest, digest_size);
        ra_probe_hex(expected_hmac, vectors[n].hmac, digest_size);
        size_t size = f->digest_ctx_size_fn(alg);
        ra_probe_require(size > 0 && size <= 1024, "digest context bound");
        memset(ctx, 0xa5, sizeof(ctx));
        memset(out, 0xa5, sizeof(out));
        f->digest_init_fn(alg, ctx, size);
        f->digest_update_fn(alg, ctx, size, NULL, 0);
        f->digest_update_fn(alg, ctx, size, "a", 1);
        f->digest_update_fn(alg, ctx, size, "bc", 2);
        f->digest_final_fn(alg, ctx, size, out, digest_size);
        ra_probe_require(memcmp(out, expected_digest, digest_size) == 0, "streaming digest vector");
        ra_probe_guard(ctx, size, sizeof(ctx));
        ra_probe_guard(out, digest_size, sizeof(out));
        memset(out, 0xa5, sizeof(out));
        f->digest_fn(alg, "abc", 3, out, digest_size);
        ra_probe_require(memcmp(out, expected_digest, digest_size) == 0, "one-shot digest vector");
        ra_probe_guard(out, digest_size, sizeof(out));
        memset(out, 0xa5, sizeof(out));
        f->digest_fn(alg, "abc", 3, out, 8);
        ra_probe_require(memcmp(out, expected_digest, 8) == 0, "truncated digest vector");
        ra_probe_guard(out, 8, sizeof(out));
        ra_probe_hex(expected_digest, empty_digests[n], digest_size);
        f->digest_fn(alg, NULL, 0, out, digest_size);
        ra_probe_require(memcmp(out, expected_digest, digest_size) == 0, "empty digest vector");

        size = f->hmac_ctx_size_fn(alg);
        ra_probe_require(size > 0 && size <= 1024, "HMAC context bound");
        memset(ctx, 0xa5, sizeof(ctx));
        memset(out, 0xa5, sizeof(out));
        f->hmac_init_fn(alg, ctx, size, "key", 3);
        f->hmac_update_fn(alg, ctx, size, NULL, 0);
        f->hmac_update_fn(alg, ctx, size, message, 7);
        f->hmac_update_fn(alg, ctx, size, message + 7, sizeof(message) - 1 - 7);
        f->hmac_final_generate_fn(alg, ctx, size, out, digest_size);
        ra_probe_require(memcmp(out, expected_hmac, digest_size) == 0, "streaming HMAC vector");
        ra_probe_guard(ctx, size, sizeof(ctx));
        ra_probe_guard(out, digest_size, sizeof(out));
        memset(out, 0xa5, sizeof(out));
        f->hmac_generate_fn(alg, "key", 3, message, sizeof(message) - 1, out, 12);
        ra_probe_require(memcmp(out, expected_hmac, 12) == 0, "truncated HMAC vector");
        ra_probe_guard(out, 12, sizeof(out));
        ra_probe_require(f->hmac_verify_fn(alg, "key", 3, message, sizeof(message) - 1, expected_hmac, digest_size), "HMAC verification");
        ra_probe_require(f->hmac_verify_fn(alg, "key", 3, message, sizeof(message) - 1, expected_hmac, 12), "truncated HMAC verification");
        expected_hmac[0] ^= 1;
        ra_probe_require(!f->hmac_verify_fn(alg, "key", 3, message, sizeof(message) - 1, expected_hmac, digest_size), "bad HMAC rejected");
        expected_hmac[0] ^= 1;
        ra_probe_require(!f->hmac_verify_fn(alg, "key", 3, message, sizeof(message) - 1, expected_hmac, 0), "empty tag rejected");
        ra_probe_require(!f->hmac_verify_fn(alg, "key", 3, message, sizeof(message) - 1, expected_hmac, digest_size + 1), "oversized tag rejected");
        f->hmac_init_fn(alg, ctx, size, "key", 3);
        f->hmac_update_fn(alg, ctx, size, message, sizeof(message) - 1);
        ra_probe_require(f->hmac_final_verify_fn(alg, ctx, size, expected_hmac, 12), "streaming tag verification");
        f->hmac_init_fn(alg, ctx, size, "key", 3);
        f->hmac_update_fn(alg, ctx, size, message, sizeof(message) - 1);
        expected_hmac[digest_size - 1] ^= 1;
        ra_probe_require(!f->hmac_final_verify_fn(alg, ctx, size, expected_hmac, digest_size), "bad streaming tag rejected");
        ra_probe_guard(ctx, size, sizeof(ctx));
        ra_probe_hex(expected_hmac, empty_hmacs[n], digest_size);
        f->hmac_generate_fn(alg, NULL, 0, NULL, 0, out, digest_size);
        ra_probe_require(memcmp(out, expected_hmac, digest_size) == 0, "empty key/data HMAC vector");
        f->hmac_init_fn(alg, ctx, size, NULL, 0);
        f->hmac_update_fn(alg, ctx, size, NULL, 0);
        ra_probe_require(f->hmac_final_verify_fn(alg, ctx, size, expected_hmac, digest_size), "empty streaming HMAC vector");
        route_a_crypto_consumer_vectors++;
    }
    unsigned char large_key[131], large_tag[32], large_expected[32];
    static const char large_message[] = "Test Using Larger Than Block-Size Key - Hash Key First";
    memset(large_key, 0xaa, sizeof(large_key));
    ra_probe_hex(large_expected, "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54", sizeof(large_expected));
    f->hmac_generate_fn(CRYPTO_DIGEST_ALG_SHA256, large_key, sizeof(large_key),
                        large_message, sizeof(large_message) - 1, large_tag, sizeof(large_tag));
    ra_probe_require(memcmp(large_tag, large_expected, sizeof(large_tag)) == 0, "long HMAC key vector");
    unsigned char legacy[256] __attribute__((aligned(16))), digest[32];
    f->ccdigest_init_fn(f->ccsha256_di, (ccdigest_ctx_t)legacy);
    f->ccdigest_update_fn(f->ccsha256_di, (ccdigest_ctx_t)legacy, 3, "abc");
    f->ccdigest_final_fn(f->ccsha256_di, (ccdigest_ctx_t)legacy, digest);
    unsigned char expected[32];
    ra_probe_hex(expected, vectors[2].digest, sizeof(expected));
    ra_probe_require(memcmp(expected, digest, sizeof(digest)) == 0, "legacy final callback");
    route_a_crypto_consumer_status = 1;
}
#endif
