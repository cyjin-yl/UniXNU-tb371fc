/* Original Route A bridge for the fixed XNU 12377 crypto_functions contract.
 * This uses the real, separately supplied provider primitives. It does not
 * replace POST, entropy collection, or the provider's existing 43 entries.
 */
#ifndef ROUTE_A_CORECRYPTO_ADAPTER_H
#define ROUTE_A_CORECRYPTO_ADAPTER_H
#include <libkern/crypto/register_crypto.h>
#include <libkern/libkern.h>
#include <kern/debug.h>
#include <corecrypto/cc.h>
#include <corecrypto/ccdigest.h>
#include <corecrypto/cchmac.h>
#include <corecrypto/ccmd5.h>
#include <corecrypto/ccsha1.h>
#include <corecrypto/ccsha2.h>
#include "abi_contract.h"

static const struct ccdigest_info *
ra_digest_info(crypto_digest_alg_t alg)
{
    switch (alg) {
    case CRYPTO_DIGEST_ALG_MD5: return ccmd5_di();
    case CRYPTO_DIGEST_ALG_SHA1: return ccsha1_di();
    case CRYPTO_DIGEST_ALG_SHA256: return ccsha256_di();
    case CRYPTO_DIGEST_ALG_SHA384: return ccsha384_di();
    case CRYPTO_DIGEST_ALG_SHA512: return ccsha512_di();
    default: panic("Route A crypto: unsupported digest algorithm %u", (unsigned)alg);
    }
}

static void ra_crypto_require(int valid)
{
    if (!valid) panic("Route A crypto: invalid buffer or length contract");
}

static void ra_context(void *ctx, size_t supplied, size_t needed)
{
    ra_crypto_require(ctx != NULL && supplied >= needed);
}

static const void *ra_bytes(const void *data, size_t size)
{
    static const unsigned char empty;
    ra_crypto_require(data != NULL || size == 0);
    return size == 0 ? &empty : data;
}

static void ra_result(const struct ccdigest_info *di, const unsigned char *full,
                      void *out, size_t size)
{
    /* A nonempty prefix may be requested; oversized outputs never get padded. */
    ra_crypto_require(out != NULL && size > 0 && size <= di->output_size);
    memcpy(out, full, size);
}

static size_t ra_digest_size(crypto_digest_alg_t alg)
{
    return ccdigest_di_size(ra_digest_info(alg));
}

static void ra_digest_init(crypto_digest_alg_t alg, void *ctx, size_t size)
{
    const struct ccdigest_info *di = ra_digest_info(alg);
    ra_context(ctx, size, ccdigest_di_size(di));
    cc_clear(ccdigest_di_size(di), ctx);
    ccdigest_init(di, (ccdigest_ctx_t)ctx);
}

static void ra_digest_update(crypto_digest_alg_t alg, void *ctx, size_t size,
                             const void *data, size_t data_size)
{
    const struct ccdigest_info *di = ra_digest_info(alg);
    ra_context(ctx, size, ccdigest_di_size(di));
    data = ra_bytes(data, data_size);
    ccdigest_update(di, (ccdigest_ctx_t)ctx, data_size, data);
}

static void ra_digest_final(crypto_digest_alg_t alg, void *ctx, size_t size,
                            void *digest, size_t digest_size)
{
    const struct ccdigest_info *di = ra_digest_info(alg);
    unsigned char full[64];
    ra_context(ctx, size, ccdigest_di_size(di));
    ra_crypto_require(digest != NULL && digest_size > 0 && digest_size <= di->output_size);
    ccdigest_final(di, (ccdigest_ctx_t)ctx, full);
    ra_result(di, full, digest, digest_size);
    cc_clear(sizeof(full), full);
    cc_clear(ccdigest_di_size(di), ctx);
}

static void ra_digest(crypto_digest_alg_t alg, const void *data, size_t data_size,
                      void *digest, size_t digest_size)
{
    const struct ccdigest_info *di = ra_digest_info(alg);
    unsigned char full[64];
    ra_crypto_require(digest != NULL && digest_size > 0 && digest_size <= di->output_size);
    ccdigest(di, data_size, ra_bytes(data, data_size), full);
    ra_result(di, full, digest, digest_size);
    cc_clear(sizeof(full), full);
}

/* The legacy field uses void *, whereas the provider's inline takes uchar *. */
static void ra_legacy_digest_final(const struct ccdigest_info *di,
                                   ccdigest_ctx_t ctx, void *digest)
{
    ccdigest_final(di, ctx, (unsigned char *)digest);
}

static size_t ra_hmac_size(crypto_digest_alg_t alg)
{
    return cchmac_di_size(ra_digest_info(alg));
}

static void ra_hmac_init(crypto_digest_alg_t alg, void *ctx, size_t size,
                         const void *key, size_t key_size)
{
    const struct ccdigest_info *di = ra_digest_info(alg);
    ra_context(ctx, size, cchmac_di_size(di));
    cc_clear(cchmac_di_size(di), ctx);
    cchmac_init(di, (cchmac_ctx_t)ctx, key_size, ra_bytes(key, key_size));
}

static void ra_hmac_update(crypto_digest_alg_t alg, void *ctx, size_t size,
                           const void *data, size_t data_size)
{
    const struct ccdigest_info *di = ra_digest_info(alg);
    ra_context(ctx, size, cchmac_di_size(di));
    cchmac_update(di, (cchmac_ctx_t)ctx, data_size, ra_bytes(data, data_size));
}

static void ra_hmac_final(crypto_digest_alg_t alg, void *ctx, size_t size,
                          void *tag, size_t tag_size)
{
    const struct ccdigest_info *di = ra_digest_info(alg);
    unsigned char full[64];
    ra_context(ctx, size, cchmac_di_size(di));
    ra_crypto_require(tag != NULL && tag_size > 0 && tag_size <= di->output_size);
    cchmac_final(di, (cchmac_ctx_t)ctx, full);
    ra_result(di, full, tag, tag_size);
    cc_clear(sizeof(full), full);
    cc_clear(cchmac_di_size(di), ctx);
}

static bool ra_hmac_final_verify(crypto_digest_alg_t alg, void *ctx, size_t size,
                                 const void *tag, size_t tag_size)
{
    const struct ccdigest_info *di = ra_digest_info(alg);
    unsigned char full[64];
    ra_context(ctx, size, cchmac_di_size(di));
    if (tag == NULL || tag_size == 0 || tag_size > di->output_size) {
        cc_clear(cchmac_di_size(di), ctx);
        return false;
    }
    cchmac_final(di, (cchmac_ctx_t)ctx, full);
    bool valid = cc_cmp_safe(tag_size, full, tag) == 0;
    cc_clear(sizeof(full), full);
    cc_clear(cchmac_di_size(di), ctx);
    return valid;
}

static void ra_hmac(crypto_digest_alg_t alg, const void *key, size_t key_size,
                    const void *data, size_t data_size, void *tag, size_t tag_size)
{
    const struct ccdigest_info *di = ra_digest_info(alg);
    unsigned char full[64];
    ra_crypto_require(tag != NULL && tag_size > 0 && tag_size <= di->output_size);
    cchmac(di, key_size, ra_bytes(key, key_size), data_size, ra_bytes(data, data_size), full);
    ra_result(di, full, tag, tag_size);
    cc_clear(sizeof(full), full);
}

static bool ra_hmac_verify(crypto_digest_alg_t alg, const void *key, size_t key_size,
                           const void *data, size_t data_size, const void *tag, size_t tag_size)
{
    const struct ccdigest_info *di = ra_digest_info(alg);
    unsigned char full[64];
    if (tag == NULL || tag_size == 0 || tag_size > di->output_size) return false;
    cchmac(di, key_size, ra_bytes(key, key_size), data_size, ra_bytes(data, data_size), full);
    bool valid = cc_cmp_safe(tag_size, full, tag) == 0;
    cc_clear(sizeof(full), full);
    return valid;
}

#define RA_ASSIGN(field, implementation) do { \
    _Static_assert(__builtin_types_compatible_p(__typeof__(((struct crypto_functions *)0)->field), \
                   __typeof__(&(implementation))), "crypto callback type: " #field); \
    table->field = &(implementation); \
} while (0)

static void route_a_complete_crypto_table(struct crypto_functions *table)
{
    RA_ASSIGN(ccdigest_final_fn, ra_legacy_digest_final);
    RA_ASSIGN(digest_ctx_size_fn, ra_digest_size);
    RA_ASSIGN(digest_init_fn, ra_digest_init);
    RA_ASSIGN(digest_update_fn, ra_digest_update);
    RA_ASSIGN(digest_final_fn, ra_digest_final);
    RA_ASSIGN(digest_fn, ra_digest);
    RA_ASSIGN(hmac_ctx_size_fn, ra_hmac_size);
    RA_ASSIGN(hmac_init_fn, ra_hmac_init);
    RA_ASSIGN(hmac_update_fn, ra_hmac_update);
    RA_ASSIGN(hmac_final_generate_fn, ra_hmac_final);
    RA_ASSIGN(hmac_final_verify_fn, ra_hmac_final_verify);
    RA_ASSIGN(hmac_generate_fn, ra_hmac);
    RA_ASSIGN(hmac_verify_fn, ra_hmac_verify);
}
#undef RA_ASSIGN
#endif
