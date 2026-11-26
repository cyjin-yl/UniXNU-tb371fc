/* Original compile-time carrier: expose legacy allocation macros as real
 * target record layouts in both independently configured translation units.
 */
#ifndef ROUTE_A_CORECRYPTO_ABI_CONTRACT_H
#define ROUTE_A_CORECRYPTO_ABI_CONTRACT_H
#include <corecrypto/ccdigest.h>
#include <corecrypto/cchmac.h>
#include <corecrypto/ccrsa.h>
#include <corecrypto/ccchacha20poly1305.h>

struct route_a_crypto_sizes {
    unsigned char digest_md5[ccdigest_ctx_size(16, 64)];
    unsigned char digest_sha1[ccdigest_ctx_size(20, 64)];
    unsigned char digest_sha256[ccdigest_ctx_size(32, 64)];
    unsigned char digest_sha512[ccdigest_ctx_size(64, 128)];
    unsigned char hmac_md5[cchmac_ctx_size(16, 64)];
    unsigned char hmac_sha1[cchmac_ctx_size(20, 64)];
    unsigned char hmac_sha256[cchmac_ctx_size(32, 64)];
    unsigned char hmac_sha512[cchmac_ctx_size(64, 128)];
    unsigned char rsa_pub_2048[ccrsa_pub_ctx_size(256)];
    unsigned char rsa_pub_4096[ccrsa_pub_ctx_size(512)];
    unsigned char chacha_context[sizeof(ccchacha20poly1305_ctx)];
    unsigned char chacha_alignment[__alignof__(ccchacha20poly1305_ctx)];
    unsigned char rsa_alignment[__alignof__(struct ccrsa_pub_ctx)];
    unsigned char digest_alignment[__alignof__(struct ccdigest_ctx)];
    unsigned char hmac_alignment[__alignof__(struct cchmac_ctx)];
    unsigned char unit_size[sizeof(cc_unit)];
    unsigned char unit_alignment[__alignof__(cc_unit)];
};
#endif
