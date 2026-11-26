/*
 * Route A PACGA software ABI: QARMA-64-5 with the Arm S-box.
 *
 * Algorithm: Roberto Avanzi, The QARMA Block Cipher Family, FSE 2017,
 * ePrint 2016/444, sections 2-3 and appendix A (CC BY).
 * https://eprint.iacr.org/2016/444
 *
 * This implementation uses packed 4-bit cells, in the paper's big-endian
 * cell order. It is independently expressed from the published operations.
 * QEMU's architected PACGA is an independent execution oracle, not linked
 * into this helper. No secret-indexed memory access is used by this C code.
 *
 * The caller supplies the complete 128-bit key. Production obtains it from
 * XNU read_random after provider initialization; there is no default key.
 * This is not Apple hardware PAC authentication or its private algorithm.
 */
#ifndef ROUTE_A_PACGA_QARMA5_H
#define ROUTE_A_PACGA_QARMA5_H

#include <stdint.h>

struct route_a_pacga_key {
    uint64_t lo;
    uint64_t hi;
};

#define ROUTE_A_PACGA_SVC_MASK UINT32_C(0xfff0001f)
#define ROUTE_A_PACGA_SVC_WORD UINT32_C(0xd4100001)
#define ROUTE_A_PACGA_ISS_MASK UINT32_C(0x01ff8000)
#define ROUTE_A_PACGA_ISS_TAG  UINT32_C(0x00008000)

/* Cell i occupies bits 63-4*i .. 60-4*i. The permutation is public. */
static inline uint64_t
route_a_qarma_permute(uint64_t value, const uint8_t permutation[16], int inverse)
{
    uint64_t result = 0;
    for (unsigned i = 0; i < 16; ++i) {
        unsigned source = inverse ? i : permutation[i];
        unsigned target = inverse ? permutation[i] : i;
        result |= ((value >> (60 - 4 * source)) & UINT64_C(15))
                  << (60 - 4 * target);
    }
    return result;
}

/* A whole S-box fits in a register; its only data-dependent index is a shift. */
static inline uint64_t
route_a_qarma_substitute(uint64_t value, uint64_t box)
{
    uint64_t result = 0;
    for (unsigned bit = 0; bit < 64; bit += 4) {
        unsigned cell = (unsigned)((value >> bit) & UINT64_C(15));
        result |= ((box >> (4 * cell)) & UINT64_C(15)) << bit;
    }
    return result;
}

static inline uint64_t
route_a_qarma_rotate_cell(uint64_t cell, unsigned count)
{
    return ((cell << count) | (cell >> (4 - count))) & UINT64_C(15);
}

/* Q = M4,2: circulant matrix with first row [0, rho, rho^2, rho]. */
static inline uint64_t
route_a_qarma_mix(uint64_t value)
{
    uint64_t result = 0;
    for (unsigned column = 0; column < 4; ++column) {
        for (unsigned row = 0; row < 4; ++row) {
            uint64_t cell = 0;
            for (unsigned distance = 1; distance < 4; ++distance) {
                unsigned source = ((row + distance) & 3) * 4 + column;
                uint64_t input = (value >> (60 - 4 * source)) & UINT64_C(15);
                cell ^= route_a_qarma_rotate_cell(input, distance == 2 ? 2 : 1);
            }
            result |= cell << (60 - 4 * (row * 4 + column));
        }
    }
    return result;
}

static inline uint64_t
route_a_qarma_tweak(uint64_t value)
{
    static const uint8_t permutation[16] = {
        6, 5, 14, 15, 0, 1, 2, 3, 7, 12, 13, 4, 8, 9, 10, 11
    };
    value = route_a_qarma_permute(value, permutation, 0);
    /* omega is applied to cells 0, 1, 3, 4, 8, 11, and 13. */
    const unsigned cells = (1U << 0) | (1U << 1) | (1U << 3) |
                           (1U << 4) | (1U << 8) | (1U << 11) | (1U << 13);
    for (unsigned i = 0; i < 16; ++i) {
        if (cells & (1U << i)) {
            unsigned shift = 60 - 4 * i;
            uint64_t cell = (value >> shift) & UINT64_C(15);
            uint64_t next = (cell >> 1) | (((cell ^ (cell >> 1)) & 1) << 3);
            value = (value & ~(UINT64_C(15) << shift)) | (next << shift);
        }
    }
    return value;
}

/* Full block output is useful for the paper's known-answer test. */
static inline uint64_t
route_a_qarma5(uint64_t value, uint64_t modifier, const struct route_a_pacga_key *key)
{
    static const uint8_t shuffle[16] = {
        0, 11, 6, 13, 10, 1, 12, 7, 5, 14, 3, 8, 15, 4, 9, 2
    };
    static const uint64_t round_constant[5] = {
        UINT64_C(0x0000000000000000), UINT64_C(0x13198a2e03707344),
        UINT64_C(0xa4093822299f31d0), UINT64_C(0x082efa98ec4e6c89),
        UINT64_C(0x452821e638d01377)
    };
    const uint64_t box = UINT64_C(0xa12d5473e90cf86b);
    const uint64_t inverse_box = UINT64_C(0x37c40f6291ba8de5);
    const uint64_t alpha = UINT64_C(0xc0ac29b7c97c50dd);
    const uint64_t whitening = ((key->hi >> 1) | (key->hi << 63)) ^ (key->hi >> 63);
    uint64_t tweaks[6];
    tweaks[0] = modifier;
    for (unsigned r = 0; r < 5; ++r) {
        tweaks[r + 1] = route_a_qarma_tweak(tweaks[r]);
    }

    uint64_t state = value ^ key->hi;
    for (unsigned r = 0; r < 5; ++r) {
        state ^= key->lo ^ tweaks[r] ^ round_constant[r];
        if (r != 0) {
            state = route_a_qarma_mix(route_a_qarma_permute(state, shuffle, 0));
        }
        state = route_a_qarma_substitute(state, box);
    }

    state ^= whitening ^ tweaks[5];
    state = route_a_qarma_substitute(
        route_a_qarma_mix(route_a_qarma_permute(state, shuffle, 0)), box);
    state = route_a_qarma_permute(
        route_a_qarma_mix(route_a_qarma_permute(state, shuffle, 0)) ^ key->lo,
        shuffle, 1);
    state = route_a_qarma_permute(
        route_a_qarma_mix(route_a_qarma_substitute(state, inverse_box)), shuffle, 1);
    state ^= key->hi ^ tweaks[5];

    for (unsigned remaining = 5; remaining != 0; --remaining) {
        unsigned r = remaining - 1;
        state = route_a_qarma_substitute(state, inverse_box);
        if (r != 0) {
            state = route_a_qarma_permute(route_a_qarma_mix(state), shuffle, 1);
        }
        state ^= key->lo ^ tweaks[r] ^ round_constant[r] ^ alpha;
    }
    return state ^ whitening;
}

static inline uint64_t
route_a_pacga_signature(uint64_t value, uint64_t modifier,
                       const struct route_a_pacga_key *key)
{
    return route_a_qarma5(value, modifier, key) & UINT64_C(0xffffffff00000000);
}

#endif /* ROUTE_A_PACGA_QARMA5_H */
