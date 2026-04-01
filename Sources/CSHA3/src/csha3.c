/*
 * Minimal SHA3-256 (FIPS 202) implementation.
 *
 * Keccak-f[1600] permutation based on the compact approach from
 * Markku-Juhani O. Saarinen's tiny_sha3 (CC0 / public domain).
 */

#include "csha3.h"
#include <string.h>

/* Keccak-f round constants */
static const uint64_t keccakf_rndc[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL,
    0x800000000000808AULL, 0x8000000080008000ULL,
    0x000000000000808BULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008AULL, 0x0000000000000088ULL,
    0x0000000080008009ULL, 0x000000008000000AULL,
    0x000000008000808BULL, 0x800000000000008BULL,
    0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800AULL, 0x800000008000000AULL,
    0x8000000080008081ULL, 0x8000000000008080ULL,
    0x0000000080000001ULL, 0x8000000080008008ULL,
};

/* Pi lane permutation order (24-element chain starting from lane 1) */
static const int keccakf_piln[24] = {
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
    15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1
};

/* Rotation offsets along the Pi chain */
static const int keccakf_rotc[24] = {
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
    27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44
};

#define ROTL64(x, y) (((x) << (y)) | ((x) >> (64 - (y))))

/* Keccak-f[1600] permutation */
static void keccak_f1600(uint64_t st[25]) {
    int i, j, r;
    uint64_t t, bc[5];

    for (r = 0; r < 24; r++) {
        /* Theta */
        for (i = 0; i < 5; i++)
            bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];
        for (i = 0; i < 5; i++) {
            t = bc[(i + 4) % 5] ^ ROTL64(bc[(i + 1) % 5], 1);
            for (j = 0; j < 25; j += 5)
                st[j + i] ^= t;
        }

        /* Rho Pi (chain-based: follow the permutation starting from st[1]) */
        t = st[1];
        for (i = 0; i < 24; i++) {
            j = keccakf_piln[i];
            bc[0] = st[j];
            st[j] = ROTL64(t, keccakf_rotc[i]);
            t = bc[0];
        }

        /* Chi */
        for (j = 0; j < 25; j += 5) {
            for (i = 0; i < 5; i++)
                bc[i] = st[j + i];
            for (i = 0; i < 5; i++)
                st[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
        }

        /* Iota */
        st[0] ^= keccakf_rndc[r];
    }
}

void csha3_256_init(csha3_ctx *ctx) {
    memset(ctx, 0, sizeof(*ctx));
    ctx->rate = 136;    /* SHA3-256: rate = 1088 bits = 136 bytes */
    ctx->suffix = 0x06; /* SHA3 domain separation (not SHAKE) */
}

void csha3_update(csha3_ctx *ctx, const uint8_t *data, size_t len) {
    while (len > 0) {
        size_t avail = ctx->rate - ctx->buf_len;
        size_t chunk = len < avail ? len : avail;
        memcpy(ctx->buf + ctx->buf_len, data, chunk);
        ctx->buf_len += chunk;
        data += chunk;
        len -= chunk;

        if (ctx->buf_len == ctx->rate) {
            /* Absorb one block */
            for (size_t i = 0; i < ctx->rate / 8; i++) {
                uint64_t lane;
                memcpy(&lane, ctx->buf + i * 8, 8);
                ctx->state[i] ^= lane;
            }
            keccak_f1600(ctx->state);
            ctx->buf_len = 0;
        }
    }
}

void csha3_256_final(csha3_ctx *ctx, uint8_t *out) {
    /* Pad: suffix byte, zero padding, and final 0x80 bit */
    ctx->buf[ctx->buf_len] = ctx->suffix;
    memset(ctx->buf + ctx->buf_len + 1, 0, ctx->rate - ctx->buf_len - 1);
    ctx->buf[ctx->rate - 1] |= 0x80;

    /* Absorb final block */
    for (size_t i = 0; i < ctx->rate / 8; i++) {
        uint64_t lane;
        memcpy(&lane, ctx->buf + i * 8, 8);
        ctx->state[i] ^= lane;
    }
    keccak_f1600(ctx->state);

    /* Squeeze 32 bytes */
    memcpy(out, ctx->state, 32);
}

void csha3_256(const uint8_t *data, size_t len, uint8_t *out) {
    csha3_ctx ctx;
    csha3_256_init(&ctx);
    csha3_update(&ctx, data, len);
    csha3_256_final(&ctx, out);
}

void ckeccak_256_init(csha3_ctx *ctx) {
    memset(ctx, 0, sizeof(*ctx));
    ctx->rate = 136;    /* Keccak-256: rate = 1088 bits = 136 bytes */
    ctx->suffix = 0x01; /* Keccak domain separation (not SHA3's 0x06) */
}

void ckeccak_256(const uint8_t *data, size_t len, uint8_t *out) {
    csha3_ctx ctx;
    ckeccak_256_init(&ctx);
    csha3_update(&ctx, data, len);
    csha3_256_final(&ctx, out);
}
