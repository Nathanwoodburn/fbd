#ifndef CSHA3_H
#define CSHA3_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/// SHA3/Keccak context.
typedef struct {
    uint64_t state[25];
    uint8_t buf[200];
    size_t buf_len;
    size_t rate;
    uint8_t suffix;
} csha3_ctx;

/// Initialize context for SHA3-256 (output = 32 bytes).
void csha3_256_init(csha3_ctx *ctx);

/// Absorb data into the sponge.
void csha3_update(csha3_ctx *ctx, const uint8_t *data, size_t len);

/// Squeeze the final hash. `out` must be at least 32 bytes for SHA3-256.
void csha3_256_final(csha3_ctx *ctx, uint8_t *out);

/// One-shot SHA3-256: hash `len` bytes of `data` into 32-byte `out`.
void csha3_256(const uint8_t *data, size_t len, uint8_t *out);

/// Initialize context for Keccak-256 (output = 32 bytes).
/// Keccak-256 uses suffix 0x01 instead of SHA3's 0x06.
void ckeccak_256_init(csha3_ctx *ctx);

/// One-shot Keccak-256: hash `len` bytes of `data` into 32-byte `out`.
void ckeccak_256(const uint8_t *data, size_t len, uint8_t *out);

#ifdef __cplusplus
}
#endif

#endif /* CSHA3_H */
