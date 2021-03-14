// sha3.h
// 19-Nov-11  Markku-Juhani O. Saarinen <mjos@iki.fi>


#ifdef __EMSCRIPTEN__
#include "emscripten.h"
#else
#define EMSCRIPTEN_KEEPALIVE
#endif

#ifndef SHA3_H
#define SHA3_H

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#ifndef KECCAKF_ROUNDS
#define KECCAKF_ROUNDS 24
#endif

#ifndef ROTL64
#define ROTL64(x, y) (((x) << (y)) | ((x) >> (64 - (y))))
#endif

#define SHA3_VARIANT_STANDARD 0x06
#define SHA3_VARIANT_KECCAK3 0x01


// state context
typedef struct {
    union {                                 // state:
        uint8_t b[200];                     // 8-bit bytes
        uint64_t q[25];                     // 64-bit words
    } st;
    int pt, rsiz, mdlen;                    // these don't overflow
    int keccak_padding_value;               // 0x01 for keccak 3.0, 0x06 for sha3
} sha3_ctx_t;

// Compression function.
void sha3_keccakf(uint64_t st[25]);


EMSCRIPTEN_KEEPALIVE
int version();
EMSCRIPTEN_KEEPALIVE
uint8_t* create_buffer(size_t size);
EMSCRIPTEN_KEEPALIVE
void destroy_buffer(void* p);

// OpenSSL - like interfece
EMSCRIPTEN_KEEPALIVE
sha3_ctx_t* sha3_init_stub(int mdlen, int variant);
EMSCRIPTEN_KEEPALIVE
void sha3_cleanup_stub(sha3_ctx_t* ctx);

int sha3_init(sha3_ctx_t *c, int mdlen, int variant);    // mdlen = hash output in bytes

EMSCRIPTEN_KEEPALIVE
int sha3_update(sha3_ctx_t *c, const void *data, size_t len);

EMSCRIPTEN_KEEPALIVE
int sha3_final(void *md, sha3_ctx_t *c);    // digest goes to md

// compute a sha3 hash (md) of given byte length from "in"
EMSCRIPTEN_KEEPALIVE
void *sha3(const void *in, size_t inlen, void *md, int mdlen, int variant);

// SHAKE128 and SHAKE256 extensible-output functions
#define shake128_init(c) sha3_init(c, 16, SHA3_VARIANT_STANDARD)
#define shake256_init(c) sha3_init(c, 32, SHA3_VARIANT_STANDARD)
#define shake_update sha3_update

void shake_xof(sha3_ctx_t *c);
void shake_out(sha3_ctx_t *c, void *out, size_t len);

#endif

