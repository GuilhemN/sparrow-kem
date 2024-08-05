//  racc_core.h
//  Copyright (c) 2024 Sparrow KEM Team. See LICENSE.

//  === Raccoon signature scheme -- Core internal API.

#ifndef _SPARROW_CORE_H_
#define _SPARROW_CORE_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "sparrow_param.h"

//  === Global namespace prefix
#ifdef SPARROW_
#define sparrow_core_keygen SPARROW_(core_keygen)
#define sparrow_core_encaps SPARROW_(core_encaps)
#define sparrow_core_decaps SPARROW_(core_decaps)
#endif

//  === Internal structures ===

//  raccoon public key
typedef struct {
    uint8_t a_seed[SPARROW_AS_SZ];             //  seed for a
    int64_t t[SPARROW_K][SPARROW_N];              //  public key
    uint8_t tr[SPARROW_TR_SZ];                 //  hash of serialized public key
} racc_pk_t;

//  raccoon secret key
typedef struct {
    racc_pk_t pk;                           //  copy of public key
    int64_t s[SPARROW_ELL][SPARROW_N];    //  d-masked secret key
} racc_sk_t;

//  raccoon signature
typedef struct {
    uint8_t ch[SPARROW_CH_SZ];                 //  challenge hash
    int64_t h[SPARROW_K][SPARROW_N];              //  hint
    int64_t z[SPARROW_ELL][SPARROW_N];            //  signature data
} racc_sig_t;

// sparrow ciphertext
typedef struct {
    uint8_t ct[SPARROW_CTBITS];
    uint8_t t[SPARROW_CRH];
} racc_ciphertext_t;

//  === Core API ===

//  Generate a public-secret keypair ("pk", "sk").
void sparrow_core_keygen(racc_pk_t *pk, racc_sk_t *sk, int transpose);

void sparrow_core_encaps(uint8_t *K, racc_ciphertext_t *ct, const racc_pk_t *pkA, const racc_sk_t *skB);

int sparrow_core_decaps(uint8_t *K, const racc_ciphertext_t *ct, const racc_pk_t *pkB, const racc_sk_t *skA);

#ifdef __cplusplus
}
#endif

//  _SPARROW_CORE_H_
#endif
