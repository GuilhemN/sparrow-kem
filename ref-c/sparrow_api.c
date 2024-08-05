//  racc_api.c
//  Copyright (c) 2024 Sparrow KEM Team. See LICENSE.

//  === Raccoon signature scheme -- NIST KAT Generator API.

#include <string.h>
#include <stdio.h>

#include "api.h"
#include "sparrow_core.h"
#include "sparrow_serial.h"
#include "xof_sample.h"

//  Generates a keypair - pk is the public key and sk is the secret key.

int
crypto_sign_keypair(  unsigned char *pk, unsigned char *sk, int transpose)
{
    racc_pk_t   r_pk;           //  internal-format public key
    racc_sk_t   r_sk;           //  internal-format secret key

    sparrow_core_keygen(&r_pk, &r_sk, transpose); //  generate keypair

    //  serialize
    if (CRYPTO_PUBLICKEYBYTES != racc_encode_pk(pk, &r_pk) ||
        CRYPTO_SECRETKEYBYTES != racc_encode_sk(sk, &r_sk))
        return -1;

    return  0;
}


int crypto_encaps(unsigned char *K, unsigned char *ct, const unsigned char *pkA, const unsigned char *skB)
{
    racc_sk_t r_skB;   //  internal-format secret key
    racc_pk_t r_pkA;   //  internal-format secret key
    racc_ciphertext_t r_ct;   //  internal-format ciphertext

    //  deserialize public key
    if (CRYPTO_PUBLICKEYBYTES != racc_decode_pk(&r_pkA, pkA)) 
        return -1;
    //  deserialize secret key
    if (CRYPTO_SECRETKEYBYTES != racc_decode_sk(&r_skB, skB))
        return -1;

    sparrow_core_encaps(K, &r_ct, &r_pkA, &r_skB);
    racc_encode_ct(ct, &r_ct);

    return 0;
}

int crypto_decaps(unsigned char *K, const unsigned char *ct, const unsigned char *pkB, const unsigned char *skA)
{
    racc_sk_t r_skA; //  internal-format secret key
    racc_pk_t r_pkB; //  internal-format secret key
    racc_ciphertext_t r_ct; //  internal-format ciphertext

    //  deserialize public key
    if (CRYPTO_PUBLICKEYBYTES != racc_decode_pk(&r_pkB, pkB))
        return -1;
    //  deserialize secret key
    if (CRYPTO_SECRETKEYBYTES != racc_decode_sk(&r_skA, skA))
        return -1;

    racc_decode_ct(&r_ct, ct);
    return sparrow_core_decaps(K, &r_ct, &r_pkB, &r_skA);
}


