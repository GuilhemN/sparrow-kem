//  api.h
//  === NIST Signature API

#ifndef _API_H_
#define _API_H_

#include "sparrow_param.h"
#include "sparrow_core.h"

//  Set these three values apropriately for your algorithm
#define CRYPTO_SECRETKEYBYTES   SPARROW_SK_SZ
#define CRYPTO_PUBLICKEYBYTES   SPARROW_PK_SZ
#define CRYPTO_BYTES            SPARROW_CT_SZ
#define CRYPTO_SHAREDKEY        SPARROW_K_SZ


// Change the algorithm name
#define CRYPTO_ALGNAME          SPARROW_NAME

int
crypto_sign_keypair(unsigned char *pk, unsigned char *sk, int transpose);

int crypto_encaps(unsigned char *K, unsigned char *ct, const unsigned char *pkA, const unsigned char *skB);

int crypto_decaps(unsigned char *K, const unsigned char *ct, const unsigned char *pkB, const unsigned char *skA);

/* _API_H_ */
#endif
