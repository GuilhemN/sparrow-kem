//  racc_core.c
//  Copyright (c) 2024 Sparrow KEM Team. See LICENSE.

//  === Raccoon signature scheme -- core scheme.

#include <string.h>
#include <stdio.h>

#include "plat_local.h"
#include "sparrow_core.h"
#include "sparrow_serial.h"
#include "polyr.h"
#include "mont64.h"
#include "ct_util.h"
#include "xof_sample.h"
#include "nist_random.h"
#include "gauss_sample.h"
#include "sparrow_rec.h"
#include "sha3_t.h"

//  ExpandA(): Use domain separated XOF to create matrix elements

static void expand_aij( int64_t aij[SPARROW_N], int i_k, int i_ell)
{
    uint8_t buf[SPARROW_AS_SZ + 8];

    //  --- 3.  hdrA := Ser8(65, i, j, 0, 0, 0, 0, 0)
    buf[0] = 'A';       //  ascii 65
    buf[1] = i_k;
    buf[2] = i_ell;
    memset(buf + 3, 0x00, 8 - 3);

    //  --- 4.  Ai,j <- SampleQ(hdrA, seed)
    xof_sample_q(aij, buf, 8);

    //  converted to NTT domain
    polyr_fntt(aij);
}

//  === sparrow_core_keygen ===
//  Generate a public-secret keypair ("pk", "sk").

void sparrow_core_keygen(racc_pk_t *pk, racc_sk_t *sk, int transpose)
{
    int i, j;
    int64_t aij[SPARROW_N];
    int64_t ttmp[SPARROW_N];

    for (i = 0; i < SPARROW_ELL; i++) {
        small_sample_gauss_vector(sk->s[i], SPARROW_N);
        polyr_fntt(sk->s[i]);
    }

    for (i = 0; i < SPARROW_K; i++) {
        polyr_zero(ttmp);

        //  --- 2.  A := ExpandA(seed)
        for (j = 0; j < SPARROW_ELL; j++) {
            expand_aij(aij, transpose ? j : i,  transpose ? i : j);
            polyr_ntt_mula(ttmp, sk->s[j], aij, ttmp);
        }
        polyr_intt(ttmp);

        //  ---  Sample e
        small_sample_gauss_vector(pk->t[i], SPARROW_N);
        //  ---  t <- (A*s) + e
        polyr_addq(pk->t[i], pk->t[i], ttmp);
    }

    //  --- 9.  return ( (vk := seed, t), sk:= (vk, [[s]]) )
    memcpy(&sk->pk, pk, sizeof(racc_pk_t));
}


//  === sparrow_core_encaps ===

void sparrow_core_encaps(uint8_t *K, racc_ciphertext_t *ct, const racc_pk_t *pkA, const racc_sk_t *skB)
{
    int i;
    size_t l;
    int64_t y[SPARROW_CTBITS];
    int64_t ttmp[SPARROW_N], v[SPARROW_N];
    uint8_t Ktmp[SPARROW_K_SZ];
    uint8_t buf[1 + 2 * SPARROW_TR_SZ + SPARROW_CT1_SZ + SPARROW_K_SZ];

    polyr_zero(v);
    for (i = 0; i < SPARROW_K; i++)
    {
        polyr_copy(ttmp, pkA->t[i]);
        polyr_fntt(ttmp);
        polyr_ntt_mula(v, skB->s[i], ttmp, v);
    }

    polyr_intt(v);

    // Sample encapsulation noise
    large_sample_gauss_vector(y, SPARROW_CTBITS);
    polyr_addq(v, v, y);

    help_recvec(v, ct);
    rec_vec(Ktmp, v, ct);

    // Compute final shared key and hash check t
    l = 1;
    memcpy(buf+l, pkA->tr, SPARROW_TR_SZ); l += SPARROW_TR_SZ;
    memcpy(buf+l, skB->pk.tr, SPARROW_TR_SZ); l += SPARROW_TR_SZ;
    racc_encode_ct1(buf+l, ct); l += SPARROW_CT1_SZ;
    memcpy(buf+l, Ktmp, SPARROW_K_SZ);

    buf[0] = 'K';
    shake256(K, SPARROW_K_SZ, buf, sizeof(buf));
    buf[0] = 't';
    shake256(ct->t, SPARROW_K_SZ, buf, sizeof(buf));
}

//  === sparrow_core_encaps ===

int sparrow_core_decaps(uint8_t *K, const racc_ciphertext_t *ct, const racc_pk_t *pkB, const racc_sk_t *skA)
{
    int i;
    size_t l;
    int64_t y[SPARROW_CTBITS];
    int64_t ttmp[SPARROW_N], v[SPARROW_N];
    uint8_t Ktmp[SPARROW_K_SZ];
    uint8_t buf[1 + 2 * SPARROW_TR_SZ + SPARROW_CT1_SZ + SPARROW_K_SZ];
    uint8_t t[SPARROW_CRH];

    polyr_zero(v);
    for (i = 0; i < SPARROW_K; i++)
    {
        polyr_copy(ttmp, pkB->t[i]);
        polyr_fntt(ttmp);
        polyr_ntt_mula(v, skA->s[i], ttmp, v);
    }

    polyr_intt(v);

    // Sample encapsulation noise
    small_sample_gauss_vector(y, SPARROW_CTBITS);
    polyr_addq(v, v, y);

    rec_vec(Ktmp, v, ct);

    // Compute final shared key and hash check t
    l = 1;
    memcpy(buf+l, skA->pk.tr, SPARROW_TR_SZ); l += SPARROW_TR_SZ;
    memcpy(buf+l, pkB->tr, SPARROW_TR_SZ); l += SPARROW_TR_SZ;
    racc_encode_ct1(buf+l, ct); l += SPARROW_CT1_SZ;
    memcpy(buf+l, Ktmp, SPARROW_K_SZ);

    buf[0] = 't';
    shake256(t, SPARROW_K_SZ, buf, sizeof(buf));
    if (memcmp(t, ct->t, SPARROW_CRH) != 0) {
        return 1;
    }

    buf[0] = 'K';
    shake256(K, SPARROW_K_SZ, buf, sizeof(buf));

    return 0;
}
