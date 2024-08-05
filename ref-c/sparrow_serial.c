//  racc_serial.c
//  Copyright (c) 2024 Sparrow KEM Team. See LICENSE.

//  === Raccoon signature scheme -- Serialize/deserialize.

#include <string.h>
#include <stdio.h>
#include "sparrow_core.h"
#include "sparrow_serial.h"
#include "plat_local.h"
#include "polyr.h"
#include "xof_sample.h"
#include "nist_random.h"
#include "mont64.h"
#include "sha3_t.h"

//  Encode vector v[SPARROW_N] as packed "bits" sized elements to  *b".
//  Return the number of bytes written -- at most ceil(SPARROW_N * bits/8).

static inline size_t inline_encode_bits(uint8_t *b, const int64_t *v, size_t v_sz,
                                        size_t bits)
{
    size_t i, j, l;
    int64_t x, m;

    i = 0;  //  source word v[i]
    j = 0;  //  destination byte b[j]
    l = 0;  //  number of bits in x
    x = 0;  //  bit buffer

    m = (1llu << bits) - 1llu;

    while (i < v_sz) {
        while (l < 8 && i < v_sz) {
            x |= (v[i++] & m) << l;
            l += bits;
        }
        while (l >= 8) {
            b[j++] = (uint8_t)(x & 0xFF);
            x >>= 8;
            l -= 8;
        }
    }
    if (l > 0) {
        b[j++] = (uint8_t)(x & 0xFF);
    }

    return j;  //   return number of bytes written
}

//  Decode bytes from "*b" as SPARROW_N vector elements of "bits" each.
//  The decoding is unsigned if "is_signed"=false, two's complement
//  signed representation assumed if "is_signed"=true. Return the
//  number of bytes read -- upper bounded by ceil(SPARROW_N * bits/8).

static inline size_t inline_decode_bits(int64_t *v, size_t v_sz, const uint8_t *b,
                                        size_t bits, bool is_signed)
{
    size_t i, j, l;
    int64_t x, m, s;

    i = 0;  //  source byte b[i]
    j = 0;  //  destination word v[j]
    l = 0;  //  number of bits in x
    x = 0;  //  bit buffer

    if (is_signed) {
        s = 1llu << (bits - 1);  // extract sign bit
        m = s - 1;
    } else {
        s = 0;  //  sign bit ignored
        m = (1llu << bits) - 1;
    }

    while (j < v_sz) {

        while (l < bits) {
            x |= ((uint64_t)b[i++]) << l;
            l += 8;
        }
        while (l >= bits && j < v_sz) {
            v[j++] = (x & m) - (x & s);
            x >>= bits;
            l -= bits;
        }
    }

    return i;  //   return number of bytes read
}

//  === Interface

//  Encode the public key "pk" to bytes "b". Return length in bytes.

size_t racc_encode_pk(uint8_t *b, const racc_pk_t *pk)
{
    size_t i, l;

    l = 0;  //  l holds the length

    //  encode t vector
    for (i = 0; i < SPARROW_K; i++) {
        //  domain is q_t; has log2(q) - log(p_t) bits
        l += inline_encode_bits(b + l, pk->t[i], SPARROW_N, SPARROW_Q_BITS);
    }

    return l;
}

//  Decode a public key from "b" to "pk". Return length in bytes.

size_t racc_decode_pk(racc_pk_t *pk, const uint8_t *b)
{
    size_t i, l;

    l = 0;

    //  decode t vector
    for (i = 0; i < SPARROW_K; i++) {
        //  domain is q; has log2(q) bits, unsigned
        l += inline_decode_bits(pk->t[i], SPARROW_N, b + l, SPARROW_Q_BITS, false);
    }

    //  also set the tr field
    shake256(pk->tr, SPARROW_TR_SZ, b, l);

    return l;
}

//  Encode secret key "sk" to bytes "b". Return length in bytes.

size_t racc_encode_sk(uint8_t *b, const racc_sk_t *sk)
{
    size_t i, l;
    int64_t s0[SPARROW_ELL][SPARROW_N];

    //  encode public key
    l = racc_encode_pk(b, &sk->pk);

    //  make a copy of share 0
    for (i = 0; i < SPARROW_ELL; i++) {
        polyr_copy(s0[i], sk->s[i]);
    }

    //  encode the zeroth share (in full)
    for (i = 0; i < SPARROW_ELL; i++) {
        polyr_ntt_smul(s0[i], s0[i], MONT_R);
        l += inline_encode_bits(b + l, s0[i], SPARROW_N, SPARROW_Q_BITS);
    }

    return l;
}

//  Decode secret key "sk" to bytes "b". Return length in bytes.

size_t racc_decode_sk(racc_sk_t *sk, const uint8_t *b)
{
    size_t i, l;

    //  decode public key
    l = racc_decode_pk(&sk->pk, b);

    //  decode the zeroth share (in full)
    for (i = 0; i < SPARROW_ELL; i++) {
        l += inline_decode_bits(sk->s[i], SPARROW_N, b + l, SPARROW_Q_BITS, false);
    }

    return l;
}

//  Encode the ciphertext "ct" to bytes "b". Return length in bytes.

size_t racc_encode_ct1(uint8_t *b, const racc_ciphertext_t *ct)
{
    size_t i, l;
    int64_t tmp[SPARROW_CTBITS];
    for (i = 0; i < SPARROW_CTBITS; i++) {
        tmp[i] = ct->ct[i];
    }

    // l holds the length
    l = inline_encode_bits(b, tmp, SPARROW_CTBITS, 1);
    memcpy(b + l, ct->t, SPARROW_CRH); l += SPARROW_CRH;

    return l;
}

//  Encode the ciphertext "ct" to bytes "b". Return length in bytes.
size_t racc_encode_ct(uint8_t *b, const racc_ciphertext_t *ct)
{
    size_t l;

    // l holds the length
    l = racc_encode_ct1(b, ct);
    memcpy(b + l, ct->t, SPARROW_CRH);
    l += SPARROW_CRH;

    return l;
}

//  Decode a ciphertext from "b" to "ct". Return length in bytes.

size_t racc_decode_ct(racc_ciphertext_t *ct, const uint8_t *b)
{
    size_t i, l;
    int64_t tmp[SPARROW_CTBITS];

    l = inline_decode_bits(tmp, SPARROW_CTBITS, b, 1, false);
    memcpy(ct->t, b + l, SPARROW_CRH); l += SPARROW_CRH;

    for (i = 0; i < SPARROW_CTBITS; i++)
    {
        ct->ct[i] = tmp[i];
    }

    return l;
}