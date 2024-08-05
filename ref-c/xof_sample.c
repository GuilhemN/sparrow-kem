//  xof_sample.c
//  Copyright (c) 2024 Sparrow KEM Team. See LICENSE.

//  === Raccoon signature scheme -- Samplers and XOF functions

#include <string.h>

#include "sparrow_param.h"
#include "xof_sample.h"
#include "sha3_t.h"
#include "mont64.h"

//  Expand "seed" of "seed_sz" bytes to a uniform polynomial (mod q).
//  The input seed is assumed to alredy contain domain separation.

void xof_sample_q(int64_t r[SPARROW_N], const uint8_t *seed, size_t seed_sz)
{
    size_t i;
    int64_t x;
    uint8_t buf[8];
    sha3_t kec;

    //  sample from squeezed output
    sha3_init(&kec, SHAKE256_RATE);
    sha3_absorb(&kec, seed, seed_sz);
    sha3_pad(&kec, SHAKE_PAD);

    memset(buf, 0, sizeof(buf));
    for (i = 0; i < SPARROW_N; i++) {
        do {
            sha3_squeeze(&kec, buf, (SPARROW_Q_BITS + 7) / 8);
            x = get64u_le(buf) & SPARROW_QMSK;
        } while (x >= SPARROW_Q);
        r[i] = x;
    }
}
