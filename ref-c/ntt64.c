//  ntt64.c
//  Copyright (c) 2024 Sparrow KEM Team. See LICENSE.

//  === 64-bit Number Theoretic Transform

#include <stddef.h>
#include <stdbool.h>

#include "polyr.h"
#include "mont64.h"

//  === Roots of unity constants

// file generated with scripts/gen_ring.py

static const int64_t sparrow_w_64[127] = {
	         121164,          146817,          218404,
	          27259,          186478,          162117,          169434,
	         243759,          231077,           72852,           23347,
	           1667,          214564,          138579,          240683,
	         170236,           28814,          127897,           26868,
	         162847,          216494,           91142,           63600,
	           8967,          163946,          227655,          106837,
	         140182,          240492,          159440,           43269,
	          23795,          127388,           69726,           96716,
	         253383,          176768,          110461,          238018,
	         107586,           41969,           63147,          143834,
	         113366,          168252,           47282,          117111,
	         134036,          229844,          118146,           33720,
	          86003,          121439,          189344,          118230,
	         129395,           44898,          173042,          184715,
	         231336,          197766,           70204,           31141,
	         147708,           11664,          223999,          185309,
	         157126,          218964,           37184,          201553,
	         215109,          251236,           37418,          213068,
	         208658,          206646,           78796,          260162,
	         141853,          159005,          196109,          247322,
	          12089,          126019,          172645,          184112,
	         218317,          233133,          136824,           24016,
	          57605,          254233,          248805,           85133,
	         258357,          147562,           41350,           34579,
	          19927,          260023,          106494,           75102,
	         217822,           58423,          108650,          256930,
	         176204,           52977,           13224,          102798,
	          79675,          159748,           93993,          211692,
	          69063,          107525,          209690,          183925,
	          62503,          116598,           31112,           56446,
	          94178,            5849,            7068,          180755,
};

// end generated

//  Forward NTT (negacyclic -- evaluate polynomial at factors of x^n+1).

void polyr_fntt(int64_t *v)
{
    size_t i, j, k;
    int64_t x, y, z;
    int64_t *p0, *p1, *p2;

    const int64_t *w = sparrow_w_64;

    for (k = 1, j = SPARROW_N >> 1; j > 0; k <<= 1, j >>= 1) {

        p0 = v;
        for (i = 0; i < k; i++) {
            z = *w++;
            p1 = p0 + j;
            p2 = p1 + j;

            while (p1 < p2) {
                x = *p0;
                y = *p1;
                y = mont64_mulq(y, z);
                *p0++ = mont64_add(x, y);
                *p1++ = mont64_sub(x, y);
            }
            p0 = p2;
        }
    }
}

//  Reverse NTT (negacyclic -- x^n+1), normalize by 1/(n*r).

void polyr_intt(int64_t *v)
{
    size_t i, j, k;
    int64_t x, y, z;
    int64_t *p0, *p1, *p2;

    const int64_t *w = &sparrow_w_64[SPARROW_N - 2];

    for (j = 1, k = SPARROW_N >> 1; k > 0; j <<= 1, k >>= 1) {

        p0 = v;

        for (i = 0; i < k; i++) {
            z = *w--;
            p1 = p0 + j;
            p2 = p1 + j;

            while (p1 < p2) {
                x = *p0;
                y = *p1;
                *p0++ = mont64_add(x, y);
                y = mont64_sub(y, x);
                *p1++ = mont64_mulq(y, z);
            }
            p0 = p2;
        }
    }

    //  normalization
    polyr_ntt_smul(v, v, MONT_NI);
}

//  Scalar multiplication, Montgomery reduction.

void polyr_ntt_smul(int64_t *r, const int64_t *a, int64_t c)
{
    size_t i;

    for (i = 0; i < SPARROW_N; i++) {
        r[i] = mont64_cadd(mont64_mulq(a[i], c), SPARROW_Q);
    }
}

//  Coefficient multiply:  r = a * b,  Montgomery reduction.

void polyr_ntt_cmul(int64_t *r, const int64_t *a, const int64_t *b)
{
    size_t i;

    for (i = 0; i < SPARROW_N; i++) {
        r[i] = mont64_cadd(mont64_mulq(a[i], b[i]), SPARROW_Q);
    }
}

//  Coefficient multiply and add:  r = a * b + c, Montgomery reduction.

void polyr_ntt_mula(int64_t *r, const int64_t *a, const int64_t *b,
                    const int64_t *c)
{
    size_t i;

    for (i = 0; i < SPARROW_N; i++) {
        r[i] = mont64_csub(mont64_cadd(mont64_mulq(a[i], b[i]), SPARROW_Q) + c[i],
                           SPARROW_Q);
    }
}
