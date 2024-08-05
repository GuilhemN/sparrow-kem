#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "nist_random.h"
#include "sparrow_param.h"
#include "sparrow_core.h"
#include "mont64.h"
#include "sha3_t.h"

#if (SPARROW_B != 2 || SPARROW_Q != 260609l)
#error "Unrecognized polynomial parameters N, Q"
#endif

static uint32_t CUTOFFS[] = {0, 65153, 130305, 195457, 260609, 325762, 390914, 456066, 521218};

int help_rec(int v) {
    return (((1 << SPARROW_B) * v) / SPARROW_Q) & 1;
}

void help_recvec(int64_t *v, racc_ciphertext_t *ct)
{
    uint8_t seed[SPARROW_SEC + 8];
    uint64_t rand; 
    int l = 0;

    //  --- 4.  sigma <- {0,1}^kappa
    randombytes(seed + 8, SPARROW_SEC);

    //  --- 5.  hdr_u := Ser8('g' || (0) || seed)
    seed[0] = 'r'; 
    memset(seed + 1, 0x00, 7);

    //  absorb seed
    sha3_t kec;
    sha3_init(&kec, SHAKE256_RATE);
    sha3_absorb(&kec, seed, sizeof(seed));
    sha3_pad(&kec, SHAKE_PAD);

    for (size_t i = 0; i < SPARROW_CTBITS; i++) {
        if (l < 2) {
            uint8_t buf[8];
            sha3_squeeze(&kec, buf, sizeof(buf));
            rand = get64u_le(buf);
            l = 64;
        }
        int r1 = rand & 1; rand >>= 1;
        int r2 = rand & 1; rand >>= 1;
        l -= 2;
        ct->ct[i] = help_rec(2*v[i] + (r1-r2));
    }
}

int closest_v(int w, int b) {
    int correct_v = help_rec(w) == b;

    int current_dist = SPARROW_Q;
    int current_closest_v = 0;

    for (size_t i = 0; i < sizeof(CUTOFFS)/sizeof(CUTOFFS[0]); i++) {
        int c = CUTOFFS[i];

        // Compute dist = abs(c-v) and s = c >= w
        int r = c - w;
        int s = r >> 31;
        int dist = (r + s) ^ s;

        int rep = (dist - s < current_dist);
        int equal = (c == w);
        current_dist = (rep * (dist - s)) | ((1 - rep) * current_dist);
        current_closest_v = (rep * (c + s - equal)) | ((1 - rep) * current_closest_v);
    }

    // decide which result to return
    current_closest_v = (correct_v * w) | ((1 - correct_v) * current_closest_v);

    // red mod 2*q
    current_closest_v = mont64_cadd(current_closest_v, SPARROW_Q << 1);
    current_closest_v = mont64_csub(current_closest_v, SPARROW_Q << 1);

    return current_closest_v;
}

int rec_element(int w, int b) {
    int v = closest_v(w, b);
    return (((v << (SPARROW_B - 1)) + (SPARROW_Q / 2)) / SPARROW_Q) & 0b11;
}

void rec_vec(uint8_t *K, const int64_t *v, const racc_ciphertext_t *ct)
{
    // unpack one byte from 4 coordinates
    for (size_t i = 0; i < SPARROW_CTBITS; i += 4) {
        K[i/4] = (rec_element(2*v[i], ct->ct[i]) << 6) | (rec_element(2*v[i+1], ct->ct[i+1]) << 4)
            | (rec_element(2*v[i+2], ct->ct[i+2]) << 2) | (rec_element(2*v[i+3], ct->ct[i+3]));
    }
}