//  test_main.c
//  Copyright (c) 2024 Sparrow KEM Team. See LICENSE.

//  === private tests and benchmarks

#ifndef NIST_KAT

#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "plat_local.h"
#include "sparrow_core.h"
#include "nist_random.h"
#include "sparrow_serial.h"
#include "mont64.h"
#include "polyr.h"
#include "sha3_t.h"
#include "gauss_sample.h"
#include "sparrow_rec.h"

#include "api.h"

//  [debug] (shake) checksums of data

void dbg_chk(const char  *label, uint8_t *data, size_t data_sz)
{
    size_t i;
    uint8_t md[16] = {0};

    shake256(md, sizeof(md), data, data_sz);
    printf("%s: ", label);
    for (i = 0; i < sizeof(md); i++) {
        printf("%02x", md[i]);
    }
    printf(" (%zu)\n", data_sz);
}

//  [debug] dump a hex string

void dbg_hex(const char *label, const uint8_t *data, size_t data_sz)
{
    size_t i;
    printf("%s= ", label);
    for (i = 0; i < data_sz; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

//  standard library process time

static inline double cpu_clock_secs()
{
    return ((double)clock()) / ((double)CLOCKS_PER_SEC);
}

//  maximum message size
#define MAX_MSG 256

int main()
{
    size_t i;

    //  timing
    size_t iter = 100;
    double ts, to;
    uint64_t cc;

    //  buffers for serialized
    uint8_t K[CRYPTO_SHAREDKEY] = {0};
    uint8_t K_[CRYPTO_SHAREDKEY] = {0};
    uint8_t ct[CRYPTO_BYTES] = {0};
    uint8_t pkA[CRYPTO_PUBLICKEYBYTES] = {0};
    uint8_t skA[CRYPTO_SECRETKEYBYTES] = {0};
    uint8_t pkB[CRYPTO_PUBLICKEYBYTES] = {0};
    uint8_t skB[CRYPTO_SECRETKEYBYTES] = {0};

    //  initialize nist pseudo random
    uint8_t seed[48];
    for (i = 0; i < 48; i++) {
        seed[i] = i;
    }
    nist_randombytes_init(seed, NULL, 256);

    //  (start)
    printf("CRYPTO_ALGNAME\t= %s\n", CRYPTO_ALGNAME);
    printf("CRYPTO_PUBLICKEYBYTES\t= %d\n", CRYPTO_PUBLICKEYBYTES);
    printf("CRYPTO_SECRETKEYBYTES\t= %d\n", CRYPTO_SECRETKEYBYTES);
    printf("CRYPTO_BYTES\t\t= %d\n", CRYPTO_BYTES);
    printf("CRYPTO_SHAREDKEY\t\t= %d\n", CRYPTO_SHAREDKEY);

    //  === keygen ===
    crypto_sign_keypair(pkA, skA, 0);
    dbg_chk(CRYPTO_ALGNAME ".pk", pkA, CRYPTO_PUBLICKEYBYTES);
    dbg_chk(CRYPTO_ALGNAME ".sk", skA, CRYPTO_SECRETKEYBYTES);

    printf("closest v %d\n", closest_v(1, 1));

    // test recover
    int v1 = 59000;
    int v2 = 60800;

    int c = (((1 << SPARROW_B) * v1) / SPARROW_Q) & 1;
    int w1 = rec_element(v1, c);
    int w2 = rec_element(v2, c);
    printf("%d vs %d\n", w1, w2);

    // test recover
    int test = 0;
    for (int i = 0; i < 1000; i++) {
        crypto_sign_keypair(pkA, skA, 0);
        crypto_sign_keypair(pkB, skB, 1);

        crypto_encaps(K, ct, pkA, skB);
        crypto_decaps(K_, ct, pkB, skA);

        int ok = 1;
        for (int j = 0; j < CRYPTO_SHAREDKEY; j++)
        {
            ok &= (K[j] == K_[j]);
        }

        test += 1 - ok;
    }
    printf("nb encaps not ok: %d\n", test);

#ifdef BENCH_TIMEOUT
    to = BENCH_TIMEOUT;
#else
    to = 1.0;  //   timeout threshold (seconds)
#endif

    printf("=== Bench ===\n");

    int64_t y[SPARROW_N * SPARROW_K];
    iter = 16;
    do
    {
        iter *= 2;
        ts = cpu_clock_secs();
        cc = plat_get_cycle();

        for (i = 0; i < iter; i++)
        {
            small_sample_gauss_vector(y, SPARROW_N * SPARROW_K);
        }
        cc = plat_get_cycle() - cc;
        ts = cpu_clock_secs() - ts;
    } while (ts < to);
    printf("%s\tSmallSampleGauss() %5zu:\t%8.3f ms\t%8.3f Mcyc\n", CRYPTO_ALGNAME, iter,
           1000.0 * ts / ((double)iter), 1E-6 * ((double)(cc / iter)));


    iter = 16;
    do
    {
        iter *= 2;
        ts = cpu_clock_secs();
        cc = plat_get_cycle();

        for (i = 0; i < iter; i++)
        {
            large_sample_gauss_vector(y, SPARROW_CTBITS);
        }
        cc = plat_get_cycle() - cc;
        ts = cpu_clock_secs() - ts;
    } while (ts < to);
    printf("%s\tLargeSampleGauss() %5zu:\t%8.3f ms\t%8.3f Mcyc\n", CRYPTO_ALGNAME, iter,
           1000.0 * ts / ((double)iter), 1E-6 * ((double)(cc / iter)));

    iter = 16;
    do {
        iter *= 2;
        ts = cpu_clock_secs();
        cc = plat_get_cycle();

        for (i = 0; i < iter; i++) {
            crypto_sign_keypair(pkA, skA, 0);
        }
        cc = plat_get_cycle() - cc;
        ts = cpu_clock_secs() - ts;
    } while (ts < to);
    printf("%s\tKeyGen() %5zu:\t%8.3f ms\t%8.3f Mcyc\n", CRYPTO_ALGNAME, iter,
           1000.0 * ts / ((double)iter), 1E-6 * ((double) (cc / iter)));

    iter = 16;
    do
    {
        iter *= 2;

        crypto_sign_keypair(pkA, skA, 0);
        crypto_sign_keypair(pkB, skB, 1);

        ts = cpu_clock_secs();
        cc = plat_get_cycle();

        for (i = 0; i < iter; i++)
        {
            crypto_encaps(K, ct, pkA, skB);
        }
        cc = plat_get_cycle() - cc;
        ts = cpu_clock_secs() - ts;
    } while (ts < to);
    printf("%s\t  Encaps() %5zu:\t%8.3f ms\t%8.3f Mcyc\n", CRYPTO_ALGNAME, iter,
           1000.0 * ts / ((double)iter), 1E-6 * ((double)(cc / iter)));

    iter = 16;
    do
    {
        iter *= 2;

        crypto_sign_keypair(pkA, skA, 0);
        crypto_sign_keypair(pkB, skB, 1);

        ts = cpu_clock_secs();
        cc = plat_get_cycle();

        for (i = 0; i < iter; i++)
        {
            crypto_decaps(K, ct, pkB, skA);
        }
        cc = plat_get_cycle() - cc;
        ts = cpu_clock_secs() - ts;
    } while (ts < to);
    printf("%s\t  Decaps() %5zu:\t%8.3f ms\t%8.3f Mcyc\n", CRYPTO_ALGNAME, iter,
           1000.0 * ts / ((double)iter), 1E-6 * ((double)(cc / iter)));

    return 0;
}

// NIST_KAT
#endif
