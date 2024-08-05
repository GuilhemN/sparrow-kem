//  mont64.h
//  Copyright (c) 2024 Sparrow KEM Team. See LICENSE.

//  === Portable 64-bit Montgomery arithmetic

#ifndef _MONT64_H_
#define _MONT64_H_

#include "plat_local.h"
#include "sparrow_param.h"

// file generated with scripts/gen_ring.py

#if (SPARROW_N != 128 || SPARROW_Q != 260609l)
#error "Unrecognized polynomial parameters N, Q"
#endif

/*
    n   = 128
    q1  = 260609
    q2  = 1
    q   = q1*q2
    r   = 2^64 % q
    rr  = r^2 % q
    ni  = lift(rr * Mod(n,q)^-1)
    qi  = lift(Mod(-q,2^64)^-1)
*/

//  Montgomery constants. These depend on Q and N
#define MONT_R 125151L
#define MONT_RR 171901L
#define MONT_NI 7451L
#define MONT_QI 2426873466807384575L

// end generated

//  Addition and subtraction

static inline int64_t mont64_add(int64_t x, int64_t y)
{
    return x + y;
}

static inline int64_t mont64_sub(int64_t x, int64_t y)
{
    return x - y;
}
//  Conditionally add m if x is negative

static inline int64_t mont64_cadd(int64_t x, int64_t m)
{
    int64_t t, r;

    XASSUME(x >= -m && x < m);

    t = x >> 63;
    r = x + (t & m);

    XASSERT(r >= 0 && r < m);
    XASSERT(r == x || r == x + m);

    return r;
}

//  Conditionally subtract m if x >= m

static inline int64_t mont64_csub(int64_t x, int64_t m)
{
    int64_t t, r;

    XASSUME(x >= 0 && x < 2 * m);
    XASSUME(m > 0);

    t = x - m;
    r = t + ((t >> 63) & m);

    XASSERT(r >= 0 && r < m);
    XASSERT(r == x || r == x - m);

    return r;
}

//  Montgomery reduction. Returns r in [-q,q-1] so that r == (x/2^64) mod q.

static inline int64_t mont64_redc(__int128 x)
{
    int64_t r;

    //  prove these input bounds
    XASSUME(x >= -(((__int128)1) << 111));
    XASSUME(x < (((__int128)1) << 111));

    r = x * MONT_QI;
    r = (x + ((__int128)r) * ((__int128)SPARROW_Q)) >> 64;

    //  prove that only one coditional addition is required
    XASSERT(r >= -SPARROW_Q && r < SPARROW_Q);

#ifdef XDEBUG
    //  this modular reduction correctness proof is too slow for SAT
    XASSERT(((((__int128)x) - (((__int128)r) << 64)) %
            ((__int128_t)SPARROW_Q)) == 0);
#endif
    return r;
}

//  Montgomery multiplication. r in [-q,q-1] so that r == (a*b)/2^64) mod q.

static inline int64_t mont64_mulq(int64_t x, int64_t y)
{
    int64_t r;

    r = mont64_redc(((__int128)x) * ((__int128)y));

    return r;
}

//  same with addition

static inline int64_t mont64_mulqa(int64_t x, int64_t y, int64_t z)
{
    int64_t r;

    r = mont64_redc(((__int128)x) * ((__int128)y) + ((__int128)z));

    return r;
}

//  _MONT64_H_
#endif
