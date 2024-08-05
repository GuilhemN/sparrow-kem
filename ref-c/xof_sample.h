//  xof_sample.h
//  Copyright (c) 2024 Sparrow KEM Team. See LICENSE.

//  === Raccoon signature scheme -- Samplers and XOF functions

#ifndef _XOF_SAMPLE_H_
#define _XOF_SAMPLE_H_

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "sparrow_param.h"

//  === Global namespace prefix
#ifdef SPARROW_
#define xof_sample_q    SPARROW_(xof_sample_q)
#endif

#ifdef __cplusplus
extern "C" {
#endif

//  Expand "seed" of "seed_sz" bytes to a uniform polynomial (mod q).
//  The input seed is assumed to alredy contain domain separation.
void xof_sample_q(int64_t r[SPARROW_N], const uint8_t *seed, size_t seed_sz);


#ifdef __cplusplus
}
#endif

//  _XOF_SAMPLE_H_
#endif
