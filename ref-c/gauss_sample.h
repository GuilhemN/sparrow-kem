//  gauss_sample.h
//  Copyright (c) 2023 Sparrow KEM Team. See LICENSE.

//  === Sparrow KEM scheme -- Samplers and XOF functions

#ifndef _GAUSS_SAMPLE_H_
#define _GAUSS_SAMPLE_H_

#include <stdint.h>
#include <stddef.h>

#include "sparrow_param.h"

//  === Global namespace prefix
#ifdef SPARROW_
#define small_sample_gauss_vector SPARROW_(small_sample_gauss_vector)
#define large_sample_gauss_vector SPARROW_(large_sample_gauss_vector)
#endif

#ifdef __cplusplus
extern "C"
{
#endif
    void small_sample_gauss_vector(int64_t *vec, size_t size);
    void large_sample_gauss_vector(int64_t *vec, size_t size);

#ifdef __cplusplus
}
#endif

//  _XOF_SAMPLE_H_
#endif
