//  racc_param.h
//  Copyright (c) 2024 Sparrow KEM Team. See LICENSE.

//  === Raccoon signature scheme -- Derived parameters.

#ifndef _SPARROW_PARAM_H_
#define _SPARROW_PARAM_H_

//  select a default parameter if somehow not defied
#if !defined(NIST_KAT) && !defined(BENCH_TIMEOUT)
#include "param_select.h"
#endif

//  include the parameter list
#include "param_list.h"

//  Byte size of symmetric keys / pre-image security
#define SPARROW_SEC    (SPARROW_KAPPA / 8)

//  Byte size for collision resistant hashes
#define SPARROW_CRH    ((2 * SPARROW_KAPPA) / 8)

//  Size of A_seed
#define SPARROW_AS_SZ  SPARROW_SEC

//  Size of public key hash used in BUFFing -- needs CRH
#define SPARROW_TR_SZ  SPARROW_CRH

//  size of pk-bound message mu = H(H(pk), msg)
#define SPARROW_MU_SZ  SPARROW_CRH

//  Size of challenge hash
#define SPARROW_CH_SZ  SPARROW_CRH

//  Size of "mask keys" in serialized secret key
#define SPARROW_MK_SZ  SPARROW_SEC

//  shared / derived parameters
#if (SPARROW_Q == 260609) && (SPARROW_N == 128)
#define SPARROW_Q_BITS 18
#define SPARROW_LGN    7
#else
#error  "No known parameter defined."
#endif

#define SPARROW_QMSK   ((1LL << SPARROW_Q_BITS) - 1)

//  "low bits" in Z encoding
#define SPARROW_ZLBITS 40

//  scaled inifinity norm for hint
#define SPARROW_BOO_H  ((SPARROW_BOO + (1l << (SPARROW_NUW - 1))) >> SPARROW_NUW)

//  _SPARROW_PARAM_H_
#endif
